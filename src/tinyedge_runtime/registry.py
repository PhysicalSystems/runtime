"""Fail-closed adapter and compatible-bundle resolution for Runtime v1."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

from .contracts import (
    ActionChunk,
    AdapterCapability,
    ArtifactRef,
    ObservationEnvelope,
    RuntimeCapabilities,
    RuntimePlan,
    SafetyPolicy,
    canonical_sha256,
)


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,127}$")
_MAX_VECTOR = 1024
_MAX_ARTIFACTS = 64
BUNDLE_VERSION = "tinyedge-runtime-qualified-bundle-v1"


class RuntimeCompatibilityError(RuntimeError):
    """A validated plan cannot be resolved on this exact Runtime."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


class SensorAdapter(Protocol):
    adapter_id: str
    version: str

    def open(self, plan: RuntimePlan) -> None: ...

    def read(self) -> ObservationEnvelope: ...

    def close(self) -> None: ...


class ModelAdapter(Protocol):
    adapter_id: str
    version: str
    artifact_digest: str

    def open(self, plan: RuntimePlan) -> None: ...

    def predict(self, observation: ObservationEnvelope) -> ActionChunk: ...

    def close(self) -> None: ...


class RobotAdapter(Protocol):
    adapter_id: str
    version: str

    def open(self, plan: RuntimePlan) -> None: ...

    def arm(self, plan: RuntimePlan) -> None: ...

    def apply_chunk(self, action: ActionChunk) -> None: ...

    def safe_stop(self, reason: str) -> None: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class QualifiedBundle:
    """One declared, internally compatible Runtime composition."""

    bundle_id: str
    execution_strategy: str
    clock_domain: str
    observation_schema_id: str
    action_schema_id: str
    action_axes: tuple[str, ...]
    action_units: tuple[str, ...]
    safety_envelope: SafetyPolicy
    sensor: AdapterCapability
    model: AdapterCapability
    robot: AdapterCapability
    required_artifacts: tuple[ArtifactRef, ...]

    @classmethod
    def from_dict(cls, value: object) -> "QualifiedBundle":
        if not isinstance(value, dict):
            raise ValueError("qualified bundle must be an object")
        required = {
            "contract_version",
            "bundle_id",
            "execution_strategy",
            "clock_domain",
            "observation_schema_id",
            "action_schema_id",
            "action_axes",
            "action_units",
            "safety_envelope",
            "sensor",
            "model",
            "robot",
            "required_artifacts",
        }
        if set(value) != required:
            missing = sorted(required - set(value))
            unknown = sorted(set(value) - required)
            raise ValueError(
                f"qualified bundle fields differ: missing={missing!r}, unknown={unknown!r}"
            )
        if value["contract_version"] != BUNDLE_VERSION:
            raise ValueError(f"unsupported qualified bundle contract {value['contract_version']!r}")
        axes = value["action_axes"]
        units = value["action_units"]
        artifacts = value["required_artifacts"]
        if (
            not isinstance(axes, list)
            or not axes
            or len(axes) > _MAX_VECTOR
            or not isinstance(units, list)
            or len(units) != len(axes)
        ):
            raise ValueError("qualified bundle axes and units must be bounded lists")
        if (
            not isinstance(artifacts, list)
            or not artifacts
            or len(artifacts) > _MAX_ARTIFACTS
        ):
            raise ValueError("qualified bundle required_artifacts must be a bounded list")
        return cls(
            bundle_id=value["bundle_id"],
            execution_strategy=value["execution_strategy"],
            clock_domain=value["clock_domain"],
            observation_schema_id=value["observation_schema_id"],
            action_schema_id=value["action_schema_id"],
            action_axes=tuple(axes),
            action_units=tuple(units),
            safety_envelope=SafetyPolicy.from_dict(
                value["safety_envelope"], "bundle.safety_envelope"
            ),
            sensor=AdapterCapability.from_dict(value["sensor"], "bundle.sensor"),
            model=AdapterCapability.from_dict(value["model"], "bundle.model"),
            robot=AdapterCapability.from_dict(value["robot"], "bundle.robot"),
            required_artifacts=tuple(
                ArtifactRef.from_dict(item, f"bundle.required_artifacts[{index}]")
                for index, item in enumerate(artifacts)
            ),
        )

    def __post_init__(self) -> None:
        for name, value in (
            ("bundle_id", self.bundle_id),
            ("execution_strategy", self.execution_strategy),
            ("clock_domain", self.clock_domain),
            ("observation_schema_id", self.observation_schema_id),
            ("action_schema_id", self.action_schema_id),
        ):
            if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
                raise ValueError(f"{name} must be a strict bounded identifier")
        if self.execution_strategy != "local_sync_v1":
            raise ValueError("Runtime v1 bundles support local_sync_v1 only")
        if (
            not isinstance(self.action_axes, tuple)
            or not self.action_axes
            or len(self.action_axes) > _MAX_VECTOR
            or any(
                not isinstance(value, str) or not _IDENTIFIER.fullmatch(value)
                for value in self.action_axes
            )
        ):
            raise ValueError("bundle action_axes must be a non-empty tuple of identifiers")
        if len(set(self.action_axes)) != len(self.action_axes):
            raise ValueError("bundle action_axes must be unique and ordered")
        if (
            not isinstance(self.action_units, tuple)
            or len(self.action_units) != len(self.action_axes)
            or any(
                not isinstance(value, str) or not _IDENTIFIER.fullmatch(value)
                for value in self.action_units
            )
        ):
            raise ValueError("bundle action_units must match the ordered action axes")
        if not isinstance(self.safety_envelope, SafetyPolicy):
            raise ValueError("bundle safety_envelope must be a SafetyPolicy")
        if self.safety_envelope.action_schema_id != self.action_schema_id:
            raise ValueError("bundle safety schema must match action_schema_id")
        if self.safety_envelope.action_axes != self.action_axes:
            raise ValueError("bundle safety axes must match action_axes")
        if self.safety_envelope.units != self.action_units:
            raise ValueError("bundle safety units must match action_units")
        expected_kinds = (("sensor", self.sensor), ("model", self.model), ("robot", self.robot))
        for expected, adapter in expected_kinds:
            if not isinstance(adapter, AdapterCapability):
                raise ValueError(f"bundle {expected} adapter must be an AdapterCapability")
            if adapter.kind != expected:
                raise ValueError(f"bundle {expected} adapter has kind {adapter.kind!r}")
            # Direct dataclass construction still receives the strict contract check.
            AdapterCapability.from_dict(adapter.to_dict(), f"bundle.{expected}")
        if (
            not isinstance(self.required_artifacts, tuple)
            or not self.required_artifacts
            or len(self.required_artifacts) > _MAX_ARTIFACTS
            or any(not isinstance(item, ArtifactRef) for item in self.required_artifacts)
        ):
            raise ValueError("bundle requires a bounded immutable artifact tuple")
        artifact_keys = tuple(
            (item.name, item.kind, item.digest) for item in self.required_artifacts
        )
        if tuple(sorted(artifact_keys)) != artifact_keys:
            raise ValueError("bundle artifacts must be sorted by name/kind/digest")
        if len({item.name for item in self.required_artifacts}) != len(self.required_artifacts):
            raise ValueError("bundle artifact names must be unique")
        if len({item.digest for item in self.required_artifacts}) != len(self.required_artifacts):
            raise ValueError("bundle artifact digests must be unique")
        model_artifacts = [item for item in self.required_artifacts if item.kind == "model"]
        if len(model_artifacts) != 1:
            raise ValueError("Runtime v1 bundles require exactly one model artifact")

    def to_dict(self) -> dict:
        return {
            "contract_version": BUNDLE_VERSION,
            "bundle_id": self.bundle_id,
            "execution_strategy": self.execution_strategy,
            "clock_domain": self.clock_domain,
            "observation_schema_id": self.observation_schema_id,
            "action_schema_id": self.action_schema_id,
            "action_axes": list(self.action_axes),
            "action_units": list(self.action_units),
            "safety_envelope": self.safety_envelope.to_dict(),
            "sensor": self.sensor.to_dict(),
            "model": self.model.to_dict(),
            "robot": self.robot.to_dict(),
            "required_artifacts": [item.to_dict() for item in self.required_artifacts],
        }

    @property
    def compatibility_digest(self) -> str:
        return canonical_sha256(self.to_dict())

    @property
    def adapter_requirements(self) -> tuple[AdapterCapability, ...]:
        return self.sensor, self.model, self.robot

    @property
    def model_artifact(self) -> ArtifactRef:
        return next(item for item in self.required_artifacts if item.kind == "model")


_RESOLUTION_TOKEN = object()


@dataclass(frozen=True, init=False)
class ResolvedRuntime:
    plan: RuntimePlan
    capabilities: RuntimeCapabilities
    bundle: QualifiedBundle
    sensor: SensorAdapter
    model: ModelAdapter
    robot: RobotAdapter

    def __init__(
        self,
        *,
        plan: RuntimePlan,
        capabilities: RuntimeCapabilities,
        bundle: QualifiedBundle,
        sensor: SensorAdapter,
        model: ModelAdapter,
        robot: RobotAdapter,
        _resolution_token: object | None = None,
    ) -> None:
        if _resolution_token is not _RESOLUTION_TOKEN:
            raise RuntimeCompatibilityError(
                "untrusted_resolution",
                "ResolvedRuntime values may only be created by RuntimeRegistry.resolve",
            )
        object.__setattr__(self, "plan", plan)
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "bundle", bundle)
        object.__setattr__(self, "sensor", sensor)
        object.__setattr__(self, "model", model)
        object.__setattr__(self, "robot", robot)


class RuntimeRegistry:
    """Registry whose only executable outputs are predeclared bundles."""

    def __init__(self) -> None:
        self._adapters: dict[tuple[str, str, str], object] = {}
        self._bundles: dict[str, QualifiedBundle] = {}

    def register_sensor(self, adapter: SensorAdapter) -> None:
        self._register("sensor", adapter)

    def register_model(self, adapter: ModelAdapter) -> None:
        self._register("model", adapter)

    def register_robot(self, adapter: RobotAdapter) -> None:
        self._register("robot", adapter)

    def _register(self, kind: str, adapter: object) -> None:
        adapter_id = getattr(adapter, "adapter_id", None)
        version = getattr(adapter, "version", None)
        capability = AdapterCapability.from_dict(
            {"kind": kind, "adapter_id": adapter_id, "version": version},
            f"registry.{kind}",
        )
        required_methods = {
            "sensor": ("open", "read", "close"),
            "model": ("open", "predict", "close"),
            "robot": ("open", "arm", "apply_chunk", "safe_stop", "close"),
        }[kind]
        missing_methods = tuple(
            name for name in required_methods if not callable(getattr(adapter, name, None))
        )
        if missing_methods:
            raise RuntimeCompatibilityError(
                "invalid_adapter_lifecycle",
                f"{kind} adapter has non-callable lifecycle methods {missing_methods!r}",
            )
        artifact_digest = getattr(adapter, "artifact_digest", "")
        if kind == "model" and (
            not isinstance(artifact_digest, str)
            or not _DIGEST.fullmatch(artifact_digest)
        ):
            raise RuntimeCompatibilityError(
                "invalid_model_artifact",
                "model adapter must declare a canonical sha256 artifact digest",
            )
        key = capability.key
        if key in self._adapters:
            raise RuntimeCompatibilityError(
                "duplicate_adapter", f"adapter {kind}/{adapter_id}@{version} is already registered"
            )
        self._adapters[key] = adapter

    def register_bundle(self, bundle: QualifiedBundle) -> None:
        if bundle.bundle_id in self._bundles:
            raise RuntimeCompatibilityError(
                "duplicate_bundle", f"bundle {bundle.bundle_id!r} is already registered"
            )
        self._bundles[bundle.bundle_id] = bundle

    def resolve(self, plan: RuntimePlan, capabilities: RuntimeCapabilities) -> ResolvedRuntime:
        """Resolve a plan without opening any adapter or touching a device."""

        if plan.target.device_id != capabilities.device_id:
            raise RuntimeCompatibilityError(
                "target_device_mismatch",
                f"plan targets {plan.target.device_id!r}, runtime is {capabilities.device_id!r}",
            )
        if plan.target.environment_id != capabilities.environment_id:
            raise RuntimeCompatibilityError(
                "target_environment_mismatch",
                "plan target environment does not match the current runtime",
            )
        if plan.target.capability_digest != capabilities.capability_digest:
            raise RuntimeCompatibilityError(
                "target_capability_mismatch",
                "plan was resolved for a different capability attestation",
            )
        bundle = self._bundles.get(plan.bundle_id)
        if bundle is None:
            raise RuntimeCompatibilityError(
                "unknown_bundle", f"bundle {plan.bundle_id!r} is not registered"
            )
        if plan.bundle_digest != bundle.compatibility_digest:
            raise RuntimeCompatibilityError(
                "bundle_digest_mismatch", "registered bundle differs from the sealed plan"
            )
        qualified_digest = capabilities.bundle_digests.get(plan.bundle_id)
        if qualified_digest is None:
            raise RuntimeCompatibilityError(
                "unqualified_bundle", "bundle is not present in the capability attestation"
            )
        if qualified_digest != bundle.compatibility_digest:
            raise RuntimeCompatibilityError(
                "qualified_bundle_mismatch", "attested bundle digest differs from the registry"
            )
        if plan.execution_strategy != bundle.execution_strategy:
            raise RuntimeCompatibilityError(
                "execution_strategy_mismatch", "plan strategy differs from its bundle"
            )
        if plan.execution_strategy != "local_sync_v1":
            raise RuntimeCompatibilityError(
                "unsupported_execution_strategy", "this Runtime slice supports local_sync_v1 only"
            )
        if plan.clock_domain != bundle.clock_domain:
            raise RuntimeCompatibilityError(
                "clock_domain_mismatch", "plan clock domain differs from its bundle"
            )
        if plan.observation_schema_id != bundle.observation_schema_id:
            raise RuntimeCompatibilityError(
                "observation_schema_mismatch", "plan observation schema differs from its bundle"
            )
        if plan.action_schema_id != bundle.action_schema_id:
            raise RuntimeCompatibilityError(
                "action_schema_mismatch", "plan action schema differs from its bundle"
            )
        if plan.safety.action_axes != bundle.action_axes:
            raise RuntimeCompatibilityError(
                "action_axes_mismatch", "plan action axis order differs from its bundle"
            )
        if plan.safety.units != bundle.action_units:
            raise RuntimeCompatibilityError(
                "action_units_mismatch", "plan action units differ from its bundle"
            )
        qualified_safety = bundle.safety_envelope
        if (
            plan.safety.max_observation_age_ns
            > qualified_safety.max_observation_age_ns
            or plan.safety.max_action_age_ns > qualified_safety.max_action_age_ns
            or any(
                plan_lower < qualified_lower or plan_upper > qualified_upper
                for plan_lower, plan_upper, qualified_lower, qualified_upper in zip(
                    plan.safety.lower_limits,
                    plan.safety.upper_limits,
                    qualified_safety.lower_limits,
                    qualified_safety.upper_limits,
                )
            )
        ):
            raise RuntimeCompatibilityError(
                "safety_envelope_exceeded",
                "plan safety limits must equal or tighten the qualified bundle envelope",
            )
        if plan.artifacts != bundle.required_artifacts:
            raise RuntimeCompatibilityError(
                "artifact_set_mismatch",
                "plan artifact roles, names, kinds and digests differ from the bundle",
            )
        missing_capabilities = [
            requirement.key
            for requirement in bundle.adapter_requirements
            if requirement.key not in capabilities.adapter_keys
        ]
        if missing_capabilities:
            raise RuntimeCompatibilityError(
                "adapter_not_attested", f"missing adapter attestations {missing_capabilities!r}"
            )
        resolved: dict[str, object] = {}
        for requirement in bundle.adapter_requirements:
            adapter = self._adapters.get(requirement.key)
            if adapter is None:
                raise RuntimeCompatibilityError(
                    "adapter_not_registered",
                    "adapter "
                    f"{requirement.kind}/{requirement.adapter_id}@{requirement.version} "
                    "is absent",
                )
            current_identity = (
                getattr(adapter, "adapter_id", None),
                getattr(adapter, "version", None),
            )
            if current_identity != (requirement.adapter_id, requirement.version):
                raise RuntimeCompatibilityError(
                    "adapter_identity_changed",
                    f"registered {requirement.kind} adapter identity changed after registration",
                )
            required_methods = {
                "sensor": ("open", "read", "close"),
                "model": ("open", "predict", "close"),
                "robot": ("open", "arm", "apply_chunk", "safe_stop", "close"),
            }[requirement.kind]
            if any(not callable(getattr(adapter, name, None)) for name in required_methods):
                raise RuntimeCompatibilityError(
                    "adapter_lifecycle_changed",
                    f"registered {requirement.kind} adapter lifecycle changed after registration",
                )
            resolved[requirement.kind] = adapter
        model = resolved["model"]
        if getattr(model, "artifact_digest", None) != bundle.model_artifact.digest:
            raise RuntimeCompatibilityError(
                "model_artifact_mismatch",
                "registered model adapter does not bind the bundle's exact model artifact",
            )
        return ResolvedRuntime(
            plan=plan,
            capabilities=capabilities,
            bundle=bundle,
            sensor=resolved["sensor"],  # type: ignore[arg-type]
            model=model,  # type: ignore[arg-type]
            robot=resolved["robot"],  # type: ignore[arg-type]
            _resolution_token=_RESOLUTION_TOKEN,
        )


__all__ = [
    "BUNDLE_VERSION",
    "ModelAdapter",
    "QualifiedBundle",
    "ResolvedRuntime",
    "RobotAdapter",
    "RuntimeCompatibilityError",
    "RuntimeRegistry",
    "SensorAdapter",
]
