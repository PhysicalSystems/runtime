"""Strict, immutable contracts for the first TinyEdge Runtime vertical slice.

These contracts are deliberately small.  They establish identity, freshness,
action shape and local safety semantics without claiming support for a real VLA
model, transport or robot.  Unknown fields fail closed so later expansion must
use a new contract version rather than changing v1 meaning in place.
"""

from __future__ import annotations

import copy
import math
import re
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from .hashing import contract_hash


CAPABILITIES_VERSION = "tinyedge-runtime-capabilities-v1"
PLAN_VERSION = "tinyedge-runtime-plan-v1"
OBSERVATION_VERSION = "tinyedge-observation-v1"
ACTION_VERSION = "tinyedge-action-chunk-v1"
TELEMETRY_VERSION = "tinyedge-runtime-telemetry-v1"

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,127}$")
_VERSION = re.compile(r"^[a-z0-9][a-z0-9._\-]{0,63}$")
_ADAPTER_KINDS = frozenset({"sensor", "model", "robot"})
_TELEMETRY_STATES = frozenset(
    {"validated", "prepared", "armed", "running", "safe_stopped", "closed"}
)
_MAX_INT = (1 << 63) - 1
_MAX_ADAPTERS = 256
_MAX_BUNDLES = 256
_MAX_ARTIFACTS = 64
_MAX_VECTOR = 1024
_MAX_ACTION_HORIZON = 4096
_MAX_CLEANUP_FAILURES = 32
_MAX_ABS_NUMBER = 1_000_000_000_000.0
_CONSTRUCTION_VALIDATION: ContextVar[bool] = ContextVar(
    "runtime_contract_construction_validation", default=False
)


class RuntimeContractError(ValueError):
    """A Runtime contract is malformed, unsupported or tampered."""

    def __init__(self, code: str, path: str, message: str):
        self.code = code
        self.path = path
        self.message = message
        super().__init__(f"{code} at {path}: {message}")


def _object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeContractError("invalid_type", path, "must be an object")
    return value


def _exact_keys(
    value: Any,
    path: str,
    required: Iterable[str],
    optional: Iterable[str] = (),
) -> dict[str, Any]:
    obj = _object(value, path)
    required_set = set(required)
    allowed = required_set | set(optional)
    missing = sorted(required_set - set(obj))
    unknown = sorted(set(obj) - allowed)
    if missing:
        raise RuntimeContractError("missing_field", path, f"missing {missing!r}")
    if unknown:
        raise RuntimeContractError("unknown_field", path, f"unknown {unknown!r}")
    return obj


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise RuntimeContractError(
            "invalid_identifier", path, "must be a bounded non-whitespace identifier"
        )
    return value


def _version(value: Any, path: str) -> str:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise RuntimeContractError(
            "invalid_version", path, "must be a bounded lowercase version token"
        )
    return value


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise RuntimeContractError("invalid_digest", path, "must be sha256:<64 lowercase hex>")
    return value


def _integer(
    value: Any,
    path: str,
    *,
    minimum: int = 0,
    maximum: int = _MAX_INT,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        raise RuntimeContractError(
            "invalid_integer", path, f"must be an integer in [{minimum}, {maximum}]"
        )
    return value


def _optional_integer(
    value: Any,
    path: str,
    *,
    minimum: int = 0,
    maximum: int = _MAX_INT,
) -> int | None:
    if value is None:
        return None
    return _integer(value, path, minimum=minimum, maximum=maximum)


def _optional_boolean(value: Any, path: str) -> bool | None:
    if value is None or isinstance(value, bool):
        return value
    raise RuntimeContractError("invalid_boolean", path, "must be true, false, or null")


def _number(value: Any, path: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeContractError("invalid_number", path, "must be a finite number")
    try:
        result = float(value)
    except (OverflowError, ValueError):
        raise RuntimeContractError("invalid_number", path, "must be a bounded finite number")
    if not math.isfinite(result) or abs(result) > _MAX_ABS_NUMBER:
        raise RuntimeContractError(
            "invalid_number",
            path,
            f"must be finite with absolute value <= {_MAX_ABS_NUMBER:g}",
        )
    return result


def _list(
    value: Any,
    path: str,
    *,
    nonempty: bool = False,
    maximum: int = _MAX_ACTION_HORIZON,
) -> list[Any]:
    if (
        not isinstance(value, list)
        or (nonempty and not value)
        or len(value) > maximum
    ):
        qualifier = "a non-empty list" if nonempty else "a list"
        raise RuntimeContractError(
            "invalid_type", path, f"must be {qualifier} with at most {maximum} items"
        )
    return value


def _number_tuple(value: Any, path: str, *, nonempty: bool = True) -> tuple[float, ...]:
    return tuple(
        _number(item, f"{path}[{index}]")
        for index, item in enumerate(
            _list(value, path, nonempty=nonempty, maximum=_MAX_VECTOR)
        )
    )


def _validate_constructed(
    instance: Any,
    parser: Callable[[Any], Any],
) -> None:
    """Make direct dataclass construction as strict as wire parsing.

    Contract classes stay convenient immutable values, but callers cannot use
    their generated constructors to bypass the v1 parser.  The context-local
    guard prevents the parser's own constructor call from recursing.
    """

    if _CONSTRUCTION_VALIDATION.get():
        return
    try:
        payload = instance.to_dict()
    except Exception as error:
        raise RuntimeContractError(
            "invalid_direct_construction",
            type(instance).__name__,
            "fields cannot be serialized as the declared contract",
        ) from error
    token = _CONSTRUCTION_VALIDATION.set(True)
    try:
        parsed = parser(payload)
    finally:
        _CONSTRUCTION_VALIDATION.reset(token)
    if parsed != instance:
        raise RuntimeContractError(
            "noncanonical_construction",
            type(instance).__name__,
            "construct through from_dict with canonical immutable field types",
        )


@dataclass(frozen=True)
class AdapterCapability:
    kind: str
    adapter_id: str
    version: str

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any, path: str = "adapter") -> "AdapterCapability":
        obj = _exact_keys(value, path, {"kind", "adapter_id", "version"})
        kind = _identifier(obj["kind"], f"{path}.kind")
        if kind not in _ADAPTER_KINDS:
            raise RuntimeContractError(
                "unsupported_adapter_kind", f"{path}.kind", f"unsupported {kind!r}"
            )
        return cls(
            kind=kind,
            adapter_id=_identifier(obj["adapter_id"], f"{path}.adapter_id"),
            version=_version(obj["version"], f"{path}.version"),
        )

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "adapter_id": self.adapter_id, "version": self.version}

    @property
    def key(self) -> tuple[str, str, str]:
        return self.kind, self.adapter_id, self.version


@dataclass(frozen=True)
class BundleCapability:
    bundle_id: str
    bundle_digest: str

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any, path: str = "bundle") -> "BundleCapability":
        obj = _exact_keys(value, path, {"bundle_id", "bundle_digest"})
        return cls(
            bundle_id=_identifier(obj["bundle_id"], f"{path}.bundle_id"),
            bundle_digest=_digest(obj["bundle_digest"], f"{path}.bundle_digest"),
        )

    def to_dict(self) -> dict[str, str]:
        return {"bundle_id": self.bundle_id, "bundle_digest": self.bundle_digest}


@dataclass(frozen=True)
class RuntimeCapabilities:
    contract_version: str
    device_id: str
    environment_id: str
    adapters: tuple[AdapterCapability, ...]
    qualified_bundles: tuple[BundleCapability, ...]
    capability_digest: str

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any) -> "RuntimeCapabilities":
        obj = _exact_keys(
            value,
            "capabilities",
            {
                "contract_version",
                "device_id",
                "environment_id",
                "adapters",
                "qualified_bundles",
                "capability_digest",
            },
        )
        version = _identifier(obj["contract_version"], "capabilities.contract_version")
        if version != CAPABILITIES_VERSION:
            raise RuntimeContractError(
                "unsupported_contract",
                "capabilities.contract_version",
                f"expected {CAPABILITIES_VERSION!r}",
            )
        adapters = tuple(
            AdapterCapability.from_dict(item, f"capabilities.adapters[{index}]")
            for index, item in enumerate(
                _list(
                    obj["adapters"],
                    "capabilities.adapters",
                    nonempty=True,
                    maximum=_MAX_ADAPTERS,
                )
            )
        )
        bundles = tuple(
            BundleCapability.from_dict(item, f"capabilities.qualified_bundles[{index}]")
            for index, item in enumerate(
                _list(
                    obj["qualified_bundles"],
                    "capabilities.qualified_bundles",
                    nonempty=True,
                    maximum=_MAX_BUNDLES,
                )
            )
        )
        if len({adapter.key for adapter in adapters}) != len(adapters):
            raise RuntimeContractError(
                "duplicate_adapter", "capabilities.adapters", "adapter entries must be unique"
            )
        if tuple(sorted(adapters, key=lambda item: item.key)) != adapters:
            raise RuntimeContractError(
                "noncanonical_order", "capabilities.adapters", "must be sorted by kind/id/version"
            )
        bundle_keys = tuple((item.bundle_id, item.bundle_digest) for item in bundles)
        if len({item.bundle_id for item in bundles}) != len(bundles):
            raise RuntimeContractError(
                "duplicate_bundle",
                "capabilities.qualified_bundles",
                "bundle ids must be unique",
            )
        if tuple(sorted(bundle_keys)) != bundle_keys:
            raise RuntimeContractError(
                "noncanonical_order",
                "capabilities.qualified_bundles",
                "must be sorted by bundle id/digest",
            )
        result = cls(
            contract_version=version,
            device_id=_identifier(obj["device_id"], "capabilities.device_id"),
            environment_id=_identifier(
                obj["environment_id"], "capabilities.environment_id"
            ),
            adapters=adapters,
            qualified_bundles=bundles,
            capability_digest=_digest(
                obj["capability_digest"], "capabilities.capability_digest"
            ),
        )
        result.verify_digest()
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "device_id": self.device_id,
            "environment_id": self.environment_id,
            "adapters": [item.to_dict() for item in self.adapters],
            "qualified_bundles": [item.to_dict() for item in self.qualified_bundles],
            "capability_digest": self.capability_digest,
        }

    def verify_digest(self) -> None:
        expected = contract_hash(self.to_dict(), "capability_digest")
        if self.capability_digest != expected:
            raise RuntimeContractError(
                "hash_mismatch",
                "capabilities.capability_digest",
                f"expected {expected}",
            )

    @property
    def adapter_keys(self) -> frozenset[tuple[str, str, str]]:
        return frozenset(item.key for item in self.adapters)

    @property
    def bundle_digests(self) -> dict[str, str]:
        return {item.bundle_id: item.bundle_digest for item in self.qualified_bundles}


@dataclass(frozen=True)
class ArtifactRef:
    name: str
    kind: str
    digest: str

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any, path: str = "artifact") -> "ArtifactRef":
        obj = _exact_keys(value, path, {"name", "kind", "digest"})
        return cls(
            name=_identifier(obj["name"], f"{path}.name"),
            kind=_identifier(obj["kind"], f"{path}.kind"),
            digest=_digest(obj["digest"], f"{path}.digest"),
        )

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "kind": self.kind, "digest": self.digest}


@dataclass(frozen=True)
class TargetLock:
    device_id: str
    environment_id: str
    capability_digest: str

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any, path: str = "target") -> "TargetLock":
        obj = _exact_keys(
            value, path, {"device_id", "environment_id", "capability_digest"}
        )
        return cls(
            device_id=_identifier(obj["device_id"], f"{path}.device_id"),
            environment_id=_identifier(obj["environment_id"], f"{path}.environment_id"),
            capability_digest=_digest(
                obj["capability_digest"], f"{path}.capability_digest"
            ),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "device_id": self.device_id,
            "environment_id": self.environment_id,
            "capability_digest": self.capability_digest,
        }


@dataclass(frozen=True)
class SafetyPolicy:
    action_schema_id: str
    action_dimensions: int
    action_axes: tuple[str, ...]
    units: tuple[str, ...]
    lower_limits: tuple[float, ...]
    upper_limits: tuple[float, ...]
    max_observation_age_ns: int
    max_action_age_ns: int
    on_violation: str

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any, path: str = "safety") -> "SafetyPolicy":
        obj = _exact_keys(
            value,
            path,
            {
                "action_schema_id",
                "action_dimensions",
                "action_axes",
                "units",
                "lower_limits",
                "upper_limits",
                "max_observation_age_ns",
                "max_action_age_ns",
                "on_violation",
            },
        )
        dimensions = _integer(
            obj["action_dimensions"],
            f"{path}.action_dimensions",
            minimum=1,
            maximum=_MAX_VECTOR,
        )
        units = tuple(
            _identifier(item, f"{path}.units[{index}]")
            for index, item in enumerate(
                _list(obj["units"], f"{path}.units", nonempty=True, maximum=_MAX_VECTOR)
            )
        )
        axes = tuple(
            _identifier(item, f"{path}.action_axes[{index}]")
            for index, item in enumerate(
                _list(
                    obj["action_axes"],
                    f"{path}.action_axes",
                    nonempty=True,
                    maximum=_MAX_VECTOR,
                )
            )
        )
        lower = _number_tuple(obj["lower_limits"], f"{path}.lower_limits")
        upper = _number_tuple(obj["upper_limits"], f"{path}.upper_limits")
        if not (len(axes) == len(units) == len(lower) == len(upper) == dimensions):
            raise RuntimeContractError(
                "dimension_mismatch",
                path,
                "axes, units and limit arrays must match action_dimensions",
            )
        if len(set(axes)) != len(axes):
            raise RuntimeContractError(
                "duplicate_action_axis", f"{path}.action_axes", "axis names must be unique"
            )
        if any(low > high for low, high in zip(lower, upper)):
            raise RuntimeContractError(
                "invalid_limits", path, "each lower limit must be <= its upper limit"
            )
        on_violation = _identifier(obj["on_violation"], f"{path}.on_violation")
        if on_violation != "safe_stop":
            raise RuntimeContractError(
                "unsupported_safety_behavior",
                f"{path}.on_violation",
                "v1 supports only safe_stop",
            )
        return cls(
            action_schema_id=_identifier(
                obj["action_schema_id"], f"{path}.action_schema_id"
            ),
            action_dimensions=dimensions,
            action_axes=axes,
            units=units,
            lower_limits=lower,
            upper_limits=upper,
            max_observation_age_ns=_integer(
                obj["max_observation_age_ns"],
                f"{path}.max_observation_age_ns",
                minimum=1,
            ),
            max_action_age_ns=_integer(
                obj["max_action_age_ns"], f"{path}.max_action_age_ns", minimum=1
            ),
            on_violation=on_violation,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_schema_id": self.action_schema_id,
            "action_dimensions": self.action_dimensions,
            "action_axes": list(self.action_axes),
            "units": list(self.units),
            "lower_limits": list(self.lower_limits),
            "upper_limits": list(self.upper_limits),
            "max_observation_age_ns": self.max_observation_age_ns,
            "max_action_age_ns": self.max_action_age_ns,
            "on_violation": self.on_violation,
        }


@dataclass(frozen=True)
class RuntimePlan:
    contract_version: str
    plan_id: str
    bundle_id: str
    bundle_digest: str
    execution_strategy: str
    clock_domain: str
    observation_schema_id: str
    action_schema_id: str
    artifacts: tuple[ArtifactRef, ...]
    target: TargetLock
    safety: SafetyPolicy
    plan_hash: str

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any) -> "RuntimePlan":
        obj = _exact_keys(
            value,
            "plan",
            {
                "contract_version",
                "plan_id",
                "bundle_id",
                "bundle_digest",
                "execution_strategy",
                "clock_domain",
                "observation_schema_id",
                "action_schema_id",
                "artifacts",
                "target",
                "safety",
                "plan_hash",
            },
        )
        version = _identifier(obj["contract_version"], "plan.contract_version")
        if version != PLAN_VERSION:
            raise RuntimeContractError(
                "unsupported_contract", "plan.contract_version", f"expected {PLAN_VERSION!r}"
            )
        artifacts = tuple(
            ArtifactRef.from_dict(item, f"plan.artifacts[{index}]")
            for index, item in enumerate(
                _list(
                    obj["artifacts"],
                    "plan.artifacts",
                    nonempty=True,
                    maximum=_MAX_ARTIFACTS,
                )
            )
        )
        artifact_keys = tuple((item.name, item.kind, item.digest) for item in artifacts)
        if len({item.name for item in artifacts}) != len(artifacts):
            raise RuntimeContractError(
                "duplicate_artifact", "plan.artifacts", "artifact names must be unique"
            )
        if len({item.digest for item in artifacts}) != len(artifacts):
            raise RuntimeContractError(
                "duplicate_artifact_digest",
                "plan.artifacts",
                "artifact digests must be unique",
            )
        if tuple(sorted(artifact_keys)) != artifact_keys:
            raise RuntimeContractError(
                "noncanonical_order", "plan.artifacts", "must be sorted by name/kind/digest"
            )
        safety = SafetyPolicy.from_dict(obj["safety"], "plan.safety")
        action_schema_id = _identifier(obj["action_schema_id"], "plan.action_schema_id")
        if safety.action_schema_id != action_schema_id:
            raise RuntimeContractError(
                "schema_mismatch",
                "plan.safety.action_schema_id",
                "must match plan.action_schema_id",
            )
        result = cls(
            contract_version=version,
            plan_id=_identifier(obj["plan_id"], "plan.plan_id"),
            bundle_id=_identifier(obj["bundle_id"], "plan.bundle_id"),
            bundle_digest=_digest(obj["bundle_digest"], "plan.bundle_digest"),
            execution_strategy=_identifier(
                obj["execution_strategy"], "plan.execution_strategy"
            ),
            clock_domain=_identifier(obj["clock_domain"], "plan.clock_domain"),
            observation_schema_id=_identifier(
                obj["observation_schema_id"], "plan.observation_schema_id"
            ),
            action_schema_id=action_schema_id,
            artifacts=artifacts,
            target=TargetLock.from_dict(obj["target"], "plan.target"),
            safety=safety,
            plan_hash=_digest(obj["plan_hash"], "plan.plan_hash"),
        )
        result.verify_hash()
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "plan_id": self.plan_id,
            "bundle_id": self.bundle_id,
            "bundle_digest": self.bundle_digest,
            "execution_strategy": self.execution_strategy,
            "clock_domain": self.clock_domain,
            "observation_schema_id": self.observation_schema_id,
            "action_schema_id": self.action_schema_id,
            "artifacts": [item.to_dict() for item in self.artifacts],
            "target": self.target.to_dict(),
            "safety": self.safety.to_dict(),
            "plan_hash": self.plan_hash,
        }

    def verify_hash(self) -> None:
        expected = contract_hash(self.to_dict(), "plan_hash")
        if self.plan_hash != expected:
            raise RuntimeContractError("hash_mismatch", "plan.plan_hash", f"expected {expected}")

    @property
    def artifact_digests(self) -> frozenset[str]:
        return frozenset(item.digest for item in self.artifacts)


@dataclass(frozen=True)
class ObservationEnvelope:
    contract_version: str
    observation_id: str
    sequence: int
    captured_monotonic_ns: int
    received_monotonic_ns: int
    clock_domain: str
    observation_schema_id: str
    sensor_values: tuple[float, ...]
    robot_state: tuple[float, ...]

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any) -> "ObservationEnvelope":
        obj = _exact_keys(
            value,
            "observation",
            {
                "contract_version",
                "observation_id",
                "sequence",
                "captured_monotonic_ns",
                "received_monotonic_ns",
                "clock_domain",
                "observation_schema_id",
                "sensor_values",
                "robot_state",
            },
        )
        version = _identifier(obj["contract_version"], "observation.contract_version")
        if version != OBSERVATION_VERSION:
            raise RuntimeContractError(
                "unsupported_contract",
                "observation.contract_version",
                f"expected {OBSERVATION_VERSION!r}",
            )
        captured = _integer(
            obj["captured_monotonic_ns"], "observation.captured_monotonic_ns"
        )
        received = _integer(
            obj["received_monotonic_ns"], "observation.received_monotonic_ns"
        )
        if received < captured:
            raise RuntimeContractError(
                "invalid_timestamp_order",
                "observation.received_monotonic_ns",
                "must be >= captured_monotonic_ns",
            )
        return cls(
            contract_version=version,
            observation_id=_identifier(obj["observation_id"], "observation.observation_id"),
            sequence=_integer(obj["sequence"], "observation.sequence"),
            captured_monotonic_ns=captured,
            received_monotonic_ns=received,
            clock_domain=_identifier(obj["clock_domain"], "observation.clock_domain"),
            observation_schema_id=_identifier(
                obj["observation_schema_id"], "observation.observation_schema_id"
            ),
            sensor_values=_number_tuple(
                obj["sensor_values"], "observation.sensor_values"
            ),
            robot_state=_number_tuple(obj["robot_state"], "observation.robot_state"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "observation_id": self.observation_id,
            "sequence": self.sequence,
            "captured_monotonic_ns": self.captured_monotonic_ns,
            "received_monotonic_ns": self.received_monotonic_ns,
            "clock_domain": self.clock_domain,
            "observation_schema_id": self.observation_schema_id,
            "sensor_values": list(self.sensor_values),
            "robot_state": list(self.robot_state),
        }


@dataclass(frozen=True)
class ActionChunk:
    contract_version: str
    action_id: str
    source_observation_id: str
    action_schema_id: str
    action_axes: tuple[str, ...]
    units: tuple[str, ...]
    clock_domain: str
    created_monotonic_ns: int
    valid_from_monotonic_ns: int
    expires_at_monotonic_ns: int
    action_period_ns: int
    values: tuple[tuple[float, ...], ...]
    model_artifact_digest: str
    committed_prefix: int

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any) -> "ActionChunk":
        obj = _exact_keys(
            value,
            "action",
            {
                "contract_version",
                "action_id",
                "source_observation_id",
                "action_schema_id",
                "action_axes",
                "units",
                "clock_domain",
                "created_monotonic_ns",
                "valid_from_monotonic_ns",
                "expires_at_monotonic_ns",
                "action_period_ns",
                "values",
                "model_artifact_digest",
                "committed_prefix",
            },
        )
        version = _identifier(obj["contract_version"], "action.contract_version")
        if version != ACTION_VERSION:
            raise RuntimeContractError(
                "unsupported_contract",
                "action.contract_version",
                f"expected {ACTION_VERSION!r}",
            )
        created = _integer(obj["created_monotonic_ns"], "action.created_monotonic_ns")
        valid_from = _integer(
            obj["valid_from_monotonic_ns"], "action.valid_from_monotonic_ns"
        )
        expires = _integer(
            obj["expires_at_monotonic_ns"], "action.expires_at_monotonic_ns"
        )
        if not created <= valid_from < expires:
            raise RuntimeContractError(
                "invalid_timestamp_order",
                "action",
                "requires created <= valid_from < expires",
            )
        rows = _list(
            obj["values"],
            "action.values",
            nonempty=True,
            maximum=_MAX_ACTION_HORIZON,
        )
        values = tuple(
            _number_tuple(row, f"action.values[{index}]") for index, row in enumerate(rows)
        )
        dimensions = {len(row) for row in values}
        if len(dimensions) != 1:
            raise RuntimeContractError(
                "dimension_mismatch", "action.values", "every action row must have equal width"
            )
        axes = tuple(
            _identifier(item, f"action.action_axes[{index}]")
            for index, item in enumerate(
                _list(
                    obj["action_axes"],
                    "action.action_axes",
                    nonempty=True,
                    maximum=_MAX_VECTOR,
                )
            )
        )
        units = tuple(
            _identifier(item, f"action.units[{index}]")
            for index, item in enumerate(
                _list(obj["units"], "action.units", nonempty=True, maximum=_MAX_VECTOR)
            )
        )
        width = next(iter(dimensions))
        if len(axes) != width or len(units) != width:
            raise RuntimeContractError(
                "dimension_mismatch",
                "action",
                "axis and unit arrays must match the action width",
            )
        if len(set(axes)) != len(axes):
            raise RuntimeContractError(
                "duplicate_action_axis", "action.action_axes", "axis names must be unique"
            )
        committed = _integer(
            obj["committed_prefix"],
            "action.committed_prefix",
            maximum=len(values),
        )
        action_period = _integer(
            obj["action_period_ns"], "action.action_period_ns", minimum=1
        )
        last_action_time = valid_from + (len(values) - 1) * action_period
        if last_action_time > _MAX_INT or last_action_time >= expires:
            raise RuntimeContractError(
                "action_horizon_exceeds_expiry",
                "action.values",
                "every scheduled action must occur before expires_at_monotonic_ns",
            )
        return cls(
            contract_version=version,
            action_id=_identifier(obj["action_id"], "action.action_id"),
            source_observation_id=_identifier(
                obj["source_observation_id"], "action.source_observation_id"
            ),
            action_schema_id=_identifier(
                obj["action_schema_id"], "action.action_schema_id"
            ),
            action_axes=axes,
            units=units,
            clock_domain=_identifier(obj["clock_domain"], "action.clock_domain"),
            created_monotonic_ns=created,
            valid_from_monotonic_ns=valid_from,
            expires_at_monotonic_ns=expires,
            action_period_ns=action_period,
            values=values,
            model_artifact_digest=_digest(
                obj["model_artifact_digest"], "action.model_artifact_digest"
            ),
            committed_prefix=committed,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "action_id": self.action_id,
            "source_observation_id": self.source_observation_id,
            "action_schema_id": self.action_schema_id,
            "action_axes": list(self.action_axes),
            "units": list(self.units),
            "clock_domain": self.clock_domain,
            "created_monotonic_ns": self.created_monotonic_ns,
            "valid_from_monotonic_ns": self.valid_from_monotonic_ns,
            "expires_at_monotonic_ns": self.expires_at_monotonic_ns,
            "action_period_ns": self.action_period_ns,
            "values": [list(row) for row in self.values],
            "model_artifact_digest": self.model_artifact_digest,
            "committed_prefix": self.committed_prefix,
        }


@dataclass(frozen=True)
class RuntimeTelemetrySummary:
    contract_version: str
    plan_hash: str
    state: str
    steps_attempted: int
    steps_succeeded: int
    rejected_actions: int
    stale_observations: int
    safe_stop_count: int
    safe_stop_confirmed: bool | None
    last_stop_reason: str | None
    cleanup_failures: tuple[str, ...]
    last_observation_age_ns: int | None
    last_action_age_ns: int | None
    last_inference_ns: int | None

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any) -> "RuntimeTelemetrySummary":
        obj = _exact_keys(
            value,
            "telemetry",
            {
                "contract_version",
                "plan_hash",
                "state",
                "steps_attempted",
                "steps_succeeded",
                "rejected_actions",
                "stale_observations",
                "safe_stop_count",
                "safe_stop_confirmed",
                "last_stop_reason",
                "cleanup_failures",
                "last_observation_age_ns",
                "last_action_age_ns",
                "last_inference_ns",
            },
        )
        version = _identifier(obj["contract_version"], "telemetry.contract_version")
        if version != TELEMETRY_VERSION:
            raise RuntimeContractError(
                "unsupported_contract",
                "telemetry.contract_version",
                f"expected {TELEMETRY_VERSION!r}",
            )
        state = _identifier(obj["state"], "telemetry.state")
        if state not in _TELEMETRY_STATES:
            raise RuntimeContractError(
                "unsupported_state", "telemetry.state", f"unsupported {state!r}"
            )
        stop_reason = obj["last_stop_reason"]
        if stop_reason is not None:
            stop_reason = _identifier(stop_reason, "telemetry.last_stop_reason")
        cleanup_failures = tuple(
            _identifier(item, f"telemetry.cleanup_failures[{index}]")
            for index, item in enumerate(
                _list(
                    obj["cleanup_failures"],
                    "telemetry.cleanup_failures",
                    maximum=_MAX_CLEANUP_FAILURES,
                )
            )
        )
        if len(set(cleanup_failures)) != len(cleanup_failures):
            raise RuntimeContractError(
                "duplicate_cleanup_failure",
                "telemetry.cleanup_failures",
                "failure codes must be unique",
            )
        result = cls(
            contract_version=version,
            plan_hash=_digest(obj["plan_hash"], "telemetry.plan_hash"),
            state=state,
            steps_attempted=_integer(obj["steps_attempted"], "telemetry.steps_attempted"),
            steps_succeeded=_integer(obj["steps_succeeded"], "telemetry.steps_succeeded"),
            rejected_actions=_integer(obj["rejected_actions"], "telemetry.rejected_actions"),
            stale_observations=_integer(
                obj["stale_observations"], "telemetry.stale_observations"
            ),
            safe_stop_count=_integer(
                obj["safe_stop_count"],
                "telemetry.safe_stop_count",
                maximum=1,
            ),
            safe_stop_confirmed=_optional_boolean(
                obj["safe_stop_confirmed"], "telemetry.safe_stop_confirmed"
            ),
            last_stop_reason=stop_reason,
            cleanup_failures=cleanup_failures,
            last_observation_age_ns=_optional_integer(
                obj["last_observation_age_ns"], "telemetry.last_observation_age_ns"
            ),
            last_action_age_ns=_optional_integer(
                obj["last_action_age_ns"], "telemetry.last_action_age_ns"
            ),
            last_inference_ns=_optional_integer(
                obj["last_inference_ns"], "telemetry.last_inference_ns"
            ),
        )
        if result.steps_succeeded > result.steps_attempted:
            raise RuntimeContractError(
                "invalid_counter",
                "telemetry.steps_succeeded",
                "cannot exceed steps_attempted",
            )
        if result.rejected_actions > result.steps_attempted:
            raise RuntimeContractError(
                "invalid_counter",
                "telemetry.rejected_actions",
                "cannot exceed steps_attempted",
            )
        if result.stale_observations > result.steps_attempted:
            raise RuntimeContractError(
                "invalid_counter",
                "telemetry.stale_observations",
                "cannot exceed steps_attempted",
            )
        if (
            result.steps_succeeded
            + result.rejected_actions
            + result.stale_observations
            > result.steps_attempted
        ):
            raise RuntimeContractError(
                "invalid_counter",
                "telemetry",
                "success, rejection and stale outcomes cannot exceed attempted steps",
            )
        if result.safe_stop_count == 0 and (
            result.safe_stop_confirmed is not None or result.last_stop_reason is not None
        ):
            raise RuntimeContractError(
                "invalid_stop_summary",
                "telemetry.safe_stop_count",
                "zero attempts require null confirmation and reason",
            )
        if result.safe_stop_count == 1 and (
            result.safe_stop_confirmed is None or result.last_stop_reason is None
        ):
            raise RuntimeContractError(
                "invalid_stop_summary",
                "telemetry.safe_stop_count",
                "one attempt requires a confirmation result and reason code",
            )
        if result.state == "safe_stopped" and (
            result.safe_stop_count != 1 or result.safe_stop_confirmed is not True
        ):
            raise RuntimeContractError(
                "invalid_stop_summary",
                "telemetry.state",
                "safe_stopped requires one confirmed stop",
            )
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "plan_hash": self.plan_hash,
            "state": self.state,
            "steps_attempted": self.steps_attempted,
            "steps_succeeded": self.steps_succeeded,
            "rejected_actions": self.rejected_actions,
            "stale_observations": self.stale_observations,
            "safe_stop_count": self.safe_stop_count,
            "safe_stop_confirmed": self.safe_stop_confirmed,
            "last_stop_reason": self.last_stop_reason,
            "cleanup_failures": list(self.cleanup_failures),
            "last_observation_age_ns": self.last_observation_age_ns,
            "last_action_age_ns": self.last_action_age_ns,
            "last_inference_ns": self.last_inference_ns,
        }


def seal_runtime_capabilities(value: dict[str, Any]) -> dict[str, Any]:
    """Canonicalize, hash and validate a capabilities document."""

    sealed = copy.deepcopy(value)
    sealed.setdefault("contract_version", CAPABILITIES_VERSION)
    if isinstance(sealed.get("adapters"), list):
        sealed["adapters"] = sorted(
            sealed["adapters"],
            key=lambda item: (
                str(item.get("kind", "")),
                str(item.get("adapter_id", "")),
                str(item.get("version", "")),
            ),
        )
    if isinstance(sealed.get("qualified_bundles"), list):
        sealed["qualified_bundles"] = sorted(
            sealed["qualified_bundles"],
            key=lambda item: (
                str(item.get("bundle_id", "")), str(item.get("bundle_digest", ""))
            ),
        )
    sealed["capability_digest"] = contract_hash(sealed, "capability_digest")
    return RuntimeCapabilities.from_dict(sealed).to_dict()


def seal_runtime_plan(value: dict[str, Any]) -> dict[str, Any]:
    """Canonicalize, hash and validate a Runtime plan."""

    sealed = copy.deepcopy(value)
    sealed.setdefault("contract_version", PLAN_VERSION)
    if isinstance(sealed.get("artifacts"), list):
        sealed["artifacts"] = sorted(
            sealed["artifacts"],
            key=lambda item: (
                str(item.get("name", "")),
                str(item.get("kind", "")),
                str(item.get("digest", "")),
            ),
        )
    sealed["plan_hash"] = contract_hash(sealed, "plan_hash")
    return RuntimePlan.from_dict(sealed).to_dict()


__all__ = [
    "ACTION_VERSION",
    "CAPABILITIES_VERSION",
    "OBSERVATION_VERSION",
    "PLAN_VERSION",
    "TELEMETRY_VERSION",
    "ActionChunk",
    "AdapterCapability",
    "ArtifactRef",
    "BundleCapability",
    "ObservationEnvelope",
    "RuntimeCapabilities",
    "RuntimeContractError",
    "RuntimePlan",
    "RuntimeTelemetrySummary",
    "SafetyPolicy",
    "TargetLock",
    "seal_runtime_capabilities",
    "seal_runtime_plan",
]
