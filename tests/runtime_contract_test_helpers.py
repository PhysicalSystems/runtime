"""Small deterministic builders shared by the Runtime v1 contract tests."""

from __future__ import annotations

from typing import Any

from tinyedge_runtime.contracts import (
    ACTION_VERSION,
    OBSERVATION_VERSION,
    TELEMETRY_VERSION,
    AdapterCapability,
    ArtifactRef,
    RuntimeCapabilities,
    RuntimePlan,
    SafetyPolicy,
    seal_runtime_capabilities,
    seal_runtime_plan,
)
from tinyedge_runtime.registry import QualifiedBundle, RuntimeRegistry


MODEL_DIGEST = "sha256:" + "a" * 64
PLACEHOLDER_DIGEST = "sha256:" + "0" * 64


def make_bundle(**overrides: Any) -> QualifiedBundle:
    values: dict[str, Any] = {
        "bundle_id": "fake_local_sync",
        "execution_strategy": "local_sync_v1",
        "clock_domain": "runtime_monotonic",
        "observation_schema_id": "fake_observation_v1",
        "action_schema_id": "fake_action_v1",
        "action_axes": ("joint_0", "joint_1"),
        "action_units": ("rad", "rad"),
        "safety_envelope": SafetyPolicy.from_dict(
            {
                "action_schema_id": "fake_action_v1",
                "action_dimensions": 2,
                "action_axes": ["joint_0", "joint_1"],
                "units": ["rad", "rad"],
                "lower_limits": [-1.0, -2.0],
                "upper_limits": [1.0, 2.0],
                "max_observation_age_ns": 1_000,
                "max_action_age_ns": 1_000,
                "on_violation": "safe_stop",
            }
        ),
        "sensor": AdapterCapability.from_dict(
            {"kind": "sensor", "adapter_id": "fake_sensor", "version": "1.0"}
        ),
        "model": AdapterCapability.from_dict(
            {"kind": "model", "adapter_id": "fake_model", "version": "1.0"}
        ),
        "robot": AdapterCapability.from_dict(
            {"kind": "robot", "adapter_id": "fake_robot", "version": "1.0"}
        ),
        "required_artifacts": (
            ArtifactRef.from_dict(
                {"name": "policy", "kind": "model", "digest": MODEL_DIGEST}
            ),
        ),
    }
    values.update(overrides)
    return QualifiedBundle(**values)


def make_capabilities(bundle: QualifiedBundle | None = None) -> RuntimeCapabilities:
    bundle = bundle or make_bundle()
    return RuntimeCapabilities.from_dict(
        seal_runtime_capabilities(
            {
                "device_id": "test_device",
                "environment_id": "test_environment",
                # Deliberately unsorted: sealing owns canonical set ordering.
                "adapters": [
                    bundle.sensor.to_dict(),
                    bundle.robot.to_dict(),
                    bundle.model.to_dict(),
                ],
                "qualified_bundles": [
                    {
                        "bundle_id": bundle.bundle_id,
                        "bundle_digest": bundle.compatibility_digest,
                    }
                ],
            }
        )
    )


def make_plan_dict(
    bundle: QualifiedBundle | None = None,
    capabilities: RuntimeCapabilities | None = None,
    *,
    artifacts: list[dict[str, Any]] | None = None,
    safety_overrides: dict[str, Any] | None = None,
    plan_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    bundle = bundle or make_bundle()
    capabilities = capabilities or make_capabilities(bundle)
    safety: dict[str, Any] = {
        "action_schema_id": bundle.action_schema_id,
        "action_dimensions": 2,
        "action_axes": ["joint_0", "joint_1"],
        "units": ["rad", "rad"],
        "lower_limits": [-1.0, -2.0],
        "upper_limits": [1.0, 2.0],
        "max_observation_age_ns": 1_000,
        "max_action_age_ns": 1_000,
        "on_violation": "safe_stop",
    }
    safety.update(safety_overrides or {})
    plan: dict[str, Any] = {
        "plan_id": "fake_plan",
        "bundle_id": bundle.bundle_id,
        "bundle_digest": bundle.compatibility_digest,
        "execution_strategy": bundle.execution_strategy,
        "clock_domain": bundle.clock_domain,
        "observation_schema_id": bundle.observation_schema_id,
        "action_schema_id": bundle.action_schema_id,
        "artifacts": artifacts
        if artifacts is not None
        else [{"name": "policy", "kind": "model", "digest": MODEL_DIGEST}],
        "target": {
            "device_id": capabilities.device_id,
            "environment_id": capabilities.environment_id,
            "capability_digest": capabilities.capability_digest,
        },
        "safety": safety,
    }
    plan.update(plan_overrides or {})
    return seal_runtime_plan(plan)


def make_plan(
    bundle: QualifiedBundle | None = None,
    capabilities: RuntimeCapabilities | None = None,
    **kwargs: Any,
) -> RuntimePlan:
    return RuntimePlan.from_dict(make_plan_dict(bundle, capabilities, **kwargs))


def make_observation_dict(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "contract_version": OBSERVATION_VERSION,
        "observation_id": "observation_0",
        "sequence": 0,
        "captured_monotonic_ns": 100,
        "received_monotonic_ns": 110,
        "clock_domain": "runtime_monotonic",
        "observation_schema_id": "fake_observation_v1",
        "sensor_values": [0.25, 0.5],
        "robot_state": [0.0, 0.0],
    }
    value.update(overrides)
    return value


def make_action_dict(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "contract_version": ACTION_VERSION,
        "action_id": "action_0",
        "source_observation_id": "observation_0",
        "action_schema_id": "fake_action_v1",
        "action_axes": ["joint_0", "joint_1"],
        "units": ["rad", "rad"],
        "clock_domain": "runtime_monotonic",
        "created_monotonic_ns": 120,
        "valid_from_monotonic_ns": 120,
        "expires_at_monotonic_ns": 151,
        "action_period_ns": 10,
        "values": [[0.1, -0.1], [0.2, -0.2], [0.3, -0.3]],
        "model_artifact_digest": MODEL_DIGEST,
        "committed_prefix": 0,
    }
    value.update(overrides)
    return value


def make_telemetry_dict(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "contract_version": TELEMETRY_VERSION,
        "plan_hash": PLACEHOLDER_DIGEST,
        "state": "closed",
        "steps_attempted": 1,
        "steps_succeeded": 1,
        "rejected_actions": 0,
        "stale_observations": 0,
        "safe_stop_count": 1,
        "safe_stop_confirmed": True,
        "last_stop_reason": "closed",
        "cleanup_failures": [],
        "last_observation_age_ns": 10,
        "last_action_age_ns": 5,
        "last_inference_ns": 2,
    }
    value.update(overrides)
    return value


class TrackingSensor:
    adapter_id = "fake_sensor"
    version = "1.0"

    def __init__(self) -> None:
        self.calls: list[str] = []

    def open(self, _plan: RuntimePlan) -> None:
        self.calls.append("open")

    def read(self):
        self.calls.append("read")
        raise AssertionError("resolve must not read the sensor")

    def close(self) -> None:
        self.calls.append("close")


class TrackingModel:
    adapter_id = "fake_model"
    version = "1.0"
    artifact_digest = MODEL_DIGEST

    def __init__(self) -> None:
        self.calls: list[str] = []

    def open(self, _plan: RuntimePlan) -> None:
        self.calls.append("open")

    def predict(self, _observation):
        self.calls.append("predict")
        raise AssertionError("resolve must not invoke the model")

    def close(self) -> None:
        self.calls.append("close")


class TrackingRobot:
    adapter_id = "fake_robot"
    version = "1.0"

    def __init__(self) -> None:
        self.calls: list[str] = []

    def open(self, _plan: RuntimePlan) -> None:
        self.calls.append("open")

    def arm(self, _plan: RuntimePlan) -> None:
        self.calls.append("arm")

    def apply_chunk(self, _action) -> None:
        self.calls.append("apply_chunk")

    def safe_stop(self, _reason: str) -> None:
        self.calls.append("safe_stop")

    def close(self) -> None:
        self.calls.append("close")


def make_registry(
    bundle: QualifiedBundle | None = None,
) -> tuple[RuntimeRegistry, TrackingSensor, TrackingModel, TrackingRobot]:
    bundle = bundle or make_bundle()
    registry = RuntimeRegistry()
    sensor = TrackingSensor()
    model = TrackingModel()
    robot = TrackingRobot()
    registry.register_sensor(sensor)
    registry.register_model(model)
    registry.register_robot(robot)
    registry.register_bundle(bundle)
    return registry, sensor, model, robot
