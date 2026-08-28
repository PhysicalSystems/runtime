from __future__ import annotations

from typing import Any

import pytest

from tinyedge_runtime import (
    ActionChunk,
    AdapterCapability,
    ArtifactRef,
    ObservationEnvelope,
    RuntimeCapabilities,
    RuntimeExecutionError,
    RuntimePlan,
    RuntimeRegistry,
    RuntimeSession,
    RuntimeState,
    SafetyPolicy,
    seal_runtime_capabilities,
    seal_runtime_plan,
)
from tinyedge_runtime.registry import QualifiedBundle
from tinyedge_runtime.testing import FakeClock, FakeModel, FakeRobot, FakeSensor


ARTIFACT_DIGEST = "sha256:" + "1" * 64
OTHER_ARTIFACT_DIGEST = "sha256:" + "2" * 64


def _plan(
    bundle: QualifiedBundle,
    capabilities: RuntimeCapabilities,
    *,
    max_observation_age_ns: int = 100,
    max_action_age_ns: int = 100,
) -> RuntimePlan:
    return RuntimePlan.from_dict(
        seal_runtime_plan(
            {
                "plan_id": "safety-plan",
                "bundle_id": "fake-local-sync",
                "bundle_digest": bundle.compatibility_digest,
                "execution_strategy": "local_sync_v1",
                "clock_domain": "host_monotonic",
                "observation_schema_id": "fake-observation-v1",
                "action_schema_id": "joint-position-v1",
                "artifacts": [
                    {
                        "name": "fake-policy",
                        "kind": "model",
                        "digest": ARTIFACT_DIGEST,
                    }
                ],
                "target": {
                    "device_id": "fake-device",
                    "environment_id": "offline-test",
                    "capability_digest": capabilities.capability_digest,
                },
                "safety": {
                    "action_schema_id": "joint-position-v1",
                    "action_dimensions": 2,
                    "action_axes": ["joint_1", "joint_2"],
                    "units": ["radian", "radian"],
                    "lower_limits": [-1.0, -1.0],
                    "upper_limits": [1.0, 1.0],
                    "max_observation_age_ns": max_observation_age_ns,
                    "max_action_age_ns": max_action_age_ns,
                    "on_violation": "safe_stop",
                },
            }
        )
    )


def _observation(**overrides: Any) -> ObservationEnvelope:
    value: dict[str, Any] = {
        "contract_version": "tinyedge-observation-v1",
        "observation_id": "observation-1",
        "sequence": 1,
        "captured_monotonic_ns": 950,
        "received_monotonic_ns": 975,
        "clock_domain": "host_monotonic",
        "observation_schema_id": "fake-observation-v1",
        "sensor_values": [0.25, 0.5],
        "robot_state": [0.0, 0.0],
    }
    value.update(overrides)
    return ObservationEnvelope.from_dict(value)


def _bundle() -> QualifiedBundle:
    return QualifiedBundle(
        bundle_id="fake-local-sync",
        execution_strategy="local_sync_v1",
        clock_domain="host_monotonic",
        observation_schema_id="fake-observation-v1",
        action_schema_id="joint-position-v1",
        action_axes=("joint_1", "joint_2"),
        action_units=("radian", "radian"),
        safety_envelope=SafetyPolicy.from_dict(
            {
                "action_schema_id": "joint-position-v1",
                "action_dimensions": 2,
                "action_axes": ["joint_1", "joint_2"],
                "units": ["radian", "radian"],
                "lower_limits": [-1.0, -1.0],
                "upper_limits": [1.0, 1.0],
                "max_observation_age_ns": 100,
                "max_action_age_ns": 100,
                "on_violation": "safe_stop",
            }
        ),
        sensor=AdapterCapability("sensor", "fake_sensor", "1.0"),
        model=AdapterCapability("model", "fake_model", "1.0"),
        robot=AdapterCapability("robot", "fake_robot", "1.0"),
        required_artifacts=(ArtifactRef("fake-policy", "model", ARTIFACT_DIGEST),),
    )


def _capabilities(bundle: QualifiedBundle) -> RuntimeCapabilities:
    return RuntimeCapabilities.from_dict(
        seal_runtime_capabilities(
            {
                "device_id": "fake-device",
                "environment_id": "offline-test",
                "adapters": [item.to_dict() for item in bundle.adapter_requirements],
                "qualified_bundles": [
                    {
                        "bundle_id": bundle.bundle_id,
                        "bundle_digest": bundle.compatibility_digest,
                    }
                ],
            }
        )
    )


def _action(
    observation: ObservationEnvelope,
    now_ns: int,
    **overrides: Any,
) -> ActionChunk:
    axes = list(overrides.pop("action_axes", ["joint_1", "joint_2"]))
    units = list(overrides.pop("units", ["radian"] * len(axes)))
    values = overrides.pop("values", [[0.1] * len(axes), [0.2] * len(axes)])
    value: dict[str, Any] = {
        "contract_version": "tinyedge-action-chunk-v1",
        "action_id": "action-1",
        "source_observation_id": observation.observation_id,
        "action_schema_id": "joint-position-v1",
        "action_axes": axes,
        "units": units,
        "clock_domain": "host_monotonic",
        "created_monotonic_ns": now_ns,
        "valid_from_monotonic_ns": now_ns,
        "expires_at_monotonic_ns": now_ns + 100,
        "action_period_ns": 1,
        "values": values,
        "model_artifact_digest": ARTIFACT_DIGEST,
        "committed_prefix": 0,
    }
    value.update(overrides)
    return ActionChunk.from_dict(value)


def _armed_session(
    *,
    observation: ObservationEnvelope | None = None,
    action_overrides: dict[str, Any] | None = None,
    clock: Any | None = None,
    max_action_age_ns: int = 100,
    inference_ns: int = 0,
) -> tuple[RuntimeSession, FakeSensor, FakeModel, FakeRobot, Any]:
    runtime_clock = clock or FakeClock(1_000)
    bundle = _bundle()
    capabilities = _capabilities(bundle)
    runtime_plan = _plan(
        bundle,
        capabilities,
        max_action_age_ns=max_action_age_ns,
    )
    sensor = FakeSensor([observation or _observation()])

    def action_factory(observed: ObservationEnvelope, now_ns: int) -> ActionChunk:
        return _action(observed, now_ns, **(action_overrides or {}))

    model = FakeModel(
        ARTIFACT_DIGEST,
        runtime_clock,
        action_factory,
        inference_ns=inference_ns,
    )
    robot = FakeRobot()
    registry = RuntimeRegistry()
    registry.register_sensor(sensor)
    registry.register_model(model)
    registry.register_robot(robot)
    registry.register_bundle(bundle)
    resolved = registry.resolve(runtime_plan, capabilities)
    session = RuntimeSession(resolved, runtime_clock)
    session.prepare()
    session.arm()
    return session, sensor, model, robot, runtime_clock


@pytest.mark.parametrize(
    ("action_overrides", "max_action_age_ns", "expected_code"),
    [
        ({"action_axes": ["joint_2", "joint_1"]}, 100, "action_axes_mismatch"),
        ({"units": ["degree", "degree"]}, 100, "action_units_mismatch"),
        ({"clock_domain": "device_clock"}, 100, "action_clock_mismatch"),
        ({"source_observation_id": "observation-other"}, 100, "action_source_mismatch"),
        ({"action_schema_id": "velocity-v1"}, 100, "action_schema_mismatch"),
        (
            {"model_artifact_digest": OTHER_ARTIFACT_DIGEST},
            100,
            "action_artifact_mismatch",
        ),
        ({"values": [[1.01, 0.0]]}, 100, "action_limit_exceeded"),
        (
            {
                "created_monotonic_ns": 975,
                "valid_from_monotonic_ns": 975,
                "expires_at_monotonic_ns": 1_100,
            },
            20,
            "action_age_exceeded",
        ),
        (
            {
                "created_monotonic_ns": 975,
                "valid_from_monotonic_ns": 975,
                "expires_at_monotonic_ns": 1_000,
            },
            100,
            "action_expired",
        ),
        (
            {
                "created_monotonic_ns": 1_001,
                "valid_from_monotonic_ns": 1_001,
                "expires_at_monotonic_ns": 1_100,
            },
            100,
            "action_from_future",
        ),
    ],
)
def test_action_contract_mismatch_or_freshness_violation_never_reaches_robot(
    action_overrides: dict[str, Any],
    max_action_age_ns: int,
    expected_code: str,
):
    session, _sensor, _model, robot, _clock = _armed_session(
        action_overrides=action_overrides,
        max_action_age_ns=max_action_age_ns,
    )

    with pytest.raises(RuntimeExecutionError) as raised:
        session.step()

    assert raised.value.code == expected_code
    assert robot.applied == []
    assert robot.safe_stop_calls == 1
    assert not robot.armed
    assert session.actions_fenced is True
    assert session.state is RuntimeState.CLOSED
    assert session.telemetry.rejected_actions == 1


@pytest.mark.parametrize(
    ("observation", "expected_code", "expected_stale_count"),
    [
        (
            _observation(observation_schema_id="other-observation-v1"),
            "observation_schema_mismatch",
            0,
        ),
        (
            _observation(clock_domain="device_clock"),
            "observation_clock_mismatch",
            0,
        ),
        (
            _observation(
                captured_monotonic_ns=1_001,
                received_monotonic_ns=1_001,
            ),
            "observation_from_future",
            0,
        ),
        (
            _observation(captured_monotonic_ns=800, received_monotonic_ns=900),
            "observation_age_exceeded",
            1,
        ),
    ],
)
def test_invalid_or_stale_observation_never_runs_model_or_robot(
    observation: ObservationEnvelope,
    expected_code: str,
    expected_stale_count: int,
):
    session, _sensor, model, robot, _clock = _armed_session(
        observation=observation
    )

    with pytest.raises(RuntimeExecutionError) as raised:
        session.step()

    assert raised.value.code == expected_code
    assert model.predict_count == 0
    assert robot.applied == []
    assert robot.safe_stop_calls == 1
    assert not robot.armed
    assert session.state is RuntimeState.CLOSED
    assert session.telemetry.stale_observations == expected_stale_count


class _RegressingClock:
    def __init__(self):
        self.values = iter([1_000, 999])

    def monotonic_ns(self) -> int:
        return next(self.values)

    def advance(self, _delta_ns: int) -> int:
        raise AssertionError("model must not run after a clock regression")


def test_clock_regression_fails_closed_before_model_or_robot_output():
    session, _sensor, model, robot, _clock = _armed_session(
        clock=_RegressingClock()
    )

    with pytest.raises(RuntimeExecutionError) as raised:
        session.step()

    assert raised.value.code == "clock_regression"
    assert model.predict_count == 0
    assert robot.applied == []
    assert robot.safe_stop_calls == 1
    assert session.state is RuntimeState.CLOSED


@pytest.mark.parametrize("invalid_clock_value", [True, -1, 1.5])
def test_invalid_monotonic_clock_value_fails_closed(invalid_clock_value: object):
    class InvalidClock:
        def monotonic_ns(self) -> object:
            return invalid_clock_value

        def advance(self, _delta_ns: int) -> int:
            raise AssertionError("model must not run with an invalid clock")

    session, _sensor, model, robot, _clock = _armed_session(clock=InvalidClock())

    with pytest.raises(RuntimeExecutionError) as raised:
        session.step()

    assert raised.value.code == "invalid_clock"
    assert model.predict_count == 0
    assert robot.applied == []
    assert robot.safe_stop_calls == 1
    assert session.state is RuntimeState.CLOSED


def test_declared_limit_boundaries_and_exact_axes_units_are_accepted():
    session, _sensor, _model, robot, _clock = _armed_session(
        action_overrides={
            "action_axes": ["joint_1", "joint_2"],
            "units": ["radian", "radian"],
            "values": [[-1.0, 1.0]],
        }
    )

    action = session.step()

    assert robot.applied == [action]
    assert robot.safe_stop_calls == 0
    session.close()
    assert robot.safe_stop_calls == 1
    assert not robot.armed


def test_observation_that_becomes_stale_during_inference_never_reaches_output():
    session, _sensor, _model, robot, _clock = _armed_session(inference_ns=60)

    with pytest.raises(RuntimeExecutionError) as raised:
        session.step()

    assert raised.value.code == "observation_age_exceeded"
    assert robot.applied == []
    assert robot.safe_stop_calls == 1
    assert session.telemetry.stale_observations == 1
    assert session.telemetry.last_observation_age_ns == 110
