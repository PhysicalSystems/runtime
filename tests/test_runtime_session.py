from __future__ import annotations

from typing import Any

import pytest

from tinyedge_runtime import (
    ActionChunk,
    AdapterCapability,
    ArtifactRef,
    ObservationEnvelope,
    RuntimeCleanupError,
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


ARTIFACT_DIGEST = "sha256:" + "a" * 64


def _plan(
    bundle: QualifiedBundle,
    capabilities: RuntimeCapabilities,
) -> RuntimePlan:
    return RuntimePlan.from_dict(
        seal_runtime_plan(
            {
                "plan_id": "session-plan",
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
                    "max_observation_age_ns": 100,
                    "max_action_age_ns": 100,
                    "on_violation": "safe_stop",
                },
            }
        )
    )


def _observation() -> ObservationEnvelope:
    return ObservationEnvelope.from_dict(
        {
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
    )


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


def _action(observation: ObservationEnvelope, now_ns: int) -> ActionChunk:
    return ActionChunk.from_dict(
        {
            "contract_version": "tinyedge-action-chunk-v1",
            "action_id": "action-1",
            "source_observation_id": observation.observation_id,
            "action_schema_id": "joint-position-v1",
            "action_axes": ["joint_1", "joint_2"],
            "units": ["radian", "radian"],
            "clock_domain": "host_monotonic",
            "created_monotonic_ns": now_ns,
            "valid_from_monotonic_ns": now_ns,
            "expires_at_monotonic_ns": now_ns + 100,
            "action_period_ns": 1,
            "values": [[0.1, -0.1], [0.2, -0.2]],
            "model_artifact_digest": ARTIFACT_DIGEST,
            "committed_prefix": 0,
        }
    )


def _session(
    *,
    observations: list[ObservationEnvelope] | None = None,
    sensor_options: dict[str, Any] | None = None,
    model_options: dict[str, Any] | None = None,
    robot_options: dict[str, Any] | None = None,
    cancellation: object | None = None,
) -> tuple[RuntimeSession, FakeSensor, FakeModel, FakeRobot, FakeClock, list[str]]:
    events: list[str] = []
    clock = FakeClock(1_000)
    sensor = FakeSensor(
        observations or [_observation()], events=events, **(sensor_options or {})
    )
    model = FakeModel(
        ARTIFACT_DIGEST,
        clock,
        _action,
        inference_ns=5,
        events=events,
        **(model_options or {}),
    )
    robot = FakeRobot(events=events, **(robot_options or {}))
    bundle = _bundle()
    capabilities = _capabilities(bundle)
    plan = _plan(bundle, capabilities)
    registry = RuntimeRegistry()
    registry.register_sensor(sensor)
    registry.register_model(model)
    registry.register_robot(robot)
    registry.register_bundle(bundle)
    resolved = registry.resolve(plan, capabilities)
    return (
        RuntimeSession(resolved, clock, cancellation=cancellation),
        sensor,
        model,
        robot,
        clock,
        events,
    )


def test_sync_session_has_exact_lifecycle_order_and_bounded_telemetry():
    session, sensor, model, robot, _clock, events = _session()

    assert session.state is RuntimeState.VALIDATED
    assert events == []
    session.prepare()
    session.arm()
    action = session.step()
    session.close()

    assert action.action_id == "action-1"
    assert events == [
        "sensor.open",
        "model.open",
        "robot.open",
        "robot.arm",
        "sensor.read",
        "model.predict",
        "robot.apply",
        "robot.safe_stop:closed",
        "robot.close",
        "model.close",
        "sensor.close",
    ]
    assert session.state_history == [
        RuntimeState.VALIDATED,
        RuntimeState.PREPARED,
        RuntimeState.ARMED,
        RuntimeState.RUNNING,
        RuntimeState.SAFE_STOPPED,
        RuntimeState.CLOSED,
    ]
    assert sensor.closed and model.closed and robot.closed
    assert not robot.armed
    assert robot.safe_stop_calls == 1
    assert robot.applied == [action]
    telemetry = session.telemetry
    assert telemetry.state == "closed"
    assert telemetry.steps_attempted == 1
    assert telemetry.steps_succeeded == 1
    assert telemetry.safe_stop_count == 1
    assert telemetry.safe_stop_confirmed is True
    assert telemetry.last_inference_ns == 5


@pytest.mark.parametrize(
    ("failed_adapter", "expected_events", "expected_stop_calls"),
    [
        ("sensor", ["sensor.open", "sensor.close"], 0),
        (
            "model",
            ["sensor.open", "model.open", "model.close", "sensor.close"],
            0,
        ),
        (
            "robot",
            [
                "sensor.open",
                "model.open",
                "robot.open",
                "robot.safe_stop:prepare_failed",
                "robot.close",
                "model.close",
                "sensor.close",
            ],
            1,
        ),
    ],
)
def test_partial_prepare_failure_closes_every_attempted_adapter(
    failed_adapter: str,
    expected_events: list[str],
    expected_stop_calls: int,
):
    failure = RuntimeError(f"{failed_adapter} open failed")
    options = {f"{failed_adapter}_options": {"fail_open": failure}}
    session, sensor, model, robot, _clock, events = _session(**options)

    with pytest.raises(RuntimeError) as raised:
        session.prepare()

    assert raised.value is failure
    assert session.state is RuntimeState.CLOSED
    assert events == expected_events
    assert {"sensor": sensor, "model": model, "robot": robot}[failed_adapter].closed
    assert robot.safe_stop_calls == expected_stop_calls
    assert session.telemetry.safe_stop_count == expected_stop_calls


def test_failure_after_prepare_stops_once_and_repeat_close_is_a_noop():
    primary = RuntimeError("predict failed")
    session, _sensor, _model, robot, _clock, events = _session(
        model_options={"fail_predict": primary}
    )
    session.prepare()
    session.arm()

    with pytest.raises(RuntimeError) as raised:
        session.step()
    assert raised.value is primary

    first_events = list(events)
    session.close()
    session.close()
    assert events == first_events
    assert robot.safe_stop_calls == 1
    assert robot.applied == []
    assert not robot.armed
    assert session.actions_fenced is True
    assert session.state is RuntimeState.CLOSED


def test_invalid_transition_after_prepare_fails_closed_once():
    session, _sensor, _model, robot, _clock, _events = _session()
    session.prepare()

    with pytest.raises(RuntimeExecutionError) as raised:
        session.prepare()

    assert raised.value.code == "invalid_state"
    assert session.state is RuntimeState.CLOSED
    assert session.actions_fenced is True
    assert robot.safe_stop_calls == 1
    session.close()
    assert robot.safe_stop_calls == 1


def test_cleanup_failures_do_not_replace_the_primary_failure():
    primary = RuntimeError("primary inference failure")
    session, sensor, model, robot, _clock, events = _session(
        sensor_options={"fail_close": OSError("sensor close")},
        model_options={
            "fail_predict": primary,
            "fail_close": ValueError("model close"),
        },
        robot_options={
            "fail_safe_stop": LookupError("stop unconfirmed"),
            "fail_close": ArithmeticError("robot close"),
        },
    )
    session.prepare()
    session.arm()

    with pytest.raises(RuntimeError) as raised:
        session.step()

    assert raised.value is primary
    assert session.state is RuntimeState.CLOSED
    assert sensor.closed and model.closed and robot.closed
    assert robot.safe_stop_calls == 1
    assert events[-4:] == [
        "robot.safe_stop:step_failed",
        "robot.close",
        "model.close",
        "sensor.close",
    ]
    telemetry = session.telemetry
    assert telemetry.safe_stop_confirmed is False
    assert len(telemetry.cleanup_failures) == 4


def test_normal_close_reports_cleanup_error_only_after_all_attempts():
    session, sensor, model, robot, _clock, events = _session(
        sensor_options={"fail_close": OSError("sensor close")},
        robot_options={"fail_safe_stop": RuntimeError("stop failed")},
    )
    session.prepare()
    session.arm()

    with pytest.raises(RuntimeCleanupError) as raised:
        session.close("manual_stop")

    assert len(raised.value.failure_codes) == 2
    assert session.state is RuntimeState.CLOSED
    assert sensor.closed and model.closed and robot.closed
    assert robot.safe_stop_calls == 1
    assert events[-4:] == [
        "robot.safe_stop:manual_stop",
        "robot.close",
        "model.close",
        "sensor.close",
    ]
    session.close()
    assert robot.safe_stop_calls == 1


class _FatalAdapterSignal(BaseException):
    pass


def test_baseexception_from_adapter_still_stops_and_closes_before_reraise():
    primary = _FatalAdapterSignal("fatal")
    session, sensor, model, robot, _clock, _events = _session(
        model_options={"fail_predict": primary}
    )
    session.prepare()
    session.arm()

    with pytest.raises(_FatalAdapterSignal) as raised:
        session.step()

    assert raised.value is primary
    assert session.state is RuntimeState.CLOSED
    assert sensor.closed and model.closed and robot.closed
    assert robot.safe_stop_calls == 1
    assert not robot.armed


class _CancelAtBoundary:
    def __init__(self, boundary_call: int):
        self.boundary_call = boundary_call
        self.calls = 0

    def is_cancelled(self) -> bool:
        self.calls += 1
        return self.calls == self.boundary_call


@pytest.mark.parametrize(
    ("boundary_call", "expected_present", "expected_absent"),
    [
        (1, "robot.open", "robot.arm"),
        (2, "robot.arm", "sensor.read"),
        (3, "sensor.read", "model.predict"),
        (4, "model.predict", "robot.apply"),
        (5, "model.predict", "robot.apply"),
        (6, "model.predict", "robot.apply"),
    ],
)
def test_cancellation_at_every_sync_boundary_stops_before_output(
    boundary_call: int,
    expected_present: str,
    expected_absent: str,
):
    cancellation = _CancelAtBoundary(boundary_call)
    session, sensor, model, robot, _clock, events = _session(
        cancellation=cancellation
    )
    session.prepare()

    with pytest.raises(RuntimeExecutionError) as raised:
        if boundary_call == 1:
            session.arm()
        else:
            session.arm()
            session.step()

    assert raised.value.code == "cancelled"
    assert expected_present in events
    assert expected_absent not in events
    assert "robot.apply" not in events
    assert robot.applied == []
    assert robot.safe_stop_calls == 1
    assert not robot.armed
    assert sensor.closed and model.closed and robot.closed
    assert session.actions_fenced is True
    assert session.state is RuntimeState.CLOSED


def test_close_is_idempotent_and_no_action_is_possible_after_fence():
    session, _sensor, _model, robot, _clock, events = _session()
    session.prepare()
    session.arm()
    session.close("operator_stop")
    stopped_events = list(events)

    with pytest.raises(RuntimeExecutionError) as raised:
        session.step()

    assert raised.value.code == "invalid_state"
    session.close()
    assert events == stopped_events
    assert robot.applied == []
    assert robot.safe_stop_calls == 1
    assert session.actions_fenced is True


def test_close_before_prepare_never_calls_robot_stop():
    session, sensor, model, robot, _clock, events = _session()

    session.close()
    session.close()

    assert session.state is RuntimeState.CLOSED
    assert events == []
    assert not sensor.opened and not model.opened and not robot.opened
    assert robot.safe_stop_calls == 0


def test_invalid_close_reason_is_sanitized_without_skipping_cleanup():
    session, sensor, model, robot, _clock, events = _session()
    session.prepare()
    session.arm()

    session.close(None)  # type: ignore[arg-type]

    assert "robot.safe_stop:requested_stop" in events
    assert sensor.closed and model.closed and robot.closed
    assert not robot.armed
    assert session.state is RuntimeState.CLOSED
    assert session.telemetry.last_stop_reason == "requested_stop"


@pytest.mark.parametrize(
    ("second", "expected_code"),
    [
        (_observation(), "observation_sequence_replay"),
        (
            ObservationEnvelope.from_dict(
                {
                    **_observation().to_dict(),
                    "sequence": 2,
                    "captured_monotonic_ns": 1_001,
                    "received_monotonic_ns": 1_002,
                }
            ),
            "observation_id_replay",
        ),
    ],
)
def test_observation_replay_is_rejected_before_a_second_model_call(
    second: ObservationEnvelope,
    expected_code: str,
):
    session, _sensor, model, robot, _clock, _events = _session(
        observations=[_observation(), second]
    )
    session.prepare()
    session.arm()
    first = session.step()

    with pytest.raises(RuntimeExecutionError) as raised:
        session.step()

    assert raised.value.code == expected_code
    assert model.predict_count == 1
    assert robot.applied == [first]
    assert robot.safe_stop_calls == 1
    assert session.state is RuntimeState.CLOSED
