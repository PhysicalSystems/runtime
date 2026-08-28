"""Deterministic synchronous RuntimeSession with local fail-closed safety."""

from __future__ import annotations

import re
from enum import Enum
from typing import Callable, Protocol

from .contracts import (
    ActionChunk,
    ObservationEnvelope,
    RuntimeTelemetrySummary,
    TELEMETRY_VERSION,
)
from .registry import ResolvedRuntime


_MAX_MONOTONIC_NS = (1 << 63) - 1
_MAX_TRACKED_OBSERVATIONS = 65_536
_REASON_CODE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,127}$")


class RuntimeState(str, Enum):
    VALIDATED = "validated"
    PREPARED = "prepared"
    ARMED = "armed"
    RUNNING = "running"
    SAFE_STOPPED = "safe_stopped"
    CLOSED = "closed"


class RuntimeExecutionError(RuntimeError):
    """The local Runtime rejected an operation or safety invariant."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


class RuntimeCleanupError(RuntimeError):
    """Normal close finished all attempts but one or more cleanups failed."""

    def __init__(self, failure_codes: tuple[str, ...]):
        self.failure_codes = failure_codes
        super().__init__(f"runtime cleanup was not fully confirmed: {failure_codes!r}")


class MonotonicClock(Protocol):
    def monotonic_ns(self) -> int: ...


class CancellationToken(Protocol):
    def is_cancelled(self) -> bool: ...


class _NeverCancelled:
    def is_cancelled(self) -> bool:
        return False


class RuntimeSession:
    """Execute a resolved local-sync bundle without owning hard robot safety.

    Construction is side-effect free.  ``prepare`` is the first operation that
    opens adapters.  Once prepared, every guarded failure fences actions,
    attempts local safe-stop once and closes all opened resources while
    preserving the primary exception.
    """

    def __init__(
        self,
        resolved: ResolvedRuntime,
        clock: MonotonicClock,
        cancellation: CancellationToken | None = None,
    ) -> None:
        self.resolved = resolved
        self.clock = clock
        self.cancellation = cancellation or _NeverCancelled()
        self.state = RuntimeState.VALIDATED
        self.state_history: list[RuntimeState] = [self.state]
        self._opened: list[tuple[str, Callable[[], None]]] = []
        self._robot_open = False
        self._actions_fenced = False
        self._safe_stop_attempted = False
        self._safe_stop_confirmed: bool | None = None
        self._cleanup_failures: list[str] = []
        self._last_clock_ns: int | None = None
        self._steps_attempted = 0
        self._steps_succeeded = 0
        self._rejected_actions = 0
        self._stale_observations = 0
        self._safe_stop_count = 0
        self._last_stop_reason: str | None = None
        self._last_observation_age_ns: int | None = None
        self._last_action_age_ns: int | None = None
        self._last_inference_ns: int | None = None
        self._last_observation_sequence: int | None = None
        self._last_captured_ns: int | None = None
        self._last_received_ns: int | None = None
        self._seen_observation_ids: set[str] = set()

    def _transition(self, state: RuntimeState) -> None:
        if self.state != state:
            self.state = state
            self.state_history.append(state)

    def _now(self) -> int:
        value = self.clock.monotonic_ns()
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            or value > _MAX_MONOTONIC_NS
        ):
            raise RuntimeExecutionError(
                "invalid_clock", "monotonic clock must return a bounded non-negative integer"
            )
        if self._last_clock_ns is not None and value < self._last_clock_ns:
            raise RuntimeExecutionError("clock_regression", "monotonic clock moved backwards")
        self._last_clock_ns = value
        return value

    def _check_cancelled(self, boundary: str) -> None:
        if self.cancellation.is_cancelled():
            raise RuntimeExecutionError("cancelled", f"cancelled at {boundary}")

    def _invalid_state(self, operation: str, allowed: tuple[RuntimeState, ...]) -> None:
        if self.state in allowed:
            return
        error = RuntimeExecutionError(
            "invalid_state",
            f"{operation} requires {[item.value for item in allowed]!r}, got {self.state.value!r}",
        )
        if self.state in {RuntimeState.PREPARED, RuntimeState.ARMED, RuntimeState.RUNNING}:
            self._abort("invalid_state")
        raise error

    def prepare(self) -> None:
        self._invalid_state("prepare", (RuntimeState.VALIDATED,))
        try:
            self._opened.append(("sensor_close", self.resolved.sensor.close))
            self.resolved.sensor.open(self.resolved.plan)
            self._opened.append(("model_close", self.resolved.model.close))
            self.resolved.model.open(self.resolved.plan)
            self._robot_open = True
            self._opened.append(("robot_close", self.resolved.robot.close))
            self.resolved.robot.open(self.resolved.plan)
            self._transition(RuntimeState.PREPARED)
        except BaseException:
            self._abort("prepare_failed")
            raise

    def arm(self) -> None:
        self._invalid_state("arm", (RuntimeState.PREPARED,))
        try:
            self._check_cancelled("before_arm")
            self.resolved.robot.arm(self.resolved.plan)
            self._transition(RuntimeState.ARMED)
        except BaseException:
            self._abort("arm_failed")
            raise

    def step(self) -> ActionChunk:
        self._invalid_state("step", (RuntimeState.ARMED, RuntimeState.RUNNING))
        if self._actions_fenced:
            raise RuntimeExecutionError("actions_fenced", "robot output has been fenced")
        self._steps_attempted += 1
        self._transition(RuntimeState.RUNNING)
        try:
            self._check_cancelled("before_sensor_read")
            observation = self.resolved.sensor.read()
            self._validate_observation(observation)
            self._check_cancelled("before_model_inference")
            inference_start = self._now()
            action = self.resolved.model.predict(observation)
            inference_end = self._now()
            self._last_inference_ns = inference_end - inference_start
            self._check_cancelled("after_model_inference")
            self._validate_action(action, observation, inference_end)
            self._check_cancelled("before_output_validation")
            if self._actions_fenced:
                raise RuntimeExecutionError("actions_fenced", "robot output has been fenced")
            # Re-evaluate age and expiry at the output boundary rather than
            # assuming model validation and actuation share an instant.
            output_now = self._now()
            self._validate_observation_freshness(observation, output_now)
            self._validate_action(action, observation, output_now)
            self._check_cancelled("before_robot_output")
            if self._actions_fenced:
                raise RuntimeExecutionError("actions_fenced", "robot output has been fenced")
            self.resolved.robot.apply_chunk(action)
            self._steps_succeeded += 1
            return action
        except BaseException as error:
            if isinstance(error, RuntimeExecutionError) and error.code in {
                "action_age_exceeded",
                "action_expired",
                "action_from_future",
                "action_limit_exceeded",
                "action_schema_mismatch",
                "action_source_mismatch",
                "action_dimension_mismatch",
                "action_axes_mismatch",
                "action_units_mismatch",
                "action_artifact_mismatch",
                "action_clock_mismatch",
                "action_predates_observation",
            }:
                self._rejected_actions += 1
            reason = error.code if isinstance(error, RuntimeExecutionError) else "step_failed"
            self._abort(reason)
            raise

    def _validate_observation(self, observation: ObservationEnvelope) -> None:
        if not isinstance(observation, ObservationEnvelope):
            raise RuntimeExecutionError(
                "invalid_observation_type", "sensor returned no ObservationEnvelope"
            )
        plan = self.resolved.plan
        if observation.observation_schema_id != plan.observation_schema_id:
            raise RuntimeExecutionError(
                "observation_schema_mismatch", "observation schema differs from the plan"
            )
        if observation.clock_domain != plan.clock_domain:
            raise RuntimeExecutionError(
                "observation_clock_mismatch", "observation clock differs from the plan"
            )
        if (
            self._last_observation_sequence is not None
            and observation.sequence <= self._last_observation_sequence
        ):
            raise RuntimeExecutionError(
                "observation_sequence_replay",
                "observation sequence must increase within a session",
            )
        if observation.observation_id in self._seen_observation_ids:
            raise RuntimeExecutionError(
                "observation_id_replay", "observation id was already consumed"
            )
        if len(self._seen_observation_ids) >= _MAX_TRACKED_OBSERVATIONS:
            raise RuntimeExecutionError(
                "observation_history_exhausted",
                "Runtime v1 requires a new session after its bounded replay window",
            )
        if (
            self._last_captured_ns is not None
            and observation.captured_monotonic_ns <= self._last_captured_ns
        ):
            raise RuntimeExecutionError(
                "observation_capture_regression",
                "observation capture time must increase within a session",
            )
        if (
            self._last_received_ns is not None
            and observation.received_monotonic_ns < self._last_received_ns
        ):
            raise RuntimeExecutionError(
                "observation_receive_regression",
                "observation receipt time cannot move backwards within a session",
            )
        self._validate_observation_freshness(observation, self._now())
        self._last_observation_sequence = observation.sequence
        self._last_captured_ns = observation.captured_monotonic_ns
        self._last_received_ns = observation.received_monotonic_ns
        self._seen_observation_ids.add(observation.observation_id)

    def _validate_observation_freshness(
        self,
        observation: ObservationEnvelope,
        now: int,
    ) -> None:
        plan = self.resolved.plan
        if observation.received_monotonic_ns > now:
            raise RuntimeExecutionError(
                "observation_from_future", "observation receipt is later than the runtime clock"
            )
        age = now - observation.captured_monotonic_ns
        self._last_observation_age_ns = age
        if age > plan.safety.max_observation_age_ns:
            self._stale_observations += 1
            raise RuntimeExecutionError(
                "observation_age_exceeded", "observation exceeds the local freshness limit"
            )

    def _validate_action(
        self,
        action: ActionChunk,
        observation: ObservationEnvelope,
        now: int,
    ) -> None:
        if not isinstance(action, ActionChunk):
            raise RuntimeExecutionError("invalid_action_type", "model returned no ActionChunk")
        plan = self.resolved.plan
        if action.source_observation_id != observation.observation_id:
            raise RuntimeExecutionError(
                "action_source_mismatch", "action does not name the current observation"
            )
        if action.action_schema_id != plan.action_schema_id:
            raise RuntimeExecutionError(
                "action_schema_mismatch", "action schema differs from the plan"
            )
        if action.clock_domain != plan.clock_domain:
            raise RuntimeExecutionError(
                "action_clock_mismatch", "action clock differs from the plan"
            )
        if action.action_axes != plan.safety.action_axes:
            raise RuntimeExecutionError(
                "action_axes_mismatch", "action axis order differs from the safety policy"
            )
        if action.units != plan.safety.units:
            raise RuntimeExecutionError(
                "action_units_mismatch", "action units differ from the safety policy"
            )
        if action.model_artifact_digest != self.resolved.bundle.model_artifact.digest:
            raise RuntimeExecutionError(
                "action_artifact_mismatch", "action names the wrong model artifact"
            )
        if action.created_monotonic_ns < observation.received_monotonic_ns:
            raise RuntimeExecutionError(
                "action_predates_observation",
                "action creation time predates receipt of its source observation",
            )
        if action.created_monotonic_ns > now:
            raise RuntimeExecutionError(
                "action_from_future", "action creation time is later than the runtime clock"
            )
        age = now - action.created_monotonic_ns
        self._last_action_age_ns = age
        if age > plan.safety.max_action_age_ns:
            raise RuntimeExecutionError(
                "action_age_exceeded", "action exceeds the local freshness limit"
            )
        if now < action.valid_from_monotonic_ns:
            raise RuntimeExecutionError("action_from_future", "action is not valid yet")
        if now >= action.expires_at_monotonic_ns:
            raise RuntimeExecutionError("action_expired", "action deadline has passed")
        dimensions = plan.safety.action_dimensions
        if any(len(row) != dimensions for row in action.values):
            raise RuntimeExecutionError(
                "action_dimension_mismatch", "action width differs from the safety policy"
            )
        for row in action.values:
            for value, lower, upper in zip(
                row, plan.safety.lower_limits, plan.safety.upper_limits
            ):
                if value < lower or value > upper:
                    raise RuntimeExecutionError(
                        "action_limit_exceeded", "action exceeds a declared local limit"
                    )

    def _record_cleanup_failure(self, stage: str, error: BaseException) -> None:
        del error  # Telemetry deliberately excludes exception types and messages.
        code = f"{stage}_failed"
        if code not in self._cleanup_failures and len(self._cleanup_failures) < 32:
            self._cleanup_failures.append(code)

    def _safe_stop_once(self, reason: object) -> None:
        if not self._robot_open or self._safe_stop_attempted:
            return
        self._actions_fenced = True
        self._safe_stop_attempted = True
        self._safe_stop_count += 1
        self._last_stop_reason = (
            reason
            if isinstance(reason, str) and _REASON_CODE.fullmatch(reason)
            else "requested_stop"
        )
        try:
            self.resolved.robot.safe_stop(self._last_stop_reason)
        except BaseException as error:
            self._safe_stop_confirmed = False
            self._record_cleanup_failure("robot_safe_stop", error)
        else:
            self._safe_stop_confirmed = True
            self._transition(RuntimeState.SAFE_STOPPED)

    def _close_resources(self) -> None:
        while self._opened:
            name, closer = self._opened.pop()
            try:
                closer()
            except BaseException as error:
                self._record_cleanup_failure(name, error)
        self._robot_open = False
        self._actions_fenced = True
        self._transition(RuntimeState.CLOSED)

    def _abort(self, reason: str) -> None:
        try:
            if self._robot_open:
                self._safe_stop_once(reason)
        finally:
            self._close_resources()

    def close(self, reason: object = "closed") -> None:
        """Fence output, stop once when prepared, and close every resource."""

        if self.state == RuntimeState.CLOSED:
            return
        try:
            if self._robot_open:
                self._safe_stop_once(reason)
        finally:
            self._close_resources()
        if self._cleanup_failures:
            raise RuntimeCleanupError(tuple(self._cleanup_failures))

    @property
    def actions_fenced(self) -> bool:
        return self._actions_fenced

    @property
    def telemetry(self) -> RuntimeTelemetrySummary:
        summary = RuntimeTelemetrySummary(
            contract_version=TELEMETRY_VERSION,
            plan_hash=self.resolved.plan.plan_hash,
            state=self.state.value,
            steps_attempted=self._steps_attempted,
            steps_succeeded=self._steps_succeeded,
            rejected_actions=self._rejected_actions,
            stale_observations=self._stale_observations,
            safe_stop_count=self._safe_stop_count,
            safe_stop_confirmed=self._safe_stop_confirmed,
            last_stop_reason=self._last_stop_reason,
            cleanup_failures=tuple(self._cleanup_failures),
            last_observation_age_ns=self._last_observation_age_ns,
            last_action_age_ns=self._last_action_age_ns,
            last_inference_ns=self._last_inference_ns,
        )
        # Round-trip through strict validation before exposing a contract object.
        return RuntimeTelemetrySummary.from_dict(summary.to_dict())

    def __enter__(self) -> "RuntimeSession":
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        if exc is None:
            self.close()
        else:
            self._abort("context_error")
        return False


__all__ = [
    "CancellationToken",
    "MonotonicClock",
    "RuntimeCleanupError",
    "RuntimeExecutionError",
    "RuntimeSession",
    "RuntimeState",
]
