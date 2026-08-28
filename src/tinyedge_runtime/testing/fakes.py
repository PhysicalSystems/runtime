"""Deterministic, device-free adapters for Runtime contract and safety tests."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from ..contracts import ActionChunk, ObservationEnvelope, RuntimePlan


class FakeClock:
    def __init__(self, now_ns: int = 0):
        self.now_ns = now_ns

    def monotonic_ns(self) -> int:
        return self.now_ns

    def advance(self, delta_ns: int) -> int:
        if isinstance(delta_ns, bool) or not isinstance(delta_ns, int) or delta_ns < 0:
            raise ValueError("delta_ns must be a non-negative integer")
        self.now_ns += delta_ns
        return self.now_ns


class FakeCancellation:
    def __init__(self, cancelled: bool = False):
        self.cancelled = cancelled

    def cancel(self) -> None:
        self.cancelled = True

    def is_cancelled(self) -> bool:
        return self.cancelled


class FakeSensor:
    adapter_id = "fake_sensor"
    version = "1.0"

    def __init__(
        self,
        observations: Iterable[ObservationEnvelope],
        *,
        events: list[str] | None = None,
        fail_open: BaseException | None = None,
        fail_read: BaseException | None = None,
        fail_close: BaseException | None = None,
    ) -> None:
        self.observations = list(observations)
        self.events = events if events is not None else []
        self.fail_open = fail_open
        self.fail_read = fail_read
        self.fail_close = fail_close
        self.opened = False
        self.closed = False
        self.read_count = 0

    def open(self, plan: RuntimePlan) -> None:
        self.events.append("sensor.open")
        # Model the worst case: an adapter may acquire something before its
        # open path reports failure. RuntimeSession must still invoke close.
        self.opened = True
        if self.fail_open is not None:
            raise self.fail_open

    def read(self) -> ObservationEnvelope:
        self.events.append("sensor.read")
        self.read_count += 1
        if self.fail_read is not None:
            raise self.fail_read
        if not self.opened or self.closed:
            raise RuntimeError("fake sensor is not open")
        if not self.observations:
            raise RuntimeError("fake sensor has no observation")
        return self.observations.pop(0)

    def close(self) -> None:
        self.events.append("sensor.close")
        self.closed = True
        self.opened = False
        if self.fail_close is not None:
            raise self.fail_close


ActionFactory = Callable[[ObservationEnvelope, int], ActionChunk]


class FakeModel:
    adapter_id = "fake_model"
    version = "1.0"

    def __init__(
        self,
        artifact_digest: str,
        clock: FakeClock,
        action_factory: ActionFactory,
        *,
        inference_ns: int = 0,
        events: list[str] | None = None,
        fail_open: BaseException | None = None,
        fail_predict: BaseException | None = None,
        fail_close: BaseException | None = None,
        after_predict: Callable[[], None] | None = None,
    ) -> None:
        self.artifact_digest = artifact_digest
        self.clock = clock
        self.action_factory = action_factory
        self.inference_ns = inference_ns
        self.events = events if events is not None else []
        self.fail_open = fail_open
        self.fail_predict = fail_predict
        self.fail_close = fail_close
        self.after_predict = after_predict
        self.opened = False
        self.closed = False
        self.predict_count = 0

    def open(self, plan: RuntimePlan) -> None:
        self.events.append("model.open")
        self.opened = True
        if self.fail_open is not None:
            raise self.fail_open

    def predict(self, observation: ObservationEnvelope) -> ActionChunk:
        self.events.append("model.predict")
        self.predict_count += 1
        if self.fail_predict is not None:
            raise self.fail_predict
        if not self.opened or self.closed:
            raise RuntimeError("fake model is not open")
        self.clock.advance(self.inference_ns)
        action = self.action_factory(observation, self.clock.monotonic_ns())
        if self.after_predict is not None:
            self.after_predict()
        return action

    def close(self) -> None:
        self.events.append("model.close")
        self.closed = True
        self.opened = False
        if self.fail_close is not None:
            raise self.fail_close


class FakeRobot:
    adapter_id = "fake_robot"
    version = "1.0"

    def __init__(
        self,
        *,
        events: list[str] | None = None,
        fail_open: BaseException | None = None,
        fail_arm: BaseException | None = None,
        fail_apply: BaseException | None = None,
        fail_safe_stop: BaseException | None = None,
        fail_close: BaseException | None = None,
    ) -> None:
        self.events = events if events is not None else []
        self.fail_open = fail_open
        self.fail_arm = fail_arm
        self.fail_apply = fail_apply
        self.fail_safe_stop = fail_safe_stop
        self.fail_close = fail_close
        self.opened = False
        self.armed = False
        self.closed = False
        self.safe_stop_calls = 0
        self.applied: list[ActionChunk] = []

    def open(self, plan: RuntimePlan) -> None:
        self.events.append("robot.open")
        self.opened = True
        if self.fail_open is not None:
            raise self.fail_open

    def arm(self, plan: RuntimePlan) -> None:
        self.events.append("robot.arm")
        if self.fail_arm is not None:
            raise self.fail_arm
        if not self.opened or self.closed:
            raise RuntimeError("fake robot is not open")
        self.armed = True

    def apply_chunk(self, action: ActionChunk) -> None:
        self.events.append("robot.apply")
        if self.fail_apply is not None:
            raise self.fail_apply
        if not self.opened or self.closed or not self.armed:
            raise RuntimeError("fake robot is not armed")
        self.applied.append(action)

    def safe_stop(self, reason: str) -> None:
        self.events.append(f"robot.safe_stop:{reason}")
        self.safe_stop_calls += 1
        if self.fail_safe_stop is not None:
            raise self.fail_safe_stop
        self.armed = False

    def close(self) -> None:
        self.events.append("robot.close")
        self.closed = True
        self.opened = False
        self.armed = False
        if self.fail_close is not None:
            raise self.fail_close


__all__ = [
    "FakeCancellation",
    "FakeClock",
    "FakeModel",
    "FakeRobot",
    "FakeSensor",
]
