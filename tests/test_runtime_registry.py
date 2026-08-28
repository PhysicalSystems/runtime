"""Fail-closed Runtime registry and qualified-bundle resolution tests."""

from __future__ import annotations

import pytest

from runtime_contract_test_helpers import (
    MODEL_DIGEST,
    make_bundle,
    make_capabilities,
    make_plan,
    make_plan_dict,
    make_registry,
    TrackingModel,
    TrackingRobot,
    TrackingSensor,
)
from tinyedge_runtime.contracts import RuntimePlan
from tinyedge_runtime.registry import (
    ResolvedRuntime,
    RuntimeCompatibilityError,
    RuntimeRegistry,
)


def test_resolve_returns_only_the_registered_qualified_bundle_without_side_effects():
    bundle = make_bundle()
    capabilities = make_capabilities(bundle)
    plan = make_plan(bundle, capabilities)
    registry, sensor, model, robot = make_registry(bundle)

    resolved = registry.resolve(plan, capabilities)

    assert resolved.bundle is bundle
    assert resolved.sensor is sensor
    assert resolved.model is model
    assert resolved.robot is robot
    assert sensor.calls == model.calls == robot.calls == []


def test_resolved_runtime_cannot_be_forged_without_registry_resolution():
    bundle = make_bundle()
    capabilities = make_capabilities(bundle)
    plan = make_plan(bundle, capabilities)
    _registry, sensor, model, robot = make_registry(bundle)

    with pytest.raises(RuntimeCompatibilityError) as raised:
        ResolvedRuntime(
            plan=plan,
            capabilities=capabilities,
            bundle=bundle,
            sensor=sensor,
            model=model,
            robot=robot,
        )

    assert raised.value.code == "untrusted_resolution"


@pytest.mark.parametrize(
    "kind,adapter",
    [
        (
            "sensor",
            type(
                "BrokenSensor",
                (),
                {
                    "adapter_id": "broken_sensor",
                    "version": "1.0",
                    "open": None,
                    "read": lambda self: None,
                    "close": lambda self: None,
                },
            )(),
        ),
        (
            "model",
            type(
                "BrokenModel",
                (),
                {
                    "adapter_id": "broken_model",
                    "version": "1.0",
                    "artifact_digest": MODEL_DIGEST,
                    "open": lambda self, plan: None,
                    "predict": 7,
                    "close": lambda self: None,
                },
            )(),
        ),
        (
            "robot",
            type(
                "BrokenRobot",
                (),
                {
                    "adapter_id": "broken_robot",
                    "version": "1.0",
                    "open": lambda self, plan: None,
                    "arm": lambda self, plan: None,
                    "apply_chunk": lambda self, action: None,
                    "safe_stop": "not-callable",
                    "close": lambda self: None,
                },
            )(),
        ),
    ],
)
def test_registration_rejects_non_callable_lifecycle_members(kind, adapter):
    registry = RuntimeRegistry()
    method = getattr(registry, f"register_{kind}")
    with pytest.raises(RuntimeCompatibilityError, match="lifecycle|callable"):
        method(adapter)


def test_duplicate_adapter_and_bundle_registration_fail_closed():
    bundle = make_bundle()
    registry, sensor, _model, _robot = make_registry(bundle)
    with pytest.raises(RuntimeCompatibilityError) as adapter_error:
        registry.register_sensor(sensor)
    assert adapter_error.value.code == "duplicate_adapter"
    with pytest.raises(RuntimeCompatibilityError) as bundle_error:
        registry.register_bundle(bundle)
    assert bundle_error.value.code == "duplicate_bundle"


def test_unknown_bundle_fails_before_any_adapter_lifecycle():
    bundle = make_bundle()
    capabilities = make_capabilities(bundle)
    plan = RuntimePlan.from_dict(
        make_plan_dict(
            bundle,
            capabilities,
            plan_overrides={"bundle_id": "unknown_bundle"},
        )
    )
    registry, sensor, model, robot = make_registry(bundle)
    with pytest.raises(RuntimeCompatibilityError) as exc:
        registry.resolve(plan, capabilities)
    assert exc.value.code == "unknown_bundle"
    assert sensor.calls == model.calls == robot.calls == []


@pytest.mark.parametrize(
    "target_override,expected_code",
    [
        ({"device_id": "other_device"}, "target_device_mismatch"),
        ({"environment_id": "other_environment"}, "target_environment_mismatch"),
        ({"capability_digest": "sha256:" + "f" * 64}, "target_capability_mismatch"),
    ],
)
def test_target_lock_mismatches_fail_before_adapter_lifecycle(
    target_override, expected_code
):
    bundle = make_bundle()
    capabilities = make_capabilities(bundle)
    base = make_plan_dict(bundle, capabilities)
    target = {**base["target"], **target_override}
    plan = RuntimePlan.from_dict(
        make_plan_dict(bundle, capabilities, plan_overrides={"target": target})
    )
    registry, sensor, model, robot = make_registry(bundle)
    with pytest.raises(RuntimeCompatibilityError) as exc:
        registry.resolve(plan, capabilities)
    assert exc.value.code == expected_code
    assert sensor.calls == model.calls == robot.calls == []


def test_bundle_digest_and_strategy_mismatch_fail_closed():
    bundle = make_bundle()
    capabilities = make_capabilities(bundle)
    registry, *_ = make_registry(bundle)

    wrong_digest = RuntimePlan.from_dict(
        make_plan_dict(
            bundle,
            capabilities,
            plan_overrides={"bundle_digest": "sha256:" + "e" * 64},
        )
    )
    with pytest.raises(RuntimeCompatibilityError) as digest_error:
        registry.resolve(wrong_digest, capabilities)
    assert digest_error.value.code == "bundle_digest_mismatch"

    wrong_strategy = RuntimePlan.from_dict(
        make_plan_dict(
            bundle,
            capabilities,
            plan_overrides={"execution_strategy": "rtc_v1"},
        )
    )
    with pytest.raises(RuntimeCompatibilityError) as strategy_error:
        registry.resolve(wrong_strategy, capabilities)
    assert strategy_error.value.code == "execution_strategy_mismatch"


def test_missing_registered_adapter_fails_closed_without_opening_others():
    bundle = make_bundle()
    capabilities = make_capabilities(bundle)
    plan = make_plan(bundle, capabilities)
    registry = RuntimeRegistry()
    sensor = TrackingSensor()
    model = TrackingModel()
    robot = TrackingRobot()
    registry.register_sensor(sensor)
    registry.register_model(model)
    registry.register_bundle(bundle)

    with pytest.raises(RuntimeCompatibilityError) as exc:
        registry.resolve(plan, capabilities)
    assert exc.value.code == "adapter_not_registered"
    assert sensor.calls == model.calls == robot.calls == []


def test_extra_or_renamed_artifacts_cannot_satisfy_a_qualified_bundle():
    bundle = make_bundle()
    capabilities = make_capabilities(bundle)
    registry, sensor, model, robot = make_registry(bundle)

    extra = RuntimePlan.from_dict(
        make_plan_dict(
            bundle,
            capabilities,
            artifacts=[
                {"name": "policy", "kind": "model", "digest": MODEL_DIGEST},
                {
                    "name": "unexpected",
                    "kind": "weights",
                    "digest": "sha256:" + "c" * 64,
                },
            ],
        )
    )
    with pytest.raises(RuntimeCompatibilityError) as extra_error:
        registry.resolve(extra, capabilities)
    assert extra_error.value.code == "artifact_set_mismatch"

    renamed = RuntimePlan.from_dict(
        make_plan_dict(
            bundle,
            capabilities,
            artifacts=[
                {"name": "renamed_policy", "kind": "weights", "digest": MODEL_DIGEST}
            ],
        )
    )
    with pytest.raises(RuntimeCompatibilityError) as renamed_error:
        registry.resolve(renamed, capabilities)
    assert renamed_error.value.code == "artifact_set_mismatch"
    assert sensor.calls == model.calls == robot.calls == []


def test_model_adapter_must_bind_the_exact_qualified_artifact():
    bundle = make_bundle()
    capabilities = make_capabilities(bundle)
    plan = make_plan(bundle, capabilities)
    registry, _sensor, model, _robot = make_registry(bundle)
    model.artifact_digest = "sha256:" + "d" * 64
    with pytest.raises(RuntimeCompatibilityError) as exc:
        registry.resolve(plan, capabilities)
    assert exc.value.code == "model_artifact_mismatch"


@pytest.mark.parametrize(
    "safety_overrides",
    [
        {"max_observation_age_ns": 1_001},
        {"max_action_age_ns": 1_001},
        {"lower_limits": [-1.01, -2.0]},
        {"upper_limits": [1.0, 2.01]},
    ],
)
def test_plan_cannot_loosen_the_qualified_bundle_safety_envelope(
    safety_overrides,
):
    bundle = make_bundle()
    capabilities = make_capabilities(bundle)
    plan = make_plan(
        bundle,
        capabilities,
        safety_overrides=safety_overrides,
    )
    registry, *_ = make_registry(bundle)

    with pytest.raises(RuntimeCompatibilityError) as raised:
        registry.resolve(plan, capabilities)

    assert raised.value.code == "safety_envelope_exceeded"


def test_plan_may_tighten_the_qualified_bundle_safety_envelope():
    bundle = make_bundle()
    capabilities = make_capabilities(bundle)
    plan = make_plan(
        bundle,
        capabilities,
        safety_overrides={
            "lower_limits": [-0.5, -1.5],
            "upper_limits": [0.5, 1.5],
            "max_observation_age_ns": 500,
            "max_action_age_ns": 500,
        },
    )
    registry, *_ = make_registry(bundle)

    assert registry.resolve(plan, capabilities).plan is plan


def test_adapter_identity_or_lifecycle_mutation_after_registration_is_rejected():
    bundle = make_bundle()
    capabilities = make_capabilities(bundle)
    plan = make_plan(bundle, capabilities)

    registry, sensor, _model, _robot = make_registry(bundle)
    sensor.adapter_id = "changed_sensor"
    with pytest.raises(RuntimeCompatibilityError) as identity_error:
        registry.resolve(plan, capabilities)
    assert identity_error.value.code == "adapter_identity_changed"

    registry, _sensor, _model, robot = make_registry(bundle)
    robot.safe_stop = None  # type: ignore[method-assign]
    with pytest.raises(RuntimeCompatibilityError) as lifecycle_error:
        registry.resolve(plan, capabilities)
    assert lifecycle_error.value.code == "adapter_lifecycle_changed"
