"""Strict Runtime v1 contract, hashing and bounds tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from runtime_contract_test_helpers import (
    MODEL_DIGEST,
    PLACEHOLDER_DIGEST,
    make_action_dict,
    make_capabilities,
    make_observation_dict,
    make_plan_dict,
    make_telemetry_dict,
)
from tinyedge_runtime.contracts import (
    ACTION_VERSION,
    AdapterCapability,
    ActionChunk,
    ArtifactRef,
    ObservationEnvelope,
    RuntimeCapabilities,
    RuntimeContractError,
    RuntimePlan,
    RuntimeTelemetrySummary,
    SafetyPolicy,
    TargetLock,
    canonical_json,
    canonical_sha256,
)
from tinyedge_runtime.registry import QualifiedBundle


FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures"


def _legacy_recipe() -> dict:
    return {
        "contract_version": "llm-recipe-v1",
        "model": {
            "source": "huggingface",
            "repo": "owner/model",
            "revision": "abc",
            "architecture": "llama",
        },
        "build": {
            "plugin": "llama_cpp",
            "plugin_version": "test",
            "configuration": {"precision": "Q4_K_M"},
        },
        "deployment": {
            "stack": "llama_cpp",
            "stack_version": "test",
            "backend": "cpu",
            "artifact_type": "gguf",
        },
        "target": {"device_id": "test", "environment_id": "test-env"},
        "workload": {
            "suite": "test",
            "scenario": "micro",
            "isl": 16,
            "osl": 8,
            "concurrency": 1,
            "duration_s": 1.0,
        },
        "comparison": {"mode": "controlled"},
    }


def test_shared_hashing_preserves_llm_recipe_v1_golden_bytes():
    recipe = _legacy_recipe()
    recipe_hash = canonical_sha256(recipe)
    sealed = {**recipe, "recipe_hash": recipe_hash}
    assert recipe_hash == (
        "sha256:ab9518b92037e603afc619876de4caf78ae086e6f2997f94daa73a00ab8a567d"
    )
    assert '"duration_s":1' in canonical_json(sealed)
    assert '"duration_s":1.0' not in canonical_json(sealed)


def test_good_runtime_contracts_round_trip_as_immutable_values():
    capabilities = make_capabilities()
    plan = RuntimePlan.from_dict(make_plan_dict(capabilities=capabilities))
    observation = ObservationEnvelope.from_dict(make_observation_dict())
    action = ActionChunk.from_dict(make_action_dict())
    telemetry = RuntimeTelemetrySummary.from_dict(
        make_telemetry_dict(plan_hash=plan.plan_hash)
    )

    assert RuntimeCapabilities.from_dict(capabilities.to_dict()) == capabilities
    assert RuntimePlan.from_dict(plan.to_dict()) == plan
    assert ObservationEnvelope.from_dict(observation.to_dict()) == observation
    assert ActionChunk.from_dict(action.to_dict()) == action
    assert RuntimeTelemetrySummary.from_dict(telemetry.to_dict()) == telemetry
    with pytest.raises(AttributeError):
        action.action_id = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("filename", "parser"),
    [
        ("runtime-qualified-bundle-v1.json", QualifiedBundle.from_dict),
        ("runtime-capabilities-v1.json", RuntimeCapabilities.from_dict),
        ("runtime-plan-v1.json", RuntimePlan.from_dict),
        ("runtime-observation-v1.json", ObservationEnvelope.from_dict),
        ("runtime-action-chunk-v1.json", ActionChunk.from_dict),
        ("runtime-telemetry-v1.json", RuntimeTelemetrySummary.from_dict),
    ],
)
def test_runtime_v1_golden_fixtures_are_strict_round_trips(filename, parser):
    value = json.loads((FIXTURE_ROOT / filename).read_text(encoding="utf-8"))

    parsed = parser(value)

    assert parsed.to_dict() == value


def test_runtime_v1_golden_lock_hashes_do_not_drift():
    capabilities = json.loads(
        (FIXTURE_ROOT / "runtime-capabilities-v1.json").read_text(encoding="utf-8")
    )
    plan = json.loads(
        (FIXTURE_ROOT / "runtime-plan-v1.json").read_text(encoding="utf-8")
    )

    assert capabilities["capability_digest"] == (
        "sha256:7e1fb179f1d5a6b7de239b422cde974a0ee67396d5aa47b83f002687e5b8e582"
    )
    assert plan["plan_hash"] == (
        "sha256:c908fff1fb782eab2c6013ac3ef5c5ac5a93d2250b6c741c6981d7435564831f"
    )
    bundle = json.loads(
        (FIXTURE_ROOT / "runtime-qualified-bundle-v1.json").read_text(
            encoding="utf-8"
        )
    )
    assert QualifiedBundle.from_dict(bundle).compatibility_digest == (
        "sha256:f4f391e708a64155603d97f3cdde86a1ae50c3524f1fe3772c7be77335890ad4"
    )


def test_plan_hash_is_order_independent_and_tamper_evident():
    sealed = make_plan_dict()
    reordered = dict(reversed(tuple(sealed.items())))
    assert RuntimePlan.from_dict(reordered).plan_hash == sealed["plan_hash"]

    tampered = copy.deepcopy(sealed)
    tampered["safety"]["upper_limits"][0] = 0.75
    with pytest.raises(RuntimeContractError, match="hash_mismatch") as exc:
        RuntimePlan.from_dict(tampered)
    assert exc.value.code == "hash_mismatch"


def test_capability_hash_is_tamper_evident():
    value = make_capabilities().to_dict()
    value["environment_id"] = "other_environment"
    with pytest.raises(RuntimeContractError, match="hash_mismatch"):
        RuntimeCapabilities.from_dict(value)


@pytest.mark.parametrize(
    "mutation,code",
    [
        (lambda value: value.__setitem__("unexpected", True), "unknown_field"),
        (lambda value: value.__setitem__("contract_version", "runtime_v2"), "unsupported_contract"),
        (lambda value: value.__setitem__("sequence", True), "invalid_integer"),
        (lambda value: value.__setitem__("sequence", 1 << 63), "invalid_integer"),
        (lambda value: value.__setitem__("sensor_values", [float("nan")]), "invalid_number"),
        (lambda value: value.__setitem__("robot_state", [float("inf")]), "invalid_number"),
        (
            lambda value: value.__setitem__("received_monotonic_ns", 99),
            "invalid_timestamp_order",
        ),
    ],
)
def test_observation_rejects_schema_smuggling_and_unbounded_values(mutation, code):
    value = make_observation_dict()
    mutation(value)
    with pytest.raises(RuntimeContractError) as exc:
        ObservationEnvelope.from_dict(value)
    assert exc.value.code == code


@pytest.mark.parametrize("bad_value", [float("nan"), float("inf"), -float("inf"), True])
def test_action_rejects_non_finite_or_boolean_values(bad_value):
    value = make_action_dict(values=[[bad_value, 0.0]])
    with pytest.raises(RuntimeContractError, match="invalid_number"):
        ActionChunk.from_dict(value)


@pytest.mark.parametrize(
    "overrides,code",
    [
        ({"action_axes": ["joint_0"]}, "dimension_mismatch"),
        ({"units": ["rad"]}, "dimension_mismatch"),
        ({"action_axes": ["joint_0", "joint_0"]}, "duplicate_action_axis"),
        ({"values": [[0.0], [0.0, 1.0]]}, "dimension_mismatch"),
        (
            {
                "valid_from_monotonic_ns": 120,
                "expires_at_monotonic_ns": 140,
                "action_period_ns": 10,
            },
            "action_horizon_exceeds_expiry",
        ),
        ({"committed_prefix": 4}, "invalid_integer"),
    ],
)
def test_action_axes_units_shape_and_full_horizon_are_exact(overrides, code):
    with pytest.raises(RuntimeContractError) as exc:
        ActionChunk.from_dict(make_action_dict(**overrides))
    assert exc.value.code == code


def test_action_preserves_axis_and_unit_order_exactly():
    action = ActionChunk.from_dict(
        make_action_dict(
            action_axes=["joint_1", "joint_0"],
            units=["degree", "rad"],
        )
    )
    assert action.action_axes == ("joint_1", "joint_0")
    assert action.units == ("degree", "rad")


def test_safety_policy_rejects_dimension_unit_axis_and_limit_mismatches():
    cases = [
        {"action_dimensions": 1},
        {"units": ["rad"]},
        {"action_axes": ["joint_0", "joint_0"]},
        {"lower_limits": [2.0, -2.0]},
        {"max_observation_age_ns": 1 << 63},
    ]
    for override in cases:
        value = make_plan_dict()
        safety = value["safety"]
        safety.update(override)
        # Parse the nested contract directly so the plan hash does not mask it.
        with pytest.raises(RuntimeContractError):
            SafetyPolicy.from_dict(safety)


def test_plan_rejects_duplicate_artifact_content_under_multiple_aliases():
    artifacts = [
        {"name": "policy", "kind": "model", "digest": MODEL_DIGEST},
        {"name": "policy_alias", "kind": "weights", "digest": MODEL_DIGEST},
    ]
    with pytest.raises(RuntimeContractError, match="duplicate_artifact"):
        RuntimePlan.from_dict(make_plan_dict(artifacts=artifacts))


@pytest.mark.parametrize(
    "factory",
    [
        lambda: AdapterCapability("sensor", "../dynamic_import", "1.0"),
        lambda: AdapterCapability("sensor", "os.system", "1.0"),
        lambda: ArtifactRef("policy", "model", "sha256:not-a-digest"),
        lambda: TargetLock("bad/device", "environment", PLACEHOLDER_DIGEST),
        lambda: ObservationEnvelope(
            "tinyedge-observation-v1",
            "observation",
            -1,
            100,
            90,
            "runtime_monotonic",
            "fake_observation_v1",
            (float("nan"),),
            (0.0,),
        ),
    ],
)
def test_direct_dataclass_construction_cannot_bypass_validation(factory):
    with pytest.raises(RuntimeContractError):
        factory()


def test_contract_collections_and_telemetry_are_bounded():
    too_many_values = [[0.0, 0.0]] * 4097
    with pytest.raises(RuntimeContractError):
        ActionChunk.from_dict(make_action_dict(values=too_many_values))

    failures = [f"cleanup_{index}" for index in range(33)]
    with pytest.raises(RuntimeContractError):
        RuntimeTelemetrySummary.from_dict(
            make_telemetry_dict(cleanup_failures=failures)
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"safe_stop_count": 2},
        {"safe_stop_count": 0, "safe_stop_confirmed": True, "last_stop_reason": "closed"},
        {"safe_stop_count": 1, "safe_stop_confirmed": None},
        {
            "steps_attempted": 1,
            "steps_succeeded": 1,
            "rejected_actions": 1,
            "stale_observations": 1,
        },
    ],
)
def test_telemetry_safe_stop_fields_are_internally_consistent(overrides):
    with pytest.raises(RuntimeContractError):
        RuntimeTelemetrySummary.from_dict(make_telemetry_dict(**overrides))


def test_action_contract_version_is_not_silently_reinterpreted():
    value = make_action_dict(contract_version="tinyedge-action-chunk-v2")
    with pytest.raises(RuntimeContractError, match="unsupported_contract"):
        ActionChunk.from_dict(value)
    assert ACTION_VERSION == "tinyedge-action-chunk-v1"
