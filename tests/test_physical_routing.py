"""Deterministic, device-free physical skill implementation routing."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Callable

import pytest

from tinyedge_runtime.contracts import (
    PHYSICAL_SKILL_CATALOG_VERSION,
    PHYSICAL_SKILL_ROUTE_REQUEST_VERSION,
    PhysicalSkillCatalog,
    PhysicalSkillRouteDecision,
    PhysicalSkillRouteRequest,
    RuntimeContractError,
    TypedArgument,
    contract_hash,
    physical_skill_invocation_digest,
    resolve_physical_skill,
    route_physical_skill,
    seal_physical_skill_catalog,
    seal_physical_skill_route_request,
)


DIGEST = {letter: "sha256:" + letter * 64 for letter in "0123456789abcdef"}
FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures"


def _binding(binding_id: str, kind: str, digest: str) -> dict[str, str]:
    return {"binding_id": binding_id, "kind": kind, "digest": digest}


def _requirement(
    requirement_id: str, digest: str, *, maximum_age_ns: int = 200
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "requirement_digest": digest,
        "maximum_age_ns": maximum_age_ns,
    }


def _skill() -> dict[str, Any]:
    value: dict[str, Any] = {
        "skill_id": "transfer_container",
        "input_fields": [
            {
                "name": "destination",
                "value_type": "identifier",
                "required": True,
                "unit": None,
                "minimum": None,
                "maximum": None,
            },
            {
                "name": "source",
                "value_type": "identifier",
                "required": True,
                "unit": None,
                "minimum": None,
                "maximum": None,
            },
            {
                "name": "speed_scale",
                "value_type": "number",
                "required": True,
                "unit": "ratio",
                "minimum": 0.05,
                "maximum": 0.25,
            },
        ],
        "preconditions": [_requirement("workspace_clear", DIGEST["a"])],
    }
    value["skill_definition_digest"] = contract_hash(
        value, "skill_definition_digest"
    )
    return value


def _arguments() -> list[dict[str, Any]]:
    return [
        {"name": "destination", "value_type": "identifier", "value": "station_b"},
        {"name": "source", "value_type": "identifier", "value": "station_a"},
        {"name": "speed_scale", "value_type": "number", "value": 0.1},
    ]


def _invocation_digest(
    arguments: list[dict[str, Any]] | None = None,
    skill_definition_digest: str | None = None,
) -> str:
    return physical_skill_invocation_digest(
        skill_id="transfer_container",
        skill_definition_digest=skill_definition_digest
        or _skill()["skill_definition_digest"],
        arguments=tuple(
            TypedArgument.from_dict(item) for item in (arguments or _arguments())
        ),
    )


def _implementation(
    implementation_id: str,
    *,
    mechanism: str,
    provider: str,
    artifact_id: str,
    artifact_digest: str,
    qualification_id: str,
    qualification_digest: str,
    eligibility: dict[str, Any],
    qualification_status: str = "qualified",
    declared_status: str = "available",
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "implementation_id": implementation_id,
        "skill_id": "transfer_container",
        "skill_definition_digest": _skill()["skill_definition_digest"],
        "workcell_digest": DIGEST["8"],
        "mechanism": mechanism,
        "provider": provider,
        "manifest_digest": DIGEST["7"],
        "dependency_bindings": [_binding("motion_stack", "adapter", DIGEST["1"])],
        "calibration_bindings": [_binding("workspace_frame", "geometry", DIGEST["2"])],
        "artifact_bindings": [_binding(artifact_id, "implementation", artifact_digest)],
        "qualification_binding": _binding(
            qualification_id, "qualification_record", qualification_digest
        ),
        "qualification_status": qualification_status,
        "execution_target": {"kind": "robot_controller", "digest": DIGEST["3"]},
        "eligibility_requirements": [eligibility],
        "declared_status": declared_status,
    }
    value["implementation_digest"] = contract_hash(
        value, "implementation_digest"
    )
    return value


def make_catalog_dict(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "contract_version": PHYSICAL_SKILL_CATALOG_VERSION,
        "catalog_id": "local_workcell_catalog",
        "workcell_id": "cell_alpha",
        "workcell_digest": DIGEST["8"],
        "skills": [_skill()],
        "implementations": [
            _implementation(
                "a_waypoint",
                mechanism="waypoint_sequence",
                provider="local_controller",
                artifact_id="waypoint_catalog",
                artifact_digest=DIGEST["4"],
                qualification_id="waypoint_qualification",
                qualification_digest=DIGEST["5"],
                eligibility=_requirement("inside_taught_region", DIGEST["b"]),
            ),
            _implementation(
                "b_learned",
                mechanism="learned_policy",
                provider="model_runtime",
                artifact_id="policy_artifact",
                artifact_digest=DIGEST["6"],
                qualification_id="policy_qualification",
                qualification_digest=DIGEST["c"],
                eligibility=_requirement("target_visible", DIGEST["d"]),
            ),
        ],
    }
    value.update(overrides)
    return seal_physical_skill_catalog(value)


def make_catalog(**overrides: Any) -> PhysicalSkillCatalog:
    return PhysicalSkillCatalog.from_dict(make_catalog_dict(**overrides))


def _assessment(
    precondition_id: str,
    requirement_digest: str,
    *,
    status: str = "met",
    observed_monotonic_ns: int | None = 900,
    state_digest: str = DIGEST["9"],
    invocation_digest: str | None = None,
) -> dict[str, Any]:
    return {
        "precondition_id": precondition_id,
        "requirement_digest": requirement_digest,
        "invocation_digest": invocation_digest or _invocation_digest(),
        "status": status,
        "state_digest": state_digest,
        "observed_monotonic_ns": observed_monotonic_ns,
        "evidence_digest": None if status == "unknown" else DIGEST["e"],
    }


def make_request_dict(
    catalog: PhysicalSkillCatalog | None = None,
    **overrides: Any,
) -> dict[str, Any]:
    catalog = catalog or make_catalog()
    skill = catalog.skill("transfer_container")
    assert skill is not None
    value: dict[str, Any] = {
        "contract_version": PHYSICAL_SKILL_ROUTE_REQUEST_VERSION,
        "request_id": "route_request_001",
        "catalog_digest": catalog.catalog_digest,
        "skill_id": skill.skill_id,
        "skill_definition_digest": skill.skill_definition_digest,
        "arguments": _arguments(),
        "invocation_digest": _invocation_digest(
            skill_definition_digest=skill.skill_definition_digest
        ),
        "workcell_id": catalog.workcell_id,
        "workcell_digest": catalog.workcell_digest,
        "manifest_digest": DIGEST["7"],
        "state_digest": DIGEST["9"],
        "evaluation_monotonic_ns": 1_000,
        "dependency_bindings": [_binding("motion_stack", "adapter", DIGEST["1"])],
        "calibration_bindings": [_binding("workspace_frame", "geometry", DIGEST["2"])],
        "artifact_bindings": [
            _binding("policy_artifact", "implementation", DIGEST["6"]),
            _binding("waypoint_catalog", "implementation", DIGEST["4"]),
        ],
        "qualification_bindings": [
            _binding("policy_qualification", "qualification_record", DIGEST["c"]),
            _binding("waypoint_qualification", "qualification_record", DIGEST["5"]),
        ],
        "execution_targets": [
            {"kind": "robot_controller", "digest": DIGEST["3"]}
        ],
        "preconditions": [
            _assessment("inside_taught_region", DIGEST["b"]),
            _assessment("target_visible", DIGEST["d"]),
            _assessment("workspace_clear", DIGEST["a"]),
        ],
        "policy": {
            "policy_id": "qualified_first",
            "implementation_order": ["a_waypoint", "b_learned"],
            "allowed_qualification_statuses": ["qualified"],
        },
    }
    value.update(overrides)
    return seal_physical_skill_route_request(value)


def make_request(
    catalog: PhysicalSkillCatalog | None = None,
    **overrides: Any,
) -> PhysicalSkillRouteRequest:
    return PhysicalSkillRouteRequest.from_dict(make_request_dict(catalog, **overrides))


def _assert_code(call: Callable[[], object], code: str) -> None:
    with pytest.raises(RuntimeContractError) as raised:
        call()
    assert raised.value.code == code


def _candidate(decision: PhysicalSkillRouteDecision, implementation_id: str):
    return next(
        item for item in decision.candidates if item.implementation_id == implementation_id
    )


@pytest.mark.parametrize(
    ("filename", "parser", "digest_field", "golden_digest"),
    [
        (
            "runtime-physical-skill-catalog-v1.json",
            PhysicalSkillCatalog.from_dict,
            "catalog_digest",
            "sha256:40875d1f3bb0245589999c599ccbe17624b38cca76361be3c0751b6179f9f0fc",
        ),
        (
            "runtime-physical-skill-route-request-v1.json",
            PhysicalSkillRouteRequest.from_dict,
            "request_digest",
            "sha256:afd6889c308c918c1b786255a7c29b8bb494996bc90983c6cb199b708496539f",
        ),
        (
            "runtime-physical-skill-route-decision-v1.json",
            PhysicalSkillRouteDecision.from_dict,
            "decision_digest",
            "sha256:c2e916c4fda44260fa79da0a301276a26ae0baa3231f2feec4ffcaa7a02e3016",
        ),
    ],
)
def test_routing_golden_contracts_are_exact_round_trips(
    filename: str,
    parser: Callable[[object], object],
    digest_field: str,
    golden_digest: str,
):
    value = json.loads((FIXTURE_ROOT / filename).read_text(encoding="utf-8"))

    parsed = parser(value)

    assert parsed.to_dict() == value  # type: ignore[attr-defined]
    assert value[digest_field] == golden_digest


def test_route_filters_first_then_applies_explicit_total_order():
    catalog = make_catalog()
    request = make_request(catalog)

    decision = route_physical_skill(catalog, request)

    assert decision.decision_status == "selected"
    assert decision.selected_implementation_id == "a_waypoint"
    assert decision.selected_execution_target is not None
    assert decision.selected_execution_target.kind == "robot_controller"
    assert _candidate(decision, "a_waypoint").status == "selected"
    assert _candidate(decision, "b_learned").status == "eligible_not_selected"
    assert decision.physical_execution_authorized is False
    assert resolve_physical_skill(catalog, request) == decision


def test_implementation_specific_precondition_does_not_block_other_candidate():
    catalog = make_catalog()
    request_value = make_request_dict(catalog)
    request_value["preconditions"][0] = _assessment(
        "inside_taught_region",
        DIGEST["b"],
        status="violated",
    )
    request = PhysicalSkillRouteRequest.from_dict(
        seal_physical_skill_route_request(request_value)
    )

    decision = route_physical_skill(catalog, request)

    assert decision.selected_implementation_id == "b_learned"
    assert _candidate(decision, "a_waypoint").rejection_codes == (
        "precondition_violated",
    )
    assert _candidate(decision, "b_learned").status == "selected"


@pytest.mark.parametrize(
    ("status", "observed", "code"),
    [
        ("unknown", None, "precondition_unknown"),
        ("met", 700, "precondition_stale"),
        ("met", 1_001, "precondition_from_future"),
    ],
)
def test_unknown_stale_and_future_preconditions_fail_closed(
    status: str, observed: int | None, code: str
):
    catalog = make_catalog()
    request_value = make_request_dict(catalog)
    request_value["preconditions"][0] = _assessment(
        "inside_taught_region",
        DIGEST["b"],
        status=status,
        observed_monotonic_ns=observed,
    )
    request = PhysicalSkillRouteRequest.from_dict(
        seal_physical_skill_route_request(request_value)
    )

    decision = route_physical_skill(catalog, request)

    assert code in _candidate(decision, "a_waypoint").rejection_codes
    assert decision.selected_implementation_id == "b_learned"


def test_common_precondition_blocks_every_implementation():
    catalog = make_catalog()
    request_value = make_request_dict(catalog)
    request_value["preconditions"][2] = _assessment(
        "workspace_clear", DIGEST["a"], status="unknown", observed_monotonic_ns=None
    )
    request = PhysicalSkillRouteRequest.from_dict(
        seal_physical_skill_route_request(request_value)
    )

    decision = route_physical_skill(catalog, request)

    assert decision.decision_status == "no_match"
    assert all(
        "precondition_unknown" in candidate.rejection_codes
        for candidate in decision.candidates
    )


def test_policy_must_explicitly_allow_demo_qualification():
    catalog_value = make_catalog_dict()
    learned = catalog_value["implementations"][1]
    learned["qualification_status"] = "demo_qualified"
    learned["implementation_digest"] = contract_hash(
        learned, "implementation_digest"
    )
    catalog = PhysicalSkillCatalog.from_dict(seal_physical_skill_catalog(catalog_value))
    request_value = make_request_dict(catalog)
    request_value["preconditions"][0] = _assessment(
        "inside_taught_region", DIGEST["b"], status="violated"
    )
    strict = PhysicalSkillRouteRequest.from_dict(
        seal_physical_skill_route_request(request_value)
    )

    strict_decision = route_physical_skill(catalog, strict)

    assert strict_decision.decision_status == "no_match"
    assert "qualification_status_not_allowed" in _candidate(
        strict_decision, "b_learned"
    ).rejection_codes

    request_value["policy"]["allowed_qualification_statuses"] = [
        "demo_qualified",
        "qualified",
    ]
    permissive = PhysicalSkillRouteRequest.from_dict(
        seal_physical_skill_route_request(request_value)
    )
    assert route_physical_skill(catalog, permissive).selected_implementation_id == (
        "b_learned"
    )


@pytest.mark.parametrize(
    ("field", "replacement", "code"),
    [
        ("dependency_bindings", [], "dependency_missing"),
        (
            "calibration_bindings",
            [_binding("workspace_frame", "different_kind", DIGEST["2"])],
            "calibration_mismatch",
        ),
        ("artifact_bindings", [], "artifact_missing"),
        ("qualification_bindings", [], "qualification_missing"),
    ],
)
def test_exact_current_bindings_are_required(
    field: str, replacement: list[dict[str, str]], code: str
):
    catalog = make_catalog()
    request = make_request(catalog, **{field: replacement})

    decision = route_physical_skill(catalog, request)

    assert code in _candidate(decision, "a_waypoint").rejection_codes


def test_execution_target_requires_exact_kind_and_digest():
    catalog = make_catalog()
    mismatch = make_request(
        catalog,
        execution_targets=[{"kind": "robot_controller", "digest": DIGEST["0"]}],
    )
    unavailable = make_request(
        catalog,
        execution_targets=[{"kind": "different_target", "digest": DIGEST["3"]}],
    )

    mismatch_decision = route_physical_skill(catalog, mismatch)
    unavailable_decision = route_physical_skill(catalog, unavailable)

    assert all(
        "execution_target_mismatch" in item.rejection_codes
        for item in mismatch_decision.candidates
    )
    assert all(
        "execution_target_unavailable" in item.rejection_codes
        for item in unavailable_decision.candidates
    )


def test_policy_must_be_a_total_order_for_the_requested_skill():
    catalog = make_catalog()
    value = make_request_dict(catalog)
    value["policy"]["implementation_order"] = ["a_waypoint"]
    request = PhysicalSkillRouteRequest.from_dict(
        seal_physical_skill_route_request(value)
    )

    decision = route_physical_skill(catalog, request)

    assert decision.decision_status == "no_match"
    assert decision.request_rejection_codes == ("policy_incomplete",)
    assert _candidate(decision, "a_waypoint").status == "eligible_not_selected"


def test_mechanism_and_provider_are_opaque_to_routing_behavior():
    original = make_catalog()
    changed_value = make_catalog_dict()
    first = changed_value["implementations"][0]
    first["mechanism"] = "another_mechanism"
    first["provider"] = "another_provider"
    first["implementation_digest"] = contract_hash(first, "implementation_digest")
    changed = PhysicalSkillCatalog.from_dict(seal_physical_skill_catalog(changed_value))

    assert route_physical_skill(
        original, make_request(original)
    ).selected_implementation_id == "a_waypoint"
    assert route_physical_skill(
        changed, make_request(changed)
    ).selected_implementation_id == "a_waypoint"


def test_request_context_mismatches_produce_explainable_no_match():
    catalog = make_catalog()
    request = make_request(
        catalog,
        catalog_digest=DIGEST["0"],
        workcell_digest=DIGEST["1"],
        skill_definition_digest=DIGEST["2"],
    )

    decision = route_physical_skill(catalog, request)

    assert decision.decision_status == "no_match"
    assert decision.request_rejection_codes == (
        "catalog_mismatch",
        "skill_definition_mismatch",
        "workcell_mismatch",
    )
    assert decision.physical_execution_authorized is False


@pytest.mark.parametrize(
    ("arguments", "code"),
    [
        (
            [item for item in _arguments() if item["name"] != "source"],
            "missing_argument",
        ),
        (
            _arguments()
            + [{"name": "unexpected", "value_type": "identifier", "value": "x"}],
            "unknown_argument",
        ),
        (
            [
                {
                    **item,
                    **(
                        {"value_type": "string", "value": "slow"}
                        if item["name"] == "speed_scale"
                        else {}
                    ),
                }
                for item in _arguments()
            ],
            "argument_type_mismatch",
        ),
        (
            [
                {**item, **({"value": 0.9} if item["name"] == "speed_scale" else {})}
                for item in _arguments()
            ],
            "argument_out_of_bounds",
        ),
    ],
)
def test_invocation_arguments_are_exact_typed_and_bounded(
    arguments: list[dict[str, Any]], code: str
):
    catalog = make_catalog()
    request = make_request(catalog, arguments=arguments)

    decision = route_physical_skill(catalog, request)

    assert decision.decision_status == "no_match"
    assert code in decision.request_rejection_codes


def test_precondition_assessment_is_bound_to_the_exact_invocation():
    catalog = make_catalog()
    value = make_request_dict(catalog)
    value["preconditions"][0]["invocation_digest"] = DIGEST["0"]
    request = PhysicalSkillRouteRequest.from_dict(
        seal_physical_skill_route_request(value)
    )

    decision = route_physical_skill(catalog, request)

    assert "precondition_invocation_mismatch" in _candidate(
        decision, "a_waypoint"
    ).rejection_codes


def test_invocation_digest_rejects_more_than_the_contract_field_limit():
    arguments = tuple(
        TypedArgument.from_dict(
            {
                "name": f"argument_{index:03}",
                "value_type": "identifier",
                "value": "value",
            }
        )
        for index in range(129)
    )

    _assert_code(
        lambda: physical_skill_invocation_digest(
            skill_id="transfer_container",
            skill_definition_digest=_skill()["skill_definition_digest"],
            arguments=arguments,
        ),
        "invalid_type",
    )


def test_invocation_digest_rejects_non_argument_items_with_contract_error():
    _assert_code(
        lambda: physical_skill_invocation_digest(
            skill_id="transfer_container",
            skill_definition_digest=_skill()["skill_definition_digest"],
            arguments=(object(),),  # type: ignore[arg-type]
        ),
        "invalid_type",
    )


def test_contract_hashes_are_tamper_evident_and_decisions_are_deterministic():
    catalog = make_catalog()
    request = make_request(catalog)
    first = route_physical_skill(catalog, request)
    second = route_physical_skill(catalog, request)

    assert first == second
    tampered = copy.deepcopy(first.to_dict())
    tampered["selected_implementation_id"] = "b_learned"
    _assert_code(lambda: PhysicalSkillRouteDecision.from_dict(tampered), "selection_mismatch")


def test_catalog_rejects_ambiguous_implementation_eligibility_requirements():
    value = make_catalog_dict()
    value["implementations"][1]["eligibility_requirements"] = [
        _requirement("inside_taught_region", DIGEST["f"])
    ]
    value["implementations"][1]["implementation_digest"] = contract_hash(
        value["implementations"][1], "implementation_digest"
    )

    _assert_code(
        lambda: PhysicalSkillCatalog.from_dict(seal_physical_skill_catalog(value)),
        "ambiguous_eligibility_requirement",
    )


def _many_requirements(prefix: str, count: int) -> list[dict[str, Any]]:
    return [
        _requirement(f"{prefix}_{index:03}", DIGEST["f"])
        for index in range(count)
    ]


def test_catalog_accepts_exact_per_skill_eligibility_union_limit():
    value = make_catalog_dict()
    value["implementations"][0]["eligibility_requirements"] = _many_requirements(
        "waypoint_requirement", 127
    )
    value["implementations"][1]["eligibility_requirements"] = _many_requirements(
        "learned_requirement", 128
    )

    catalog = PhysicalSkillCatalog.from_dict(seal_physical_skill_catalog(value))

    assert len(catalog.skills[0].preconditions) == 1
    assert sum(
        len(item.eligibility_requirements) for item in catalog.implementations
    ) == 255


def test_catalog_rejects_per_skill_eligibility_union_over_request_limit():
    value = make_catalog_dict()
    value["implementations"][0]["eligibility_requirements"] = _many_requirements(
        "waypoint_requirement", 128
    )
    value["implementations"][1]["eligibility_requirements"] = _many_requirements(
        "learned_requirement", 128
    )

    _assert_code(
        lambda: PhysicalSkillCatalog.from_dict(seal_physical_skill_catalog(value)),
        "eligibility_requirement_limit_exceeded",
    )


def test_unknown_fields_and_noncanonical_order_fail_closed():
    catalog = make_catalog_dict()
    catalog["vendor_extension"] = True
    _assert_code(lambda: PhysicalSkillCatalog.from_dict(catalog), "unknown_field")

    request = make_request_dict()
    request["artifact_bindings"].reverse()
    _assert_code(lambda: PhysicalSkillRouteRequest.from_dict(request), "noncanonical_order")
