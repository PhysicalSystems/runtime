"""Strict contracts for commissioned, but never implicitly authorized, workflows."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Callable

import pytest

from tinyedge_runtime.contracts import (
    PhysicalProtocol,
    PhysicalRunRecord,
    PhysicalSystemManifest,
    ResolvedPhysicalProtocol,
    RunOutcome,
    RuntimeContractError,
    SafeStopRecord,
    TypedArgument,
    physical_identity_digest,
    physical_trust_domain_digest,
    resolve_physical_protocol,
    seal_physical_manifest,
    seal_physical_protocol,
    seal_physical_run_record,
    validate_physical_run_record,
)


FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures"
MANIFEST_FIXTURE = "runtime-physical-manifest-v1.json"
PROTOCOL_FIXTURE = "runtime-physical-protocol-v1.json"
RUN_FIXTURE = "runtime-physical-run-record-v1.json"


def _fixture(filename: str) -> dict[str, Any]:
    return json.loads((FIXTURE_ROOT / filename).read_text(encoding="utf-8"))


def _manifest(value: dict[str, Any] | None = None) -> PhysicalSystemManifest:
    return PhysicalSystemManifest.from_dict(value or _fixture(MANIFEST_FIXTURE))


def _protocol(value: dict[str, Any] | None = None) -> PhysicalProtocol:
    return PhysicalProtocol.from_dict(value or _fixture(PROTOCOL_FIXTURE))


def _record(value: dict[str, Any] | None = None) -> PhysicalRunRecord:
    return PhysicalRunRecord.from_dict(value or _fixture(RUN_FIXTURE))


def _resolved() -> ResolvedPhysicalProtocol:
    return resolve_physical_protocol(_manifest(), _protocol())


def _rebind_protocol(
    value: dict[str, Any], manifest: PhysicalSystemManifest
) -> PhysicalProtocol:
    rebound = copy.deepcopy(value)
    rebound["manifest_digest"] = manifest.manifest_digest
    return PhysicalProtocol.from_dict(seal_physical_protocol(rebound))


def _rebind_run(
    value: dict[str, Any], resolved: ResolvedPhysicalProtocol
) -> PhysicalRunRecord:
    rebound = copy.deepcopy(value)
    rebound["manifest_digest"] = resolved.manifest.manifest_digest
    rebound["protocol_hash"] = resolved.protocol.protocol_hash
    return PhysicalRunRecord.from_dict(seal_physical_run_record(rebound))


def _assert_code(call: Callable[[], object], code: str) -> None:
    with pytest.raises(RuntimeContractError) as raised:
        call()
    assert raised.value.code == code


@pytest.mark.parametrize(
    ("filename", "parser", "digest_field", "golden_digest"),
    [
        (
            MANIFEST_FIXTURE,
            PhysicalSystemManifest.from_dict,
            "manifest_digest",
            "sha256:981c2d3d508098ed32bdb43be5f736cb6deff84e7f89369be8c62cc44363f1af",
        ),
        (
            PROTOCOL_FIXTURE,
            PhysicalProtocol.from_dict,
            "protocol_hash",
            "sha256:f278a042d3730e5595efa681455afdbea19fa45b07a72f26be1f8af682fed1ab",
        ),
        (
            RUN_FIXTURE,
            PhysicalRunRecord.from_dict,
            "run_digest",
            "sha256:8602aa945deaed637d8c78ada390b918708266a405aa78bb27407e729b037ae3",
        ),
    ],
)
def test_physical_golden_contracts_are_exact_round_trips(
    filename: str,
    parser: Callable[[object], object],
    digest_field: str,
    golden_digest: str,
):
    value = _fixture(filename)

    parsed = parser(value)

    assert parsed.to_dict() == value  # type: ignore[attr-defined]
    assert value[digest_field] == golden_digest


def test_resolution_is_side_effect_free_and_never_grants_execution_authority():
    manifest = _manifest()
    protocol = _protocol()
    manifest_before = manifest.to_dict()
    protocol_before = protocol.to_dict()

    resolved = resolve_physical_protocol(manifest, protocol)

    assert manifest.to_dict() == manifest_before
    assert protocol.to_dict() == protocol_before
    assert resolved.manifest is manifest
    assert resolved.protocol is protocol
    assert resolved.required_locks == (
        "overhead_camera",
        "so101_arm",
        "workcell_motion_zone",
    )
    assert resolved.physical_execution_authorized is False


def test_hardware_identity_digest_is_domain_separated_by_system_and_device():
    first = physical_identity_digest(
        system_id="cell_a", device_id="camera", hardware_identity="fake-camera-1"
    )

    assert first == physical_identity_digest(
        system_id="cell_a", device_id="camera", hardware_identity="fake-camera-1"
    )
    assert first != physical_identity_digest(
        system_id="cell_b", device_id="camera", hardware_identity="fake-camera-1"
    )
    assert first != physical_identity_digest(
        system_id="cell_a", device_id="robot", hardware_identity="fake-camera-1"
    )


def test_trust_domain_digest_is_stable_without_a_logical_device_id():
    first = physical_trust_domain_digest(
        system_id="cell_a", trust_domain_identity="shared-controller-1"
    )

    assert first == physical_trust_domain_digest(
        system_id="cell_a", trust_domain_identity="shared-controller-1"
    )
    assert first != physical_trust_domain_digest(
        system_id="cell_a", trust_domain_identity="independent-camera-1"
    )
    assert first != physical_trust_domain_digest(
        system_id="cell_b", trust_domain_identity="shared-controller-1"
    )


@pytest.mark.parametrize(
    ("filename", "parser", "semantic_field", "replacement"),
    [
        (MANIFEST_FIXTURE, PhysicalSystemManifest.from_dict, "system_id", "other_cell"),
        (PROTOCOL_FIXTURE, PhysicalProtocol.from_dict, "protocol_id", "other_protocol"),
        (RUN_FIXTURE, PhysicalRunRecord.from_dict, "run_id", "other_run"),
    ],
)
def test_physical_contract_hashes_are_tamper_evident(
    filename: str,
    parser: Callable[[object], object],
    semantic_field: str,
    replacement: str,
):
    value = _fixture(filename)
    value[semantic_field] = replacement

    _assert_code(lambda: parser(value), "hash_mismatch")


@pytest.mark.parametrize(
    ("filename", "parser"),
    [
        (MANIFEST_FIXTURE, PhysicalSystemManifest.from_dict),
        (PROTOCOL_FIXTURE, PhysicalProtocol.from_dict),
        (RUN_FIXTURE, PhysicalRunRecord.from_dict),
    ],
)
def test_physical_contracts_reject_unknown_top_level_fields(
    filename: str, parser: Callable[[object], object]
):
    value = _fixture(filename)
    value["vendor_extension"] = {"module": "dynamic"}

    _assert_code(lambda: parser(value), "unknown_field")


def test_physical_contracts_reject_unknown_nested_fields_before_hashing():
    value = _fixture(MANIFEST_FIXTURE)
    value["devices"][0]["commands"][0]["python_entrypoint"] = "os.system"

    _assert_code(lambda: PhysicalSystemManifest.from_dict(value), "unknown_field")


def test_manifest_sealing_canonicalizes_all_set_like_members():
    value = _fixture(MANIFEST_FIXTURE)
    value["resources"].reverse()
    value["devices"].reverse()
    value["devices"][0]["state_fields"].reverse()
    value["devices"][0]["commands"].reverse()
    value["devices"][0]["commands"][1]["required_resources"].reverse()

    assert seal_physical_manifest(value) == _fixture(MANIFEST_FIXTURE)


def test_protocol_and_run_sealing_canonicalize_sets_but_preserve_step_order():
    protocol = _fixture(PROTOCOL_FIXTURE)
    run = _fixture(RUN_FIXTURE)
    protocol["steps"][1]["resource_ids"].reverse()
    run["locks"].reverse()
    run["commands"].reverse()
    run["evidence"].reverse()

    assert seal_physical_protocol(protocol) == _fixture(PROTOCOL_FIXTURE)
    assert seal_physical_run_record(run) == _fixture(RUN_FIXTURE)

    reversed_steps = _fixture(PROTOCOL_FIXTURE)
    reversed_steps["steps"].reverse()
    resealed = seal_physical_protocol(reversed_steps)
    assert [item["step_id"] for item in resealed["steps"]] == [
        "move_to_destination",
        "observe_source",
    ]
    assert resealed["protocol_hash"] != _fixture(PROTOCOL_FIXTURE)["protocol_hash"]


def test_authoritative_parsers_reject_noncanonical_order_without_rewriting():
    manifest = _fixture(MANIFEST_FIXTURE)
    manifest["resources"].reverse()

    _assert_code(lambda: PhysicalSystemManifest.from_dict(manifest), "noncanonical_order")


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda step: step.__setitem__("arguments", []), "missing_argument"),
        (
            lambda step: step["arguments"].append(
                {"name": "speed", "value_type": "number", "value": 0.25}
            ),
            "unknown_argument",
        ),
        (
            lambda step: step["arguments"][0].update(
                {"value_type": "string", "value": "slow"}
            ),
            "argument_type_mismatch",
        ),
    ],
)
def test_resolution_enforces_the_declared_typed_arguments(mutate, code: str):
    manifest = _manifest()
    value = _fixture(PROTOCOL_FIXTURE)
    mutate(value["steps"][1])
    protocol = _rebind_protocol(value, manifest)

    _assert_code(lambda: resolve_physical_protocol(manifest, protocol), code)


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (
            lambda value: value["resources"].pop(1),
            "missing_device_resource",
        ),
        (
            lambda value: value["devices"][1]["commands"][0][
                "required_resources"
            ].append("unknown_zone"),
            "unknown_resource",
        ),
    ],
)
def test_manifest_requires_explicit_device_and_command_resources(mutate, code: str):
    value = _fixture(MANIFEST_FIXTURE)
    mutate(value)

    _assert_code(lambda: seal_physical_manifest(value), code)


@pytest.mark.parametrize(
    ("required_artifacts", "code"),
    [
        ([], "missing_commissioned_artifact"),
        (["missing_waypoint_catalog"], "unknown_artifact"),
    ],
)
def test_actuating_commands_bind_a_known_commissioned_artifact(
    required_artifacts: list[str], code: str
):
    value = _fixture(MANIFEST_FIXTURE)
    value["devices"][1]["commands"][0]["required_artifacts"] = required_artifacts

    _assert_code(lambda: seal_physical_manifest(value), code)


def test_actuating_devices_require_a_calibration_binding():
    value = _fixture(MANIFEST_FIXTURE)
    value["devices"][1]["calibration_digest"] = None

    _assert_code(lambda: seal_physical_manifest(value), "missing_calibration_binding")


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (
            lambda field: field.__setitem__("unit", None),
            "missing_numeric_bounds",
        ),
        (
            lambda field: field.update({"minimum": 0.5, "maximum": 0.25}),
            "invalid_limits",
        ),
        (
            lambda field: field.update(
                {"unit": "ratio", "minimum": 0.0, "maximum": 1.0}
            ),
            "unexpected_scalar_bounds",
        ),
    ],
)
def test_typed_fields_require_explicit_consistent_units_and_ranges(mutate, code: str):
    value = _fixture(MANIFEST_FIXTURE)
    field = value["devices"][1]["commands"][0]["input_fields"][0]
    if code == "unexpected_scalar_bounds":
        field = value["devices"][1]["commands"][0]["input_fields"][1]
    mutate(field)

    _assert_code(lambda: seal_physical_manifest(value), code)


def test_resolution_rejects_numeric_arguments_outside_commissioned_range():
    manifest = _manifest()
    value = _fixture(PROTOCOL_FIXTURE)
    value["steps"][1]["arguments"][0]["value"] = 0.5
    protocol = _rebind_protocol(value, manifest)

    _assert_code(
        lambda: resolve_physical_protocol(manifest, protocol),
        "argument_out_of_bounds",
    )


@pytest.mark.parametrize(
    ("resource_ids", "code"),
    [
        ([], "invalid_type"),
        (["so101_arm"], "missing_resource_lock"),
        (["so101_arm", "unknown_zone", "workcell_motion_zone"], "unknown_resource"),
    ],
)
def test_resolution_requires_known_device_and_command_locks(
    resource_ids: list[str], code: str
):
    manifest = _manifest()
    value = _fixture(PROTOCOL_FIXTURE)
    value["steps"][1]["resource_ids"] = resource_ids

    def resolve() -> ResolvedPhysicalProtocol:
        protocol = _rebind_protocol(value, manifest)
        return resolve_physical_protocol(manifest, protocol)

    _assert_code(resolve, code)


def test_resolution_rejects_unknown_evidence_producers_and_unobserved_actuation():
    manifest = _manifest()
    unknown_producer = _fixture(PROTOCOL_FIXTURE)
    unknown_producer["steps"][1]["evidence_requirements"][0][
        "producer_device_id"
    ] = "missing_camera"
    protocol = _rebind_protocol(unknown_producer, manifest)
    _assert_code(
        lambda: resolve_physical_protocol(manifest, protocol),
        "unknown_evidence_producer",
    )

    no_actuation_evidence = _fixture(PROTOCOL_FIXTURE)
    no_actuation_evidence["steps"][1]["evidence_requirements"] = []
    protocol = _rebind_protocol(no_actuation_evidence, manifest)
    _assert_code(
        lambda: resolve_physical_protocol(manifest, protocol),
        "missing_actuation_precondition",
    )

    no_postcondition = _fixture(PROTOCOL_FIXTURE)
    no_postcondition["steps"][1]["evidence_requirements"].pop(0)
    protocol = _rebind_protocol(no_postcondition, manifest)
    _assert_code(
        lambda: resolve_physical_protocol(manifest, protocol),
        "missing_actuation_evidence",
    )


@pytest.mark.parametrize(
    ("field", "replacement", "code"),
    [
        ("phase", "during_command", "unsupported_evidence_phase"),
        ("operator", "greater_or_equal", "invalid_predicate_operator"),
    ],
)
def test_evidence_requirements_reject_ambiguous_phases_and_predicates(
    field: str, replacement: str, code: str
):
    value = _fixture(PROTOCOL_FIXTURE)
    value["steps"][1]["evidence_requirements"][0][field] = replacement

    _assert_code(lambda: seal_physical_protocol(value), code)


def test_resolution_requires_the_evidence_producer_lock_for_the_whole_step():
    manifest = _manifest()
    value = _fixture(PROTOCOL_FIXTURE)
    value["steps"][1]["resource_ids"].remove("overhead_camera")
    protocol = _rebind_protocol(value, manifest)

    _assert_code(
        lambda: resolve_physical_protocol(manifest, protocol),
        "missing_evidence_producer_lock",
    )


def test_resolution_reserves_resources_needed_by_the_safety_stop():
    value = _fixture(MANIFEST_FIXTURE)
    value["resources"].append(
        {"kind": "controller", "resource_id": "stop_controller"}
    )
    value["devices"][1]["commands"][1]["required_resources"].append(
        "stop_controller"
    )
    manifest = PhysicalSystemManifest.from_dict(seal_physical_manifest(value))
    protocol = _rebind_protocol(_fixture(PROTOCOL_FIXTURE), manifest)

    _assert_code(
        lambda: resolve_physical_protocol(manifest, protocol),
        "missing_safety_stop_lock",
    )


def test_actuation_requires_a_postcondition_from_an_independent_device():
    manifest = _manifest()
    value = _fixture(PROTOCOL_FIXTURE)
    requirement = value["steps"][1]["evidence_requirements"][0]
    requirement["producer_device_id"] = "so101_arm"
    requirement["state_field"] = "motion_state"
    protocol = _rebind_protocol(value, manifest)

    _assert_code(
        lambda: resolve_physical_protocol(manifest, protocol),
        "missing_actuation_evidence",
    )


def test_logical_alias_of_the_actuator_is_not_an_independent_observer():
    value = _fixture(MANIFEST_FIXTURE)
    value["devices"][0]["trust_domain_digest"] = value["devices"][1][
        "trust_domain_digest"
    ]
    manifest = PhysicalSystemManifest.from_dict(seal_physical_manifest(value))
    protocol = _rebind_protocol(_fixture(PROTOCOL_FIXTURE), manifest)

    _assert_code(
        lambda: resolve_physical_protocol(manifest, protocol),
        "missing_actuation_precondition",
    )


def test_safety_stop_commands_are_reserved_for_cleanup():
    manifest = _manifest()
    value = _fixture(PROTOCOL_FIXTURE)
    value["steps"][0].update(
        {
            "arguments": [],
            "command_id": "safe_stop",
            "device_id": "so101_arm",
            "evidence_requirements": [],
            "resource_ids": ["so101_arm"],
        }
    )
    protocol = _rebind_protocol(value, manifest)

    _assert_code(
        lambda: resolve_physical_protocol(manifest, protocol),
        "reserved_safety_stop_command",
    )


def test_read_only_steps_may_omit_evidence_without_weakening_actuation_checks():
    manifest = _manifest()
    value = _fixture(PROTOCOL_FIXTURE)
    value["steps"][0]["evidence_requirements"] = []
    protocol = _rebind_protocol(value, manifest)

    resolved = resolve_physical_protocol(manifest, protocol)

    assert resolved.qualification == "qualified"


@pytest.mark.parametrize("qualification", ["qualified", "provisional", "blocked"])
def test_resolution_preserves_the_weakest_command_qualification(qualification: str):
    value = _fixture(MANIFEST_FIXTURE)
    value["devices"][1]["commands"][0]["qualification"] = qualification
    manifest = PhysicalSystemManifest.from_dict(seal_physical_manifest(value))
    protocol = _rebind_protocol(_fixture(PROTOCOL_FIXTURE), manifest)

    resolved = resolve_physical_protocol(manifest, protocol)

    assert resolved.qualification == qualification
    assert resolved.physical_execution_authorized is False


def test_actuation_resolution_also_preserves_safe_stop_qualification():
    value = _fixture(MANIFEST_FIXTURE)
    value["devices"][1]["commands"][1]["qualification"] = "blocked"
    manifest = PhysicalSystemManifest.from_dict(seal_physical_manifest(value))
    protocol = _rebind_protocol(_fixture(PROTOCOL_FIXTURE), manifest)

    resolved = resolve_physical_protocol(manifest, protocol)

    assert resolved.qualification == "blocked"
    assert resolved.physical_execution_authorized is False


@pytest.mark.parametrize("qualification", ["provisional", "blocked"])
def test_actuation_resolution_preserves_artifact_qualification(qualification: str):
    value = _fixture(MANIFEST_FIXTURE)
    value["artifacts"][0]["qualification"] = qualification
    manifest = PhysicalSystemManifest.from_dict(seal_physical_manifest(value))
    protocol = _rebind_protocol(_fixture(PROTOCOL_FIXTURE), manifest)

    resolved = resolve_physical_protocol(manifest, protocol)

    assert resolved.qualification == qualification
    assert resolved.physical_execution_authorized is False


def test_actuation_resolution_preserves_safe_stop_artifact_qualification():
    value = _fixture(MANIFEST_FIXTURE)
    value["artifacts"].append(
        {
            "artifact_id": "stop_profile",
            "digest": "sha256:" + "9" * 64,
            "kind": "stop_configuration",
            "qualification": "blocked",
        }
    )
    value["devices"][1]["commands"][1]["required_artifacts"] = ["stop_profile"]
    manifest = PhysicalSystemManifest.from_dict(seal_physical_manifest(value))
    protocol = _rebind_protocol(_fixture(PROTOCOL_FIXTURE), manifest)

    resolved = resolve_physical_protocol(manifest, protocol)

    assert resolved.qualification == "blocked"
    assert resolved.physical_execution_authorized is False


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (
            lambda value: value["lifecycle"][1].__setitem__("state", "running"),
            "invalid_run_transition",
        ),
        (
            lambda value: value["lifecycle"][2].__setitem__(
                "monotonic_ns", value["lifecycle"][1]["monotonic_ns"] - 1
            ),
            "invalid_timestamp_order",
        ),
        (
            lambda value: value["lifecycle"].__setitem__(
                -1, {"sequence": 3, "state": "running", "monotonic_ns": 2_200_000_000}
            ),
            "invalid_run_lifecycle",
        ),
    ],
)
def test_run_records_enforce_a_contiguous_terminal_lifecycle(mutate, code: str):
    value = _fixture(RUN_FIXTURE)
    mutate(value)

    _assert_code(lambda: seal_physical_run_record(value), code)


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (
            lambda command: command.__setitem__("acknowledged_monotonic_ns", None),
            "invalid_command_outcome",
        ),
        (
            lambda command: command.update(
                {"status": "failed", "failure_code": "driver_fault"}
            ),
            "invalid_command_outcome",
        ),
        (
            lambda command: command.update(
                {
                    "completed_monotonic_ns": command["dispatched_monotonic_ns"] - 1,
                    "acknowledged_monotonic_ns": command["dispatched_monotonic_ns"]
                    - 1,
                }
            ),
            "invalid_timestamp_order",
        ),
    ],
)
def test_command_acknowledgements_have_exact_outcome_fields(mutate, code: str):
    value = _fixture(RUN_FIXTURE)
    mutate(value["commands"][0])

    _assert_code(lambda: seal_physical_run_record(value), code)


def test_sequential_commands_cannot_overlap_or_continue_after_failure():
    overlapping = _fixture(RUN_FIXTURE)
    overlapping["commands"][1]["dispatched_monotonic_ns"] = 1_150_000_000
    record = PhysicalRunRecord.from_dict(seal_physical_run_record(overlapping))
    _assert_code(
        lambda: validate_physical_run_record(record, _resolved()),
        "overlapping_command_dispatch",
    )

    after_failure = _fixture(RUN_FIXTURE)
    after_failure["commands"][0].update(
        {
            "status": "failed",
            "acknowledged_monotonic_ns": None,
            "failure_code": "driver_fault",
        }
    )
    after_failure["outcome"].update(
        {"status": "failed", "failure_code": "driver_fault"}
    )
    after_failure["lifecycle"][-1]["state"] = "failed"
    record = PhysicalRunRecord.from_dict(seal_physical_run_record(after_failure))
    _assert_code(
        lambda: validate_physical_run_record(record, _resolved()),
        "command_after_failure",
    )


def test_successful_golden_run_matches_protocol_commands_locks_and_evidence():
    validate_physical_run_record(_record(), _resolved())


def test_success_requires_every_acknowledged_command_in_protocol_order():
    value = _fixture(RUN_FIXTURE)
    value["commands"].pop()
    value["evidence"].clear()
    record = PhysicalRunRecord.from_dict(seal_physical_run_record(value))
    _assert_code(
        lambda: validate_physical_run_record(record, _resolved()),
        "incomplete_success",
    )

    wrong_order = _fixture(RUN_FIXTURE)
    wrong_order["commands"][0]["step_id"] = "move_to_destination"
    wrong_order["commands"][1]["step_id"] = "observe_source"
    record = PhysicalRunRecord.from_dict(seal_physical_run_record(wrong_order))
    _assert_code(
        lambda: validate_physical_run_record(record, _resolved()),
        "command_order_mismatch",
    )


@pytest.mark.parametrize("extra", [False, True])
def test_run_locks_must_exactly_match_the_resolved_protocol(extra: bool):
    value = _fixture(RUN_FIXTURE)
    if extra:
        value["locks"].append(
            {
                "resource_id": "unresolved_resource",
                "acquired_monotonic_ns": 1_010_000_000,
                "released_monotonic_ns": 2_200_000_000,
            }
        )
    else:
        value["locks"].pop()
    record = PhysicalRunRecord.from_dict(seal_physical_run_record(value))

    _assert_code(
        lambda: validate_physical_run_record(record, _resolved()),
        "resource_lock_mismatch",
    )


def test_success_requires_exactly_one_matching_evidence_reference_per_requirement():
    missing = _fixture(RUN_FIXTURE)
    missing["evidence"].pop(0)
    record = PhysicalRunRecord.from_dict(seal_physical_run_record(missing))
    _assert_code(
        lambda: validate_physical_run_record(record, _resolved()),
        "incomplete_success_evidence",
    )

    mismatched = _fixture(RUN_FIXTURE)
    mismatched["evidence"][0]["producer_device_id"] = "so101_arm"
    record = PhysicalRunRecord.from_dict(seal_physical_run_record(mismatched))
    _assert_code(
        lambda: validate_physical_run_record(record, _resolved()),
        "evidence_requirement_mismatch",
    )


def test_retained_evidence_must_satisfy_the_declared_predicate():
    value = _fixture(RUN_FIXTURE)
    value["evidence"][0]["observed_value"] = "source_station"
    record = PhysicalRunRecord.from_dict(seal_physical_run_record(value))

    _assert_code(
        lambda: validate_physical_run_record(record, _resolved()),
        "evidence_predicate_failed",
    )


def test_postcondition_evidence_must_follow_command_completion():
    value = _fixture(RUN_FIXTURE)
    value["evidence"][0]["captured_monotonic_ns"] = 1_990_000_000
    record = PhysicalRunRecord.from_dict(seal_physical_run_record(value))

    _assert_code(
        lambda: validate_physical_run_record(record, _resolved()),
        "early_postcondition_evidence",
    )


def test_precondition_evidence_must_precede_dispatch():
    value = _fixture(RUN_FIXTURE)
    value["evidence"][1]["captured_monotonic_ns"] = 1_350_000_000
    record = PhysicalRunRecord.from_dict(seal_physical_run_record(value))

    _assert_code(
        lambda: validate_physical_run_record(record, _resolved()),
        "late_precondition_evidence",
    )


def test_actuation_precondition_must_follow_the_prior_step_completion():
    value = _fixture(RUN_FIXTURE)
    value["evidence"][1]["captured_monotonic_ns"] = 1_190_000_000
    record = PhysicalRunRecord.from_dict(seal_physical_run_record(value))

    _assert_code(
        lambda: validate_physical_run_record(record, _resolved()),
        "precondition_before_prior_completion",
    )


def test_failed_precondition_is_retained_without_dispatching_the_actuator():
    value = _fixture(RUN_FIXTURE)
    value["commands"].pop()
    value["evidence"].pop(0)
    value["evidence"][0]["observed_value"] = "source_missing"
    value["safe_stops"] = []
    value["lifecycle"][-1].update(
        {"state": "failed", "monotonic_ns": 1_400_000_000}
    )
    for lock in value["locks"]:
        lock["released_monotonic_ns"] = 1_400_000_000
    value["outcome"] = {
        "status": "failed",
        "failure_code": "precondition_failed",
    }
    record = PhysicalRunRecord.from_dict(seal_physical_run_record(value))

    validate_physical_run_record(record, _resolved())

    passing = record.to_dict()
    passing["evidence"][0]["observed_value"] = "source_station"
    passing_record = PhysicalRunRecord.from_dict(seal_physical_run_record(passing))
    _assert_code(
        lambda: validate_physical_run_record(passing_record, _resolved()),
        "unjustified_precondition_block",
    )


def test_next_command_waits_for_the_prior_postcondition_barrier():
    manifest = _manifest()
    protocol_value = _fixture(PROTOCOL_FIXTURE)
    observe_requirement = copy.deepcopy(
        protocol_value["steps"][1]["evidence_requirements"][1]
    )
    observe_requirement.update(
        {"phase": "postcondition", "requirement_id": "observed_source_state"}
    )
    protocol_value["steps"][0]["evidence_requirements"] = [observe_requirement]
    protocol = _rebind_protocol(protocol_value, manifest)
    resolved = resolve_physical_protocol(manifest, protocol)

    value = _fixture(RUN_FIXTURE)
    value["commands"][1]["dispatched_monotonic_ns"] = 1_240_000_000
    value["evidence"].append(
        {
            "captured_monotonic_ns": 1_250_000_000,
            "digest": "sha256:" + "5" * 64,
            "evidence_id": "evidence_observed_source_state",
            "evidence_kind": "physical_state",
            "observed_value": "source_station",
            "producer_device_id": "overhead_camera",
            "requirement_id": "observed_source_state",
            "state_field": "cup_location",
            "step_id": "observe_source",
            "value_type": "identifier",
        }
    )
    record = _rebind_run(value, resolved)

    _assert_code(
        lambda: validate_physical_run_record(record, resolved),
        "command_before_postcondition",
    )


def test_prior_postcondition_must_still_be_fresh_at_next_dispatch():
    manifest = _manifest()
    protocol_value = _fixture(PROTOCOL_FIXTURE)
    observe_requirement = copy.deepcopy(
        protocol_value["steps"][1]["evidence_requirements"][1]
    )
    observe_requirement.update(
        {"phase": "postcondition", "requirement_id": "observed_source_state"}
    )
    protocol_value["steps"][0]["evidence_requirements"] = [observe_requirement]
    protocol = _rebind_protocol(protocol_value, manifest)
    resolved = resolve_physical_protocol(manifest, protocol)

    value = _fixture(RUN_FIXTURE)
    value["commands"][1]["dispatched_monotonic_ns"] = 1_800_000_000
    value["evidence"][1]["captured_monotonic_ns"] = 1_790_000_000
    value["evidence"].append(
        {
            "captured_monotonic_ns": 1_210_000_000,
            "digest": "sha256:" + "5" * 64,
            "evidence_id": "evidence_observed_source_state",
            "evidence_kind": "physical_state",
            "observed_value": "source_station",
            "producer_device_id": "overhead_camera",
            "requirement_id": "observed_source_state",
            "state_field": "cup_location",
            "step_id": "observe_source",
            "value_type": "identifier",
        }
    )
    record = _rebind_run(value, resolved)

    _assert_code(
        lambda: validate_physical_run_record(record, resolved),
        "stale_postcondition_barrier",
    )


def test_failed_final_postcondition_remains_a_valid_failure_record():
    value = _fixture(RUN_FIXTURE)
    value["evidence"][0]["observed_value"] = "source_station"
    value["lifecycle"][-1]["state"] = "failed"
    value["outcome"] = {
        "status": "failed",
        "failure_code": "expected_state_not_reached",
    }
    record = PhysicalRunRecord.from_dict(seal_physical_run_record(value))

    validate_physical_run_record(record, _resolved())


def test_evidence_must_be_within_the_protocol_freshness_window():
    manifest = _manifest()
    protocol_value = _fixture(PROTOCOL_FIXTURE)
    protocol_value["steps"][1]["evidence_requirements"][0][
        "maximum_age_ns"
    ] = 50_000_000
    protocol = _rebind_protocol(protocol_value, manifest)
    resolved = resolve_physical_protocol(manifest, protocol)
    record = _rebind_run(_fixture(RUN_FIXTURE), resolved)

    _assert_code(
        lambda: validate_physical_run_record(record, resolved),
        "stale_evidence",
    )


def test_non_timeout_command_completion_cannot_exceed_the_step_timeout():
    manifest = _manifest()
    protocol_value = _fixture(PROTOCOL_FIXTURE)
    protocol_value["steps"][1]["timeout_ns"] = 500_000_000
    protocol = _rebind_protocol(protocol_value, manifest)
    resolved = resolve_physical_protocol(manifest, protocol)
    record = _rebind_run(_fixture(RUN_FIXTURE), resolved)

    _assert_code(
        lambda: validate_physical_run_record(record, resolved),
        "command_timeout_exceeded",
    )


def test_timed_out_command_cannot_be_classified_before_its_deadline():
    value = _fixture(RUN_FIXTURE)
    value["commands"][1].update(
        {
            "acknowledged_monotonic_ns": None,
            "failure_code": "step_timeout",
            "status": "timed_out",
        }
    )
    value["lifecycle"][-1]["state"] = "failed"
    value["outcome"] = {"failure_code": "step_timeout", "status": "failed"}
    record = PhysicalRunRecord.from_dict(seal_physical_run_record(value))

    _assert_code(
        lambda: validate_physical_run_record(record, _resolved()),
        "premature_timeout",
    )


@pytest.mark.parametrize(
    ("resource_id", "released_monotonic_ns", "code"),
    [
        ("workcell_motion_zone", 1_900_000_000, "lock_not_held_for_command"),
        ("overhead_camera", 2_050_000_000, "lock_not_held_for_evidence"),
    ],
)
def test_step_locks_cover_command_and_evidence_windows(
    resource_id: str, released_monotonic_ns: int, code: str
):
    value = _fixture(RUN_FIXTURE)
    lock = next(item for item in value["locks"] if item["resource_id"] == resource_id)
    lock["released_monotonic_ns"] = released_monotonic_ns
    record = PhysicalRunRecord.from_dict(seal_physical_run_record(value))

    _assert_code(lambda: validate_physical_run_record(record, _resolved()), code)


def test_dispatched_actuation_requires_one_safe_stop_record_for_that_device():
    value = _fixture(RUN_FIXTURE)
    value["safe_stops"] = []
    record = PhysicalRunRecord.from_dict(seal_physical_run_record(value))

    _assert_code(
        lambda: validate_physical_run_record(record, _resolved()),
        "safe_stop_coverage_mismatch",
    )


def test_safe_stop_is_recorded_at_most_once_per_device():
    value = _fixture(RUN_FIXTURE)
    duplicate = copy.deepcopy(value["safe_stops"][0])
    duplicate["dispatch_id"] = "second_safe_stop_dispatch"
    value["safe_stops"].append(duplicate)

    _assert_code(lambda: seal_physical_run_record(value), "duplicate_safe_stop")


def test_safe_stop_dispatch_is_distinct_and_follows_actuation_completion():
    duplicate_dispatch = _fixture(RUN_FIXTURE)
    duplicate_dispatch["safe_stops"][0]["dispatch_id"] = duplicate_dispatch[
        "commands"
    ][1]["dispatch_id"]
    record = PhysicalRunRecord.from_dict(seal_physical_run_record(duplicate_dispatch))
    _assert_code(
        lambda: validate_physical_run_record(record, _resolved()),
        "duplicate_dispatch",
    )

    early = _fixture(RUN_FIXTURE)
    early["safe_stops"][0].update(
        {
            "dispatched_monotonic_ns": 1_990_000_000,
            "completed_monotonic_ns": 2_000_000_000,
        }
    )
    record = PhysicalRunRecord.from_dict(seal_physical_run_record(early))
    _assert_code(
        lambda: validate_physical_run_record(record, _resolved()),
        "early_safe_stop",
    )


def test_successful_actuation_requires_a_confirmed_safe_stop():
    value = _fixture(RUN_FIXTURE)
    value["safe_stops"][0].update(
        {"confirmed": False, "failure_code": "stop_not_confirmed"}
    )
    record = PhysicalRunRecord.from_dict(seal_physical_run_record(value))

    _assert_code(
        lambda: validate_physical_run_record(record, _resolved()),
        "unconfirmed_safe_stop",
    )


def test_safe_stop_required_locks_cover_dispatch_through_completion():
    value = _fixture(RUN_FIXTURE)
    arm_lock = next(
        item for item in value["locks"] if item["resource_id"] == "so101_arm"
    )
    arm_lock["released_monotonic_ns"] = 2_115_000_000
    record = PhysicalRunRecord.from_dict(seal_physical_run_record(value))

    _assert_code(
        lambda: validate_physical_run_record(record, _resolved()),
        "lock_not_held_for_safe_stop",
    )


@pytest.mark.parametrize(
    ("filename", "sealer", "mutate"),
    [
        (
            MANIFEST_FIXTURE,
            seal_physical_manifest,
            lambda value: value["resources"].append(None),
        ),
        (
            MANIFEST_FIXTURE,
            seal_physical_manifest,
            lambda value: value["artifacts"].append(None),
        ),
        (
            MANIFEST_FIXTURE,
            seal_physical_manifest,
            lambda value: value["devices"].append(None),
        ),
        (
            MANIFEST_FIXTURE,
            seal_physical_manifest,
            lambda value: value["devices"][0]["commands"].append(None),
        ),
        (
            MANIFEST_FIXTURE,
            seal_physical_manifest,
            lambda value: value["devices"][0]["state_fields"].append(None),
        ),
        (
            MANIFEST_FIXTURE,
            seal_physical_manifest,
            lambda value: value["devices"][0]["commands"][0][
                "input_fields"
            ].append(None),
        ),
        (
            PROTOCOL_FIXTURE,
            seal_physical_protocol,
            lambda value: value["steps"].append(None),
        ),
        (
            PROTOCOL_FIXTURE,
            seal_physical_protocol,
            lambda value: value["steps"][0]["arguments"].append(None),
        ),
        (
            PROTOCOL_FIXTURE,
            seal_physical_protocol,
            lambda value: value["steps"][0]["evidence_requirements"].append(None),
        ),
        (
            RUN_FIXTURE,
            seal_physical_run_record,
            lambda value: value["lifecycle"].append(None),
        ),
        (
            RUN_FIXTURE,
            seal_physical_run_record,
            lambda value: value["locks"].append(None),
        ),
        (
            RUN_FIXTURE,
            seal_physical_run_record,
            lambda value: value["commands"].append(None),
        ),
        (
            RUN_FIXTURE,
            seal_physical_run_record,
            lambda value: value["safe_stops"].append(None),
        ),
        (
            RUN_FIXTURE,
            seal_physical_run_record,
            lambda value: value["evidence"].append(None),
        ),
    ],
)
def test_sealers_turn_malformed_nested_members_into_contract_errors(
    filename: str,
    sealer: Callable[[dict[str, Any]], dict[str, Any]],
    mutate: Callable[[dict[str, Any]], None],
):
    value = _fixture(filename)
    mutate(value)

    with pytest.raises(RuntimeContractError):
        sealer(value)


def test_direct_construction_cannot_bypass_scalar_or_outcome_validation():
    _assert_code(lambda: TypedArgument("count", "integer", True), "invalid_integer")
    _assert_code(
        lambda: RunOutcome("failed", None),
        "invalid_run_outcome",
    )
    _assert_code(
        lambda: SafeStopRecord(
            "stop_1",
            "so101_arm",
            10,
            20,
            False,
            None,
        ),
        "invalid_safe_stop_outcome",
    )


def test_resolved_protocol_cannot_be_forged_by_direct_construction():
    _assert_code(
        lambda: ResolvedPhysicalProtocol(
            manifest=_manifest(),
            protocol=_protocol(),
            qualification="qualified",
            required_locks=(),
        ),
        "untrusted_resolution",
    )
