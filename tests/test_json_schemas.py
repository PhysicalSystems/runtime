"""Public JSON Schemas are structural projections, not semantic authorities."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from tinyedge_runtime.contracts import (
    ActionChunk,
    ObservationEnvelope,
    PhysicalProtocol,
    PhysicalRunRecord,
    PhysicalSystemManifest,
    PhysicalSkillCatalog,
    PhysicalSkillRouteDecision,
    PhysicalSkillRouteRequest,
    RuntimeCapabilities,
    RuntimeContractError,
    RuntimePlan,
    RuntimeTelemetrySummary,
)
from tinyedge_runtime.registry import QualifiedBundle


ROOT = Path(__file__).parents[1]
SCHEMA_ROOT = ROOT / "schemas"
FIXTURE_ROOT = ROOT / "fixtures"
Parser = Callable[[object], object]

CONTRACTS: tuple[tuple[str, Parser], ...] = (
    ("runtime-capabilities-v1", RuntimeCapabilities.from_dict),
    ("runtime-qualified-bundle-v1", QualifiedBundle.from_dict),
    ("runtime-plan-v1", RuntimePlan.from_dict),
    ("runtime-observation-v1", ObservationEnvelope.from_dict),
    ("runtime-action-chunk-v1", ActionChunk.from_dict),
    ("runtime-telemetry-v1", RuntimeTelemetrySummary.from_dict),
    ("runtime-physical-manifest-v1", PhysicalSystemManifest.from_dict),
    ("runtime-physical-protocol-v1", PhysicalProtocol.from_dict),
    ("runtime-physical-run-record-v1", PhysicalRunRecord.from_dict),
    ("runtime-physical-skill-catalog-v1", PhysicalSkillCatalog.from_dict),
    (
        "runtime-physical-skill-route-request-v1",
        PhysicalSkillRouteRequest.from_dict,
    ),
    (
        "runtime-physical-skill-route-decision-v1",
        PhysicalSkillRouteDecision.from_dict,
    ),
)


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _schema(name: str) -> dict[str, Any]:
    return _load(SCHEMA_ROOT / f"{name}.schema.json")


def _fixture(name: str) -> dict[str, Any]:
    return _load(FIXTURE_ROOT / f"{name}.json")


def _object_schemas(value: Any, path: str = "$") -> Iterator[tuple[str, dict[str, Any]]]:
    if isinstance(value, dict):
        if value.get("type") == "object":
            yield path, value
        for key, nested in value.items():
            yield from _object_schemas(nested, f"{path}/{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            yield from _object_schemas(nested, f"{path}/{index}")


@pytest.mark.parametrize(("name", "_parser"), CONTRACTS)
def test_runtime_v1_schema_is_valid_draft_2020_12(name: str, _parser: Parser):
    schema = _schema(name)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert "Python parser remains authoritative" in schema["$comment"]
    Draft202012Validator.check_schema(schema)


@pytest.mark.parametrize(("name", "parser"), CONTRACTS)
def test_golden_fixture_matches_schema_and_authoritative_parser(
    name: str,
    parser: Parser,
):
    instance = _fixture(name)

    Draft202012Validator(_schema(name)).validate(instance)
    parsed = parser(instance)

    assert parsed.to_dict() == instance


@pytest.mark.parametrize(("name", "_parser"), CONTRACTS)
def test_schema_rejects_unknown_top_level_fields(name: str, _parser: Parser):
    instance = _fixture(name)
    instance["unexpected"] = True

    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(name)).validate(instance)


@pytest.mark.parametrize(("name", "_parser"), CONTRACTS)
def test_every_declared_object_boundary_is_closed(name: str, _parser: Parser):
    object_schemas = tuple(_object_schemas(_schema(name)))

    assert object_schemas
    for path, object_schema in object_schemas:
        assert object_schema.get("additionalProperties") is False, path


def test_python_parser_remains_authoritative_for_capability_hashes():
    instance = _fixture("runtime-capabilities-v1")
    instance["environment_id"] = "different_environment"

    # The projection validates digest syntax, but it cannot recompute canonical bytes.
    Draft202012Validator(_schema("runtime-capabilities-v1")).validate(instance)

    with pytest.raises(RuntimeContractError) as exc:
        RuntimeCapabilities.from_dict(instance)
    assert exc.value.code == "hash_mismatch"


def test_python_parser_remains_authoritative_for_cross_field_ordering():
    instance = copy.deepcopy(_fixture("runtime-observation-v1"))
    instance["received_monotonic_ns"] = instance["captured_monotonic_ns"] - 1

    # Draft 2020-12 has no portable sibling-value comparison for these timestamps.
    Draft202012Validator(_schema("runtime-observation-v1")).validate(instance)

    with pytest.raises(RuntimeContractError) as exc:
        ObservationEnvelope.from_dict(instance)
    assert exc.value.code == "invalid_timestamp_order"
