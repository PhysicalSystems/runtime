"""Device-free conformance validation for TinyEdge Runtime wire contracts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Protocol

from .contracts import (
    ACTION_VERSION,
    CAPABILITIES_VERSION,
    OBSERVATION_VERSION,
    PHYSICAL_MANIFEST_VERSION,
    PHYSICAL_PROTOCOL_VERSION,
    PHYSICAL_RUN_RECORD_VERSION,
    PHYSICAL_SKILL_CATALOG_VERSION,
    PHYSICAL_SKILL_ROUTE_DECISION_VERSION,
    PHYSICAL_SKILL_ROUTE_REQUEST_VERSION,
    PLAN_VERSION,
    TELEMETRY_VERSION,
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
from .registry import BUNDLE_VERSION, QualifiedBundle


class _WireContract(Protocol):
    def to_dict(self) -> dict[str, Any]: ...


_PARSERS = {
    ACTION_VERSION: ActionChunk.from_dict,
    BUNDLE_VERSION: QualifiedBundle.from_dict,
    CAPABILITIES_VERSION: RuntimeCapabilities.from_dict,
    OBSERVATION_VERSION: ObservationEnvelope.from_dict,
    PHYSICAL_MANIFEST_VERSION: PhysicalSystemManifest.from_dict,
    PHYSICAL_PROTOCOL_VERSION: PhysicalProtocol.from_dict,
    PHYSICAL_RUN_RECORD_VERSION: PhysicalRunRecord.from_dict,
    PHYSICAL_SKILL_CATALOG_VERSION: PhysicalSkillCatalog.from_dict,
    PHYSICAL_SKILL_ROUTE_REQUEST_VERSION: PhysicalSkillRouteRequest.from_dict,
    PHYSICAL_SKILL_ROUTE_DECISION_VERSION: PhysicalSkillRouteDecision.from_dict,
    PLAN_VERSION: RuntimePlan.from_dict,
    TELEMETRY_VERSION: RuntimeTelemetrySummary.from_dict,
}


def validate_contract(value: Any) -> _WireContract:
    """Strictly parse one supported Runtime v1 wire contract."""

    if not isinstance(value, dict):
        raise RuntimeContractError("invalid_type", "contract", "must be an object")
    version = value.get("contract_version")
    parser = _PARSERS.get(version)
    if parser is None:
        raise RuntimeContractError(
            "unsupported_contract",
            "contract.contract_version",
            f"unsupported Runtime contract {version!r}",
        )
    return parser(value)


def validate_file(path: Path) -> _WireContract:
    """Load and validate one UTF-8 JSON contract document."""

    value = json.loads(path.read_text(encoding="utf-8"))
    return validate_contract(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Strictly validate TinyEdge Runtime v1 JSON contracts."
    )
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args(argv)

    failed = False
    for path in args.paths:
        try:
            parsed = validate_file(path)
        except (OSError, UnicodeError, json.JSONDecodeError, RuntimeContractError) as exc:
            failed = True
            print(f"INVALID {path}: {exc}")
        else:
            version = parsed.to_dict()["contract_version"]
            print(f"VALID {version} {path}")
    return 1 if failed else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["main", "validate_contract", "validate_file"]
