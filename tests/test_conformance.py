from __future__ import annotations

import json
from pathlib import Path

import pytest

from tinyedge_runtime.conformance import main, validate_contract, validate_file
from tinyedge_runtime.contracts import RuntimeContractError


FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures"


@pytest.mark.parametrize("path", sorted(FIXTURE_ROOT.glob("runtime-*.json")))
def test_all_public_golden_fixtures_pass_strict_conformance(path: Path):
    parsed = validate_file(path)
    assert parsed.to_dict() == json.loads(path.read_text(encoding="utf-8"))


def test_conformance_rejects_unknown_contract_versions():
    with pytest.raises(RuntimeContractError) as raised:
        validate_contract({"contract_version": "tinyedge-runtime-future-v99"})
    assert raised.value.code == "unsupported_contract"


def test_cli_returns_nonzero_if_any_document_is_invalid(tmp_path, capsys):
    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"contract_version":"unknown"}', encoding="utf-8")

    assert main([str(FIXTURE_ROOT / "runtime-plan-v1.json"), str(invalid)]) == 1
    output = capsys.readouterr().out
    assert "VALID tinyedge-runtime-plan-v1" in output
    assert f"INVALID {invalid}" in output
