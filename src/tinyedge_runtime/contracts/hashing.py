"""Canonical hash helpers for immutable TinyEdge versioned contracts.

These normalization rules are part of the Runtime v1 wire contract. Changing
them requires a new contract version and new cross-language golden fixtures.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _normalize(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    # Match JSON.stringify for the common integral-float case (1.0 -> 1).
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def canonical_json(value: Any) -> str:
    """Return canonical UTF-8 JSON text under the TinyEdge v1 rules."""

    return json.dumps(
        _normalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_sha256(value: Any) -> str:
    """Hash canonical JSON and return a prefixed lowercase digest."""

    digest = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def contract_hash(value: dict[str, Any], hash_field: str) -> str:
    """Hash a contract after removing its self-referential hash field."""

    unsigned = copy.deepcopy(value)
    unsigned.pop(hash_field, None)
    return canonical_sha256(unsigned)


__all__ = ["canonical_json", "canonical_sha256", "contract_hash"]
