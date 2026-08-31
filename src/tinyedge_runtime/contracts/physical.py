"""Neutral contracts for commissioned physical-system workflows.

These contracts describe what a host says is installed, an ordered protocol
compiled against that exact manifest, and a digest-only record of one terminal
run.  They deliberately contain no transport, dynamic import, device I/O or
execution authority.  A host application owns concrete adapters,
authentication, local authorization and hardware qualification.

The contracts are intentionally independent of any vendor protocol.  A future
MHS, ROS or vendor adapter can project into the same manifest without changing
the protocol or run-evidence boundary.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from .hashing import canonical_sha256, contract_hash
from .models import (
    RuntimeContractError,
    _digest,
    _exact_keys,
    _identifier,
    _integer,
    _list,
    _number,
    _validate_constructed,
    _version,
)


PHYSICAL_MANIFEST_VERSION = "tinyedge-runtime-physical-manifest-v1"
PHYSICAL_PROTOCOL_VERSION = "tinyedge-runtime-physical-protocol-v1"
PHYSICAL_RUN_RECORD_VERSION = "tinyedge-runtime-physical-run-record-v1"

_SCALAR_TYPES = frozenset(
    {"boolean", "integer", "number", "string", "identifier", "digest"}
)
_COMMAND_EFFECTS = frozenset({"read_only", "actuating", "safety_stop"})
_QUALIFICATIONS = frozenset({"qualified", "provisional", "blocked"})
_EVIDENCE_PHASES = frozenset({"precondition", "postcondition"})
_PREDICATE_OPERATORS = frozenset(
    {"equals", "not_equals", "greater_or_equal", "less_or_equal"}
)
_QUALIFICATION_RANK = {"qualified": 0, "provisional": 1, "blocked": 2}
_RUN_STATES = frozenset(
    {"created", "locked", "running", "succeeded", "failed", "cancelled"}
)
_TERMINAL_STATES = frozenset({"succeeded", "failed", "cancelled"})
_COMMAND_STATUSES = frozenset(
    {"acknowledged", "timed_out", "failed", "cancelled"}
)
_ALLOWED_TRANSITIONS = {
    "created": frozenset({"locked", "failed", "cancelled"}),
    "locked": frozenset({"running", "failed", "cancelled"}),
    "running": frozenset({"succeeded", "failed", "cancelled"}),
}

_MAX_TEXT = 512
_MAX_RESOURCES = 256
_MAX_ARTIFACTS = 256
_MAX_DEVICES = 64
_MAX_FIELDS = 128
_MAX_COMMANDS = 128
_MAX_STEPS = 1024
_MAX_ARGUMENTS = 128
_MAX_EVIDENCE_REQUIREMENTS = 64
_MAX_LIFECYCLE_TRANSITIONS = 4
_MAX_EVIDENCE = 4096
_MAX_TIMEOUT_NS = 300_000_000_000


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise RuntimeContractError("invalid_boolean", path, "must be true or false")
    return value


def _optional_boolean(value: Any, path: str) -> bool | None:
    if value is None:
        return None
    return _boolean(value, path)


def _optional_identifier(value: Any, path: str) -> str | None:
    if value is None:
        return None
    return _identifier(value, path)


def _optional_version(value: Any, path: str) -> str | None:
    if value is None:
        return None
    return _version(value, path)


def _optional_digest(value: Any, path: str) -> str | None:
    if value is None:
        return None
    return _digest(value, path)


def _optional_number(value: Any, path: str) -> float | None:
    if value is None:
        return None
    return _number(value, path)


def _text(value: Any, path: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_TEXT
        or not value.isprintable()
    ):
        raise RuntimeContractError(
            "invalid_string",
            path,
            f"must be printable non-empty text of at most {_MAX_TEXT} characters",
        )
    return value


def _scalar_type(value: Any, path: str) -> str:
    value_type = _identifier(value, path)
    if value_type not in _SCALAR_TYPES:
        raise RuntimeContractError(
            "unsupported_scalar_type", path, f"unsupported {value_type!r}"
        )
    return value_type


def _scalar_value(value: Any, value_type: str, path: str) -> bool | int | float | str:
    if value_type == "boolean":
        return _boolean(value, path)
    if value_type == "integer":
        return _integer(
            value, path, minimum=-1_000_000_000_000, maximum=1_000_000_000_000
        )
    if value_type == "number":
        return _number(value, path)
    if value_type == "string":
        return _text(value, path)
    if value_type == "identifier":
        return _identifier(value, path)
    if value_type == "digest":
        return _digest(value, path)
    raise RuntimeContractError(
        "unsupported_scalar_type", path, f"unsupported {value_type!r}"
    )


def _predicate_matches(
    operator: str,
    observed: bool | int | float | str,
    expected: bool | int | float | str,
) -> bool:
    if operator == "equals":
        return observed == expected
    if operator == "not_equals":
        return observed != expected
    if operator == "greater_or_equal":
        return observed >= expected  # type: ignore[operator]
    if operator == "less_or_equal":
        return observed <= expected  # type: ignore[operator]
    return False  # pragma: no cover - parsers close the operator set


def physical_identity_digest(
    *, system_id: str, device_id: str, hardware_identity: str
) -> str:
    """Return a domain-separated digest without putting a raw identity on wire."""

    return canonical_sha256(
        {
            "domain": "tinyedge-runtime-physical-hardware-identity-v1",
            "system_id": _identifier(system_id, "physical_identity.system_id"),
            "device_id": _identifier(device_id, "physical_identity.device_id"),
            "hardware_identity": _text(
                hardware_identity, "physical_identity.hardware_identity"
            ),
        }
    )


def physical_trust_domain_digest(
    *, system_id: str, trust_domain_identity: str
) -> str:
    """Bind an observer/actuator trust domain independently of logical device IDs."""

    return canonical_sha256(
        {
            "domain": "tinyedge-runtime-physical-trust-domain-v1",
            "system_id": _identifier(system_id, "physical_trust_domain.system_id"),
            "trust_domain_identity": _text(
                trust_domain_identity,
                "physical_trust_domain.trust_domain_identity",
            ),
        }
    )


def _sorted_unique_identifiers(
    value: Any,
    path: str,
    *,
    nonempty: bool = False,
    maximum: int,
) -> tuple[str, ...]:
    result = tuple(
        _identifier(item, f"{path}[{index}]")
        for index, item in enumerate(
            _list(value, path, nonempty=nonempty, maximum=maximum)
        )
    )
    if len(set(result)) != len(result):
        raise RuntimeContractError("duplicate_identifier", path, "must be unique")
    if tuple(sorted(result)) != result:
        raise RuntimeContractError("noncanonical_order", path, "must be sorted")
    return result


def _integer_sort_key(value: Any) -> tuple[int, int | str]:
    """Sort valid integers numerically while leaving malformed values parseable."""

    if isinstance(value, int) and not isinstance(value, bool):
        return (0, value)
    return (1, str(value))


@dataclass(frozen=True)
class TypedField:
    name: str
    value_type: str
    required: bool
    unit: str | None
    minimum: float | None
    maximum: float | None

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any, path: str = "field") -> "TypedField":
        obj = _exact_keys(
            value,
            path,
            {"name", "value_type", "required", "unit", "minimum", "maximum"},
        )
        value_type = _scalar_type(obj["value_type"], f"{path}.value_type")
        unit = _optional_identifier(obj["unit"], f"{path}.unit")
        minimum = _optional_number(obj["minimum"], f"{path}.minimum")
        maximum = _optional_number(obj["maximum"], f"{path}.maximum")
        if value_type in {"integer", "number"}:
            if unit is None or minimum is None or maximum is None:
                raise RuntimeContractError(
                    "missing_numeric_bounds",
                    path,
                    "numeric fields require a unit and finite minimum/maximum",
                )
            if minimum > maximum:
                raise RuntimeContractError(
                    "invalid_limits", path, "minimum must be <= maximum"
                )
            if value_type == "integer" and (
                not minimum.is_integer() or not maximum.is_integer()
            ):
                raise RuntimeContractError(
                    "invalid_integer_limits",
                    path,
                    "integer field limits must be integral",
                )
        elif unit is not None or minimum is not None or maximum is not None:
            raise RuntimeContractError(
                "unexpected_scalar_bounds",
                path,
                "non-numeric fields require null unit/minimum/maximum",
            )
        return cls(
            name=_identifier(obj["name"], f"{path}.name"),
            value_type=value_type,
            required=_boolean(obj["required"], f"{path}.required"),
            unit=unit,
            minimum=minimum,
            maximum=maximum,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value_type": self.value_type,
            "required": self.required,
            "unit": self.unit,
            "minimum": self.minimum,
            "maximum": self.maximum,
        }


def _typed_fields(
    value: Any, path: str, *, nonempty: bool = False
) -> tuple[TypedField, ...]:
    fields = tuple(
        TypedField.from_dict(item, f"{path}[{index}]")
        for index, item in enumerate(
            _list(value, path, nonempty=nonempty, maximum=_MAX_FIELDS)
        )
    )
    names = tuple(item.name for item in fields)
    if len(set(names)) != len(names):
        raise RuntimeContractError("duplicate_field", path, "field names must be unique")
    if tuple(sorted(names)) != names:
        raise RuntimeContractError(
            "noncanonical_order", path, "fields must be sorted by name"
        )
    return fields


@dataclass(frozen=True)
class PhysicalResource:
    resource_id: str
    kind: str

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any, path: str = "resource") -> "PhysicalResource":
        obj = _exact_keys(value, path, {"resource_id", "kind"})
        return cls(
            resource_id=_identifier(obj["resource_id"], f"{path}.resource_id"),
            kind=_identifier(obj["kind"], f"{path}.kind"),
        )

    def to_dict(self) -> dict[str, str]:
        return {"resource_id": self.resource_id, "kind": self.kind}


@dataclass(frozen=True)
class PhysicalArtifact:
    artifact_id: str
    kind: str
    digest: str
    qualification: str

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any, path: str = "artifact") -> "PhysicalArtifact":
        obj = _exact_keys(
            value, path, {"artifact_id", "kind", "digest", "qualification"}
        )
        qualification = _identifier(
            obj["qualification"], f"{path}.qualification"
        )
        if qualification not in _QUALIFICATIONS:
            raise RuntimeContractError(
                "unsupported_qualification",
                f"{path}.qualification",
                f"unsupported {qualification!r}",
            )
        return cls(
            artifact_id=_identifier(obj["artifact_id"], f"{path}.artifact_id"),
            kind=_identifier(obj["kind"], f"{path}.kind"),
            digest=_digest(obj["digest"], f"{path}.digest"),
            qualification=qualification,
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "digest": self.digest,
            "qualification": self.qualification,
        }


@dataclass(frozen=True)
class PhysicalCommand:
    command_id: str
    effect: str
    qualification: str
    input_fields: tuple[TypedField, ...]
    output_fields: tuple[TypedField, ...]
    required_resources: tuple[str, ...]
    required_artifacts: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any, path: str = "command") -> "PhysicalCommand":
        obj = _exact_keys(
            value,
            path,
            {
                "command_id",
                "effect",
                "qualification",
                "input_fields",
                "output_fields",
                "required_resources",
                "required_artifacts",
            },
        )
        effect = _identifier(obj["effect"], f"{path}.effect")
        if effect not in _COMMAND_EFFECTS:
            raise RuntimeContractError(
                "unsupported_command_effect", f"{path}.effect", f"unsupported {effect!r}"
            )
        qualification = _identifier(
            obj["qualification"], f"{path}.qualification"
        )
        if qualification not in _QUALIFICATIONS:
            raise RuntimeContractError(
                "unsupported_qualification",
                f"{path}.qualification",
                f"unsupported {qualification!r}",
            )
        return cls(
            command_id=_identifier(obj["command_id"], f"{path}.command_id"),
            effect=effect,
            qualification=qualification,
            input_fields=_typed_fields(obj["input_fields"], f"{path}.input_fields"),
            output_fields=_typed_fields(
                obj["output_fields"], f"{path}.output_fields"
            ),
            required_resources=_sorted_unique_identifiers(
                obj["required_resources"],
                f"{path}.required_resources",
                nonempty=True,
                maximum=_MAX_RESOURCES,
            ),
            required_artifacts=_sorted_unique_identifiers(
                obj["required_artifacts"],
                f"{path}.required_artifacts",
                maximum=_MAX_ARTIFACTS,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "effect": self.effect,
            "qualification": self.qualification,
            "input_fields": [item.to_dict() for item in self.input_fields],
            "output_fields": [item.to_dict() for item in self.output_fields],
            "required_resources": list(self.required_resources),
            "required_artifacts": list(self.required_artifacts),
        }


@dataclass(frozen=True)
class PhysicalDevice:
    device_id: str
    kind: str
    adapter_id: str
    adapter_version: str
    adapter_revision: str | None
    hardware_identity_digest: str
    trust_domain_digest: str
    calibration_digest: str | None
    state_fields: tuple[TypedField, ...]
    commands: tuple[PhysicalCommand, ...]

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any, path: str = "device") -> "PhysicalDevice":
        obj = _exact_keys(
            value,
            path,
            {
                "device_id",
                "kind",
                "adapter_id",
                "adapter_version",
                "adapter_revision",
                "hardware_identity_digest",
                "trust_domain_digest",
                "calibration_digest",
                "state_fields",
                "commands",
            },
        )
        device_id = _identifier(obj["device_id"], f"{path}.device_id")
        commands = tuple(
            PhysicalCommand.from_dict(item, f"{path}.commands[{index}]")
            for index, item in enumerate(
                _list(
                    obj["commands"],
                    f"{path}.commands",
                    nonempty=True,
                    maximum=_MAX_COMMANDS,
                )
            )
        )
        command_ids = tuple(item.command_id for item in commands)
        if len(set(command_ids)) != len(command_ids):
            raise RuntimeContractError(
                "duplicate_command", f"{path}.commands", "command ids must be unique"
            )
        if tuple(sorted(command_ids)) != command_ids:
            raise RuntimeContractError(
                "noncanonical_order",
                f"{path}.commands",
                "commands must be sorted by command_id",
            )
        missing_device_locks = [
            item.command_id
            for item in commands
            if device_id not in item.required_resources
        ]
        if missing_device_locks:
            raise RuntimeContractError(
                "missing_device_lock",
                f"{path}.commands",
                "every command must require its owning device resource: "
                f"{missing_device_locks!r}",
            )
        stop_commands = [item for item in commands if item.effect == "safety_stop"]
        if any(item.effect == "actuating" for item in commands) and len(stop_commands) != 1:
            raise RuntimeContractError(
                "missing_safety_stop",
                f"{path}.commands",
                "a device with actuating commands must declare exactly one safety_stop command",
            )
        if any(
            item.effect == "actuating" and not item.required_artifacts
            for item in commands
        ):
            raise RuntimeContractError(
                "missing_commissioned_artifact",
                f"{path}.commands",
                "actuating commands must bind at least one commissioned artifact",
            )
        if any(item.effect == "actuating" for item in commands) and obj[
            "calibration_digest"
        ] is None:
            raise RuntimeContractError(
                "missing_calibration_binding",
                f"{path}.calibration_digest",
                "a device with actuating commands must bind calibrated configuration",
            )
        if any(item.input_fields for item in stop_commands):
            raise RuntimeContractError(
                "unsafe_stop_signature",
                f"{path}.commands",
                "the v1 safety_stop command must be invokable without inputs",
            )
        return cls(
            device_id=device_id,
            kind=_identifier(obj["kind"], f"{path}.kind"),
            adapter_id=_identifier(obj["adapter_id"], f"{path}.adapter_id"),
            adapter_version=_version(
                obj["adapter_version"], f"{path}.adapter_version"
            ),
            adapter_revision=_optional_version(
                obj["adapter_revision"], f"{path}.adapter_revision"
            ),
            hardware_identity_digest=_digest(
                obj["hardware_identity_digest"], f"{path}.hardware_identity_digest"
            ),
            trust_domain_digest=_digest(
                obj["trust_domain_digest"], f"{path}.trust_domain_digest"
            ),
            calibration_digest=_optional_digest(
                obj["calibration_digest"], f"{path}.calibration_digest"
            ),
            state_fields=_typed_fields(
                obj["state_fields"], f"{path}.state_fields", nonempty=True
            ),
            commands=commands,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "kind": self.kind,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "adapter_revision": self.adapter_revision,
            "hardware_identity_digest": self.hardware_identity_digest,
            "trust_domain_digest": self.trust_domain_digest,
            "calibration_digest": self.calibration_digest,
            "state_fields": [item.to_dict() for item in self.state_fields],
            "commands": [item.to_dict() for item in self.commands],
        }

    def command(self, command_id: str) -> PhysicalCommand | None:
        return next((item for item in self.commands if item.command_id == command_id), None)


@dataclass(frozen=True)
class PhysicalSystemManifest:
    contract_version: str
    system_id: str
    resources: tuple[PhysicalResource, ...]
    artifacts: tuple[PhysicalArtifact, ...]
    devices: tuple[PhysicalDevice, ...]
    manifest_digest: str

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any) -> "PhysicalSystemManifest":
        obj = _exact_keys(
            value,
            "physical_manifest",
            {
                "contract_version",
                "system_id",
                "resources",
                "artifacts",
                "devices",
                "manifest_digest",
            },
        )
        version = _identifier(
            obj["contract_version"], "physical_manifest.contract_version"
        )
        if version != PHYSICAL_MANIFEST_VERSION:
            raise RuntimeContractError(
                "unsupported_contract",
                "physical_manifest.contract_version",
                f"expected {PHYSICAL_MANIFEST_VERSION!r}",
            )
        resources = tuple(
            PhysicalResource.from_dict(item, f"physical_manifest.resources[{index}]")
            for index, item in enumerate(
                _list(
                    obj["resources"],
                    "physical_manifest.resources",
                    nonempty=True,
                    maximum=_MAX_RESOURCES,
                )
            )
        )
        resource_keys = tuple((item.resource_id, item.kind) for item in resources)
        if len({item.resource_id for item in resources}) != len(resources):
            raise RuntimeContractError(
                "duplicate_resource",
                "physical_manifest.resources",
                "resource ids must be unique",
            )
        if tuple(sorted(resource_keys)) != resource_keys:
            raise RuntimeContractError(
                "noncanonical_order",
                "physical_manifest.resources",
                "resources must be sorted by resource_id and kind",
            )
        artifacts = tuple(
            PhysicalArtifact.from_dict(item, f"physical_manifest.artifacts[{index}]")
            for index, item in enumerate(
                _list(
                    obj["artifacts"],
                    "physical_manifest.artifacts",
                    maximum=_MAX_ARTIFACTS,
                )
            )
        )
        artifact_ids = tuple(item.artifact_id for item in artifacts)
        if len(set(artifact_ids)) != len(artifact_ids):
            raise RuntimeContractError(
                "duplicate_artifact",
                "physical_manifest.artifacts",
                "artifact ids must be unique",
            )
        if tuple(sorted(artifact_ids)) != artifact_ids:
            raise RuntimeContractError(
                "noncanonical_order",
                "physical_manifest.artifacts",
                "artifacts must be sorted by artifact_id",
            )
        devices = tuple(
            PhysicalDevice.from_dict(item, f"physical_manifest.devices[{index}]")
            for index, item in enumerate(
                _list(
                    obj["devices"],
                    "physical_manifest.devices",
                    nonempty=True,
                    maximum=_MAX_DEVICES,
                )
            )
        )
        device_ids = tuple(item.device_id for item in devices)
        if len(set(device_ids)) != len(device_ids):
            raise RuntimeContractError(
                "duplicate_device",
                "physical_manifest.devices",
                "device ids must be unique",
            )
        if tuple(sorted(device_ids)) != device_ids:
            raise RuntimeContractError(
                "noncanonical_order",
                "physical_manifest.devices",
                "devices must be sorted by device_id",
            )
        resource_ids = {item.resource_id for item in resources}
        resources_by_id = {item.resource_id: item for item in resources}
        missing_device_locks = {
            device_id
            for device_id in device_ids
            if device_id not in resources_by_id
            or resources_by_id[device_id].kind != "device"
        }
        if missing_device_locks:
            raise RuntimeContractError(
                "missing_device_resource",
                "physical_manifest.resources",
                "every device needs a same-id resource of kind 'device': "
                f"{sorted(missing_device_locks)!r}",
            )
        for device in devices:
            for command in device.commands:
                unknown = set(command.required_resources) - resource_ids
                if unknown:
                    raise RuntimeContractError(
                        "unknown_resource",
                        f"physical_manifest.devices.{device.device_id}.commands.{command.command_id}",
                        f"unknown required resources {sorted(unknown)!r}",
                    )
                unknown_artifacts = set(command.required_artifacts) - set(artifact_ids)
                if unknown_artifacts:
                    raise RuntimeContractError(
                        "unknown_artifact",
                        f"physical_manifest.devices.{device.device_id}.commands.{command.command_id}",
                        f"unknown required artifacts {sorted(unknown_artifacts)!r}",
                    )
        result = cls(
            contract_version=version,
            system_id=_identifier(obj["system_id"], "physical_manifest.system_id"),
            resources=resources,
            artifacts=artifacts,
            devices=devices,
            manifest_digest=_digest(
                obj["manifest_digest"], "physical_manifest.manifest_digest"
            ),
        )
        result.verify_digest()
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "system_id": self.system_id,
            "resources": [item.to_dict() for item in self.resources],
            "artifacts": [item.to_dict() for item in self.artifacts],
            "devices": [item.to_dict() for item in self.devices],
            "manifest_digest": self.manifest_digest,
        }

    def verify_digest(self) -> None:
        expected = contract_hash(self.to_dict(), "manifest_digest")
        if self.manifest_digest != expected:
            raise RuntimeContractError(
                "hash_mismatch",
                "physical_manifest.manifest_digest",
                f"expected {expected}",
            )

    def device(self, device_id: str) -> PhysicalDevice | None:
        return next((item for item in self.devices if item.device_id == device_id), None)

    def artifact(self, artifact_id: str) -> PhysicalArtifact | None:
        return next((item for item in self.artifacts if item.artifact_id == artifact_id), None)

    @property
    def lockable_ids(self) -> frozenset[str]:
        return frozenset(item.resource_id for item in self.resources)


@dataclass(frozen=True)
class TypedArgument:
    name: str
    value_type: str
    value: bool | int | float | str

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any, path: str = "argument") -> "TypedArgument":
        obj = _exact_keys(value, path, {"name", "value_type", "value"})
        value_type = _scalar_type(obj["value_type"], f"{path}.value_type")
        return cls(
            name=_identifier(obj["name"], f"{path}.name"),
            value_type=value_type,
            value=_scalar_value(obj["value"], value_type, f"{path}.value"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "value_type": self.value_type, "value": self.value}


@dataclass(frozen=True)
class EvidenceRequirement:
    requirement_id: str
    evidence_kind: str
    producer_device_id: str
    phase: str
    state_field: str
    value_type: str
    operator: str
    expected_value: bool | int | float | str
    maximum_age_ns: int

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(
        cls, value: Any, path: str = "evidence_requirement"
    ) -> "EvidenceRequirement":
        obj = _exact_keys(
            value,
            path,
            {
                "requirement_id",
                "evidence_kind",
                "producer_device_id",
                "phase",
                "state_field",
                "value_type",
                "operator",
                "expected_value",
                "maximum_age_ns",
            },
        )
        phase = _identifier(obj["phase"], f"{path}.phase")
        if phase not in _EVIDENCE_PHASES:
            raise RuntimeContractError(
                "unsupported_evidence_phase",
                f"{path}.phase",
                f"unsupported {phase!r}",
            )
        value_type = _scalar_type(obj["value_type"], f"{path}.value_type")
        operator = _identifier(obj["operator"], f"{path}.operator")
        if operator not in _PREDICATE_OPERATORS:
            raise RuntimeContractError(
                "unsupported_predicate_operator",
                f"{path}.operator",
                f"unsupported {operator!r}",
            )
        if operator in {"greater_or_equal", "less_or_equal"} and value_type not in {
            "integer",
            "number",
        }:
            raise RuntimeContractError(
                "invalid_predicate_operator",
                f"{path}.operator",
                "ordered comparisons require integer or number evidence",
            )
        return cls(
            requirement_id=_identifier(
                obj["requirement_id"], f"{path}.requirement_id"
            ),
            evidence_kind=_identifier(obj["evidence_kind"], f"{path}.evidence_kind"),
            producer_device_id=_identifier(
                obj["producer_device_id"], f"{path}.producer_device_id"
            ),
            phase=phase,
            state_field=_identifier(obj["state_field"], f"{path}.state_field"),
            value_type=value_type,
            operator=operator,
            expected_value=_scalar_value(
                obj["expected_value"], value_type, f"{path}.expected_value"
            ),
            maximum_age_ns=_integer(
                obj["maximum_age_ns"],
                f"{path}.maximum_age_ns",
                minimum=1,
                maximum=_MAX_TIMEOUT_NS,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "evidence_kind": self.evidence_kind,
            "producer_device_id": self.producer_device_id,
            "phase": self.phase,
            "state_field": self.state_field,
            "value_type": self.value_type,
            "operator": self.operator,
            "expected_value": self.expected_value,
            "maximum_age_ns": self.maximum_age_ns,
        }


@dataclass(frozen=True)
class ProtocolStep:
    step_id: str
    device_id: str
    command_id: str
    arguments: tuple[TypedArgument, ...]
    resource_ids: tuple[str, ...]
    timeout_ns: int
    evidence_requirements: tuple[EvidenceRequirement, ...]

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any, path: str = "step") -> "ProtocolStep":
        obj = _exact_keys(
            value,
            path,
            {
                "step_id",
                "device_id",
                "command_id",
                "arguments",
                "resource_ids",
                "timeout_ns",
                "evidence_requirements",
            },
        )
        arguments = tuple(
            TypedArgument.from_dict(item, f"{path}.arguments[{index}]")
            for index, item in enumerate(
                _list(obj["arguments"], f"{path}.arguments", maximum=_MAX_ARGUMENTS)
            )
        )
        argument_names = tuple(item.name for item in arguments)
        if len(set(argument_names)) != len(argument_names):
            raise RuntimeContractError(
                "duplicate_argument", f"{path}.arguments", "argument names must be unique"
            )
        if tuple(sorted(argument_names)) != argument_names:
            raise RuntimeContractError(
                "noncanonical_order",
                f"{path}.arguments",
                "arguments must be sorted by name",
            )
        requirements = tuple(
            EvidenceRequirement.from_dict(
                item, f"{path}.evidence_requirements[{index}]"
            )
            for index, item in enumerate(
                _list(
                    obj["evidence_requirements"],
                    f"{path}.evidence_requirements",
                    maximum=_MAX_EVIDENCE_REQUIREMENTS,
                )
            )
        )
        requirement_ids = tuple(item.requirement_id for item in requirements)
        if len(set(requirement_ids)) != len(requirement_ids):
            raise RuntimeContractError(
                "duplicate_evidence_requirement",
                f"{path}.evidence_requirements",
                "requirement ids must be unique",
            )
        if tuple(sorted(requirement_ids)) != requirement_ids:
            raise RuntimeContractError(
                "noncanonical_order",
                f"{path}.evidence_requirements",
                "requirements must be sorted by requirement_id",
            )
        return cls(
            step_id=_identifier(obj["step_id"], f"{path}.step_id"),
            device_id=_identifier(obj["device_id"], f"{path}.device_id"),
            command_id=_identifier(obj["command_id"], f"{path}.command_id"),
            arguments=arguments,
            resource_ids=_sorted_unique_identifiers(
                obj["resource_ids"],
                f"{path}.resource_ids",
                nonempty=True,
                maximum=_MAX_RESOURCES + _MAX_DEVICES,
            ),
            timeout_ns=_integer(
                obj["timeout_ns"],
                f"{path}.timeout_ns",
                minimum=1,
                maximum=_MAX_TIMEOUT_NS,
            ),
            evidence_requirements=requirements,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "device_id": self.device_id,
            "command_id": self.command_id,
            "arguments": [item.to_dict() for item in self.arguments],
            "resource_ids": list(self.resource_ids),
            "timeout_ns": self.timeout_ns,
            "evidence_requirements": [
                item.to_dict() for item in self.evidence_requirements
            ],
        }


@dataclass(frozen=True)
class PhysicalProtocol:
    contract_version: str
    protocol_id: str
    manifest_digest: str
    failure_policy: str
    steps: tuple[ProtocolStep, ...]
    protocol_hash: str

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any) -> "PhysicalProtocol":
        obj = _exact_keys(
            value,
            "physical_protocol",
            {
                "contract_version",
                "protocol_id",
                "manifest_digest",
                "failure_policy",
                "steps",
                "protocol_hash",
            },
        )
        version = _identifier(
            obj["contract_version"], "physical_protocol.contract_version"
        )
        if version != PHYSICAL_PROTOCOL_VERSION:
            raise RuntimeContractError(
                "unsupported_contract",
                "physical_protocol.contract_version",
                f"expected {PHYSICAL_PROTOCOL_VERSION!r}",
            )
        failure_policy = _identifier(
            obj["failure_policy"], "physical_protocol.failure_policy"
        )
        if failure_policy != "safe_stop":
            raise RuntimeContractError(
                "unsupported_failure_policy",
                "physical_protocol.failure_policy",
                "v1 supports only safe_stop",
            )
        steps = tuple(
            ProtocolStep.from_dict(item, f"physical_protocol.steps[{index}]")
            for index, item in enumerate(
                _list(
                    obj["steps"],
                    "physical_protocol.steps",
                    nonempty=True,
                    maximum=_MAX_STEPS,
                )
            )
        )
        if len({item.step_id for item in steps}) != len(steps):
            raise RuntimeContractError(
                "duplicate_step", "physical_protocol.steps", "step ids must be unique"
            )
        result = cls(
            contract_version=version,
            protocol_id=_identifier(
                obj["protocol_id"], "physical_protocol.protocol_id"
            ),
            manifest_digest=_digest(
                obj["manifest_digest"], "physical_protocol.manifest_digest"
            ),
            failure_policy=failure_policy,
            steps=steps,
            protocol_hash=_digest(
                obj["protocol_hash"], "physical_protocol.protocol_hash"
            ),
        )
        result.verify_hash()
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "protocol_id": self.protocol_id,
            "manifest_digest": self.manifest_digest,
            "failure_policy": self.failure_policy,
            "steps": [item.to_dict() for item in self.steps],
            "protocol_hash": self.protocol_hash,
        }

    def verify_hash(self) -> None:
        expected = contract_hash(self.to_dict(), "protocol_hash")
        if self.protocol_hash != expected:
            raise RuntimeContractError(
                "hash_mismatch",
                "physical_protocol.protocol_hash",
                f"expected {expected}",
            )


_PHYSICAL_RESOLUTION_TOKEN = object()


@dataclass(frozen=True, init=False)
class ResolvedPhysicalProtocol:
    """Side-effect-free compatibility result; never execution authority."""

    manifest: PhysicalSystemManifest
    protocol: PhysicalProtocol
    qualification: str
    required_locks: tuple[str, ...]

    def __init__(
        self,
        *,
        manifest: PhysicalSystemManifest,
        protocol: PhysicalProtocol,
        qualification: str,
        required_locks: tuple[str, ...],
        _resolution_token: object | None = None,
    ) -> None:
        if _resolution_token is not _PHYSICAL_RESOLUTION_TOKEN:
            raise RuntimeContractError(
                "untrusted_resolution",
                "resolved_physical_protocol",
                "values may only be created by resolve_physical_protocol",
            )
        object.__setattr__(self, "manifest", manifest)
        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "qualification", qualification)
        object.__setattr__(self, "required_locks", required_locks)

    @property
    def physical_execution_authorized(self) -> bool:
        return False


def resolve_physical_protocol(
    manifest: PhysicalSystemManifest,
    protocol: PhysicalProtocol,
) -> ResolvedPhysicalProtocol:
    """Validate one sequential protocol without opening or invoking an adapter."""

    if protocol.manifest_digest != manifest.manifest_digest:
        raise RuntimeContractError(
            "manifest_mismatch",
            "physical_protocol.manifest_digest",
            "protocol targets a different physical manifest",
        )
    qualification = "qualified"
    required_locks: set[str] = set()
    for index, step in enumerate(protocol.steps):
        path = f"physical_protocol.steps[{index}]"
        device = manifest.device(step.device_id)
        if device is None:
            raise RuntimeContractError(
                "unknown_device", f"{path}.device_id", f"unknown {step.device_id!r}"
            )
        command = device.command(step.command_id)
        if command is None:
            raise RuntimeContractError(
                "unknown_command",
                f"{path}.command_id",
                f"device {device.device_id!r} has no command {step.command_id!r}",
            )
        if command.effect == "safety_stop":
            raise RuntimeContractError(
                "reserved_safety_stop_command",
                f"{path}.command_id",
                "safety-stop commands are reserved for mandatory cleanup",
            )
        argument_by_name = {item.name: item for item in step.arguments}
        field_by_name = {item.name: item for item in command.input_fields}
        unknown_arguments = set(argument_by_name) - set(field_by_name)
        missing_arguments = {
            item.name
            for item in command.input_fields
            if item.required and item.name not in argument_by_name
        }
        if unknown_arguments:
            raise RuntimeContractError(
                "unknown_argument",
                f"{path}.arguments",
                f"unknown arguments {sorted(unknown_arguments)!r}",
            )
        if missing_arguments:
            raise RuntimeContractError(
                "missing_argument",
                f"{path}.arguments",
                f"missing required arguments {sorted(missing_arguments)!r}",
            )
        for name, argument in argument_by_name.items():
            field = field_by_name[name]
            if argument.value_type != field.value_type:
                raise RuntimeContractError(
                    "argument_type_mismatch",
                    f"{path}.arguments.{name}",
                    f"expected {field.value_type!r}",
                )
            if argument.value_type in {"integer", "number"}:
                assert field.minimum is not None and field.maximum is not None
                if not field.minimum <= argument.value <= field.maximum:
                    raise RuntimeContractError(
                        "argument_out_of_bounds",
                        f"{path}.arguments.{name}",
                        f"must be within [{field.minimum:g}, {field.maximum:g}]",
                    )
        step_locks = set(step.resource_ids)
        unknown_locks = step_locks - manifest.lockable_ids
        if unknown_locks:
            raise RuntimeContractError(
                "unknown_resource",
                f"{path}.resource_ids",
                f"unknown lock ids {sorted(unknown_locks)!r}",
            )
        if device.device_id not in step_locks:
            raise RuntimeContractError(
                "missing_device_lock",
                f"{path}.resource_ids",
                f"must lock device {device.device_id!r}",
            )
        missing_locks = set(command.required_resources) - step_locks
        if missing_locks:
            raise RuntimeContractError(
                "missing_resource_lock",
                f"{path}.resource_ids",
                f"missing command locks {sorted(missing_locks)!r}",
            )
        if command.effect == "actuating":
            stop_command = next(
                item for item in device.commands if item.effect == "safety_stop"
            )
            missing_stop_locks = set(stop_command.required_resources) - step_locks
            if missing_stop_locks:
                raise RuntimeContractError(
                    "missing_safety_stop_lock",
                    f"{path}.resource_ids",
                    "actuating steps must reserve every safety-stop resource: "
                    f"{sorted(missing_stop_locks)!r}",
                )
        for requirement in step.evidence_requirements:
            producer = manifest.device(requirement.producer_device_id)
            if producer is None:
                raise RuntimeContractError(
                    "unknown_evidence_producer",
                    f"{path}.evidence_requirements.{requirement.requirement_id}",
                    f"unknown device {requirement.producer_device_id!r}",
                )
            producer_fields = {item.name: item for item in producer.state_fields}
            producer_field = producer_fields.get(requirement.state_field)
            if producer_field is None:
                raise RuntimeContractError(
                    "unknown_evidence_field",
                    f"{path}.evidence_requirements.{requirement.requirement_id}",
                    f"producer has no state field {requirement.state_field!r}",
                )
            if producer_field.value_type != requirement.value_type:
                raise RuntimeContractError(
                    "evidence_type_mismatch",
                    f"{path}.evidence_requirements.{requirement.requirement_id}",
                    f"producer field uses {producer_field.value_type!r}",
                )
            if requirement.value_type in {"integer", "number"}:
                assert (
                    producer_field.minimum is not None
                    and producer_field.maximum is not None
                )
                if not (
                    producer_field.minimum
                    <= requirement.expected_value
                    <= producer_field.maximum
                ):
                    raise RuntimeContractError(
                        "evidence_expectation_out_of_bounds",
                        f"{path}.evidence_requirements.{requirement.requirement_id}",
                        "expected evidence value falls outside producer field limits",
                    )
            if requirement.producer_device_id not in step_locks:
                raise RuntimeContractError(
                    "missing_evidence_producer_lock",
                    f"{path}.resource_ids",
                    "evidence producer devices must remain locked for the step",
                )
        independent_preconditions = []
        independent_postconditions = []
        for requirement in step.evidence_requirements:
            producer = manifest.device(requirement.producer_device_id)
            if (
                producer is not None
                and producer.trust_domain_digest != device.trust_domain_digest
            ):
                if requirement.phase == "precondition":
                    independent_preconditions.append(requirement)
                else:
                    independent_postconditions.append(requirement)
        if command.effect == "actuating" and not independent_preconditions:
            raise RuntimeContractError(
                "missing_actuation_precondition",
                f"{path}.evidence_requirements",
                "actuating steps require an independent precondition",
            )
        if command.effect == "actuating" and not independent_postconditions:
            raise RuntimeContractError(
                "missing_actuation_evidence",
                f"{path}.evidence_requirements",
                "actuating steps require an independent postcondition",
            )
        relevant_qualifications = [command.qualification]
        relevant_qualifications.extend(
            artifact.qualification
            for artifact_id in command.required_artifacts
            for artifact in [manifest.artifact(artifact_id)]
            if artifact is not None
        )
        if command.effect == "actuating":
            stop_command = next(
                item for item in device.commands if item.effect == "safety_stop"
            )
            relevant_qualifications.append(stop_command.qualification)
            relevant_qualifications.extend(
                artifact.qualification
                for artifact_id in stop_command.required_artifacts
                for artifact in [manifest.artifact(artifact_id)]
                if artifact is not None
            )
        for command_qualification in relevant_qualifications:
            if _QUALIFICATION_RANK[command_qualification] > _QUALIFICATION_RANK[
                qualification
            ]:
                qualification = command_qualification
        required_locks.update(step_locks)
    return ResolvedPhysicalProtocol(
        manifest=manifest,
        protocol=protocol,
        qualification=qualification,
        required_locks=tuple(sorted(required_locks)),
        _resolution_token=_PHYSICAL_RESOLUTION_TOKEN,
    )


@dataclass(frozen=True)
class RunTransition:
    sequence: int
    state: str
    monotonic_ns: int

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any, path: str = "transition") -> "RunTransition":
        obj = _exact_keys(value, path, {"sequence", "state", "monotonic_ns"})
        state = _identifier(obj["state"], f"{path}.state")
        if state not in _RUN_STATES:
            raise RuntimeContractError(
                "unsupported_run_state", f"{path}.state", f"unsupported {state!r}"
            )
        return cls(
            sequence=_integer(obj["sequence"], f"{path}.sequence"),
            state=state,
            monotonic_ns=_integer(obj["monotonic_ns"], f"{path}.monotonic_ns"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "state": self.state,
            "monotonic_ns": self.monotonic_ns,
        }


@dataclass(frozen=True)
class ResourceLock:
    resource_id: str
    acquired_monotonic_ns: int
    released_monotonic_ns: int | None

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any, path: str = "lock") -> "ResourceLock":
        obj = _exact_keys(
            value,
            path,
            {"resource_id", "acquired_monotonic_ns", "released_monotonic_ns"},
        )
        acquired = _integer(
            obj["acquired_monotonic_ns"], f"{path}.acquired_monotonic_ns"
        )
        released_value = obj["released_monotonic_ns"]
        released = (
            None
            if released_value is None
            else _integer(released_value, f"{path}.released_monotonic_ns")
        )
        if released is not None and released < acquired:
            raise RuntimeContractError(
                "invalid_timestamp_order",
                path,
                "release must not precede acquisition",
            )
        return cls(
            resource_id=_identifier(obj["resource_id"], f"{path}.resource_id"),
            acquired_monotonic_ns=acquired,
            released_monotonic_ns=released,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "acquired_monotonic_ns": self.acquired_monotonic_ns,
            "released_monotonic_ns": self.released_monotonic_ns,
        }


@dataclass(frozen=True)
class CommandRecord:
    dispatch_id: str
    step_id: str
    status: str
    dispatched_monotonic_ns: int
    completed_monotonic_ns: int
    acknowledged_monotonic_ns: int | None
    failure_code: str | None

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any, path: str = "command_record") -> "CommandRecord":
        obj = _exact_keys(
            value,
            path,
            {
                "dispatch_id",
                "step_id",
                "status",
                "dispatched_monotonic_ns",
                "completed_monotonic_ns",
                "acknowledged_monotonic_ns",
                "failure_code",
            },
        )
        status = _identifier(obj["status"], f"{path}.status")
        if status not in _COMMAND_STATUSES:
            raise RuntimeContractError(
                "unsupported_command_status",
                f"{path}.status",
                f"unsupported {status!r}",
            )
        dispatched = _integer(
            obj["dispatched_monotonic_ns"], f"{path}.dispatched_monotonic_ns"
        )
        completed = _integer(
            obj["completed_monotonic_ns"], f"{path}.completed_monotonic_ns"
        )
        if completed < dispatched:
            raise RuntimeContractError(
                "invalid_timestamp_order",
                path,
                "completion must not precede dispatch",
            )
        acknowledged_value = obj["acknowledged_monotonic_ns"]
        acknowledged = (
            None
            if acknowledged_value is None
            else _integer(
                acknowledged_value, f"{path}.acknowledged_monotonic_ns"
            )
        )
        failure_code = _optional_identifier(
            obj["failure_code"], f"{path}.failure_code"
        )
        if status == "acknowledged":
            if acknowledged is None or failure_code is not None:
                raise RuntimeContractError(
                    "invalid_command_outcome",
                    path,
                    "acknowledged requires an acknowledgement time and no failure code",
                )
            if acknowledged != completed:
                raise RuntimeContractError(
                    "invalid_command_outcome",
                    path,
                    "acknowledgement and terminal completion times must match",
                )
        elif acknowledged is not None or failure_code is None:
            raise RuntimeContractError(
                "invalid_command_outcome",
                path,
                "non-acknowledged outcomes require a failure code and no acknowledgement time",
            )
        if acknowledged is not None and acknowledged < dispatched:
            raise RuntimeContractError(
                "invalid_timestamp_order",
                path,
                "acknowledgement must not precede dispatch",
            )
        return cls(
            dispatch_id=_identifier(obj["dispatch_id"], f"{path}.dispatch_id"),
            step_id=_identifier(obj["step_id"], f"{path}.step_id"),
            status=status,
            dispatched_monotonic_ns=dispatched,
            completed_monotonic_ns=completed,
            acknowledged_monotonic_ns=acknowledged,
            failure_code=failure_code,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "dispatch_id": self.dispatch_id,
            "step_id": self.step_id,
            "status": self.status,
            "dispatched_monotonic_ns": self.dispatched_monotonic_ns,
            "completed_monotonic_ns": self.completed_monotonic_ns,
            "acknowledged_monotonic_ns": self.acknowledged_monotonic_ns,
            "failure_code": self.failure_code,
        }


@dataclass(frozen=True)
class SafeStopRecord:
    dispatch_id: str
    device_id: str
    dispatched_monotonic_ns: int
    completed_monotonic_ns: int
    confirmed: bool
    failure_code: str | None

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any, path: str = "safe_stop") -> "SafeStopRecord":
        obj = _exact_keys(
            value,
            path,
            {
                "dispatch_id",
                "device_id",
                "dispatched_monotonic_ns",
                "completed_monotonic_ns",
                "confirmed",
                "failure_code",
            },
        )
        dispatched = _integer(
            obj["dispatched_monotonic_ns"], f"{path}.dispatched_monotonic_ns"
        )
        completed = _integer(
            obj["completed_monotonic_ns"], f"{path}.completed_monotonic_ns"
        )
        if completed < dispatched:
            raise RuntimeContractError(
                "invalid_timestamp_order",
                path,
                "safe-stop completion must not precede dispatch",
            )
        confirmed = _boolean(obj["confirmed"], f"{path}.confirmed")
        failure_code = _optional_identifier(
            obj["failure_code"], f"{path}.failure_code"
        )
        if confirmed == (failure_code is not None):
            raise RuntimeContractError(
                "invalid_safe_stop_outcome",
                path,
                "confirmed stop requires no failure code; unconfirmed stop requires one",
            )
        return cls(
            dispatch_id=_identifier(obj["dispatch_id"], f"{path}.dispatch_id"),
            device_id=_identifier(obj["device_id"], f"{path}.device_id"),
            dispatched_monotonic_ns=dispatched,
            completed_monotonic_ns=completed,
            confirmed=confirmed,
            failure_code=failure_code,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "dispatch_id": self.dispatch_id,
            "device_id": self.device_id,
            "dispatched_monotonic_ns": self.dispatched_monotonic_ns,
            "completed_monotonic_ns": self.completed_monotonic_ns,
            "confirmed": self.confirmed,
            "failure_code": self.failure_code,
        }


@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: str
    step_id: str
    requirement_id: str
    evidence_kind: str
    producer_device_id: str
    state_field: str
    value_type: str
    observed_value: bool | int | float | str
    digest: str
    captured_monotonic_ns: int

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any, path: str = "evidence") -> "EvidenceRef":
        obj = _exact_keys(
            value,
            path,
            {
                "evidence_id",
                "step_id",
                "requirement_id",
                "evidence_kind",
                "producer_device_id",
                "state_field",
                "value_type",
                "observed_value",
                "digest",
                "captured_monotonic_ns",
            },
        )
        value_type = _scalar_type(obj["value_type"], f"{path}.value_type")
        return cls(
            evidence_id=_identifier(obj["evidence_id"], f"{path}.evidence_id"),
            step_id=_identifier(obj["step_id"], f"{path}.step_id"),
            requirement_id=_identifier(
                obj["requirement_id"], f"{path}.requirement_id"
            ),
            evidence_kind=_identifier(obj["evidence_kind"], f"{path}.evidence_kind"),
            producer_device_id=_identifier(
                obj["producer_device_id"], f"{path}.producer_device_id"
            ),
            state_field=_identifier(obj["state_field"], f"{path}.state_field"),
            value_type=value_type,
            observed_value=_scalar_value(
                obj["observed_value"], value_type, f"{path}.observed_value"
            ),
            digest=_digest(obj["digest"], f"{path}.digest"),
            captured_monotonic_ns=_integer(
                obj["captured_monotonic_ns"], f"{path}.captured_monotonic_ns"
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "step_id": self.step_id,
            "requirement_id": self.requirement_id,
            "evidence_kind": self.evidence_kind,
            "producer_device_id": self.producer_device_id,
            "state_field": self.state_field,
            "value_type": self.value_type,
            "observed_value": self.observed_value,
            "digest": self.digest,
            "captured_monotonic_ns": self.captured_monotonic_ns,
        }


@dataclass(frozen=True)
class RunOutcome:
    status: str
    failure_code: str | None

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any, path: str = "outcome") -> "RunOutcome":
        obj = _exact_keys(
            value,
            path,
            {
                "status",
                "failure_code",
            },
        )
        status = _identifier(obj["status"], f"{path}.status")
        if status not in _TERMINAL_STATES:
            raise RuntimeContractError(
                "unsupported_run_outcome", f"{path}.status", f"unsupported {status!r}"
            )
        failure_code = _optional_identifier(
            obj["failure_code"], f"{path}.failure_code"
        )
        if status == "succeeded" and failure_code is not None:
            raise RuntimeContractError(
                "invalid_run_outcome", path, "success cannot carry a failure code"
            )
        if status != "succeeded" and failure_code is None:
            raise RuntimeContractError(
                "invalid_run_outcome", path, "failure or cancellation needs a code"
            )
        return cls(
            status=status,
            failure_code=failure_code,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "failure_code": self.failure_code,
        }


@dataclass(frozen=True)
class PhysicalRunRecord:
    contract_version: str
    run_id: str
    manifest_digest: str
    protocol_hash: str
    authorization_digest: str
    lifecycle: tuple[RunTransition, ...]
    locks: tuple[ResourceLock, ...]
    commands: tuple[CommandRecord, ...]
    safe_stops: tuple[SafeStopRecord, ...]
    evidence: tuple[EvidenceRef, ...]
    outcome: RunOutcome
    run_digest: str

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any) -> "PhysicalRunRecord":
        obj = _exact_keys(
            value,
            "physical_run_record",
            {
                "contract_version",
                "run_id",
                "manifest_digest",
                "protocol_hash",
                "authorization_digest",
                "lifecycle",
                "locks",
                "commands",
                "safe_stops",
                "evidence",
                "outcome",
                "run_digest",
            },
        )
        version = _identifier(
            obj["contract_version"], "physical_run_record.contract_version"
        )
        if version != PHYSICAL_RUN_RECORD_VERSION:
            raise RuntimeContractError(
                "unsupported_contract",
                "physical_run_record.contract_version",
                f"expected {PHYSICAL_RUN_RECORD_VERSION!r}",
            )
        lifecycle = tuple(
            RunTransition.from_dict(item, f"physical_run_record.lifecycle[{index}]")
            for index, item in enumerate(
                _list(
                    obj["lifecycle"],
                    "physical_run_record.lifecycle",
                    nonempty=True,
                    maximum=_MAX_LIFECYCLE_TRANSITIONS,
                )
            )
        )
        if lifecycle[0].state != "created" or lifecycle[0].sequence != 0:
            raise RuntimeContractError(
                "invalid_run_lifecycle",
                "physical_run_record.lifecycle",
                "must start with sequence 0 in created",
            )
        if lifecycle[-1].state not in _TERMINAL_STATES:
            raise RuntimeContractError(
                "invalid_run_lifecycle",
                "physical_run_record.lifecycle",
                "a run record must end in a terminal state",
            )
        for index, transition in enumerate(lifecycle):
            if transition.sequence != index:
                raise RuntimeContractError(
                    "invalid_run_sequence",
                    f"physical_run_record.lifecycle[{index}].sequence",
                    "sequence numbers must be contiguous from zero",
                )
            if index:
                previous = lifecycle[index - 1]
                if transition.state not in _ALLOWED_TRANSITIONS.get(
                    previous.state, frozenset()
                ):
                    raise RuntimeContractError(
                        "invalid_run_transition",
                        f"physical_run_record.lifecycle[{index}].state",
                        f"cannot transition from {previous.state!r} to {transition.state!r}",
                    )
                if transition.monotonic_ns < previous.monotonic_ns:
                    raise RuntimeContractError(
                        "invalid_timestamp_order",
                        f"physical_run_record.lifecycle[{index}].monotonic_ns",
                        "lifecycle timestamps must not decrease",
                    )
        locks = tuple(
            ResourceLock.from_dict(item, f"physical_run_record.locks[{index}]")
            for index, item in enumerate(
                _list(
                    obj["locks"],
                    "physical_run_record.locks",
                    maximum=_MAX_RESOURCES + _MAX_DEVICES,
                )
            )
        )
        lock_ids = tuple(item.resource_id for item in locks)
        if len(set(lock_ids)) != len(lock_ids):
            raise RuntimeContractError(
                "duplicate_resource_lock",
                "physical_run_record.locks",
                "resource ids must be unique",
            )
        if tuple(sorted(lock_ids)) != lock_ids:
            raise RuntimeContractError(
                "noncanonical_order",
                "physical_run_record.locks",
                "locks must be sorted by resource_id",
            )
        commands = tuple(
            CommandRecord.from_dict(item, f"physical_run_record.commands[{index}]")
            for index, item in enumerate(
                _list(
                    obj["commands"],
                    "physical_run_record.commands",
                    maximum=_MAX_STEPS,
                )
            )
        )
        if len({item.dispatch_id for item in commands}) != len(commands):
            raise RuntimeContractError(
                "duplicate_dispatch",
                "physical_run_record.commands",
                "dispatch ids must be unique",
            )
        if len({item.step_id for item in commands}) != len(commands):
            raise RuntimeContractError(
                "duplicate_step_record",
                "physical_run_record.commands",
                "each step may be dispatched at most once",
            )
        command_order = tuple(
            (item.dispatched_monotonic_ns, item.dispatch_id) for item in commands
        )
        if tuple(sorted(command_order)) != command_order:
            raise RuntimeContractError(
                "noncanonical_order",
                "physical_run_record.commands",
                "commands must be ordered by dispatch time and id",
            )
        if any(
            current.dispatched_monotonic_ns <= previous.dispatched_monotonic_ns
            for previous, current in zip(commands, commands[1:])
        ):
            raise RuntimeContractError(
                "invalid_timestamp_order",
                "physical_run_record.commands",
                "sequential command dispatch times must strictly increase",
            )
        safe_stops = tuple(
            SafeStopRecord.from_dict(
                item, f"physical_run_record.safe_stops[{index}]"
            )
            for index, item in enumerate(
                _list(
                    obj["safe_stops"],
                    "physical_run_record.safe_stops",
                    maximum=_MAX_DEVICES,
                )
            )
        )
        safe_stop_device_ids = tuple(item.device_id for item in safe_stops)
        if len(set(safe_stop_device_ids)) != len(safe_stops):
            raise RuntimeContractError(
                "duplicate_safe_stop",
                "physical_run_record.safe_stops",
                "each device may have exactly one safe-stop record",
            )
        if tuple(sorted(safe_stop_device_ids)) != safe_stop_device_ids:
            raise RuntimeContractError(
                "noncanonical_order",
                "physical_run_record.safe_stops",
                "safe stops must be sorted by device_id",
            )
        if len({item.dispatch_id for item in safe_stops}) != len(safe_stops):
            raise RuntimeContractError(
                "duplicate_dispatch",
                "physical_run_record.safe_stops",
                "safe-stop dispatch ids must be unique",
            )
        evidence = tuple(
            EvidenceRef.from_dict(item, f"physical_run_record.evidence[{index}]")
            for index, item in enumerate(
                _list(
                    obj["evidence"],
                    "physical_run_record.evidence",
                    maximum=_MAX_EVIDENCE,
                )
            )
        )
        evidence_ids = tuple(item.evidence_id for item in evidence)
        if len(set(evidence_ids)) != len(evidence_ids):
            raise RuntimeContractError(
                "duplicate_evidence",
                "physical_run_record.evidence",
                "evidence ids must be unique",
            )
        if tuple(sorted(evidence_ids)) != evidence_ids:
            raise RuntimeContractError(
                "noncanonical_order",
                "physical_run_record.evidence",
                "evidence must be sorted by evidence_id",
            )
        outcome = RunOutcome.from_dict(obj["outcome"], "physical_run_record.outcome")
        if lifecycle[-1].state != outcome.status:
            raise RuntimeContractError(
                "run_outcome_mismatch",
                "physical_run_record.outcome.status",
                "outcome must match the final lifecycle state",
            )
        started = lifecycle[0].monotonic_ns
        finished = lifecycle[-1].monotonic_ns
        for lock in locks:
            if lock.acquired_monotonic_ns < started:
                raise RuntimeContractError(
                    "invalid_timestamp_order",
                    "physical_run_record.locks",
                    "lock acquisition cannot predate run creation",
                )
            if lock.released_monotonic_ns is None:
                raise RuntimeContractError(
                    "unreleased_resource",
                    "physical_run_record.locks",
                    "terminal run records require every lock to be released",
                )
            if lock.released_monotonic_ns > finished:
                raise RuntimeContractError(
                    "invalid_timestamp_order",
                    "physical_run_record.locks",
                    "lock release cannot follow the terminal transition",
                )
        for command in commands:
            if not started <= command.dispatched_monotonic_ns <= finished:
                raise RuntimeContractError(
                    "invalid_timestamp_order",
                    "physical_run_record.commands",
                    "dispatch must occur within the run lifecycle",
                )
            if (
                command.acknowledged_monotonic_ns is not None
                and command.acknowledged_monotonic_ns > finished
            ):
                raise RuntimeContractError(
                    "invalid_timestamp_order",
                    "physical_run_record.commands",
                    "acknowledgement cannot follow the terminal transition",
                )
            if command.completed_monotonic_ns > finished:
                raise RuntimeContractError(
                    "invalid_timestamp_order",
                    "physical_run_record.commands",
                    "command completion cannot follow the terminal transition",
                )
        for stop in safe_stops:
            if not started <= stop.dispatched_monotonic_ns <= finished:
                raise RuntimeContractError(
                    "invalid_timestamp_order",
                    "physical_run_record.safe_stops",
                    "safe-stop dispatch must occur within the run lifecycle",
                )
            if stop.completed_monotonic_ns > finished:
                raise RuntimeContractError(
                    "invalid_timestamp_order",
                    "physical_run_record.safe_stops",
                    "safe-stop completion cannot follow the terminal transition",
                )
        for item in evidence:
            if not started <= item.captured_monotonic_ns <= finished:
                raise RuntimeContractError(
                    "invalid_timestamp_order",
                    "physical_run_record.evidence",
                    "evidence capture must occur within the run lifecycle",
                )
        result = cls(
            contract_version=version,
            run_id=_identifier(obj["run_id"], "physical_run_record.run_id"),
            manifest_digest=_digest(
                obj["manifest_digest"], "physical_run_record.manifest_digest"
            ),
            protocol_hash=_digest(
                obj["protocol_hash"], "physical_run_record.protocol_hash"
            ),
            authorization_digest=_digest(
                obj["authorization_digest"],
                "physical_run_record.authorization_digest",
            ),
            lifecycle=lifecycle,
            locks=locks,
            commands=commands,
            safe_stops=safe_stops,
            evidence=evidence,
            outcome=outcome,
            run_digest=_digest(obj["run_digest"], "physical_run_record.run_digest"),
        )
        result.verify_digest()
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "run_id": self.run_id,
            "manifest_digest": self.manifest_digest,
            "protocol_hash": self.protocol_hash,
            "authorization_digest": self.authorization_digest,
            "lifecycle": [item.to_dict() for item in self.lifecycle],
            "locks": [item.to_dict() for item in self.locks],
            "commands": [item.to_dict() for item in self.commands],
            "safe_stops": [item.to_dict() for item in self.safe_stops],
            "evidence": [item.to_dict() for item in self.evidence],
            "outcome": self.outcome.to_dict(),
            "run_digest": self.run_digest,
        }

    def verify_digest(self) -> None:
        expected = contract_hash(self.to_dict(), "run_digest")
        if self.run_digest != expected:
            raise RuntimeContractError(
                "hash_mismatch",
                "physical_run_record.run_digest",
                f"expected {expected}",
            )


def validate_physical_run_record(
    record: PhysicalRunRecord,
    resolved: ResolvedPhysicalProtocol,
) -> None:
    """Cross-check terminal run evidence against one resolved protocol."""

    if record.manifest_digest != resolved.manifest.manifest_digest:
        raise RuntimeContractError(
            "manifest_mismatch",
            "physical_run_record.manifest_digest",
            "run record targets a different manifest",
        )
    if record.protocol_hash != resolved.protocol.protocol_hash:
        raise RuntimeContractError(
            "protocol_mismatch",
            "physical_run_record.protocol_hash",
            "run record targets a different protocol",
        )
    lifecycle_states = {item.state for item in record.lifecycle}
    expected_locks = set(resolved.required_locks) if "locked" in lifecycle_states else set()
    actual_locks = {item.resource_id for item in record.locks}
    if actual_locks != expected_locks:
        raise RuntimeContractError(
            "resource_lock_mismatch",
            "physical_run_record.locks",
            f"expected exact locks {sorted(expected_locks)!r}",
        )
    protocol_steps = resolved.protocol.steps
    step_by_id = {item.step_id: item for item in protocol_steps}
    command_steps = tuple(item.step_id for item in record.commands)
    expected_prefix = tuple(item.step_id for item in protocol_steps[: len(record.commands)])
    if command_steps != expected_prefix:
        raise RuntimeContractError(
            "command_order_mismatch",
            "physical_run_record.commands",
            "command records must be the exact ordered protocol prefix",
        )
    if "running" not in lifecycle_states and record.commands:
        raise RuntimeContractError(
            "command_without_running",
            "physical_run_record.commands",
            "commands require a running lifecycle transition",
        )
    running_transition = next(
        (item for item in record.lifecycle if item.state == "running"), None
    )
    if running_transition is not None and any(
        item.dispatched_monotonic_ns < running_transition.monotonic_ns
        for item in record.commands
    ):
        raise RuntimeContractError(
            "command_before_running",
            "physical_run_record.commands",
            "command dispatch cannot precede the running transition",
        )
    locked_transition = next(
        (item for item in record.lifecycle if item.state == "locked"), None
    )
    if locked_transition is not None and any(
        item.acquired_monotonic_ns > locked_transition.monotonic_ns
        for item in record.locks
    ):
        raise RuntimeContractError(
            "late_resource_lock",
            "physical_run_record.locks",
            "all resources must be acquired before entering locked",
        )
    for previous, current in zip(record.commands, record.commands[1:]):
        if previous.status != "acknowledged":
            raise RuntimeContractError(
                "command_after_failure",
                "physical_run_record.commands",
                "a sequential protocol cannot dispatch after a non-acknowledged command",
            )
        if current.dispatched_monotonic_ns < previous.completed_monotonic_ns:
            raise RuntimeContractError(
                "overlapping_command_dispatch",
                "physical_run_record.commands",
                "a sequential step cannot dispatch before prior completion",
            )
    lock_by_id = {item.resource_id: item for item in record.locks}
    command_by_step = {item.step_id: item for item in record.commands}
    if record.evidence and "locked" not in lifecycle_states:
        raise RuntimeContractError(
            "evidence_without_locks",
            "physical_run_record.evidence",
            "physical evidence requires the resolved resources to be locked",
        )
    next_undispatched_step = (
        protocol_steps[len(record.commands)]
        if len(record.commands) < len(protocol_steps)
        else None
    )
    for command_record in record.commands:
        step = step_by_id[command_record.step_id]
        elapsed = (
            command_record.completed_monotonic_ns
            - command_record.dispatched_monotonic_ns
        )
        if command_record.status == "timed_out":
            if elapsed < step.timeout_ns:
                raise RuntimeContractError(
                    "premature_timeout",
                    "physical_run_record.commands",
                    "timed_out classification cannot precede the step timeout",
                )
        elif elapsed > step.timeout_ns:
            raise RuntimeContractError(
                "command_timeout_exceeded",
                "physical_run_record.commands",
                "non-timeout command completion exceeded the step timeout",
            )
        for resource_id in step.resource_ids:
            lock = lock_by_id[resource_id]
            assert lock.released_monotonic_ns is not None
            if (
                lock.acquired_monotonic_ns > command_record.dispatched_monotonic_ns
                or lock.released_monotonic_ns < command_record.completed_monotonic_ns
            ):
                raise RuntimeContractError(
                    "lock_not_held_for_command",
                    "physical_run_record.locks",
                    f"resource {resource_id!r} did not cover step {step.step_id!r}",
                )
    evidence_by_key: dict[tuple[str, str], EvidenceRef] = {}
    evidence_matches: dict[tuple[str, str], bool] = {}
    for item in record.evidence:
        step = step_by_id.get(item.step_id)
        if step is None:
            raise RuntimeContractError(
                "unknown_evidence_step",
                "physical_run_record.evidence",
                f"unknown step {item.step_id!r}",
            )
        requirement = next(
            (
                required
                for required in step.evidence_requirements
                if required.requirement_id == item.requirement_id
            ),
            None,
        )
        if requirement is None:
            raise RuntimeContractError(
                "unknown_evidence_requirement",
                "physical_run_record.evidence",
                f"unknown requirement {item.requirement_id!r} for {item.step_id!r}",
            )
        if (
            item.evidence_kind != requirement.evidence_kind
            or item.producer_device_id != requirement.producer_device_id
            or item.state_field != requirement.state_field
            or item.value_type != requirement.value_type
        ):
            raise RuntimeContractError(
                "evidence_requirement_mismatch",
                "physical_run_record.evidence",
                "evidence kind, producer, state field and type must match the requirement",
            )
        producer = resolved.manifest.device(requirement.producer_device_id)
        assert producer is not None
        producer_field = next(
            field for field in producer.state_fields if field.name == requirement.state_field
        )
        if item.value_type in {"integer", "number"}:
            assert producer_field.minimum is not None and producer_field.maximum is not None
            if not (
                producer_field.minimum
                <= item.observed_value
                <= producer_field.maximum
            ):
                raise RuntimeContractError(
                    "evidence_observation_out_of_bounds",
                    "physical_run_record.evidence",
                    "observed evidence value falls outside producer field limits",
                )
        command_record = command_by_step.get(item.step_id)
        blocked_precondition = (
            command_record is None
            and next_undispatched_step is not None
            and item.step_id == next_undispatched_step.step_id
            and requirement.phase == "precondition"
            and record.outcome.status == "failed"
        )
        if command_record is None and not blocked_precondition:
            raise RuntimeContractError(
                "evidence_without_command",
                "physical_run_record.evidence",
                "evidence requires a command or the next blocked precondition",
            )
        if blocked_precondition:
            prior_completion = (
                record.commands[-1].completed_monotonic_ns
                if record.commands
                else record.lifecycle[0].monotonic_ns
            )
            if item.captured_monotonic_ns < prior_completion:
                raise RuntimeContractError(
                    "precondition_before_prior_completion",
                    "physical_run_record.evidence",
                    "a blocked precondition cannot predate the prior step completion",
                )
            age_ns = (
                record.lifecycle[-1].monotonic_ns - item.captured_monotonic_ns
            )
        elif requirement.phase == "precondition":
            assert command_record is not None
            age_ns = command_record.dispatched_monotonic_ns - item.captured_monotonic_ns
            if age_ns < 0:
                raise RuntimeContractError(
                    "late_precondition_evidence",
                    "physical_run_record.evidence",
                    "precondition evidence must be captured before dispatch",
                )
        else:
            assert command_record is not None
            age_ns = item.captured_monotonic_ns - command_record.completed_monotonic_ns
            if age_ns < 0:
                raise RuntimeContractError(
                    "early_postcondition_evidence",
                    "physical_run_record.evidence",
                    "postcondition evidence must be captured after command completion",
                )
        if age_ns > requirement.maximum_age_ns:
            raise RuntimeContractError(
                "stale_evidence",
                "physical_run_record.evidence",
                "evidence falls outside the requirement freshness window",
            )
        predicate_matches = _predicate_matches(
            requirement.operator, item.observed_value, requirement.expected_value
        )
        if (
            requirement.phase == "precondition"
            and not predicate_matches
            and not blocked_precondition
        ):
            raise RuntimeContractError(
                "evidence_predicate_failed",
                "physical_run_record.evidence",
                f"requirement {requirement.requirement_id!r} was not satisfied",
            )
        for resource_id in step.resource_ids:
            lock = lock_by_id[resource_id]
            assert lock.released_monotonic_ns is not None
            if (
                lock.acquired_monotonic_ns > item.captured_monotonic_ns
                or lock.released_monotonic_ns < item.captured_monotonic_ns
            ):
                raise RuntimeContractError(
                    "lock_not_held_for_evidence",
                    "physical_run_record.locks",
                    f"resource {resource_id!r} did not cover evidence for {step.step_id!r}",
                )
        key = (item.step_id, item.requirement_id)
        if key in evidence_by_key:
            raise RuntimeContractError(
                "duplicate_requirement_evidence",
                "physical_run_record.evidence",
                "each step requirement has exactly one retained evidence reference",
            )
        evidence_by_key[key] = item
        evidence_matches[key] = predicate_matches
    if next_undispatched_step is not None:
        blocked_keys = [
            (next_undispatched_step.step_id, requirement.requirement_id)
            for requirement in next_undispatched_step.evidence_requirements
            if requirement.phase == "precondition"
            and (next_undispatched_step.step_id, requirement.requirement_id)
            in evidence_by_key
        ]
        if blocked_keys and all(evidence_matches[key] for key in blocked_keys):
            raise RuntimeContractError(
                "unjustified_precondition_block",
                "physical_run_record.evidence",
                "an undispatched step needs at least one failed retained precondition",
            )
    for index, command_record in enumerate(record.commands):
        step = step_by_id[command_record.step_id]
        previous_command = record.commands[index - 1] if index else None
        for requirement in step.evidence_requirements:
            if requirement.phase != "precondition":
                continue
            key = (step.step_id, requirement.requirement_id)
            item = evidence_by_key.get(key)
            if item is None:
                raise RuntimeContractError(
                    "missing_precondition_evidence",
                    "physical_run_record.evidence",
                    f"step {step.step_id!r} was dispatched without its precondition",
                )
            if (
                previous_command is not None
                and item.captured_monotonic_ns
                < previous_command.completed_monotonic_ns
            ):
                raise RuntimeContractError(
                    "precondition_before_prior_completion",
                    "physical_run_record.evidence",
                    "a step precondition cannot predate the prior step completion",
                )
        if index + 1 >= len(record.commands):
            continue
        next_command = record.commands[index + 1]
        for requirement in step.evidence_requirements:
            if requirement.phase != "postcondition":
                continue
            key = (step.step_id, requirement.requirement_id)
            item = evidence_by_key.get(key)
            if item is None:
                raise RuntimeContractError(
                    "missing_postcondition_evidence",
                    "physical_run_record.evidence",
                    "the next step was dispatched before the prior postcondition existed",
                )
            if not evidence_matches[key]:
                raise RuntimeContractError(
                    "evidence_predicate_failed",
                    "physical_run_record.evidence",
                    f"requirement {requirement.requirement_id!r} was not satisfied",
                )
            if item.captured_monotonic_ns > next_command.dispatched_monotonic_ns:
                raise RuntimeContractError(
                    "command_before_postcondition",
                    "physical_run_record.commands",
                    "the next step dispatched before the prior postcondition was observed",
                )
            if (
                next_command.dispatched_monotonic_ns - item.captured_monotonic_ns
                > requirement.maximum_age_ns
            ):
                raise RuntimeContractError(
                    "stale_postcondition_barrier",
                    "physical_run_record.evidence",
                    "the prior postcondition expired before the next step dispatched",
                )
    if record.outcome.status == "succeeded":
        if len(record.commands) != len(protocol_steps) or any(
            item.status != "acknowledged" for item in record.commands
        ):
            raise RuntimeContractError(
                "incomplete_success",
                "physical_run_record.commands",
                "success requires every protocol command to be acknowledged",
            )
        required_evidence = {
            (step.step_id, requirement.requirement_id)
            for step in protocol_steps
            for requirement in step.evidence_requirements
        }
        if set(evidence_by_key) != required_evidence:
            raise RuntimeContractError(
                "incomplete_success_evidence",
                "physical_run_record.evidence",
                "success requires exactly one reference for every requirement",
            )
        failed_predicates = sorted(
            key for key in required_evidence if not evidence_matches[key]
        )
        if failed_predicates:
            raise RuntimeContractError(
                "evidence_predicate_failed",
                "physical_run_record.evidence",
                f"success predicates were not satisfied: {failed_predicates!r}",
            )
    if any(item.status in {"timed_out", "failed"} for item in record.commands) and (
        record.outcome.status != "failed"
    ):
        raise RuntimeContractError(
            "command_outcome_mismatch",
            "physical_run_record.outcome.status",
            "failed or timed-out commands require a failed run",
        )
    if any(item.status == "cancelled" for item in record.commands) and (
        record.outcome.status != "cancelled"
    ):
        raise RuntimeContractError(
            "command_outcome_mismatch",
            "physical_run_record.outcome.status",
            "a cancelled command requires a cancelled run",
        )
    actuating_by_device: dict[str, list[CommandRecord]] = {}
    for command_record in record.commands:
        step = step_by_id[command_record.step_id]
        device = resolved.manifest.device(step.device_id)
        assert device is not None
        command = device.command(step.command_id)
        assert command is not None
        if command.effect == "actuating":
            actuating_by_device.setdefault(device.device_id, []).append(command_record)
    safe_stop_by_device = {item.device_id: item for item in record.safe_stops}
    if set(safe_stop_by_device) != set(actuating_by_device):
        raise RuntimeContractError(
            "safe_stop_coverage_mismatch",
            "physical_run_record.safe_stops",
            "every device with dispatched actuation needs exactly one safe-stop record",
        )
    command_dispatch_ids = {item.dispatch_id for item in record.commands}
    if command_dispatch_ids & {item.dispatch_id for item in record.safe_stops}:
        raise RuntimeContractError(
            "duplicate_dispatch",
            "physical_run_record.safe_stops",
            "command and safe-stop dispatch ids must be disjoint",
        )
    for device_id, stop_record in safe_stop_by_device.items():
        device = resolved.manifest.device(device_id)
        assert device is not None
        stop_command = next(
            item for item in device.commands if item.effect == "safety_stop"
        )
        last_actuation_completion = max(
            item.completed_monotonic_ns for item in actuating_by_device[device_id]
        )
        if stop_record.dispatched_monotonic_ns < last_actuation_completion:
            raise RuntimeContractError(
                "early_safe_stop",
                "physical_run_record.safe_stops",
                "safe-stop dispatch cannot precede the final actuation outcome",
            )
        for resource_id in stop_command.required_resources:
            lock = lock_by_id[resource_id]
            assert lock.released_monotonic_ns is not None
            if (
                lock.acquired_monotonic_ns > stop_record.dispatched_monotonic_ns
                or lock.released_monotonic_ns < stop_record.completed_monotonic_ns
            ):
                raise RuntimeContractError(
                    "lock_not_held_for_safe_stop",
                    "physical_run_record.locks",
                    f"resource {resource_id!r} did not cover safe stop for {device_id!r}",
                )
    if record.outcome.status == "succeeded" and any(
        not item.confirmed for item in record.safe_stops
    ):
        raise RuntimeContractError(
            "unconfirmed_safe_stop",
            "physical_run_record.safe_stops",
            "successful actuation requires confirmed safe-stop cleanup",
        )


def seal_physical_manifest(value: dict[str, Any]) -> dict[str, Any]:
    """Canonicalize set-like manifest members, hash, and validate."""

    sealed = copy.deepcopy(value)
    sealed.setdefault("contract_version", PHYSICAL_MANIFEST_VERSION)
    if isinstance(sealed.get("resources"), list):
        sealed["resources"] = sorted(
            sealed["resources"],
            key=lambda item: (
                str(item.get("resource_id", "")) if isinstance(item, dict) else "",
                str(item.get("kind", "")) if isinstance(item, dict) else "",
            ),
        )
    if isinstance(sealed.get("artifacts"), list):
        sealed["artifacts"] = sorted(
            sealed["artifacts"],
            key=lambda item: (
                str(item.get("artifact_id", "")) if isinstance(item, dict) else ""
            ),
        )
    if isinstance(sealed.get("devices"), list):
        for device in sealed["devices"]:
            if not isinstance(device, dict):
                continue
            if isinstance(device.get("state_fields"), list):
                device["state_fields"] = sorted(
                    device["state_fields"],
                    key=lambda item: (
                        str(item.get("name", "")) if isinstance(item, dict) else ""
                    ),
                )
            if isinstance(device.get("commands"), list):
                for command in device["commands"]:
                    if not isinstance(command, dict):
                        continue
                    for key in ("input_fields", "output_fields"):
                        if isinstance(command.get(key), list):
                            command[key] = sorted(
                                command[key],
                                key=lambda item: (
                                    str(item.get("name", ""))
                                    if isinstance(item, dict)
                                    else ""
                                ),
                            )
                    for key in ("required_resources", "required_artifacts"):
                        if isinstance(command.get(key), list):
                            command[key] = sorted(command[key], key=str)
                device["commands"] = sorted(
                    device["commands"],
                    key=lambda item: (
                        str(item.get("command_id", ""))
                        if isinstance(item, dict)
                        else ""
                    ),
                )
        sealed["devices"] = sorted(
            sealed["devices"],
            key=lambda item: (
                str(item.get("device_id", "")) if isinstance(item, dict) else ""
            ),
        )
    sealed["manifest_digest"] = contract_hash(sealed, "manifest_digest")
    return PhysicalSystemManifest.from_dict(sealed).to_dict()


def seal_physical_protocol(value: dict[str, Any]) -> dict[str, Any]:
    """Canonicalize set-like step members, hash, and validate."""

    sealed = copy.deepcopy(value)
    sealed.setdefault("contract_version", PHYSICAL_PROTOCOL_VERSION)
    if isinstance(sealed.get("steps"), list):
        for step in sealed["steps"]:
            if not isinstance(step, dict):
                continue
            if isinstance(step.get("arguments"), list):
                step["arguments"] = sorted(
                    step["arguments"],
                    key=lambda item: (
                        str(item.get("name", "")) if isinstance(item, dict) else ""
                    ),
                )
            if isinstance(step.get("resource_ids"), list):
                step["resource_ids"] = sorted(step["resource_ids"], key=str)
            if isinstance(step.get("evidence_requirements"), list):
                step["evidence_requirements"] = sorted(
                    step["evidence_requirements"],
                    key=lambda item: (
                        str(item.get("requirement_id", ""))
                        if isinstance(item, dict)
                        else ""
                    ),
                )
    sealed["protocol_hash"] = contract_hash(sealed, "protocol_hash")
    return PhysicalProtocol.from_dict(sealed).to_dict()


def seal_physical_run_record(value: dict[str, Any]) -> dict[str, Any]:
    """Canonicalize set-like run members, hash, and validate."""

    sealed = copy.deepcopy(value)
    sealed.setdefault("contract_version", PHYSICAL_RUN_RECORD_VERSION)
    if isinstance(sealed.get("locks"), list):
        sealed["locks"] = sorted(
            sealed["locks"],
            key=lambda item: (
                str(item.get("resource_id", "")) if isinstance(item, dict) else ""
            ),
        )
    if isinstance(sealed.get("commands"), list):
        sealed["commands"] = sorted(
            sealed["commands"],
            key=lambda item: (
                _integer_sort_key(item.get("dispatched_monotonic_ns"))
                if isinstance(item, dict)
                else (1, ""),
                str(item.get("dispatch_id", "")) if isinstance(item, dict) else "",
            ),
        )
    if isinstance(sealed.get("safe_stops"), list):
        sealed["safe_stops"] = sorted(
            sealed["safe_stops"],
            key=lambda item: (
                str(item.get("device_id", "")) if isinstance(item, dict) else ""
            ),
        )
    if isinstance(sealed.get("evidence"), list):
        sealed["evidence"] = sorted(
            sealed["evidence"],
            key=lambda item: (
                str(item.get("evidence_id", "")) if isinstance(item, dict) else ""
            ),
        )
    sealed["run_digest"] = contract_hash(sealed, "run_digest")
    return PhysicalRunRecord.from_dict(sealed).to_dict()


__all__ = [
    "PHYSICAL_MANIFEST_VERSION",
    "PHYSICAL_PROTOCOL_VERSION",
    "PHYSICAL_RUN_RECORD_VERSION",
    "CommandRecord",
    "EvidenceRef",
    "EvidenceRequirement",
    "PhysicalArtifact",
    "PhysicalCommand",
    "PhysicalDevice",
    "PhysicalProtocol",
    "PhysicalResource",
    "PhysicalRunRecord",
    "PhysicalSystemManifest",
    "ProtocolStep",
    "ResolvedPhysicalProtocol",
    "ResourceLock",
    "RunOutcome",
    "RunTransition",
    "SafeStopRecord",
    "TypedArgument",
    "TypedField",
    "resolve_physical_protocol",
    "physical_identity_digest",
    "physical_trust_domain_digest",
    "seal_physical_manifest",
    "seal_physical_protocol",
    "seal_physical_run_record",
    "validate_physical_run_record",
]
