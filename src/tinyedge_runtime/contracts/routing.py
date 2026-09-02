"""Neutral, deterministic routing for qualified physical skill implementations.

The contracts in this module describe a sealed workcell-local skill catalogue,
one point-in-time routing request, and the resulting explainable decision.  The
resolver performs no I/O, imports no adapter, grants no execution authority,
and assigns no special meaning to an implementation mechanism or provider.

Hosts are responsible for projecting authenticated, current device and
qualification state into these contracts.  Runtime only compares exact
bindings, evaluates fail-closed eligibility, and applies the explicit total
order supplied by policy.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Iterable

from .hashing import canonical_sha256, contract_hash
from .models import (
    RuntimeContractError,
    _digest,
    _exact_keys,
    _identifier,
    _integer,
    _list,
    _optional_integer,
    _validate_constructed,
)
from .physical import TypedArgument, TypedField


PHYSICAL_SKILL_CATALOG_VERSION = "tinyedge-runtime-physical-skill-catalog-v1"
PHYSICAL_SKILL_ROUTE_REQUEST_VERSION = (
    "tinyedge-runtime-physical-skill-route-request-v1"
)
PHYSICAL_SKILL_ROUTE_DECISION_VERSION = (
    "tinyedge-runtime-physical-skill-route-decision-v1"
)

_IMPLEMENTATION_STATUSES = frozenset({"available", "blocked"})
_PRECONDITION_STATUSES = frozenset({"met", "violated", "unknown"})
_QUALIFICATION_STATUSES = frozenset(
    {"qualified", "demo_qualified", "provisional", "blocked"}
)
_POLICY_QUALIFICATION_STATUSES = frozenset(
    {"qualified", "demo_qualified", "provisional"}
)
_CANDIDATE_STATUSES = frozenset(
    {"selected", "eligible_not_selected", "rejected"}
)
_DECISION_STATUSES = frozenset({"selected", "no_match"})

_REQUEST_REJECTION_CODES = frozenset(
    {
        "catalog_mismatch",
        "argument_out_of_bounds",
        "argument_type_mismatch",
        "missing_argument",
        "policy_incomplete",
        "policy_unknown_implementation",
        "skill_definition_mismatch",
        "unknown_skill",
        "unknown_argument",
        "workcell_mismatch",
    }
)
_CANDIDATE_REJECTION_CODES = frozenset(
    {
        "artifact_mismatch",
        "artifact_missing",
        "calibration_mismatch",
        "calibration_missing",
        "dependency_mismatch",
        "dependency_missing",
        "execution_target_mismatch",
        "execution_target_unavailable",
        "implementation_blocked",
        "manifest_mismatch",
        "precondition_from_future",
        "precondition_invocation_mismatch",
        "precondition_missing",
        "precondition_requirement_mismatch",
        "precondition_stale",
        "precondition_state_mismatch",
        "precondition_unknown",
        "precondition_violated",
        "qualification_mismatch",
        "qualification_missing",
        "qualification_status_not_allowed",
    }
)

_MAX_SKILLS = 256
_MAX_IMPLEMENTATIONS = 1024
_MAX_FIELDS = 128
_MAX_REQUIREMENTS = 256
_MAX_BINDINGS = 512
_MAX_TARGETS = 256
_MAX_REJECTION_CODES = 32
_MAX_AGE_NS = 300_000_000_000


def _enum(value: Any, path: str, allowed: frozenset[str], code: str) -> str:
    token = _identifier(value, path)
    if token not in allowed:
        raise RuntimeContractError(code, path, f"unsupported {token!r}")
    return token


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


def _ordered_unique_identifiers(
    value: Any,
    path: str,
    *,
    maximum: int,
) -> tuple[str, ...]:
    result = tuple(
        _identifier(item, f"{path}[{index}]")
        for index, item in enumerate(_list(value, path, maximum=maximum))
    )
    if len(set(result)) != len(result):
        raise RuntimeContractError("duplicate_identifier", path, "must be unique")
    return result


@dataclass(frozen=True)
class PhysicalDigestBinding:
    """One typed, exact digest binding supplied by a host projection."""

    binding_id: str
    kind: str
    digest: str

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(
        cls, value: Any, path: str = "physical_digest_binding"
    ) -> "PhysicalDigestBinding":
        obj = _exact_keys(value, path, {"binding_id", "kind", "digest"})
        return cls(
            binding_id=_identifier(obj["binding_id"], f"{path}.binding_id"),
            kind=_identifier(obj["kind"], f"{path}.kind"),
            digest=_digest(obj["digest"], f"{path}.digest"),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "binding_id": self.binding_id,
            "kind": self.kind,
            "digest": self.digest,
        }

    @property
    def key(self) -> tuple[str, str, str]:
        return self.binding_id, self.kind, self.digest


def _digest_bindings(value: Any, path: str) -> tuple[PhysicalDigestBinding, ...]:
    bindings = tuple(
        PhysicalDigestBinding.from_dict(item, f"{path}[{index}]")
        for index, item in enumerate(_list(value, path, maximum=_MAX_BINDINGS))
    )
    if len({item.binding_id for item in bindings}) != len(bindings):
        raise RuntimeContractError(
            "duplicate_binding", path, "binding_id values must be unique"
        )
    if tuple(sorted(bindings, key=lambda item: item.key)) != bindings:
        raise RuntimeContractError(
            "noncanonical_order", path, "must be sorted by id/kind/digest"
        )
    return bindings


@dataclass(frozen=True)
class PhysicalExecutionTarget:
    """Opaque execution-target identity; Runtime never opens the target."""

    kind: str
    digest: str

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(
        cls, value: Any, path: str = "physical_execution_target"
    ) -> "PhysicalExecutionTarget":
        obj = _exact_keys(value, path, {"kind", "digest"})
        return cls(
            kind=_identifier(obj["kind"], f"{path}.kind"),
            digest=_digest(obj["digest"], f"{path}.digest"),
        )

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "digest": self.digest}

    @property
    def key(self) -> tuple[str, str]:
        return self.kind, self.digest


def _execution_targets(value: Any, path: str) -> tuple[PhysicalExecutionTarget, ...]:
    targets = tuple(
        PhysicalExecutionTarget.from_dict(item, f"{path}[{index}]")
        for index, item in enumerate(_list(value, path, maximum=_MAX_TARGETS))
    )
    if len({item.key for item in targets}) != len(targets):
        raise RuntimeContractError("duplicate_execution_target", path, "must be unique")
    if tuple(sorted(targets, key=lambda item: item.key)) != targets:
        raise RuntimeContractError(
            "noncanonical_order", path, "must be sorted by kind/digest"
        )
    return targets


@dataclass(frozen=True)
class PhysicalEligibilityRequirement:
    """Host-evaluated eligibility fact with an exact semantic digest."""

    requirement_id: str
    requirement_digest: str
    maximum_age_ns: int

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(
        cls, value: Any, path: str = "physical_eligibility_requirement"
    ) -> "PhysicalEligibilityRequirement":
        obj = _exact_keys(
            value,
            path,
            {"requirement_id", "requirement_digest", "maximum_age_ns"},
        )
        return cls(
            requirement_id=_identifier(
                obj["requirement_id"], f"{path}.requirement_id"
            ),
            requirement_digest=_digest(
                obj["requirement_digest"], f"{path}.requirement_digest"
            ),
            maximum_age_ns=_integer(
                obj["maximum_age_ns"],
                f"{path}.maximum_age_ns",
                minimum=1,
                maximum=_MAX_AGE_NS,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "requirement_digest": self.requirement_digest,
            "maximum_age_ns": self.maximum_age_ns,
        }

    @property
    def key(self) -> tuple[str, str, int]:
        return self.requirement_id, self.requirement_digest, self.maximum_age_ns


def _eligibility_requirements(
    value: Any, path: str
) -> tuple[PhysicalEligibilityRequirement, ...]:
    requirements = tuple(
        PhysicalEligibilityRequirement.from_dict(item, f"{path}[{index}]")
        for index, item in enumerate(
            _list(value, path, maximum=_MAX_REQUIREMENTS)
        )
    )
    if len({item.requirement_id for item in requirements}) != len(requirements):
        raise RuntimeContractError(
            "duplicate_eligibility_requirement",
            path,
            "requirement_id values must be unique",
        )
    if tuple(sorted(requirements, key=lambda item: item.key)) != requirements:
        raise RuntimeContractError(
            "noncanonical_order", path, "must be sorted by id/digest/maximum age"
        )
    return requirements


@dataclass(frozen=True)
class PhysicalSkillDefinition:
    skill_id: str
    input_fields: tuple[TypedField, ...]
    preconditions: tuple[PhysicalEligibilityRequirement, ...]
    skill_definition_digest: str

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(
        cls, value: Any, path: str = "physical_skill_definition"
    ) -> "PhysicalSkillDefinition":
        obj = _exact_keys(
            value,
            path,
            {
                "skill_id",
                "input_fields",
                "preconditions",
                "skill_definition_digest",
            },
        )
        input_fields = tuple(
            TypedField.from_dict(item, f"{path}.input_fields[{index}]")
            for index, item in enumerate(
                _list(obj["input_fields"], f"{path}.input_fields", maximum=_MAX_FIELDS)
            )
        )
        if len({item.name for item in input_fields}) != len(input_fields):
            raise RuntimeContractError(
                "duplicate_field", f"{path}.input_fields", "field names must be unique"
            )
        if tuple(sorted(input_fields, key=lambda item: item.name)) != input_fields:
            raise RuntimeContractError(
                "noncanonical_order", f"{path}.input_fields", "must be sorted by name"
            )
        if any(not item.required for item in input_fields):
            raise RuntimeContractError(
                "optional_skill_input_unsupported",
                f"{path}.input_fields",
                "v1 skill routing requires an exact set of required inputs",
            )
        result = cls(
            skill_id=_identifier(obj["skill_id"], f"{path}.skill_id"),
            input_fields=input_fields,
            preconditions=_eligibility_requirements(
                obj["preconditions"], f"{path}.preconditions"
            ),
            skill_definition_digest=_digest(
                obj["skill_definition_digest"], f"{path}.skill_definition_digest"
            ),
        )
        expected = contract_hash(result.to_dict(), "skill_definition_digest")
        if result.skill_definition_digest != expected:
            raise RuntimeContractError(
                "hash_mismatch",
                f"{path}.skill_definition_digest",
                f"expected {expected}",
            )
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "skill_id": self.skill_id,
            "input_fields": [item.to_dict() for item in self.input_fields],
            "preconditions": [item.to_dict() for item in self.preconditions],
            "skill_definition_digest": self.skill_definition_digest,
        }


@dataclass(frozen=True)
class PhysicalSkillImplementation:
    implementation_id: str
    skill_id: str
    skill_definition_digest: str
    workcell_digest: str
    mechanism: str
    provider: str
    manifest_digest: str
    dependency_bindings: tuple[PhysicalDigestBinding, ...]
    calibration_bindings: tuple[PhysicalDigestBinding, ...]
    artifact_bindings: tuple[PhysicalDigestBinding, ...]
    qualification_binding: PhysicalDigestBinding
    qualification_status: str
    execution_target: PhysicalExecutionTarget
    eligibility_requirements: tuple[PhysicalEligibilityRequirement, ...]
    declared_status: str
    implementation_digest: str

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(
        cls, value: Any, path: str = "physical_skill_implementation"
    ) -> "PhysicalSkillImplementation":
        obj = _exact_keys(
            value,
            path,
            {
                "implementation_id",
                "skill_id",
                "skill_definition_digest",
                "workcell_digest",
                "mechanism",
                "provider",
                "manifest_digest",
                "dependency_bindings",
                "calibration_bindings",
                "artifact_bindings",
                "qualification_binding",
                "qualification_status",
                "execution_target",
                "eligibility_requirements",
                "declared_status",
                "implementation_digest",
            },
        )
        result = cls(
            implementation_id=_identifier(
                obj["implementation_id"], f"{path}.implementation_id"
            ),
            skill_id=_identifier(obj["skill_id"], f"{path}.skill_id"),
            skill_definition_digest=_digest(
                obj["skill_definition_digest"], f"{path}.skill_definition_digest"
            ),
            workcell_digest=_digest(
                obj["workcell_digest"], f"{path}.workcell_digest"
            ),
            mechanism=_identifier(obj["mechanism"], f"{path}.mechanism"),
            provider=_identifier(obj["provider"], f"{path}.provider"),
            manifest_digest=_digest(
                obj["manifest_digest"], f"{path}.manifest_digest"
            ),
            dependency_bindings=_digest_bindings(
                obj["dependency_bindings"], f"{path}.dependency_bindings"
            ),
            calibration_bindings=_digest_bindings(
                obj["calibration_bindings"], f"{path}.calibration_bindings"
            ),
            artifact_bindings=_digest_bindings(
                obj["artifact_bindings"], f"{path}.artifact_bindings"
            ),
            qualification_binding=PhysicalDigestBinding.from_dict(
                obj["qualification_binding"], f"{path}.qualification_binding"
            ),
            qualification_status=_enum(
                obj["qualification_status"],
                f"{path}.qualification_status",
                _QUALIFICATION_STATUSES,
                "unsupported_qualification_status",
            ),
            execution_target=PhysicalExecutionTarget.from_dict(
                obj["execution_target"], f"{path}.execution_target"
            ),
            eligibility_requirements=_eligibility_requirements(
                obj["eligibility_requirements"], f"{path}.eligibility_requirements"
            ),
            declared_status=_enum(
                obj["declared_status"],
                f"{path}.declared_status",
                _IMPLEMENTATION_STATUSES,
                "unsupported_implementation_status",
            ),
            implementation_digest=_digest(
                obj["implementation_digest"], f"{path}.implementation_digest"
            ),
        )
        expected = contract_hash(result.to_dict(), "implementation_digest")
        if result.implementation_digest != expected:
            raise RuntimeContractError(
                "hash_mismatch",
                f"{path}.implementation_digest",
                f"expected {expected}",
            )
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "implementation_id": self.implementation_id,
            "skill_id": self.skill_id,
            "skill_definition_digest": self.skill_definition_digest,
            "workcell_digest": self.workcell_digest,
            "mechanism": self.mechanism,
            "provider": self.provider,
            "manifest_digest": self.manifest_digest,
            "dependency_bindings": [item.to_dict() for item in self.dependency_bindings],
            "calibration_bindings": [item.to_dict() for item in self.calibration_bindings],
            "artifact_bindings": [item.to_dict() for item in self.artifact_bindings],
            "qualification_binding": self.qualification_binding.to_dict(),
            "qualification_status": self.qualification_status,
            "execution_target": self.execution_target.to_dict(),
            "eligibility_requirements": [
                item.to_dict() for item in self.eligibility_requirements
            ],
            "declared_status": self.declared_status,
            "implementation_digest": self.implementation_digest,
        }


@dataclass(frozen=True)
class PhysicalRoutingPolicy:
    policy_id: str
    implementation_order: tuple[str, ...]
    allowed_qualification_statuses: tuple[str, ...]
    policy_digest: str

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(
        cls, value: Any, path: str = "physical_routing_policy"
    ) -> "PhysicalRoutingPolicy":
        obj = _exact_keys(
            value,
            path,
            {
                "policy_id",
                "implementation_order",
                "allowed_qualification_statuses",
                "policy_digest",
            },
        )
        allowed = _sorted_unique_identifiers(
            obj["allowed_qualification_statuses"],
            f"{path}.allowed_qualification_statuses",
            nonempty=True,
            maximum=len(_POLICY_QUALIFICATION_STATUSES),
        )
        unsupported = sorted(set(allowed) - _POLICY_QUALIFICATION_STATUSES)
        if unsupported:
            raise RuntimeContractError(
                "unsupported_qualification_status",
                f"{path}.allowed_qualification_statuses",
                f"policy cannot allow {unsupported!r}",
            )
        result = cls(
            policy_id=_identifier(obj["policy_id"], f"{path}.policy_id"),
            implementation_order=_ordered_unique_identifiers(
                obj["implementation_order"],
                f"{path}.implementation_order",
                maximum=_MAX_IMPLEMENTATIONS,
            ),
            allowed_qualification_statuses=allowed,
            policy_digest=_digest(obj["policy_digest"], f"{path}.policy_digest"),
        )
        expected = contract_hash(result.to_dict(), "policy_digest")
        if result.policy_digest != expected:
            raise RuntimeContractError(
                "hash_mismatch", f"{path}.policy_digest", f"expected {expected}"
            )
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "implementation_order": list(self.implementation_order),
            "allowed_qualification_statuses": list(
                self.allowed_qualification_statuses
            ),
            "policy_digest": self.policy_digest,
        }


def _typed_arguments(value: Any, path: str) -> tuple[TypedArgument, ...]:
    arguments = tuple(
        TypedArgument.from_dict(item, f"{path}[{index}]")
        for index, item in enumerate(_list(value, path, maximum=_MAX_FIELDS))
    )
    if len({item.name for item in arguments}) != len(arguments):
        raise RuntimeContractError(
            "duplicate_argument", path, "argument names must be unique"
        )
    if tuple(sorted(arguments, key=lambda item: item.name)) != arguments:
        raise RuntimeContractError(
            "noncanonical_order", path, "must be sorted by argument name"
        )
    return arguments


def physical_skill_invocation_digest(
    *,
    skill_id: str,
    skill_definition_digest: str,
    arguments: Iterable[TypedArgument],
) -> str:
    """Hash one exact typed invocation independently of request transport state."""

    try:
        argument_iterator = iter(arguments)
    except TypeError as error:
        raise RuntimeContractError(
            "invalid_type",
            "physical_skill_invocation.arguments",
            f"must be an iterable with at most {_MAX_FIELDS} TypedArgument items",
        ) from error
    bounded_arguments: list[TypedArgument] = []
    for index, item in enumerate(argument_iterator):
        if index >= _MAX_FIELDS:
            raise RuntimeContractError(
                "invalid_type",
                "physical_skill_invocation.arguments",
                f"must contain at most {_MAX_FIELDS} items",
            )
        if not isinstance(item, TypedArgument):
            raise RuntimeContractError(
                "invalid_type",
                f"physical_skill_invocation.arguments[{index}]",
                "must be a TypedArgument",
            )
        bounded_arguments.append(item)
    argument_values = tuple(bounded_arguments)
    if len({item.name for item in argument_values}) != len(argument_values):
        raise RuntimeContractError(
            "duplicate_argument",
            "physical_skill_invocation.arguments",
            "argument names must be unique",
        )
    if tuple(sorted(argument_values, key=lambda item: item.name)) != argument_values:
        raise RuntimeContractError(
            "noncanonical_order",
            "physical_skill_invocation.arguments",
            "must be sorted by argument name",
        )
    return canonical_sha256(
        {
            "domain": "tinyedge-runtime-physical-skill-invocation-v1",
            "skill_id": _identifier(skill_id, "physical_skill_invocation.skill_id"),
            "skill_definition_digest": _digest(
                skill_definition_digest,
                "physical_skill_invocation.skill_definition_digest",
            ),
            "arguments": [item.to_dict() for item in argument_values],
        }
    )


@dataclass(frozen=True)
class PhysicalPreconditionAssessment:
    precondition_id: str
    requirement_digest: str
    invocation_digest: str
    status: str
    state_digest: str
    observed_monotonic_ns: int | None
    evidence_digest: str | None

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(
        cls, value: Any, path: str = "physical_precondition_assessment"
    ) -> "PhysicalPreconditionAssessment":
        obj = _exact_keys(
            value,
            path,
            {
                "precondition_id",
                "requirement_digest",
                "invocation_digest",
                "status",
                "state_digest",
                "observed_monotonic_ns",
                "evidence_digest",
            },
        )
        status = _enum(
            obj["status"],
            f"{path}.status",
            _PRECONDITION_STATUSES,
            "unsupported_precondition_status",
        )
        observed = _optional_integer(
            obj["observed_monotonic_ns"], f"{path}.observed_monotonic_ns"
        )
        evidence = obj["evidence_digest"]
        if evidence is not None:
            evidence = _digest(evidence, f"{path}.evidence_digest")
        if status in {"met", "violated"} and (observed is None or evidence is None):
            raise RuntimeContractError(
                "missing_precondition_evidence",
                path,
                "met or violated assessments require time and evidence digest",
            )
        if status == "unknown" and observed is not None:
            raise RuntimeContractError(
                "unexpected_precondition_time",
                f"{path}.observed_monotonic_ns",
                "unknown assessments cannot claim an observation time",
            )
        return cls(
            precondition_id=_identifier(
                obj["precondition_id"], f"{path}.precondition_id"
            ),
            requirement_digest=_digest(
                obj["requirement_digest"], f"{path}.requirement_digest"
            ),
            invocation_digest=_digest(
                obj["invocation_digest"], f"{path}.invocation_digest"
            ),
            status=status,
            state_digest=_digest(obj["state_digest"], f"{path}.state_digest"),
            observed_monotonic_ns=observed,
            evidence_digest=evidence,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "precondition_id": self.precondition_id,
            "requirement_digest": self.requirement_digest,
            "invocation_digest": self.invocation_digest,
            "status": self.status,
            "state_digest": self.state_digest,
            "observed_monotonic_ns": self.observed_monotonic_ns,
            "evidence_digest": self.evidence_digest,
        }


def _precondition_assessments(
    value: Any, path: str
) -> tuple[PhysicalPreconditionAssessment, ...]:
    assessments = tuple(
        PhysicalPreconditionAssessment.from_dict(item, f"{path}[{index}]")
        for index, item in enumerate(
            _list(value, path, maximum=_MAX_REQUIREMENTS)
        )
    )
    if len({item.precondition_id for item in assessments}) != len(assessments):
        raise RuntimeContractError(
            "duplicate_precondition_assessment",
            path,
            "precondition_id values must be unique",
        )
    if tuple(sorted(assessments, key=lambda item: item.precondition_id)) != assessments:
        raise RuntimeContractError(
            "noncanonical_order", path, "must be sorted by precondition_id"
        )
    return assessments


@dataclass(frozen=True)
class PhysicalSkillCatalog:
    contract_version: str
    catalog_id: str
    workcell_id: str
    workcell_digest: str
    skills: tuple[PhysicalSkillDefinition, ...]
    implementations: tuple[PhysicalSkillImplementation, ...]
    catalog_digest: str

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any) -> "PhysicalSkillCatalog":
        obj = _exact_keys(
            value,
            "physical_skill_catalog",
            {
                "contract_version",
                "catalog_id",
                "workcell_id",
                "workcell_digest",
                "skills",
                "implementations",
                "catalog_digest",
            },
        )
        version = _identifier(
            obj["contract_version"], "physical_skill_catalog.contract_version"
        )
        if version != PHYSICAL_SKILL_CATALOG_VERSION:
            raise RuntimeContractError(
                "unsupported_contract",
                "physical_skill_catalog.contract_version",
                f"expected {PHYSICAL_SKILL_CATALOG_VERSION!r}",
            )
        skills = tuple(
            PhysicalSkillDefinition.from_dict(
                item, f"physical_skill_catalog.skills[{index}]"
            )
            for index, item in enumerate(
                _list(
                    obj["skills"],
                    "physical_skill_catalog.skills",
                    nonempty=True,
                    maximum=_MAX_SKILLS,
                )
            )
        )
        implementations = tuple(
            PhysicalSkillImplementation.from_dict(
                item, f"physical_skill_catalog.implementations[{index}]"
            )
            for index, item in enumerate(
                _list(
                    obj["implementations"],
                    "physical_skill_catalog.implementations",
                    maximum=_MAX_IMPLEMENTATIONS,
                )
            )
        )
        if len({item.skill_id for item in skills}) != len(skills):
            raise RuntimeContractError(
                "duplicate_skill", "physical_skill_catalog.skills", "ids must be unique"
            )
        if tuple(sorted(skills, key=lambda item: item.skill_id)) != skills:
            raise RuntimeContractError(
                "noncanonical_order",
                "physical_skill_catalog.skills",
                "must be sorted by skill_id",
            )
        if len({item.implementation_id for item in implementations}) != len(
            implementations
        ):
            raise RuntimeContractError(
                "duplicate_implementation",
                "physical_skill_catalog.implementations",
                "ids must be unique",
            )
        if tuple(
            sorted(implementations, key=lambda item: item.implementation_id)
        ) != implementations:
            raise RuntimeContractError(
                "noncanonical_order",
                "physical_skill_catalog.implementations",
                "must be sorted by implementation_id",
            )
        skill_by_id = {item.skill_id: item for item in skills}
        workcell_digest = _digest(
            obj["workcell_digest"], "physical_skill_catalog.workcell_digest"
        )
        requirements_by_skill: dict[
            str, dict[str, PhysicalEligibilityRequirement]
        ] = {}
        for skill in skills:
            requirements = requirements_by_skill.setdefault(skill.skill_id, {})
            for requirement in skill.preconditions:
                previous = requirements.setdefault(requirement.requirement_id, requirement)
                if previous != requirement:
                    raise RuntimeContractError(
                        "ambiguous_eligibility_requirement",
                        "physical_skill_catalog.skills",
                        f"{requirement.requirement_id!r} has conflicting semantics",
                    )
        for implementation in implementations:
            skill = skill_by_id.get(implementation.skill_id)
            if skill is None:
                raise RuntimeContractError(
                    "unknown_skill",
                    "physical_skill_catalog.implementations",
                    f"implementation targets {implementation.skill_id!r}",
                )
            if implementation.skill_definition_digest != skill.skill_definition_digest:
                raise RuntimeContractError(
                    "skill_definition_mismatch",
                    "physical_skill_catalog.implementations",
                    f"implementation {implementation.implementation_id!r} is stale",
                )
            if implementation.workcell_digest != workcell_digest:
                raise RuntimeContractError(
                    "workcell_mismatch",
                    "physical_skill_catalog.implementations",
                    f"implementation {implementation.implementation_id!r} is for another workcell",
                )
            requirements = requirements_by_skill[implementation.skill_id]
            for requirement in implementation.eligibility_requirements:
                previous = requirements.setdefault(requirement.requirement_id, requirement)
                if previous != requirement:
                    raise RuntimeContractError(
                        "ambiguous_eligibility_requirement",
                        "physical_skill_catalog.implementations",
                        f"{requirement.requirement_id!r} has conflicting semantics",
                    )
        for skill_id, requirements in requirements_by_skill.items():
            if len(requirements) > _MAX_REQUIREMENTS:
                raise RuntimeContractError(
                    "eligibility_requirement_limit_exceeded",
                    "physical_skill_catalog.implementations",
                    f"skill {skill_id!r} has more than {_MAX_REQUIREMENTS} distinct requirements",
                )
        result = cls(
            contract_version=version,
            catalog_id=_identifier(
                obj["catalog_id"], "physical_skill_catalog.catalog_id"
            ),
            workcell_id=_identifier(
                obj["workcell_id"], "physical_skill_catalog.workcell_id"
            ),
            workcell_digest=workcell_digest,
            skills=skills,
            implementations=implementations,
            catalog_digest=_digest(
                obj["catalog_digest"], "physical_skill_catalog.catalog_digest"
            ),
        )
        expected = contract_hash(result.to_dict(), "catalog_digest")
        if result.catalog_digest != expected:
            raise RuntimeContractError(
                "hash_mismatch",
                "physical_skill_catalog.catalog_digest",
                f"expected {expected}",
            )
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "catalog_id": self.catalog_id,
            "workcell_id": self.workcell_id,
            "workcell_digest": self.workcell_digest,
            "skills": [item.to_dict() for item in self.skills],
            "implementations": [item.to_dict() for item in self.implementations],
            "catalog_digest": self.catalog_digest,
        }

    def skill(self, skill_id: str) -> PhysicalSkillDefinition | None:
        return next((item for item in self.skills if item.skill_id == skill_id), None)

    def implementations_for(self, skill_id: str) -> tuple[PhysicalSkillImplementation, ...]:
        return tuple(item for item in self.implementations if item.skill_id == skill_id)


@dataclass(frozen=True)
class PhysicalSkillRouteRequest:
    contract_version: str
    request_id: str
    catalog_digest: str
    skill_id: str
    skill_definition_digest: str
    arguments: tuple[TypedArgument, ...]
    invocation_digest: str
    workcell_id: str
    workcell_digest: str
    manifest_digest: str
    state_digest: str
    evaluation_monotonic_ns: int
    dependency_bindings: tuple[PhysicalDigestBinding, ...]
    calibration_bindings: tuple[PhysicalDigestBinding, ...]
    artifact_bindings: tuple[PhysicalDigestBinding, ...]
    qualification_bindings: tuple[PhysicalDigestBinding, ...]
    execution_targets: tuple[PhysicalExecutionTarget, ...]
    preconditions: tuple[PhysicalPreconditionAssessment, ...]
    policy: PhysicalRoutingPolicy
    request_digest: str

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any) -> "PhysicalSkillRouteRequest":
        obj = _exact_keys(
            value,
            "physical_skill_route_request",
            {
                "contract_version",
                "request_id",
                "catalog_digest",
                "skill_id",
                "skill_definition_digest",
                "arguments",
                "invocation_digest",
                "workcell_id",
                "workcell_digest",
                "manifest_digest",
                "state_digest",
                "evaluation_monotonic_ns",
                "dependency_bindings",
                "calibration_bindings",
                "artifact_bindings",
                "qualification_bindings",
                "execution_targets",
                "preconditions",
                "policy",
                "request_digest",
            },
        )
        version = _identifier(
            obj["contract_version"],
            "physical_skill_route_request.contract_version",
        )
        if version != PHYSICAL_SKILL_ROUTE_REQUEST_VERSION:
            raise RuntimeContractError(
                "unsupported_contract",
                "physical_skill_route_request.contract_version",
                f"expected {PHYSICAL_SKILL_ROUTE_REQUEST_VERSION!r}",
            )
        arguments = _typed_arguments(
            obj["arguments"], "physical_skill_route_request.arguments"
        )
        skill_id = _identifier(
            obj["skill_id"], "physical_skill_route_request.skill_id"
        )
        skill_definition_digest = _digest(
            obj["skill_definition_digest"],
            "physical_skill_route_request.skill_definition_digest",
        )
        invocation_digest = _digest(
            obj["invocation_digest"],
            "physical_skill_route_request.invocation_digest",
        )
        expected_invocation_digest = physical_skill_invocation_digest(
            skill_id=skill_id,
            skill_definition_digest=skill_definition_digest,
            arguments=arguments,
        )
        if invocation_digest != expected_invocation_digest:
            raise RuntimeContractError(
                "hash_mismatch",
                "physical_skill_route_request.invocation_digest",
                f"expected {expected_invocation_digest}",
            )
        result = cls(
            contract_version=version,
            request_id=_identifier(
                obj["request_id"], "physical_skill_route_request.request_id"
            ),
            catalog_digest=_digest(
                obj["catalog_digest"], "physical_skill_route_request.catalog_digest"
            ),
            skill_id=skill_id,
            skill_definition_digest=skill_definition_digest,
            arguments=arguments,
            invocation_digest=invocation_digest,
            workcell_id=_identifier(
                obj["workcell_id"], "physical_skill_route_request.workcell_id"
            ),
            workcell_digest=_digest(
                obj["workcell_digest"], "physical_skill_route_request.workcell_digest"
            ),
            manifest_digest=_digest(
                obj["manifest_digest"], "physical_skill_route_request.manifest_digest"
            ),
            state_digest=_digest(
                obj["state_digest"], "physical_skill_route_request.state_digest"
            ),
            evaluation_monotonic_ns=_integer(
                obj["evaluation_monotonic_ns"],
                "physical_skill_route_request.evaluation_monotonic_ns",
            ),
            dependency_bindings=_digest_bindings(
                obj["dependency_bindings"],
                "physical_skill_route_request.dependency_bindings",
            ),
            calibration_bindings=_digest_bindings(
                obj["calibration_bindings"],
                "physical_skill_route_request.calibration_bindings",
            ),
            artifact_bindings=_digest_bindings(
                obj["artifact_bindings"],
                "physical_skill_route_request.artifact_bindings",
            ),
            qualification_bindings=_digest_bindings(
                obj["qualification_bindings"],
                "physical_skill_route_request.qualification_bindings",
            ),
            execution_targets=_execution_targets(
                obj["execution_targets"],
                "physical_skill_route_request.execution_targets",
            ),
            preconditions=_precondition_assessments(
                obj["preconditions"], "physical_skill_route_request.preconditions"
            ),
            policy=PhysicalRoutingPolicy.from_dict(
                obj["policy"], "physical_skill_route_request.policy"
            ),
            request_digest=_digest(
                obj["request_digest"], "physical_skill_route_request.request_digest"
            ),
        )
        expected = contract_hash(result.to_dict(), "request_digest")
        if result.request_digest != expected:
            raise RuntimeContractError(
                "hash_mismatch",
                "physical_skill_route_request.request_digest",
                f"expected {expected}",
            )
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "request_id": self.request_id,
            "catalog_digest": self.catalog_digest,
            "skill_id": self.skill_id,
            "skill_definition_digest": self.skill_definition_digest,
            "arguments": [item.to_dict() for item in self.arguments],
            "invocation_digest": self.invocation_digest,
            "workcell_id": self.workcell_id,
            "workcell_digest": self.workcell_digest,
            "manifest_digest": self.manifest_digest,
            "state_digest": self.state_digest,
            "evaluation_monotonic_ns": self.evaluation_monotonic_ns,
            "dependency_bindings": [item.to_dict() for item in self.dependency_bindings],
            "calibration_bindings": [item.to_dict() for item in self.calibration_bindings],
            "artifact_bindings": [item.to_dict() for item in self.artifact_bindings],
            "qualification_bindings": [
                item.to_dict() for item in self.qualification_bindings
            ],
            "execution_targets": [item.to_dict() for item in self.execution_targets],
            "preconditions": [item.to_dict() for item in self.preconditions],
            "policy": self.policy.to_dict(),
            "request_digest": self.request_digest,
        }


@dataclass(frozen=True)
class PhysicalCandidateRoute:
    implementation_id: str
    implementation_digest: str
    mechanism: str
    provider: str
    execution_target: PhysicalExecutionTarget
    status: str
    rejection_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(
        cls, value: Any, path: str = "physical_candidate_route"
    ) -> "PhysicalCandidateRoute":
        obj = _exact_keys(
            value,
            path,
            {
                "implementation_id",
                "implementation_digest",
                "mechanism",
                "provider",
                "execution_target",
                "status",
                "rejection_codes",
            },
        )
        status = _enum(
            obj["status"],
            f"{path}.status",
            _CANDIDATE_STATUSES,
            "unsupported_candidate_status",
        )
        codes = _sorted_unique_identifiers(
            obj["rejection_codes"],
            f"{path}.rejection_codes",
            maximum=_MAX_REJECTION_CODES,
        )
        unsupported = sorted(set(codes) - _CANDIDATE_REJECTION_CODES)
        if unsupported:
            raise RuntimeContractError(
                "unsupported_rejection_code",
                f"{path}.rejection_codes",
                f"unsupported {unsupported!r}",
            )
        if status == "rejected" and not codes:
            raise RuntimeContractError(
                "missing_rejection_code",
                f"{path}.rejection_codes",
                "rejected candidates require at least one code",
            )
        if status != "rejected" and codes:
            raise RuntimeContractError(
                "unexpected_rejection_code",
                f"{path}.rejection_codes",
                "eligible candidates cannot carry rejection codes",
            )
        return cls(
            implementation_id=_identifier(
                obj["implementation_id"], f"{path}.implementation_id"
            ),
            implementation_digest=_digest(
                obj["implementation_digest"], f"{path}.implementation_digest"
            ),
            mechanism=_identifier(obj["mechanism"], f"{path}.mechanism"),
            provider=_identifier(obj["provider"], f"{path}.provider"),
            execution_target=PhysicalExecutionTarget.from_dict(
                obj["execution_target"], f"{path}.execution_target"
            ),
            status=status,
            rejection_codes=codes,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "implementation_id": self.implementation_id,
            "implementation_digest": self.implementation_digest,
            "mechanism": self.mechanism,
            "provider": self.provider,
            "execution_target": self.execution_target.to_dict(),
            "status": self.status,
            "rejection_codes": list(self.rejection_codes),
        }


@dataclass(frozen=True)
class PhysicalSkillRouteDecision:
    contract_version: str
    request_id: str
    request_digest: str
    catalog_digest: str
    policy_digest: str
    state_digest: str
    invocation_digest: str
    decision_status: str
    selected_implementation_id: str | None
    selected_implementation_digest: str | None
    selected_execution_target: PhysicalExecutionTarget | None
    request_rejection_codes: tuple[str, ...]
    candidates: tuple[PhysicalCandidateRoute, ...]
    physical_execution_authorized: bool
    decision_digest: str

    def __post_init__(self) -> None:
        _validate_constructed(self, type(self).from_dict)

    @classmethod
    def from_dict(cls, value: Any) -> "PhysicalSkillRouteDecision":
        obj = _exact_keys(
            value,
            "physical_skill_route_decision",
            {
                "contract_version",
                "request_id",
                "request_digest",
                "catalog_digest",
                "policy_digest",
                "state_digest",
                "invocation_digest",
                "decision_status",
                "selected_implementation_id",
                "selected_implementation_digest",
                "selected_execution_target",
                "request_rejection_codes",
                "candidates",
                "physical_execution_authorized",
                "decision_digest",
            },
        )
        version = _identifier(
            obj["contract_version"],
            "physical_skill_route_decision.contract_version",
        )
        if version != PHYSICAL_SKILL_ROUTE_DECISION_VERSION:
            raise RuntimeContractError(
                "unsupported_contract",
                "physical_skill_route_decision.contract_version",
                f"expected {PHYSICAL_SKILL_ROUTE_DECISION_VERSION!r}",
            )
        status = _enum(
            obj["decision_status"],
            "physical_skill_route_decision.decision_status",
            _DECISION_STATUSES,
            "unsupported_route_decision",
        )
        selected_id = obj["selected_implementation_id"]
        if selected_id is not None:
            selected_id = _identifier(
                selected_id,
                "physical_skill_route_decision.selected_implementation_id",
            )
        selected_digest = obj["selected_implementation_digest"]
        if selected_digest is not None:
            selected_digest = _digest(
                selected_digest,
                "physical_skill_route_decision.selected_implementation_digest",
            )
        selected_target_value = obj["selected_execution_target"]
        selected_target = (
            None
            if selected_target_value is None
            else PhysicalExecutionTarget.from_dict(
                selected_target_value,
                "physical_skill_route_decision.selected_execution_target",
            )
        )
        request_codes = _sorted_unique_identifiers(
            obj["request_rejection_codes"],
            "physical_skill_route_decision.request_rejection_codes",
            maximum=_MAX_REJECTION_CODES,
        )
        unsupported = sorted(set(request_codes) - _REQUEST_REJECTION_CODES)
        if unsupported:
            raise RuntimeContractError(
                "unsupported_rejection_code",
                "physical_skill_route_decision.request_rejection_codes",
                f"unsupported {unsupported!r}",
            )
        candidates = tuple(
            PhysicalCandidateRoute.from_dict(
                item, f"physical_skill_route_decision.candidates[{index}]"
            )
            for index, item in enumerate(
                _list(
                    obj["candidates"],
                    "physical_skill_route_decision.candidates",
                    maximum=_MAX_IMPLEMENTATIONS,
                )
            )
        )
        if len({item.implementation_id for item in candidates}) != len(candidates):
            raise RuntimeContractError(
                "duplicate_candidate",
                "physical_skill_route_decision.candidates",
                "implementation ids must be unique",
            )
        if tuple(sorted(candidates, key=lambda item: item.implementation_id)) != candidates:
            raise RuntimeContractError(
                "noncanonical_order",
                "physical_skill_route_decision.candidates",
                "must be sorted by implementation_id",
            )
        if obj["physical_execution_authorized"] is not False:
            raise RuntimeContractError(
                "execution_authority_forbidden",
                "physical_skill_route_decision.physical_execution_authorized",
                "routing never authorizes physical execution",
            )
        selected_candidates = [item for item in candidates if item.status == "selected"]
        if status == "selected":
            if (
                request_codes
                or selected_id is None
                or selected_digest is None
                or selected_target is None
            ):
                raise RuntimeContractError(
                    "invalid_route_decision",
                    "physical_skill_route_decision",
                    "selected decisions require one selection and no request rejection",
                )
            if len(selected_candidates) != 1:
                raise RuntimeContractError(
                    "invalid_route_decision",
                    "physical_skill_route_decision.candidates",
                    "selected decisions require exactly one selected candidate",
                )
            selected = selected_candidates[0]
            if (
                selected.implementation_id != selected_id
                or selected.implementation_digest != selected_digest
                or selected.execution_target != selected_target
            ):
                raise RuntimeContractError(
                    "selection_mismatch",
                    "physical_skill_route_decision.candidates",
                    "selected candidate must match top-level selection",
                )
        else:
            if (
                selected_id is not None
                or selected_digest is not None
                or selected_target is not None
                or selected_candidates
            ):
                raise RuntimeContractError(
                    "invalid_route_decision",
                    "physical_skill_route_decision",
                    "no-match decisions cannot contain a selection",
                )
            if not request_codes and any(
                item.status != "rejected" for item in candidates
            ):
                raise RuntimeContractError(
                    "invalid_route_decision",
                    "physical_skill_route_decision.candidates",
                    "no-match without a request rejection requires all candidates rejected",
                )
        result = cls(
            contract_version=version,
            request_id=_identifier(
                obj["request_id"], "physical_skill_route_decision.request_id"
            ),
            request_digest=_digest(
                obj["request_digest"], "physical_skill_route_decision.request_digest"
            ),
            catalog_digest=_digest(
                obj["catalog_digest"], "physical_skill_route_decision.catalog_digest"
            ),
            policy_digest=_digest(
                obj["policy_digest"], "physical_skill_route_decision.policy_digest"
            ),
            state_digest=_digest(
                obj["state_digest"], "physical_skill_route_decision.state_digest"
            ),
            invocation_digest=_digest(
                obj["invocation_digest"],
                "physical_skill_route_decision.invocation_digest",
            ),
            decision_status=status,
            selected_implementation_id=selected_id,
            selected_implementation_digest=selected_digest,
            selected_execution_target=selected_target,
            request_rejection_codes=request_codes,
            candidates=candidates,
            physical_execution_authorized=False,
            decision_digest=_digest(
                obj["decision_digest"], "physical_skill_route_decision.decision_digest"
            ),
        )
        expected = contract_hash(result.to_dict(), "decision_digest")
        if result.decision_digest != expected:
            raise RuntimeContractError(
                "hash_mismatch",
                "physical_skill_route_decision.decision_digest",
                f"expected {expected}",
            )
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "request_id": self.request_id,
            "request_digest": self.request_digest,
            "catalog_digest": self.catalog_digest,
            "policy_digest": self.policy_digest,
            "state_digest": self.state_digest,
            "invocation_digest": self.invocation_digest,
            "decision_status": self.decision_status,
            "selected_implementation_id": self.selected_implementation_id,
            "selected_implementation_digest": self.selected_implementation_digest,
            "selected_execution_target": (
                None
                if self.selected_execution_target is None
                else self.selected_execution_target.to_dict()
            ),
            "request_rejection_codes": list(self.request_rejection_codes),
            "candidates": [item.to_dict() for item in self.candidates],
            "physical_execution_authorized": self.physical_execution_authorized,
            "decision_digest": self.decision_digest,
        }


def _seal_nested_hash(value: dict[str, Any], hash_field: str) -> dict[str, Any]:
    result = copy.deepcopy(value)
    result[hash_field] = contract_hash(result, hash_field)
    return result


def seal_physical_skill_catalog(value: dict[str, Any]) -> dict[str, Any]:
    """Canonicalize a catalogue and seal every nested semantic boundary."""

    sealed = copy.deepcopy(value)
    sealed.setdefault("contract_version", PHYSICAL_SKILL_CATALOG_VERSION)
    if isinstance(sealed.get("skills"), list):
        for skill in sealed["skills"]:
            if not isinstance(skill, dict):
                continue
            if isinstance(skill.get("input_fields"), list):
                skill["input_fields"] = sorted(
                    skill["input_fields"],
                    key=lambda item: str(item.get("name", "")) if isinstance(item, dict) else "",
                )
            if isinstance(skill.get("preconditions"), list):
                skill["preconditions"] = sorted(
                    skill["preconditions"],
                    key=lambda item: (
                        str(item.get("requirement_id", "")) if isinstance(item, dict) else "",
                        str(item.get("requirement_digest", "")) if isinstance(item, dict) else "",
                    ),
                )
            skill.update(_seal_nested_hash(skill, "skill_definition_digest"))
        sealed["skills"] = sorted(
            sealed["skills"],
            key=lambda item: str(item.get("skill_id", "")) if isinstance(item, dict) else "",
        )
    if isinstance(sealed.get("implementations"), list):
        for implementation in sealed["implementations"]:
            if not isinstance(implementation, dict):
                continue
            for field in (
                "dependency_bindings",
                "calibration_bindings",
                "artifact_bindings",
            ):
                if isinstance(implementation.get(field), list):
                    implementation[field] = sorted(
                        implementation[field],
                        key=lambda item: (
                            str(item.get("binding_id", "")) if isinstance(item, dict) else "",
                            str(item.get("kind", "")) if isinstance(item, dict) else "",
                            str(item.get("digest", "")) if isinstance(item, dict) else "",
                        ),
                    )
            if isinstance(implementation.get("eligibility_requirements"), list):
                implementation["eligibility_requirements"] = sorted(
                    implementation["eligibility_requirements"],
                    key=lambda item: (
                        str(item.get("requirement_id", "")) if isinstance(item, dict) else "",
                        str(item.get("requirement_digest", "")) if isinstance(item, dict) else "",
                    ),
                )
            implementation.update(
                _seal_nested_hash(implementation, "implementation_digest")
            )
        sealed["implementations"] = sorted(
            sealed["implementations"],
            key=lambda item: (
                str(item.get("implementation_id", "")) if isinstance(item, dict) else ""
            ),
        )
    sealed["catalog_digest"] = contract_hash(sealed, "catalog_digest")
    return PhysicalSkillCatalog.from_dict(sealed).to_dict()


def seal_physical_skill_route_request(value: dict[str, Any]) -> dict[str, Any]:
    """Canonicalize and hash one point-in-time route request."""

    sealed = copy.deepcopy(value)
    sealed.setdefault("contract_version", PHYSICAL_SKILL_ROUTE_REQUEST_VERSION)
    if isinstance(sealed.get("arguments"), list):
        sealed["arguments"] = sorted(
            sealed["arguments"],
            key=lambda item: str(item.get("name", "")) if isinstance(item, dict) else "",
        )
    for field in (
        "dependency_bindings",
        "calibration_bindings",
        "artifact_bindings",
        "qualification_bindings",
    ):
        if isinstance(sealed.get(field), list):
            sealed[field] = sorted(
                sealed[field],
                key=lambda item: (
                    str(item.get("binding_id", "")) if isinstance(item, dict) else "",
                    str(item.get("kind", "")) if isinstance(item, dict) else "",
                    str(item.get("digest", "")) if isinstance(item, dict) else "",
                ),
            )
    if isinstance(sealed.get("execution_targets"), list):
        sealed["execution_targets"] = sorted(
            sealed["execution_targets"],
            key=lambda item: (
                str(item.get("kind", "")) if isinstance(item, dict) else "",
                str(item.get("digest", "")) if isinstance(item, dict) else "",
            ),
        )
    if isinstance(sealed.get("preconditions"), list):
        sealed["preconditions"] = sorted(
            sealed["preconditions"],
            key=lambda item: (
                str(item.get("precondition_id", "")) if isinstance(item, dict) else ""
            ),
        )
    policy = sealed.get("policy")
    if isinstance(policy, dict):
        if isinstance(policy.get("allowed_qualification_statuses"), list):
            policy["allowed_qualification_statuses"] = sorted(
                policy["allowed_qualification_statuses"], key=str
            )
        policy.update(_seal_nested_hash(policy, "policy_digest"))
    arguments = sealed.get("arguments")
    if isinstance(arguments, list):
        try:
            parsed_arguments = tuple(
                TypedArgument.from_dict(item, f"physical_skill_route_request.arguments[{index}]")
                for index, item in enumerate(arguments)
            )
            sealed["invocation_digest"] = physical_skill_invocation_digest(
                skill_id=sealed.get("skill_id"),
                skill_definition_digest=sealed.get("skill_definition_digest"),
                arguments=parsed_arguments,
            )
        except RuntimeContractError:
            # The authoritative parser below reports the precise contract path.
            pass
    sealed["request_digest"] = contract_hash(sealed, "request_digest")
    return PhysicalSkillRouteRequest.from_dict(sealed).to_dict()


def _binding_rejections(
    required: Iterable[PhysicalDigestBinding],
    available: tuple[PhysicalDigestBinding, ...],
    *,
    missing_code: str,
    mismatch_code: str,
) -> set[str]:
    available_by_id = {item.binding_id: item for item in available}
    rejections: set[str] = set()
    for binding in required:
        present = available_by_id.get(binding.binding_id)
        if present is None:
            rejections.add(missing_code)
        elif present != binding:
            rejections.add(mismatch_code)
    return rejections


def _precondition_rejections(
    requirements: Iterable[PhysicalEligibilityRequirement],
    request: PhysicalSkillRouteRequest,
) -> set[str]:
    assessment_by_id = {item.precondition_id: item for item in request.preconditions}
    rejections: set[str] = set()
    for requirement in requirements:
        assessment = assessment_by_id.get(requirement.requirement_id)
        if assessment is None:
            rejections.add("precondition_missing")
            continue
        if assessment.requirement_digest != requirement.requirement_digest:
            rejections.add("precondition_requirement_mismatch")
        if assessment.invocation_digest != request.invocation_digest:
            rejections.add("precondition_invocation_mismatch")
        if assessment.state_digest != request.state_digest:
            rejections.add("precondition_state_mismatch")
        if assessment.status == "unknown":
            rejections.add("precondition_unknown")
            continue
        if assessment.status == "violated":
            rejections.add("precondition_violated")
        assert assessment.observed_monotonic_ns is not None
        if assessment.observed_monotonic_ns > request.evaluation_monotonic_ns:
            rejections.add("precondition_from_future")
        elif (
            request.evaluation_monotonic_ns - assessment.observed_monotonic_ns
            > requirement.maximum_age_ns
        ):
            rejections.add("precondition_stale")
    return rejections


def _argument_rejections(
    skill: PhysicalSkillDefinition,
    request: PhysicalSkillRouteRequest,
) -> set[str]:
    field_by_name = {item.name: item for item in skill.input_fields}
    argument_by_name = {item.name: item for item in request.arguments}
    rejections: set[str] = set()
    if set(field_by_name) - set(argument_by_name):
        rejections.add("missing_argument")
    if set(argument_by_name) - set(field_by_name):
        rejections.add("unknown_argument")
    for name in set(field_by_name) & set(argument_by_name):
        field = field_by_name[name]
        argument = argument_by_name[name]
        if argument.value_type != field.value_type:
            rejections.add("argument_type_mismatch")
            continue
        if argument.value_type in {"integer", "number"}:
            assert field.minimum is not None and field.maximum is not None
            if not field.minimum <= argument.value <= field.maximum:  # type: ignore[operator]
                rejections.add("argument_out_of_bounds")
    return rejections


def route_physical_skill(
    catalog: PhysicalSkillCatalog,
    request: PhysicalSkillRouteRequest,
) -> PhysicalSkillRouteDecision:
    """Filter candidates, then apply the request's explicit total-order policy.

    Mechanism and provider values are carried into the catalogue hash but are
    intentionally absent from resolver behavior.  The result is an auditable
    proposal and always has ``physical_execution_authorized == False``.
    """

    request_rejections: set[str] = set()
    if request.catalog_digest != catalog.catalog_digest:
        request_rejections.add("catalog_mismatch")
    if (
        request.workcell_id != catalog.workcell_id
        or request.workcell_digest != catalog.workcell_digest
    ):
        request_rejections.add("workcell_mismatch")
    skill = catalog.skill(request.skill_id)
    if skill is None:
        request_rejections.add("unknown_skill")
        candidates: tuple[PhysicalSkillImplementation, ...] = ()
    else:
        if request.skill_definition_digest != skill.skill_definition_digest:
            request_rejections.add("skill_definition_mismatch")
        request_rejections.update(_argument_rejections(skill, request))
        candidates = catalog.implementations_for(skill.skill_id)

    candidate_ids = {item.implementation_id for item in candidates}
    policy_ids = set(request.policy.implementation_order)
    if candidate_ids - policy_ids:
        request_rejections.add("policy_incomplete")
    if policy_ids - candidate_ids:
        request_rejections.add("policy_unknown_implementation")

    filtered: dict[str, set[str]] = {}
    for implementation in candidates:
        rejections: set[str] = set()
        if implementation.declared_status == "blocked":
            rejections.add("implementation_blocked")
        if implementation.manifest_digest != request.manifest_digest:
            rejections.add("manifest_mismatch")
        rejections.update(
            _binding_rejections(
                implementation.dependency_bindings,
                request.dependency_bindings,
                missing_code="dependency_missing",
                mismatch_code="dependency_mismatch",
            )
        )
        rejections.update(
            _binding_rejections(
                implementation.calibration_bindings,
                request.calibration_bindings,
                missing_code="calibration_missing",
                mismatch_code="calibration_mismatch",
            )
        )
        rejections.update(
            _binding_rejections(
                implementation.artifact_bindings,
                request.artifact_bindings,
                missing_code="artifact_missing",
                mismatch_code="artifact_mismatch",
            )
        )
        rejections.update(
            _binding_rejections(
                (implementation.qualification_binding,),
                request.qualification_bindings,
                missing_code="qualification_missing",
                mismatch_code="qualification_mismatch",
            )
        )
        if (
            implementation.qualification_status
            not in request.policy.allowed_qualification_statuses
        ):
            rejections.add("qualification_status_not_allowed")
        target_keys = {item.key for item in request.execution_targets}
        if implementation.execution_target.key not in target_keys:
            if any(
                item.kind == implementation.execution_target.kind
                for item in request.execution_targets
            ):
                rejections.add("execution_target_mismatch")
            else:
                rejections.add("execution_target_unavailable")
        requirements: tuple[PhysicalEligibilityRequirement, ...] = (
            (() if skill is None else skill.preconditions)
            + implementation.eligibility_requirements
        )
        rejections.update(_precondition_rejections(requirements, request))
        filtered[implementation.implementation_id] = rejections

    selected_id: str | None = None
    if not request_rejections:
        selected_id = next(
            (
                implementation_id
                for implementation_id in request.policy.implementation_order
                if not filtered[implementation_id]
            ),
            None,
        )
    implementation_by_id = {item.implementation_id: item for item in candidates}
    candidate_values = []
    for implementation in candidates:
        codes = tuple(sorted(filtered[implementation.implementation_id]))
        if codes:
            status = "rejected"
        elif implementation.implementation_id == selected_id:
            status = "selected"
        else:
            status = "eligible_not_selected"
        candidate_values.append(
            {
                "implementation_id": implementation.implementation_id,
                "implementation_digest": implementation.implementation_digest,
                "mechanism": implementation.mechanism,
                "provider": implementation.provider,
                "execution_target": implementation.execution_target.to_dict(),
                "status": status,
                "rejection_codes": list(codes),
            }
        )
    selected = implementation_by_id.get(selected_id) if selected_id is not None else None
    decision: dict[str, Any] = {
        "contract_version": PHYSICAL_SKILL_ROUTE_DECISION_VERSION,
        "request_id": request.request_id,
        "request_digest": request.request_digest,
        "catalog_digest": catalog.catalog_digest,
        "policy_digest": request.policy.policy_digest,
        "state_digest": request.state_digest,
        "invocation_digest": request.invocation_digest,
        "decision_status": "selected" if selected is not None else "no_match",
        "selected_implementation_id": None if selected is None else selected.implementation_id,
        "selected_implementation_digest": (
            None if selected is None else selected.implementation_digest
        ),
        "selected_execution_target": (
            None if selected is None else selected.execution_target.to_dict()
        ),
        "request_rejection_codes": sorted(request_rejections),
        "candidates": candidate_values,
        "physical_execution_authorized": False,
    }
    decision["decision_digest"] = contract_hash(decision, "decision_digest")
    return PhysicalSkillRouteDecision.from_dict(decision)


def resolve_physical_skill(
    catalog: PhysicalSkillCatalog,
    request: PhysicalSkillRouteRequest,
) -> PhysicalSkillRouteDecision:
    """Alias for callers that use Runtime's existing ``resolve_*`` vocabulary."""

    return route_physical_skill(catalog, request)


__all__ = [
    "PHYSICAL_SKILL_CATALOG_VERSION",
    "PHYSICAL_SKILL_ROUTE_REQUEST_VERSION",
    "PHYSICAL_SKILL_ROUTE_DECISION_VERSION",
    "PhysicalCandidateRoute",
    "PhysicalDigestBinding",
    "PhysicalEligibilityRequirement",
    "PhysicalExecutionTarget",
    "PhysicalPreconditionAssessment",
    "PhysicalRoutingPolicy",
    "PhysicalSkillCatalog",
    "PhysicalSkillDefinition",
    "PhysicalSkillImplementation",
    "PhysicalSkillRouteDecision",
    "PhysicalSkillRouteRequest",
    "physical_skill_invocation_digest",
    "resolve_physical_skill",
    "route_physical_skill",
    "seal_physical_skill_catalog",
    "seal_physical_skill_route_request",
]
