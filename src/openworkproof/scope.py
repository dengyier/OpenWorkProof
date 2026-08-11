"""Pure construction and comparison helpers for v0.3 evaluation scopes."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import rfc8785
from pydantic import TypeAdapter, model_validator

from openworkproof.models import (
    Digest64,
    EvaluationScopeDraft,
    EvaluationScopeManifest,
    ObjectId40,
    ProtocolModel,
    SafeNonNegativeInt,
    ScopeLocator,
    ScopeMember,
    ScopeRequirementBinding,
    ScopeSelectorRule,
    SubjectClaim,
)


ScopeStatus = Literal["satisfied", "contradicted", "indeterminate"]


class ObservedScope(ProtocolModel):
    """Verifier-observed scope summary used by the pure comparison boundary."""

    member_ids: tuple[Digest64, ...]
    member_count: SafeNonNegativeInt
    population_digest: Digest64
    required_target_ids: tuple[Digest64, ...]
    source_revision: ObjectId40
    workspace_manifest_digest: Digest64
    selector_engine_digests: tuple[Digest64, ...]
    evidence_complete: bool

    @model_validator(mode="after")
    def _closed_observation(self) -> ObservedScope:
        for values, label in (
            (self.member_ids, "member_ids"),
            (self.required_target_ids, "required_target_ids"),
            (self.selector_engine_digests, "selector_engine_digests"),
        ):
            if len(set(values)) != len(values):
                raise ValueError(f"{label} must be unique")
        return self


class ScopeComparisonResult(ProtocolModel):
    scope_status: ScopeStatus
    reason_codes: tuple[str, ...]
    missing_required_target_ids: tuple[Digest64, ...]


def _domain_digest(domain: str, payload: object) -> str:
    return hashlib.sha256(
        rfc8785.dumps(
            {"domain": f"openworkproof/{domain}/v0.3", "payload": payload}
        )
    ).hexdigest()


def scope_member_id(member_kind: str, locator: str) -> str:
    if member_kind not in {"source_file", "test_case", "delivery_artifact"}:
        raise ValueError("unknown scope member kind")
    locator = TypeAdapter(ScopeLocator).validate_python(locator)
    return _domain_digest(
        "scope-member",
        {"member_kind": member_kind, "locator": locator},
    )


def requirement_digest(requirement_kind: str, value: object) -> str:
    if requirement_kind not in {"acceptance_condition", "required_artifact"}:
        raise ValueError("unknown scope requirement kind")
    return _domain_digest(
        "scope-requirement",
        {"requirement_kind": requirement_kind, "value": value},
    )


def population_digest(members: Sequence[ScopeMember]) -> str:
    ordered = sorted(
        members,
        key=lambda member: (
            member.member_kind,
            member.locator_digest,
            member.member_id,
        ),
    )
    identities = [
        {
            "member_id": member.member_id,
            "member_kind": member.member_kind,
            "locator_digest": member.locator_digest,
        }
        for member in ordered
    ]
    return _domain_digest("scope-population", identities)


def evaluation_scope_id(payload: Mapping[str, object]) -> str:
    forbidden = {
        "scope_id",
        "digest",
        "signature_alg",
        "signer_key_id",
        "signature",
    }
    if forbidden.intersection(payload):
        raise ValueError("scope identity payload contains an identity envelope")
    return _domain_digest("evaluation-scope", dict(payload))


def _claim_requirement_keys(
    claim: SubjectClaim,
) -> set[tuple[str, str]]:
    return {
        *(
            (
                "acceptance_condition",
                requirement_digest("acceptance_condition", condition),
            )
            for condition in claim.acceptance_conditions
        ),
        *(
            (
                "required_artifact",
                requirement_digest("required_artifact", artifact),
            )
            for artifact in claim.required_artifacts
        ),
    }


def validate_evaluation_scope(
    manifest: EvaluationScopeDraft | EvaluationScopeManifest,
    *,
    claim: SubjectClaim,
) -> None:
    if not isinstance(manifest, (EvaluationScopeDraft, EvaluationScopeManifest)):
        raise ValueError("manifest must be a v0.3 evaluation scope")
    if not isinstance(claim, SubjectClaim):
        raise ValueError("claim must be a canonical SubjectClaim")
    if manifest.work_order_digest != claim.work_order_digest:
        raise ValueError("work_order_digest does not match SubjectClaim")
    if manifest.subject_claim_digest != claim.digest:
        raise ValueError("subject_claim_digest does not match SubjectClaim")
    if manifest.source_revision != claim.source_revision:
        raise ValueError("source_revision does not match SubjectClaim")

    actual_requirement_keys = {
        (binding.requirement_kind, binding.requirement_digest)
        for binding in manifest.requirement_bindings
    }
    if actual_requirement_keys != _claim_requirement_keys(claim):
        raise ValueError(
            "requirement_bindings do not exactly cover the SubjectClaim"
        )

    model_type = type(manifest)
    model_type.model_validate(manifest.model_dump(mode="json"))


def _canonical_time(value: datetime, label: str) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timezone.utc.utcoffset(value)
        or value.microsecond
    ):
        raise ValueError(f"{label} must be an exact UTC second")
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_repository_member(root: Path, member: ScopeMember) -> None:
    if member.member_kind == "delivery_artifact":
        return
    relative_path = member.locator.partition("::")[0]
    current = root
    for segment in relative_path.split("/"):
        current = current / segment
        if current.is_symlink():
            raise ValueError("scope member path traverses a symlink")
    if not current.is_file():
        raise ValueError("scope member path is not a repository file")
    try:
        current.resolve(strict=True).relative_to(root)
    except ValueError as error:
        raise ValueError("scope member path escapes repository root") from error


def build_evaluation_scope(
    *,
    claim: SubjectClaim,
    work_order_digest: str,
    source_revision: str,
    candidate_commit: str,
    workspace_manifest_digest: str,
    selector_rules: Sequence[ScopeSelectorRule],
    explicit_members: Sequence[ScopeMember],
    requirement_bindings: Sequence[ScopeRequirementBinding],
    excluded_locator_digests: Sequence[str],
    repository_root: Path,
    created_at: datetime,
    expires_at: datetime,
    nonce: str,
) -> EvaluationScopeDraft:
    if not isinstance(claim, SubjectClaim):
        raise ValueError("claim must be a canonical SubjectClaim")
    if work_order_digest != claim.work_order_digest:
        raise ValueError("work_order_digest does not match SubjectClaim")
    if source_revision != claim.source_revision:
        raise ValueError("source_revision does not match SubjectClaim")

    root = Path(repository_root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("repository_root must be a directory")
    rules = tuple(
        sorted(
            selector_rules,
            key=lambda rule: (
                rule.selector_kind.encode("utf-8"),
                rule.rule_id,
            ),
        )
    )
    if not rules or any(rule.selector_kind != "explicit" for rule in rules):
        raise ValueError("Task 3 builder accepts only explicit selector rules")

    members = tuple(
        sorted(
            explicit_members,
            key=lambda member: (
                member.member_kind,
                member.locator_digest,
                member.member_id,
            ),
        )
    )
    if not 1 <= len(members) <= 4096:
        raise ValueError("explicit_members must contain 1..4096 items")
    for member in members:
        if member.source_revision != source_revision:
            raise ValueError("member source_revision does not match scope")
        _validate_repository_member(root, member)

    bindings = tuple(
        sorted(
            requirement_bindings,
            key=lambda binding: (
                binding.requirement_kind.encode("utf-8"),
                binding.requirement_digest,
            ),
        )
    )
    exclusions = tuple(
        sorted(
            set(excluded_locator_digests),
            key=lambda digest: digest.encode("utf-8"),
        )
    )
    if any(member.locator_digest in exclusions for member in members):
        raise ValueError("excluded locator cannot be selected")
    required_target_ids = tuple(
        sorted(
            {
                member_id
                for binding in bindings
                for member_id in binding.member_ids
            },
            key=lambda member_id: member_id.encode("utf-8"),
        )
    )

    payload: dict[str, Any] = {
        "schema_version": "openworkproof-evaluation-scope/0.3",
        "scope_id": "0" * 64,
        "work_order_digest": work_order_digest,
        "subject_claim_digest": claim.digest,
        "source_revision": source_revision,
        "candidate_commit": candidate_commit,
        "selector_rules": [rule.model_dump(mode="json") for rule in rules],
        "members": [member.model_dump(mode="json") for member in members],
        "member_count": len(members),
        "population_digest": population_digest(members),
        "requirement_bindings": [
            binding.model_dump(mode="json") for binding in bindings
        ],
        "required_target_ids": required_target_ids,
        "excluded_locator_digests": exclusions,
        "workspace_manifest_digest": workspace_manifest_digest,
        "freshness_mode": "immutable_git_revision",
        "created_at": _canonical_time(created_at, "created_at"),
        "expires_at": _canonical_time(expires_at, "expires_at"),
        "nonce": nonce,
    }
    payload["scope_id"] = evaluation_scope_id(
        {key: value for key, value in payload.items() if key != "scope_id"}
    )
    draft = EvaluationScopeDraft.model_validate(payload)
    validate_evaluation_scope(draft, claim=claim)
    return draft


def compare_observed_scope(
    manifest: EvaluationScopeManifest,
    observed: ObservedScope,
) -> ScopeComparisonResult:
    if not isinstance(manifest, EvaluationScopeManifest):
        raise ValueError("manifest must be a signed v0.3 evaluation scope")
    if not isinstance(observed, ObservedScope):
        raise ValueError("observed must be an ObservedScope")

    observed_ids = tuple(observed.member_ids)
    observed_id_set = set(observed_ids)
    missing_required = tuple(
        sorted(
            set(manifest.required_target_ids) - observed_id_set,
            key=lambda member_id: member_id.encode("utf-8"),
        )
    )
    reasons: list[str] = []
    if not observed_ids:
        reasons.append("SCOPE_EMPTY")
    if missing_required or set(observed.required_target_ids) != set(
        manifest.required_target_ids
    ):
        reasons.append("SCOPE_REQUIRED_TARGET_MISSING")
    if (
        observed.source_revision != manifest.source_revision
        or observed.workspace_manifest_digest
        != manifest.workspace_manifest_digest
    ):
        reasons.append("SCOPE_WORKSPACE_DRIFT")

    expected_engines = tuple(
        sorted(rule.selector_engine_digest for rule in manifest.selector_rules)
    )
    if tuple(observed.selector_engine_digests) != expected_engines:
        reasons.append("SCOPE_SELECTOR_MISMATCH")
    if (
        not observed.evidence_complete
        or observed.member_count != len(observed_ids)
        or len(observed_id_set) != len(observed_ids)
    ):
        reasons.append("SCOPE_EVIDENCE_MISSING")

    declared_ids = {member.member_id for member in manifest.members}
    population_mismatch = (
        observed.member_count != manifest.member_count
        or observed.population_digest != manifest.population_digest
        or observed_id_set != declared_ids
    )
    indeterminate_codes = {
        "SCOPE_EMPTY",
        "SCOPE_REQUIRED_TARGET_MISSING",
        "SCOPE_WORKSPACE_DRIFT",
        "SCOPE_SELECTOR_MISMATCH",
        "SCOPE_EVIDENCE_MISSING",
    }
    if any(reason in indeterminate_codes for reason in reasons):
        status: ScopeStatus = "indeterminate"
    elif population_mismatch:
        reasons.append("SCOPE_POPULATION_DRIFT")
        status = "contradicted"
    else:
        status = "satisfied"

    return ScopeComparisonResult(
        scope_status=status,
        reason_codes=tuple(reasons),
        missing_required_target_ids=missing_required,
    )
