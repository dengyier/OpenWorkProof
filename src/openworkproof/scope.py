"""Pure construction and comparison helpers for v0.3 evaluation scopes."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import rfc8785
from pydantic import TypeAdapter, model_validator

from openworkproof.integrity import (
    PopulationObservationBuildResult,
    population_observation_payload,
)
from openworkproof.models import (
    Digest64,
    EvaluationScopeDraft,
    EvaluationScopeManifest,
    ObjectId40,
    PopulationContractV05,
    PopulationObservationV05,
    ProtocolModel,
    SafeNonNegativeInt,
    ScopeLocator,
    ScopeMember,
    ScopeRequirementBinding,
    ScopeSelectorRule,
    SubjectClaim,
)


ScopeStatus = Literal["satisfied", "contradicted", "indeterminate"]
_FULL_COMMIT = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class ScopeSelectorExecution:
    selector_kind: Literal["git_diff_closure", "pytest_collection"]
    selector_spec_bytes: bytes
    engine_digest: str
    evidence_path: str
    members: tuple[ScopeMember, ...]
    status: Literal["satisfied", "indeterminate"]
    reason_codes: tuple[str, ...]


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


def _selector_engine_digest() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


_CANONICAL_COLLECT_CONFTEST = """# -*- coding: utf-8 -*-
\"\"\"OpenWorkProof canonical pytest collection hook (frozen).\"\"\"

import json
import os


def pytest_collection_finish(session):
    target = os.environ.get("OWP_COLLECT_OUTPUT")
    if not target:
        return
    node_ids = sorted({item.nodeid for item in session.items})
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(
            json.dumps(
                {"node_ids": node_ids}, sort_keys=True, separators=(",", ":")
            )
        )
"""


def _selector_spec_bytes(selector_kind: str, payload: Mapping[str, object]) -> bytes:
    return rfc8785.dumps(
        {
            "schema_version": "openworkproof-scope-selector/0.3",
            "selector_kind": selector_kind,
            **dict(payload),
        }
    )


def _validated_repo(repo: Path) -> Path:
    candidate = Path(repo)
    if candidate.is_symlink():
        raise ValueError("repository root cannot be a symlink")
    root = candidate.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("repository root must be a directory")
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or Path(result.stdout.strip()).resolve() != root:
        raise ValueError("repository root must be the Git top level")
    return root


def _validate_commit(repo: Path, value: str, label: str) -> None:
    if type(value) is not str or _FULL_COMMIT.fullmatch(value) is None:
        raise ValueError(f"{label} must be a full 40-character commit")
    result = subprocess.run(
        ["git", "cat-file", "-t", value],
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or result.stdout.strip() != "commit":
        raise ValueError(f"{label} is not a committed Git revision")


def _git_blob_member(
    repo: Path,
    *,
    commit: str,
    source_revision: str,
    locator: str,
    member_kind: Literal["source_file", "test_case"] = "source_file",
) -> ScopeMember:
    tree = subprocess.run(
        ["git", "ls-tree", "-z", commit, "--", locator.partition("::")[0]],
        cwd=repo,
        check=True,
        capture_output=True,
    ).stdout
    if not tree:
        raise ValueError("selector path is absent from the committed tree")
    metadata, _, _ = tree.partition(b"\t")
    mode, object_type, _object_id = metadata.decode("ascii").split(" ")
    if object_type != "blob" or mode not in {"100644", "100755"}:
        label = "symlink" if mode == "120000" else "non-file"
        raise ValueError(f"selector path resolves to a {label} Git entry")
    path = locator.partition("::")[0]
    content = subprocess.run(
        ["git", "cat-file", "blob", f"{commit}:{path}"],
        cwd=repo,
        check=True,
        capture_output=True,
    ).stdout
    return ScopeMember.model_validate(
        {
            "member_id": scope_member_id(member_kind, locator),
            "member_kind": member_kind,
            "locator": locator,
            "locator_digest": hashlib.sha256(locator.encode("utf-8")).hexdigest(),
            "content_digest": hashlib.sha256(content).hexdigest(),
            "source_revision": source_revision,
        }
    )


def _sorted_members(members: Sequence[ScopeMember]) -> tuple[ScopeMember, ...]:
    ordered = tuple(
        sorted(
            members,
            key=lambda member: (
                member.member_kind,
                member.locator_digest,
                member.member_id,
            ),
        )
    )
    if len({member.member_id for member in ordered}) != len(ordered):
        raise ValueError("selector produced duplicate member identities")
    return ordered


def select_git_diff_closure(
    repo: Path,
    *,
    source_revision: str,
    candidate_commit: str,
    expected_engine_digest: str | None = None,
) -> ScopeSelectorExecution:
    root = _validated_repo(repo)
    _validate_commit(root, source_revision, "source_revision")
    _validate_commit(root, candidate_commit, "candidate_commit")
    raw = subprocess.run(
        [
            "git",
            "diff",
            "--name-status",
            "-z",
            "--find-renames",
            source_revision,
            candidate_commit,
            "--",
        ],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    tokens = raw.split(b"\x00")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    members: list[ScopeMember] = []
    index = 0
    while index < len(tokens):
        status = tokens[index].decode("ascii")
        index += 1
        if status.startswith(("R", "C")):
            if index + 1 >= len(tokens):
                raise ValueError("Git rename record is truncated")
            old_path = tokens[index].decode("utf-8")
            new_path = tokens[index + 1].decode("utf-8")
            index += 2
            members.append(
                _git_blob_member(
                    root,
                    commit=source_revision,
                    source_revision=source_revision,
                    locator=old_path,
                )
            )
            members.append(
                _git_blob_member(
                    root,
                    commit=candidate_commit,
                    source_revision=source_revision,
                    locator=new_path,
                )
            )
            continue
        if index >= len(tokens):
            raise ValueError("Git diff record is truncated")
        path = tokens[index].decode("utf-8")
        index += 1
        if status == "D":
            commit = source_revision
        elif status[:1] in {"A", "M", "T"}:
            commit = candidate_commit
        else:
            raise ValueError(f"unsupported committed Git status: {status}")
        members.append(
            _git_blob_member(
                root,
                commit=commit,
                source_revision=source_revision,
                locator=path,
            )
        )

    engine_digest = _selector_engine_digest()
    reasons: list[str] = []
    if not members:
        reasons.append("SCOPE_EMPTY")
    if (
        expected_engine_digest is not None
        and expected_engine_digest != engine_digest
    ):
        reasons.append("SCOPE_SELECTOR_MISMATCH")
    reason_codes = tuple(reasons)
    return ScopeSelectorExecution(
        selector_kind="git_diff_closure",
        selector_spec_bytes=_selector_spec_bytes(
            "git_diff_closure",
            {
                "source_revision": source_revision,
                "candidate_commit": candidate_commit,
                "git_diff_mode": "name-status-z-find-renames",
            },
        ),
        engine_digest=engine_digest,
        evidence_path="scope/selectors/git-diff-closure.json",
        members=_sorted_members(members),
        status="indeterminate" if reason_codes else "satisfied",
        reason_codes=reason_codes,
    )


def select_pytest_collection(
    repo: Path,
    *,
    source_revision: str,
    candidate_commit: str,
    python_executable: Path,
    timeout_seconds: int,
    expected_engine_digest: str | None = None,
    required_node_ids: Sequence[str] = (),
) -> ScopeSelectorExecution:
    root = _validated_repo(repo)
    _validate_commit(root, source_revision, "source_revision")
    _validate_commit(root, candidate_commit, "candidate_commit")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 300:
        raise ValueError("timeout_seconds must be in 1..300")
    python = Path(python_executable).resolve(strict=True)
    if not python.is_file():
        raise ValueError("python_executable must be a file")
    python_digest = hashlib.sha256(python.read_bytes()).hexdigest()
    command = (str(python), "-I", "-m", "pytest", "--collect-only", "-q")
    spec = _selector_spec_bytes(
        "pytest_collection",
        {
            "source_revision": source_revision,
            "candidate_commit": candidate_commit,
            "python_executable_digest": python_digest,
            "argv": list(command[1:]),
            "timeout_seconds": timeout_seconds,
        },
    )
    engine_digest = _selector_engine_digest()
    reasons: list[str] = []
    members: tuple[ScopeMember, ...] = ()
    temporary_parent = Path(tempfile.mkdtemp(prefix="owp-scope-pytest-"))
    checkout = temporary_parent / "checkout"
    added = False
    try:
        subprocess.run(
            ["git", "worktree", "add", "--detach", "--quiet", str(checkout), candidate_commit],
            cwd=root,
            check=True,
            capture_output=True,
        )
        added = True
        environment = os.environ.copy()
        environment.update(
            {
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                "LC_ALL": "C.UTF-8",
                "TZ": "UTC",
            }
        )
        try:
            completed = subprocess.run(
                command,
                cwd=checkout,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            reasons.append("SCOPE_SELECTOR_MISMATCH")
        else:
            if completed.returncode != 0:
                reasons.append("SCOPE_SELECTOR_MISMATCH")
            else:
                node_ids = tuple(
                    sorted(
                        {
                            line.strip()
                            for line in completed.stdout.splitlines()
                            if "::" in line.strip()
                        },
                        key=lambda node_id: node_id.encode("utf-8"),
                    )
                )
                if not node_ids:
                    reasons.append("SCOPE_EMPTY")
                else:
                    members = _sorted_members(
                        tuple(
                            _git_blob_member(
                                root,
                                commit=candidate_commit,
                                source_revision=source_revision,
                                locator=node_id,
                                member_kind="test_case",
                            )
                            for node_id in node_ids
                        )
                    )
                    missing = set(required_node_ids) - set(node_ids)
                    if missing:
                        reasons.append("SCOPE_REQUIRED_TARGET_MISSING")
    finally:
        if added:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(checkout)],
                cwd=root,
                check=False,
                capture_output=True,
            )
        shutil.rmtree(temporary_parent, ignore_errors=True)

    if expected_engine_digest is not None and expected_engine_digest != engine_digest:
        reasons.append("SCOPE_SELECTOR_MISMATCH")
    reason_codes = tuple(dict.fromkeys(reasons))
    return ScopeSelectorExecution(
        selector_kind="pytest_collection",
        selector_spec_bytes=spec,
        engine_digest=engine_digest,
        evidence_path="scope/selectors/pytest-collection.json",
        members=members,
        status="indeterminate" if reason_codes else "satisfied",
        reason_codes=reason_codes,
    )


# ---------------------------------------------------------------------------
# v0.5 population observation adapters: Git diff closure and pytest collection.
# ---------------------------------------------------------------------------

def _canonical_utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _adapter_observation(
    contract: "PopulationContractV05",
    eligible_members: Sequence[ScopeMember],
    selected_members: Sequence[ScopeMember],
    reasons: list[str],
    *,
    observed_at: str | None = None,
) -> "PopulationObservationBuildResult":
    eligible_ids = tuple(member.member_id for member in eligible_members)
    selected_ids = tuple(member.member_id for member in selected_members)
    if eligible_ids and set(selected_ids) != set(
        contract.declared_selected_member_ids
    ):
        reasons.append("SCOPE_SELECTOR_MISMATCH")
    reasons = list(dict.fromkeys(reasons))
    if reasons:
        return PopulationObservationBuildResult(
            observation=None,
            evidence_inventory=(),
            eligible_member_ids=eligible_ids,
            selected_member_ids=selected_ids,
            status="indeterminate",
            reason_codes=tuple(reasons),
        )
    payload, inventory = population_observation_payload(
        contract=contract,
        eligible_member_ids=eligible_ids,
        selected_member_ids=selected_ids,
        observed_at=observed_at if observed_at is not None else _canonical_utc_now(),
    )
    return PopulationObservationBuildResult(
        observation=PopulationObservationV05.model_validate(payload),
        evidence_inventory=tuple(sorted(inventory.items())),
        eligible_member_ids=eligible_ids,
        selected_member_ids=selected_ids,
        status="satisfied",
        reason_codes=(),
    )


def _reject_unsafe_locator(value: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\\" in value
        or value.startswith("/")
    ):
        raise ValueError("selector locator must be a relative path")
    segments = value.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        raise ValueError("selector locator must not traverse paths")


def observe_git_population(
    repo: Path,
    *,
    contract: "PopulationContractV05",
    source_revision: str,
    candidate_commit: str,
    allowlist_locators: Sequence[str] = (),
    excluded_locators: Sequence[str] = (),
    required_locators: Sequence[str] = (),
    observed_at: str | None = None,
) -> "PopulationObservationBuildResult":
    """Observe the Git eligible population (the committed diff closure) and
    the selected population (the closure after allowlist, exclusions, and
    required targets). The frozen selector spec extends the v0.3 rule
    encoding with the closed selector parameter fields (allowlist, excluded,
    and required locators); any revision or engine drift closes the
    observation as indeterminate."""

    from openworkproof.models import PopulationContractV05

    if type(contract) is not PopulationContractV05:
        raise ValueError("contract must be an exact PopulationContractV05")
    root = _validated_repo(repo)
    _validate_commit(root, source_revision, "source_revision")
    _validate_commit(root, candidate_commit, "candidate_commit")
    for label, values in (
        ("allowlist", allowlist_locators),
        ("excluded", excluded_locators),
        ("required", required_locators),
    ):
        if type(values) not in {list, tuple}:
            raise ValueError(f"{label} locators must be an exact list or tuple")
        for value in values:
            _reject_unsafe_locator(value)
    allowlist = tuple(sorted(set(allowlist_locators)))
    excluded = tuple(sorted(set(excluded_locators)))
    required = tuple(sorted(set(required_locators)))
    spec = _selector_spec_bytes(
        "git_diff_closure",
        {
            "source_revision": source_revision,
            "candidate_commit": candidate_commit,
            "git_diff_mode": "name-status-z-find-renames",
            "allowlist_locators": list(allowlist),
            "excluded_locators": list(excluded),
            "required_locators": list(required),
        },
    )
    reasons: list[str] = []
    if hashlib.sha256(spec).hexdigest() != contract.selector_spec_digest:
        reasons.append("SCOPE_SELECTOR_MISMATCH")
    if _selector_engine_digest() != contract.selector_engine_digest:
        reasons.append("SCOPE_SELECTOR_MISMATCH")
    if reasons:
        return PopulationObservationBuildResult(
            observation=None,
            evidence_inventory=(),
            eligible_member_ids=(),
            selected_member_ids=(),
            status="indeterminate",
            reason_codes=tuple(dict.fromkeys(reasons)),
        )
    try:
        status_check = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=root,
            check=True,
            capture_output=True,
        ).stdout
        if status_check.strip():
            raise ValueError("repository has uncommitted content")
        raw = subprocess.run(
            [
                "git", "diff", "--name-status", "-z", "--find-renames",
                source_revision, candidate_commit, "--",
            ],
            cwd=root,
            check=True,
            capture_output=True,
        ).stdout
    except subprocess.CalledProcessError as error:
        raise ValueError("git observation failed") from error
    tokens = raw.split(b"\x00")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    eligible: list[ScopeMember] = []
    index = 0
    try:
        while index < len(tokens):
            status = tokens[index].decode("ascii")
            index += 1
            if status.startswith(("R", "C")):
                if index + 1 >= len(tokens):
                    raise ValueError("Git rename record is truncated")
                old_path = tokens[index].decode("utf-8")
                new_path = tokens[index + 1].decode("utf-8")
                index += 2
                eligible.append(
                    _git_blob_member(
                        root,
                        commit=source_revision,
                        source_revision=source_revision,
                        locator=old_path,
                    )
                )
                eligible.append(
                    _git_blob_member(
                        root,
                        commit=candidate_commit,
                        source_revision=source_revision,
                        locator=new_path,
                    )
                )
                continue
            if index >= len(tokens):
                raise ValueError("Git diff record is truncated")
            path = tokens[index].decode("utf-8")
            index += 1
            if status == "D":
                commit = source_revision
            elif status[:1] in {"A", "M", "T"}:
                commit = candidate_commit
            else:
                raise ValueError(f"unsupported committed Git status: {status}")
            eligible.append(
                _git_blob_member(
                    root,
                    commit=commit,
                    source_revision=source_revision,
                    locator=path,
                )
            )
    except subprocess.CalledProcessError as error:
        raise ValueError("git observation failed") from error
    eligible = tuple(_sorted_members(eligible))
    eligible_locators = {member.locator for member in eligible}
    missing_required = [
        locator for locator in required if locator not in eligible_locators
    ]
    if missing_required:
        reasons.append("SCOPE_REQUIRED_TARGET_MISSING")
    filtered = tuple(
        member
        for member in eligible
        if member.locator not in excluded
        and (not allowlist or member.locator in set(allowlist))
    )
    required_members = tuple(
        member for member in eligible if member.locator in set(required)
    )
    selected_members = {
        member.member_id: member for member in (*filtered, *required_members)
    }
    selected = tuple(
        sorted(
            selected_members.values(),
            key=lambda member: (
                member.member_kind,
                member.locator_digest,
                member.member_id,
            ),
        )
    )
    return _adapter_observation(
        contract,
        eligible,
        selected,
        reasons,
        observed_at=observed_at,
    )


def observe_pytest_population(
    repo: Path,
    *,
    contract: "PopulationContractV05",
    source_revision: str,
    candidate_commit: str,
    python_executable: Path,
    selector_args: Sequence[str],
    timeout_seconds: int,
    required_node_ids: Sequence[str] = (),
    observed_at: str | None = None,
) -> "PopulationObservationBuildResult":
    """Observe the pytest eligible population (the full pre-selector
    collection) and the selected population (the selector-applied
    collection). Both phases run with plugin autoload disabled in a frozen,
    conftest-free checkout of the candidate commit. The frozen selector spec
    extends the v0.3 rule encoding with the closed selector parameter fields
    (selector_args, required_node_ids, and the canonical collector digest);
    node ids come exclusively from the canonical collector output file."""

    from openworkproof.models import PopulationContractV05

    if type(contract) is not PopulationContractV05:
        raise ValueError("contract must be an exact PopulationContractV05")
    root = _validated_repo(repo)
    _validate_commit(root, source_revision, "source_revision")
    _validate_commit(root, candidate_commit, "candidate_commit")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 300:
        raise ValueError("timeout_seconds must be in 1..300")
    if type(selector_args) not in {list, tuple} or any(
        type(item) is not str for item in selector_args
    ):
        raise ValueError("selector_args must be an exact list or tuple of strings")
    if len(selector_args) > 64 or any(
        not item or len(item.encode("utf-8")) > 256 or "\x00" in item
        or item != item.strip()
        for item in selector_args
    ):
        raise ValueError("selector_args entries are outside the closed bounds")
    if type(required_node_ids) not in {list, tuple} or any(
        type(item) is not str for item in required_node_ids
    ):
        raise ValueError("required_node_ids must be an exact list or tuple of strings")
    required_nodes = tuple(sorted(set(required_node_ids)))
    for node_id in required_nodes:
        if (
            not node_id
            or "::" not in node_id
            or "\\" in node_id
            or node_id.startswith("/")
        ):
            raise ValueError("required_node_ids entries are not valid node ids")
    python = Path(python_executable).resolve(strict=True)
    if not python.is_file():
        raise ValueError("python_executable must be a file")
    python_digest = hashlib.sha256(python.read_bytes()).hexdigest()
    base_command = (str(python), "-I", "-m", "pytest", "--collect-only", "-q")
    spec = _selector_spec_bytes(
        "pytest_collection",
        {
            "source_revision": source_revision,
            "candidate_commit": candidate_commit,
            "python_executable_digest": python_digest,
            "argv": list(base_command[1:]),
            "timeout_seconds": timeout_seconds,
            "selector_args": list(selector_args),
            "required_node_ids": list(required_nodes),
            "collector_conftest_digest": hashlib.sha256(
                _CANONICAL_COLLECT_CONFTEST.encode("utf-8")
            ).hexdigest(),
        },
    )
    reasons: list[str] = []
    if hashlib.sha256(spec).hexdigest() != contract.selector_spec_digest:
        reasons.append("SCOPE_SELECTOR_MISMATCH")
    if _selector_engine_digest() != contract.selector_engine_digest:
        reasons.append("SCOPE_SELECTOR_MISMATCH")
    if reasons:
        return PopulationObservationBuildResult(
            observation=None,
            evidence_inventory=(),
            eligible_member_ids=(),
            selected_member_ids=(),
            status="indeterminate",
            reason_codes=tuple(dict.fromkeys(reasons)),
        )

    environment = os.environ.copy()
    environment.update(
        {
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
        }
    )
    temporary_parent = Path(tempfile.mkdtemp(prefix="owp-observe-pytest-"))
    checkout = temporary_parent / "checkout"
    added = False
    try:
        try:
            subprocess.run(
                [
                    "git", "worktree", "add", "--detach", "--quiet",
                    str(checkout), candidate_commit,
                ],
                cwd=root,
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as error:
            raise ValueError("pytest checkout failed") from error
        added = True
        tracked_paths = subprocess.run(
            [
                "git", "ls-tree", "-r", "--name-only", candidate_commit,
            ],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        conftest_paths = [
            relative for relative in tracked_paths if relative.endswith("conftest.py")
        ]
        if conftest_paths:
            # A nested candidate conftest.py runs arbitrary code during
            # collection and can overwrite the canonical plugin output
            # (trylast hooks, atexit handlers). Collection must be
            # conftest-free; this is a closed protocol boundary.
            raise ValueError(
                "candidate checkout contains conftest files; "
                "pytest collection must be conftest-free"
            )
        if (checkout / "conftest.py").exists():
            raise ValueError(
                "candidate checkout already contains a root conftest.py"
            )
        (checkout / "conftest.py").write_text(
            _CANONICAL_COLLECT_CONFTEST, encoding="utf-8"
        )

        def collect(extra_args: Sequence[str]) -> list[str]:
            output_path = temporary_parent / (
                f"collect-{uuid.uuid4().hex}.json"
            )
            environment["OWP_COLLECT_OUTPUT"] = str(output_path)
            completed = subprocess.run(
                [*base_command, *list(extra_args)],
                cwd=checkout,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
            if completed.returncode not in {0, 5}:
                raise ValueError("pytest collection failed")
            try:
                document = json.loads(output_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, ValueError) as error:
                raise ValueError(
                    "canonical pytest collection output is unavailable"
                ) from error
            if (
                type(document) is not dict
                or set(document) != {"node_ids"}
                or type(document["node_ids"]) is not list
                or any(
                    type(item) is not str or "::" not in item
                    for item in document["node_ids"]
                )
            ):
                raise ValueError("canonical pytest collection output is invalid")
            return sorted(
                set(document["node_ids"]),
                key=lambda item: item.encode("utf-8"),
            )

        try:
            eligible_nodes = collect(())
            selected_nodes = collect(selector_args)
        except (ValueError, subprocess.TimeoutExpired):
            reasons.append("SCOPE_SELECTOR_MISMATCH")
            return PopulationObservationBuildResult(
                observation=None,
                evidence_inventory=(),
                eligible_member_ids=(),
                selected_member_ids=(),
                status="indeterminate",
                reason_codes=tuple(dict.fromkeys(reasons)),
            )
        missing_required = [
            node_id
            for node_id in required_nodes
            if node_id not in set(eligible_nodes)
        ]
        if missing_required:
            reasons.append("SCOPE_REQUIRED_TARGET_MISSING")
        try:
            eligible_members = tuple(
                _git_blob_member(
                    root,
                    commit=candidate_commit,
                    source_revision=source_revision,
                    locator=node_id,
                    member_kind="test_case",
                )
                for node_id in eligible_nodes
            )
            selected_members = tuple(
                _git_blob_member(
                    root,
                    commit=candidate_commit,
                    source_revision=source_revision,
                    locator=node_id,
                    member_kind="test_case",
                )
                for node_id in selected_nodes
            )
        except subprocess.CalledProcessError as error:
            raise ValueError("pytest member resolution failed") from error
        return _adapter_observation(
            contract,
            eligible_members,
            selected_members,
            reasons,
            observed_at=observed_at,
        )
    finally:
        if added:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(checkout)],
                cwd=root,
                check=False,
                capture_output=True,
            )
        shutil.rmtree(temporary_parent, ignore_errors=True)
