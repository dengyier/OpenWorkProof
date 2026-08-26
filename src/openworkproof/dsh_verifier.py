"""Independent repository readback for the DeepSeek Harness adapter."""

from __future__ import annotations

import hashlib
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import rfc8785
from pydantic import model_validator

import openworkproof.evidence as evidence
from openworkproof.dsh_protocol import (
    DshExecutionIdentityV01,
    dsh_execution_context_id,
    dsh_execution_identity_digest,
)
from openworkproof.models import (
    ApplyPatchArguments,
    CanonicalRoot,
    CanonicalUTCTime,
    Digest64,
    ObjectId40,
    ProtocolModel,
    ToolCallReceipt,
)


class DshArtifactBindingV01(ProtocolModel):
    path: CanonicalRoot
    sha256: Digest64


class DshVerificationResultV01(ProtocolModel):
    schema_version: Literal["openworkproof-dsh-verification/0.1"]
    case_id: Digest64
    status: Literal["VERIFIED", "REFUTED", "UNKNOWN"]
    work_order_digest: Digest64 | None
    execution_identity_digest: Digest64 | None
    action_receipt_digest: Digest64 | None
    source_revision: ObjectId40
    candidate_revision: ObjectId40 | None
    candidate_tree_digest: Digest64 | None
    changed_paths: tuple[CanonicalRoot, ...]
    artifact_bindings: tuple[DshArtifactBindingV01, ...]
    test_profile_digest: Digest64
    test_exit_code: int | None
    reason_codes: tuple[str, ...]
    verified_at: CanonicalUTCTime

    @model_validator(mode="after")
    def _canonical_collections(self) -> DshVerificationResultV01:
        for values, name in (
            (self.changed_paths, "changed_paths"),
            (self.reason_codes, "reason_codes"),
        ):
            if tuple(values) != tuple(
                sorted(set(values), key=lambda value: value.encode("utf-8"))
            ):
                raise ValueError(f"{name} must be UTF-8 sorted and unique")
        artifact_paths = tuple(item.path for item in self.artifact_bindings)
        if artifact_paths != tuple(
            sorted(set(artifact_paths), key=lambda value: value.encode("utf-8"))
        ):
            raise ValueError("artifact_bindings must be path-sorted and unique")
        if (
            self.candidate_tree_digest is not None
            and artifact_paths != self.changed_paths
        ):
            raise ValueError("artifact_bindings must cover every changed path")
        if self.candidate_tree_digest is None and self.artifact_bindings:
            raise ValueError("artifact bindings require a candidate tree digest")
        if self.status == "VERIFIED" and self.reason_codes:
            raise ValueError("verified result cannot contain reason codes")
        if self.status == "VERIFIED" and any(
            value is None
            for value in (
                self.work_order_digest,
                self.execution_identity_digest,
                self.action_receipt_digest,
                self.candidate_tree_digest,
            )
        ):
            raise ValueError("verified result requires exact execution bindings")
        if self.status != "VERIFIED" and not self.reason_codes:
            raise ValueError("non-verified result requires a reason code")
        return self


@dataclass(frozen=True, slots=True)
class DshVerificationCaseV01:
    case_id: str
    repository_root: Path
    source_revision: str
    allowed_path_roots: tuple[str, ...]
    denied_path_roots: tuple[str, ...]
    test_profile_digest: str
    ledger_path: Path | None
    evidence_root: Path | None
    verification_runner: Callable[[Path], int] | None
    execution: DshExecutionIdentityV01 | None = None
    action_receipt_digest: str | None = None
    git_dir: Path | None = None


def _git(root: Path, *args: str, git_dir: Path | None = None) -> bytes:
    prefix = (
        ["git", "-C", str(root)]
        if git_dir is None
        else [
            "git",
            f"--git-dir={git_dir}",
            f"--work-tree={root}",
        ]
    )
    return subprocess.run(
        [*prefix, *args],
        check=True,
        capture_output=True,
    ).stdout


def _is_under(path: str, roots: tuple[str, ...]) -> bool:
    return any(path == root or path.startswith(root + "/") for root in roots)


def _result(
    case: DshVerificationCaseV01,
    *,
    status: Literal["VERIFIED", "REFUTED", "UNKNOWN"],
    candidate_revision: str | None,
    changed_paths: tuple[str, ...],
    artifact_bindings: tuple[DshArtifactBindingV01, ...] = (),
    candidate_tree_digest: str | None = None,
    work_order_digest: str | None = None,
    execution_identity_digest: str | None = None,
    action_receipt_digest: str | None = None,
    test_exit_code: int | None = None,
    reason_codes: tuple[str, ...],
    now: datetime,
) -> DshVerificationResultV01:
    return DshVerificationResultV01.model_validate(
        {
            "schema_version": "openworkproof-dsh-verification/0.1",
            "case_id": case.case_id,
            "status": status,
            "work_order_digest": work_order_digest,
            "execution_identity_digest": execution_identity_digest,
            "action_receipt_digest": action_receipt_digest,
            "source_revision": case.source_revision,
            "candidate_revision": candidate_revision,
            "candidate_tree_digest": candidate_tree_digest,
            "changed_paths": sorted(set(changed_paths)),
            "artifact_bindings": [
                binding.model_dump(mode="json") for binding in artifact_bindings
            ],
            "test_profile_digest": case.test_profile_digest,
            "test_exit_code": test_exit_code,
            "reason_codes": sorted(set(reason_codes)),
            "verified_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )


def _candidate_tree_digest(
    source_revision: str,
    bindings: tuple[DshArtifactBindingV01, ...],
) -> str:
    return hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/dsh-candidate-tree/v0.1",
                "source_revision": source_revision,
                "artifact_bindings": [
                    binding.model_dump(mode="json") for binding in bindings
                ],
            }
        )
    ).hexdigest()


def verify_dsh_code_change(
    case: DshVerificationCaseV01,
    *,
    criterion_digest: str | None = None,
    clock: Callable[[], datetime],
) -> DshVerificationResultV01:
    """Read Git and durable OWP evidence without trusting Agent output."""

    now = clock()
    if now.tzinfo is None or now.utcoffset() is None or now.microsecond:
        raise ValueError("verification clock must return an exact aware second")
    now = now.astimezone(timezone.utc)
    selected_criterion = (
        case.test_profile_digest
        if criterion_digest is None
        else criterion_digest
    )
    if selected_criterion != case.test_profile_digest:
        return _result(
            case,
            status="REFUTED",
            candidate_revision=None,
            changed_paths=(),
            reason_codes=("CRITERION_BINDING_MISMATCH",),
            now=now,
        )
    try:
        candidate = _git(
            case.repository_root,
            "rev-parse",
            "HEAD",
            git_dir=case.git_dir,
        ).decode(
            "ascii"
        ).strip()
        _git(
            case.repository_root,
            "cat-file",
            "-e",
            case.source_revision,
            git_dir=case.git_dir,
        )
        raw_paths = _git(
            case.repository_root,
            "diff",
            "--name-only",
            "-z",
            case.source_revision,
            "--",
            git_dir=case.git_dir,
        ) + _git(
            case.repository_root,
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            git_dir=case.git_dir,
        )
        changed = tuple(
            sorted(
                {
                    item.decode("utf-8")
                    for item in raw_paths.split(b"\0")
                    if item
                }
            )
        )
    except (OSError, UnicodeError, subprocess.CalledProcessError):
        return _result(
            case,
            status="UNKNOWN",
            candidate_revision=None,
            changed_paths=(),
            reason_codes=("REPOSITORY_IDENTITY_UNAVAILABLE",),
            now=now,
        )

    out_of_scope = tuple(
        path
        for path in changed
        if not _is_under(path, case.allowed_path_roots)
        or _is_under(path, case.denied_path_roots)
    )
    if out_of_scope:
        return _result(
            case,
            status="REFUTED",
            candidate_revision=candidate,
            changed_paths=changed,
            reason_codes=("OUT_OF_SCOPE_CHANGE",),
            now=now,
        )
    bindings: list[DshArtifactBindingV01] = []
    try:
        for relative in changed:
            path = case.repository_root / relative
            if not path.is_file() or path.is_symlink():
                raise OSError("changed artifact is not a regular file")
            bindings.append(
                DshArtifactBindingV01(
                    path=relative,
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                )
            )
    except OSError:
        return _result(
            case,
            status="UNKNOWN",
            candidate_revision=candidate,
            changed_paths=changed,
            reason_codes=("ARTIFACT_READ_UNAVAILABLE",),
            now=now,
        )
    artifact_bindings = tuple(bindings)
    tree_digest = _candidate_tree_digest(case.source_revision, artifact_bindings)
    if case.verification_runner is None:
        return _result(
            case,
            status="UNKNOWN",
            candidate_revision=candidate,
            changed_paths=changed,
            artifact_bindings=artifact_bindings,
            candidate_tree_digest=tree_digest,
            reason_codes=("VERIFIER_UNAVAILABLE",),
            now=now,
        )
    try:
        exit_code = case.verification_runner(case.repository_root)
    except Exception:
        return _result(
            case,
            status="UNKNOWN",
            candidate_revision=candidate,
            changed_paths=changed,
            artifact_bindings=artifact_bindings,
            candidate_tree_digest=tree_digest,
            reason_codes=("VERIFIER_UNAVAILABLE",),
            now=now,
        )
    if type(exit_code) is not int:
        return _result(
            case,
            status="UNKNOWN",
            candidate_revision=candidate,
            changed_paths=changed,
            artifact_bindings=artifact_bindings,
            candidate_tree_digest=tree_digest,
            reason_codes=("VERIFIER_RESULT_INVALID",),
            now=now,
        )
    if exit_code != 0:
        return _result(
            case,
            status="REFUTED",
            candidate_revision=candidate,
            changed_paths=changed,
            artifact_bindings=artifact_bindings,
            candidate_tree_digest=tree_digest,
            test_exit_code=exit_code,
            reason_codes=("FROZEN_TEST_FAILED",),
            now=now,
        )
    if case.ledger_path is None or case.evidence_root is None:
        return _result(
            case,
            status="UNKNOWN",
            candidate_revision=candidate,
            changed_paths=changed,
            artifact_bindings=artifact_bindings,
            candidate_tree_digest=tree_digest,
            test_exit_code=exit_code,
            reason_codes=("DURABLE_EVIDENCE_UNAVAILABLE",),
            now=now,
        )
    try:
        connection = evidence.connect_ledger(case.ledger_path)
        try:
            work_order, receipts, _, _ = (
                evidence._replay_receipt_publication_ledger(connection)
            )
        finally:
            connection.close()
    except Exception:
        return _result(
            case,
            status="UNKNOWN",
            candidate_revision=candidate,
            changed_paths=changed,
            artifact_bindings=artifact_bindings,
            candidate_tree_digest=tree_digest,
            test_exit_code=exit_code,
            reason_codes=("CAUSAL_REPLAY_UNAVAILABLE",),
            now=now,
        )
    if case.execution is None or case.action_receipt_digest is None:
        return _result(
            case,
            status="UNKNOWN",
            work_order_digest=work_order.digest,
            candidate_revision=candidate,
            changed_paths=changed,
            artifact_bindings=artifact_bindings,
            candidate_tree_digest=tree_digest,
            test_exit_code=exit_code,
            reason_codes=("ACTION_RECEIPT_BINDING_MISSING",),
            now=now,
        )
    execution_digest = dsh_execution_identity_digest(case.execution)
    matching_receipts = tuple(
        receipt
        for receipt in receipts
        if receipt.digest == case.action_receipt_digest
    )
    if len(matching_receipts) != 1:
        return _result(
            case,
            status="UNKNOWN",
            work_order_digest=work_order.digest,
            execution_identity_digest=execution_digest,
            candidate_revision=candidate,
            changed_paths=changed,
            artifact_bindings=artifact_bindings,
            candidate_tree_digest=tree_digest,
            test_exit_code=exit_code,
            reason_codes=("ACTION_RECEIPT_BINDING_INVALID",),
            now=now,
        )
    action_receipt = matching_receipts[0]
    if (
        case.execution.tool_name != "owp_apply_patch"
        or not isinstance(action_receipt, ToolCallReceipt)
        or action_receipt.tool_name != "owp.apply_patch"
        or action_receipt.policy_decision != "allow"
        or action_receipt.execution_status != "succeeded"
        or action_receipt.work_order_digest != work_order.digest
        or not isinstance(action_receipt.request_arguments, ApplyPatchArguments)
        or action_receipt.request_arguments.target_paths != changed
        or action_receipt.correlation_factors is None
        or action_receipt.correlation_factors.execution_context_id
        != dsh_execution_context_id(case.execution)
    ):
        return _result(
            case,
            status="UNKNOWN",
            work_order_digest=work_order.digest,
            execution_identity_digest=execution_digest,
            candidate_revision=candidate,
            changed_paths=changed,
            artifact_bindings=artifact_bindings,
            candidate_tree_digest=tree_digest,
            test_exit_code=exit_code,
            reason_codes=("ACTION_RECEIPT_BINDING_INVALID",),
            now=now,
        )
    return _result(
        case,
        status="VERIFIED",
        work_order_digest=work_order.digest,
        execution_identity_digest=execution_digest,
        action_receipt_digest=action_receipt.digest,
        candidate_revision=candidate,
        changed_paths=changed,
        artifact_bindings=artifact_bindings,
        candidate_tree_digest=tree_digest,
        test_exit_code=exit_code,
        reason_codes=(),
        now=now,
    )


__all__ = [
    "DshArtifactBindingV01",
    "DshVerificationCaseV01",
    "DshVerificationResultV01",
    "verify_dsh_code_change",
]
