"""Independent repository readback for the DeepSeek Harness adapter."""

from __future__ import annotations

import hashlib
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import model_validator

import openworkproof.evidence as evidence
from openworkproof.models import (
    CanonicalRoot,
    CanonicalUTCTime,
    Digest64,
    ObjectId40,
    ProtocolModel,
)


class DshVerificationResultV01(ProtocolModel):
    schema_version: Literal["openworkproof-dsh-verification/0.1"]
    case_id: Digest64
    status: Literal["VERIFIED", "REFUTED", "UNKNOWN"]
    source_revision: ObjectId40
    candidate_revision: ObjectId40 | None
    changed_paths: tuple[CanonicalRoot, ...]
    artifact_digests: tuple[Digest64, ...]
    test_profile_digest: Digest64
    test_exit_code: int | None
    reason_codes: tuple[str, ...]
    verified_at: CanonicalUTCTime

    @model_validator(mode="after")
    def _canonical_collections(self) -> DshVerificationResultV01:
        for values, name in (
            (self.changed_paths, "changed_paths"),
            (self.artifact_digests, "artifact_digests"),
            (self.reason_codes, "reason_codes"),
        ):
            if tuple(values) != tuple(
                sorted(set(values), key=lambda value: value.encode("utf-8"))
            ):
                raise ValueError(f"{name} must be UTF-8 sorted and unique")
        if self.status == "VERIFIED" and self.reason_codes:
            raise ValueError("verified result cannot contain reason codes")
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


def _git(root: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *args],
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
    artifact_digests: tuple[str, ...] = (),
    test_exit_code: int | None = None,
    reason_codes: tuple[str, ...],
    now: datetime,
) -> DshVerificationResultV01:
    return DshVerificationResultV01.model_validate(
        {
            "schema_version": "openworkproof-dsh-verification/0.1",
            "case_id": case.case_id,
            "status": status,
            "source_revision": case.source_revision,
            "candidate_revision": candidate_revision,
            "changed_paths": sorted(set(changed_paths)),
            "artifact_digests": sorted(set(artifact_digests)),
            "test_profile_digest": case.test_profile_digest,
            "test_exit_code": test_exit_code,
            "reason_codes": sorted(set(reason_codes)),
            "verified_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )


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
        candidate = _git(case.repository_root, "rev-parse", "HEAD").decode(
            "ascii"
        ).strip()
        _git(case.repository_root, "cat-file", "-e", case.source_revision)
        raw_paths = _git(
            case.repository_root,
            "diff",
            "--name-only",
            "-z",
            case.source_revision,
            "--",
        ) + _git(
            case.repository_root,
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
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
    digests: list[str] = []
    try:
        for relative in changed:
            path = case.repository_root / relative
            if path.is_file() and not path.is_symlink():
                digests.append(hashlib.sha256(path.read_bytes()).hexdigest())
    except OSError:
        return _result(
            case,
            status="UNKNOWN",
            candidate_revision=candidate,
            changed_paths=changed,
            reason_codes=("ARTIFACT_READ_UNAVAILABLE",),
            now=now,
        )
    if case.verification_runner is None:
        return _result(
            case,
            status="UNKNOWN",
            candidate_revision=candidate,
            changed_paths=changed,
            artifact_digests=tuple(digests),
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
            artifact_digests=tuple(digests),
            reason_codes=("VERIFIER_UNAVAILABLE",),
            now=now,
        )
    if type(exit_code) is not int:
        return _result(
            case,
            status="UNKNOWN",
            candidate_revision=candidate,
            changed_paths=changed,
            artifact_digests=tuple(digests),
            reason_codes=("VERIFIER_RESULT_INVALID",),
            now=now,
        )
    if exit_code != 0:
        return _result(
            case,
            status="REFUTED",
            candidate_revision=candidate,
            changed_paths=changed,
            artifact_digests=tuple(digests),
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
            artifact_digests=tuple(digests),
            test_exit_code=exit_code,
            reason_codes=("DURABLE_EVIDENCE_UNAVAILABLE",),
            now=now,
        )
    try:
        connection = evidence.connect_ledger(case.ledger_path)
        try:
            evidence._replay_receipt_publication_ledger(connection)
        finally:
            connection.close()
    except Exception:
        return _result(
            case,
            status="UNKNOWN",
            candidate_revision=candidate,
            changed_paths=changed,
            artifact_digests=tuple(digests),
            test_exit_code=exit_code,
            reason_codes=("CAUSAL_REPLAY_UNAVAILABLE",),
            now=now,
        )
    return _result(
        case,
        status="VERIFIED",
        candidate_revision=candidate,
        changed_paths=changed,
        artifact_digests=tuple(digests),
        test_exit_code=exit_code,
        reason_codes=(),
        now=now,
    )


__all__ = [
    "DshVerificationCaseV01",
    "DshVerificationResultV01",
    "verify_dsh_code_change",
]
