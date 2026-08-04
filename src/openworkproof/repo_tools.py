"""Bounded, deterministic repository reference primitives."""

from __future__ import annotations

import base64
import calendar
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import time
from typing import Any, Literal, Mapping, Sequence
import zlib

import rfc8785

from openworkproof.models import (
    Artifact,
    EvidencePolicy,
    EvidenceRef,
    PatchResultEvidence,
    ReplayProfile,
    RepoReadOutput,
    TestResultEvidence,
    WorkOrder,
)


_LOCAL_SIGNATURE = 0x04034B50
_CENTRAL_SIGNATURE = 0x02014B50
_EOCD_SIGNATURE = 0x06054B50
_VERSION_NEEDED = 20
_VERSION_MADE_BY = 0x0314
_DOS_TIME = 0
_DOS_DATE = 0x0021
_EXTERNAL_ATTRIBUTES = 0o100444 << 16

_MAX_SOURCE_ENTRIES = 126
_MAX_SOURCE_MEMBERS = 128
_MAX_SOURCE_PATH_BYTES = 506
_MAX_MEMBER_PATH_BYTES = 512
_MAX_SOURCE_FILE_BYTES = 1_048_576
_MAX_MANIFEST_BYTES = 65_536
_MAX_COMMIT_BYTES = 65_536
_MAX_SOURCE_BYTES = 8_388_608

_PATH_PATTERN = re.compile(r"^[A-Za-z0-9._/-]+$")
_OID_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_RUNTIME_CHILD_PATTERN = re.compile(
    r"^[0-9a-f]{64}(?:\.(?:rebuild|destroying))?$"
)
_IMAGE_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_DOCKER_HOST_PATTERN = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$")
_DOCKER_REPOSITORY_COMPONENT_PATTERN = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$"
)
_DOCKER_IDENTIFIER_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9_.-]{0,62}$"
)
_DOCKER_OWNERSHIP_LABEL = "openworkproof.execution-owner"
_DOCKER_CREATION_ORDER = (
    "workspace_volume",
    "output_volume",
    "container",
)
_DOCKER_CLEANUP_ORDER = (
    "container",
    "workspace_volume",
    "output_volume",
)
_PATCH_PATH_PATTERN = re.compile(r"^[A-Za-z0-9._/-]+$")
_PATCH_HEADER_PATTERN = re.compile(
    r"^diff --git a/(.+) b/(.+)\n$"
)
_MODIFY_INDEX_PATTERN = re.compile(
    r"^index ([0-9a-f]{40})\.\.([0-9a-f]{40}) (100644|100755)\n$"
)
_CREATE_INDEX_PATTERN = re.compile(
    r"^index (0{40})\.\.([0-9a-f]{40})\n$"
)
_DELETE_INDEX_PATTERN = re.compile(
    r"^index ([0-9a-f]{40})\.\.(0{40})\n$"
)
_HUNK_PATTERN = re.compile(r"^@@ -([^ ]+) \+([^ ]+) @@\n$")
_RANGE_PATTERN = re.compile(r"^(0|[1-9][0-9]*)(?:,(0|[1-9][0-9]*))?$")
_CANONICAL_TIME_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_ALLOWED_MODES = frozenset({"100644", "100755"})
_MANIFEST_KEYS = frozenset(
    {"schema_version", "source_commit", "tree_oid", "commit_path", "entries"}
)
_ENTRY_KEYS = frozenset(
    {"path", "mode", "size_bytes", "sha256", "blob_oid"}
)
_MAX_PATCH_BYTES = 65_536
_MAX_PATCH_PATHS = 32
_MAX_PATCH_PATH_BYTES = 512
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_MAX_WORKSPACE_MANIFEST_ENTRIES = 512
_MAX_WORKSPACE_IDENTITY_DEPTH = 256
_MAX_WORKSPACE_IDENTITY_PATH_BYTES = _MAX_PATCH_PATH_BYTES
_WORKSPACE_TYPES = frozenset({"regular", "directory", "symlink", "other"})
_MAX_PURGE_ENTRIES = 1_024
_MAX_PURGE_DEPTH = 64
# Git authority includes at most 126 source entries / 8 MiB of source plus
# bounded Git metadata, so these limits leave headroom without an unbounded scan.
_MAX_GIT_AUTHORITY_ENTRIES = 2_048
_MAX_GIT_AUTHORITY_DEPTH = 64
_MAX_GIT_AUTHORITY_PATH_BYTES = 1_024
_MAX_GIT_AUTHORITY_FILE_BYTES = 8_388_608
_MAX_GIT_AUTHORITY_TOTAL_BYTES = 16_777_216
_MAX_RUN_TESTS_ENVELOPE_BYTES = 8_192

OPENAT2_RESOLVE_FLAGS = (
    "RESOLVE_BENEATH",
    "RESOLVE_NO_MAGICLINKS",
    "RESOLVE_NO_SYMLINKS",
)


class SourceArchiveError(ValueError):
    """The source artifact is not the frozen v0.1 representation."""


class PatchError(ValueError):
    """The patch is not valid under the frozen v0.1 patch profile."""


class PathError(ValueError):
    """A path is not valid under the frozen v0.1 path profile."""


class ManifestError(ValueError):
    """A workspace manifest or snapshot plan is invalid."""


class ResolutionError(ValueError):
    """A resolution manifest is not bound to the frozen resolver profile."""


class ReplayError(ValueError):
    """An offline workspace sequence cannot be deterministically replayed."""


class EvidenceOrdinalError(ValueError):
    """A patch evidence pair cannot be derived from the immutable prefix."""


class CandidateWorkspaceError(RuntimeError):
    """A trusted candidate workspace cannot be proven or reconstructed."""


class ProcessExecutionError(RuntimeError):
    """A bounded child process cannot be launched or cleaned up safely."""


class EvidencePurgeError(RuntimeError):
    """An evidence root cannot be safely purged."""


@dataclass(frozen=True, slots=True)
class SourceFile:
    path: str
    mode: str
    content: bytes


@dataclass(frozen=True, slots=True)
class ParsedSourceArchive:
    files: tuple[SourceFile, ...]
    commit_raw: bytes
    tree_oid: str
    source_commit: str
    artifact_sha256: str
    artifact_size_bytes: int
    shallow_bytes: bytes | None


@dataclass(frozen=True, slots=True)
class PatchLine:
    operation: str
    content: bytes


@dataclass(frozen=True, slots=True)
class PatchHunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: tuple[PatchLine, ...]


@dataclass(frozen=True, slots=True)
class PatchSection:
    operation: str
    path: str
    mode: str
    old_oid: str
    new_oid: str
    hunks: tuple[PatchHunk, ...]


@dataclass(frozen=True, slots=True)
class CanonicalPatch:
    raw: bytes
    patch_digest: str
    patch_size_bytes: int
    derived_patch_paths: tuple[str, ...]
    sections: tuple[PatchSection, ...]


@dataclass(frozen=True, slots=True)
class PatchApplication:
    files: tuple[SourceFile, ...]
    changed_paths: tuple[str, ...]
    tree_oid: str
    commit_raw: bytes
    candidate_commit: str
    evidence: PatchResultEvidence


@dataclass(frozen=True, slots=True)
class WorkspaceScanRecord:
    path_bytes: bytes
    entry_type: str
    posix_mode: int
    size_bytes: int | None
    content: bytes | None
    symlink_target: bytes | None
    link_count: int
    read_token_before: str
    read_token_after: str


@dataclass(frozen=True, slots=True)
class WorkspaceManifestEntry:
    path_bytes_b64url: str
    type: str
    posix_mode: str
    size_bytes: int | None
    sha256: str | None
    symlink_target_b64url: str | None


@dataclass(frozen=True, slots=True)
class WorkspaceManifest:
    schema_version: str
    head_commit: str
    entries: tuple[WorkspaceManifestEntry, ...]


@dataclass(frozen=True, slots=True)
class ExecutionSnapshotPlan:
    files: tuple[SourceFile, ...]
    read_only: bool
    owner_uid: int
    owner_gid: int
    atime_unix_seconds: int
    mtime_unix_seconds: int
    clear_extended_attributes: bool
    clear_posix_acls: bool
    clear_file_capabilities: bool


@dataclass(frozen=True, slots=True)
class ResolutionProbe:
    requested_path: str
    resolved_relative_path: str | None
    openat2_flags: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ResolutionManifestEntry:
    requested_path: str
    resolved_relative_path: str | None


@dataclass(frozen=True, slots=True)
class ResolutionManifest:
    schema_version: str
    workspace_manifest_digest: str
    requested_paths: tuple[str, ...]
    resolved_entries: tuple[ResolutionManifestEntry, ...]


@dataclass(frozen=True, slots=True)
class ReplayPatchStep:
    patch_bytes: bytes
    target_paths: tuple[str, ...]
    occurred_at: str
    evidence: PatchResultEvidence
    patch_receipt_id: str
    patch_receipt_digest: str


@dataclass(frozen=True, slots=True)
class ReplayTestStep:
    evidence: TestResultEvidence


@dataclass(frozen=True, slots=True)
class ReplayRollbackStep:
    target_patch_receipt_id: str
    target_patch_receipt_digest: str
    before_commit: str
    after_commit: str
    after_manifest_digest: str


@dataclass(frozen=True, slots=True)
class ReplayCheckpoint:
    files: tuple[SourceFile, ...]
    head_commit: str
    workspace_manifest: WorkspaceManifest
    workspace_manifest_digest: str
    verified_test_results: tuple[TestResultEvidence, ...]


@dataclass(frozen=True, slots=True)
class WorkspaceInitRequest:
    runtime_root: Path
    workspace_id: str
    source: ParsedSourceArchive


@dataclass(frozen=True, slots=True)
class CandidateWorkspace:
    runtime_root: Path
    candidate_root: Path
    worktree: Path
    git_dir: Path
    workspace_id: str
    source_artifact_sha256: str
    head_commit: str
    workspace_manifest_digest: str


CandidateReadFailureCode = Literal[
    "RECOVERY_REQUIRED",
    "PATH_DENIED",
    "FILE_CHANGED",
]


class CandidateReadError(RuntimeError):
    def __init__(self, code: CandidateReadFailureCode) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class CandidateReadRequest:
    runtime_root: Path
    workspace_id: str
    source_artifact_sha256: str
    expected_head_commit: str
    expected_workspace_manifest_digest: str
    path: str


@dataclass(frozen=True, slots=True)
class CandidateReadResult:
    content: bytes
    output: RepoReadOutput


@dataclass(frozen=True, slots=True)
class CandidateExecutionSnapshotRequest:
    runtime_root: Path
    workspace_id: str
    source_artifact_sha256: str
    expected_head_commit: str
    expected_workspace_manifest_digest: str


@dataclass(frozen=True, slots=True)
class CandidateExecutionSnapshot:
    head_commit: str
    workspace_manifest_digest: str
    plan: ExecutionSnapshotPlan


@dataclass(frozen=True, slots=True)
class _CandidateReadAnchor:
    descriptor: int
    token: str
    parent_descriptor: int | None
    name: str | Path


@dataclass(frozen=True, slots=True)
class _GitAuthoritySnapshotEntry:
    path_bytes: bytes
    entry_type: Literal["directory", "regular"]
    token: str
    size_bytes: int | None
    sha256: str | None


@dataclass(frozen=True, slots=True)
class _WorkspaceIdentitySnapshotEntry:
    path_bytes: bytes
    entry_type: Literal["directory", "regular"]
    token: str


@dataclass(frozen=True, slots=True)
class _VerifiedCandidateReadCheckpoint:
    manifest: WorkspaceManifest
    workspace_snapshot: tuple[_WorkspaceIdentitySnapshotEntry, ...]
    anchors: tuple[_CandidateReadAnchor, ...]
    worktree_descriptor: int
    git_descriptor: int
    leaf_descriptor: int | None
    control_descriptor: int
    control_size_bytes: int
    control_sha256: str
    git_authority_snapshot: tuple[_GitAuthoritySnapshotEntry, ...]


def _candidate_read_checkpoint_hook() -> None:
    """Provide a deterministic test seam after checkpoint verification."""


def _candidate_execution_snapshot_file_hook(path: str) -> None:
    """Provide a deterministic test seam immediately before one file read."""


def _candidate_execution_snapshot_after_files_hook() -> None:
    """Provide a deterministic test seam after every snapshot byte is read."""


def read_candidate_file(request: CandidateReadRequest) -> CandidateReadResult:
    workspace = _candidate_from_read_request(request)
    checkpoint = _verify_candidate_checkpoint_read_only(workspace, request.path)
    try:
        _candidate_read_checkpoint_hook()
        content = _read_verified_candidate_path(checkpoint, request.path)
        return CandidateReadResult(
            content=content,
            output=RepoReadOutput(
                path=request.path,
                content_sha256=hashlib.sha256(content).hexdigest(),
                size_bytes=len(content),
                workspace_manifest_digest=(
                    request.expected_workspace_manifest_digest
                ),
            ),
        )
    finally:
        _close_candidate_read_checkpoint(checkpoint)


def prepare_candidate_execution_snapshot(
    request: CandidateExecutionSnapshotRequest,
) -> CandidateExecutionSnapshot:
    """Capture exact candidate worktree bytes for one verifier execution."""

    checkpoint: _VerifiedCandidateReadCheckpoint | None = None
    try:
        workspace = _candidate_from_execution_snapshot_request(request)
        checkpoint = _verify_candidate_checkpoint_read_only(workspace, None)
        checkpoint_manifest_digest = workspace_manifest_digest(
            checkpoint.manifest
        )
        if (
            checkpoint.manifest.head_commit
            != request.expected_head_commit
            or checkpoint_manifest_digest
            != request.expected_workspace_manifest_digest
            or not _candidate_read_semantic_authority_matches(
                checkpoint,
                workspace,
            )
        ):
            raise CandidateReadError("RECOVERY_REQUIRED")
        regular_entries = _candidate_execution_snapshot_regular_entries(
            checkpoint.manifest
        )
        files = tuple(
            _read_candidate_execution_snapshot_file(
                checkpoint,
                entry,
            )
            for entry in regular_entries
        )
        _candidate_execution_snapshot_after_files_hook()
        workspace_snapshot_before = _scan_candidate_workspace_identity(
            checkpoint.worktree_descriptor
        )
        fresh_manifest = scan_workspace_manifest(
            checkpoint.worktree_descriptor,
            checkpoint.manifest.head_commit,
        )
        workspace_snapshot_after = _scan_candidate_workspace_identity(
            checkpoint.worktree_descriptor
        )
        if (
            workspace_snapshot_before != workspace_snapshot_after
            or workspace_snapshot_after != checkpoint.workspace_snapshot
            or workspace_manifest_digest(fresh_manifest)
            != checkpoint_manifest_digest
            or not _candidate_read_semantic_authority_matches(
                checkpoint,
                workspace,
            )
        ):
            raise CandidateReadError("RECOVERY_REQUIRED")
        plan = derive_execution_snapshot_plan(checkpoint.manifest, files)
        return CandidateExecutionSnapshot(
            head_commit=checkpoint.manifest.head_commit,
            workspace_manifest_digest=checkpoint_manifest_digest,
            plan=plan,
        )
    except (
        CandidateReadError,
        CandidateWorkspaceError,
        ManifestError,
        OSError,
    ) as error:
        raise CandidateReadError("RECOVERY_REQUIRED") from error
    finally:
        if checkpoint is not None:
            _close_candidate_read_checkpoint(checkpoint)


@dataclass(frozen=True, slots=True)
class PatchRequest:
    workspace: CandidateWorkspace
    patch_bytes: bytes
    expected_patch_digest: str
    expected_patch_size_bytes: int
    declared_target_paths: tuple[str, ...]
    parent_commit: str
    parent_manifest_digest: str
    occurred_at: str
    replay_profile: ReplayProfile
    replay_profile_digest: str


@dataclass(frozen=True, slots=True)
class PatchResult:
    parent_commit: str
    parent_manifest_digest: str
    candidate_commit: str
    workspace_manifest_digest: str
    patch_digest: str
    patch_size_bytes: int
    changed_paths: tuple[str, ...]
    evidence: PatchResultEvidence


@dataclass(frozen=True, slots=True)
class RollbackRequest:
    workspace: CandidateWorkspace
    target_patch_receipt_id: str
    target_patch_receipt_digest: str
    failure_target_patch_receipt_id: str
    failure_target_patch_receipt_digest: str
    before_commit: str
    before_manifest_digest: str
    parent_commit: str
    parent_manifest_digest: str


@dataclass(frozen=True, slots=True)
class RollbackResult:
    execution_status: Literal["succeeded", "failed"]
    before_commit: str
    after_commit: str
    after_manifest_digest: str


@dataclass(frozen=True, slots=True)
class WorkspaceRebuildRequest:
    runtime_root: Path
    workspace_id: str
    source_bytes: bytes
    work_order: WorkOrder
    trusted_helper_image_digest: str
    steps: tuple[ReplayPatchStep | ReplayTestStep | ReplayRollbackStep, ...]


@dataclass(frozen=True, slots=True)
class WorkspaceDestroyRequest:
    workspace: CandidateWorkspace
    expected_head_commit: str
    expected_manifest_digest: str
    lifecycle_state: Literal["terminal", "aborted", "retention_expired"]


@dataclass(frozen=True, slots=True)
class WorkspaceDestroyResult:
    workspace_id: str
    destroyed: bool


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    max_combined_stdio_bytes: int = field(default=1_048_576, init=False)
    wall_clock_timeout_seconds: int = field(default=120, init=False)
    cleanup_grace_seconds: int = field(default=10, init=False)


@dataclass(frozen=True, slots=True)
class ProcessRequest:
    argv: tuple[str, ...]
    working_directory: Path
    environment: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class BoundedProcessResult:
    exit_code: int | None
    failure_code: Literal["OUTPUT_LIMIT", "TIMEOUT", "DISK_LIMIT"] | None
    stdout_prefix: bytes
    stderr_prefix: bytes
    combined_bytes_captured: int


@dataclass(frozen=True, slots=True)
class DockerVolumePlan:
    name: str
    size_bytes: int
    mount_path: str
    read_only: bool
    create_argv: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DockerExecutionPlan:
    docker_binary: Path
    image_reference: str
    container_name: str
    ownership_token: str
    command: tuple[str, ...]
    workspace_volume: DockerVolumePlan
    output_volume: DockerVolumePlan
    create_container_argv: tuple[str, ...]
    preflight_absent_argv: tuple[tuple[str, ...], ...]


@dataclass(frozen=True, slots=True)
class DockerPreflightObservation:
    container_names: tuple[str, ...]
    volume_names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DockerLifecycleState:
    ownership_token: str
    resource_names: tuple[str, str, str]
    created_resources: tuple[
        Literal["container", "workspace_volume", "output_volume"], ...
    ]


@dataclass(frozen=True, slots=True)
class DockerCleanupPlan:
    commands: tuple[tuple[str, ...], ...]
    retained_resources: tuple[
        Literal["container", "workspace_volume", "output_volume"], ...
    ]


@dataclass(frozen=True, slots=True)
class DockerReadyStart:
    ownership_token: str
    resource_names: tuple[str, str, str]
    start_argv: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DockerObservedResult:
    exit_code: int | None
    output_limit_exceeded: bool
    timed_out: bool
    workspace_volume_exhausted: bool
    output_volume_exhausted: bool


RunTestsFailureCode = Literal["OUTPUT_LIMIT", "TIMEOUT", "DISK_LIMIT"]


@dataclass(frozen=True, slots=True)
class RunTestsExecutionContract:
    execution_id: str
    request_digest: str
    arguments_digest: str
    candidate_workspace_id: str
    source_artifact_sha256: str
    source_commit: str
    candidate_commit: str
    workspace_manifest_digest: str
    container_image_digest: str
    command_digest: str
    fixed_test_source_digest: str


@dataclass(frozen=True, slots=True)
class RunTestsStartedEnvelope:
    execution_id: str
    execution_contract_digest: str


@dataclass(frozen=True, slots=True)
class RunTestsResultEnvelope:
    execution_id: str
    execution_contract_digest: str
    actual_exit_code: int | None
    failure_code: RunTestsFailureCode | None
    stdout_bytes: int
    stdout_sha256: str
    stderr_bytes: int
    stderr_sha256: str

    def __post_init__(self) -> None:
        completed = (
            type(self.actual_exit_code) is int
            and 0 <= self.actual_exit_code <= 255
            and self.failure_code is None
        )
        failed = (
            self.actual_exit_code is None
            and type(self.failure_code) is str
            and self.failure_code in {"OUTPUT_LIMIT", "TIMEOUT", "DISK_LIMIT"}
        )
        if not completed and not failed:
            raise ValueError("run-tests result does not contain one closed outcome")


FROZEN_VERIFIER_ARGV = (
    "/opt/venv/bin/python",
    "-I",
    "-m",
    "pytest",
    "-q",
)


def frozen_verifier_command_digest() -> str:
    return hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/verifier-command/v0.1",
                "argv": list(FROZEN_VERIFIER_ARGV),
            }
        )
    ).hexdigest()


def _run_tests_digest(value: object) -> str:
    if type(value) is not str or _DIGEST_PATTERN.fullmatch(value) is None:
        raise ValueError("run-tests digest is invalid")
    return value


def _run_tests_oid(value: object) -> str:
    if type(value) is not str or _OID_PATTERN.fullmatch(value) is None:
        raise ValueError("run-tests object id is invalid")
    return value


def _run_tests_image_digest(value: object) -> str:
    if type(value) is not str or _IMAGE_DIGEST_PATTERN.fullmatch(value) is None:
        raise ValueError("run-tests image digest is invalid")
    return value


def _run_tests_safe_size(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SAFE_INTEGER:
        raise ValueError("run-tests stream size is invalid")
    return value


def _run_tests_execution_contract_json(
    contract: RunTestsExecutionContract,
) -> dict[str, str]:
    if type(contract) is not RunTestsExecutionContract:
        raise ValueError("run-tests execution contract is invalid")
    return {
        "arguments_digest": _run_tests_digest(contract.arguments_digest),
        "candidate_commit": _run_tests_oid(contract.candidate_commit),
        "candidate_workspace_id": _run_tests_digest(
            contract.candidate_workspace_id
        ),
        "command_digest": _run_tests_digest(contract.command_digest),
        "container_image_digest": _run_tests_image_digest(
            contract.container_image_digest
        ),
        "execution_id": _run_tests_digest(contract.execution_id),
        "fixed_test_source_digest": _run_tests_digest(
            contract.fixed_test_source_digest
        ),
        "request_digest": _run_tests_digest(contract.request_digest),
        "schema_version": "openworkproof-run-contract/0.1",
        "source_artifact_sha256": _run_tests_digest(
            contract.source_artifact_sha256
        ),
        "source_commit": _run_tests_oid(contract.source_commit),
        "test_mode": "verifier",
        "tool_name": "owp.run_tests",
        "workspace_manifest_digest": _run_tests_digest(
            contract.workspace_manifest_digest
        ),
    }


def encode_run_tests_execution_contract(
    contract: RunTestsExecutionContract,
) -> bytes:
    return rfc8785.dumps(_run_tests_execution_contract_json(contract))


def _run_tests_started_envelope_json(
    envelope: RunTestsStartedEnvelope,
) -> dict[str, str]:
    if type(envelope) is not RunTestsStartedEnvelope:
        raise ValueError("run-tests started envelope is invalid")
    return {
        "execution_contract_digest": _run_tests_digest(
            envelope.execution_contract_digest
        ),
        "execution_id": _run_tests_digest(envelope.execution_id),
        "schema_version": "openworkproof-run-started/0.1",
    }


def encode_run_tests_started_envelope(
    envelope: RunTestsStartedEnvelope,
) -> bytes:
    return rfc8785.dumps(_run_tests_started_envelope_json(envelope))


def _run_tests_result_envelope_json(
    envelope: RunTestsResultEnvelope,
) -> dict[str, str | int | None]:
    if type(envelope) is not RunTestsResultEnvelope:
        raise ValueError("run-tests result envelope is invalid")
    actual_exit_code = envelope.actual_exit_code
    failure_code = envelope.failure_code
    completed = (
        type(actual_exit_code) is int
        and 0 <= actual_exit_code <= 255
        and failure_code is None
    )
    failed = (
        actual_exit_code is None
        and type(failure_code) is str
        and failure_code in {"OUTPUT_LIMIT", "TIMEOUT", "DISK_LIMIT"}
    )
    if not completed and not failed:
        raise ValueError("run-tests result does not contain one closed outcome")
    return {
        "actual_exit_code": actual_exit_code,
        "execution_contract_digest": _run_tests_digest(
            envelope.execution_contract_digest
        ),
        "execution_id": _run_tests_digest(envelope.execution_id),
        "failure_code": failure_code,
        "schema_version": "openworkproof-run-result/0.1",
        "stderr_bytes": _run_tests_safe_size(envelope.stderr_bytes),
        "stderr_sha256": _run_tests_digest(envelope.stderr_sha256),
        "stdout_bytes": _run_tests_safe_size(envelope.stdout_bytes),
        "stdout_sha256": _run_tests_digest(envelope.stdout_sha256),
    }


def encode_run_tests_result_envelope(
    envelope: RunTestsResultEnvelope,
) -> bytes:
    return rfc8785.dumps(_run_tests_result_envelope_json(envelope))


def _decode_run_tests_json(
    raw: bytes,
    expected_keys: frozenset[str],
) -> dict[str, Any]:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= _MAX_RUN_TESTS_ENVELOPE_BYTES
    ):
        raise ValueError("run-tests envelope size is invalid")
    try:
        text = raw.decode("utf-8")

        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("run-tests envelope has duplicate keys")
                value[key] = item
            return value

        def reject_constant(constant: str) -> None:
            raise ValueError(f"invalid JSON constant: {constant}")

        value = json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("run-tests envelope cannot be parsed") from error
    if type(value) is not dict or frozenset(value) != expected_keys:
        raise ValueError("run-tests envelope has invalid keys")
    return value


def decode_run_tests_execution_contract(raw: bytes) -> RunTestsExecutionContract:
    value = _decode_run_tests_json(
        raw,
        frozenset(
            {
                "arguments_digest",
                "candidate_commit",
                "candidate_workspace_id",
                "command_digest",
                "container_image_digest",
                "execution_id",
                "fixed_test_source_digest",
                "request_digest",
                "schema_version",
                "source_artifact_sha256",
                "source_commit",
                "test_mode",
                "tool_name",
                "workspace_manifest_digest",
            }
        ),
    )
    if (
        value["schema_version"] != "openworkproof-run-contract/0.1"
        or value["test_mode"] != "verifier"
        or value["tool_name"] != "owp.run_tests"
    ):
        raise ValueError("run-tests execution contract constants are invalid")
    contract = RunTestsExecutionContract(
        execution_id=_run_tests_digest(value["execution_id"]),
        request_digest=_run_tests_digest(value["request_digest"]),
        arguments_digest=_run_tests_digest(value["arguments_digest"]),
        candidate_workspace_id=_run_tests_digest(value["candidate_workspace_id"]),
        source_artifact_sha256=_run_tests_digest(
            value["source_artifact_sha256"]
        ),
        source_commit=_run_tests_oid(value["source_commit"]),
        candidate_commit=_run_tests_oid(value["candidate_commit"]),
        workspace_manifest_digest=_run_tests_digest(
            value["workspace_manifest_digest"]
        ),
        container_image_digest=_run_tests_image_digest(
            value["container_image_digest"]
        ),
        command_digest=_run_tests_digest(value["command_digest"]),
        fixed_test_source_digest=_run_tests_digest(
            value["fixed_test_source_digest"]
        ),
    )
    if encode_run_tests_execution_contract(contract) != raw:
        raise ValueError("run-tests execution contract is not canonical")
    return contract


def decode_run_tests_started_envelope(raw: bytes) -> RunTestsStartedEnvelope:
    value = _decode_run_tests_json(
        raw,
        frozenset(
            {
                "execution_contract_digest",
                "execution_id",
                "schema_version",
            }
        ),
    )
    if value["schema_version"] != "openworkproof-run-started/0.1":
        raise ValueError("run-tests started envelope schema is invalid")
    envelope = RunTestsStartedEnvelope(
        execution_id=_run_tests_digest(value["execution_id"]),
        execution_contract_digest=_run_tests_digest(
            value["execution_contract_digest"]
        ),
    )
    if encode_run_tests_started_envelope(envelope) != raw:
        raise ValueError("run-tests started envelope is not canonical")
    return envelope


def decode_run_tests_result_envelope(raw: bytes) -> RunTestsResultEnvelope:
    value = _decode_run_tests_json(
        raw,
        frozenset(
            {
                "actual_exit_code",
                "execution_contract_digest",
                "execution_id",
                "failure_code",
                "schema_version",
                "stderr_bytes",
                "stderr_sha256",
                "stdout_bytes",
                "stdout_sha256",
            }
        ),
    )
    if value["schema_version"] != "openworkproof-run-result/0.1":
        raise ValueError("run-tests result envelope schema is invalid")
    try:
        envelope = RunTestsResultEnvelope(
            execution_id=_run_tests_digest(value["execution_id"]),
            execution_contract_digest=_run_tests_digest(
                value["execution_contract_digest"]
            ),
            actual_exit_code=value["actual_exit_code"],
            failure_code=value["failure_code"],
            stdout_bytes=_run_tests_safe_size(value["stdout_bytes"]),
            stdout_sha256=_run_tests_digest(value["stdout_sha256"]),
            stderr_bytes=_run_tests_safe_size(value["stderr_bytes"]),
            stderr_sha256=_run_tests_digest(value["stderr_sha256"]),
        )
        _run_tests_result_envelope_json(envelope)
    except ValueError as error:
        raise ValueError("run-tests result envelope is invalid") from error
    if encode_run_tests_result_envelope(envelope) != raw:
        raise ValueError("run-tests result envelope is not canonical")
    return envelope


@dataclass(frozen=True, slots=True)
class PurgeResult:
    eligible: bool
    removed_entries: int


@dataclass(frozen=True, slots=True)
class PatchEvidenceUse:
    patch_receipt_id: str
    execution_status: str
    patch_input_ref: EvidenceRef
    patch_result_ordinal: int | None


@dataclass(frozen=True, slots=True)
class PatchEvidencePair:
    input_artifact: Artifact
    result_artifact: Artifact


@dataclass(frozen=True, slots=True)
class PatchEvidencePairState:
    consumed_input_ordinals: tuple[int, ...]
    committed_input_refs: tuple[EvidenceRef, ...]
    burned_result_ordinals: tuple[int, ...]
    committed_result_ordinals: tuple[int, ...]
    next_pair: PatchEvidencePair | None


def derive_patch_evidence_pair_state(
    policy: EvidencePolicy,
    ledger_prefix: Sequence[PatchEvidenceUse],
) -> PatchEvidencePairState:
    """Derive paired patch slots solely from an immutable receipt projection."""

    if not isinstance(policy, EvidencePolicy):
        raise EvidenceOrdinalError("evidence policy is invalid")
    inputs = {
        artifact.ordinal: artifact
        for artifact in policy.artifacts
        if artifact.purpose == "patch_input"
    }
    inputs_by_path = {
        f"{policy.evidence_root}/{artifact.path}": artifact
        for artifact in inputs.values()
    }
    results = {
        artifact.ordinal: artifact
        for artifact in policy.artifacts
        if artifact.purpose == "patch_result"
    }
    if not inputs or set(inputs) != set(results):
        raise EvidenceOrdinalError("patch evidence policy is not paired")
    try:
        uses = tuple(ledger_prefix)
    except TypeError as error:
        raise EvidenceOrdinalError("ledger prefix is not a sequence") from error

    consumed_inputs: list[int] = []
    committed_inputs: list[EvidenceRef] = []
    burned_results: list[int] = []
    committed_results: list[int] = []
    seen_receipts: set[str] = set()
    expected_ordinal = 1
    for use in uses:
        if not isinstance(use, PatchEvidenceUse):
            raise EvidenceOrdinalError("ledger prefix patch use is invalid")
        if (
            type(use.patch_receipt_id) is not str
            or _DIGEST_PATTERN.fullmatch(use.patch_receipt_id) is None
            or use.patch_receipt_id in seen_receipts
        ):
            raise EvidenceOrdinalError("patch receipt identity is invalid or duplicated")
        seen_receipts.add(use.patch_receipt_id)
        input_ref = use.patch_input_ref
        input_artifact = (
            inputs_by_path.get(input_ref.path)
            if isinstance(input_ref, EvidenceRef)
            else None
        )
        if (
            input_artifact is None
            or input_artifact.ordinal != expected_ordinal
            or input_ref.media_type != input_artifact.media_type
            or input_ref.size_bytes > input_artifact.max_size_bytes
        ):
            raise EvidenceOrdinalError(
                "patch input EvidenceRef is invalid, out of sequence, or reuses a pair"
            )
        consumed_inputs.append(expected_ordinal)
        committed_inputs.append(input_ref)
        if use.execution_status == "failed":
            if use.patch_result_ordinal is not None:
                raise EvidenceOrdinalError(
                    "failed patch must burn rather than publish its result slot"
                )
            burned_results.append(expected_ordinal)
        elif use.execution_status == "succeeded":
            if (
                type(use.patch_result_ordinal) is not int
                or use.patch_result_ordinal != expected_ordinal
                or use.patch_result_ordinal not in results
            ):
                raise EvidenceOrdinalError(
                    "successful patch result does not match its input pair"
                )
            committed_results.append(expected_ordinal)
        else:
            raise EvidenceOrdinalError(
                "patch pair prefix accepts only started succeeded/failed attempts"
            )
        expected_ordinal += 1

    next_pair = (
        PatchEvidencePair(
            input_artifact=inputs[expected_ordinal],
            result_artifact=results[expected_ordinal],
        )
        if expected_ordinal in inputs
        else None
    )
    return PatchEvidencePairState(
        consumed_input_ordinals=tuple(consumed_inputs),
        committed_input_refs=tuple(committed_inputs),
        burned_result_ordinals=tuple(burned_results),
        committed_result_ordinals=tuple(committed_results),
        next_pair=next_pair,
    )


def _git_object_oid(kind: bytes, content: bytes) -> str:
    header = kind + b" " + str(len(content)).encode("ascii") + b"\0"
    return hashlib.sha1(header + content).hexdigest()


def git_blob_oid(content: bytes) -> str:
    """Return the canonical Git SHA-1 blob object ID."""

    if type(content) is not bytes:
        raise SourceArchiveError("blob content must be bytes")
    return _git_object_oid(b"blob", content)


def git_commit_oid(content: bytes) -> str:
    """Return the canonical Git SHA-1 commit object ID."""

    if type(content) is not bytes:
        raise SourceArchiveError("commit content must be bytes")
    return _git_object_oid(b"commit", content)


def _validated_files(files: Sequence[SourceFile]) -> tuple[SourceFile, ...]:
    if len(files) > _MAX_SOURCE_ENTRIES:
        raise SourceArchiveError("source archive exceeds 126 entries")
    validated: list[SourceFile] = []
    seen: set[str] = set()
    for source_file in files:
        if not isinstance(source_file, SourceFile):
            raise SourceArchiveError("source entry is invalid")
        _validate_source_path(source_file.path)
        if source_file.mode not in _ALLOWED_MODES:
            raise SourceArchiveError("source mode is not allowed")
        if type(source_file.content) is not bytes:
            raise SourceArchiveError("source file content must be bytes")
        if len(source_file.content) > _MAX_SOURCE_FILE_BYTES:
            raise SourceArchiveError("source file exceeds 1 MiB")
        if source_file.path in seen:
            raise SourceArchiveError("source path is duplicated")
        seen.add(source_file.path)
        validated.append(source_file)
    validated.sort(key=lambda source_file: source_file.path.encode("ascii"))
    _reject_file_directory_collisions(validated)
    return tuple(validated)


def _validated_candidate_files(
    files: Sequence[SourceFile],
) -> tuple[SourceFile, ...]:
    try:
        file_tuple = tuple(files)
    except TypeError as error:
        raise SourceArchiveError("candidate files must be a sequence") from error
    validated: list[SourceFile] = []
    seen: set[str] = set()
    directories: set[str] = set()
    total_size = 0
    for source_file in file_tuple:
        if not isinstance(source_file, SourceFile):
            raise SourceArchiveError("candidate entry is invalid")
        try:
            validate_canonical_relative_path(source_file.path)
        except PathError as error:
            raise SourceArchiveError("candidate path is not canonical") from error
        if source_file.mode not in _ALLOWED_MODES:
            raise SourceArchiveError("candidate mode is not allowed")
        if type(source_file.content) is not bytes:
            raise SourceArchiveError("candidate file content must be bytes")
        content_size = len(source_file.content)
        if content_size > _MAX_SOURCE_FILE_BYTES:
            raise SourceArchiveError("candidate file exceeds 1 MiB")
        if content_size > _MAX_SOURCE_BYTES - total_size:
            raise SourceArchiveError("candidate files exceed 8 MiB")
        total_size += content_size
        if source_file.path in seen:
            raise SourceArchiveError("candidate path is duplicated")
        seen.add(source_file.path)
        segments = source_file.path.split("/")
        directories.update(
            "/".join(segments[:index])
            for index in range(1, len(segments))
        )
        validated.append(source_file)
    if len(validated) + len(directories) > _MAX_WORKSPACE_MANIFEST_ENTRIES:
        raise SourceArchiveError("candidate workspace exceeds 512 manifest entries")
    validated.sort(key=lambda source_file: source_file.path.encode("ascii"))
    _reject_file_directory_collisions(validated)
    return tuple(validated)


def _validate_source_path(path: str) -> None:
    if type(path) is not str:
        raise SourceArchiveError("source path must be text")
    try:
        encoded = path.encode("ascii")
    except UnicodeEncodeError as error:
        raise SourceArchiveError("source path must be ASCII") from error
    if (
        not 1 <= len(encoded) <= _MAX_SOURCE_PATH_BYTES
        or _PATH_PATTERN.fullmatch(path) is None
    ):
        raise SourceArchiveError("source path is not canonical")
    segments = path.split("/")
    if (
        any(segment in {"", ".", ".."} for segment in segments)
        or segments[0] == ".git"
    ):
        raise SourceArchiveError("source path is not canonical or is protected")


def _reject_file_directory_collisions(files: Sequence[SourceFile]) -> None:
    paths = {source_file.path for source_file in files}
    for path in paths:
        segments = path.split("/")
        for index in range(1, len(segments)):
            if "/".join(segments[:index]) in paths:
                raise SourceArchiveError(
                    "source path has a file/directory collision"
                )


def _tree_node(files: Sequence[SourceFile]) -> dict[bytes, Any]:
    root: dict[bytes, Any] = {}
    for source_file in files:
        node = root
        segments = source_file.path.encode("ascii").split(b"/")
        for segment in segments[:-1]:
            child = node.setdefault(segment, {})
            if not isinstance(child, dict):
                raise SourceArchiveError(
                    "source path has a file/directory collision"
                )
            node = child
        if segments[-1] in node:
            raise SourceArchiveError("source path is duplicated")
        node[segments[-1]] = source_file
    return root


def _tree_oid(node: Mapping[bytes, Any]) -> str:
    entries: list[bytes] = []
    ordered = sorted(
        node.items(),
        key=lambda item: item[0] + (b"/" if isinstance(item[1], dict) else b""),
    )
    for name, value in ordered:
        if isinstance(value, dict):
            mode = b"40000"
            oid = _tree_oid(value)
        else:
            if not isinstance(value, SourceFile):
                raise SourceArchiveError("source tree entry is invalid")
            mode = value.mode.encode("ascii")
            oid = git_blob_oid(value.content)
        entries.append(mode + b" " + name + b"\0" + bytes.fromhex(oid))
    return _git_object_oid(b"tree", b"".join(entries))


def git_tree_oid(files: Sequence[SourceFile]) -> str:
    """Return the recursive Git tree OID for canonical flat source files."""

    validated = _validated_candidate_files(files)
    return _tree_oid(_tree_node(validated))


def _validate_patch_path(path: str) -> None:
    if type(path) is not str:
        raise PatchError("patch path must be text")
    try:
        encoded = path.encode("ascii")
    except UnicodeEncodeError as error:
        raise PatchError("patch path must be ASCII") from error
    if (
        not 1 <= len(encoded) <= _MAX_PATCH_PATH_BYTES
        or _PATCH_PATH_PATTERN.fullmatch(path) is None
        or any(segment in {"", ".", ".."} for segment in path.split("/"))
    ):
        raise PatchError("patch path is not canonical")


def _parse_patch_range(raw_range: str) -> tuple[int, int]:
    match = _RANGE_PATTERN.fullmatch(raw_range)
    if match is None:
        raise PatchError("patch hunk range is not canonical")
    start = int(match.group(1))
    count = 1 if match.group(2) is None else int(match.group(2))
    if start > _MAX_SAFE_INTEGER or count > _MAX_SAFE_INTEGER:
        raise PatchError("patch hunk range exceeds the safe integer limit")
    return start, count


def _parse_patch_hunks(
    lines: Sequence[str],
    position: int,
) -> tuple[tuple[PatchHunk, ...], int]:
    hunks: list[PatchHunk] = []
    while position < len(lines) and lines[position].startswith("@@ "):
        header = _HUNK_PATTERN.fullmatch(lines[position])
        if header is None:
            raise PatchError("patch hunk header is not canonical")
        old_start, old_count = _parse_patch_range(header.group(1))
        new_start, new_count = _parse_patch_range(header.group(2))
        position += 1
        old_seen = 0
        new_seen = 0
        change_seen = False
        hunk_lines: list[PatchLine] = []
        while old_seen < old_count or new_seen < new_count:
            if position >= len(lines):
                raise PatchError("patch hunk body is truncated")
            raw_line = lines[position]
            if not raw_line.endswith("\n") or not raw_line:
                raise PatchError("patch hunk line is not canonical")
            marker = raw_line[0]
            if marker not in {" ", "+", "-"}:
                raise PatchError("patch hunk line is not canonical")
            if marker == " ":
                old_seen += 1
                new_seen += 1
            elif marker == "-":
                old_seen += 1
                change_seen = True
            else:
                new_seen += 1
                change_seen = True
            if old_seen > old_count or new_seen > new_count:
                raise PatchError("patch hunk counts do not match its body")
            hunk_lines.append(
                PatchLine(marker, raw_line[1:-1].encode("utf-8"))
            )
            position += 1
        if not change_seen:
            raise PatchError("patch hunk must contain a change")
        hunks.append(
            PatchHunk(
                old_start=old_start,
                old_count=old_count,
                new_start=new_start,
                new_count=new_count,
                lines=tuple(hunk_lines),
            )
        )
    if not hunks:
        raise PatchError("patch section must contain at least one hunk")
    return tuple(hunks), position


def _declared_patch_paths(
    declared_target_paths: Sequence[str],
) -> tuple[str, ...]:
    if isinstance(declared_target_paths, (str, bytes)):
        raise PatchError("declared patch targets must be a path sequence")
    try:
        paths = tuple(declared_target_paths)
    except TypeError as error:
        raise PatchError("declared patch targets must be a path sequence") from error
    if not 1 <= len(paths) <= _MAX_PATCH_PATHS:
        raise PatchError("patch must declare 1..32 target paths")
    for path in paths:
        _validate_patch_path(path)
    encoded = tuple(path.encode("ascii") for path in paths)
    if encoded != tuple(sorted(encoded)) or len(paths) != len(set(paths)):
        raise PatchError("declared patch targets must be sorted and unique")
    return paths


def parse_patch_phase_a(
    raw: bytes,
    *,
    expected_patch_digest: str,
    expected_patch_size_bytes: int,
    declared_target_paths: Sequence[str],
) -> CanonicalPatch:
    """Validate and parse a bounded canonical patch without repository access."""

    if type(raw) is not bytes:
        raise PatchError("patch must be exact bytes")
    if (
        type(expected_patch_digest) is not str
        or _DIGEST_PATTERN.fullmatch(expected_patch_digest) is None
        or hashlib.sha256(raw).hexdigest() != expected_patch_digest
    ):
        raise PatchError("patch digest binding mismatch")
    if (
        type(expected_patch_size_bytes) is not int
        or expected_patch_size_bytes != len(raw)
    ):
        raise PatchError("patch size binding mismatch")
    if not 1 <= len(raw) <= _MAX_PATCH_BYTES:
        raise PatchError("patch must contain 1..65536 bytes")
    declared_paths = _declared_patch_paths(declared_target_paths)
    if (
        raw.startswith(b"\xef\xbb\xbf")
        or b"\0" in raw
        or b"\r" in raw
        or not raw.endswith(b"\n")
    ):
        raise PatchError("patch byte grammar is not canonical")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PatchError("patch must be valid UTF-8") from error

    lines = text.splitlines(keepends=True)
    sections: list[PatchSection] = []
    position = 0
    previous_path: bytes | None = None
    seen: set[str] = set()
    zero_oid = "0" * 40
    while position < len(lines):
        header = _PATCH_HEADER_PATTERN.fullmatch(lines[position])
        if header is None:
            raise PatchError("patch file header is not canonical")
        left_path, right_path = header.groups()
        if left_path != right_path:
            raise PatchError("patch header paths do not match")
        path = left_path
        _validate_patch_path(path)
        encoded_path = path.encode("ascii")
        if path in seen:
            raise PatchError("patch path is duplicated")
        if previous_path is not None and encoded_path <= previous_path:
            raise PatchError("patch sections are not in canonical path order")
        seen.add(path)
        previous_path = encoded_path
        position += 1
        if position >= len(lines):
            raise PatchError("patch section is truncated")

        operation: str
        mode: str
        old_oid: str
        new_oid: str
        line = lines[position]
        modify = _MODIFY_INDEX_PATTERN.fullmatch(line)
        if modify is not None:
            operation = "modify"
            old_oid, new_oid, mode = modify.groups()
            if old_oid == zero_oid or new_oid == zero_oid:
                raise PatchError("modify patch object IDs must be nonzero")
            position += 1
            expected_headers = (f"--- a/{path}\n", f"+++ b/{path}\n")
        elif line.startswith("new file mode "):
            mode_match = re.fullmatch(r"new file mode (100644|100755)\n", line)
            if mode_match is None:
                raise PatchError("new file mode is not canonical")
            operation = "create"
            mode = mode_match.group(1)
            position += 1
            if position >= len(lines):
                raise PatchError("create patch is truncated")
            index_match = _CREATE_INDEX_PATTERN.fullmatch(lines[position])
            if index_match is None:
                raise PatchError("create patch index is not canonical")
            old_oid, new_oid = index_match.groups()
            if new_oid == zero_oid:
                raise PatchError("created blob object ID must be nonzero")
            position += 1
            expected_headers = ("--- /dev/null\n", f"+++ b/{path}\n")
        elif line.startswith("deleted file mode "):
            mode_match = re.fullmatch(
                r"deleted file mode (100644|100755)\n",
                line,
            )
            if mode_match is None:
                raise PatchError("deleted file mode is not canonical")
            operation = "delete"
            mode = mode_match.group(1)
            position += 1
            if position >= len(lines):
                raise PatchError("delete patch is truncated")
            index_match = _DELETE_INDEX_PATTERN.fullmatch(lines[position])
            if index_match is None:
                raise PatchError("delete patch index is not canonical")
            old_oid, new_oid = index_match.groups()
            if old_oid == zero_oid:
                raise PatchError("deleted blob object ID must be nonzero")
            position += 1
            expected_headers = (f"--- a/{path}\n", "+++ /dev/null\n")
        else:
            raise PatchError("patch operation is unsupported or noncanonical")

        if (
            position + 1 >= len(lines)
            or lines[position] != expected_headers[0]
            or lines[position + 1] != expected_headers[1]
        ):
            raise PatchError("patch old/new path headers are not canonical")
        position += 2
        hunks, position = _parse_patch_hunks(lines, position)
        sections.append(
            PatchSection(
                operation=operation,
                path=path,
                mode=mode,
                old_oid=old_oid,
                new_oid=new_oid,
                hunks=hunks,
            )
        )

    derived_paths = tuple(section.path for section in sections)
    if derived_paths != declared_paths:
        raise PatchError("derived patch paths do not match declared targets")
    return CanonicalPatch(
        raw=raw,
        patch_digest=expected_patch_digest,
        patch_size_bytes=len(raw),
        derived_patch_paths=derived_paths,
        sections=tuple(sections),
    )


def _canonical_patch_text(content: bytes) -> tuple[bytes, ...]:
    if (
        type(content) is not bytes
        or not content
        or content.startswith(b"\xef\xbb\xbf")
        or b"\0" in content
        or b"\r" in content
        or not content.endswith(b"\n")
    ):
        raise PatchError("touched file is not canonical UTF-8 text")
    try:
        content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PatchError("touched file is not canonical UTF-8 text") from error
    return tuple(content.splitlines(keepends=True))


def _apply_hunks(
    original: tuple[bytes, ...],
    hunks: Sequence[PatchHunk],
) -> bytes:
    source_position = 0
    output: list[bytes] = []
    for hunk in hunks:
        target = hunk.old_start if hunk.old_count == 0 else hunk.old_start - 1
        if target < source_position or target > len(original):
            raise PatchError("patch hunk offset does not match the parent")
        output.extend(original[source_position:target])
        source_position = target
        expected_new_start = len(output) + (1 if hunk.new_count else 0)
        if hunk.new_start != expected_new_start:
            raise PatchError("patch hunk output offset is not canonical")
        for line in hunk.lines:
            content_line = line.content + b"\n"
            if line.operation == "+":
                output.append(content_line)
                continue
            if (
                source_position >= len(original)
                or original[source_position] != content_line
            ):
                raise PatchError("patch context does not match the parent")
            if line.operation == " ":
                output.append(content_line)
            source_position += 1
    output.extend(original[source_position:])
    return b"".join(output)


def _has_immediate_parent(paths: set[str], path: str) -> bool:
    parent, separator, _ = path.rpartition("/")
    if not separator:
        return True
    prefix = parent + "/"
    return any(candidate.startswith(prefix) for candidate in paths)


def _validate_patch_binding(value: str, pattern: re.Pattern[str], name: str) -> None:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise PatchError(f"{name} binding is invalid")


def _unix_seconds(occurred_at: str) -> int:
    if (
        type(occurred_at) is not str
        or _CANONICAL_TIME_PATTERN.fullmatch(occurred_at) is None
    ):
        raise PatchError("patch commit time is not a canonical UTC second")
    try:
        parsed = datetime.strptime(
            occurred_at,
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise PatchError("patch commit time is not a valid UTC second") from error
    if parsed < datetime(1970, 1, 1, tzinfo=timezone.utc):
        raise PatchError("patch commit time precedes the Unix epoch")
    return calendar.timegm(parsed.utctimetuple())


def apply_patch_phase_b(
    patch: CanonicalPatch,
    parent_files: Sequence[SourceFile],
    *,
    parent_commit: str,
    parent_manifest_digest: str,
    workspace_manifest_digest: str,
    occurred_at: str,
    replay_profile: ReplayProfile,
    replay_profile_digest: str,
    observed_manifest_delta_paths: Sequence[str],
) -> PatchApplication:
    """Apply a parsed canonical patch to an in-memory source snapshot."""

    if not isinstance(patch, CanonicalPatch):
        raise PatchError("Phase B requires a canonical Phase A patch")
    try:
        validated_parent = _validated_candidate_files(parent_files)
    except SourceArchiveError as error:
        message = str(error)
        if "collision" in message:
            raise PatchError("parent source has a path collision") from error
        raise PatchError(f"parent source is invalid: {message}") from error
    parent_by_path = {
        source_file.path: source_file for source_file in validated_parent
    }
    parent_paths = set(parent_by_path)
    result_by_path = dict(parent_by_path)

    for section in patch.sections:
        existing = parent_by_path.get(section.path)
        if section.operation == "create":
            if existing is not None:
                raise PatchError("create target already exists")
            if (
                len(section.hunks) != 1
                or section.hunks[0].old_start != 0
                or section.hunks[0].old_count != 0
                or any(
                    line.operation != "+"
                    for line in section.hunks[0].lines
                )
            ):
                raise PatchError("create patch hunk is not canonical")
            if any(
                section.path.startswith(candidate + "/")
                or candidate.startswith(section.path + "/")
                for candidate in parent_paths
            ):
                raise PatchError("create target has a file/directory collision")
            if not _has_immediate_parent(parent_paths, section.path):
                raise PatchError("create target immediate parent does not exist")
            created = _apply_hunks((), section.hunks)
            if not created:
                raise PatchError("create patch produced an empty file")
            _canonical_patch_text(created)
            if git_blob_oid(created) != section.new_oid:
                raise PatchError("create patch new blob object ID mismatch")
            result_by_path[section.path] = SourceFile(
                section.path,
                section.mode,
                created,
            )
            continue

        if existing is None:
            raise PatchError("patch target does not exist")
        if existing.mode != section.mode:
            raise PatchError("patch target mode does not match the parent")
        original_lines = _canonical_patch_text(existing.content)
        if git_blob_oid(existing.content) != section.old_oid:
            raise PatchError("patch old blob object ID mismatch")
        updated = _apply_hunks(original_lines, section.hunks)

        if section.operation == "modify":
            if not updated:
                raise PatchError("modify patch may not produce an empty file")
            _canonical_patch_text(updated)
            if updated == existing.content:
                raise PatchError("modify patch is a no-op")
            if git_blob_oid(updated) != section.new_oid:
                raise PatchError("modify patch new blob object ID mismatch")
            result_by_path[section.path] = SourceFile(
                section.path,
                section.mode,
                updated,
            )
        elif section.operation == "delete":
            if (
                len(section.hunks) != 1
                or section.hunks[0].new_start != 0
                or section.hunks[0].new_count != 0
                or any(
                    line.operation != "-"
                    for line in section.hunks[0].lines
                )
            ):
                raise PatchError("delete patch hunk is not canonical")
            if updated:
                raise PatchError("delete patch did not remove the complete file")
            result_by_path.pop(section.path)
        else:
            raise PatchError("patch operation is unsupported")

    result_paths = set(result_by_path)
    for section in patch.sections:
        if (
            section.operation == "delete"
            and not _has_immediate_parent(result_paths, section.path)
        ):
            raise PatchError("delete patch removed its immediate parent directory")

    try:
        result_files = _validated_candidate_files(tuple(result_by_path.values()))
    except SourceArchiveError as error:
        message = str(error)
        if "collision" in message:
            raise PatchError("patch result has a path collision") from error
        raise PatchError(f"patch result is invalid: {message}") from error
    changed_paths = tuple(
        path
        for path in sorted(parent_paths | result_paths)
        if parent_by_path.get(path) != result_by_path.get(path)
    )
    if changed_paths != patch.derived_patch_paths:
        raise PatchError("patch manifest delta does not match target paths")
    try:
        observed_paths = tuple(observed_manifest_delta_paths)
    except TypeError as error:
        raise PatchError("observed manifest delta is invalid") from error
    if observed_paths != changed_paths:
        raise PatchError("observed manifest delta does not match patch result")

    if not isinstance(replay_profile, ReplayProfile):
        raise PatchError("replay profile is invalid")
    expected_replay_digest = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/replay-profile/v0.1",
                "profile": replay_profile.model_dump(mode="json"),
            }
        )
    ).hexdigest()
    if replay_profile_digest != expected_replay_digest:
        raise PatchError("replay profile digest binding mismatch")
    _validate_patch_binding(parent_commit, _OID_PATTERN, "parent commit")
    _validate_patch_binding(
        parent_manifest_digest,
        _DIGEST_PATTERN,
        "parent manifest digest",
    )
    _validate_patch_binding(
        workspace_manifest_digest,
        _DIGEST_PATTERN,
        "workspace manifest digest",
    )
    unix_seconds = _unix_seconds(occurred_at)
    tree_oid = git_tree_oid(result_files)
    author = f"{replay_profile.author_name} <{replay_profile.author_email}>"
    commit_raw = (
        f"tree {tree_oid}\n"
        f"parent {parent_commit}\n"
        f"author {author} {unix_seconds} +0000\n"
        f"committer {author} {unix_seconds} +0000\n"
        "\n"
        f"{replay_profile.commit_message_prefix}{patch.patch_digest}\n"
    ).encode("utf-8")
    candidate_commit = git_commit_oid(commit_raw)
    evidence = PatchResultEvidence(
        schema_version="openworkproof-patch-result/0.1",
        parent_commit=parent_commit,
        parent_manifest_digest=parent_manifest_digest,
        candidate_commit=candidate_commit,
        workspace_manifest_digest=workspace_manifest_digest,
        patch_digest=patch.patch_digest,
        patch_size_bytes=patch.patch_size_bytes,
        replay_profile_digest=replay_profile_digest,
    )
    return PatchApplication(
        files=result_files,
        changed_paths=changed_paths,
        tree_oid=tree_oid,
        commit_raw=commit_raw,
        candidate_commit=candidate_commit,
        evidence=evidence,
    )


def validate_canonical_relative_path(path: str) -> str:
    """Return a path only if it is canonical and outside protected ``.git``."""

    if type(path) is not str:
        raise PathError("path must be text")
    try:
        encoded = path.encode("ascii")
    except UnicodeEncodeError as error:
        raise PathError("path must be ASCII") from error
    segments = path.split("/")
    if (
        not 1 <= len(encoded) <= _MAX_PATCH_PATH_BYTES
        or _PATCH_PATH_PATTERN.fullmatch(path) is None
        or any(segment in {"", ".", ".."} for segment in segments)
    ):
        raise PathError("path is not a canonical relative POSIX path")
    if segments[0] == ".git":
        raise PathError(".git is a protected path")
    return path


def _source_paths_and_directories(
    files: Sequence[SourceFile],
) -> tuple[set[str], set[str]]:
    try:
        validated = _validated_files(files)
    except SourceArchiveError as error:
        raise PathError(f"source manifest is invalid: {error}") from error
    file_paths = {source_file.path for source_file in validated}
    directories: set[str] = set()
    for path in file_paths:
        segments = path.split("/")
        directories.update(
            "/".join(segments[:index])
            for index in range(1, len(segments))
        )
    return file_paths, directories


def root_semantically_covers(
    root: str,
    path: str,
    source_manifest: Sequence[SourceFile],
) -> bool:
    """Apply the frozen file-root versus directory-root coverage rule."""

    root = validate_canonical_relative_path(root)
    path = validate_canonical_relative_path(path)
    file_paths, directories = _source_paths_and_directories(source_manifest)
    if root in file_paths:
        return path == root
    if root in directories:
        return path == root or path.startswith(root + "/")
    raise PathError("root does not resolve in the source manifest")


def _encode_unpadded_base64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_unpadded_path(value: str) -> bytes:
    if type(value) is not str or not value or "=" in value:
        raise ManifestError("manifest path encoding is not canonical base64url")
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as error:
        raise ManifestError(
            "manifest path encoding is not canonical base64url"
        ) from error
    if _encode_unpadded_base64url(raw) != value:
        raise ManifestError("manifest path encoding is not canonical base64url")
    return raw


def _workspace_entry_from_record(
    record: WorkspaceScanRecord,
) -> tuple[bytes, WorkspaceManifestEntry]:
    if not isinstance(record, WorkspaceScanRecord):
        raise ManifestError("workspace scan record is invalid")
    if (
        type(record.path_bytes) is not bytes
        or not record.path_bytes
        or b"\0" in record.path_bytes
    ):
        raise ManifestError("workspace path bytes are invalid")
    if record.entry_type not in _WORKSPACE_TYPES:
        raise ManifestError("workspace entry type is invalid")
    if (
        type(record.posix_mode) is not int
        or not 0 <= record.posix_mode <= 0o177777
    ):
        raise ManifestError("workspace POSIX mode is invalid")
    if (
        type(record.read_token_before) is not str
        or type(record.read_token_after) is not str
        or record.read_token_before != record.read_token_after
    ):
        raise ManifestError("workspace read race was detected")
    if type(record.link_count) is not int or record.link_count < 1:
        raise ManifestError("workspace link count is invalid")

    size_bytes = record.size_bytes
    sha256: str | None = None
    symlink_target: str | None = None
    if record.entry_type == "directory":
        if (
            size_bytes is not None
            or record.content is not None
            or record.symlink_target is not None
        ):
            raise ManifestError("directory scan record is inconsistent")
    elif record.entry_type == "regular":
        if record.link_count != 1:
            raise ManifestError("regular file is a forbidden hardlink")
        if (
            type(size_bytes) is not int
            or size_bytes < 0
            or type(record.content) is not bytes
            or size_bytes != len(record.content)
            or record.symlink_target is not None
        ):
            raise ManifestError("regular file scan record is inconsistent")
        sha256 = hashlib.sha256(record.content).hexdigest()
    elif record.entry_type == "symlink":
        if (
            type(size_bytes) is not int
            or size_bytes < 0
            or record.content is not None
            or type(record.symlink_target) is not bytes
            or size_bytes != len(record.symlink_target)
        ):
            raise ManifestError("symlink scan record is inconsistent")
        symlink_target = _encode_unpadded_base64url(record.symlink_target)
    elif (
        type(size_bytes) is not int
        or size_bytes < 0
        or record.content is not None
        or record.symlink_target is not None
    ):
        raise ManifestError("other scan record is inconsistent")

    return (
        record.path_bytes,
        WorkspaceManifestEntry(
            path_bytes_b64url=_encode_unpadded_base64url(record.path_bytes),
            type=record.entry_type,
            posix_mode=f"{record.posix_mode:06o}",
            size_bytes=size_bytes,
            sha256=sha256,
            symlink_target_b64url=symlink_target,
        ),
    )


def build_workspace_manifest(
    head_commit: str,
    records: Sequence[WorkspaceScanRecord],
) -> WorkspaceManifest:
    """Build a closed manifest from already bounded, non-following scan facts."""

    if type(head_commit) is not str or _OID_PATTERN.fullmatch(head_commit) is None:
        raise ManifestError("workspace head commit is invalid")
    try:
        record_tuple = tuple(records)
    except TypeError as error:
        raise ManifestError("workspace scan records are invalid") from error
    if len(record_tuple) > _MAX_WORKSPACE_MANIFEST_ENTRIES:
        raise ManifestError("workspace manifest exceeds 512 entries")
    encoded = tuple(_workspace_entry_from_record(item) for item in record_tuple)
    paths = [path for path, _ in encoded]
    if len(paths) != len(set(paths)):
        raise ManifestError("workspace manifest path is duplicated")
    entries = tuple(entry for _, entry in sorted(encoded, key=lambda item: item[0]))
    return WorkspaceManifest(
        schema_version="openworkproof-workspace-manifest/0.1",
        head_commit=head_commit,
        entries=entries,
    )


def _workspace_read_token(metadata: os.stat_result) -> str:
    return ":".join(
        str(value)
        for value in (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
    )


def _read_workspace_file(descriptor: int, expected_size: int) -> bytes:
    if expected_size > _MAX_SOURCE_FILE_BYTES:
        raise ManifestError("workspace regular file exceeds 1 MiB")
    chunks: list[bytes] = []
    remaining = expected_size
    while remaining:
        chunk = os.read(descriptor, min(remaining, 65_536))
        if not chunk:
            raise ManifestError("workspace regular file changed during read")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise ManifestError("workspace regular file changed during read")
    return b"".join(chunks)


def scan_workspace_manifest(
    root_fd: int,
    head_commit: str,
) -> WorkspaceManifest:
    """Scan every descendant from one anchored directory without following links."""

    if type(root_fd) is not int or root_fd < 0:
        raise ManifestError("workspace root descriptor is invalid")
    try:
        root_metadata = os.fstat(root_fd)
    except OSError as error:
        raise ManifestError("workspace root descriptor is unavailable") from error
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise ManifestError("workspace root descriptor is not a directory")
    root_token = _workspace_read_token(root_metadata)
    records: list[WorkspaceScanRecord] = []
    entries_seen = 0
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if type(nofollow) is not int or nofollow <= 0:
        raise ManifestError("workspace scan requires O_NOFOLLOW support")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow

    def scan(directory_fd: int, prefix: bytes) -> None:
        nonlocal entries_seen
        try:
            names = tuple(
                sorted(
                    os.listdir(directory_fd),
                    key=os.fsencode,
                )
            )
        except OSError as error:
            raise ManifestError("workspace directory cannot be listed") from error
        for name in names:
            name_bytes = os.fsencode(name)
            path_bytes = prefix + name_bytes if prefix else name_bytes
            if entries_seen >= _MAX_WORKSPACE_MANIFEST_ENTRIES:
                raise ManifestError("workspace manifest exceeds 512 entries")
            entries_seen += 1
            try:
                before = os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise ManifestError("workspace entry cannot be inspected") from error
            token_before = _workspace_read_token(before)
            content: bytes | None = None
            target: bytes | None = None
            size: int | None
            if stat.S_ISDIR(before.st_mode):
                entry_type = "directory"
                size = None
                try:
                    child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
                except OSError as error:
                    raise ManifestError(
                        "workspace directory cannot be opened safely"
                    ) from error
                try:
                    if not os.path.samestat(before, os.fstat(child_fd)):
                        raise ManifestError(
                            "workspace directory changed before traversal"
                        )
                    scan(child_fd, path_bytes + b"/")
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(before.st_mode):
                entry_type = "regular"
                size = before.st_size
                try:
                    descriptor = os.open(
                        name,
                        os.O_RDONLY | nofollow,
                        dir_fd=directory_fd,
                    )
                except OSError as error:
                    raise ManifestError(
                        "workspace regular file cannot be opened safely"
                    ) from error
                try:
                    opened = os.fstat(descriptor)
                    if not os.path.samestat(before, opened):
                        raise ManifestError(
                            "workspace regular file changed before read"
                        )
                    content = _read_workspace_file(descriptor, size)
                    if _workspace_read_token(os.fstat(descriptor)) != token_before:
                        raise ManifestError(
                            "workspace regular file changed during read"
                        )
                finally:
                    os.close(descriptor)
            elif stat.S_ISLNK(before.st_mode):
                entry_type = "symlink"
                try:
                    target = os.fsencode(os.readlink(name, dir_fd=directory_fd))
                except OSError as error:
                    raise ManifestError(
                        "workspace symlink cannot be read safely"
                    ) from error
                size = len(target)
            else:
                entry_type = "other"
                size = before.st_size
            try:
                after = os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise ManifestError("workspace entry changed during scan") from error
            records.append(
                WorkspaceScanRecord(
                    path_bytes=path_bytes,
                    entry_type=entry_type,
                    posix_mode=before.st_mode,
                    size_bytes=size,
                    content=content,
                    symlink_target=target,
                    link_count=before.st_nlink,
                    read_token_before=token_before,
                    read_token_after=_workspace_read_token(after),
                )
            )

    duplicate = os.dup(root_fd)
    try:
        scan(duplicate, b"")
        if _workspace_read_token(os.fstat(root_fd)) != root_token:
            raise ManifestError("workspace root changed during scan")
    except OSError as error:
        raise ManifestError("workspace scan failed") from error
    finally:
        os.close(duplicate)
    manifest = build_workspace_manifest(head_commit, records)
    _workspace_manifest_json(manifest)
    return manifest


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _run_git(
    *,
    git_dir: Path | None,
    worktree: Path | None,
    arguments: Sequence[str],
    input_bytes: bytes | None = None,
) -> bytes:
    executable = Path("/usr/bin/git")
    if not executable.is_file():
        raise CandidateWorkspaceError("trusted Git executable is unavailable")
    command = [str(executable)]
    if git_dir is not None:
        command.append(f"--git-dir={git_dir}")
    if worktree is not None:
        command.append(f"--work-tree={worktree}")
    command.extend(
        (
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.filemode=true",
            "-c",
            "core.hooksPath=/dev/null",
        )
    )
    command.extend(arguments)
    try:
        completed = subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            timeout=30,
            env=_git_environment(),
            cwd=worktree if worktree is not None else None,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CandidateWorkspaceError("trusted Git operation failed") from error
    return completed.stdout


def _run_git_read_only(
    *,
    git_dir: Path,
    worktree: Path | None,
    arguments: tuple[str, ...],
) -> subprocess.CompletedProcess[bytes]:
    executable = Path("/usr/bin/git")
    if not executable.is_file():
        raise CandidateWorkspaceError("trusted Git executable is unavailable")
    command = [str(executable), f"--git-dir={git_dir}"]
    if worktree is not None:
        command.append(f"--work-tree={worktree}")
    command.extend(
        (
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.filemode=true",
            "-c",
            "core.hooksPath=/dev/null",
        )
    )
    command.extend(arguments)
    try:
        return subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
            env={
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_TERMINAL_PROMPT": "0",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
            cwd=worktree if worktree is not None else None,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CandidateWorkspaceError("trusted Git operation failed") from error


def _write_candidate_source(
    worktree: Path,
    files: Sequence[SourceFile],
) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if type(nofollow) is not int or nofollow <= 0:
        raise CandidateWorkspaceError("candidate setup requires O_NOFOLLOW")
    for source_file in files:
        segments = source_file.path.split("/")
        parent = worktree
        for segment in segments[:-1]:
            parent = parent / segment
            parent.mkdir(mode=0o755, exist_ok=True)
            parent.chmod(0o755)
        target = parent / segments[-1]
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
            0o600,
        )
        try:
            view = memoryview(source_file.content)
            written = 0
            while written < len(view):
                count = os.write(descriptor, view[written:])
                if count <= 0:
                    raise CandidateWorkspaceError(
                        "candidate source write made no progress"
                    )
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        target.chmod(0o755 if source_file.mode == "100755" else 0o644)


def initialize_candidate_workspace(
    request: WorkspaceInitRequest,
) -> CandidateWorkspace:
    """Recreate one controlled candidate using separate Git metadata."""

    if type(request) is not WorkspaceInitRequest:
        raise CandidateWorkspaceError("workspace initialization request is invalid")
    runtime_root = request.runtime_root
    source = request.source
    if (
        not isinstance(runtime_root, Path)
        or not runtime_root.is_absolute()
        or runtime_root != Path(os.path.abspath(runtime_root))
        or type(request.workspace_id) is not str
        or _DIGEST_PATTERN.fullmatch(request.workspace_id) is None
        or type(source) is not ParsedSourceArchive
    ):
        raise CandidateWorkspaceError("workspace initialization binding is invalid")
    try:
        root_named = os.stat(runtime_root, follow_symlinks=False)
        if (
            not stat.S_ISDIR(root_named.st_mode)
            or stat.S_IMODE(root_named.st_mode) != 0o700
            or root_named.st_uid != os.geteuid()
        ):
            raise CandidateWorkspaceError(
                "candidate runtime root must be a private directory"
            )
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if (
            type(nofollow) is not int
            or nofollow <= 0
            or type(directory) is not int
            or directory <= 0
        ):
            raise CandidateWorkspaceError(
                "candidate setup requires directory no-follow support"
            )
        root_fd = os.open(runtime_root, os.O_RDONLY | directory | nofollow)
        try:
            if not os.path.samestat(root_named, os.fstat(root_fd)):
                raise CandidateWorkspaceError("candidate runtime root changed")
            os.mkdir(request.workspace_id, 0o700, dir_fd=root_fd)
        finally:
            os.close(root_fd)
        candidate_root = runtime_root / request.workspace_id
        candidate_root.chmod(0o700)
        worktree = candidate_root / "worktree"
        git_dir = candidate_root / "git"
        worktree.mkdir(mode=0o700)
        git_dir.mkdir(mode=0o700)

        files = _validated_candidate_files(source.files)
        if (
            git_tree_oid(files) != source.tree_oid
            or git_commit_oid(source.commit_raw) != source.source_commit
        ):
            raise CandidateWorkspaceError(
                "candidate source object binding is invalid"
            )
        _validate_commit_raw(source.commit_raw, source.tree_oid)
        _write_candidate_source(worktree, files)
        _run_git(
            git_dir=None,
            worktree=None,
            arguments=("init", "--bare", "--quiet", str(git_dir)),
        )
        _run_git(
            git_dir=git_dir,
            worktree=worktree,
            arguments=("add", "--all", "--", "."),
        )
        tree_oid = _run_git(
            git_dir=git_dir,
            worktree=worktree,
            arguments=("write-tree",),
        ).decode("ascii").strip()
        if tree_oid != source.tree_oid:
            raise CandidateWorkspaceError(
                "candidate Git tree does not match source"
            )
        commit_oid = _run_git(
            git_dir=git_dir,
            worktree=worktree,
            arguments=("hash-object", "-t", "commit", "-w", "--stdin"),
            input_bytes=source.commit_raw,
        ).decode("ascii").strip()
        if commit_oid != source.source_commit:
            raise CandidateWorkspaceError(
                "candidate Git commit does not match source"
            )
        _run_git(
            git_dir=git_dir,
            worktree=worktree,
            arguments=("update-ref", "refs/heads/candidate", commit_oid),
        )
        _run_git(
            git_dir=git_dir,
            worktree=worktree,
            arguments=("symbolic-ref", "HEAD", "refs/heads/candidate"),
        )
        _run_git(
            git_dir=git_dir,
            worktree=worktree,
            arguments=("reset", "--hard", commit_oid),
        )
        if _run_git(
            git_dir=git_dir,
            worktree=worktree,
            arguments=("status", "--porcelain=v1", "--untracked-files=all"),
        ):
            raise CandidateWorkspaceError("candidate Git worktree is not clean")
        worktree_fd = os.open(worktree, os.O_RDONLY | directory | nofollow)
        try:
            manifest = scan_workspace_manifest(worktree_fd, commit_oid)
        finally:
            os.close(worktree_fd)
        manifest_digest = workspace_manifest_digest(manifest)
        control = rfc8785.dumps(
            {
                "schema_version": "openworkproof-candidate-control/0.1",
                "workspace_id": request.workspace_id,
                "source_artifact_sha256": source.artifact_sha256,
                "head_commit": commit_oid,
                "workspace_manifest_digest": manifest_digest,
                "worktree_inode": os.stat(worktree, follow_symlinks=False).st_ino,
                "git_inode": os.stat(git_dir, follow_symlinks=False).st_ino,
            }
        )
        control_path = candidate_root / "control.json"
        control_fd = os.open(
            control_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
            0o600,
        )
        try:
            view = memoryview(control)
            written = 0
            while written < len(view):
                count = os.write(control_fd, view[written:])
                if count <= 0:
                    raise CandidateWorkspaceError(
                        "candidate control record write made no progress"
                    )
                written += count
            os.fsync(control_fd)
        finally:
            os.close(control_fd)
        return CandidateWorkspace(
            runtime_root=runtime_root,
            candidate_root=candidate_root,
            worktree=worktree,
            git_dir=git_dir,
            workspace_id=request.workspace_id,
            source_artifact_sha256=source.artifact_sha256,
            head_commit=commit_oid,
            workspace_manifest_digest=manifest_digest,
        )
    except CandidateWorkspaceError:
        raise
    except Exception as error:
        raise CandidateWorkspaceError("RECOVERY_REQUIRED") from error


def _candidate_from_read_request(
    request: CandidateReadRequest,
) -> CandidateWorkspace:
    if type(request) is not CandidateReadRequest:
        raise CandidateReadError("RECOVERY_REQUIRED")
    try:
        validate_canonical_relative_path(request.path)
    except (PathError, TypeError, ValueError):
        raise CandidateReadError("PATH_DENIED") from None
    return _candidate_from_request_binding(
        runtime_root=request.runtime_root,
        workspace_id=request.workspace_id,
        source_artifact_sha256=request.source_artifact_sha256,
        expected_head_commit=request.expected_head_commit,
        expected_workspace_manifest_digest=(
            request.expected_workspace_manifest_digest
        ),
    )


def _candidate_from_execution_snapshot_request(
    request: CandidateExecutionSnapshotRequest,
) -> CandidateWorkspace:
    if type(request) is not CandidateExecutionSnapshotRequest:
        raise CandidateReadError("RECOVERY_REQUIRED")
    return _candidate_from_request_binding(
        runtime_root=request.runtime_root,
        workspace_id=request.workspace_id,
        source_artifact_sha256=request.source_artifact_sha256,
        expected_head_commit=request.expected_head_commit,
        expected_workspace_manifest_digest=(
            request.expected_workspace_manifest_digest
        ),
    )


def _candidate_from_request_binding(
    *,
    runtime_root: Path,
    workspace_id: str,
    source_artifact_sha256: str,
    expected_head_commit: str,
    expected_workspace_manifest_digest: str,
) -> CandidateWorkspace:
    if (
        type(runtime_root) is not type(Path())
        or not runtime_root.is_absolute()
        or runtime_root != Path(os.path.abspath(runtime_root))
        or type(workspace_id) is not str
        or _DIGEST_PATTERN.fullmatch(workspace_id) is None
        or type(source_artifact_sha256) is not str
        or _DIGEST_PATTERN.fullmatch(source_artifact_sha256) is None
        or type(expected_head_commit) is not str
        or _OID_PATTERN.fullmatch(expected_head_commit) is None
        or type(expected_workspace_manifest_digest) is not str
        or _DIGEST_PATTERN.fullmatch(expected_workspace_manifest_digest) is None
    ):
        raise CandidateReadError("RECOVERY_REQUIRED")
    candidate_root = runtime_root / workspace_id
    return CandidateWorkspace(
        runtime_root=runtime_root,
        candidate_root=candidate_root,
        worktree=candidate_root / "worktree",
        git_dir=candidate_root / "git",
        workspace_id=workspace_id,
        source_artifact_sha256=source_artifact_sha256,
        head_commit=expected_head_commit,
        workspace_manifest_digest=expected_workspace_manifest_digest,
    )


def _verify_candidate_checkpoint_read_only(
    workspace: CandidateWorkspace,
    path: str | None,
) -> _VerifiedCandidateReadCheckpoint:
    descriptors: list[int] = []
    ownership_transferred = False
    try:
        _validate_candidate_layout(workspace)
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if (
            type(nofollow) is not int
            or nofollow <= 0
            or type(directory) is not int
            or directory <= 0
        ):
            raise CandidateWorkspaceError(
                "candidate scan requires directory no-follow support"
            )
        directory_flags = os.O_RDONLY | directory | nofollow
        root_descriptor = os.open(workspace.runtime_root, directory_flags)
        descriptors.append(root_descriptor)
        candidate_descriptor = os.open(
            workspace.workspace_id,
            directory_flags,
            dir_fd=root_descriptor,
        )
        descriptors.append(candidate_descriptor)
        worktree_descriptor = os.open(
            "worktree",
            directory_flags,
            dir_fd=candidate_descriptor,
        )
        descriptors.append(worktree_descriptor)
        git_descriptor = os.open(
            "git",
            directory_flags,
            dir_fd=candidate_descriptor,
        )
        descriptors.append(git_descriptor)
        anchors: list[_CandidateReadAnchor] = [
            _candidate_read_anchor(
                root_descriptor,
                parent_descriptor=None,
                name=workspace.runtime_root,
            ),
            _candidate_read_anchor(
                candidate_descriptor,
                parent_descriptor=root_descriptor,
                name=workspace.workspace_id,
            ),
            _candidate_read_anchor(
                worktree_descriptor,
                parent_descriptor=candidate_descriptor,
                name="worktree",
            ),
            _candidate_read_anchor(
                git_descriptor,
                parent_descriptor=candidate_descriptor,
                name="git",
            ),
        ]
        for anchor in anchors:
            metadata = os.fstat(anchor.descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o700
                or metadata.st_uid != os.geteuid()
            ):
                raise CandidateWorkspaceError(
                    "candidate workspace directory identity is invalid"
                )
        if set(os.listdir(candidate_descriptor)) != {
            "control.json",
            "git",
            "worktree",
        }:
            raise CandidateWorkspaceError(
                "candidate control root has extra entries"
            )
        control_named = os.stat(
            "control.json",
            dir_fd=candidate_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(control_named.st_mode)
            or stat.S_IMODE(control_named.st_mode) != 0o600
            or control_named.st_nlink != 1
            or not 1 <= control_named.st_size <= 4_096
        ):
            raise CandidateWorkspaceError(
                "candidate control record is invalid"
            )
        control_descriptor = os.open(
            "control.json",
            os.O_RDONLY | nofollow,
            dir_fd=candidate_descriptor,
        )
        descriptors.append(control_descriptor)
        control_anchor = _candidate_read_anchor(
            control_descriptor,
            parent_descriptor=candidate_descriptor,
            name="control.json",
        )
        if control_anchor.token != _workspace_read_token(control_named):
            raise CandidateWorkspaceError(
                "candidate control record changed"
            )
        control_raw = _read_candidate_control_descriptor(
            control_descriptor,
            control_named.st_size,
        )
        control = _parse_candidate_control(control_raw, workspace)
        anchors.append(control_anchor)
        try:
            os.stat(".git", dir_fd=worktree_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise CandidateWorkspaceError(
                "candidate Git metadata entered worktree"
            )
        leaf_descriptor: int | None = None
        if path is not None:
            current_descriptor = worktree_descriptor
            segments = path.split("/")
            for segment in segments[:-1]:
                try:
                    child_descriptor = os.open(
                        segment,
                        directory_flags,
                        dir_fd=current_descriptor,
                    )
                except OSError as error:
                    raise CandidateReadError("PATH_DENIED") from error
                descriptors.append(child_descriptor)
                try:
                    anchor = _candidate_read_anchor(
                        child_descriptor,
                        parent_descriptor=current_descriptor,
                        name=segment,
                    )
                except OSError as error:
                    raise CandidateWorkspaceError(
                        "candidate ancestor changed before checkpoint scan"
                    ) from error
                anchors.append(anchor)
                current_descriptor = child_descriptor
            leaf_name = segments[-1]
            try:
                leaf_named = os.stat(
                    leaf_name,
                    dir_fd=current_descriptor,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise CandidateReadError("PATH_DENIED") from error
            if (
                not stat.S_ISREG(leaf_named.st_mode)
                or leaf_named.st_nlink != 1
                or leaf_named.st_size > _MAX_MANIFEST_BYTES
            ):
                raise CandidateReadError("PATH_DENIED")
            try:
                leaf_descriptor = os.open(
                    leaf_name,
                    os.O_RDONLY | nofollow,
                    dir_fd=current_descriptor,
                )
            except OSError as error:
                raise CandidateWorkspaceError(
                    "candidate leaf cannot be opened for checkpoint scan"
                ) from error
            descriptors.append(leaf_descriptor)
            leaf_anchor = _candidate_read_anchor(
                leaf_descriptor,
                parent_descriptor=current_descriptor,
                name=leaf_name,
            )
            if leaf_anchor.token != _workspace_read_token(leaf_named):
                raise CandidateWorkspaceError(
                    "candidate leaf changed before checkpoint scan"
                )
            anchors.append(leaf_anchor)
        if (
            control["worktree_inode"]
            != os.fstat(worktree_descriptor).st_ino
            or control["git_inode"] != os.fstat(git_descriptor).st_ino
        ):
            raise CandidateWorkspaceError(
                "candidate control identity mismatches"
            )
        git_authority_before = _scan_candidate_git_authority(git_descriptor)
        workspace_snapshot_before = _scan_candidate_workspace_identity(
            worktree_descriptor
        )
        manifest = scan_workspace_manifest(
            worktree_descriptor,
            workspace.head_commit,
        )
        workspace_snapshot_after = _scan_candidate_workspace_identity(
            worktree_descriptor
        )
        if (
            workspace_snapshot_before != workspace_snapshot_after
            or workspace_manifest_digest(manifest)
            != workspace.workspace_manifest_digest
        ):
            raise CandidateWorkspaceError("candidate manifest mismatches")
        git_authority_after = _scan_candidate_git_authority(git_descriptor)
        if git_authority_after != git_authority_before:
            raise CandidateWorkspaceError(
                "candidate Git authority changed during checkpoint"
            )
        checkpoint = _VerifiedCandidateReadCheckpoint(
            manifest=manifest,
            workspace_snapshot=workspace_snapshot_after,
            anchors=tuple(anchors),
            worktree_descriptor=worktree_descriptor,
            git_descriptor=git_descriptor,
            leaf_descriptor=leaf_descriptor,
            control_descriptor=control_descriptor,
            control_size_bytes=control_named.st_size,
            control_sha256=hashlib.sha256(control_raw).hexdigest(),
            git_authority_snapshot=git_authority_after,
        )
        if not _candidate_read_semantic_authority_matches(
            checkpoint,
            workspace,
        ):
            raise CandidateWorkspaceError(
                "candidate Git checkpoint mismatches"
            )
        ownership_transferred = True
        return checkpoint
    except CandidateReadError:
        raise
    except Exception as error:
        raise CandidateReadError("RECOVERY_REQUIRED") from error
    finally:
        if not ownership_transferred:
            _close_candidate_read_descriptors(descriptors)


def _candidate_read_anchor(
    descriptor: int,
    *,
    parent_descriptor: int | None,
    name: str | Path,
) -> _CandidateReadAnchor:
    anchor = _CandidateReadAnchor(
        descriptor=descriptor,
        token=_workspace_read_token(os.fstat(descriptor)),
        parent_descriptor=parent_descriptor,
        name=name,
    )
    if _candidate_read_named_token(anchor) != anchor.token:
        raise OSError("candidate read anchor binding changed")
    return anchor


def _candidate_read_named_token(anchor: _CandidateReadAnchor) -> str:
    if anchor.parent_descriptor is None:
        metadata = os.stat(anchor.name, follow_symlinks=False)
    else:
        metadata = os.stat(
            anchor.name,
            dir_fd=anchor.parent_descriptor,
            follow_symlinks=False,
        )
    return _workspace_read_token(metadata)


def _candidate_read_anchors_match(
    checkpoint: _VerifiedCandidateReadCheckpoint,
) -> bool:
    try:
        return all(
            _workspace_read_token(os.fstat(anchor.descriptor)) == anchor.token
            and _candidate_read_named_token(anchor) == anchor.token
            for anchor in checkpoint.anchors
        )
    except OSError:
        return False


def _read_candidate_control_descriptor(
    descriptor: int,
    size_bytes: int,
) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    return _read_workspace_file(descriptor, size_bytes)


def _scan_candidate_workspace_identity(
    worktree_descriptor: int,
) -> tuple[_WorkspaceIdentitySnapshotEntry, ...]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if (
        type(nofollow) is not int
        or nofollow <= 0
        or type(directory) is not int
        or directory <= 0
    ):
        raise CandidateWorkspaceError(
            "candidate workspace identity scan requires no-follow support"
        )
    try:
        root_metadata = os.fstat(worktree_descriptor)
    except OSError as error:
        raise CandidateWorkspaceError(
            "candidate workspace identity root is unavailable"
        ) from error
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise CandidateWorkspaceError(
            "candidate workspace identity root is not a directory"
        )
    root_token = _workspace_read_token(root_metadata)
    entries: list[_WorkspaceIdentitySnapshotEntry] = [
        _WorkspaceIdentitySnapshotEntry(
            path_bytes=b"",
            entry_type="directory",
            token=root_token,
        )
    ]
    entries_seen = 0
    directory_flags = os.O_RDONLY | directory | nofollow

    def scan(
        directory_descriptor: int,
        prefix: bytes,
        depth: int,
    ) -> None:
        nonlocal entries_seen
        if depth > _MAX_WORKSPACE_IDENTITY_DEPTH:
            raise CandidateWorkspaceError(
                "candidate workspace identity exceeds depth limit"
            )
        try:
            iterator = os.scandir(directory_descriptor)
        except OSError as error:
            raise CandidateWorkspaceError(
                "candidate workspace identity directory cannot be listed"
            ) from error
        names: list[str] = []
        with iterator:
            for item in iterator:
                if (
                    len(names)
                    >= _MAX_WORKSPACE_MANIFEST_ENTRIES - entries_seen
                ):
                    raise CandidateWorkspaceError(
                        "candidate workspace identity exceeds entry limit"
                    )
                names.append(item.name)
        names.sort(key=os.fsencode)
        for name in names:
            if entries_seen >= _MAX_WORKSPACE_MANIFEST_ENTRIES:
                raise CandidateWorkspaceError(
                    "candidate workspace identity exceeds entry limit"
                )
            name_bytes = os.fsencode(name)
            path_bytes = prefix + name_bytes if prefix else name_bytes
            if len(path_bytes) > _MAX_WORKSPACE_IDENTITY_PATH_BYTES:
                raise CandidateWorkspaceError(
                    "candidate workspace identity path exceeds limit"
                )
            try:
                validate_canonical_relative_path(path_bytes.decode("ascii"))
            except (PathError, UnicodeDecodeError) as error:
                raise CandidateWorkspaceError(
                    "candidate workspace identity path is invalid"
                ) from error
            try:
                before = os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise CandidateWorkspaceError(
                    "candidate workspace identity entry cannot be inspected"
                ) from error
            token = _workspace_read_token(before)
            entries_seen += 1
            if stat.S_ISDIR(before.st_mode):
                try:
                    child_descriptor = os.open(
                        name,
                        directory_flags,
                        dir_fd=directory_descriptor,
                    )
                except OSError as error:
                    raise CandidateWorkspaceError(
                        "candidate workspace identity directory cannot be opened"
                    ) from error
                try:
                    if (
                        _workspace_read_token(os.fstat(child_descriptor))
                        != token
                    ):
                        raise CandidateWorkspaceError(
                            "candidate workspace identity directory changed"
                        )
                    entries.append(
                        _WorkspaceIdentitySnapshotEntry(
                            path_bytes=path_bytes,
                            entry_type="directory",
                            token=token,
                        )
                    )
                    scan(
                        child_descriptor,
                        path_bytes + b"/",
                        depth + 1,
                    )
                    named_after = os.stat(
                        name,
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                    if (
                        _workspace_read_token(os.fstat(child_descriptor))
                        != token
                        or _workspace_read_token(named_after) != token
                    ):
                        raise CandidateWorkspaceError(
                            "candidate workspace identity directory changed"
                        )
                except OSError as error:
                    raise CandidateWorkspaceError(
                        "candidate workspace identity directory changed"
                    ) from error
                finally:
                    _close_candidate_read_descriptors([child_descriptor])
                continue
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise CandidateWorkspaceError(
                    "candidate workspace identity entry type is unsupported"
                )
            try:
                file_descriptor = os.open(
                    name,
                    os.O_RDONLY | nofollow,
                    dir_fd=directory_descriptor,
                )
            except OSError as error:
                raise CandidateWorkspaceError(
                    "candidate workspace identity file cannot be opened"
                ) from error
            try:
                if _workspace_read_token(os.fstat(file_descriptor)) != token:
                    raise CandidateWorkspaceError(
                        "candidate workspace identity file changed"
                    )
                named_after = os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
                if (
                    _workspace_read_token(os.fstat(file_descriptor)) != token
                    or _workspace_read_token(named_after) != token
                ):
                    raise CandidateWorkspaceError(
                        "candidate workspace identity file changed"
                    )
            except OSError as error:
                raise CandidateWorkspaceError(
                    "candidate workspace identity file changed"
                ) from error
            finally:
                _close_candidate_read_descriptors([file_descriptor])
            entries.append(
                _WorkspaceIdentitySnapshotEntry(
                    path_bytes=path_bytes,
                    entry_type="regular",
                    token=token,
                )
            )

    scan(worktree_descriptor, b"", 0)
    try:
        root_after = os.fstat(worktree_descriptor)
    except OSError as error:
        raise CandidateWorkspaceError(
            "candidate workspace identity root changed during scan"
        ) from error
    if _workspace_read_token(root_after) != root_token:
        raise CandidateWorkspaceError(
            "candidate workspace identity root changed during scan"
        )
    return tuple(sorted(entries, key=lambda entry: entry.path_bytes))


def _scan_candidate_git_authority(
    git_descriptor: int,
) -> tuple[_GitAuthoritySnapshotEntry, ...]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if (
        type(nofollow) is not int
        or nofollow <= 0
        or type(directory) is not int
        or directory <= 0
    ):
        raise CandidateWorkspaceError(
            "candidate Git authority scan requires no-follow support"
        )
    root_metadata = os.fstat(git_descriptor)
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise CandidateWorkspaceError(
            "candidate Git authority root is not a directory"
        )
    root_token = _workspace_read_token(root_metadata)
    entries: list[_GitAuthoritySnapshotEntry] = [
        _GitAuthoritySnapshotEntry(
            path_bytes=b"",
            entry_type="directory",
            token=root_token,
            size_bytes=None,
            sha256=None,
        )
    ]
    entries_seen = 1
    total_bytes = 0
    directory_flags = os.O_RDONLY | directory | nofollow

    def scan(
        directory_descriptor: int,
        prefix: bytes,
        depth: int,
    ) -> None:
        nonlocal entries_seen, total_bytes
        if depth > _MAX_GIT_AUTHORITY_DEPTH:
            raise CandidateWorkspaceError(
                "candidate Git authority exceeds depth limit"
            )
        try:
            iterator = os.scandir(directory_descriptor)
        except OSError as error:
            raise CandidateWorkspaceError(
                "candidate Git authority directory cannot be scanned"
            ) from error
        with iterator:
            for item in iterator:
                if entries_seen >= _MAX_GIT_AUTHORITY_ENTRIES:
                    raise CandidateWorkspaceError(
                        "candidate Git authority exceeds entry limit"
                    )
                name = item.name
                name_bytes = os.fsencode(name)
                path_bytes = prefix + name_bytes if prefix else name_bytes
                if (
                    not name_bytes
                    or b"\0" in name_bytes
                    or len(path_bytes) > _MAX_GIT_AUTHORITY_PATH_BYTES
                ):
                    raise CandidateWorkspaceError(
                        "candidate Git authority path is invalid"
                    )
                if path_bytes in {
                    b"objects/info/alternates",
                    b"objects/info/http-alternates",
                }:
                    raise CandidateWorkspaceError(
                        "candidate Git authority cannot use alternates"
                    )
                try:
                    before = os.stat(
                        name,
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                except OSError as error:
                    raise CandidateWorkspaceError(
                        "candidate Git authority entry cannot be inspected"
                    ) from error
                token = _workspace_read_token(before)
                entries_seen += 1
                if stat.S_ISDIR(before.st_mode):
                    try:
                        child_descriptor = os.open(
                            name,
                            directory_flags,
                            dir_fd=directory_descriptor,
                        )
                    except OSError as error:
                        raise CandidateWorkspaceError(
                            "candidate Git authority directory cannot be opened"
                        ) from error
                    try:
                        if (
                            _workspace_read_token(os.fstat(child_descriptor))
                            != token
                        ):
                            raise CandidateWorkspaceError(
                                "candidate Git authority directory changed"
                            )
                        entries.append(
                            _GitAuthoritySnapshotEntry(
                                path_bytes=path_bytes,
                                entry_type="directory",
                                token=token,
                                size_bytes=None,
                                sha256=None,
                            )
                        )
                        scan(
                            child_descriptor,
                            path_bytes + b"/",
                            depth + 1,
                        )
                        named_after = os.stat(
                            name,
                            dir_fd=directory_descriptor,
                            follow_symlinks=False,
                        )
                        if (
                            _workspace_read_token(os.fstat(child_descriptor))
                            != token
                            or _workspace_read_token(named_after) != token
                        ):
                            raise CandidateWorkspaceError(
                                "candidate Git authority directory changed"
                            )
                    finally:
                        _close_candidate_read_descriptors([child_descriptor])
                    continue
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                    raise CandidateWorkspaceError(
                        "candidate Git authority entry type is unsupported"
                    )
                if (
                    before.st_size > _MAX_GIT_AUTHORITY_FILE_BYTES
                    or total_bytes + before.st_size
                    > _MAX_GIT_AUTHORITY_TOTAL_BYTES
                ):
                    raise CandidateWorkspaceError(
                        "candidate Git authority exceeds byte limit"
                    )
                try:
                    file_descriptor = os.open(
                        name,
                        os.O_RDONLY | nofollow,
                        dir_fd=directory_descriptor,
                    )
                except OSError as error:
                    raise CandidateWorkspaceError(
                        "candidate Git authority file cannot be opened"
                    ) from error
                try:
                    if (
                        _workspace_read_token(os.fstat(file_descriptor))
                        != token
                    ):
                        raise CandidateWorkspaceError(
                            "candidate Git authority file changed"
                        )
                    digest = hashlib.sha256()
                    remaining = before.st_size
                    while remaining:
                        chunk = os.read(
                            file_descriptor,
                            min(remaining, 65_536),
                        )
                        if not chunk:
                            raise CandidateWorkspaceError(
                                "candidate Git authority file was truncated"
                            )
                        digest.update(chunk)
                        remaining -= len(chunk)
                    if os.read(file_descriptor, 1):
                        raise CandidateWorkspaceError(
                            "candidate Git authority file grew during scan"
                        )
                    named_after = os.stat(
                        name,
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                    if (
                        _workspace_read_token(os.fstat(file_descriptor))
                        != token
                        or _workspace_read_token(named_after) != token
                    ):
                        raise CandidateWorkspaceError(
                            "candidate Git authority file changed"
                        )
                finally:
                    _close_candidate_read_descriptors([file_descriptor])
                total_bytes += before.st_size
                entries.append(
                    _GitAuthoritySnapshotEntry(
                        path_bytes=path_bytes,
                        entry_type="regular",
                        token=token,
                        size_bytes=before.st_size,
                        sha256=digest.hexdigest(),
                    )
                )

    scan(git_descriptor, b"", 0)
    if _workspace_read_token(os.fstat(git_descriptor)) != root_token:
        raise CandidateWorkspaceError(
            "candidate Git authority root changed during scan"
        )
    return tuple(sorted(entries, key=lambda entry: entry.path_bytes))


def _candidate_read_authority_matches(
    checkpoint: _VerifiedCandidateReadCheckpoint,
) -> bool:
    try:
        if not _candidate_read_anchors_match(checkpoint):
            return False
        control_raw = _read_candidate_control_descriptor(
            checkpoint.control_descriptor,
            checkpoint.control_size_bytes,
        )
        return (
            hashlib.sha256(control_raw).hexdigest()
            == checkpoint.control_sha256
            and _scan_candidate_git_authority(checkpoint.git_descriptor)
            == checkpoint.git_authority_snapshot
        )
    except (CandidateWorkspaceError, ManifestError, OSError):
        return False


def _candidate_read_semantic_authority_matches(
    checkpoint: _VerifiedCandidateReadCheckpoint,
    workspace: CandidateWorkspace,
) -> bool:
    if not _candidate_read_authority_matches(checkpoint):
        return False
    semantic_matches = False
    try:
        actual_head_result = _run_git_read_only(
            git_dir=workspace.git_dir,
            worktree=workspace.worktree,
            arguments=("rev-parse", "HEAD"),
        )
        commit_result = _run_git_read_only(
            git_dir=workspace.git_dir,
            worktree=workspace.worktree,
            arguments=("cat-file", "-e", "HEAD^{commit}"),
        )
        index_result = _run_git_read_only(
            git_dir=workspace.git_dir,
            worktree=workspace.worktree,
            arguments=(
                "diff-index",
                "--cached",
                "--quiet",
                "HEAD",
                "--",
            ),
        )
        semantic_matches = (
            actual_head_result.returncode == 0
            and actual_head_result.stdout.decode("ascii").strip()
            == workspace.head_commit
            and commit_result.returncode == 0
            and index_result.returncode == 0
        )
    except (CandidateWorkspaceError, OSError, UnicodeDecodeError):
        semantic_matches = False
    authority_matches_after = _candidate_read_authority_matches(checkpoint)
    return semantic_matches and authority_matches_after


def _close_candidate_read_checkpoint(
    checkpoint: _VerifiedCandidateReadCheckpoint,
) -> None:
    _close_candidate_read_descriptors(
        [anchor.descriptor for anchor in checkpoint.anchors]
    )


def _close_candidate_read_descriptors(descriptors: Sequence[int]) -> None:
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except OSError:
            pass


def _read_candidate_execution_snapshot_file(
    checkpoint: _VerifiedCandidateReadCheckpoint,
    entry: WorkspaceManifestEntry,
) -> SourceFile:
    if (
        not isinstance(entry, WorkspaceManifestEntry)
        or entry.type != "regular"
        or entry.posix_mode not in _ALLOWED_MODES
        or type(entry.size_bytes) is not int
        or not 0 <= entry.size_bytes <= _MAX_SOURCE_FILE_BYTES
        or type(entry.sha256) is not str
        or _DIGEST_PATTERN.fullmatch(entry.sha256) is None
    ):
        raise ManifestError("snapshot regular file binding is invalid")
    raw_path = _decode_unpadded_path(entry.path_bytes_b64url)
    try:
        path = raw_path.decode("ascii")
        validate_canonical_relative_path(path)
    except (PathError, UnicodeDecodeError) as error:
        raise ManifestError("snapshot path is not canonical") from error

    _candidate_execution_snapshot_file_hook(path)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if (
        type(nofollow) is not int
        or nofollow <= 0
        or type(directory) is not int
        or directory <= 0
    ):
        raise CandidateWorkspaceError(
            "candidate snapshot requires directory no-follow support"
        )
    descriptors: list[int] = []
    parent_descriptor = checkpoint.worktree_descriptor
    try:
        for segment in path.split("/")[:-1]:
            named = os.stat(
                segment,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if not stat.S_ISDIR(named.st_mode):
                raise CandidateWorkspaceError(
                    "candidate snapshot ancestor is not a directory"
                )
            token = _workspace_read_token(named)
            child_descriptor = os.open(
                segment,
                os.O_RDONLY | directory | nofollow,
                dir_fd=parent_descriptor,
            )
            descriptors.append(child_descriptor)
            if _workspace_read_token(os.fstat(child_descriptor)) != token:
                raise CandidateWorkspaceError(
                    "candidate snapshot ancestor changed before open"
                )
            parent_descriptor = child_descriptor

        leaf_name = path.split("/")[-1]
        named_before = os.stat(
            leaf_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        token_before = _workspace_read_token(named_before)
        if (
            not stat.S_ISREG(named_before.st_mode)
            or named_before.st_nlink != 1
            or f"{named_before.st_mode:06o}" != entry.posix_mode
            or named_before.st_size != entry.size_bytes
        ):
            raise CandidateWorkspaceError(
                "candidate snapshot regular file metadata mismatches"
            )
        file_descriptor = os.open(
            leaf_name,
            os.O_RDONLY | nofollow,
            dir_fd=parent_descriptor,
        )
        descriptors.append(file_descriptor)
        opened = os.fstat(file_descriptor)
        if _workspace_read_token(opened) != token_before:
            raise CandidateWorkspaceError(
                "candidate snapshot regular file changed before read"
            )
        content = _read_workspace_file(file_descriptor, entry.size_bytes)
        named_after = os.stat(
            leaf_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            _workspace_read_token(os.fstat(file_descriptor)) != token_before
            or _workspace_read_token(named_after) != token_before
            or not stat.S_ISREG(named_after.st_mode)
            or named_after.st_nlink != 1
            or f"{named_after.st_mode:06o}" != entry.posix_mode
            or named_after.st_size != entry.size_bytes
            or hashlib.sha256(content).hexdigest() != entry.sha256
        ):
            raise CandidateWorkspaceError(
                "candidate snapshot regular file changed during read"
            )
        return SourceFile(path, entry.posix_mode, content)
    finally:
        _close_candidate_read_descriptors(descriptors)


def _candidate_execution_snapshot_regular_entries(
    manifest: WorkspaceManifest,
) -> tuple[WorkspaceManifestEntry, ...]:
    _workspace_manifest_json(manifest)
    regular_entries: list[WorkspaceManifestEntry] = []
    total_size = 0
    for entry in manifest.entries:
        if entry.type != "regular":
            continue
        size = entry.size_bytes
        if (
            type(size) is not int
            or not 0 <= size <= _MAX_SOURCE_FILE_BYTES
            or size > _MAX_SOURCE_BYTES - total_size
        ):
            raise ManifestError("snapshot regular files exceed the byte limit")
        total_size += size
        regular_entries.append(entry)
    return tuple(regular_entries)


def _read_verified_candidate_path(
    checkpoint: _VerifiedCandidateReadCheckpoint,
    path: str,
) -> bytes:
    try:
        entries, _ = _canonical_manifest_entries(checkpoint.manifest)
        entry = entries.get(path)
    except (ManifestError, TypeError, ValueError) as error:
        raise CandidateReadError("PATH_DENIED") from error
    if (
        entry is None
        or entry.type != "regular"
        or type(entry.size_bytes) is not int
        or not 0 <= entry.size_bytes <= _MAX_MANIFEST_BYTES
        or type(entry.sha256) is not str
        or _DIGEST_PATTERN.fullmatch(entry.sha256) is None
    ):
        raise CandidateReadError("PATH_DENIED")
    try:
        if not _candidate_read_authority_matches(checkpoint):
            raise CandidateReadError("FILE_CHANGED")
        if type(checkpoint.leaf_descriptor) is not int:
            raise CandidateReadError("FILE_CHANGED")
        opened = os.fstat(checkpoint.leaf_descriptor)
        if (
            entry.posix_mode != f"{opened.st_mode:06o}"
            or entry.size_bytes != opened.st_size
        ):
            raise CandidateReadError("FILE_CHANGED")
        os.lseek(checkpoint.leaf_descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(
                checkpoint.leaf_descriptor,
                min(remaining, 65_536),
            )
            if not chunk:
                raise CandidateReadError("FILE_CHANGED")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(checkpoint.leaf_descriptor, 1):
            raise CandidateReadError("FILE_CHANGED")
        content = b"".join(chunks)
        if hashlib.sha256(content).hexdigest() != entry.sha256:
            raise CandidateReadError("FILE_CHANGED")
        workspace_snapshot_before = _scan_candidate_workspace_identity(
            checkpoint.worktree_descriptor
        )
        fresh_manifest = scan_workspace_manifest(
            checkpoint.worktree_descriptor,
            checkpoint.manifest.head_commit,
        )
        workspace_snapshot_after = _scan_candidate_workspace_identity(
            checkpoint.worktree_descriptor
        )
        if (
            workspace_snapshot_before != workspace_snapshot_after
            or workspace_snapshot_before != checkpoint.workspace_snapshot
            or workspace_manifest_digest(fresh_manifest)
            != workspace_manifest_digest(checkpoint.manifest)
        ):
            raise CandidateReadError("FILE_CHANGED")
        if not _candidate_read_authority_matches(checkpoint):
            raise CandidateReadError("FILE_CHANGED")
        return content
    except CandidateReadError:
        raise
    except (CandidateWorkspaceError, ManifestError, OSError) as error:
        raise CandidateReadError("FILE_CHANGED") from error


def _read_candidate_control(workspace: CandidateWorkspace) -> dict[str, Any]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if type(nofollow) is not int or nofollow <= 0:
        raise CandidateWorkspaceError("candidate control requires O_NOFOLLOW")
    control_path = workspace.candidate_root / "control.json"
    metadata = os.stat(control_path, follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or not 1 <= metadata.st_size <= 4_096
    ):
        raise CandidateWorkspaceError("candidate control record is invalid")
    descriptor = os.open(control_path, os.O_RDONLY | nofollow)
    try:
        opened = os.fstat(descriptor)
        if not os.path.samestat(metadata, opened):
            raise CandidateWorkspaceError("candidate control record changed")
        raw = _read_workspace_file(descriptor, metadata.st_size)
        if _workspace_read_token(os.fstat(descriptor)) != _workspace_read_token(
            opened
        ):
            raise CandidateWorkspaceError("candidate control record changed")
    finally:
        os.close(descriptor)
    return _parse_candidate_control(raw, workspace)


def _parse_candidate_control(
    raw: bytes,
    workspace: CandidateWorkspace,
) -> dict[str, Any]:
    try:
        value = json.loads(raw)
        if rfc8785.dumps(value) != raw:
            raise CandidateWorkspaceError(
                "candidate control record is not canonical"
            )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        rfc8785.CanonicalizationError,
    ) as error:
        raise CandidateWorkspaceError(
            "candidate control record cannot be parsed"
        ) from error
    if (
        type(value) is not dict
        or set(value)
        != {
            "schema_version",
            "workspace_id",
            "source_artifact_sha256",
            "head_commit",
            "workspace_manifest_digest",
            "worktree_inode",
            "git_inode",
        }
        or value["schema_version"]
        != "openworkproof-candidate-control/0.1"
        or value["workspace_id"] != workspace.workspace_id
        or value["source_artifact_sha256"]
        != workspace.source_artifact_sha256
        or value["head_commit"] != workspace.head_commit
        or value["workspace_manifest_digest"]
        != workspace.workspace_manifest_digest
        or type(value["worktree_inode"]) is not int
        or type(value["git_inode"]) is not int
    ):
        raise CandidateWorkspaceError("candidate control binding is invalid")
    return value


def _validate_candidate_layout(workspace: CandidateWorkspace) -> None:
    if (
        type(workspace) is not CandidateWorkspace
        or not workspace.runtime_root.is_absolute()
        or workspace.runtime_root
        != Path(os.path.abspath(workspace.runtime_root))
        or workspace.candidate_root
        != workspace.runtime_root / workspace.workspace_id
        or workspace.worktree != workspace.candidate_root / "worktree"
        or workspace.git_dir != workspace.candidate_root / "git"
        or _DIGEST_PATTERN.fullmatch(workspace.workspace_id) is None
        or _DIGEST_PATTERN.fullmatch(workspace.source_artifact_sha256) is None
        or _OID_PATTERN.fullmatch(workspace.head_commit) is None
        or _DIGEST_PATTERN.fullmatch(workspace.workspace_manifest_digest) is None
    ):
        raise CandidateWorkspaceError("candidate workspace layout is invalid")
    for path, expected_mode in (
        (workspace.runtime_root, 0o700),
        (workspace.candidate_root, 0o700),
        (workspace.worktree, 0o700),
        (workspace.git_dir, 0o700),
    ):
        metadata = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != expected_mode
            or metadata.st_uid != os.geteuid()
        ):
            raise CandidateWorkspaceError(
                "candidate workspace directory identity is invalid"
            )
    if set(os.listdir(workspace.candidate_root)) != {
        "control.json",
        "git",
        "worktree",
    }:
        raise CandidateWorkspaceError("candidate control root has extra entries")
    if os.path.lexists(workspace.worktree / ".git"):
        raise CandidateWorkspaceError("candidate Git metadata entered worktree")
    control = _read_candidate_control(workspace)
    bare_repository = _run_git_read_only(
        git_dir=workspace.git_dir,
        worktree=None,
        arguments=("rev-parse", "--is-bare-repository"),
    )
    if (
        control["worktree_inode"]
        != os.stat(workspace.worktree, follow_symlinks=False).st_ino
        or control["git_inode"]
        != os.stat(workspace.git_dir, follow_symlinks=False).st_ino
        or bare_repository.returncode != 0
        or bare_repository.stdout.strip() != b"true"
    ):
        raise CandidateWorkspaceError("candidate control identity mismatches")


def _candidate_manifest_digest(
    workspace: CandidateWorkspace,
    head_commit: str,
) -> str:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if (
        type(nofollow) is not int
        or nofollow <= 0
        or type(directory) is not int
        or directory <= 0
    ):
        raise CandidateWorkspaceError(
            "candidate scan requires directory no-follow support"
        )
    descriptor = os.open(
        workspace.worktree,
        os.O_RDONLY | directory | nofollow,
    )
    try:
        return workspace_manifest_digest(
            scan_workspace_manifest(descriptor, head_commit)
        )
    finally:
        os.close(descriptor)


def _verify_candidate_checkpoint(
    workspace: CandidateWorkspace,
    *,
    head_commit: str,
    manifest_digest: str,
) -> None:
    actual_head = _run_git(
        git_dir=workspace.git_dir,
        worktree=workspace.worktree,
        arguments=("rev-parse", "HEAD"),
    ).decode("ascii").strip()
    status = _run_git(
        git_dir=workspace.git_dir,
        worktree=workspace.worktree,
        arguments=(
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
        ),
    )
    index_tree = _run_git(
        git_dir=workspace.git_dir,
        worktree=workspace.worktree,
        arguments=("write-tree",),
    ).decode("ascii").strip()
    commit_tree = _run_git(
        git_dir=workspace.git_dir,
        worktree=workspace.worktree,
        arguments=("rev-parse", f"{head_commit}^{{tree}}"),
    ).decode("ascii").strip()
    if (
        actual_head != head_commit
        or status
        or index_tree != commit_tree
        or _candidate_manifest_digest(workspace, head_commit)
        != manifest_digest
    ):
        raise CandidateWorkspaceError(
            "candidate checkpoint does not match authority"
        )


def _candidate_files_from_git(
    workspace: CandidateWorkspace,
    head_commit: str,
) -> tuple[SourceFile, ...]:
    listing = _run_git(
        git_dir=workspace.git_dir,
        worktree=workspace.worktree,
        arguments=("ls-tree", "-rz", "--full-tree", head_commit),
    )
    if len(listing) > 131_072:
        raise CandidateWorkspaceError("candidate Git tree listing is too large")
    files: list[SourceFile] = []
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        try:
            metadata, path_bytes = entry.split(b"\t", 1)
            mode, object_type, object_id = metadata.split(b" ", 2)
            path = path_bytes.decode("ascii")
            mode_text = mode.decode("ascii")
            object_id_text = object_id.decode("ascii")
        except (UnicodeDecodeError, ValueError) as error:
            raise CandidateWorkspaceError(
                "candidate Git tree entry is invalid"
            ) from error
        if (
            object_type != b"blob"
            or mode_text not in _ALLOWED_MODES
            or _OID_PATTERN.fullmatch(object_id_text) is None
        ):
            raise CandidateWorkspaceError(
                "candidate Git tree entry is unsupported"
            )
        size_raw = _run_git(
            git_dir=workspace.git_dir,
            worktree=workspace.worktree,
            arguments=("cat-file", "-s", object_id_text),
        )
        try:
            size = int(size_raw.decode("ascii").strip())
        except (UnicodeDecodeError, ValueError) as error:
            raise CandidateWorkspaceError(
                "candidate Git blob size is invalid"
            ) from error
        if not 0 <= size <= _MAX_SOURCE_FILE_BYTES:
            raise CandidateWorkspaceError("candidate Git blob is too large")
        content = _run_git(
            git_dir=workspace.git_dir,
            worktree=workspace.worktree,
            arguments=("cat-file", "blob", object_id_text),
        )
        if len(content) != size or git_blob_oid(content) != object_id_text:
            raise CandidateWorkspaceError("candidate Git blob binding failed")
        files.append(SourceFile(path, mode_text, content))
    try:
        return _validated_candidate_files(files)
    except SourceArchiveError as error:
        raise CandidateWorkspaceError(
            "candidate Git file set is invalid"
        ) from error


def _materialize_candidate_changes(
    workspace: CandidateWorkspace,
    parent_files: Sequence[SourceFile],
    application: PatchApplication,
) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if type(nofollow) is not int or nofollow <= 0:
        raise CandidateWorkspaceError("candidate patch requires O_NOFOLLOW")
    parent_by_path = {item.path: item for item in parent_files}
    result_by_path = {item.path: item for item in application.files}
    for path in application.changed_paths:
        target = workspace.worktree / path
        before = parent_by_path.get(path)
        after = result_by_path.get(path)
        if after is None:
            if before is None:
                raise CandidateWorkspaceError(
                    "candidate patch deletion binding is invalid"
                )
            os.unlink(target)
            continue
        flags = os.O_WRONLY | nofollow
        if before is None:
            flags |= os.O_CREAT | os.O_EXCL
        else:
            flags |= os.O_TRUNC
        descriptor = os.open(target, flags, 0o600)
        try:
            view = memoryview(after.content)
            written = 0
            while written < len(view):
                count = os.write(descriptor, view[written:])
                if count <= 0:
                    raise CandidateWorkspaceError(
                        "candidate patch write made no progress"
                    )
                written += count
            os.fchmod(descriptor, 0o755 if after.mode == "100755" else 0o644)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def apply_patch_in_candidate_workspace(request: PatchRequest) -> PatchResult:
    """Apply one canonical patch and commit the verified candidate checkpoint."""

    if type(request) is not PatchRequest:
        raise CandidateWorkspaceError("candidate patch request is invalid")
    workspace = request.workspace
    _validate_candidate_layout(workspace)
    if (
        not isinstance(request.replay_profile, ReplayProfile)
        or request.replay_profile.source_artifact_sha256
        != workspace.source_artifact_sha256
    ):
        raise CandidateWorkspaceError("candidate replay profile is unbound")
    _verify_candidate_checkpoint(
        workspace,
        head_commit=request.parent_commit,
        manifest_digest=request.parent_manifest_digest,
    )
    patch = parse_patch_phase_a(
        request.patch_bytes,
        expected_patch_digest=request.expected_patch_digest,
        expected_patch_size_bytes=request.expected_patch_size_bytes,
        declared_target_paths=request.declared_target_paths,
    )
    parent_files = _candidate_files_from_git(workspace, request.parent_commit)
    application = apply_patch_phase_b(
        patch,
        parent_files,
        parent_commit=request.parent_commit,
        parent_manifest_digest=request.parent_manifest_digest,
        workspace_manifest_digest="0" * 64,
        occurred_at=request.occurred_at,
        replay_profile=request.replay_profile,
        replay_profile_digest=request.replay_profile_digest,
        observed_manifest_delta_paths=patch.derived_patch_paths,
    )
    try:
        _, expected_manifest_digest = _replay_workspace_manifest(
            application.files,
            application.candidate_commit,
        )
    except ReplayError as error:
        raise CandidateWorkspaceError(
            "candidate result manifest is invalid"
        ) from error
    evidence = PatchResultEvidence(
        schema_version="openworkproof-patch-result/0.1",
        parent_commit=request.parent_commit,
        parent_manifest_digest=request.parent_manifest_digest,
        candidate_commit=application.candidate_commit,
        workspace_manifest_digest=expected_manifest_digest,
        patch_digest=patch.patch_digest,
        patch_size_bytes=patch.patch_size_bytes,
        replay_profile_digest=request.replay_profile_digest,
    )

    try:
        _materialize_candidate_changes(workspace, parent_files, application)
        _run_git(
            git_dir=workspace.git_dir,
            worktree=workspace.worktree,
            arguments=("add", "--all", "--", *application.changed_paths),
        )
        actual_tree = _run_git(
            git_dir=workspace.git_dir,
            worktree=workspace.worktree,
            arguments=("write-tree",),
        ).decode("ascii").strip()
        if actual_tree != application.tree_oid:
            raise CandidateWorkspaceError("candidate patch tree mismatches")
        actual_commit = _run_git(
            git_dir=workspace.git_dir,
            worktree=workspace.worktree,
            arguments=("hash-object", "-t", "commit", "-w", "--stdin"),
            input_bytes=application.commit_raw,
        ).decode("ascii").strip()
        if actual_commit != application.candidate_commit:
            raise CandidateWorkspaceError("candidate patch commit mismatches")
        _run_git(
            git_dir=workspace.git_dir,
            worktree=workspace.worktree,
            arguments=(
                "update-ref",
                "HEAD",
                actual_commit,
                request.parent_commit,
            ),
        )
        _run_git(
            git_dir=workspace.git_dir,
            worktree=workspace.worktree,
            arguments=("reset", "--hard", actual_commit),
        )
        _verify_candidate_checkpoint(
            workspace,
            head_commit=actual_commit,
            manifest_digest=expected_manifest_digest,
        )
    except Exception as patch_error:
        try:
            _run_git(
                git_dir=workspace.git_dir,
                worktree=workspace.worktree,
                arguments=("reset", "--hard", request.parent_commit),
            )
            _run_git(
                git_dir=workspace.git_dir,
                worktree=workspace.worktree,
                arguments=("clean", "-ffdx"),
            )
            _verify_candidate_checkpoint(
                workspace,
                head_commit=request.parent_commit,
                manifest_digest=request.parent_manifest_digest,
            )
        except Exception as recovery_error:
            raise CandidateWorkspaceError("RECOVERY_REQUIRED") from recovery_error
        if isinstance(patch_error, CandidateWorkspaceError):
            raise patch_error
        raise CandidateWorkspaceError(
            "candidate patch application failed"
        ) from patch_error
    return PatchResult(
        parent_commit=request.parent_commit,
        parent_manifest_digest=request.parent_manifest_digest,
        candidate_commit=application.candidate_commit,
        workspace_manifest_digest=expected_manifest_digest,
        patch_digest=patch.patch_digest,
        patch_size_bytes=patch.patch_size_bytes,
        changed_paths=application.changed_paths,
        evidence=evidence,
    )


def rollback_candidate_workspace(request: RollbackRequest) -> RollbackResult:
    """Restore one frozen failure target to its exact parent checkpoint."""

    if type(request) is not RollbackRequest:
        raise CandidateWorkspaceError("rollback request is invalid")
    digest_values = (
        request.target_patch_receipt_id,
        request.target_patch_receipt_digest,
        request.failure_target_patch_receipt_id,
        request.failure_target_patch_receipt_digest,
        request.before_manifest_digest,
        request.parent_manifest_digest,
    )
    if (
        any(
            type(value) is not str or _DIGEST_PATTERN.fullmatch(value) is None
            for value in digest_values
        )
        or type(request.before_commit) is not str
        or _OID_PATTERN.fullmatch(request.before_commit) is None
        or type(request.parent_commit) is not str
        or _OID_PATTERN.fullmatch(request.parent_commit) is None
        or request.before_commit == request.parent_commit
        or request.target_patch_receipt_id
        != request.failure_target_patch_receipt_id
        or request.target_patch_receipt_digest
        != request.failure_target_patch_receipt_digest
    ):
        raise CandidateWorkspaceError("rollback target binding is invalid")
    workspace = request.workspace
    _validate_candidate_layout(workspace)
    _verify_candidate_checkpoint(
        workspace,
        head_commit=request.before_commit,
        manifest_digest=request.before_manifest_digest,
    )
    commit = _run_git(
        git_dir=workspace.git_dir,
        worktree=workspace.worktree,
        arguments=("cat-file", "-p", request.before_commit),
    )
    parent_lines = tuple(
        line.removeprefix(b"parent ")
        for line in commit.splitlines()
        if line.startswith(b"parent ")
    )
    if parent_lines != (request.parent_commit.encode("ascii"),):
        raise CandidateWorkspaceError("rollback parent binding is invalid")

    try:
        _run_git(
            git_dir=workspace.git_dir,
            worktree=workspace.worktree,
            arguments=("reset", "--hard", request.parent_commit),
        )
        _run_git(
            git_dir=workspace.git_dir,
            worktree=workspace.worktree,
            arguments=("clean", "-ffdx"),
        )
        _verify_candidate_checkpoint(
            workspace,
            head_commit=request.parent_commit,
            manifest_digest=request.parent_manifest_digest,
        )
    except CandidateWorkspaceError:
        try:
            _run_git(
                git_dir=workspace.git_dir,
                worktree=workspace.worktree,
                arguments=("reset", "--hard", request.before_commit),
            )
            _run_git(
                git_dir=workspace.git_dir,
                worktree=workspace.worktree,
                arguments=("clean", "-ffdx"),
            )
            _verify_candidate_checkpoint(
                workspace,
                head_commit=request.before_commit,
                manifest_digest=request.before_manifest_digest,
            )
        except CandidateWorkspaceError as recovery_error:
            raise CandidateWorkspaceError("RECOVERY_REQUIRED") from recovery_error
        return RollbackResult(
            execution_status="failed",
            before_commit=request.before_commit,
            after_commit=request.before_commit,
            after_manifest_digest=request.before_manifest_digest,
        )
    return RollbackResult(
        execution_status="succeeded",
        before_commit=request.before_commit,
        after_commit=request.parent_commit,
        after_manifest_digest=request.parent_manifest_digest,
    )


def _open_candidate_runtime_root(runtime_root: Path) -> int:
    if (
        not isinstance(runtime_root, Path)
        or not runtime_root.is_absolute()
        or runtime_root != Path(os.path.abspath(runtime_root))
    ):
        raise CandidateWorkspaceError("candidate runtime root is invalid")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if (
        type(nofollow) is not int
        or nofollow <= 0
        or type(directory) is not int
        or directory <= 0
    ):
        raise CandidateWorkspaceError(
            "candidate runtime requires directory no-follow support"
        )
    named = os.stat(runtime_root, follow_symlinks=False)
    if (
        not stat.S_ISDIR(named.st_mode)
        or stat.S_IMODE(named.st_mode) != 0o700
        or named.st_uid != os.geteuid()
    ):
        raise CandidateWorkspaceError(
            "candidate runtime root must be a private owned directory"
        )
    descriptor = os.open(runtime_root, os.O_RDONLY | directory | nofollow)
    if not os.path.samestat(named, os.fstat(descriptor)):
        os.close(descriptor)
        raise CandidateWorkspaceError("candidate runtime root changed")
    return descriptor


def _validate_runtime_child_name(child_name: str) -> None:
    if (
        type(child_name) is not str
        or _RUNTIME_CHILD_PATTERN.fullmatch(child_name) is None
    ):
        raise CandidateWorkspaceError("candidate runtime child name is invalid")


def _remove_runtime_child(runtime_root: Path, child_name: str) -> None:
    _validate_runtime_child_name(child_name)
    target = runtime_root / child_name
    if target.parent != runtime_root:
        raise CandidateWorkspaceError("candidate removal target is invalid")
    metadata = os.stat(target, follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
        raise CandidateWorkspaceError("candidate removal target is unsafe")
    shutil.rmtree(target)


def _rename_runtime_child(
    runtime_root: Path,
    source_name: str,
    target_name: str,
) -> None:
    _validate_runtime_child_name(source_name)
    _validate_runtime_child_name(target_name)
    descriptor = _open_candidate_runtime_root(runtime_root)
    try:
        os.rename(
            source_name,
            target_name,
            src_dir_fd=descriptor,
            dst_dir_fd=descriptor,
        )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _source_workspace_identity(
    runtime_root: Path,
    workspace_id: str,
    source: ParsedSourceArchive,
) -> CandidateWorkspace:
    try:
        _, manifest_digest = _replay_workspace_manifest(
            source.files,
            source.source_commit,
        )
    except ReplayError as error:
        raise CandidateWorkspaceError(
            "candidate source checkpoint is invalid"
        ) from error
    candidate_root = runtime_root / workspace_id
    return CandidateWorkspace(
        runtime_root=runtime_root,
        candidate_root=candidate_root,
        worktree=candidate_root / "worktree",
        git_dir=candidate_root / "git",
        workspace_id=workspace_id,
        source_artifact_sha256=source.artifact_sha256,
        head_commit=source.source_commit,
        workspace_manifest_digest=manifest_digest,
    )


def _replay_candidate_steps(
    workspace: CandidateWorkspace,
    work_order: WorkOrder,
    steps: tuple[ReplayPatchStep | ReplayTestStep | ReplayRollbackStep, ...],
) -> None:
    active_patch: tuple[PatchResult, str, str] | None = None
    for step in steps:
        if isinstance(step, ReplayPatchStep):
            result = apply_patch_in_candidate_workspace(
                PatchRequest(
                    workspace=workspace,
                    patch_bytes=step.patch_bytes,
                    expected_patch_digest=step.evidence.patch_digest,
                    expected_patch_size_bytes=step.evidence.patch_size_bytes,
                    declared_target_paths=step.target_paths,
                    parent_commit=step.evidence.parent_commit,
                    parent_manifest_digest=(
                        step.evidence.parent_manifest_digest
                    ),
                    occurred_at=step.occurred_at,
                    replay_profile=work_order.replay_profile,
                    replay_profile_digest=work_order.replay_profile_digest,
                )
            )
            if result.evidence != step.evidence:
                raise CandidateWorkspaceError(
                    "candidate replay patch evidence mismatches"
                )
            active_patch = (
                result,
                result.parent_commit,
                result.parent_manifest_digest,
            )
            continue
        if isinstance(step, ReplayTestStep):
            continue
        if not isinstance(step, ReplayRollbackStep) or active_patch is None:
            raise CandidateWorkspaceError("candidate replay step is invalid")
        patch_result, parent_commit, parent_manifest_digest = active_patch
        result = rollback_candidate_workspace(
            RollbackRequest(
                workspace=workspace,
                target_patch_receipt_id=step.target_patch_receipt_id,
                target_patch_receipt_digest=step.target_patch_receipt_digest,
                failure_target_patch_receipt_id=step.target_patch_receipt_id,
                failure_target_patch_receipt_digest=(
                    step.target_patch_receipt_digest
                ),
                before_commit=patch_result.candidate_commit,
                before_manifest_digest=(
                    patch_result.workspace_manifest_digest
                ),
                parent_commit=parent_commit,
                parent_manifest_digest=parent_manifest_digest,
            )
        )
        if (
            result.execution_status != "succeeded"
            or result.before_commit != step.before_commit
            or result.after_commit != step.after_commit
            or result.after_manifest_digest != step.after_manifest_digest
        ):
            raise CandidateWorkspaceError(
                "candidate replay rollback evidence mismatches"
            )
        active_patch = None


def rebuild_candidate_workspace(
    request: WorkspaceRebuildRequest,
) -> CandidateWorkspace:
    """Converge a candidate path to the checkpoint proven by replay steps."""

    if (
        type(request) is not WorkspaceRebuildRequest
        or _DIGEST_PATTERN.fullmatch(request.workspace_id) is None
    ):
        raise CandidateWorkspaceError("candidate rebuild request is invalid")
    try:
        steps = tuple(request.steps)
        expected = replay_workspace_sequence(
            source_bytes=request.source_bytes,
            work_order=request.work_order,
            trusted_helper_image_digest=request.trusted_helper_image_digest,
            steps=steps,
        )
        source = parse_source_archive(
            request.source_bytes,
            request.work_order,
            trusted_helper_image_digest=request.trusted_helper_image_digest,
        )
    except (ReplayError, SourceArchiveError, TypeError, ValueError) as error:
        raise CandidateWorkspaceError(
            "candidate rebuild authority is invalid"
        ) from error
    workspace = _source_workspace_identity(
        request.runtime_root,
        request.workspace_id,
        source,
    )
    runtime_descriptor = _open_candidate_runtime_root(request.runtime_root)
    os.close(runtime_descriptor)
    candidate_name = request.workspace_id
    backup_name = f"{request.workspace_id}.rebuild"
    candidate_exists = os.path.lexists(workspace.candidate_root)
    backup_path = request.runtime_root / backup_name
    backup_exists = os.path.lexists(backup_path)

    if backup_exists:
        if candidate_exists:
            try:
                _validate_candidate_layout(workspace)
                _verify_candidate_checkpoint(
                    workspace,
                    head_commit=expected.head_commit,
                    manifest_digest=expected.workspace_manifest_digest,
                )
            except CandidateWorkspaceError:
                _remove_runtime_child(request.runtime_root, candidate_name)
                _rename_runtime_child(
                    request.runtime_root,
                    backup_name,
                    candidate_name,
                )
                candidate_exists = True
            else:
                _remove_runtime_child(request.runtime_root, backup_name)
                return workspace
        else:
            _rename_runtime_child(
                request.runtime_root,
                backup_name,
                candidate_name,
            )
            candidate_exists = True

    if candidate_exists:
        try:
            _validate_candidate_layout(workspace)
            _verify_candidate_checkpoint(
                workspace,
                head_commit=expected.head_commit,
                manifest_digest=expected.workspace_manifest_digest,
            )
        except CandidateWorkspaceError:
            _rename_runtime_child(
                request.runtime_root,
                candidate_name,
                backup_name,
            )
        else:
            return workspace

    try:
        workspace = initialize_candidate_workspace(
            WorkspaceInitRequest(
                runtime_root=request.runtime_root,
                workspace_id=request.workspace_id,
                source=source,
            )
        )
        _replay_candidate_steps(workspace, request.work_order, steps)
        _verify_candidate_checkpoint(
            workspace,
            head_commit=expected.head_commit,
            manifest_digest=expected.workspace_manifest_digest,
        )
        if os.path.lexists(backup_path):
            _remove_runtime_child(request.runtime_root, backup_name)
        return workspace
    except Exception as rebuild_error:
        try:
            if os.path.lexists(workspace.candidate_root):
                _remove_runtime_child(request.runtime_root, candidate_name)
            if os.path.lexists(backup_path):
                _rename_runtime_child(
                    request.runtime_root,
                    backup_name,
                    candidate_name,
                )
        except Exception as recovery_error:
            raise CandidateWorkspaceError("RECOVERY_REQUIRED") from recovery_error
        if isinstance(rebuild_error, CandidateWorkspaceError):
            raise rebuild_error
        raise CandidateWorkspaceError("candidate rebuild failed") from rebuild_error


def destroy_candidate_workspace(
    request: WorkspaceDestroyRequest,
) -> WorkspaceDestroyResult:
    """Remove one exact terminal candidate without broad path deletion."""

    if (
        type(request) is not WorkspaceDestroyRequest
        or request.lifecycle_state
        not in {"terminal", "aborted", "retention_expired"}
    ):
        raise CandidateWorkspaceError("candidate destroy request is invalid")
    workspace = request.workspace
    _validate_candidate_layout(workspace)
    _verify_candidate_checkpoint(
        workspace,
        head_commit=request.expected_head_commit,
        manifest_digest=request.expected_manifest_digest,
    )
    tombstone_name = f"{workspace.workspace_id}.destroying"
    tombstone = workspace.runtime_root / tombstone_name
    if os.path.lexists(tombstone):
        raise CandidateWorkspaceError("RECOVERY_REQUIRED")
    _rename_runtime_child(
        workspace.runtime_root,
        workspace.workspace_id,
        tombstone_name,
    )
    try:
        _remove_runtime_child(workspace.runtime_root, tombstone_name)
    except Exception as error:
        raise CandidateWorkspaceError("RECOVERY_REQUIRED") from error
    return WorkspaceDestroyResult(
        workspace_id=workspace.workspace_id,
        destroyed=True,
    )


def _docker_volume_plan(
    docker_binary: str,
    *,
    name: str,
    size_mebibytes: int,
    mount_path: str,
    read_only: bool,
    ownership_token: str,
) -> DockerVolumePlan:
    return DockerVolumePlan(
        name=name,
        size_bytes=size_mebibytes * 1_024 * 1_024,
        mount_path=mount_path,
        read_only=read_only,
        create_argv=(
            docker_binary,
            "volume",
            "create",
            "--driver",
            "local",
            "--opt",
            "type=tmpfs",
            "--opt",
            "device=tmpfs",
            "--opt",
            f"o=size={size_mebibytes}m",
            "--label",
            f"{_DOCKER_OWNERSHIP_LABEL}={ownership_token}",
            name,
        ),
    )


def _valid_immutable_image_reference(image_reference: object) -> bool:
    if (
        type(image_reference) is not str
        or len(image_reference.encode("utf-8")) > 255
        or image_reference.count("@") != 1
    ):
        return False
    repository, digest = image_reference.split("@")
    if _IMAGE_DIGEST_PATTERN.fullmatch(digest) is None:
        return False
    components = repository.split("/")
    if len(components) < 2 or any(not component for component in components):
        return False
    registry = components[0]
    host = registry
    if ":" in registry:
        if registry.count(":") != 1:
            return False
        host, port_text = registry.rsplit(":", 1)
        if (
            not port_text.isdigit()
            or not 1 <= int(port_text) <= 65_535
        ):
            return False
    elif registry != "localhost" and "." not in registry:
        return False
    if (
        not host
        or len(host) > 253
        or _DOCKER_HOST_PATTERN.fullmatch(host) is None
        or any(len(label) > 63 for label in host.split("."))
    ):
        return False
    return all(
        len(component) <= 128
        and _DOCKER_REPOSITORY_COMPONENT_PATTERN.fullmatch(component)
        is not None
        for component in components[1:]
    )


def _canonical_observed_repo_digest(reference: object) -> str | None:
    if type(reference) is not str or reference.count("@") != 1:
        return None
    repository, digest = reference.split("@")
    components = repository.split("/")
    if not components or any(not component for component in components):
        return None
    first = components[0]
    if len(components) == 1:
        qualified = f"docker.io/library/{repository}@{digest}"
    elif first == "localhost" or "." in first or ":" in first:
        qualified = reference
    else:
        qualified = f"docker.io/{repository}@{digest}"
    if not _valid_immutable_image_reference(qualified):
        return None
    return qualified


def derive_docker_execution_plan(
    *,
    docker_binary: Path,
    image_reference: str,
    container_name: str,
    workspace_volume_name: str,
    output_volume_name: str,
    ownership_token: str,
    command: tuple[str, ...],
) -> DockerExecutionPlan:
    """Return a deterministic, disposable Docker containment plan."""

    if (
        not isinstance(docker_binary, Path)
        or not docker_binary.is_absolute()
        or docker_binary != Path(os.path.abspath(docker_binary))
        or "\0" in str(docker_binary)
    ):
        raise ValueError("Docker binary path is invalid")
    if not _valid_immutable_image_reference(image_reference):
        raise ValueError("Docker immutable image reference is invalid")
    identifiers = (
        container_name,
        workspace_volume_name,
        output_volume_name,
    )
    if (
        any(
            type(identifier) is not str
            or _DOCKER_IDENTIFIER_PATTERN.fullmatch(identifier) is None
            for identifier in identifiers
        )
        or len(set(identifiers)) != len(identifiers)
    ):
        raise ValueError("Docker identifiers must be valid and unique")
    if (
        type(ownership_token) is not str
        or _DIGEST_PATTERN.fullmatch(ownership_token) is None
    ):
        raise ValueError("Docker ownership token is invalid")
    if type(command) is not tuple or not 1 <= len(command) <= 16:
        raise ValueError("Docker command is invalid")
    for argument in command:
        if (
            type(argument) is not str
            or not argument
            or "\0" in argument
            or len(argument.encode("utf-8")) > 4_096
        ):
            raise ValueError("Docker command is invalid")

    docker = str(docker_binary)
    workspace = _docker_volume_plan(
        docker,
        name=workspace_volume_name,
        size_mebibytes=512,
        mount_path="/workspace",
        read_only=True,
        ownership_token=ownership_token,
    )
    output = _docker_volume_plan(
        docker,
        name=output_volume_name,
        size_mebibytes=64,
        mount_path="/output",
        read_only=False,
        ownership_token=ownership_token,
    )
    create_container_argv = (
        docker,
        "create",
        "--name",
        container_name,
        "--label",
        f"{_DOCKER_OWNERSHIP_LABEL}={ownership_token}",
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--user",
        "65532:65532",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "128",
        "--memory",
        "1g",
        "--cpus",
        "1",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=256m",
        "--workdir",
        "/workspace",
        "--mount",
        (
            f"type=volume,source={workspace.name},"
            "target=/workspace,readonly,volume-nocopy"
        ),
        "--mount",
        (
            f"type=volume,source={output.name},"
            "target=/output,volume-nocopy"
        ),
        image_reference,
        *command,
    )
    return DockerExecutionPlan(
        docker_binary=docker_binary,
        image_reference=image_reference,
        container_name=container_name,
        ownership_token=ownership_token,
        command=command,
        workspace_volume=workspace,
        output_volume=output,
        create_container_argv=create_container_argv,
        preflight_absent_argv=(
            (
                docker,
                "container",
                "ls",
                "--all",
                "--format",
                "{{.Names}}",
            ),
            (
                docker,
                "volume",
                "ls",
                "--format",
                "{{.Name}}",
            ),
        ),
    )


def _docker_plan_resource_names(
    plan: DockerExecutionPlan,
) -> tuple[str, str, str]:
    return (
        plan.container_name,
        plan.workspace_volume.name,
        plan.output_volume.name,
    )


def _valid_docker_lifecycle_state(
    plan: DockerExecutionPlan,
    state: DockerLifecycleState,
) -> bool:
    return (
        type(plan) is DockerExecutionPlan
        and type(state) is DockerLifecycleState
        and state.ownership_token == plan.ownership_token
        and state.resource_names == _docker_plan_resource_names(plan)
        and type(state.created_resources) is tuple
        and state.created_resources
        == _DOCKER_CREATION_ORDER[: len(state.created_resources)]
    )


def validate_docker_preflight_absent(
    plan: DockerExecutionPlan,
    observation: DockerPreflightObservation,
) -> DockerLifecycleState:
    """Start lifecycle state only after all caller names are absent."""

    if type(plan) is not DockerExecutionPlan or type(
        observation
    ) is not DockerPreflightObservation:
        raise ValueError("Docker preflight observation is invalid")
    name_groups = (
        observation.container_names,
        observation.volume_names,
    )
    if any(
        type(group) is not tuple
        or any(type(name) is not str for name in group)
        for group in name_groups
    ):
        raise ValueError("Docker preflight observation is invalid")
    if plan.container_name in observation.container_names or any(
        volume_name in observation.volume_names
        for volume_name in (
            plan.workspace_volume.name,
            plan.output_volume.name,
        )
    ):
        raise ValueError("Docker resource already exists")
    return DockerLifecycleState(
        ownership_token=plan.ownership_token,
        resource_names=_docker_plan_resource_names(plan),
        created_resources=(),
    )


def mark_docker_resource_created(
    plan: DockerExecutionPlan,
    state: DockerLifecycleState,
    resource: Literal["container", "workspace_volume", "output_volume"],
) -> DockerLifecycleState:
    """Record one successful create command after an absent preflight."""

    if not _valid_docker_lifecycle_state(plan, state):
        raise ValueError("Docker lifecycle transition is invalid")
    if (
        len(state.created_resources) >= len(_DOCKER_CREATION_ORDER)
        or resource != _DOCKER_CREATION_ORDER[len(state.created_resources)]
    ):
        raise ValueError("Docker resource creation order is invalid")
    return DockerLifecycleState(
        ownership_token=state.ownership_token,
        resource_names=state.resource_names,
        created_resources=(*state.created_resources, resource),
    )


def _docker_resource_is_owned(
    plan: DockerExecutionPlan,
    resource: str,
    inspection: object,
) -> bool:
    if type(inspection) is not dict:
        return False
    if resource == "container":
        config = inspection.get("Config")
        return (
            inspection.get("Name") == f"/{plan.container_name}"
            and type(config) is dict
            and type(config.get("Labels")) is dict
            and config["Labels"].get(_DOCKER_OWNERSHIP_LABEL)
            == plan.ownership_token
        )
    if resource == "workspace_volume":
        expected_name = plan.workspace_volume.name
    elif resource == "output_volume":
        expected_name = plan.output_volume.name
    else:
        return False
    labels = inspection.get("Labels")
    return (
        inspection.get("Name") == expected_name
        and type(labels) is dict
        and labels.get(_DOCKER_OWNERSHIP_LABEL) == plan.ownership_token
    )


def derive_docker_cleanup_plan(
    plan: DockerExecutionPlan,
    state: DockerLifecycleState,
    current_inspections: Mapping[str, Mapping[str, Any]],
) -> DockerCleanupPlan:
    """Remove only resources created in-state and still bearing its label."""

    if (
        not _valid_docker_lifecycle_state(plan, state)
        or type(current_inspections) is not dict
    ):
        raise ValueError("Docker cleanup state is invalid")
    docker = str(plan.docker_binary)
    commands: list[tuple[str, ...]] = []
    retained: list[str] = []
    for resource in _DOCKER_CLEANUP_ORDER:
        if resource not in state.created_resources:
            continue
        inspection = current_inspections.get(resource)
        if not _docker_resource_is_owned(plan, resource, inspection):
            retained.append(resource)
            continue
        if resource == "container":
            commands.append(
                (
                    docker,
                    "rm",
                    "--force",
                    "--volumes",
                    plan.container_name,
                )
            )
        elif resource == "workspace_volume":
            commands.append(
                (docker, "volume", "rm", plan.workspace_volume.name)
            )
        else:
            commands.append(
                (docker, "volume", "rm", plan.output_volume.name)
            )
    return DockerCleanupPlan(
        commands=tuple(commands),
        retained_resources=tuple(retained),
    )


def _valid_docker_volume_inspection(
    plan: DockerExecutionPlan,
    inspection: object,
    *,
    resource: Literal["workspace_volume", "output_volume"],
) -> bool:
    size = "512m" if resource == "workspace_volume" else "64m"
    return (
        _docker_resource_is_owned(plan, resource, inspection)
        and inspection.get("Driver") == "local"
        and inspection.get("Options")
        == {"type": "tmpfs", "device": "tmpfs", "o": f"size={size}"}
    )


def validate_docker_execution_inspections(
    plan: DockerExecutionPlan,
    container_inspection: Mapping[str, Any],
    workspace_volume_inspection: Mapping[str, Any],
    output_volume_inspection: Mapping[str, Any],
) -> None:
    """Fail closed unless runtime inspect matches the frozen profile."""

    try:
        config = container_inspection["Config"]
        host = container_inspection["HostConfig"]
        mounts = container_inspection["Mounts"]
        configured_mounts = host["Mounts"]
        by_destination = {mount["Destination"]: mount for mount in mounts}
        by_target = {mount["Target"]: mount for mount in configured_mounts}
        workspace_mount = by_destination["/workspace"]
        output_mount = by_destination["/output"]
        configured_workspace = by_target["/workspace"]
        configured_output = by_target["/output"]
        valid = (
            type(plan) is DockerExecutionPlan
            and _docker_resource_is_owned(
                plan,
                "container",
                container_inspection,
            )
            and config.get("Image") == plan.image_reference
            and config.get("User") == "65532:65532"
            and config.get("Volumes") in (None, {})
            and host.get("NetworkMode") == "none"
            and host.get("ReadonlyRootfs") is True
            and host.get("CapDrop") == ["ALL"]
            and host.get("SecurityOpt")
            in (["no-new-privileges"], ["no-new-privileges:true"])
            and host.get("PidsLimit") == 128
            and host.get("Memory") == 1_024 * 1_024 * 1_024
            and host.get("NanoCpus") == 1_000_000_000
            and host.get("Tmpfs")
            == {"/tmp": "rw,noexec,nosuid,size=256m"}
            and len(mounts) == 2
            and set(by_destination) == {"/workspace", "/output"}
            and len(configured_mounts) == 2
            and set(by_target) == {"/workspace", "/output"}
            and workspace_mount.get("Type") == "volume"
            and workspace_mount.get("Name") == plan.workspace_volume.name
            and workspace_mount.get("RW") is False
            and output_mount.get("Type") == "volume"
            and output_mount.get("Name") == plan.output_volume.name
            and output_mount.get("RW") is True
            and configured_workspace.get("Type") == "volume"
            and configured_workspace.get("Source")
            == plan.workspace_volume.name
            and configured_workspace.get("ReadOnly") is True
            and configured_workspace.get("VolumeOptions", {}).get("NoCopy")
            is True
            and configured_output.get("Type") == "volume"
            and configured_output.get("Source") == plan.output_volume.name
            and (
                "ReadOnly" not in configured_output
                or configured_output.get("ReadOnly") is False
            )
            and configured_output.get("VolumeOptions", {}).get("NoCopy")
            is True
            and _valid_docker_volume_inspection(
                plan,
                workspace_volume_inspection,
                resource="workspace_volume",
            )
            and _valid_docker_volume_inspection(
                plan,
                output_volume_inspection,
                resource="output_volume",
            )
        )
    except (KeyError, TypeError, AttributeError):
        valid = False
    if not valid:
        raise ValueError("Docker inspection does not match the frozen profile")


def derive_ready_docker_start(
    plan: DockerExecutionPlan,
    lifecycle: DockerLifecycleState,
    image_inspection: Mapping[str, Any],
    container_inspection: Mapping[str, Any],
    workspace_volume_inspection: Mapping[str, Any],
    output_volume_inspection: Mapping[str, Any],
) -> DockerReadyStart:
    """Return start authority only for a fully inspected, never-started container."""

    if (
        not _valid_docker_lifecycle_state(plan, lifecycle)
        or lifecycle.created_resources != _DOCKER_CREATION_ORDER
    ):
        raise ValueError("Docker lifecycle is not complete")
    try:
        image_config = image_inspection["Config"]
        repo_digests = image_inspection["RepoDigests"]
        canonical_repo_digests = [
            _canonical_observed_repo_digest(reference)
            for reference in repo_digests
        ]
        image_valid = (
            type(image_inspection) is dict
            and type(image_config) is dict
            and image_config.get("Volumes") in (None, {})
            and type(repo_digests) is list
            and None not in canonical_repo_digests
            and plan.image_reference in canonical_repo_digests
        )
    except (KeyError, TypeError, AttributeError):
        image_valid = False
    if not image_valid:
        raise ValueError("Docker image inspection is invalid")

    validate_docker_execution_inspections(
        plan,
        container_inspection,
        workspace_volume_inspection,
        output_volume_inspection,
    )
    try:
        state = container_inspection["State"]
        ready = (
            type(state) is dict
            and state.get("Status") == "created"
            and state.get("Running") is False
            and state.get("Paused") is False
            and state.get("Restarting") is False
            and state.get("Dead") is False
            and state.get("Pid") == 0
            and state.get("ExitCode") == 0
            and state.get("StartedAt") == "0001-01-01T00:00:00Z"
            and state.get("FinishedAt") == "0001-01-01T00:00:00Z"
        )
    except (KeyError, TypeError, AttributeError):
        ready = False
    if not ready:
        raise ValueError("Docker container is not ready to start")
    return DockerReadyStart(
        ownership_token=plan.ownership_token,
        resource_names=_docker_plan_resource_names(plan),
        start_argv=(
            str(plan.docker_binary),
            "start",
            "--attach",
            plan.container_name,
        ),
    )


def classify_docker_execution_failure(
    observed: DockerObservedResult,
) -> Literal["OUTPUT_LIMIT", "TIMEOUT", "DISK_LIMIT"] | None:
    """Classify authoritative runtime observations without stderr parsing."""

    if (
        type(observed) is not DockerObservedResult
        or (
            observed.exit_code is not None
            and (
                type(observed.exit_code) is not int
                or not 0 <= observed.exit_code <= 255
            )
        )
        or any(
            type(value) is not bool
            for value in (
                observed.output_limit_exceeded,
                observed.timed_out,
                observed.workspace_volume_exhausted,
                observed.output_volume_exhausted,
            )
        )
    ):
        raise ValueError("Docker observed result is invalid")
    if observed.output_limit_exceeded:
        return "OUTPUT_LIMIT"
    if observed.timed_out:
        return "TIMEOUT"
    if observed.workspace_volume_exhausted or observed.output_volume_exhausted:
        return "DISK_LIMIT"
    return None


def _validated_process_request(
    request: ProcessRequest,
    policy: SandboxPolicy,
) -> tuple[tuple[str, ...], Path, dict[str, str]]:
    if (
        type(request) is not ProcessRequest
        or type(policy) is not SandboxPolicy
        or policy != SandboxPolicy()
    ):
        raise ProcessExecutionError("bounded process binding is invalid")
    argv = request.argv
    if type(argv) is not tuple or not 1 <= len(argv) <= 16:
        raise ProcessExecutionError("bounded process argv is invalid")
    for argument in argv:
        if (
            type(argument) is not str
            or not argument
            or "\0" in argument
            or len(argument.encode("utf-8")) > 4_096
        ):
            raise ProcessExecutionError("bounded process argument is invalid")
    executable = Path(argv[0])
    if (
        not executable.is_absolute()
        or not executable.is_file()
        or not os.access(executable, os.X_OK)
    ):
        raise ProcessExecutionError("bounded process executable is invalid")
    working_directory = request.working_directory
    if (
        not isinstance(working_directory, Path)
        or not working_directory.is_absolute()
        or working_directory != Path(os.path.abspath(working_directory))
    ):
        raise ProcessExecutionError(
            "bounded process working directory is invalid"
        )
    metadata = os.stat(working_directory, follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode):
        raise ProcessExecutionError(
            "bounded process working directory is not a directory"
        )
    environment = request.environment
    if type(environment) is not dict or len(environment) > 32:
        raise ProcessExecutionError("bounded process environment is invalid")
    validated_environment: dict[str, str] = {}
    total_environment_bytes = 0
    for key, value in environment.items():
        if (
            type(key) is not str
            or type(value) is not str
            or not key
            or "=" in key
            or "\0" in key
            or "\0" in value
        ):
            raise ProcessExecutionError(
                "bounded process environment entry is invalid"
            )
        total_environment_bytes += len(key.encode("utf-8"))
        total_environment_bytes += len(value.encode("utf-8"))
        if total_environment_bytes > 16_384:
            raise ProcessExecutionError(
                "bounded process environment is too large"
            )
        validated_environment[key] = value
    return argv, working_directory, validated_environment


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    cleanup_grace_seconds: int,
) -> None:
    deadline = time.monotonic() + cleanup_grace_seconds
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=min(1.0, max(0.0, deadline - time.monotonic())))
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    remaining = max(0.0, deadline - time.monotonic())
    try:
        process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as error:
        raise ProcessExecutionError(
            "bounded process cleanup exceeded its grace period"
        ) from error


def run_bounded_process(
    request: ProcessRequest,
    policy: SandboxPolicy,
) -> BoundedProcessResult:
    """Run one child with incremental shared-cap stdout/stderr capture."""

    argv, working_directory, environment = _validated_process_request(
        request,
        policy,
    )
    try:
        process = subprocess.Popen(
            argv,
            cwd=working_directory,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            start_new_session=True,
        )
    except OSError as error:
        raise ProcessExecutionError("bounded process could not start") from error
    if process.stdout is None or process.stderr is None:
        _terminate_process_group(process, policy.cleanup_grace_seconds)
        raise ProcessExecutionError("bounded process pipes are unavailable")

    selector = selectors.DefaultSelector()
    streams = {
        "stdout": process.stdout,
        "stderr": process.stderr,
    }
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    captured = 0
    failure_code: Literal["OUTPUT_LIMIT", "TIMEOUT", "DISK_LIMIT"] | None = None
    deadline = time.monotonic() + policy.wall_clock_timeout_seconds
    try:
        for name, stream in streams.items():
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map() or process.poll() is None:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                failure_code = "TIMEOUT"
                break
            try:
                events = selector.select(timeout=min(remaining_time, 0.1))
            except InterruptedError:
                continue
            for key, _ in events:
                remaining_bytes = policy.max_combined_stdio_bytes - captured
                read_size = min(65_536, remaining_bytes + 1)
                try:
                    data = os.read(key.fd, read_size)
                except BlockingIOError:
                    continue
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                retained = data[:remaining_bytes]
                if retained:
                    buffers[key.data].extend(retained)
                    captured += len(retained)
                if len(data) > remaining_bytes:
                    failure_code = "OUTPUT_LIMIT"
                    break
            if failure_code is not None:
                break
        if failure_code is not None:
            _terminate_process_group(process, policy.cleanup_grace_seconds)
        elif process.poll() is None:
            _terminate_process_group(process, policy.cleanup_grace_seconds)
            raise ProcessExecutionError("bounded process ended without a status")
    except ProcessExecutionError:
        raise
    except Exception as error:
        _terminate_process_group(process, policy.cleanup_grace_seconds)
        raise ProcessExecutionError("bounded process capture failed") from error
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return BoundedProcessResult(
        exit_code=process.returncode,
        failure_code=failure_code,
        stdout_prefix=bytes(buffers["stdout"]),
        stderr_prefix=bytes(buffers["stderr"]),
        combined_bytes_captured=captured,
    )


def _validated_purge_time(value: datetime, field_name: str) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != timezone.utc.utcoffset(value)
        or value.microsecond != 0
    ):
        raise EvidencePurgeError(
            f"{field_name} must be a UTC datetime at whole-second precision"
        )
    return value


def _open_private_evidence_root(evidence_root: Path) -> tuple[int, os.stat_result]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    if (
        type(nofollow) is not int
        or nofollow <= 0
        or type(directory) is not int
        or directory <= 0
    ):
        raise EvidencePurgeError(
            "evidence purge requires directory no-follow support"
        )
    if (
        not isinstance(evidence_root, Path)
        or not evidence_root.is_absolute()
        or evidence_root != Path(os.path.abspath(evidence_root))
    ):
        raise EvidencePurgeError("evidence root must be an absolute canonical path")
    try:
        named = os.stat(evidence_root, follow_symlinks=False)
        if (
            not stat.S_ISDIR(named.st_mode)
            or stat.S_IMODE(named.st_mode) != 0o700
            or named.st_uid != os.geteuid()
        ):
            raise EvidencePurgeError(
                "evidence root must be a private directory owned by this process"
            )
        descriptor = os.open(
            evidence_root,
            os.O_RDONLY | directory | nofollow | cloexec,
        )
    except EvidencePurgeError:
        raise
    except OSError as error:
        raise EvidencePurgeError("evidence root cannot be opened safely") from error
    try:
        opened = os.fstat(descriptor)
        if not os.path.samestat(named, opened):
            raise EvidencePurgeError("evidence root identity changed while opening")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, opened


def _purge_entry_count(
    directory_fd: int,
    *,
    root_device: int,
    depth: int,
    count: list[int],
) -> None:
    if depth > _MAX_PURGE_DEPTH:
        raise EvidencePurgeError("evidence tree exceeds the purge depth limit")
    nofollow = os.O_NOFOLLOW
    directory = os.O_DIRECTORY
    cloexec = getattr(os, "O_CLOEXEC", 0)
    try:
        names = sorted(os.listdir(directory_fd), key=os.fsencode)
        for name in names:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            count[0] += 1
            if count[0] > _MAX_PURGE_ENTRIES:
                raise EvidencePurgeError(
                    "evidence tree exceeds the purge entry limit"
                )
            if not stat.S_ISDIR(metadata.st_mode):
                continue
            if metadata.st_dev != root_device:
                raise EvidencePurgeError(
                    "evidence tree crosses a filesystem boundary"
                )
            child_fd = os.open(
                name,
                os.O_RDONLY | directory | nofollow | cloexec,
                dir_fd=directory_fd,
            )
            try:
                if not os.path.samestat(metadata, os.fstat(child_fd)):
                    raise EvidencePurgeError(
                        "evidence directory identity changed while scanning"
                    )
                _purge_entry_count(
                    child_fd,
                    root_device=root_device,
                    depth=depth + 1,
                    count=count,
                )
            finally:
                os.close(child_fd)
    except EvidencePurgeError:
        raise
    except OSError as error:
        raise EvidencePurgeError("evidence tree cannot be scanned safely") from error


def _purge_directory(directory_fd: int, *, root_device: int) -> int:
    nofollow = os.O_NOFOLLOW
    directory = os.O_DIRECTORY
    cloexec = getattr(os, "O_CLOEXEC", 0)
    removed = 0
    try:
        names = sorted(os.listdir(directory_fd), key=os.fsencode)
        for name in names:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                if metadata.st_dev != root_device:
                    raise EvidencePurgeError(
                        "evidence tree crosses a filesystem boundary"
                    )
                child_fd = os.open(
                    name,
                    os.O_RDONLY | directory | nofollow | cloexec,
                    dir_fd=directory_fd,
                )
                try:
                    if not os.path.samestat(metadata, os.fstat(child_fd)):
                        raise EvidencePurgeError(
                            "evidence directory identity changed while purging"
                        )
                    removed += _purge_directory(
                        child_fd,
                        root_device=root_device,
                    )
                finally:
                    os.close(child_fd)
                os.rmdir(name, dir_fd=directory_fd)
            else:
                os.unlink(name, dir_fd=directory_fd)
            removed += 1
        if names:
            os.fsync(directory_fd)
        return removed
    except EvidencePurgeError:
        raise
    except OSError as error:
        raise EvidencePurgeError("evidence tree cannot be purged safely") from error


def purge_expired_evidence(
    evidence_root: Path,
    retention_until: datetime,
    now: datetime,
) -> PurgeResult:
    """Delete an expired evidence root's descendants without following links."""

    retention = _validated_purge_time(retention_until, "retention_until")
    current_time = _validated_purge_time(now, "now")
    root_fd, root_metadata = _open_private_evidence_root(evidence_root)
    try:
        if current_time < retention:
            return PurgeResult(eligible=False, removed_entries=0)
        count = [0]
        _purge_entry_count(
            root_fd,
            root_device=root_metadata.st_dev,
            depth=0,
            count=count,
        )
        removed = _purge_directory(
            root_fd,
            root_device=root_metadata.st_dev,
        )
        if removed != count[0]:
            raise EvidencePurgeError("evidence tree changed while purging")
        try:
            named_root = os.stat(evidence_root, follow_symlinks=False)
        except OSError as error:
            raise EvidencePurgeError(
                "evidence root identity changed while purging"
            ) from error
        if (
            not os.path.samestat(root_metadata, os.fstat(root_fd))
            or not os.path.samestat(root_metadata, named_root)
        ):
            raise EvidencePurgeError("evidence root identity changed while purging")
        return PurgeResult(eligible=True, removed_entries=removed)
    finally:
        os.close(root_fd)


def _workspace_manifest_json(
    manifest: WorkspaceManifest,
) -> dict[str, Any]:
    if not isinstance(manifest, WorkspaceManifest):
        raise ManifestError("workspace manifest is invalid")
    if (
        type(manifest.schema_version) is not str
        or type(manifest.head_commit) is not str
        or type(manifest.entries) is not tuple
        or manifest.schema_version
        != "openworkproof-workspace-manifest/0.1"
        or _OID_PATTERN.fullmatch(manifest.head_commit) is None
        or len(manifest.entries) > _MAX_WORKSPACE_MANIFEST_ENTRIES
    ):
        raise ManifestError("workspace manifest header is invalid")
    entries: list[dict[str, Any]] = []
    previous: bytes | None = None
    for entry in manifest.entries:
        if not isinstance(entry, WorkspaceManifestEntry):
            raise ManifestError("workspace manifest entry is invalid")
        raw_path = _decode_unpadded_path(entry.path_bytes_b64url)
        segments = raw_path.split(b"/")
        if (
            not 1 <= len(raw_path) <= _MAX_MEMBER_PATH_BYTES
            or raw_path.startswith(b"/")
            or raw_path.endswith(b"/")
            or b"\0" in raw_path
            or any(segment in {b"", b".", b".."} for segment in segments)
        ):
            raise ManifestError("workspace manifest path is not canonical")
        if previous is not None and raw_path <= previous:
            raise ManifestError("workspace manifest entries are not raw-byte ordered")
        previous = raw_path
        if (
            type(entry.type) is not str
            or entry.type not in _WORKSPACE_TYPES
            or type(entry.posix_mode) is not str
            or len(entry.posix_mode) != 6
            or any(character not in "01234567" for character in entry.posix_mode)
        ):
            raise ManifestError("workspace manifest entry type or mode is invalid")
        mode = int(entry.posix_mode, 8)
        if not 0 <= mode <= 0o177777:
            raise ManifestError("workspace manifest POSIX mode is out of range")
        mode_type = mode & 0o170000
        expected_mode_type = {
            "directory": 0o040000,
            "regular": 0o100000,
            "symlink": 0o120000,
        }.get(entry.type)
        if (
            expected_mode_type is not None
            and mode_type != expected_mode_type
        ) or (
            entry.type == "other"
            and mode_type in {0o040000, 0o100000, 0o120000}
        ):
            raise ManifestError("workspace manifest entry mode mismatches type")
        size = entry.size_bytes
        if size is not None and (
            type(size) is not int
            or not 0 <= size <= _MAX_SAFE_INTEGER
        ):
            raise ManifestError("workspace manifest entry size is invalid")
        if entry.type == "directory":
            fields_valid = (
                size is None
                and entry.sha256 is None
                and entry.symlink_target_b64url is None
            )
        elif entry.type == "regular":
            fields_valid = (
                size is not None
                and type(entry.sha256) is str
                and _DIGEST_PATTERN.fullmatch(entry.sha256) is not None
                and entry.symlink_target_b64url is None
            )
        elif entry.type == "symlink":
            target = (
                _decode_unpadded_path(entry.symlink_target_b64url)
                if type(entry.symlink_target_b64url) is str
                else None
            )
            fields_valid = (
                size is not None
                and entry.sha256 is None
                and target is not None
                and len(target) == size
            )
        else:
            fields_valid = (
                size is not None
                and entry.sha256 is None
                and entry.symlink_target_b64url is None
            )
        if not fields_valid:
            raise ManifestError("workspace manifest entry fields are inconsistent")
        entries.append(
            {
                "path_bytes_b64url": entry.path_bytes_b64url,
                "type": entry.type,
                "posix_mode": entry.posix_mode,
                "size_bytes": entry.size_bytes,
                "sha256": entry.sha256,
                "symlink_target_b64url": entry.symlink_target_b64url,
            }
        )
    return {
        "schema_version": manifest.schema_version,
        "head_commit": manifest.head_commit,
        "entries": entries,
    }


def workspace_manifest_digest(manifest: WorkspaceManifest) -> str:
    """Return the domain-separated digest of a closed WorkspaceManifest."""

    try:
        encoded = rfc8785.dumps(
            {
                "domain": "openworkproof/workspace-manifest/v0.1",
                "manifest": _workspace_manifest_json(manifest),
            }
        )
    except ManifestError:
        raise
    except (TypeError, ValueError, OverflowError) as error:
        raise ManifestError("workspace manifest cannot be serialized") from error
    return hashlib.sha256(encoded).hexdigest()


def _canonical_manifest_entries(
    manifest: WorkspaceManifest,
) -> tuple[dict[str, WorkspaceManifestEntry], set[str]]:
    _workspace_manifest_json(manifest)
    by_path: dict[str, WorkspaceManifestEntry] = {}
    directories: set[str] = set()
    for entry in manifest.entries:
        raw_path = _decode_unpadded_path(entry.path_bytes_b64url)
        try:
            path = raw_path.decode("ascii")
        except UnicodeDecodeError as error:
            raise ManifestError(
                "workspace path is not canonical ASCII"
            ) from error
        try:
            validate_canonical_relative_path(path)
        except PathError as error:
            raise ManifestError("workspace path is not canonical") from error
        by_path[path] = entry
        if entry.type == "directory":
            directories.add(path)
    return by_path, directories


def derive_execution_snapshot_plan(
    manifest: WorkspaceManifest,
    files: Sequence[SourceFile],
) -> ExecutionSnapshotPlan:
    """Validate a manifest as canonical source and return a normalized plan."""

    try:
        validated_files = _validated_candidate_files(files)
    except SourceArchiveError as error:
        raise ManifestError(f"snapshot source is invalid: {error}") from error
    by_path, actual_directories = _canonical_manifest_entries(manifest)
    expected_files = {source_file.path: source_file for source_file in validated_files}
    expected_directories: set[str] = set()
    for path in expected_files:
        segments = path.split("/")
        expected_directories.update(
            "/".join(segments[:index])
            for index in range(1, len(segments))
        )

    for path, entry in by_path.items():
        if entry.type == "symlink":
            raise ManifestError("snapshot cannot contain a symlink")
        if entry.type == "other":
            raise ManifestError("snapshot cannot contain an other entry")
        if entry.type == "directory":
            if (
                entry.posix_mode != "040755"
                or entry.size_bytes is not None
                or entry.sha256 is not None
                or entry.symlink_target_b64url is not None
            ):
                raise ManifestError("snapshot directory mode or fields are invalid")
            continue
        if entry.type != "regular":
            raise ManifestError("snapshot entry type is invalid")
        source_file = expected_files.get(path)
        if (
            source_file is None
            or entry.posix_mode != source_file.mode
            or entry.posix_mode not in _ALLOWED_MODES
            or entry.size_bytes != len(source_file.content)
            or entry.sha256 != hashlib.sha256(source_file.content).hexdigest()
            or entry.symlink_target_b64url is not None
        ):
            raise ManifestError("snapshot regular file mode or binding is invalid")

    actual_regular = {
        path for path, entry in by_path.items() if entry.type == "regular"
    }
    if (
        actual_regular != set(expected_files)
        or actual_directories != expected_directories
    ):
        raise ManifestError("snapshot manifest does not match canonical source")
    return ExecutionSnapshotPlan(
        files=validated_files,
        read_only=True,
        owner_uid=65_532,
        owner_gid=65_532,
        atime_unix_seconds=0,
        mtime_unix_seconds=0,
        clear_extended_attributes=True,
        clear_posix_acls=True,
        clear_file_capabilities=True,
    )


def _resolution_manifest_json(
    manifest: ResolutionManifest,
) -> dict[str, Any]:
    if (
        not isinstance(manifest, ResolutionManifest)
        or type(manifest.schema_version) is not str
        or type(manifest.workspace_manifest_digest) is not str
        or type(manifest.requested_paths) is not tuple
        or type(manifest.resolved_entries) is not tuple
        or manifest.schema_version
        != "openworkproof-resolution-manifest/0.1"
        or _DIGEST_PATTERN.fullmatch(manifest.workspace_manifest_digest) is None
        or not manifest.requested_paths
        or len(manifest.requested_paths) > _MAX_PATCH_PATHS
        or len(manifest.resolved_entries) != len(manifest.requested_paths)
    ):
        raise ResolutionError("resolution manifest is invalid")
    try:
        canonical = tuple(
            validate_canonical_relative_path(path)
            for path in manifest.requested_paths
        )
    except PathError as error:
        raise ResolutionError("resolution manifest path is invalid") from error
    encoded = tuple(path.encode("ascii") for path in canonical)
    if (
        canonical != manifest.requested_paths
        or encoded != tuple(sorted(encoded))
        or len(canonical) != len(set(canonical))
    ):
        raise ResolutionError(
            "resolution manifest paths are not canonical, ordered, and unique"
        )
    entries: list[dict[str, str | None]] = []
    for requested, entry in zip(
        manifest.requested_paths,
        manifest.resolved_entries,
        strict=True,
    ):
        if (
            not isinstance(entry, ResolutionManifestEntry)
            or type(entry.requested_path) is not str
            or entry.requested_path != requested
        ):
            raise ResolutionError("resolution manifest vectors are not aligned")
        resolved = entry.resolved_relative_path
        if resolved is not None:
            try:
                resolved = validate_canonical_relative_path(resolved)
            except PathError as error:
                raise ResolutionError(
                    "resolution manifest resolved path is invalid"
                ) from error
            if resolved != requested:
                raise ResolutionError(
                    "resolution manifest resolved path changed request"
                )
        entries.append(
            {
                "requested_path": entry.requested_path,
                "resolved_relative_path": resolved,
            }
        )
    return {
        "schema_version": manifest.schema_version,
        "workspace_manifest_digest": manifest.workspace_manifest_digest,
        "requested_paths": list(manifest.requested_paths),
        "resolved_entries": entries,
    }


def build_resolution_manifest(
    workspace_manifest: WorkspaceManifest,
    requested_paths: Sequence[str],
    probes: Sequence[ResolutionProbe],
) -> ResolutionManifest:
    """Bind exact openat2 probe results to one immutable workspace manifest."""

    try:
        requested = tuple(requested_paths)
        probe_tuple = tuple(probes)
    except TypeError as error:
        raise ResolutionError("resolution vectors are invalid") from error
    if (
        not 1 <= len(requested) <= _MAX_PATCH_PATHS
        or len(probe_tuple) != len(requested)
    ):
        raise ResolutionError("resolution vectors are not aligned")
    try:
        canonical = tuple(
            validate_canonical_relative_path(path) for path in requested
        )
    except PathError as error:
        raise ResolutionError("resolution requested path is invalid") from error
    encoded = tuple(path.encode("ascii") for path in canonical)
    if encoded != tuple(sorted(encoded)):
        raise ResolutionError("resolution requested paths are not ordered")
    if len(canonical) != len(set(canonical)):
        raise ResolutionError("resolution requested paths are duplicated")

    by_path, directories = _canonical_manifest_entries(workspace_manifest)
    entries: list[ResolutionManifestEntry] = []
    for requested_path, probe in zip(canonical, probe_tuple, strict=True):
        if (
            not isinstance(probe, ResolutionProbe)
            or probe.requested_path != requested_path
        ):
            raise ResolutionError("resolution probe vectors are not aligned")
        if probe.openat2_flags != OPENAT2_RESOLVE_FLAGS:
            raise ResolutionError("resolution probe lacks the exact openat2 flags")
        resolved = probe.resolved_relative_path
        if resolved is not None:
            try:
                resolved = validate_canonical_relative_path(resolved)
            except PathError as error:
                raise ResolutionError("resolved path is invalid") from error
            if resolved != requested_path:
                raise ResolutionError("resolution changed the requested path")

        segments = requested_path.split("/")
        ancestors = [
            "/".join(segments[:index])
            for index in range(1, len(segments))
        ]
        unsafe_ancestor = any(
            ancestor in by_path and ancestor not in directories
            for ancestor in ancestors
        )
        existing = by_path.get(requested_path)
        if existing is not None and existing.type not in {"regular", "directory"}:
            unsafe_ancestor = True
        if existing is None:
            parent = requested_path.rpartition("/")[0]
            safe_parent = not parent or parent in directories
        else:
            safe_parent = True
        if resolved is not None and (unsafe_ancestor or not safe_parent):
            raise ResolutionError("symlink or unsafe parent resolution was claimed")
        entries.append(
            ResolutionManifestEntry(
                requested_path=requested_path,
                resolved_relative_path=resolved,
            )
        )

    manifest = ResolutionManifest(
        schema_version="openworkproof-resolution-manifest/0.1",
        workspace_manifest_digest=workspace_manifest_digest(workspace_manifest),
        requested_paths=canonical,
        resolved_entries=tuple(entries),
    )
    _resolution_manifest_json(manifest)
    return manifest


def resolution_manifest_digest(manifest: ResolutionManifest) -> str:
    """Return the domain-separated digest of a closed ResolutionManifest."""

    try:
        encoded = rfc8785.dumps(
            {
                "domain": "openworkproof/resolution-manifest/v0.1",
                "manifest": _resolution_manifest_json(manifest),
            }
        )
    except ResolutionError:
        raise
    except (TypeError, ValueError, OverflowError) as error:
        raise ResolutionError(
            "resolution manifest cannot be serialized"
        ) from error
    return hashlib.sha256(encoded).hexdigest()


def _validate_commit_raw(commit_raw: bytes, tree_oid: str) -> bool:
    if type(commit_raw) is not bytes:
        raise SourceArchiveError("commit.raw must be bytes")
    if not 1 <= len(commit_raw) <= _MAX_COMMIT_BYTES:
        raise SourceArchiveError("commit.raw exceeds 64 KiB")
    if b"\0" in commit_raw or b"\r" in commit_raw:
        raise SourceArchiveError("commit.raw contains forbidden bytes")
    lines = commit_raw.splitlines(keepends=True)
    expected_tree_line = f"tree {tree_oid}\n".encode("ascii")
    tree_lines = [line for line in lines if line.startswith(b"tree ")]
    if not lines or lines[0] != expected_tree_line or tree_lines != [
        expected_tree_line
    ]:
        raise SourceArchiveError("commit.raw tree line is not unique and first")
    for line in lines:
        if line.startswith(b"parent "):
            value = line.removeprefix(b"parent ").removesuffix(b"\n")
            try:
                parent = value.decode("ascii")
            except UnicodeDecodeError as error:
                raise SourceArchiveError("commit.raw parent is invalid") from error
            if _OID_PATTERN.fullmatch(parent) is None:
                raise SourceArchiveError("commit.raw parent is invalid")
    return any(line.startswith(b"parent ") for line in lines)


def _canonical_zip(members: Sequence[tuple[bytes, bytes]]) -> bytes:
    local_parts: list[bytes] = []
    central_parts: list[bytes] = []
    offset = 0
    for name, content in members:
        crc = zlib.crc32(content) & 0xFFFFFFFF
        local = struct.pack(
            "<IHHHHHIIIHH",
            _LOCAL_SIGNATURE,
            _VERSION_NEEDED,
            0,
            0,
            _DOS_TIME,
            _DOS_DATE,
            crc,
            len(content),
            len(content),
            len(name),
            0,
        ) + name
        local_parts.extend((local, content))
        central_parts.append(
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                _CENTRAL_SIGNATURE,
                _VERSION_MADE_BY,
                _VERSION_NEEDED,
                0,
                0,
                _DOS_TIME,
                _DOS_DATE,
                crc,
                len(content),
                len(content),
                len(name),
                0,
                0,
                0,
                0,
                _EXTERNAL_ATTRIBUTES,
                offset,
            )
            + name
        )
        offset += len(local) + len(content)
    local_bytes = b"".join(local_parts)
    central_bytes = b"".join(central_parts)
    count = len(members)
    return (
        local_bytes
        + central_bytes
        + struct.pack(
            "<IHHHHIIH",
            _EOCD_SIGNATURE,
            0,
            0,
            count,
            count,
            len(central_bytes),
            len(local_bytes),
            0,
        )
    )


def _source_manifest(
    files: Sequence[SourceFile],
    *,
    commit_raw: bytes,
    tree_oid: str,
) -> dict[str, Any]:
    return {
        "schema_version": "openworkproof-source-manifest/0.1",
        "source_commit": git_commit_oid(commit_raw),
        "tree_oid": tree_oid,
        "commit_path": "commit.raw",
        "entries": [
            {
                "path": source_file.path,
                "mode": source_file.mode,
                "size_bytes": len(source_file.content),
                "sha256": hashlib.sha256(source_file.content).hexdigest(),
                "blob_oid": git_blob_oid(source_file.content),
            }
            for source_file in files
        ],
    }


def write_source_archive(
    files: Sequence[SourceFile],
    commit_raw: bytes,
) -> bytes:
    """Write the exact in-memory v0.1 ``source/base.owpsrc`` bytes."""

    validated = _validated_files(files)
    tree_oid = git_tree_oid(validated)
    _validate_commit_raw(commit_raw, tree_oid)
    manifest_bytes = rfc8785.dumps(
        _source_manifest(
            validated,
            commit_raw=commit_raw,
            tree_oid=tree_oid,
        )
    )
    if len(manifest_bytes) > _MAX_MANIFEST_BYTES:
        raise SourceArchiveError("source manifest exceeds 64 KiB")
    members = tuple(
        sorted(
            (
                (b"commit.raw", commit_raw),
                *(
                    (
                        b"files/" + source_file.path.encode("ascii"),
                        source_file.content,
                    )
                    for source_file in validated
                ),
                (b"source-manifest.json", manifest_bytes),
            ),
            key=lambda item: item[0],
        )
    )
    if sum(len(content) for _, content in members) > _MAX_SOURCE_BYTES:
        raise SourceArchiveError("source archive exceeds 8 MiB uncompressed")
    raw = _canonical_zip(members)
    if len(raw) > _MAX_SOURCE_BYTES:
        raise SourceArchiveError("source artifact exceeds 8 MiB")
    return raw


def _unpack_from(
    format_string: str,
    raw: bytes,
    offset: int,
) -> tuple[Any, ...]:
    try:
        return struct.unpack_from(format_string, raw, offset)
    except struct.error as error:
        raise SourceArchiveError("source is not canonical ZIP") from error


def _parse_zip(raw: bytes) -> tuple[tuple[bytes, bytes], ...]:
    if type(raw) is not bytes:
        raise SourceArchiveError("source must be bounded raw bytes")
    if not 1 <= len(raw) <= _MAX_SOURCE_BYTES:
        raise SourceArchiveError("source artifact exceeds 8 MiB")

    members: list[tuple[bytes, bytes]] = []
    position = 0
    while raw[position : position + 4] == b"PK\x03\x04":
        (
            signature,
            _version,
            _flags,
            _method,
            _time,
            _date,
            _crc,
            compressed_size,
            _uncompressed_size,
            name_length,
            extra_length,
        ) = _unpack_from("<IHHHHHIIIHH", raw, position)
        if signature != _LOCAL_SIGNATURE:
            raise SourceArchiveError("source is not canonical ZIP")
        name_start = position + 30
        name_end = name_start + name_length
        content_start = name_end + extra_length
        content_end = content_start + compressed_size
        if (
            name_length == 0
            or name_length > _MAX_MEMBER_PATH_BYTES
            or content_end > len(raw)
        ):
            if name_length > _MAX_MEMBER_PATH_BYTES:
                raise SourceArchiveError(
                    "source path exceeds canonical ZIP member limit"
                )
            raise SourceArchiveError("source is not canonical ZIP")
        members.append((raw[name_start:name_end], raw[content_start:content_end]))
        if len(members) > _MAX_SOURCE_MEMBERS:
            raise SourceArchiveError("source archive exceeds 126 entries")
        position = content_end

    central_start = position
    central_names: list[bytes] = []
    while raw[position : position + 4] == b"PK\x01\x02":
        values = _unpack_from("<IHHHHHHIIIHHHHHII", raw, position)
        name_length = values[10]
        extra_length = values[11]
        comment_length = values[12]
        name_start = position + 46
        name_end = name_start + name_length
        position = name_end + extra_length + comment_length
        if (
            name_length == 0
            or name_length > _MAX_MEMBER_PATH_BYTES
            or position > len(raw)
        ):
            raise SourceArchiveError("source is not canonical ZIP")
        central_names.append(raw[name_start:name_end])
        if len(central_names) > _MAX_SOURCE_MEMBERS:
            raise SourceArchiveError("source archive exceeds 126 entries")

    eocd_offset = position
    eocd = _unpack_from("<IHHHHIIH", raw, eocd_offset)
    comment_length = eocd[7]
    if eocd_offset + 22 + comment_length != len(raw):
        raise SourceArchiveError("source is not canonical ZIP")
    if central_names != [name for name, _ in members]:
        raise SourceArchiveError("source is not canonical ZIP")
    if central_start != eocd[6]:
        raise SourceArchiveError("source is not canonical ZIP")
    if raw != _canonical_zip(members):
        raise SourceArchiveError("source is not canonical ZIP")
    return tuple(members)


def _canonical_manifest(raw: bytes) -> dict[str, Any]:
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise SourceArchiveError("source manifest exceeds 64 KiB")
    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SourceArchiveError("source manifest is invalid") from error
    if (
        type(manifest) is not dict
        or frozenset(manifest) != _MANIFEST_KEYS
        or rfc8785.dumps(manifest) != raw
    ):
        raise SourceArchiveError("source manifest is not canonical")
    return manifest


def _manifest_files(
    manifest: Mapping[str, Any],
    member_contents: Mapping[bytes, bytes],
) -> tuple[SourceFile, ...]:
    if (
        manifest["schema_version"] != "openworkproof-source-manifest/0.1"
        or manifest["commit_path"] != "commit.raw"
        or type(manifest["entries"]) is not list
    ):
        raise SourceArchiveError("source manifest header is invalid")
    entries = manifest["entries"]
    if len(entries) > _MAX_SOURCE_ENTRIES:
        raise SourceArchiveError("source manifest exceeds 126 entries")

    files: list[SourceFile] = []
    previous_path: bytes | None = None
    expected_members = {b"commit.raw", b"source-manifest.json"}
    for entry in entries:
        if type(entry) is not dict or frozenset(entry) != _ENTRY_KEYS:
            raise SourceArchiveError("source manifest entry is invalid")
        path = entry["path"]
        mode = entry["mode"]
        _validate_source_path(path)
        if mode not in _ALLOWED_MODES:
            raise SourceArchiveError("source manifest mode is invalid")
        encoded_path = path.encode("ascii")
        if previous_path is not None and encoded_path <= previous_path:
            raise SourceArchiveError("source manifest entries are not ordered")
        previous_path = encoded_path
        member_name = b"files/" + encoded_path
        expected_members.add(member_name)
        try:
            content = member_contents[member_name]
        except KeyError as error:
            raise SourceArchiveError(
                "source manifest member registry is incomplete"
            ) from error
        if type(entry["size_bytes"]) is not int or entry["size_bytes"] < 0:
            raise SourceArchiveError("source manifest size is invalid")
        if len(content) > _MAX_SOURCE_FILE_BYTES:
            raise SourceArchiveError("source file exceeds 1 MiB")
        if (
            entry["size_bytes"] != len(content)
            or type(entry["sha256"]) is not str
            or _DIGEST_PATTERN.fullmatch(entry["sha256"]) is None
            or entry["sha256"] != hashlib.sha256(content).hexdigest()
            or type(entry["blob_oid"]) is not str
            or _OID_PATTERN.fullmatch(entry["blob_oid"]) is None
            or entry["blob_oid"] != git_blob_oid(content)
        ):
            raise SourceArchiveError("source manifest file binding is invalid")
        files.append(SourceFile(path, mode, content))

    if set(member_contents) != expected_members:
        raise SourceArchiveError("source manifest member registry is not closed")
    validated = _validated_files(files)
    return validated


def _validate_manifest_and_commit(
    manifest: Mapping[str, Any],
    files: Sequence[SourceFile],
    commit_raw: bytes,
) -> tuple[str, str, bytes | None]:
    tree_oid = git_tree_oid(files)
    if (
        type(manifest["tree_oid"]) is not str
        or _OID_PATTERN.fullmatch(manifest["tree_oid"]) is None
        or manifest["tree_oid"] != tree_oid
    ):
        raise SourceArchiveError("source manifest tree binding is invalid")
    has_parent = _validate_commit_raw(commit_raw, tree_oid)
    source_commit = git_commit_oid(commit_raw)
    if (
        type(manifest["source_commit"]) is not str
        or _OID_PATTERN.fullmatch(manifest["source_commit"]) is None
        or manifest["source_commit"] != source_commit
    ):
        raise SourceArchiveError("source manifest commit binding is invalid")
    shallow = f"{source_commit}\n".encode("ascii") if has_parent else None
    return tree_oid, source_commit, shallow


def _profile_json(work_order: WorkOrder) -> dict[str, Any]:
    profile = work_order.replay_profile.model_dump(mode="json")
    if type(profile) is not dict:
        raise SourceArchiveError("source binding replay profile is invalid")
    return profile


def _validate_work_order_binding(
    raw: bytes,
    *,
    source_commit: str,
    work_order: WorkOrder,
    trusted_helper_image_digest: str,
) -> None:
    actual_digest = hashlib.sha256(raw).hexdigest()
    profile = _profile_json(work_order)
    replay_digest = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/replay-profile/v0.1",
                "profile": profile,
            }
        )
    ).hexdigest()
    artifact = work_order.source_artifact
    if (
        artifact.path != "source/base.owpsrc"
        or artifact.media_type
        != "application/vnd.openworkproof.source+zip"
        or artifact.sha256 != actual_digest
        or artifact.size_bytes != len(raw)
        or work_order.replay_profile.source_artifact_sha256 != actual_digest
        or work_order.replay_profile_digest != replay_digest
        or work_order.source_commit != source_commit
        or _IMAGE_DIGEST_PATTERN.fullmatch(trusted_helper_image_digest) is None
        or (
            work_order.replay_profile.trusted_helper_image_digest
            != trusted_helper_image_digest
        )
    ):
        raise SourceArchiveError("source binding mismatch")


def parse_source_archive(
    raw: bytes,
    work_order: WorkOrder,
    *,
    trusted_helper_image_digest: str,
) -> ParsedSourceArchive:
    """Validate an in-memory source artifact without filesystem extraction."""

    members = _parse_zip(raw)
    names = [name for name, _ in members]
    if names != sorted(names) or len(names) != len(set(names)):
        raise SourceArchiveError("source manifest member order is invalid")
    member_contents = dict(members)
    try:
        manifest_raw = member_contents[b"source-manifest.json"]
        commit_raw = member_contents[b"commit.raw"]
    except KeyError as error:
        raise SourceArchiveError(
            "source manifest member registry is incomplete"
        ) from error
    if sum(len(content) for content in member_contents.values()) > (
        _MAX_SOURCE_BYTES
    ):
        raise SourceArchiveError("source archive exceeds 8 MiB uncompressed")
    manifest = _canonical_manifest(manifest_raw)
    files = _manifest_files(manifest, member_contents)
    tree_oid, source_commit, shallow = _validate_manifest_and_commit(
        manifest,
        files,
        commit_raw,
    )
    _validate_work_order_binding(
        raw,
        source_commit=source_commit,
        work_order=work_order,
        trusted_helper_image_digest=trusted_helper_image_digest,
    )
    return ParsedSourceArchive(
        files=files,
        commit_raw=commit_raw,
        tree_oid=tree_oid,
        source_commit=source_commit,
        artifact_sha256=hashlib.sha256(raw).hexdigest(),
        artifact_size_bytes=len(raw),
        shallow_bytes=shallow,
    )


def _workspace_records_for_files(
    files: Sequence[SourceFile],
) -> tuple[WorkspaceScanRecord, ...]:
    try:
        validated = _validated_candidate_files(files)
    except SourceArchiveError as error:
        raise ReplayError(f"replay source files are invalid: {error}") from error
    directories: set[str] = set()
    for source_file in validated:
        segments = source_file.path.split("/")
        directories.update(
            "/".join(segments[:index])
            for index in range(1, len(segments))
        )
    records = [
        WorkspaceScanRecord(
            path_bytes=directory.encode("ascii"),
            entry_type="directory",
            posix_mode=0o040755,
            size_bytes=None,
            content=None,
            symlink_target=None,
            link_count=1,
            read_token_before="replay",
            read_token_after="replay",
        )
        for directory in directories
    ]
    records.extend(
        WorkspaceScanRecord(
            path_bytes=source_file.path.encode("ascii"),
            entry_type="regular",
            posix_mode=int(source_file.mode, 8),
            size_bytes=len(source_file.content),
            content=source_file.content,
            symlink_target=None,
            link_count=1,
            read_token_before="replay",
            read_token_after="replay",
        )
        for source_file in validated
    )
    return tuple(records)


def _replay_workspace_manifest(
    files: Sequence[SourceFile],
    head_commit: str,
) -> tuple[WorkspaceManifest, str]:
    try:
        manifest = build_workspace_manifest(
            head_commit,
            _workspace_records_for_files(files),
        )
        digest = workspace_manifest_digest(manifest)
        derive_execution_snapshot_plan(manifest, files)
    except (ManifestError, PathError) as error:
        raise ReplayError(f"replay workspace manifest is invalid: {error}") from error
    return manifest, digest


def _validate_replayed_test(
    evidence: TestResultEvidence,
    *,
    work_order: WorkOrder,
    head_commit: str,
    manifest_digest: str,
) -> None:
    if not isinstance(evidence, TestResultEvidence):
        raise ReplayError("replay test evidence is invalid")
    matching_profiles = tuple(
        profile
        for profile in work_order.test_profiles
        if (
            profile.test_mode == evidence.test_mode
            and profile.command_digest == evidence.command_digest
            and profile.container_image_digest
            == evidence.container_image_digest
            and profile.fixed_test_source_digest
            == evidence.fixed_test_source_digest
        )
    )
    if (
        len(matching_profiles) != 1
        or evidence.source_commit != work_order.source_commit
        or evidence.candidate_commit != head_commit
        or evidence.workspace_manifest_digest != manifest_digest
    ):
        raise ReplayError(
            "replay test evidence does not match its source checkpoint"
        )


def replay_workspace_sequence(
    *,
    source_bytes: bytes,
    work_order: WorkOrder,
    trusted_helper_image_digest: str,
    steps: Sequence[ReplayPatchStep | ReplayTestStep | ReplayRollbackStep],
) -> ReplayCheckpoint:
    """Rebuild a checkpoint from exact source bytes and committed replay steps."""

    try:
        source = parse_source_archive(
            source_bytes,
            work_order,
            trusted_helper_image_digest=trusted_helper_image_digest,
        )
    except (SourceArchiveError, ValueError, TypeError) as error:
        raise ReplayError(f"replay source artifact is invalid: {error}") from error
    files = source.files
    head_commit = source.source_commit
    manifest, manifest_digest = _replay_workspace_manifest(files, head_commit)
    verified_tests: list[TestResultEvidence] = []
    active_patch: tuple[
        ReplayPatchStep,
        tuple[SourceFile, ...],
        str,
        WorkspaceManifest,
        str,
    ] | None = None

    try:
        step_tuple = tuple(steps)
    except TypeError as error:
        raise ReplayError("replay sequence is invalid") from error
    for step in step_tuple:
        if isinstance(step, ReplayPatchStep):
            if active_patch is not None:
                raise ReplayError("replay patch requires a restored checkpoint")
            if not isinstance(step.evidence, PatchResultEvidence):
                raise ReplayError("replay patch evidence is invalid")
            evidence = step.evidence
            if (
                type(step.patch_receipt_id) is not str
                or _DIGEST_PATTERN.fullmatch(step.patch_receipt_id) is None
                or type(step.patch_receipt_digest) is not str
                or _DIGEST_PATTERN.fullmatch(step.patch_receipt_digest) is None
                or step.patch_receipt_digest == evidence.patch_digest
            ):
                raise ReplayError(
                    "replay patch receipt identity is invalid or uses a diff digest"
                )
            if (
                evidence.parent_commit != head_commit
                or evidence.parent_manifest_digest != manifest_digest
                or evidence.replay_profile_digest
                != work_order.replay_profile_digest
            ):
                raise ReplayError("replay patch parent binding is invalid")
            try:
                parsed = parse_patch_phase_a(
                    step.patch_bytes,
                    expected_patch_digest=evidence.patch_digest,
                    expected_patch_size_bytes=evidence.patch_size_bytes,
                    declared_target_paths=step.target_paths,
                )
                application = apply_patch_phase_b(
                    parsed,
                    files,
                    parent_commit=head_commit,
                    parent_manifest_digest=manifest_digest,
                    workspace_manifest_digest=evidence.workspace_manifest_digest,
                    occurred_at=step.occurred_at,
                    replay_profile=work_order.replay_profile,
                    replay_profile_digest=work_order.replay_profile_digest,
                    observed_manifest_delta_paths=step.target_paths,
                )
            except (PatchError, SourceArchiveError, ValueError) as error:
                raise ReplayError(f"replay patch failed: {error}") from error
            if (
                application.candidate_commit != evidence.candidate_commit
                or application.evidence != evidence
            ):
                raise ReplayError("replay patch candidate commit is inconsistent")
            next_manifest, next_digest = _replay_workspace_manifest(
                application.files,
                application.candidate_commit,
            )
            if next_digest != evidence.workspace_manifest_digest:
                raise ReplayError("replay patch workspace manifest is inconsistent")
            active_patch = (
                step,
                files,
                head_commit,
                manifest,
                manifest_digest,
            )
            files = application.files
            head_commit = application.candidate_commit
            manifest = next_manifest
            manifest_digest = next_digest
            continue

        if isinstance(step, ReplayTestStep):
            if active_patch is None:
                raise ReplayError("replay test has no active patch checkpoint")
            _validate_replayed_test(
                step.evidence,
                work_order=work_order,
                head_commit=head_commit,
                manifest_digest=manifest_digest,
            )
            verified_tests.append(step.evidence)
            continue

        if isinstance(step, ReplayRollbackStep):
            if active_patch is None:
                raise ReplayError("replay rollback has no active patch checkpoint")
            (
                patch_step,
                parent_files,
                parent_commit,
                parent_manifest,
                parent_manifest_digest,
            ) = active_patch
            if (
                step.target_patch_receipt_id
                != patch_step.patch_receipt_id
                or step.target_patch_receipt_digest
                != patch_step.patch_receipt_digest
                or step.before_commit != head_commit
                or step.after_commit != parent_commit
                or step.after_manifest_digest != parent_manifest_digest
            ):
                raise ReplayError(
                    "replay rollback does not match the recorded parent checkpoint"
                )
            files = parent_files
            head_commit = parent_commit
            manifest = parent_manifest
            manifest_digest = parent_manifest_digest
            active_patch = None
            continue

        raise ReplayError("replay sequence step type is unsupported")

    return ReplayCheckpoint(
        files=files,
        head_commit=head_commit,
        workspace_manifest=manifest,
        workspace_manifest_digest=manifest_digest,
        verified_test_results=tuple(verified_tests),
    )
