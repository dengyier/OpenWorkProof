"""Bounded, deterministic repository reference primitives."""

from __future__ import annotations

import base64
import calendar
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
from typing import Any, Literal, Mapping, Sequence
import zlib

import rfc8785

from openworkproof.models import (
    Artifact,
    EvidencePolicy,
    EvidenceRef,
    PatchResultEvidence,
    ReplayProfile,
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
_IMAGE_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
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
_WORKSPACE_TYPES = frozenset({"regular", "directory", "symlink", "other"})

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
    head_commit: str
    workspace_manifest_digest: str


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
            head_commit=commit_oid,
            workspace_manifest_digest=manifest_digest,
        )
    except CandidateWorkspaceError:
        raise
    except Exception as error:
        raise CandidateWorkspaceError("RECOVERY_REQUIRED") from error


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
            "head_commit",
            "workspace_manifest_digest",
            "worktree_inode",
            "git_inode",
        }
        or value["schema_version"]
        != "openworkproof-candidate-control/0.1"
        or value["workspace_id"] != workspace.workspace_id
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
        or workspace.candidate_root
        != workspace.runtime_root / workspace.workspace_id
        or workspace.worktree != workspace.candidate_root / "worktree"
        or workspace.git_dir != workspace.candidate_root / "git"
        or _DIGEST_PATTERN.fullmatch(workspace.workspace_id) is None
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
    if (
        control["worktree_inode"]
        != os.stat(workspace.worktree, follow_symlinks=False).st_ino
        or control["git_inode"]
        != os.stat(workspace.git_dir, follow_symlinks=False).st_ino
        or _run_git(
            git_dir=workspace.git_dir,
            worktree=None,
            arguments=("rev-parse", "--is-bare-repository"),
        ).strip()
        != b"true"
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
