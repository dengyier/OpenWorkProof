"""Frozen case configuration and one-use authorization decisions for DSH."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import subprocess
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import rfc8785
from pydantic import model_validator

from openworkproof.dsh_protocol import (
    DshExecutionIdentityV01,
    canonical_bytes,
)
from openworkproof.models import (
    CanonicalRoot,
    Digest64,
    ObjectId40,
    ProtocolModel,
)


_CASE_ID_DOMAIN = "openworkproof/dsh-case-id/v0.1"
_CASE_STABLE_FIELDS = frozenset(
    {
        "schema_version",
        "work_order_digest",
        "source_revision",
        "allowed_path_roots",
        "denied_path_roots",
        "allowed_tools",
        "test_profile_digest",
        "mode",
    }
)
_HUMAN_ROLES = ("manager", "verifier", "acceptor")


class DshCaseError(ValueError):
    """The local case directory is unsafe or does not match its manifest."""


def _utf8_sorted_unique(values: tuple[str, ...]) -> bool:
    return list(values) == sorted(set(values), key=lambda item: item.encode("utf-8"))


def dsh_case_id(stable_manifest: Mapping[str, Any]) -> str:
    if not isinstance(stable_manifest, Mapping):
        raise ValueError("stable case manifest must be a mapping")
    if set(stable_manifest) != _CASE_STABLE_FIELDS:
        raise ValueError("stable case manifest fields are not exact")
    return hashlib.sha256(
        rfc8785.dumps(
            {"domain": _CASE_ID_DOMAIN, "payload": dict(stable_manifest)}
        )
    ).hexdigest()


class DshCaseManifestV01(ProtocolModel):
    schema_version: Literal["openworkproof-dsh-case/0.1"]
    case_id: Digest64
    work_order_digest: Digest64
    source_revision: ObjectId40
    repository_root: str
    allowed_path_roots: tuple[CanonicalRoot, ...]
    denied_path_roots: tuple[CanonicalRoot, ...]
    allowed_tools: tuple[
        Literal["owp_apply_patch", "owp_run_tests"], ...
    ]
    test_profile_digest: Digest64
    ledger_path: str
    evidence_root: str
    candidate_runtime_root: str
    verifier_socket_path: str | None = None
    sidecar_key_path: str
    developer_key_path: str
    mode: Literal["audit", "enforce"]

    @model_validator(mode="after")
    def _validate_manifest(self) -> DshCaseManifestV01:
        if not _utf8_sorted_unique(self.allowed_path_roots):
            raise ValueError("allowed path roots must be UTF-8 sorted and unique")
        if not _utf8_sorted_unique(self.denied_path_roots):
            raise ValueError("denied path roots must be UTF-8 sorted and unique")
        if not self.allowed_tools or not _utf8_sorted_unique(self.allowed_tools):
            raise ValueError("allowed tools must be UTF-8 sorted and unique")
        runtime_paths = (
            self.repository_root,
            self.ledger_path,
            self.evidence_root,
            self.candidate_runtime_root,
            self.sidecar_key_path,
            self.developer_key_path,
        )
        if any(not Path(value).is_absolute() for value in runtime_paths):
            raise ValueError("runtime paths must be absolute")
        if "owp_run_tests" in self.allowed_tools:
            if self.verifier_socket_path is None:
                raise ValueError(
                    "external Verifier transport is required for owp_run_tests"
                )
            if not Path(self.verifier_socket_path).is_absolute():
                raise ValueError("Verifier transport path must be absolute")
        stable = {
            "schema_version": self.schema_version,
            "work_order_digest": self.work_order_digest,
            "source_revision": self.source_revision,
            "allowed_path_roots": list(self.allowed_path_roots),
            "denied_path_roots": list(self.denied_path_roots),
            "allowed_tools": list(self.allowed_tools),
            "test_profile_digest": self.test_profile_digest,
            "mode": self.mode,
        }
        if self.case_id != dsh_case_id(stable):
            raise ValueError("case_id does not match stable public case fields")
        return self


def _contains_human_private_key_name(name: str) -> bool:
    lowered = name.casefold().replace("_", "-")
    return any(role in lowered for role in _HUMAN_ROLES) and any(
        marker in lowered for marker in ("private", "secret", "key")
    )


def _json_contains_human_private_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and _contains_human_private_key_name(key):
                return True
            if _json_contains_human_private_key(item):
                return True
    elif isinstance(value, list):
        return any(_json_contains_human_private_key(item) for item in value)
    return False


def _relative_runtime_path(case_root: Path, raw_path: str) -> Path:
    path = Path(raw_path)
    if ".." in path.parts:
        raise DshCaseError("runtime path is not canonical")
    try:
        return path.relative_to(case_root)
    except ValueError as error:
        raise DshCaseError("runtime path escapes the case parent") from error


def _reject_symlink_components(case_root: Path, relative_path: Path) -> None:
    current = case_root
    for part in relative_path.parts:
        current = current / part
        if current.is_symlink():
            raise DshCaseError("runtime path contains a symlink")


def _require_private_key_file(path: Path) -> None:
    try:
        info = path.stat()
    except OSError as error:
        raise DshCaseError("key file is unavailable") from error
    if not stat.S_ISREG(info.st_mode):
        raise DshCaseError("key path must be a regular file")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise DshCaseError("key file mode must be exactly 0600")


def _require_private_candidate_runtime(path: Path) -> None:
    try:
        info = path.stat()
    except OSError as error:
        raise DshCaseError("candidate runtime root is unavailable") from error
    if not stat.S_ISDIR(info.st_mode):
        raise DshCaseError("candidate runtime root must be a directory")
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise DshCaseError("candidate runtime root mode must be exactly 0700")
    if info.st_uid != os.geteuid():
        raise DshCaseError("candidate runtime root must be owned by this user")


def _paths_overlap(left: Path, right: Path) -> bool:
    return (
        left == right
        or left.is_relative_to(right)
        or right.is_relative_to(left)
    )


def _git_output(repository: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise DshCaseError("repository Git state is unavailable") from error
    return result.stdout.strip()


def load_dsh_case(case_directory: Path | str) -> DshCaseManifestV01:
    supplied = Path(case_directory)
    if supplied.is_symlink():
        raise DshCaseError("case directory must not be a symlink")
    try:
        case_root = supplied.resolve(strict=True)
    except OSError as error:
        raise DshCaseError("case directory is unavailable") from error
    if not case_root.is_dir():
        raise DshCaseError("case path must be a directory")

    for path in case_root.rglob("*"):
        if _contains_human_private_key_name(path.name):
            raise DshCaseError("human private key material is forbidden")

    manifest_path = case_root / "case.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise DshCaseError("case.json must be a regular non-symlink file")
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DshCaseError("case.json is not strict UTF-8 JSON") from error
    if _json_contains_human_private_key(raw):
        raise DshCaseError("human private key fields are forbidden")
    try:
        manifest = DshCaseManifestV01.model_validate(raw)
    except ValueError as error:
        raise DshCaseError(str(error)) from error

    runtime_values = (
        manifest.repository_root,
        manifest.ledger_path,
        manifest.evidence_root,
        manifest.candidate_runtime_root,
        manifest.sidecar_key_path,
        manifest.developer_key_path,
        *(
            ()
            if manifest.verifier_socket_path is None
            else (manifest.verifier_socket_path,)
        ),
    )
    relative_paths = tuple(
        _relative_runtime_path(case_root, value) for value in runtime_values
    )
    for relative in relative_paths:
        _reject_symlink_components(case_root, relative)

    repository = Path(manifest.repository_root)
    ledger = Path(manifest.ledger_path)
    evidence = Path(manifest.evidence_root)
    candidate_runtime = Path(manifest.candidate_runtime_root)
    if not repository.is_dir():
        raise DshCaseError("repository_root must be a directory")
    if not ledger.is_file():
        raise DshCaseError("ledger_path must be a regular file")
    if not evidence.is_dir():
        raise DshCaseError("evidence_root must be a directory")
    if _paths_overlap(candidate_runtime, repository):
        raise DshCaseError(
            "candidate runtime root must be outside repository_root"
        )
    protected_paths = (
        ledger,
        evidence,
        Path(manifest.sidecar_key_path),
        Path(manifest.developer_key_path),
        *(
            ()
            if manifest.verifier_socket_path is None
            else (Path(manifest.verifier_socket_path),)
        ),
    )
    if any(_paths_overlap(candidate_runtime, path) for path in protected_paths):
        raise DshCaseError(
            "candidate runtime root overlaps protected case paths"
        )
    _require_private_candidate_runtime(candidate_runtime)
    _require_private_key_file(Path(manifest.sidecar_key_path))
    _require_private_key_file(Path(manifest.developer_key_path))
    if Path(manifest.sidecar_key_path).samefile(manifest.developer_key_path):
        raise DshCaseError("Sidecar and Developer keys must be distinct files")

    key_paths = {
        Path(manifest.sidecar_key_path),
        Path(manifest.developer_key_path),
    }
    for key_path in key_paths:
        if key_path.is_relative_to(repository) or key_path.is_relative_to(evidence):
            raise DshCaseError("key files must be outside repository and evidence roots")
    for key_parent in {path.parent for path in key_paths}:
        if key_parent == case_root:
            continue
        allowed_key_names = {
            path.name for path in key_paths if path.parent == key_parent
        }
        unknown_keys = sorted(
            entry.name
            for entry in key_parent.iterdir()
            if entry.name not in allowed_key_names
        )
        if unknown_keys:
            raise DshCaseError(
                f"unknown case control entry: {unknown_keys[0]}"
            )

    allowed_top_level = {"case.json"}
    allowed_top_level.update(relative.parts[0] for relative in relative_paths)
    unknown = sorted(
        entry.name
        for entry in case_root.iterdir()
        if entry.name not in allowed_top_level
    )
    if unknown:
        raise DshCaseError(f"unknown case control entry: {unknown[0]}")

    if _git_output(repository, "rev-parse", "HEAD") != manifest.source_revision:
        raise DshCaseError("repository does not match the frozen source revision")
    if _git_output(repository, "status", "--porcelain=v1", "--untracked-files=all"):
        raise DshCaseError("repository source revision has uncommitted drift")
    return manifest


@dataclass(frozen=True, slots=True)
class DecisionToken:
    token: str
    execution_digest: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class _StoredDecision:
    execution_digest: str
    expires_at: datetime


class DecisionTokenStore:
    def __init__(self, *, clock: Callable[[], datetime]) -> None:
        self._clock = clock
        self._tokens: dict[str, _StoredDecision] = {}
        self._lock = threading.Lock()

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("decision-token clock must return an aware datetime")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _execution_digest(execution: DshExecutionIdentityV01) -> str:
        return hashlib.sha256(canonical_bytes(execution)).hexdigest()

    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(bytes.fromhex(token)).hexdigest()

    def issue(
        self,
        execution: DshExecutionIdentityV01,
        *,
        expires_at: datetime,
    ) -> DecisionToken:
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise ValueError("decision-token expiry must be timezone-aware")
        expiry = expires_at.astimezone(timezone.utc)
        if expiry <= self._now():
            raise ValueError("decision-token expiry must be in the future")
        plaintext = secrets.token_hex(32)
        execution_digest = self._execution_digest(execution)
        with self._lock:
            self._tokens[self._token_hash(plaintext)] = _StoredDecision(
                execution_digest=execution_digest,
                expires_at=expiry,
            )
        return DecisionToken(
            token=plaintext,
            execution_digest=execution_digest,
            expires_at=expiry,
        )

    def consume(
        self,
        token: DecisionToken | str,
        execution: DshExecutionIdentityV01,
    ) -> bool:
        plaintext = token.token if isinstance(token, DecisionToken) else token
        if (
            type(plaintext) is not str
            or len(plaintext) != 64
            or any(character not in "0123456789abcdef" for character in plaintext)
        ):
            return False
        token_hash = self._token_hash(plaintext)
        with self._lock:
            stored = self._tokens.pop(token_hash, None)
        if stored is None or self._now() >= stored.expires_at:
            return False
        return stored.execution_digest == self._execution_digest(execution)
