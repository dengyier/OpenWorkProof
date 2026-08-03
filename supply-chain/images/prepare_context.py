#!/usr/bin/env python3
"""Assemble the two candidate image contexts from one Git revision."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile


IMAGE_PREFIX = "supply-chain/images"
EXECUTION_PREFIX = f"{IMAGE_PREFIX}/execution"
HELPER_PREFIX = f"{IMAGE_PREFIX}/trusted-helper"


class ContextError(RuntimeError):
    """A candidate context input is incomplete or inconsistent."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(repo: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ContextError(detail or "Git command failed")
    return result.stdout


def _resolve_revision(repo: Path, revision: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ContextError("source revision must be exactly 40 lowercase hexadecimal characters")
    try:
        resolved = _git(repo, "rev-parse", "--verify", f"{revision}^{{commit}}")
    except ContextError as error:
        raise ContextError(f"invalid source revision {revision}: {error}") from error
    resolved_text = resolved.decode("ascii").strip()
    if resolved_text != revision:
        raise ContextError(
            f"source revision resolved to a different commit: {resolved_text}"
        )
    return resolved_text


def _git_blob(repo: Path, revision: str, relative_path: str) -> bytes:
    try:
        return _git(repo, "show", f"{revision}:{relative_path}")
    except ContextError as error:
        raise ContextError(
            f"missing Git blob at source revision: {relative_path}: {error}"
        ) from error


def _parse_sums(data: bytes, label: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    names: set[str] = set()
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ContextError(f"invalid {label}: not UTF-8") from error
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/]+)", line)
        if not match:
            raise ContextError(f"invalid {label} line: {line!r}")
        digest, name = match.groups()
        if name in names or name in {".", "..", "SHA256SUMS"}:
            raise ContextError(f"invalid or duplicate {label} filename: {name}")
        names.add(name)
        rows.append((digest, name))
    if not rows:
        raise ContextError(f"empty {label}")
    return rows


def _verify_directory(directory: Path, label: str) -> list[tuple[str, str]]:
    sums_path = directory / "SHA256SUMS"
    if not sums_path.is_file():
        raise ContextError(f"missing {label}: {sums_path}")
    rows = _parse_sums(sums_path.read_bytes(), label)
    expected_names = {name for _, name in rows} | {"SHA256SUMS"}
    entries = list(directory.iterdir())
    invalid = sorted(
        path.name for path in entries if path.is_symlink() or not path.is_file()
    )
    if invalid:
        raise ContextError(
            f"{label} entries must be regular non-symlink files: {invalid}"
        )
    actual_names = {path.name for path in entries}
    if actual_names != expected_names:
        missing = sorted(expected_names - actual_names)
        extra = sorted(actual_names - expected_names)
        raise ContextError(f"{label} files differ; missing={missing}, extra={extra}")
    for expected, name in rows:
        actual = _sha256(directory / name)
        if actual != expected:
            raise ContextError(
                f"{label} digest mismatch for {name}: {actual} != {expected}"
            )
    return rows


def _required_hashes(lock_data: bytes, label: str) -> set[str]:
    hashes = set(re.findall(rb"--hash=sha256:([0-9a-f]{64})", lock_data))
    if not hashes:
        raise ContextError(f"no wheel hashes in {label}")
    return {digest.decode("ascii") for digest in hashes}


def _select_wheels(
    rows: list[tuple[str, str]], lock_data: bytes, label: str
) -> list[tuple[str, str]]:
    required = _required_hashes(lock_data, label)
    selected = [(digest, name) for digest, name in rows if digest in required]
    found = {digest for digest, _ in selected}
    missing = sorted(required - found)
    if missing:
        raise ContextError(f"missing wheels for {label}: {missing}")
    return selected


def _debian_rows(lock_data: bytes) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for line in lock_data.decode("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        columns = line.split("\t")
        if len(columns) != 5 or not re.fullmatch(r"[0-9a-f]{64}", columns[0]):
            raise ContextError(f"invalid Debian lock line: {line!r}")
        rows.append((columns[0], columns[1]))
    if not rows or len({name for _, name in rows}) != len(rows):
        raise ContextError("invalid or empty Debian lock closure")
    return rows


def _allowlisted_sources(data: bytes) -> list[str]:
    paths = data.decode("utf-8").splitlines()
    if not paths:
        raise ContextError("empty SOURCE_ALLOWLIST")
    basenames: set[str] = set()
    for source in paths:
        path = PurePosixPath(source)
        if (
            not source
            or path.as_posix() != source
            or path.is_absolute()
            or ".." in path.parts
            or path.name in basenames
        ):
            raise ContextError(f"unsafe or colliding SOURCE_ALLOWLIST path: {source}")
        if not source.startswith("src/openworkproof/") or path.suffix != ".py":
            raise ContextError(f"source outside helper package: {source}")
        basenames.add(path.name)
    return paths


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _copy_selected(
    source: Path,
    destination: Path,
    rows: list[tuple[str, str]],
    sums_data: bytes | None = None,
) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for _, name in rows:
        shutil.copyfile(source / name, destination / name)
    if sums_data is None:
        sums_data = "".join(
            f"{digest}  {name}\n" for digest, name in rows
        ).encode("utf-8")
    _write(destination / "SHA256SUMS", sums_data)


def assemble(
    repo: Path,
    revision: str,
    wheelhouse: Path,
    deb_closure: Path,
    output_root: Path,
) -> None:
    repo = repo.resolve()
    revision = _resolve_revision(repo, revision)
    if output_root.exists():
        raise ContextError(f"output root already exists: {output_root}")

    tracked_paths = {
        "execution_dockerfile": f"{EXECUTION_PREFIX}/Dockerfile",
        "execution_lock": f"{EXECUTION_PREFIX}/requirements.lock",
        "helper_dockerfile": f"{HELPER_PREFIX}/Dockerfile",
        "helper_lock": f"{HELPER_PREFIX}/requirements.lock",
        "debian_lock": f"{HELPER_PREFIX}/debian-packages.lock",
        "source_allowlist": f"{HELPER_PREFIX}/SOURCE_ALLOWLIST",
        "project_lock": "requirements-lock.txt",
    }
    blobs = {
        name: _git_blob(repo, revision, path)
        for name, path in tracked_paths.items()
    }
    # Reading the project lock is intentional: it makes this tracked global
    # input part of revision validation even though it is not copied.
    if not blobs["project_lock"]:
        raise ContextError("empty project requirements lock")

    wheel_rows = _verify_directory(wheelhouse, "full wheelhouse SHA256SUMS")
    execution_wheels = _select_wheels(
        wheel_rows, blobs["execution_lock"], "execution requirements lock"
    )
    helper_wheels = _select_wheels(
        wheel_rows, blobs["helper_lock"], "helper requirements lock"
    )

    closure_rows = _verify_directory(deb_closure, "Debian closure SHA256SUMS")
    locked_debs = _debian_rows(blobs["debian_lock"])
    if closure_rows != locked_debs:
        raise ContextError("Debian closure does not exactly match Debian lock")

    sources = _allowlisted_sources(blobs["source_allowlist"])
    source_blobs = [
        (PurePosixPath(source).name, _git_blob(repo, revision, source))
        for source in sources
    ]

    output_root.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{output_root.name}.tmp-", dir=output_root.parent
        )
    )
    try:
        execution = temporary / "execution"
        helper = temporary / "trusted-helper"
        _write(execution / "Dockerfile", blobs["execution_dockerfile"])
        _write(execution / "requirements.lock", blobs["execution_lock"])
        _copy_selected(wheelhouse, execution / "wheels", execution_wheels)

        _write(helper / "Dockerfile", blobs["helper_dockerfile"])
        _write(helper / "requirements.lock", blobs["helper_lock"])
        _copy_selected(wheelhouse, helper / "wheels", helper_wheels)
        _copy_selected(
            deb_closure,
            helper / "debs",
            locked_debs,
            (deb_closure / "SHA256SUMS").read_bytes(),
        )
        helper_source = helper / "helper-src"
        helper_source.mkdir(parents=True)
        source_sums = []
        for name, data in source_blobs:
            _write(helper_source / name, data)
            source_sums.append(f"{hashlib.sha256(data).hexdigest()}  {name}\n")
        _write(
            helper_source / "SHA256SUMS",
            "".join(source_sums).encode("utf-8"),
        )

        _verify_directory(execution / "wheels", "generated execution wheels")
        _verify_directory(helper / "wheels", "generated helper wheels")
        _verify_directory(helper / "debs", "generated helper Debian closure")
        _verify_directory(helper_source, "generated helper source")
        expected_files = {
            execution / "Dockerfile": blobs["execution_dockerfile"],
            execution / "requirements.lock": blobs["execution_lock"],
            helper / "Dockerfile": blobs["helper_dockerfile"],
            helper / "requirements.lock": blobs["helper_lock"],
        }
        for path, expected in expected_files.items():
            if path.is_symlink() or not path.is_file() or path.read_bytes() != expected:
                raise ContextError(f"generated tracked context input drifted: {path.name}")
        os.replace(temporary, output_root)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--deb-closure", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        assemble(
            arguments.repo,
            arguments.source_revision,
            arguments.wheelhouse,
            arguments.deb_closure,
            arguments.output_root,
        )
    except (ContextError, OSError, UnicodeDecodeError) as error:
        print(f"prepare_context: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
