"""Offline-verifiable OpenWorkProof surface bundles (0.1)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
import shutil
import stat
import sys
import tempfile
from typing import Annotated, Any, Literal
import uuid

import rfc8785
from pydantic import BeforeValidator, ConfigDict, model_validator

from openworkproof.delivery_package import (
    load_surface_facts,
    verify_delivery_package,
)
from openworkproof.environment_fingerprint import (
    SignedEnvironmentFingerprintV01,
)
from openworkproof.models import Digest64, ProtocolModel, SafeNonNegativeInt
from openworkproof.verification_report import (
    VerificationReportV01,
    compose_verification_report,
    render_report_html,
)


__all__ = [
    "MAX_SURFACE_FILES",
    "MAX_SURFACE_FILE_BYTES",
    "MAX_SURFACE_TOTAL_BYTES",
    "SurfaceBundleError",
    "SurfaceManifestEntry",
    "SurfaceManifestV01",
    "SurfaceVerificationResult",
    "build_surface_bundle",
    "verify_surface_bundle",
]

MAX_SURFACE_FILES = 4096
MAX_SURFACE_FILE_BYTES = 64 * 1024 * 1024
MAX_SURFACE_TOTAL_BYTES = 512 * 1024 * 1024

_VERIFY_SCRIPT = (
    b"#!/bin/sh\n"
    b"set -eu\n"
    b'exec python -m openworkproof.surface_bundle "${1:-.}"\n'
)
_SURFACE_VERSION = "openworkproof-surface-bundle/0.1"


class SurfaceBundleError(RuntimeError):
    """A surface bundle cannot be built or verified safely."""


def _safe_relative(value: Any) -> str:
    if type(value) is not str:
        raise ValueError("surface path must be a strict string")
    if not value or len(value.encode("utf-8")) > 512:
        raise ValueError("surface path length is invalid")
    if (
        value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or "//" in value
    ):
        raise ValueError("surface path is not canonical relative POSIX")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("surface path contains an unsafe segment")
    return value


SurfaceRelativePath = Annotated[str, BeforeValidator(_safe_relative)]


class SurfaceManifestEntry(ProtocolModel):
    path: SurfaceRelativePath
    sha256: Digest64
    size_bytes: SafeNonNegativeInt


class SurfaceManifestV01(ProtocolModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="subclass-instances",
    )

    schema_version: Literal["openworkproof-surface-bundle/0.1"]
    delivery_manifest_digest: Digest64
    report_digest: Digest64
    entries: tuple[SurfaceManifestEntry, ...]

    @model_validator(mode="after")
    def _closed_manifest(self) -> SurfaceManifestV01:
        paths = tuple(entry.path for entry in self.entries)
        if not paths or paths != tuple(
            sorted(set(paths), key=lambda value: value.encode("utf-8"))
        ):
            raise ValueError("surface entries must be non-empty, sorted, and unique")
        by_path = {entry.path: entry for entry in self.entries}
        delivery = by_path.get("delivery-package/manifest.json")
        report = by_path.get("report.json")
        if (
            delivery is None
            or report is None
            or delivery.sha256 != self.delivery_manifest_digest
            or report.sha256 != self.report_digest
        ):
            raise ValueError("surface manifest summary digests are inconsistent")
        return self


@dataclass(frozen=True, slots=True)
class SurfaceVerificationResult:
    manifest: SurfaceManifestV01
    report: VerificationReportV01
    manifest_digest: str


@dataclass(frozen=True, slots=True)
class _ScannedFile:
    payload: bytes
    mode: int


def _canonical(value: object) -> bytes:
    return rfc8785.dumps(value)


def _read_regular(path: Path) -> _ScannedFile:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise SurfaceBundleError(
                "surface bundles contain stable single-link regular files only"
            )
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except SurfaceBundleError:
        raise
    except OSError as error:
        raise SurfaceBundleError("surface file cannot be opened safely") from error
    try:
        opened = os.fstat(descriptor)
        identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
        )
        if (
            stat.S_ISREG(opened.st_mode) is False
            or opened.st_nlink != 1
            or (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
            )
            != identity
        ):
            raise SurfaceBundleError(
                "surface bundles contain stable single-link regular files only"
            )
        if opened.st_size > MAX_SURFACE_FILE_BYTES:
            raise SurfaceBundleError("surface file exceeds the size limit")
        chunks: list[bytes] = []
        remaining = MAX_SURFACE_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(payload) != opened.st_size
            or (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
            )
            != identity
        ):
            raise SurfaceBundleError("surface file changed while being read")
    finally:
        os.close(descriptor)
    try:
        final = path.lstat()
    except OSError as error:
        raise SurfaceBundleError("surface file changed after read") from error
    if (
        final.st_dev,
        final.st_ino,
        final.st_mode,
        final.st_nlink,
        final.st_size,
        final.st_mtime_ns,
    ) != identity:
        raise SurfaceBundleError("surface file changed after read")
    return _ScannedFile(payload=payload, mode=stat.S_IMODE(opened.st_mode))


def _scan_tree(root: Path) -> dict[str, _ScannedFile]:
    if root.is_symlink() or not root.is_dir():
        raise SurfaceBundleError("surface root must be a real directory")
    files: dict[str, _ScannedFile] = {}
    total = 0
    try:
        walker = os.walk(root, followlinks=False)
        for directory, names, filenames in walker:
            directory_path = Path(directory)
            for name in names:
                child = directory_path / name
                metadata = child.lstat()
                if child.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                    raise SurfaceBundleError(
                        "surface directory tree contains a non-directory"
                    )
            for name in filenames:
                path = directory_path / name
                relative = _safe_relative(path.relative_to(root).as_posix())
                if relative in files:
                    raise SurfaceBundleError("surface path is duplicated")
                if len(files) >= MAX_SURFACE_FILES:
                    raise SurfaceBundleError("surface file count exceeds the limit")
                scanned = _read_regular(path)
                files[relative] = scanned
                total += len(scanned.payload)
                if total > MAX_SURFACE_TOTAL_BYTES:
                    raise SurfaceBundleError("surface total size exceeds the limit")
    except SurfaceBundleError:
        raise
    except OSError as error:
        raise SurfaceBundleError("surface tree scan failed") from error
    return files


def _write_new(root: Path, relative: str, payload: bytes, *, mode: int = 0o600) -> None:
    relative = _safe_relative(relative)
    target = root.joinpath(*relative.split("/"))
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags, mode)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise SurfaceBundleError("surface write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _canonical_root(path: Path, *, must_exist: bool) -> Path:
    absolute = Path(os.path.abspath(path))
    if absolute.is_symlink():
        raise SurfaceBundleError("surface path must not be a symlink")
    try:
        resolved = absolute.resolve(strict=must_exist)
    except OSError as error:
        raise SurfaceBundleError("surface path cannot be resolved") from error
    if resolved != absolute:
        raise SurfaceBundleError("surface path must not traverse symlinks")
    return resolved


def _is_within(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
    except ValueError:
        return False
    return True


def _manifest_for(files: dict[str, bytes]) -> SurfaceManifestV01:
    entries = tuple(
        SurfaceManifestEntry(
            path=path,
            sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
        )
        for path, payload in sorted(
            files.items(), key=lambda item: item[0].encode("utf-8")
        )
    )
    by_path = {entry.path: entry for entry in entries}
    return SurfaceManifestV01(
        schema_version=_SURFACE_VERSION,
        delivery_manifest_digest=by_path[
            "delivery-package/manifest.json"
        ].sha256,
        report_digest=by_path["report.json"].sha256,
        entries=[entry.model_dump(mode="json") for entry in entries],
    )


def build_surface_bundle(
    delivery_package_root: Path,
    fingerprints: tuple[SignedEnvironmentFingerprintV01, ...]
    | list[SignedEnvironmentFingerprintV01],
    output: Path,
) -> SurfaceManifestV01:
    """Build one immutable, verified surface bundle in a sibling stage."""

    source = _canonical_root(Path(delivery_package_root), must_exist=True)
    output_input = Path(output)
    if output_input.exists() or output_input.is_symlink():
        raise SurfaceBundleError("surface output already exists")
    output_input.parent.mkdir(parents=True, exist_ok=True)
    destination = _canonical_root(output_input.parent, must_exist=True) / output_input.name
    if _is_within(destination, source) or _is_within(source, destination):
        raise SurfaceBundleError("surface input and output must not overlap")
    if type(fingerprints) not in {tuple, list}:
        raise SurfaceBundleError("surface fingerprints must be an exact tuple or list")
    if not 1 <= len(fingerprints) <= 2:
        raise SurfaceBundleError("surface requires one or two fingerprints")
    fingerprint_items = tuple(fingerprints)

    try:
        verify_delivery_package(source)
        facts = load_surface_facts(source)
        scanned_delivery = _scan_tree(source)
        delivery_files = {
            f"delivery-package/{path}": value.payload
            for path, value in scanned_delivery.items()
        }
        manifest_payload = scanned_delivery["manifest.json"].payload
        bundle_digest = hashlib.sha256(manifest_payload).hexdigest()
        ordered_fingerprints = tuple(
            sorted(
                fingerprint_items,
                key=lambda item: item.digest.encode("utf-8"),
            )
        )
        report = compose_verification_report(
            facts, ordered_fingerprints, bundle_digest=bundle_digest
        )
        files = dict(delivery_files)
        for index, fingerprint in enumerate(ordered_fingerprints):
            files[f"environments/{index:02d}.json"] = _canonical(
                fingerprint.model_dump(mode="json", warnings="error")
            )
        files["report.json"] = _canonical(report.model_dump(mode="json"))
        files["report.html"] = render_report_html(report)
        files["verify.sh"] = _VERIFY_SCRIPT
        manifest = _manifest_for(files)
        manifest_bytes = _canonical(manifest.model_dump(mode="json"))
    except SurfaceBundleError:
        raise
    except Exception as error:
        raise SurfaceBundleError("surface inputs are invalid") from error

    stage = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.tmp"
    try:
        stage.mkdir(mode=0o700)
        for relative, payload in files.items():
            _write_new(
                stage,
                relative,
                payload,
                mode=0o700 if relative == "verify.sh" else 0o600,
            )
        _write_new(stage, "surface-manifest.json", manifest_bytes)
        verify_surface_bundle(stage)
        if destination.exists() or destination.is_symlink():
            raise SurfaceBundleError("surface output appeared during build")
        os.rename(stage, destination)
        return manifest
    except SurfaceBundleError:
        if stage.exists():
            shutil.rmtree(stage)
        raise
    except Exception as error:
        if destination.is_dir() and not destination.is_symlink():
            try:
                committed = verify_surface_bundle(destination)
            except SurfaceBundleError:
                pass
            else:
                if committed.manifest == manifest:
                    return manifest
        if stage.exists():
            shutil.rmtree(stage)
        raise SurfaceBundleError("surface bundle commit failed") from error


def _parse_surface_manifest(payload: bytes) -> SurfaceManifestV01:
    try:
        raw = json.loads(payload)
        manifest = SurfaceManifestV01.model_validate(raw)
    except Exception as error:
        raise SurfaceBundleError("surface manifest is invalid") from error
    if _canonical(manifest.model_dump(mode="json")) != payload:
        raise SurfaceBundleError("surface manifest is not canonical")
    return manifest


def _verify_snapshot(
    root: Path,
    scanned: dict[str, _ScannedFile],
) -> SurfaceVerificationResult:
    manifest_file = scanned.get("surface-manifest.json")
    if manifest_file is None:
        raise SurfaceBundleError("surface manifest is missing")
    manifest = _parse_surface_manifest(manifest_file.payload)
    actual = set(scanned) - {"surface-manifest.json"}
    expected = {entry.path for entry in manifest.entries}
    if actual != expected:
        raise SurfaceBundleError("surface manifest file set is not exact")
    for entry in manifest.entries:
        payload = scanned[entry.path].payload
        if (
            len(payload) != entry.size_bytes
            or hashlib.sha256(payload).hexdigest() != entry.sha256
        ):
            raise SurfaceBundleError("surface entry integrity failed")

    allowed_exact = {"report.json", "report.html", "verify.sh"}
    environment_paths = sorted(
        path for path in actual if path.startswith("environments/")
    )
    if (
        not 1 <= len(environment_paths) <= 2
        or environment_paths
        != [f"environments/{index:02d}.json" for index in range(len(environment_paths))]
        or any(
            path not in allowed_exact
            and not path.startswith("delivery-package/")
            and not path.startswith("environments/")
            for path in actual
        )
    ):
        raise SurfaceBundleError("surface path allowlist is invalid")
    required = {
        "delivery-package/manifest.json",
        "report.json",
        "report.html",
        "verify.sh",
        *environment_paths,
    }
    if not required <= actual or scanned["verify.sh"].payload != _VERIFY_SCRIPT:
        raise SurfaceBundleError("surface required files are invalid")

    inner = root / "delivery-package"
    verification = verify_delivery_package(inner)
    if verification.full_offline_replay is not True:
        raise SurfaceBundleError("surface inner package is not fully replayable")
    facts = load_surface_facts(inner)
    fingerprints: list[SignedEnvironmentFingerprintV01] = []
    for relative in environment_paths:
        payload = scanned[relative].payload
        try:
            raw = json.loads(payload)
            fingerprint = SignedEnvironmentFingerprintV01.model_validate(raw)
        except Exception as error:
            raise SurfaceBundleError("surface environment is invalid") from error
        if _canonical(fingerprint.model_dump(mode="json")) != payload:
            raise SurfaceBundleError("surface environment is not canonical")
        fingerprints.append(fingerprint)

    delivery_manifest_payload = scanned[
        "delivery-package/manifest.json"
    ].payload
    delivery_manifest_digest = hashlib.sha256(
        delivery_manifest_payload
    ).hexdigest()
    if delivery_manifest_digest != manifest.delivery_manifest_digest:
        raise SurfaceBundleError("surface delivery manifest digest mismatch")
    recomposed = compose_verification_report(
        facts,
        tuple(fingerprints),
        bundle_digest=delivery_manifest_digest,
    )
    report_payload = scanned["report.json"].payload
    try:
        stored_report = VerificationReportV01.model_validate_json(report_payload)
    except Exception as error:
        raise SurfaceBundleError("surface report is invalid") from error
    if (
        _canonical(stored_report.model_dump(mode="json")) != report_payload
        or stored_report != recomposed
        or hashlib.sha256(report_payload).hexdigest() != manifest.report_digest
        or scanned["report.html"].payload != render_report_html(recomposed)
    ):
        raise SurfaceBundleError("surface report replay mismatch")
    return SurfaceVerificationResult(
        manifest=manifest,
        report=recomposed,
        manifest_digest=hashlib.sha256(manifest_file.payload).hexdigest(),
    )


def verify_surface_bundle(surface_root: Path) -> SurfaceVerificationResult:
    """Verify a surface bundle from a stable byte snapshot, never disk status."""
    try:
        source = _canonical_root(Path(surface_root), must_exist=True)
        scanned = _scan_tree(source)
        verify_file = scanned.get("verify.sh")
        if verify_file is None or not verify_file.mode & 0o111:
            raise SurfaceBundleError(
                "surface verifier entrypoint is not executable"
            )
        with tempfile.TemporaryDirectory(
            prefix="openworkproof-surface-verify-"
        ) as raw:
            snapshot = Path(raw)
            for relative, value in scanned.items():
                _write_new(
                    snapshot,
                    relative,
                    value.payload,
                    mode=0o700 if relative == "verify.sh" else 0o600,
                )
            return _verify_snapshot(snapshot, scanned)
    except SurfaceBundleError:
        raise
    except Exception as error:
        raise SurfaceBundleError("surface bundle verification failed") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("surface", nargs="?", default=".")
    args = parser.parse_args(argv)
    try:
        result = verify_surface_bundle(Path(args.surface))
    except SurfaceBundleError as error:
        print(f"OpenWorkProof surface verification error: {error}", file=sys.stderr)
        return 4
    print(result.report.model_dump_json())
    return {"VERIFIED": 0, "REFUTED": 2, "UNKNOWN": 3}[
        result.report.decision_status
    ]


if __name__ == "__main__":
    raise SystemExit(main())
