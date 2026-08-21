"""Filesystem and manifest gates for Acceptance Bundle 0.1."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import rfc8785
from pydantic import ValidationError

import openworkproof.acceptance_bundle as bundle


def _canonical(value: object) -> bytes:
    return rfc8785.dumps(value)


def _base_files() -> dict[str, bytes]:
    return {
        "acceptance/committed-evidence-index.json": b"{}",
        "acceptance/composition-reports.json": b"[]",
        "acceptance/decision-binding.json": b"{}",
        "acceptance/effective-grants.json": b"[]",
        "acceptance/grant-attempts.json": b"[]",
        "acceptance/terminal-receipt.json": b"{}",
        "surface/delivery-package/manifest.json": b"{}",
        "surface/surface-manifest.json": b"{}",
        "verify.sh": bundle.ACCEPTANCE_VERIFY_SCRIPT,
    }


def _manifest_document(files: dict[str, bytes]) -> dict[str, object]:
    return {
        "schema_version": "openworkproof-acceptance-bundle/0.1",
        "surface_manifest_digest": hashlib.sha256(
            files["surface/surface-manifest.json"]
        ).hexdigest(),
        "delivery_manifest_digest": hashlib.sha256(
            files["surface/delivery-package/manifest.json"]
        ).hexdigest(),
        "work_order_digest": "1" * 64,
        "verification_decision_digest": "2" * 64,
        "composition_report_digest": "3" * 64,
        "terminal_decision": "accepted",
        "terminal_receipt_digest": "4" * 64,
        "acceptance_decision_binding_digest": "5" * 64,
        "entries": [
            {
                "path": path,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size_bytes": len(payload),
            }
            for path, payload in sorted(
                files.items(), key=lambda item: item[0].encode("utf-8")
            )
        ],
    }


def _write_bundle(root: Path, files: dict[str, bytes] | None = None) -> Path:
    files = dict(_base_files() if files is None else files)
    root.mkdir()
    for relative, payload in files.items():
        target = root.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    (root / "verify.sh").chmod(0o700)
    (root / "acceptance-manifest.json").write_bytes(
        _canonical(_manifest_document(files))
    )
    return root


@pytest.fixture
def acceptance_bundle(tmp_path: Path) -> Path:
    return _write_bundle(tmp_path / "acceptance-bundle")


def test_acceptance_manifest_round_trips_canonical_snapshot(
    acceptance_bundle: Path,
) -> None:
    manifest = bundle.validate_acceptance_bundle_manifest(acceptance_bundle)
    assert manifest.schema_version == "openworkproof-acceptance-bundle/0.1"
    assert tuple(entry.path for entry in manifest.entries) == tuple(
        sorted(_base_files(), key=lambda value: value.encode("utf-8"))
    )


def test_compose_acceptance_manifest_is_deterministic() -> None:
    files = _base_files()
    summary = _manifest_document(files)
    fields = {
        key: value
        for key, value in summary.items()
        if key not in {"schema_version", "entries"}
    }
    first = bundle.compose_acceptance_manifest(files, **fields)
    second = bundle.compose_acceptance_manifest(
        dict(reversed(tuple(files.items()))),
        **fields,
    )
    assert first == second
    assert _canonical(first.model_dump(mode="json")) == _canonical(summary)


def test_acceptance_manifest_requires_jcs_canonical_bytes(
    acceptance_bundle: Path,
) -> None:
    manifest_path = acceptance_bundle / "acceptance-manifest.json"
    raw = json.loads(manifest_path.read_bytes())
    manifest_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    with pytest.raises(bundle.AcceptanceBundleError, match="canonical"):
        bundle.validate_acceptance_bundle_manifest(acceptance_bundle)


@pytest.mark.parametrize(
    "unsafe",
    (
        "/absolute",
        "../escape",
        "a/../b",
        "a\\b",
        "a\x00b",
        "a//b",
        "a/./b",
    ),
)
def test_acceptance_manifest_rejects_unsafe_paths(
    acceptance_bundle: Path,
    unsafe: str,
) -> None:
    manifest_path = acceptance_bundle / "acceptance-manifest.json"
    raw = json.loads(manifest_path.read_bytes())
    raw["entries"][0]["path"] = unsafe
    manifest_path.write_bytes(_canonical(raw))
    with pytest.raises(bundle.AcceptanceBundleError):
        bundle.validate_acceptance_bundle_manifest(acceptance_bundle)


def test_acceptance_manifest_rejects_duplicate_or_unsorted_entries() -> None:
    raw = _manifest_document(_base_files())
    duplicate = json.loads(json.dumps(raw))
    duplicate["entries"][1]["path"] = duplicate["entries"][0]["path"]
    with pytest.raises(ValidationError):
        bundle.AcceptanceManifestV01.model_validate(duplicate)
    unsorted = json.loads(json.dumps(raw))
    unsorted["entries"].reverse()
    with pytest.raises(ValidationError):
        bundle.AcceptanceManifestV01.model_validate(unsorted)


@pytest.mark.parametrize(
    ("field", "path"),
    (
        ("surface_manifest_digest", "surface/surface-manifest.json"),
        ("delivery_manifest_digest", "surface/delivery-package/manifest.json"),
    ),
)
def test_acceptance_manifest_rejects_summary_digest_mismatch(
    field: str,
    path: str,
) -> None:
    raw = _manifest_document(_base_files())
    raw[field] = "0" * 64
    assert raw[field] != next(
        entry["sha256"] for entry in raw["entries"] if entry["path"] == path
    )
    with pytest.raises(ValidationError, match="summary"):
        bundle.AcceptanceManifestV01.model_validate(raw)


def test_acceptance_manifest_requires_exact_file_set(
    acceptance_bundle: Path,
) -> None:
    (acceptance_bundle / "unexpected.txt").write_text("extra", encoding="utf-8")
    with pytest.raises(bundle.AcceptanceBundleError, match="file set"):
        bundle.validate_acceptance_bundle_manifest(acceptance_bundle)


def test_acceptance_manifest_rejects_missing_required_file(
    acceptance_bundle: Path,
) -> None:
    (acceptance_bundle / "acceptance/effective-grants.json").unlink()
    manifest_path = acceptance_bundle / "acceptance-manifest.json"
    raw = json.loads(manifest_path.read_bytes())
    raw["entries"] = [
        entry
        for entry in raw["entries"]
        if entry["path"] != "acceptance/effective-grants.json"
    ]
    manifest_path.write_bytes(_canonical(raw))
    with pytest.raises(bundle.AcceptanceBundleError, match="required"):
        bundle.validate_acceptance_bundle_manifest(acceptance_bundle)


def test_acceptance_manifest_rejects_path_outside_allowlist(
    tmp_path: Path,
) -> None:
    files = _base_files()
    files["private/secret.json"] = b"{}"
    root = _write_bundle(tmp_path / "bad-allowlist", files)
    with pytest.raises(bundle.AcceptanceBundleError, match="allowlist"):
        bundle.validate_acceptance_bundle_manifest(root)


def test_acceptance_manifest_requires_exact_verify_script(
    acceptance_bundle: Path,
) -> None:
    script = acceptance_bundle / "verify.sh"
    script.write_bytes(b"#!/bin/sh\nexit 0\n")
    raw = json.loads((acceptance_bundle / "acceptance-manifest.json").read_bytes())
    for entry in raw["entries"]:
        if entry["path"] == "verify.sh":
            entry["sha256"] = hashlib.sha256(script.read_bytes()).hexdigest()
            entry["size_bytes"] = len(script.read_bytes())
    (acceptance_bundle / "acceptance-manifest.json").write_bytes(_canonical(raw))
    with pytest.raises(bundle.AcceptanceBundleError, match="required"):
        bundle.validate_acceptance_bundle_manifest(acceptance_bundle)


@pytest.mark.parametrize("kind", ("symlink", "hardlink", "fifo"))
def test_acceptance_bundle_rejects_link_or_fifo(
    acceptance_bundle: Path,
    kind: str,
) -> None:
    hostile = acceptance_bundle / "hostile"
    if kind == "symlink":
        hostile.symlink_to("verify.sh")
    elif kind == "hardlink":
        os.link(acceptance_bundle / "verify.sh", hostile)
    else:
        os.mkfifo(hostile)
    try:
        with pytest.raises(bundle.AcceptanceBundleError):
            bundle.validate_acceptance_bundle_manifest(acceptance_bundle)
    finally:
        hostile.unlink(missing_ok=True)


def test_acceptance_bundle_rejects_device_file() -> None:
    with pytest.raises(bundle.AcceptanceBundleError, match="regular"):
        bundle._read_regular(Path("/dev/null"))


def test_acceptance_bundle_rejects_file_count_limit(
    acceptance_bundle: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bundle, "MAX_ACCEPTANCE_FILES", 2)
    with pytest.raises(bundle.AcceptanceBundleError, match="count"):
        bundle.validate_acceptance_bundle_manifest(acceptance_bundle)


def test_acceptance_bundle_rejects_single_file_limit(
    acceptance_bundle: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bundle, "MAX_ACCEPTANCE_FILE_BYTES", 1)
    with pytest.raises(bundle.AcceptanceBundleError, match="size"):
        bundle.validate_acceptance_bundle_manifest(acceptance_bundle)


def test_acceptance_bundle_rejects_total_size_limit(
    acceptance_bundle: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bundle, "MAX_ACCEPTANCE_TOTAL_BYTES", 2)
    with pytest.raises(bundle.AcceptanceBundleError, match="total"):
        bundle.validate_acceptance_bundle_manifest(acceptance_bundle)


def test_acceptance_bundle_rejects_file_drift_during_read(
    acceptance_bundle: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_fstat = bundle.os.fstat
    calls = 0

    def drifting_fstat(descriptor: int):
        nonlocal calls
        calls += 1
        observed = real_fstat(descriptor)
        if calls == 2:
            return SimpleNamespace(
                st_dev=observed.st_dev,
                st_ino=observed.st_ino,
                st_mode=observed.st_mode,
                st_nlink=observed.st_nlink,
                st_size=observed.st_size + 1,
                st_mtime_ns=observed.st_mtime_ns,
            )
        return observed

    monkeypatch.setattr(bundle.os, "fstat", drifting_fstat)
    with pytest.raises(bundle.AcceptanceBundleError, match="changed"):
        bundle.validate_acceptance_bundle_manifest(acceptance_bundle)
