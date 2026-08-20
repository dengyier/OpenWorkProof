from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import rfc8785

from openworkproof.delivery_package import (
    export_delivery_package,
    load_surface_facts,
)
from openworkproof.environment_fingerprint import (
    EnvironmentFingerprintPayloadV01,
    sign_environment_fingerprint,
)
from openworkproof.signing import key_id
from openworkproof.surface_bundle import (
    SurfaceBundleError,
    SurfaceManifestV01,
    build_surface_bundle,
    verify_surface_bundle,
)
from openworkproof.verification_report import VerificationReportV01

from test_acceptance_v05 import _commit_v05_decision
from test_verification_integrity_transactions_v05 import (
    v05_transaction_case,
    verification_profile_v03,
)


def _complete_fingerprint(case, package_root: Path):
    facts = load_surface_facts(package_root)
    private_key = case["keys"]["Verifier"][0]
    verifier_key_id = key_id(private_key.public_key())
    payload = EnvironmentFingerprintPayloadV01.model_validate(
        {
            "schema_version": "openworkproof-execution-environment/0.1",
            "source_revision": facts.source_revision,
            "runner_os": "linux",
            "runner_arch": "amd64",
            "runner_image_digest": "a" * 64,
            "container_image_digest": "b" * 64,
            "toolchain_lock_digest": "c" * 64,
            "command_digest": "d" * 64,
            "arguments_digest": "e" * 64,
            "environment_allowlist_digest": "f" * 64,
            "sandbox_policy_digest": "0" * 64,
            "workflow_identity_digest": "1" * 64,
            "collection_status": "complete",
            "missing_reason_codes": [],
            "collected_at": "2026-01-01T00:10:00Z",
            "collector_actor_id": facts.trusted_verifier_subjects[
                verifier_key_id
            ],
        }
    )
    return sign_environment_fingerprint(payload, private_key)


@pytest.fixture
def surface_source(v05_transaction_case):
    case = dict(v05_transaction_case)
    _commit_v05_decision(case)
    package_root = case["tmp_path"] / "surface-source-package"
    export_delivery_package(
        case["ledger"], package_root, privacy_view="customer_private"
    )
    return case, package_root, _complete_fingerprint(case, package_root)


@pytest.fixture
def surface_bundle(surface_source):
    case, package_root, fingerprint = surface_source
    output = case["tmp_path"] / "surface-bundle"
    build_surface_bundle(package_root, (fingerprint,), output)
    return output


def _canonical(value: object) -> bytes:
    return rfc8785.dumps(value)


def _sync_surface_entry(root: Path, relative: str) -> None:
    manifest_path = root / "surface-manifest.json"
    raw = json.loads(manifest_path.read_bytes())
    payload = (root / relative).read_bytes()
    entry = next(item for item in raw["entries"] if item["path"] == relative)
    entry["sha256"] = hashlib.sha256(payload).hexdigest()
    entry["size_bytes"] = len(payload)
    if relative == "report.json":
        raw["report_digest"] = entry["sha256"]
    if relative == "delivery-package/manifest.json":
        raw["delivery_manifest_digest"] = entry["sha256"]
    manifest_path.write_bytes(_canonical(raw))


def test_surface_bundle_round_trips_offline(surface_source) -> None:
    case, package_root, fingerprint = surface_source
    output = case["tmp_path"] / "round-trip-surface"
    manifest = build_surface_bundle(package_root, (fingerprint,), output)
    result = verify_surface_bundle(output)

    assert isinstance(manifest, SurfaceManifestV01)
    assert result.report.decision_status == "VERIFIED"
    assert result.report == VerificationReportV01.model_validate_json(
        (output / "report.json").read_bytes()
    )
    assert result.manifest == manifest
    assert (output / "verify.sh").stat().st_mode & 0o111


def test_surface_bundle_is_deterministic(surface_source) -> None:
    case, package_root, fingerprint = surface_source
    first = case["tmp_path"] / "surface-first"
    second = case["tmp_path"] / "surface-second"
    build_surface_bundle(package_root, (fingerprint,), first)
    build_surface_bundle(package_root, (fingerprint,), second)
    for relative in (
        "surface-manifest.json",
        "report.json",
        "report.html",
        "environments/00.json",
        "verify.sh",
    ):
        assert (first / relative).read_bytes() == (second / relative).read_bytes()


def test_generated_verify_script_replays_bundle(surface_bundle: Path) -> None:
    environment = dict(os.environ)
    environment["PATH"] = (
        f"{Path(sys.executable).parent}{os.pathsep}{environment.get('PATH', '')}"
    )
    completed = subprocess.run(
        [str(surface_bundle / "verify.sh")],
        cwd=surface_bundle,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["decision_status"] == "VERIFIED"


@pytest.mark.parametrize(
    "target",
    [
        "surface-manifest.json",
        "report.json",
        "report.html",
        "environments/00.json",
        "delivery-package/manifest.json",
    ],
)
def test_surface_bundle_rejects_each_tampered_layer(
    surface_bundle: Path, target: str
) -> None:
    path = surface_bundle / target
    path.write_bytes(path.read_bytes() + b"tamper")
    with pytest.raises(SurfaceBundleError):
        verify_surface_bundle(surface_bundle)


def test_rejects_semantic_report_tamper_even_with_outer_manifest_synced(
    surface_bundle: Path,
) -> None:
    report_path = surface_bundle / "report.json"
    raw = json.loads(report_path.read_bytes())
    raw["decision_status"] = "REFUTED"
    raw["reason_codes"] = ["DELIVERY_REFUTED"]
    unsigned = {
        key: value for key, value in raw.items() if key != "replay_result_digest"
    }
    raw["replay_result_digest"] = hashlib.sha256(
        _canonical(unsigned)
    ).hexdigest()
    report_path.write_bytes(_canonical(raw))
    _sync_surface_entry(surface_bundle, "report.json")
    with pytest.raises(SurfaceBundleError):
        verify_surface_bundle(surface_bundle)


def test_rejects_environment_signature_tamper_with_outer_manifest_synced(
    surface_bundle: Path,
) -> None:
    environment_path = surface_bundle / "environments/00.json"
    raw = json.loads(environment_path.read_bytes())
    raw["signature"] = "A" * 86
    environment_path.write_bytes(_canonical(raw))
    _sync_surface_entry(surface_bundle, "environments/00.json")
    with pytest.raises(SurfaceBundleError):
        verify_surface_bundle(surface_bundle)


def test_rejects_inner_package_tamper_with_outer_manifest_synced(
    surface_bundle: Path,
) -> None:
    inner_manifest = surface_bundle / "delivery-package/manifest.json"
    inner_manifest.write_bytes(inner_manifest.read_bytes() + b" ")
    _sync_surface_entry(surface_bundle, "delivery-package/manifest.json")
    with pytest.raises(SurfaceBundleError):
        verify_surface_bundle(surface_bundle)


@pytest.mark.parametrize("path_value", ["../escape", "/absolute", "a//b", "a/./b"])
def test_surface_manifest_rejects_unsafe_paths(
    surface_bundle: Path, path_value: str
) -> None:
    manifest_path = surface_bundle / "surface-manifest.json"
    raw = json.loads(manifest_path.read_bytes())
    raw["entries"][0]["path"] = path_value
    manifest_path.write_bytes(_canonical(raw))
    with pytest.raises(SurfaceBundleError):
        verify_surface_bundle(surface_bundle)


def test_surface_manifest_rejects_duplicate_and_missing_paths(
    surface_bundle: Path,
) -> None:
    manifest_path = surface_bundle / "surface-manifest.json"
    original = json.loads(manifest_path.read_bytes())
    duplicate = json.loads(manifest_path.read_bytes())
    duplicate["entries"][1]["path"] = duplicate["entries"][0]["path"]
    manifest_path.write_bytes(_canonical(duplicate))
    with pytest.raises(SurfaceBundleError):
        verify_surface_bundle(surface_bundle)

    missing = original
    missing["entries"].pop()
    manifest_path.write_bytes(_canonical(missing))
    with pytest.raises(SurfaceBundleError):
        verify_surface_bundle(surface_bundle)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_surface_bundle_rejects_non_regular_or_linked_files(
    surface_bundle: Path, kind: str
) -> None:
    extra = surface_bundle / "hostile"
    if kind == "symlink":
        extra.symlink_to("report.json")
    elif kind == "hardlink":
        os.link(surface_bundle / "report.json", extra)
    else:
        os.mkfifo(extra)
    try:
        with pytest.raises(SurfaceBundleError):
            verify_surface_bundle(surface_bundle)
    finally:
        extra.unlink(missing_ok=True)


def test_builder_rejects_overlap_and_preserves_existing_output(
    surface_source,
) -> None:
    case, package_root, fingerprint = surface_source
    with pytest.raises(SurfaceBundleError):
        build_surface_bundle(
            package_root,
            (fingerprint,),
            package_root / "nested-output",
        )

    output = case["tmp_path"] / "existing-surface"
    output.mkdir()
    marker = output / "keep.txt"
    marker.write_text("unchanged", encoding="utf-8")
    with pytest.raises(SurfaceBundleError):
        build_surface_bundle(package_root, (fingerprint,), output)
    assert marker.read_text(encoding="utf-8") == "unchanged"
    assert not tuple(output.parent.glob(f".{output.name}.*.tmp"))


def test_builder_rejects_hostile_fingerprint_sequence_without_traversal(
    surface_source,
) -> None:
    case, package_root, _fingerprint = surface_source
    traversed = False

    class HostileSequence:
        def __iter__(self):
            nonlocal traversed
            traversed = True
            raise AssertionError("must not traverse hostile sequence")

    with pytest.raises(SurfaceBundleError):
        build_surface_bundle(
            package_root,
            HostileSequence(),  # type: ignore[arg-type]
            case["tmp_path"] / "hostile-sequence-output",
        )
    assert traversed is False


def test_failed_stage_verification_preserves_absent_output_and_cleans_stage(
    surface_source, monkeypatch: pytest.MonkeyPatch
) -> None:
    import openworkproof.surface_bundle as module

    case, package_root, fingerprint = surface_source
    output = case["tmp_path"] / "failed-stage-output"

    def reject_stage(_root):
        raise SurfaceBundleError("injected verification failure")

    monkeypatch.setattr(module, "verify_surface_bundle", reject_stage)
    with pytest.raises(SurfaceBundleError, match="injected"):
        build_surface_bundle(package_root, (fingerprint,), output)
    assert not output.exists()
    assert not tuple(output.parent.glob(f".{output.name}.*.tmp"))


def test_commit_ack_loss_returns_exact_committed_surface(
    surface_source, monkeypatch: pytest.MonkeyPatch
) -> None:
    import openworkproof.surface_bundle as module

    case, package_root, fingerprint = surface_source
    output = case["tmp_path"] / "ack-loss-output"
    real_rename = module.os.rename
    lost = False

    def rename_then_raise(source, destination):
        nonlocal lost
        real_rename(source, destination)
        lost = True
        raise OSError("simulated commit ACK loss")

    monkeypatch.setattr(module.os, "rename", rename_then_raise)
    manifest = build_surface_bundle(package_root, (fingerprint,), output)
    assert lost is True
    result = verify_surface_bundle(output)
    assert result.manifest == manifest
    assert result.report.decision_status == "VERIFIED"
    assert not tuple(output.parent.glob(f".{output.name}.*.tmp"))


def test_surface_limits_are_fixed_and_enforced(
    surface_bundle: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import openworkproof.surface_bundle as module

    assert module.MAX_SURFACE_FILES == 4096
    assert module.MAX_SURFACE_FILE_BYTES == 64 * 1024 * 1024
    assert module.MAX_SURFACE_TOTAL_BYTES == 512 * 1024 * 1024

    with monkeypatch.context() as patcher:
        patcher.setattr(module, "MAX_SURFACE_FILES", 2)
        with pytest.raises(SurfaceBundleError):
            verify_surface_bundle(surface_bundle)
    with monkeypatch.context() as patcher:
        patcher.setattr(module, "MAX_SURFACE_FILE_BYTES", 1)
        with pytest.raises(SurfaceBundleError):
            verify_surface_bundle(surface_bundle)
    with monkeypatch.context() as patcher:
        patcher.setattr(module, "MAX_SURFACE_TOTAL_BYTES", 1)
        with pytest.raises(SurfaceBundleError):
            verify_surface_bundle(surface_bundle)


def test_surface_file_count_limit_rejects_before_reading_excess_file(
    surface_bundle: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import openworkproof.surface_bundle as module

    reads: list[Path] = []
    real_read_regular = module._read_regular

    def counted_read(path: Path):
        reads.append(path)
        return real_read_regular(path)

    monkeypatch.setattr(module, "MAX_SURFACE_FILES", 2)
    monkeypatch.setattr(module, "_read_regular", counted_read)
    with pytest.raises(SurfaceBundleError, match="file count"):
        verify_surface_bundle(surface_bundle)
    assert len(reads) == 2


def test_surface_writer_rejects_zero_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import openworkproof.surface_bundle as module

    monkeypatch.setattr(module.os, "write", lambda *_args: 0)
    with pytest.raises(SurfaceBundleError, match="write made no progress"):
        module._write_new(tmp_path, "payload.bin", b"payload")
