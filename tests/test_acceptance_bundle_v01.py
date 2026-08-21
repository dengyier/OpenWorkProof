"""Filesystem and manifest gates for Acceptance Bundle 0.1."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest
import rfc8785
from pydantic import ValidationError

import openworkproof.acceptance_bundle as bundle

from test_acceptance_decision_binding_v01 import (
    accepted_v05_case as accepted_v05_case,
    rejected_v05_case as rejected_v05_case,
    _sign_binding_draft,
    _stub_candidate_execution_snapshot as _stub_candidate_execution_snapshot,
)


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


def _write_canonical(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical(value))


def _build_real_acceptance_bundle(case, root: Path):
    import openworkproof.acceptance as acceptance
    import openworkproof.evidence as evidence
    from openworkproof.delivery_package import export_delivery_package
    from openworkproof.surface_bundle import build_surface_bundle
    from test_mcp_server import _current_run_tests_context
    from test_surface_bundle_v01 import _complete_fingerprint

    draft = acceptance.prepare_acceptance_decision_binding(
        case["ledger_path"], clock=lambda: case["binding_now"]
    )
    binding = _sign_binding_draft(draft, case["keys"])
    acceptance.commit_acceptance_decision_binding(
        case["ledger_path"], binding, clock=lambda: case["binding_now"]
    )
    package = root.parent / f"{root.name}-delivery"
    surface = root.parent / f"{root.name}-surface"
    export_delivery_package(
        case["ledger_path"], package, privacy_view="customer_private"
    )
    surface_case = {
        "keys": case["keys"],
    }
    build_surface_bundle(
        package,
        (_complete_fingerprint(surface_case, package),),
        surface,
    )
    root.mkdir()
    shutil.copytree(surface, root / "surface")
    context = _current_run_tests_context(case, case["binding_now"])
    _write_canonical(
        root / "acceptance/effective-grants.json",
        [
            item.model_dump(mode="json")
            for item in context.ledger_prefix.effective_grants
        ],
    )
    _write_canonical(
        root / "acceptance/grant-attempts.json",
        [
            item.model_dump(mode="json")
            for item in context.ledger_prefix.grant_attempts
        ],
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        reports = evidence._validated_composition_reports(
            connection, case["work_order"]
        )
    finally:
        connection.close()
    _write_canonical(
        root / "acceptance/composition-reports.json",
        [item.model_dump(mode="json") for item in reports],
    )
    evidence_entries = []
    for item in context.committed_evidence:
        bundle_path = f"acceptance/evidence/{item.reference.path}"
        target = root.joinpath(*bundle_path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(item.payload)
        evidence_entries.append(
            {
                "bundle_path": bundle_path,
                "reference": item.reference.model_dump(mode="json"),
            }
        )
    _write_canonical(
        root / "acceptance/committed-evidence-index.json",
        {
            "schema_version": "openworkproof-committed-evidence-index/0.1",
            "entries": evidence_entries,
        },
    )
    _write_canonical(
        root / "acceptance/terminal-receipt.json",
        case["terminal"].model_dump(mode="json"),
    )
    _write_canonical(
        root / "acceptance/decision-binding.json",
        binding.model_dump(mode="json"),
    )
    (root / "verify.sh").write_bytes(bundle.ACCEPTANCE_VERIFY_SCRIPT)
    (root / "verify.sh").chmod(0o700)
    files = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }
    manifest = bundle.compose_acceptance_manifest(
        files,
        surface_manifest_digest=hashlib.sha256(
            files["surface/surface-manifest.json"]
        ).hexdigest(),
        delivery_manifest_digest=hashlib.sha256(
            files["surface/delivery-package/manifest.json"]
        ).hexdigest(),
        work_order_digest=case["work_order"].digest,
        verification_decision_digest=case["decision"].digest,
        composition_report_digest=acceptance.composition_report_digest(
            case["report"]
        ),
        terminal_decision=(
            "accepted"
            if hasattr(case["terminal"], "acceptance_id")
            else "rejected"
        ),
        terminal_receipt_digest=case["terminal"].digest,
        acceptance_decision_binding_digest=binding.digest,
    )
    _write_canonical(
        root / "acceptance-manifest.json", manifest.model_dump(mode="json")
    )
    return manifest, binding


@pytest.mark.parametrize(
    "case_fixture",
    ("accepted_v05_case", "rejected_v05_case"),
)
def test_acceptance_bundle_round_trip_is_fully_offline(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    case_fixture: str,
) -> None:
    case = request.getfixturevalue(case_fixture)
    root = tmp_path / f"round-trip-{case_fixture}"
    manifest, binding = _build_real_acceptance_bundle(case, root)
    result = bundle.verify_acceptance_bundle_directory(root)
    assert result.terminal_decision == (
        "ACCEPTED" if manifest.terminal_decision == "accepted" else "REJECTED"
    )
    assert result.acceptance_decision_binding_digest == binding.digest
    assert result.boundary == "not payment, settlement, legal audit, or adoption"


def _sync_outer_manifest(root: Path, relative: str) -> None:
    path = root.joinpath(*relative.split("/"))
    raw = json.loads((root / "acceptance-manifest.json").read_bytes())
    entry = next(item for item in raw["entries"] if item["path"] == relative)
    entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    entry["size_bytes"] = len(path.read_bytes())
    (root / "acceptance-manifest.json").write_bytes(_canonical(raw))


def _set_outer_summary(root: Path, **updates: object) -> None:
    path = root / "acceptance-manifest.json"
    raw = json.loads(path.read_bytes())
    raw.update(updates)
    path.write_bytes(_canonical(raw))


def test_acceptance_bundle_rejects_missing_binding(
    accepted_v05_case,
    tmp_path: Path,
) -> None:
    root = tmp_path / "missing-binding"
    _build_real_acceptance_bundle(accepted_v05_case, root)
    (root / "acceptance/decision-binding.json").unlink()
    raw = json.loads((root / "acceptance-manifest.json").read_bytes())
    raw["entries"] = [
        item
        for item in raw["entries"]
        if item["path"] != "acceptance/decision-binding.json"
    ]
    (root / "acceptance-manifest.json").write_bytes(_canonical(raw))
    with pytest.raises(bundle.AcceptanceBundleError):
        bundle.verify_acceptance_bundle_directory(root)


def test_acceptance_bundle_rejects_self_signed_binding_even_when_outer_synced(
    accepted_v05_case,
    tmp_path: Path,
) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from openworkproof.models import AcceptanceDecisionBindingV01
    from openworkproof.signing import sign_payload

    root = tmp_path / "self-signed-binding"
    _manifest, original = _build_real_acceptance_bundle(accepted_v05_case, root)
    payload = original.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    forged = AcceptanceDecisionBindingV01.model_validate(
        sign_payload(
            "acceptance-decision-binding",
            payload,
            Ed25519PrivateKey.generate(),
        )
    )
    _write_canonical(
        root / "acceptance/decision-binding.json",
        forged.model_dump(mode="json"),
    )
    _sync_outer_manifest(root, "acceptance/decision-binding.json")
    raw = json.loads((root / "acceptance-manifest.json").read_bytes())
    raw["acceptance_decision_binding_digest"] = forged.digest
    (root / "acceptance-manifest.json").write_bytes(_canonical(raw))
    with pytest.raises(bundle.AcceptanceBundleError, match="binding"):
        bundle.verify_acceptance_bundle_directory(root)


def test_acceptance_bundle_verifier_does_not_open_live_ledger(
    accepted_v05_case,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import openworkproof.evidence as evidence

    root = tmp_path / "offline-without-ledger"
    _build_real_acceptance_bundle(accepted_v05_case, root)

    def forbidden_live_ledger(*_args, **_kwargs):
        raise AssertionError("offline verification opened a live ledger")

    monkeypatch.setattr(evidence, "connect_ledger", forbidden_live_ledger)
    assert (
        bundle.verify_acceptance_bundle_directory(root).terminal_decision
        == "ACCEPTED"
    )


def test_acceptance_bundle_rejects_spliced_report_and_binding(
    accepted_v05_case,
    tmp_path: Path,
) -> None:
    import openworkproof.acceptance as acceptance
    from openworkproof.models import (
        AcceptanceDecisionBindingV01,
        CompositionReport,
        acceptance_decision_binding_id,
    )
    from openworkproof.signing import sign_payload

    accepted = tmp_path / "spliced-report"
    _manifest, original = _build_real_acceptance_bundle(
        accepted_v05_case,
        accepted,
    )
    reports_path = accepted / "acceptance/composition-reports.json"
    reports = json.loads(reports_path.read_bytes())
    assert len(reports) == 1
    spliced_raw = dict(reports[0])
    spliced_raw["composed_at"] = "2026-01-01T00:00:04Z"
    spliced_report = CompositionReport.model_validate(spliced_raw)
    reports_path.write_bytes(
        _canonical([spliced_report.model_dump(mode="json")])
    )
    payload = original.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    payload["composition_report_digest"] = acceptance.composition_report_digest(
        spliced_report
    )
    payload["binding_id"] = acceptance_decision_binding_id(payload)
    forged = AcceptanceDecisionBindingV01.model_validate(
        sign_payload(
            "acceptance-decision-binding",
            payload,
            accepted_v05_case["keys"]["Acceptor"][0],
        )
    )
    _write_canonical(
        accepted / "acceptance/decision-binding.json",
        forged.model_dump(mode="json"),
    )
    _sync_outer_manifest(accepted, "acceptance/composition-reports.json")
    _sync_outer_manifest(accepted, "acceptance/decision-binding.json")
    _set_outer_summary(
        accepted,
        composition_report_digest=payload["composition_report_digest"],
        acceptance_decision_binding_digest=forged.digest,
    )
    with pytest.raises(bundle.AcceptanceBundleError):
        bundle.verify_acceptance_bundle_directory(accepted)


@pytest.mark.parametrize(
    "field",
    (
        "verification_decision_digest",
        "composition_report_digest",
        "acceptance_request_receipt_digest",
        "terminal_receipt_digest",
    ),
)
def test_acceptance_bundle_rejects_resigned_binding_field_swap(
    accepted_v05_case,
    tmp_path: Path,
    field: str,
) -> None:
    from openworkproof.models import (
        AcceptanceDecisionBindingV01,
        acceptance_decision_binding_id,
    )
    from openworkproof.signing import sign_payload

    root = tmp_path / f"resigned-{field}"
    _manifest, original = _build_real_acceptance_bundle(
        accepted_v05_case,
        root,
    )
    payload = original.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    payload[field] = "0" * 64
    payload["binding_id"] = acceptance_decision_binding_id(payload)
    forged = AcceptanceDecisionBindingV01.model_validate(
        sign_payload(
            "acceptance-decision-binding",
            payload,
            accepted_v05_case["keys"]["Acceptor"][0],
        )
    )
    _write_canonical(
        root / "acceptance/decision-binding.json",
        forged.model_dump(mode="json"),
    )
    _sync_outer_manifest(root, "acceptance/decision-binding.json")
    _set_outer_summary(
        root,
        acceptance_decision_binding_digest=forged.digest,
    )
    with pytest.raises(bundle.AcceptanceBundleError, match="binding"):
        bundle.verify_acceptance_bundle_directory(root)


@pytest.mark.parametrize(
    ("relative", "payload"),
    (
        ("acceptance/effective-grants.json", b"{"),
        ("acceptance/grant-attempts.json", _canonical({})),
        ("acceptance/composition-reports.json", _canonical([{}])),
        ("acceptance/committed-evidence-index.json", _canonical([])),
        ("acceptance/terminal-receipt.json", _canonical({})),
        ("acceptance/decision-binding.json", _canonical({})),
    ),
)
def test_acceptance_bundle_closes_companion_parse_errors(
    accepted_v05_case,
    tmp_path: Path,
    relative: str,
    payload: bytes,
) -> None:
    root = tmp_path / f"closed-{Path(relative).name}"
    _build_real_acceptance_bundle(accepted_v05_case, root)
    root.joinpath(*relative.split("/")).write_bytes(payload)
    _sync_outer_manifest(root, relative)
    with pytest.raises(bundle.AcceptanceBundleError):
        bundle.verify_acceptance_bundle_directory(root)


def test_acceptance_bundle_closes_nested_operational_errors(
    accepted_v05_case,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import openworkproof.surface_bundle as surface_bundle

    root = tmp_path / "closed-surface-oserror"
    _build_real_acceptance_bundle(accepted_v05_case, root)

    def fail_surface(_root: Path):
        raise OSError("simulated snapshot failure")

    monkeypatch.setattr(surface_bundle, "verify_surface_bundle", fail_surface)
    with pytest.raises(bundle.AcceptanceBundleError) as captured:
        bundle.verify_acceptance_bundle_directory(root)
    assert type(captured.value) is bundle.AcceptanceBundleError
