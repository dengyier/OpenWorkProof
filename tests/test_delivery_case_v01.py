"""Verified Delivery Case 0.1 — model, initialization, status, export gates."""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import stat
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
import rfc8785
from pydantic import ValidationError

from openworkproof.delivery_case import (
    DeliveryCaseError,
    DeliveryCaseManifestV01,
    DeliveryCaseResultV01,
    DeliveryCaseStage,
    ExternalEvidenceReferenceV01,
    initialize_delivery_case,
    inspect_delivery_case,
)
from openworkproof.surface_bundle import verify_surface_bundle

from test_acceptance_bundle_v01 import (
    _build_real_acceptance_bundle as _build_real_acceptance_bundle,
    _build_surface_from_ledger as _build_surface_from_ledger,
)
from test_acceptance_decision_binding_v01 import (
    accepted_v05_case as accepted_v05_case,
    rejected_v05_case as rejected_v05_case,
    _stub_candidate_execution_snapshot as _stub_candidate_execution_snapshot,
)


_FIXED_NOW = datetime(2026, 8, 22, tzinfo=timezone.utc)


def test_case_manifest_is_closed_and_contains_no_runtime_status() -> None:
    payload = {
        "schema_version": "openworkproof-delivery-case/0.1",
        "case_id": "1" * 64,
        "profile": "coding-agent",
        "buyer_alias": "buyer",
        "delivery_provider_alias": "provider",
        "created_at": "2026-08-22T00:00:00Z",
    }
    case = DeliveryCaseManifestV01.model_validate(payload)
    assert "case_stage" not in DeliveryCaseManifestV01.model_fields
    with pytest.raises(ValidationError):
        DeliveryCaseManifestV01.model_validate({**payload, "case_stage": "ACCEPTED"})


@pytest.mark.parametrize("field", ("reference_digest", "observed_at"))
def test_not_evidenced_reference_cannot_carry_evidence(field: str) -> None:
    payload = {
        "schema_version": "openworkproof-external-evidence/0.1",
        "status": "not_evidenced",
        "reference_digest": None,
        "observed_at": None,
    }
    payload[field] = "2" * 64 if field == "reference_digest" else "2026-08-22T00:00:00Z"
    with pytest.raises(ValidationError):
        ExternalEvidenceReferenceV01.model_validate(payload)


def test_initialize_case_writes_only_closed_non_secret_templates(tmp_path) -> None:
    root = tmp_path / "case"
    result = initialize_delivery_case(
        root,
        case_id="3" * 64,
        now=datetime(2026, 8, 22, tzinfo=timezone.utc),
    )
    assert result.case_id == "3" * 64
    assert sorted(
        str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()
    ) == [
        "case.json",
        "commercial/payer-status.json",
        "commercial/scorecard.json",
        "commercial/sow-reference.json",
    ]
    assert json.loads((root / "commercial/sow-reference.json").read_text())[
        "status"
    ] == "not_evidenced"


def test_initialize_case_never_overwrites_existing_target(tmp_path) -> None:
    root = tmp_path / "case"
    root.mkdir()
    (root / "owner.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(DeliveryCaseError, match="already exists"):
        initialize_delivery_case(root, case_id="3" * 64)
    assert (root / "owner.txt").read_text(encoding="utf-8") == "keep"


def test_initialize_case_rejects_symlink_target(tmp_path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "case"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(DeliveryCaseError, match="already exists"):
        initialize_delivery_case(link, case_id="3" * 64)
    assert real.is_dir()


def test_initialize_case_writes_private_permissions(tmp_path) -> None:
    root = tmp_path / "case"
    initialize_delivery_case(root, case_id="3" * 64)
    for path in root.rglob("*"):
        if path.is_file():
            assert stat.S_IMODE(path.lstat().st_mode) == 0o600, path
        else:
            assert stat.S_IMODE(path.lstat().st_mode) == 0o700, path


def test_initialize_case_scorecard_has_fixed_keys(tmp_path) -> None:
    root = tmp_path / "case"
    initialize_delivery_case(root, case_id="3" * 64)
    scorecard = json.loads((root / "commercial/scorecard.json").read_text())
    assert set(scorecard) == {
        "schema_version",
        "outreach_sent",
        "buyer_interviewed",
        "sow_signed",
        "deposit_evidenced",
        "delivery_verified",
        "customer_accepted",
        "external_payment_evidenced",
        "repeat_order_evidenced",
    }
    for key in (
        "outreach_sent",
        "buyer_interviewed",
        "sow_signed",
        "deposit_evidenced",
        "delivery_verified",
        "customer_accepted",
        "external_payment_evidenced",
        "repeat_order_evidenced",
    ):
        assert scorecard[key] == "not_evidenced"


def test_initialize_case_defaults_case_id_and_now(tmp_path) -> None:
    import openworkproof.delivery_case as delivery_case

    root = tmp_path / "case"
    result = initialize_delivery_case(root)
    assert len(result.case_id) == 64
    assert result.created_at.microsecond == 0
    assert result.created_at.tzinfo is not None


def test_initialize_case_precommit_fault_is_zero_write(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import openworkproof.delivery_case as delivery_case

    root = tmp_path / "case"
    real_rename = os.rename

    def failing_rename(source, destination):
        raise OSError("injected pre-commit fault")

    monkeypatch.setattr(delivery_case.os, "rename", failing_rename)
    with pytest.raises(DeliveryCaseError):
        initialize_delivery_case(root, case_id="3" * 64)
    assert not root.exists()
    assert len(list(tmp_path.iterdir())) == 0


def test_initialize_case_rename_conflict_raises(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import openworkproof.delivery_case as delivery_case

    root = tmp_path / "case"

    def conflicting_rename(source, destination):
        raise FileExistsError("target appeared")

    monkeypatch.setattr(delivery_case.os, "rename", conflicting_rename)
    with pytest.raises(DeliveryCaseError, match="already exists"):
        initialize_delivery_case(root, case_id="3" * 64)
    assert not root.exists()


def test_initialize_case_cleanup_failure_raises(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import openworkproof.delivery_case as delivery_case

    root = tmp_path / "case"
    real_rename = os.rename

    def failing_rename(source, destination):
        raise OSError("injected commit fault")

    monkeypatch.setattr(delivery_case.os, "rename", failing_rename)

    def failing_rmtree(path):
        raise OSError("injected cleanup fault")

    monkeypatch.setattr(delivery_case.shutil, "rmtree", failing_rmtree)
    with pytest.raises(DeliveryCaseError, match="cleanup"):
        initialize_delivery_case(root, case_id="3" * 64)
    assert not root.exists()


def _write_sow(root, *, evidenced: bool = True) -> None:
    sow = ExternalEvidenceReferenceV01.model_validate(
        {
            "schema_version": "openworkproof-external-evidence/0.1",
            "status": "external_reference_present" if evidenced else "not_evidenced",
            "reference_digest": "4" * 64 if evidenced else None,
            "observed_at": "2026-08-22T00:00:00Z" if evidenced else None,
        }
    )
    (root / "commercial/sow-reference.json").write_bytes(
        rfc8785.dumps(sow.model_dump(mode="json"))
    )


def _populate_surface(root: Path, case) -> None:
    """Build a real surface bundle into root/surface from a sibling stage."""
    stage = root.parent / f"{root.name}-surface-stage"
    stage.mkdir()
    (root / "surface").rmdir()
    _build_surface_from_ledger(case, stage / "surface")
    os.rename(stage / "surface", root / "surface")
    shutil.rmtree(stage)


def _populate_bundles(root: Path, case) -> None:
    """Build real surface + acceptance bundles into root from a sibling stage."""
    stage = root.parent / f"{root.name}-bundle-stage"
    stage.mkdir()
    (root / "surface").rmdir()
    (root / "acceptance").rmdir()
    _build_real_acceptance_bundle(case, stage / "acceptance")
    shutil.copytree(stage / "acceptance" / "surface", root / "surface")
    os.rename(stage / "acceptance", root / "acceptance")
    shutil.rmtree(stage)


@pytest.fixture
def full_delivery_case(tmp_path, accepted_v05_case):
    """One complete accepted case: surface + accepted acceptance + settlement."""
    case = accepted_v05_case
    root = tmp_path / "case"
    initialize_delivery_case(root, case_id="3" * 64, now=_FIXED_NOW)
    _write_sow(root, evidenced=True)
    _populate_bundles(root, case)
    from openworkproof.settlement import read_settlement_snapshot

    snapshot = read_settlement_snapshot(case["ledger_path"])
    (root / "settlement" / "settlement-status.json").write_bytes(
        rfc8785.dumps(snapshot.model_dump(mode="json"))
    )
    return root, case


@pytest.fixture
def rejected_delivery_case(tmp_path, rejected_v05_case):
    case = rejected_v05_case
    root = tmp_path / "case"
    initialize_delivery_case(root, case_id="3" * 64, now=_FIXED_NOW)
    _write_sow(root, evidenced=True)
    _populate_bundles(root, case)
    return root, case


def test_inspect_case_with_sow_but_no_surface_is_sow_referenced(tmp_path) -> None:
    root = tmp_path / "case"
    initialize_delivery_case(root, case_id="3" * 64, now=_FIXED_NOW)
    _write_sow(root, evidenced=True)
    result = inspect_delivery_case(root)
    assert result.case_stage == "SOW_REFERENCED"
    assert result.reason_codes == ("SURFACE_MISSING",)


def test_inspect_case_without_sow_is_scope_drafted(tmp_path) -> None:
    root = tmp_path / "case"
    initialize_delivery_case(root, case_id="3" * 64, now=_FIXED_NOW)
    result = inspect_delivery_case(root)
    assert result.case_stage == "SCOPE_DRAFTED"
    assert result.reason_codes == ("SOW_NOT_EVIDENCED",)


def test_inspect_verified_surface_without_acceptance_is_ready_for_acceptance(
    tmp_path, accepted_v05_case
) -> None:
    case = accepted_v05_case
    root = tmp_path / "case"
    initialize_delivery_case(root, case_id="3" * 64, now=_FIXED_NOW)
    _write_sow(root, evidenced=True)
    _populate_surface(root, case)
    result = inspect_delivery_case(root)
    assert result.case_stage == "READY_FOR_ACCEPTANCE"
    assert result.reason_codes == ("ACCEPTANCE_MISSING",)
    assert result.verification_decision == "VERIFIED"


def test_inspect_rejected_acceptance_is_rejected(rejected_delivery_case) -> None:
    root, _ = rejected_delivery_case
    result = inspect_delivery_case(root)
    assert result.case_stage == "REJECTED"
    assert result.reason_codes == ("CUSTOMER_REJECTED",)
    assert result.acceptance_decision == "REJECTED"


def test_inspect_accepted_without_settlement_is_accepted(full_delivery_case) -> None:
    root, _ = full_delivery_case
    (root / "settlement" / "settlement-status.json").unlink()
    result = inspect_delivery_case(root)
    assert result.case_stage == "ACCEPTED"
    assert result.reason_codes == ("SETTLEMENT_STATUS_MISSING",)
    assert result.acceptance_decision == "ACCEPTED"


def test_inspect_full_case_is_ready_for_settlement_review(full_delivery_case) -> None:
    root, _ = full_delivery_case
    result = inspect_delivery_case(root)
    assert result.case_stage == "READY_FOR_SETTLEMENT_REVIEW"
    assert result.reason_codes == ("PAYMENT_NOT_EVIDENCED",)
    assert result.verification_decision == "VERIFIED"
    assert result.acceptance_decision == "ACCEPTED"
    assert result.payment_evidence == "not_evidenced"
    assert result.settlement_readiness is not None


def test_inspect_unknown_surface_is_unknown(
    full_delivery_case, monkeypatch: pytest.MonkeyPatch
) -> None:
    import openworkproof.delivery_case as delivery_case

    root, _ = full_delivery_case
    monkeypatch.setattr(
        delivery_case,
        "verify_surface_bundle",
        lambda _path: SimpleNamespace(
            report=SimpleNamespace(decision_status="UNKNOWN"),
            manifest_digest="a" * 64,
        ),
    )
    result = inspect_delivery_case(root)
    assert result.case_stage == "UNKNOWN"
    assert result.reason_codes == ("SURFACE_UNKNOWN",)


def test_inspect_refuted_surface_is_refuted(
    full_delivery_case, monkeypatch: pytest.MonkeyPatch
) -> None:
    import openworkproof.delivery_case as delivery_case

    root, _ = full_delivery_case
    monkeypatch.setattr(
        delivery_case,
        "verify_surface_bundle",
        lambda _path: SimpleNamespace(
            report=SimpleNamespace(decision_status="REFUTED"),
            manifest_digest="a" * 64,
        ),
    )
    result = inspect_delivery_case(root)
    assert result.case_stage == "REFUTED"
    assert result.reason_codes == ("SURFACE_REFUTED",)


def test_inspect_rejects_surface_acceptance_digest_mismatch(
    full_delivery_case, monkeypatch: pytest.MonkeyPatch
) -> None:
    import openworkproof.delivery_case as delivery_case

    root, _ = full_delivery_case
    real = verify_surface_bundle(root / "surface")
    spliced = dataclasses.replace(real, manifest_digest="f" * 64)
    monkeypatch.setattr(
        delivery_case, "verify_surface_bundle", lambda _path: spliced
    )
    with pytest.raises(DeliveryCaseError, match="one delivery"):
        inspect_delivery_case(root)


def test_inspect_rejects_settlement_decision_id_mismatch(
    full_delivery_case, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _ = full_delivery_case
    settlement = root / "settlement" / "settlement-status.json"
    raw = json.loads(settlement.read_bytes())
    raw["current_decision_id"] = "e" * 64
    settlement.write_bytes(rfc8785.dumps(raw))
    with pytest.raises(DeliveryCaseError):
        inspect_delivery_case(root)


def test_inspect_rejects_prewritten_positive_result(full_delivery_case) -> None:
    root, _ = full_delivery_case
    (root / "delivery-result.json").write_bytes(
        rfc8785.dumps(
            {
                "schema_version": "openworkproof-delivery-case-result/0.1",
                "case_stage": "READY_FOR_SETTLEMENT_REVIEW",
            }
        )
    )
    with pytest.raises(DeliveryCaseError):
        inspect_delivery_case(root)


def test_inspect_rejects_non_canonical_sow(full_delivery_case) -> None:
    root, _ = full_delivery_case
    sow = root / "commercial" / "sow-reference.json"
    raw = json.loads(sow.read_bytes())
    sow.write_bytes(json.dumps(raw, indent=2).encode("utf-8"))
    with pytest.raises(DeliveryCaseError):
        inspect_delivery_case(root)


@pytest.mark.parametrize("kind", ("symlink", "hardlink", "fifo"))
def test_inspect_rejects_unsafe_case_entry(
    full_delivery_case, kind: str
) -> None:
    root, _ = full_delivery_case
    hostile = root / "protocol" / "hostile"
    if kind == "symlink":
        hostile.symlink_to("../case.json")
    elif kind == "hardlink":
        os.link(root / "case.json", hostile)
    else:
        os.mkfifo(hostile)
    try:
        with pytest.raises(DeliveryCaseError):
            inspect_delivery_case(root)
    finally:
        hostile.unlink(missing_ok=True)


def test_inspect_rejects_unknown_file(full_delivery_case) -> None:
    root, _ = full_delivery_case
    (root / "evil.txt").write_text("nope", encoding="utf-8")
    with pytest.raises(DeliveryCaseError, match="unknown"):
        inspect_delivery_case(root)


@pytest.fixture
def verified_result(full_delivery_case) -> DeliveryCaseResultV01:
    root, _ = full_delivery_case
    return inspect_delivery_case(root)


def test_summary_answers_business_questions_without_overclaim(
    verified_result: DeliveryCaseResultV01,
) -> None:
    from openworkproof.delivery_case_render import render_delivery_summary

    rendered = render_delivery_summary(verified_result)
    for text in (
        "Who authorized",
        "What was executed",
        "Who verified",
        "Can the buyer accept",
        "Settlement review",
    ):
        assert text in rendered
    assert "payment completed" not in rendered.lower()
    assert "guaranteed" not in rendered.lower()
    assert "/Users/" not in rendered


def test_render_delivery_result_is_canonical_json(
    verified_result: DeliveryCaseResultV01,
) -> None:
    from openworkproof.delivery_case_render import render_delivery_result

    payload = render_delivery_result(verified_result)
    assert rfc8785.dumps(verified_result.model_dump(mode="json")) == payload
    assert json.loads(payload)["case_id"] == verified_result.case_id


def test_export_is_no_replace_and_self_verifies(full_delivery_case, tmp_path) -> None:
    from openworkproof.delivery_case import export_delivery_case

    root, _ = full_delivery_case
    output = tmp_path / "export"
    first = export_delivery_case(root, output)
    assert first.case_stage == "READY_FOR_SETTLEMENT_REVIEW"
    with pytest.raises(DeliveryCaseError, match="already exists"):
        export_delivery_case(root, output)


def test_export_produces_exact_allowlist_file_set(full_delivery_case, tmp_path) -> None:
    from openworkproof.delivery_case import export_delivery_case

    root, _ = full_delivery_case
    output = tmp_path / "export"
    export_delivery_case(root, output)
    top_level = sorted(
        path.relative_to(output).as_posix()
        for path in output.iterdir()
    )
    assert top_level == [
        "case",
        "delivery-case-manifest.json",
        "delivery-result.json",
        "delivery-summary.md",
    ]
    assert (output / "delivery-case-manifest.json").is_file()
    assert (output / "delivery-result.json").is_file()
    assert (output / "delivery-summary.md").is_file()


def test_export_round_trips_through_verify(full_delivery_case, tmp_path) -> None:
    from openworkproof.delivery_case import (
        export_delivery_case,
        verify_exported_delivery_case,
    )

    root, _ = full_delivery_case
    output = tmp_path / "export"
    exported = export_delivery_case(root, output)
    verified = verify_exported_delivery_case(output)
    assert verified == exported


def test_export_rejects_tampered_case_file(full_delivery_case, tmp_path) -> None:
    from openworkproof.delivery_case import (
        DeliveryCaseError,
        export_delivery_case,
        verify_exported_delivery_case,
    )

    root, _ = full_delivery_case
    output = tmp_path / "export"
    export_delivery_case(root, output)
    tampered = output / "case" / "settlement" / "settlement-status.json"
    tampered.write_bytes(tampered.read_bytes() + b"tamper")
    with pytest.raises(DeliveryCaseError):
        verify_exported_delivery_case(output)


def test_export_manifest_is_integrity_only(full_delivery_case, tmp_path) -> None:
    from openworkproof.delivery_case import export_delivery_case

    root, _ = full_delivery_case
    output = tmp_path / "export"
    export_delivery_case(root, output)
    manifest = json.loads(
        (output / "delivery-case-manifest.json").read_text(encoding="utf-8")
    )
    assert "integrity only" in manifest["boundary"]
    assert "trust root" in manifest["boundary"]
    assert manifest["schema_version"] == "openworkproof-delivery-case-manifest/0.1"
    paths = {entry["path"] for entry in manifest["entries"]}
    assert "delivery-case-manifest.json" not in paths
    assert "delivery-result.json" in paths
    assert "delivery-summary.md" in paths
    assert "case/case.json" in paths


def test_export_contains_no_secret_or_absolute_path(
    full_delivery_case, tmp_path
) -> None:
    from openworkproof.delivery_case import export_delivery_case

    root, _ = full_delivery_case
    output = tmp_path / "export"
    export_delivery_case(root, output)
    combined = b"".join(
        path.read_bytes() for path in output.rglob("*") if path.is_file()
    )
    text = combined.decode("utf-8", errors="replace")
    assert str(tmp_path) not in text
    assert "private_key" not in text
    assert "PRIVATE KEY" not in text
