"""Verified Delivery Case 0.1 — model, initialization, status, export gates."""

from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from openworkproof.delivery_case import (
    DeliveryCaseError,
    DeliveryCaseManifestV01,
    ExternalEvidenceReferenceV01,
    initialize_delivery_case,
)


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
