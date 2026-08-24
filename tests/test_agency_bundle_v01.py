"""Offline boundary-bundle gates for Human Agency Profile 0.1.

This file covers the deterministic exporter and the pure offline verifier for
the agency boundary bundle. The bundle proves, for one frozen evaluation second,
the WorkOrder, its key bindings, the full profile/transition history, and the
appeals, together with the re-resolved authorization boundary status. It never
contains a private key and never trusts a caller-supplied ``now``.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

import openworkproof.agency_bundle as bundle
import openworkproof.evidence as evidence
from openworkproof.agency import (
    AgencyAppealV01,
    AgencyProfileTransitionV01,
    HumanAgencyProfileV01,
    agency_appeal_id,
    agency_profile_transition_id,
    delegated_action_id,
    human_agency_profile_id,
)
from openworkproof.agency_ledger import (
    commit_agency_appeal,
    commit_agency_profile_transition,
    commit_human_agency_profile,
)
from openworkproof.models import WorkOrder
from openworkproof.signing import digest_payload, sign_payload

from conftest import EPHEMERAL_ROLES, SHA256_A, SHA256_B, SHA256_C, SHA256_E

_ACTIVE_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _canonical(value: object) -> bytes:
    return rfc8785.dumps(value)


@dataclass(frozen=True)
class _AgencyCase:
    work_order: WorkOrder
    keys: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]]


@pytest.fixture
def agency_case(
    signed_work_order: WorkOrder,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> _AgencyCase:
    return _AgencyCase(
        work_order=signed_work_order,
        keys=ephemeral_role_keys,
    )


@pytest.fixture
def ledger_case(
    tmp_path: Path,
    signed_work_order: WorkOrder,
) -> dict[str, Any]:
    ledger = tmp_path / "agency-ledger.sqlite3"
    evidence.initialize_ledger(ledger, signed_work_order)
    return {"ledger": ledger, "work_order": signed_work_order}


def _mk_profile(
    case: _AgencyCase,
    nonce: str,
    *,
    delegated: tuple[str, ...] = ("owp.repo_read",),
    issued_at: str = "2026-01-01T00:00:00Z",
    valid_from: str = "2026-01-01T00:00:01Z",
    expires_at: str = "2026-01-01T23:59:59Z",
    signer: str = "Acceptor",
) -> HumanAgencyProfileV01:
    payload = {
        "schema_version": "openworkproof-human-agency-profile/0.1",
        "work_order_digest": case.work_order.digest,
        "delegated_actions": [
            {
                "action_id": delegated_action_id(
                    {"tool_name": tool, "autonomy": "delegated"}
                ),
                "tool_name": tool,
                "autonomy": "delegated",
            }
            for tool in delegated
        ],
        "reserved_decisions": [],
        "escalation_conditions": [{"condition_code": "reserved_decision_requested"}],
        "revocation_and_appeal": {
            "revocation_mode": "acceptor_signed_transition",
            "appeal_mode": "signed_request_then_acceptor_decision",
            "appeal_roles": ["Developer", "Manager", "Verifier"],
        },
        "valid_from": valid_from,
        "expires_at": expires_at,
        "issued_at": issued_at,
        "nonce": nonce,
    }
    payload["profile_id"] = human_agency_profile_id(payload)
    return HumanAgencyProfileV01.model_validate(
        sign_payload("human-agency-profile", payload, case.keys[signer][0])
    )


def _mk_transition(
    case: _AgencyCase,
    *,
    target: HumanAgencyProfileV01,
    transition: str = "revoked",
    replacement: HumanAgencyProfileV01 | None = None,
    transitioned_at: str = "2026-01-01T02:00:00Z",
    nonce: str = SHA256_C,
    signer: str = "Acceptor",
) -> AgencyProfileTransitionV01:
    payload = {
        "schema_version": "openworkproof-agency-profile-transition/0.1",
        "work_order_digest": case.work_order.digest,
        "target_profile_id": target.profile_id,
        "target_profile_digest": target.digest,
        "transition": transition,
        "replacement_profile_id": (
            replacement.profile_id if replacement is not None else None
        ),
        "replacement_profile_digest": (
            replacement.digest if replacement is not None else None
        ),
        "reason_code": (
            "scope_changed" if transition == "superseded" else "human_withdrawal"
        ),
        "transitioned_at": transitioned_at,
        "nonce": nonce,
    }
    payload["transition_id"] = agency_profile_transition_id(payload)
    return AgencyProfileTransitionV01.model_validate(
        sign_payload("agency-profile-transition", payload, case.keys[signer][0])
    )


def _mk_appeal(
    case: _AgencyCase,
    *,
    profile: HumanAgencyProfileV01,
    role: str = "Manager",
    nonce: str = SHA256_A,
) -> AgencyAppealV01:
    binding = case.keys[role][1]
    payload = {
        "schema_version": "openworkproof-agency-appeal/0.1",
        "work_order_digest": case.work_order.digest,
        "profile_id": profile.profile_id,
        "profile_digest": profile.digest,
        "appellant_role": role,
        "appellant_subject_id": binding["subject_id"],
        "requested_change_digest": SHA256_E,
        "reason_code": "task_blocked",
        "created_at": "2026-01-01T01:05:00Z",
        "nonce": nonce,
    }
    payload["appeal_id"] = agency_appeal_id(payload)
    return AgencyAppealV01.model_validate(
        sign_payload("agency-appeal", payload, case.keys[role][0])
    )


def _bundle_files(
    work_order: WorkOrder,
    profiles: tuple[HumanAgencyProfileV01, ...] = (),
    transitions: tuple[AgencyProfileTransitionV01, ...] = (),
    appeals: tuple[AgencyAppealV01, ...] = (),
) -> dict[str, bytes]:
    files: dict[str, bytes] = {
        "agency/work-order.json": _canonical(work_order.model_dump(mode="json")),
        "verify.sh": bundle.AGENCY_VERIFY_SCRIPT,
    }
    for profile in profiles:
        files[f"agency/profiles/{profile.profile_id}.json"] = _canonical(
            profile.model_dump(mode="json")
        )
    for transition in transitions:
        files[
            f"agency/transitions/{transition.transition_id}.json"
        ] = _canonical(transition.model_dump(mode="json"))
    for appeal in appeals:
        files[f"agency/appeals/{appeal.appeal_id}.json"] = _canonical(
            appeal.model_dump(mode="json")
        )
    return files


def _write_bundle(
    root: Path,
    files: dict[str, bytes],
    *,
    work_order_digest: str,
    evaluated_at: str,
    current_status: str,
    current_profile_id: str | None,
    sidecar_private_key: Ed25519PrivateKey,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for relative, payload in files.items():
        target = root.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    (root / "verify.sh").chmod(0o700)
    manifest = bundle.compose_agency_manifest(
        files,
        work_order_digest=work_order_digest,
        evaluated_at=evaluated_at,
        current_status=current_status,
        current_profile_id=current_profile_id,
        sidecar_private_key=sidecar_private_key,
    )
    (root / "agency-manifest.json").write_bytes(
        _canonical(manifest.model_dump(mode="json"))
    )
    return root


def _keyless_rebuild_manifest(raw: dict[str, Any]) -> dict[str, Any]:
    """Rebuild the manifest digest without the Sidecar private key.

    A keyless attacker can recompute the public SHA-256 digest over the edited
    unsigned content but cannot forge the Ed25519 signature, so the signature
    field is deliberately left stale.
    """

    unsigned = {
        key: value
        for key, value in raw.items()
        if key not in {"digest", "signature"}
    }
    raw["digest"] = digest_payload("manifest", unsigned)
    return raw


def _sign_other_work_order(case: _AgencyCase) -> WorkOrder:
    candidate = case.work_order.model_dump(mode="json")
    for field in ("digest", "signature", "signature_alg", "signer_key_id"):
        candidate.pop(field, None)
    candidate["objective"] = "A second objective to fork the WorkOrder digest."
    return WorkOrder.model_validate(
        sign_payload("work-order", candidate, case.keys["Maintainer"][0])
    )


# --- exporter: status and self-verification ---


def test_export_active_bundle_self_verifies(
    tmp_path: Path,
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    output = tmp_path / "agency-bundle"
    manifest = bundle.export_agency_bundle(
        ledger_case["ledger"], output, sidecar_private_key=agency_case.keys["Sidecar"][0], clock=lambda: _ACTIVE_NOW
    )
    assert manifest.current_status == "active"
    assert manifest.current_profile_id == profile.profile_id
    assert manifest.boundary == bundle.AGENCY_BUNDLE_BOUNDARY

    result = bundle.verify_agency_bundle_directory(output)
    assert result.current_status == "active"
    assert result.current_profile_id == profile.profile_id
    assert result.work_order_digest == agency_case.work_order.digest
    assert result.appeal_count == 0
    assert result.boundary == bundle.AGENCY_BUNDLE_BOUNDARY


def test_export_revoked_bundle(
    tmp_path: Path,
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    revoke = _mk_transition(agency_case, target=profile, transition="revoked")
    commit_agency_profile_transition(ledger_case["ledger"], revoke)

    output = tmp_path / "agency-bundle"
    manifest = bundle.export_agency_bundle(
        ledger_case["ledger"], output, sidecar_private_key=agency_case.keys["Sidecar"][0], clock=lambda: _ACTIVE_NOW
    )
    assert manifest.current_status == "revoked"
    assert manifest.current_profile_id is None
    result = bundle.verify_agency_bundle_directory(output)
    assert result.current_status == "revoked"
    assert result.current_profile_id is None


def test_export_expired_bundle(
    tmp_path: Path,
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(
        agency_case,
        SHA256_A,
        valid_from="2026-01-01T00:00:01Z",
        expires_at="2026-01-01T00:01:00Z",
    )
    commit_human_agency_profile(ledger_case["ledger"], profile)

    output = tmp_path / "agency-bundle"
    manifest = bundle.export_agency_bundle(
        ledger_case["ledger"], output, sidecar_private_key=agency_case.keys["Sidecar"][0], clock=lambda: _ACTIVE_NOW
    )
    assert manifest.current_status == "expired"
    assert manifest.current_profile_id == profile.profile_id
    result = bundle.verify_agency_bundle_directory(output)
    assert result.current_status == "expired"
    assert result.current_profile_id == profile.profile_id


def test_export_counts_appeals(
    tmp_path: Path,
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    appeal = _mk_appeal(agency_case, profile=profile)
    commit_agency_appeal(ledger_case["ledger"], appeal)

    output = tmp_path / "agency-bundle"
    bundle.export_agency_bundle(
        ledger_case["ledger"], output, sidecar_private_key=agency_case.keys["Sidecar"][0], clock=lambda: _ACTIVE_NOW
    )
    result = bundle.verify_agency_bundle_directory(output)
    assert result.appeal_count == 1


def test_export_is_deterministic_under_fixed_clock(
    tmp_path: Path,
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    appeal = _mk_appeal(agency_case, profile=profile)
    commit_agency_appeal(ledger_case["ledger"], appeal)

    first = tmp_path / "first"
    second = tmp_path / "second"
    bundle.export_agency_bundle(
        ledger_case["ledger"], first, sidecar_private_key=agency_case.keys["Sidecar"][0], clock=lambda: _ACTIVE_NOW
    )
    bundle.export_agency_bundle(
        ledger_case["ledger"], second, sidecar_private_key=agency_case.keys["Sidecar"][0], clock=lambda: _ACTIVE_NOW
    )
    first_files = {
        path.relative_to(first).as_posix(): path.read_bytes()
        for path in first.rglob("*")
        if path.is_file()
    }
    second_files = {
        path.relative_to(second).as_posix(): path.read_bytes()
        for path in second.rglob("*")
        if path.is_file()
    }
    assert first_files == second_files


def test_export_contains_no_private_keys(
    tmp_path: Path,
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)

    output = tmp_path / "agency-bundle"
    bundle.export_agency_bundle(
        ledger_case["ledger"], output, sidecar_private_key=agency_case.keys["Sidecar"][0], clock=lambda: _ACTIVE_NOW
    )
    private_bytes = {
        role: private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        for role, (private_key, _binding) in agency_case.keys.items()
    }
    for path in output.rglob("*"):
        if not path.is_file():
            continue
        payload = path.read_bytes()
        for role, raw in private_bytes.items():
            assert raw not in payload, f"{role} private key leaked into {path}"
        assert b"PRIVATE KEY" not in payload
        assert b"BEGIN " not in payload


# --- verifier: filesystem safety ---


def test_verify_rejects_extra_file(
    tmp_path: Path,
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    output = tmp_path / "agency-bundle"
    bundle.export_agency_bundle(
        ledger_case["ledger"], output, sidecar_private_key=agency_case.keys["Sidecar"][0], clock=lambda: _ACTIVE_NOW
    )
    (output / "agency" / "extra.json").write_text("{}", encoding="utf-8")
    with pytest.raises(bundle.AgencyBundleError, match="file set"):
        bundle.verify_agency_bundle_directory(output)


def test_verify_rejects_extra_empty_directory(
    tmp_path: Path,
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    output = tmp_path / "agency-bundle"
    bundle.export_agency_bundle(
        ledger_case["ledger"], output, sidecar_private_key=agency_case.keys["Sidecar"][0], clock=lambda: _ACTIVE_NOW
    )
    (output / "unexpected").mkdir()
    with pytest.raises(bundle.AgencyBundleError, match="directory set"):
        bundle.verify_agency_bundle_directory(output)


def test_verify_rejects_missing_file(
    tmp_path: Path,
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    output = tmp_path / "agency-bundle"
    bundle.export_agency_bundle(
        ledger_case["ledger"], output, sidecar_private_key=agency_case.keys["Sidecar"][0], clock=lambda: _ACTIVE_NOW
    )
    (output / "agency" / "work-order.json").unlink()
    with pytest.raises(bundle.AgencyBundleError):
        bundle.verify_agency_bundle_directory(output)


@pytest.mark.parametrize("kind", ("symlink", "hardlink"))
def test_verify_rejects_link_files(
    tmp_path: Path,
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
    kind: str,
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    output = tmp_path / "agency-bundle"
    bundle.export_agency_bundle(
        ledger_case["ledger"], output, sidecar_private_key=agency_case.keys["Sidecar"][0], clock=lambda: _ACTIVE_NOW
    )
    hostile = output / "hostile"
    if kind == "symlink":
        hostile.symlink_to(output / "verify.sh")
    else:
        os.link(output / "verify.sh", hostile)
    try:
        with pytest.raises(bundle.AgencyBundleError):
            bundle.verify_agency_bundle_directory(output)
    finally:
        hostile.unlink(missing_ok=True)


def test_relative_path_rejects_traversal() -> None:
    for unsafe in (
        "/absolute",
        "../escape",
        "a/../b",
        "a\\b",
        "a\x00b",
        "a//b",
        "a/./b",
    ):
        with pytest.raises(ValueError):
            bundle._agency_relative_path(unsafe)


# --- verifier: byte tamper matrix ---


@pytest.mark.parametrize("kind", ("work-order", "profile", "transition", "appeal"))
def test_verify_rejects_every_object_byte_tamper(
    tmp_path: Path,
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
    kind: str,
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    replacement = _mk_profile(agency_case, SHA256_B)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    commit_human_agency_profile(ledger_case["ledger"], replacement)
    transition = _mk_transition(
        agency_case,
        target=profile,
        transition="superseded",
        replacement=replacement,
    )
    commit_agency_profile_transition(ledger_case["ledger"], transition)
    appeal = _mk_appeal(agency_case, profile=profile)
    commit_agency_appeal(ledger_case["ledger"], appeal)

    output = tmp_path / "agency-bundle"
    bundle.export_agency_bundle(
        ledger_case["ledger"], output, sidecar_private_key=agency_case.keys["Sidecar"][0], clock=lambda: _ACTIVE_NOW
    )
    if kind == "work-order":
        target = output / "agency" / "work-order.json"
    elif kind == "profile":
        target = output / "agency" / "profiles" / f"{profile.profile_id}.json"
    elif kind == "transition":
        target = (
            output
            / "agency"
            / "transitions"
            / f"{transition.transition_id}.json"
        )
    else:
        target = output / "agency" / "appeals" / f"{appeal.appeal_id}.json"

    tampered = bytearray(target.read_bytes())
    tampered[len(tampered) // 2] ^= 0x01
    target.write_bytes(bytes(tampered))
    with pytest.raises(bundle.AgencyBundleError):
        bundle.verify_agency_bundle_directory(output)


def test_verify_rejects_manifest_entry_digest_tamper(
    tmp_path: Path,
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    output = tmp_path / "agency-bundle"
    bundle.export_agency_bundle(
        ledger_case["ledger"], output, sidecar_private_key=agency_case.keys["Sidecar"][0], clock=lambda: _ACTIVE_NOW
    )
    manifest_path = output / "agency-manifest.json"
    raw = json.loads(manifest_path.read_bytes())
    raw["entries"][0]["sha256"] = "0" * 64
    manifest_path.write_bytes(_canonical(raw))
    with pytest.raises(bundle.AgencyBundleError, match="manifest"):
        bundle.verify_agency_bundle_directory(output)


def test_verify_rejects_manifest_status_mismatch(
    tmp_path: Path,
    agency_case: _AgencyCase,
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    files = _bundle_files(agency_case.work_order, profiles=(profile,))
    root = _write_bundle(
        tmp_path / "bad-status",
        files,
        work_order_digest=agency_case.work_order.digest,
        evaluated_at="2026-01-01T12:00:00Z",
        current_status="revoked",
        current_profile_id=None,
        sidecar_private_key=agency_case.keys["Sidecar"][0],
    )
    with pytest.raises(bundle.AgencyBundleError, match="status"):
        bundle.verify_agency_bundle_directory(root)


def test_verify_rejects_manifest_work_order_digest_mismatch(
    tmp_path: Path,
    agency_case: _AgencyCase,
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    files = _bundle_files(agency_case.work_order, profiles=(profile,))
    root = _write_bundle(
        tmp_path / "bad-work-order",
        files,
        work_order_digest=SHA256_B,
        evaluated_at="2026-01-01T12:00:00Z",
        current_status="active",
        current_profile_id=profile.profile_id,
        sidecar_private_key=agency_case.keys["Sidecar"][0],
    )
    with pytest.raises(bundle.AgencyBundleError, match="work_order_digest"):
        bundle.verify_agency_bundle_directory(root)


def test_verify_rejects_non_canonical_object_json(
    tmp_path: Path,
    agency_case: _AgencyCase,
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    files = _bundle_files(agency_case.work_order, profiles=(profile,))
    files["agency/work-order.json"] = json.dumps(
        json.loads(files["agency/work-order.json"]),
        indent=2,
    ).encode("utf-8")
    root = _write_bundle(
        tmp_path / "non-canonical",
        files,
        work_order_digest=agency_case.work_order.digest,
        evaluated_at="2026-01-01T12:00:00Z",
        current_status="active",
        current_profile_id=profile.profile_id,
        sidecar_private_key=agency_case.keys["Sidecar"][0],
    )
    with pytest.raises(bundle.AgencyBundleError, match="canonical"):
        bundle.verify_agency_bundle_directory(root)


def test_verify_rejects_wrong_verify_script(
    tmp_path: Path,
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    output = tmp_path / "agency-bundle"
    bundle.export_agency_bundle(
        ledger_case["ledger"], output, sidecar_private_key=agency_case.keys["Sidecar"][0], clock=lambda: _ACTIVE_NOW
    )
    (output / "verify.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
    manifest_path = output / "agency-manifest.json"
    raw = json.loads(manifest_path.read_bytes())
    for entry in raw["entries"]:
        if entry["path"] == "verify.sh":
            entry["sha256"] = hashlib.sha256(
                (output / "verify.sh").read_bytes()
            ).hexdigest()
            entry["size_bytes"] = (output / "verify.sh").stat().st_size
    manifest_path.write_bytes(_canonical(_keyless_rebuild_manifest(raw)))
    with pytest.raises(bundle.AgencyBundleError, match="required"):
        bundle.verify_agency_bundle_directory(output)


# --- verifier: invalid signed graphs fail closed ---


def test_verify_rejects_multiple_genesis(
    tmp_path: Path,
    agency_case: _AgencyCase,
) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    second = _mk_profile(agency_case, SHA256_B)
    files = _bundle_files(agency_case.work_order, profiles=(first, second))
    root = _write_bundle(
        tmp_path / "fork",
        files,
        work_order_digest=agency_case.work_order.digest,
        evaluated_at="2026-01-01T12:00:00Z",
        current_status="active",
        current_profile_id=first.profile_id,
        sidecar_private_key=agency_case.keys["Sidecar"][0],
    )
    with pytest.raises(bundle.AgencyBundleError):
        bundle.verify_agency_bundle_directory(root)


def test_verify_rejects_fork_two_outgoing_transitions(
    tmp_path: Path,
    agency_case: _AgencyCase,
) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    second = _mk_profile(agency_case, SHA256_B)
    third = _mk_profile(agency_case, SHA256_C)
    t1 = _mk_transition(
        agency_case, target=first, transition="superseded", replacement=second
    )
    t2 = _mk_transition(
        agency_case,
        target=first,
        transition="superseded",
        replacement=third,
        nonce="e" * 64,
    )
    files = _bundle_files(
        agency_case.work_order,
        profiles=(first, second, third),
        transitions=(t1, t2),
    )
    root = _write_bundle(
        tmp_path / "fork",
        files,
        work_order_digest=agency_case.work_order.digest,
        evaluated_at="2026-01-01T12:00:00Z",
        current_status="active",
        current_profile_id=second.profile_id,
        sidecar_private_key=agency_case.keys["Sidecar"][0],
    )
    with pytest.raises(bundle.AgencyBundleError):
        bundle.verify_agency_bundle_directory(root)


def test_verify_rejects_cycle(
    tmp_path: Path,
    agency_case: _AgencyCase,
) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    second = _mk_profile(agency_case, SHA256_B)
    t1 = _mk_transition(
        agency_case, target=first, transition="superseded", replacement=second
    )
    t2 = _mk_transition(
        agency_case,
        target=second,
        transition="superseded",
        replacement=first,
        nonce="e" * 64,
    )
    files = _bundle_files(
        agency_case.work_order,
        profiles=(first, second),
        transitions=(t1, t2),
    )
    root = _write_bundle(
        tmp_path / "cycle",
        files,
        work_order_digest=agency_case.work_order.digest,
        evaluated_at="2026-01-01T12:00:00Z",
        current_status="active",
        current_profile_id=second.profile_id,
        sidecar_private_key=agency_case.keys["Sidecar"][0],
    )
    with pytest.raises(bundle.AgencyBundleError):
        bundle.verify_agency_bundle_directory(root)


def test_verify_rejects_disconnected_cycle_beside_genesis(
    tmp_path: Path,
    agency_case: _AgencyCase,
) -> None:
    genesis = _mk_profile(agency_case, SHA256_A)
    first = _mk_profile(agency_case, SHA256_B)
    second = _mk_profile(agency_case, SHA256_C)
    t1 = _mk_transition(
        agency_case, target=first, transition="superseded", replacement=second
    )
    t2 = _mk_transition(
        agency_case,
        target=second,
        transition="superseded",
        replacement=first,
        nonce="e" * 64,
    )
    files = _bundle_files(
        agency_case.work_order,
        profiles=(genesis, first, second),
        transitions=(t1, t2),
    )
    root = _write_bundle(
        tmp_path / "disconnected",
        files,
        work_order_digest=agency_case.work_order.digest,
        evaluated_at="2026-01-01T12:00:00Z",
        current_status="active",
        current_profile_id=genesis.profile_id,
        sidecar_private_key=agency_case.keys["Sidecar"][0],
    )
    with pytest.raises(bundle.AgencyBundleError):
        bundle.verify_agency_bundle_directory(root)


def test_verify_rejects_time_reversal(
    tmp_path: Path,
    agency_case: _AgencyCase,
) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    second = _mk_profile(agency_case, SHA256_B)
    t1 = _mk_transition(
        agency_case,
        target=first,
        transition="superseded",
        replacement=second,
        transitioned_at="2025-12-31T23:59:59Z",
    )
    files = _bundle_files(
        agency_case.work_order,
        profiles=(first, second),
        transitions=(t1,),
    )
    root = _write_bundle(
        tmp_path / "time-reversal",
        files,
        work_order_digest=agency_case.work_order.digest,
        evaluated_at="2026-01-01T12:00:00Z",
        current_status="active",
        current_profile_id=second.profile_id,
        sidecar_private_key=agency_case.keys["Sidecar"][0],
    )
    with pytest.raises(bundle.AgencyBundleError):
        bundle.verify_agency_bundle_directory(root)


def test_verify_rejects_missing_replacement(
    tmp_path: Path,
    agency_case: _AgencyCase,
) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    second = _mk_profile(agency_case, SHA256_B)
    t1 = _mk_transition(
        agency_case, target=first, transition="superseded", replacement=second
    ).model_copy(update={"replacement_profile_id": "9" * 64})
    files = _bundle_files(
        agency_case.work_order,
        profiles=(first, second),
        transitions=(t1,),
    )
    root = _write_bundle(
        tmp_path / "missing-replacement",
        files,
        work_order_digest=agency_case.work_order.digest,
        evaluated_at="2026-01-01T12:00:00Z",
        current_status="active",
        current_profile_id=second.profile_id,
        sidecar_private_key=agency_case.keys["Sidecar"][0],
    )
    with pytest.raises(bundle.AgencyBundleError):
        bundle.verify_agency_bundle_directory(root)


def test_verify_rejects_appeal_target_inconsistency(
    tmp_path: Path,
    agency_case: _AgencyCase,
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    ghost = _mk_profile(agency_case, SHA256_B)
    appeal = _mk_appeal(agency_case, profile=ghost)
    files = _bundle_files(
        agency_case.work_order,
        profiles=(profile,),
        appeals=(appeal,),
    )
    root = _write_bundle(
        tmp_path / "appeal-mismatch",
        files,
        work_order_digest=agency_case.work_order.digest,
        evaluated_at="2026-01-01T12:00:00Z",
        current_status="active",
        current_profile_id=profile.profile_id,
        sidecar_private_key=agency_case.keys["Sidecar"][0],
    )
    with pytest.raises(bundle.AgencyBundleError, match="appeal"):
        bundle.verify_agency_bundle_directory(root)


# --- verifier: cross WorkOrder binding ---


def test_verify_rejects_profile_bound_to_another_work_order(
    tmp_path: Path,
    agency_case: _AgencyCase,
) -> None:
    other_work_order = _sign_other_work_order(agency_case)
    foreign = _mk_profile(
        _AgencyCase(work_order=other_work_order, keys=agency_case.keys),
        SHA256_A,
    )
    files = _bundle_files(
        agency_case.work_order,
        profiles=(foreign,),
    )
    root = _write_bundle(
        tmp_path / "cross-work-order",
        files,
        work_order_digest=agency_case.work_order.digest,
        evaluated_at="2026-01-01T12:00:00Z",
        current_status="active",
        current_profile_id=foreign.profile_id,
        sidecar_private_key=agency_case.keys["Sidecar"][0],
    )
    with pytest.raises(bundle.AgencyBundleError):
        bundle.verify_agency_bundle_directory(root)


# --- model closure ---


def test_manifest_models_are_closed() -> None:
    key = Ed25519PrivateKey.generate()
    signed = sign_payload(
        "manifest",
        {
            "schema_version": "openworkproof-agency-bundle/0.1",
            "work_order_digest": "0" * 64,
            "evaluated_at": "2026-01-01T00:00:00Z",
            "current_status": "active",
            "current_profile_id": "1" * 64,
            "boundary": bundle.AGENCY_BUNDLE_BOUNDARY,
            "entries": [
                {
                    "path": "verify.sh",
                    "sha256": hashlib.sha256(
                        bundle.AGENCY_VERIFY_SCRIPT
                    ).hexdigest(),
                    "size_bytes": len(bundle.AGENCY_VERIFY_SCRIPT),
                }
            ],
        },
        key,
    )
    signed["unexpected"] = True
    with pytest.raises(ValidationError):
        bundle.AgencyBundleManifestV01.model_validate(signed)


def test_result_boundary_is_exact_literal() -> None:
    result = bundle.AgencyBundleVerificationResultV01(
        schema_version="openworkproof-agency-bundle-result/0.1",
        work_order_digest="0" * 64,
        evaluated_at="2026-01-01T00:00:00Z",
        current_status="active",
        current_profile_id="1" * 64,
        appeal_count=0,
        boundary=bundle.AGENCY_BUNDLE_BOUNDARY,
    )
    assert (
        result.boundary
        == "authorization evidence, not legal or employment judgment"
    )
    with pytest.raises(ValidationError):
        bundle.AgencyBundleVerificationResultV01(
            schema_version="openworkproof-agency-bundle-result/0.1",
            work_order_digest="0" * 64,
            evaluated_at="2026-01-01T00:00:00Z",
            current_status="active",
            current_profile_id="1" * 64,
            appeal_count=0,
            boundary="not payment, settlement, legal audit, or adoption",
        )


# --- manifest snapshot attestation: Sidecar signature is authoritative ---


def test_export_rejects_non_sidecar_signer(
    tmp_path: Path,
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    output = tmp_path / "agency-bundle"
    with pytest.raises(bundle.AgencyBundleError, match="Sidecar"):
        bundle.export_agency_bundle(
            ledger_case["ledger"],
            output,
            sidecar_private_key=agency_case.keys["Acceptor"][0],
            clock=lambda: _ACTIVE_NOW,
        )
    assert not output.exists()


def test_verify_rejects_manifest_signed_by_wrong_role(
    tmp_path: Path,
    agency_case: _AgencyCase,
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    files = _bundle_files(agency_case.work_order, profiles=(profile,))
    root = _write_bundle(
        tmp_path / "wrong-role",
        files,
        work_order_digest=agency_case.work_order.digest,
        evaluated_at="2026-01-01T12:00:00Z",
        current_status="active",
        current_profile_id=profile.profile_id,
        sidecar_private_key=agency_case.keys["Acceptor"][0],
    )
    with pytest.raises(bundle.AgencyBundleError, match="signature"):
        bundle.verify_agency_bundle_directory(root)


def test_verify_rejects_keyless_truncation_of_supersede_chain(
    tmp_path: Path,
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    second = _mk_profile(agency_case, SHA256_B)
    commit_human_agency_profile(ledger_case["ledger"], first)
    commit_human_agency_profile(ledger_case["ledger"], second)
    transition = _mk_transition(
        agency_case, target=first, transition="superseded", replacement=second
    )
    commit_agency_profile_transition(ledger_case["ledger"], transition)

    output = tmp_path / "agency-bundle"
    manifest = bundle.export_agency_bundle(
        ledger_case["ledger"],
        output,
        sidecar_private_key=agency_case.keys["Sidecar"][0],
        clock=lambda: _ACTIVE_NOW,
    )
    assert manifest.current_status == "active"
    assert manifest.current_profile_id == second.profile_id

    # Truncate the signed p1 -> p2 chain back to the genesis profile and
    # keylessly rebuild the manifest digest (the Ed25519 signature stays stale).
    (output / "agency" / "transitions" / f"{transition.transition_id}.json").unlink()
    (output / "agency" / "transitions").rmdir()
    (output / "agency" / "profiles" / f"{second.profile_id}.json").unlink()

    manifest_path = output / "agency-manifest.json"
    raw = json.loads(manifest_path.read_bytes())
    dropped = {
        f"agency/transitions/{transition.transition_id}.json",
        f"agency/profiles/{second.profile_id}.json",
    }
    raw["entries"] = [
        entry for entry in raw["entries"] if entry["path"] not in dropped
    ]
    raw["current_status"] = "active"
    raw["current_profile_id"] = first.profile_id
    manifest_path.write_bytes(_canonical(_keyless_rebuild_manifest(raw)))

    with pytest.raises(bundle.AgencyBundleError, match="signature"):
        bundle.verify_agency_bundle_directory(output)


def test_verify_rejects_keyless_rollback_of_revoked_bundle(
    tmp_path: Path,
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    revoke = _mk_transition(agency_case, target=profile, transition="revoked")
    commit_agency_profile_transition(ledger_case["ledger"], revoke)

    output = tmp_path / "agency-bundle"
    manifest = bundle.export_agency_bundle(
        ledger_case["ledger"],
        output,
        sidecar_private_key=agency_case.keys["Sidecar"][0],
        clock=lambda: _ACTIVE_NOW,
    )
    assert manifest.current_status == "revoked"

    # Delete the revoke suffix and keylessly rebuild the manifest to claim the
    # genesis profile is active again; the stale signature must fail closed.
    (output / "agency" / "transitions" / f"{revoke.transition_id}.json").unlink()
    (output / "agency" / "transitions").rmdir()

    manifest_path = output / "agency-manifest.json"
    raw = json.loads(manifest_path.read_bytes())
    raw["entries"] = [
        entry
        for entry in raw["entries"]
        if entry["path"] != f"agency/transitions/{revoke.transition_id}.json"
    ]
    raw["current_status"] = "active"
    raw["current_profile_id"] = profile.profile_id
    manifest_path.write_bytes(_canonical(_keyless_rebuild_manifest(raw)))

    with pytest.raises(bundle.AgencyBundleError, match="signature"):
        bundle.verify_agency_bundle_directory(output)


def test_verify_rejects_keyless_evaluated_at_and_status_rewrite(
    tmp_path: Path,
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(
        agency_case, SHA256_A, valid_from="2026-01-01T00:00:01Z"
    )
    commit_human_agency_profile(ledger_case["ledger"], profile)

    output = tmp_path / "agency-bundle"
    manifest = bundle.export_agency_bundle(
        ledger_case["ledger"],
        output,
        sidecar_private_key=agency_case.keys["Sidecar"][0],
        clock=lambda: _ACTIVE_NOW,
    )
    assert manifest.current_status == "active"

    # Rewrite evaluated_at to a second before the profile validity window and
    # coherently change status/profile to what replay would derive there. Only
    # the Sidecar signature can authorize such a snapshot, so it must reject.
    manifest_path = output / "agency-manifest.json"
    raw = json.loads(manifest_path.read_bytes())
    raw["evaluated_at"] = "2026-01-01T00:00:00Z"
    raw["current_status"] = "expired"
    raw["current_profile_id"] = profile.profile_id
    manifest_path.write_bytes(_canonical(_keyless_rebuild_manifest(raw)))

    with pytest.raises(bundle.AgencyBundleError, match="signature"):
        bundle.verify_agency_bundle_directory(output)


def test_verify_rejects_manifest_signature_byte_tamper(
    tmp_path: Path,
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    output = tmp_path / "agency-bundle"
    bundle.export_agency_bundle(
        ledger_case["ledger"],
        output,
        sidecar_private_key=agency_case.keys["Sidecar"][0],
        clock=lambda: _ACTIVE_NOW,
    )

    manifest_path = output / "agency-manifest.json"
    raw = json.loads(manifest_path.read_bytes())
    raw["signature"] = "A" * 86
    manifest_path.write_bytes(_canonical(raw))
    with pytest.raises(bundle.AgencyBundleError, match="signature"):
        bundle.verify_agency_bundle_directory(output)


def test_verify_rejects_manifest_signer_key_id_tamper(
    tmp_path: Path,
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    output = tmp_path / "agency-bundle"
    bundle.export_agency_bundle(
        ledger_case["ledger"],
        output,
        sidecar_private_key=agency_case.keys["Sidecar"][0],
        clock=lambda: _ACTIVE_NOW,
    )

    manifest_path = output / "agency-manifest.json"
    raw = json.loads(manifest_path.read_bytes())
    raw["signer_key_id"] = "ed25519:" + "f" * 64
    manifest_path.write_bytes(_canonical(_keyless_rebuild_manifest(raw)))
    with pytest.raises(bundle.AgencyBundleError, match="signature"):
        bundle.verify_agency_bundle_directory(output)


def test_verifier_is_pure_offline_and_keyless(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    output = tmp_path / "agency-bundle"
    bundle.export_agency_bundle(
        ledger_case["ledger"],
        output,
        sidecar_private_key=agency_case.keys["Sidecar"][0],
        clock=lambda: _ACTIVE_NOW,
    )

    def _guard(label: str) -> Any:
        def _boom(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError(f"offline verifier accessed {label}")

        return _boom

    # System / wall clock.
    monkeypatch.setattr(time, "time", _guard("system clock"))
    monkeypatch.setattr(time, "monotonic", _guard("system clock"))
    monkeypatch.setattr(bundle, "datetime", _guard("datetime class"))
    # Ledger access (both the shared entry point and the bundle's lazy loaders).
    monkeypatch.setattr(evidence, "connect_ledger", _guard("ledger"))
    monkeypatch.setattr(evidence, "initialize_ledger", _guard("ledger"))
    monkeypatch.setattr(bundle, "load_agency_history", _guard("ledger"))
    monkeypatch.setattr(bundle, "load_agency_appeals", _guard("ledger"))
    # Network.
    monkeypatch.setattr(socket, "socket", _guard("network"))
    # Private-key signing.
    monkeypatch.setattr(bundle, "sign_payload", _guard("private key signing"))
    monkeypatch.setattr(bundle, "Ed25519PrivateKey", _guard("private key"))

    result = bundle.verify_agency_bundle_directory(output)
    assert result.current_status == "active"
    assert result.current_profile_id == profile.profile_id
