"""Composed offline delivery for one DeepSeek Harness verification."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid
from pathlib import Path

import rfc8785

from openworkproof.delivery_package import (
    DeliveryManifest,
    DeliveryPackageError,
)
from openworkproof.dsh_verifier import DshVerificationResultV01
from openworkproof.services import OpenWorkProofServices


_MAX_FILE_BYTES = 1_048_576


def _canonical(raw: bytes, *, label: str) -> dict[str, object]:
    if not raw or len(raw) > _MAX_FILE_BYTES:
        raise DeliveryPackageError(f"{label} is unavailable")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise DeliveryPackageError(f"{label} is invalid") from error
    if type(value) is not dict or rfc8785.dumps(value) != raw:
        raise DeliveryPackageError(f"{label} is not canonical")
    return value


def _read_result(root: Path, kind: str, digest: str) -> bytes:
    directory = root / kind
    path = directory / f"{digest}.json"
    if root.is_symlink() or directory.is_symlink() or path.is_symlink():
        raise DeliveryPackageError(f"{kind} result is unavailable")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
            if metadata.st_size > _MAX_FILE_BYTES + 1:
                raise DeliveryPackageError(f"{kind} result is unavailable")
            raw = os.read(descriptor, _MAX_FILE_BYTES + 2)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise DeliveryPackageError(f"{kind} result is unavailable") from error
    if not raw.endswith(b"\n"):
        raise DeliveryPackageError(f"{kind} result is invalid")
    canonical = raw[:-1]
    if hashlib.sha256(canonical).hexdigest() != digest:
        raise DeliveryPackageError(f"{kind} result digest is invalid")
    _canonical(canonical, label=kind)
    return canonical


def build_dsh_delivery(
    *,
    case_id: str,
    ledger_path: Path,
    evidence_root: Path,
    destination: Path,
    verification_digest: str,
    acceptance_draft_digest: str,
) -> str:
    if destination.exists() or destination.is_symlink():
        raise DeliveryPackageError("DSH delivery destination already exists")
    verification_raw = _read_result(
        evidence_root, "dsh-verifications", verification_digest
    )
    verification = DshVerificationResultV01.model_validate_json(
        verification_raw
    )
    draft_raw = _read_result(
        evidence_root, "dsh-acceptance-drafts", acceptance_draft_digest
    )
    draft = _canonical(draft_raw, label="DSH acceptance draft")
    if (
        verification.case_id != case_id
        or verification.status != "VERIFIED"
        or draft.get("case_id") != case_id
        or draft.get("dsh_verification_digest") != verification_digest
        or draft.get("core_verification_decision_id")
        != verification.core_verification_decision_id
        or draft.get("core_verification_decision_digest")
        != verification.core_verification_decision_digest
    ):
        raise DeliveryPackageError("DSH delivery bindings are invalid")

    temporary = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.tmp"
    try:
        temporary.mkdir(mode=0o700)
        core = temporary / "core-delivery"
        services = OpenWorkProofServices()
        services.build_delivery(ledger_path, core, "customer_private")
        core_audit = services.audit_delivery(core)
        files = {
            "dsh-verification.json": verification_raw,
            "dsh-acceptance-draft.json": draft_raw,
        }
        entries = []
        for relative, payload in sorted(files.items()):
            (temporary / relative).write_bytes(payload)
            entries.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size_bytes": len(payload),
                }
            )
        manifest = {
            "schema_version": "openworkproof-dsh-delivery/0.1",
            "case_id": case_id,
            "core_manifest_digest": core_audit["manifest_digest"],
            "core_verification_decision_id": (
                verification.core_verification_decision_id
            ),
            "core_verification_decision_digest": (
                verification.core_verification_decision_digest
            ),
            "dsh_verification_digest": verification_digest,
            "dsh_acceptance_draft_digest": acceptance_draft_digest,
            "entries": entries,
        }
        encoded = rfc8785.dumps(manifest)
        (temporary / "manifest.json").write_bytes(encoded)
        digest = hashlib.sha256(encoded).hexdigest()
        audit = audit_dsh_delivery(temporary)
        if audit["manifest_digest"] != digest:
            raise DeliveryPackageError("DSH delivery self-audit failed")
        os.replace(temporary, destination)
        return digest
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def audit_dsh_delivery(root: Path) -> dict[str, object]:
    root = Path(root)
    manifest_path = root / "manifest.json"
    if root.is_symlink() or manifest_path.is_symlink() or not manifest_path.is_file():
        raise DeliveryPackageError("DSH delivery manifest is unavailable")
    manifest_raw = manifest_path.read_bytes()
    manifest = _canonical(manifest_raw, label="DSH delivery manifest")
    expected_keys = {
        "schema_version",
        "case_id",
        "core_manifest_digest",
        "core_verification_decision_id",
        "core_verification_decision_digest",
        "dsh_verification_digest",
        "dsh_acceptance_draft_digest",
        "entries",
    }
    if (
        set(manifest) != expected_keys
        or manifest["schema_version"] != "openworkproof-dsh-delivery/0.1"
        or set(path.name for path in root.iterdir())
        != {
            "core-delivery",
            "dsh-verification.json",
            "dsh-acceptance-draft.json",
            "manifest.json",
        }
    ):
        raise DeliveryPackageError("DSH delivery manifest shape is invalid")
    entries = manifest["entries"]
    if type(entries) is not list or [item.get("path") for item in entries] != [
        "dsh-acceptance-draft.json",
        "dsh-verification.json",
    ]:
        raise DeliveryPackageError("DSH delivery entry inventory is invalid")
    payloads: dict[str, bytes] = {}
    for entry in entries:
        if type(entry) is not dict or set(entry) != {
            "path",
            "sha256",
            "size_bytes",
        }:
            raise DeliveryPackageError("DSH delivery entry is invalid")
        path = root / entry["path"]
        if path.is_symlink() or not path.is_file():
            raise DeliveryPackageError("DSH delivery file is unavailable")
        payload = path.read_bytes()
        if (
            len(payload) != entry["size_bytes"]
            or hashlib.sha256(payload).hexdigest() != entry["sha256"]
        ):
            raise DeliveryPackageError("DSH delivery file integrity failed")
        payloads[entry["path"]] = payload

    verification = DshVerificationResultV01.model_validate_json(
        payloads["dsh-verification.json"]
    )
    draft = _canonical(
        payloads["dsh-acceptance-draft.json"],
        label="DSH acceptance draft",
    )
    core_root = root / "core-delivery"
    core_audit = OpenWorkProofServices().audit_delivery(core_root)
    core_manifest = DeliveryManifest.model_validate_json(
        (core_root / "manifest.json").read_bytes()
    )
    core_binding = draft.get("core_acceptance_binding")
    if type(core_binding) is not dict:
        raise DeliveryPackageError("core acceptance binding is unavailable")
    receipts = json.loads(
        (core_root / "execution-ledger" / "receipts.json").read_bytes()
    )
    receipt_map = {item.get("receipt_id"): item for item in receipts}
    terminal_relative = (
        "acceptance/acceptance-receipt.json"
        if core_binding.get("terminal_kind") == "accepted"
        else "acceptance/rejection-receipt.json"
    )
    terminal = _canonical(
        (core_root / terminal_relative).read_bytes(),
        label="core terminal receipt",
    )
    if (
        verification.status != "VERIFIED"
        or manifest["case_id"] != verification.case_id
        or manifest["dsh_verification_digest"]
        != hashlib.sha256(payloads["dsh-verification.json"]).hexdigest()
        or manifest["dsh_acceptance_draft_digest"]
        != hashlib.sha256(payloads["dsh-acceptance-draft.json"]).hexdigest()
        or draft.get("dsh_verification_digest")
        != manifest["dsh_verification_digest"]
        or core_audit["manifest_digest"] != manifest["core_manifest_digest"]
        or core_audit["current_decision"] != "VERIFIED"
        or core_manifest.verification_decision_digest
        != verification.core_verification_decision_digest
        or core_binding.get("verification_decision_id")
        != verification.core_verification_decision_id
        or core_binding.get("verification_decision_digest")
        != verification.core_verification_decision_digest
        or terminal.get("acceptance_id", terminal.get("rejection_id"))
        != core_binding.get("terminal_receipt_id")
        or receipt_map.get(verification.action_receipt_id, {}).get("digest")
        != verification.action_receipt_digest
        or receipt_map.get(verification.test_receipt_id, {}).get("digest")
        != verification.test_receipt_digest
    ):
        raise DeliveryPackageError("DSH delivery causal binding failed")
    return {
        "schema_version": "openworkproof-dsh-delivery-audit/0.1",
        "case_id": verification.case_id,
        "current_decision": core_audit["current_decision"],
        "manifest_digest": hashlib.sha256(manifest_raw).hexdigest(),
        "dsh_verification_digest": manifest["dsh_verification_digest"],
        "boundary": "offline integrity verified; payment and adoption are separate",
    }


__all__ = ["audit_dsh_delivery", "build_dsh_delivery"]
