"""Portable, offline-verifiable Evidence Lifecycle v0.2 delivery packages."""

from __future__ import annotations

import hashlib
import html
import json
import os
from pathlib import Path
import re
import shutil
from typing import Literal
import uuid

import rfc8785
from pydantic import model_validator

import openworkproof.evidence as evidence
from openworkproof.models import (
    AcceptanceReceipt,
    AcceptanceRejectionReceipt,
    AcceptanceTransitionReceipt,
    CanonicalRoot,
    CommitmentAnchor,
    Digest64,
    Identifier,
    PolicyAnchor,
    ProtocolModel,
    SafeNonNegativeInt,
    SubjectClaim,
    VerificationArmResult,
    VerificationDecision,
    VerificationProfileV02,
    WorkOrder,
)
from openworkproof.settlement import (
    AcceptanceHistory,
    EffectiveAcceptance,
    SettlementReadiness,
    effective_acceptance,
    settlement_readiness,
)
from openworkproof.signing import (
    decode_and_verify_key_binding,
    verify_payload,
    verify_work_order_identity_bindings,
)
from openworkproof.verification import (
    VerificationInputError,
    _validate_single_arm_result,
    _validate_profile_authority,
    external_anchor_digest,
    validate_verification_decision,
)


_MAX_FILE_BYTES = 8 * 1024 * 1024
_MAX_PACKAGE_BYTES = 32 * 1024 * 1024
_SECRET_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        rb"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        rb"(?:api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{12,}",
        rb"authorization\s*:\s*bearer\s+[A-Za-z0-9._\-]{12,}",
    )
)


class DeliveryPackageError(RuntimeError):
    """A delivery package cannot be exported or verified safely."""


class DeliveryManifestEntry(ProtocolModel):
    path: CanonicalRoot
    sha256: Digest64
    size_bytes: SafeNonNegativeInt
    media_type: Identifier
    privacy_class: Literal["public", "customer_private"]
    required: bool


class DeliveryManifest(ProtocolModel):
    schema_version: Literal["openworkproof-delivery-manifest/0.1"]
    privacy_view: Literal["public", "customer_private"]
    work_order_digest: Digest64
    subject_claim_digest: Digest64
    verification_decision_digest: Digest64
    entries: tuple[DeliveryManifestEntry, ...]

    @model_validator(mode="after")
    def _closed_manifest(self) -> DeliveryManifest:
        paths = tuple(entry.path for entry in self.entries)
        if not paths or paths != tuple(
            sorted(set(paths), key=lambda value: value.encode("utf-8"))
        ):
            raise ValueError("manifest entries must be non-empty, sorted, and unique")
        if "manifest.json" in paths:
            raise ValueError("manifest.json cannot be its own manifest entry")
        if sum(entry.size_bytes for entry in self.entries) > _MAX_PACKAGE_BYTES:
            raise ValueError("delivery package exceeds the total size limit")
        if self.privacy_view == "public" and any(
            entry.privacy_class != "public" for entry in self.entries
        ):
            raise ValueError("public manifest contains a customer-private entry")
        return self


class DeliveryVerificationResult(ProtocolModel):
    current_decision: Literal["VERIFIED", "REFUTED", "UNKNOWN"]
    effective_acceptance: Literal[
        "NONE", "ACTIVE", "SUSPENDED", "WITHDRAWN", "SUPERSEDED"
    ]
    settlement_readiness: Literal[
        "NOT_READY",
        "READY_FOR_ACCEPTANCE",
        "ACCEPTED_FOR_SETTLEMENT",
        "SUSPENDED",
        "WITHDRAWN",
        "SUPERSEDED",
    ]
    manifest_digest: Digest64


def digest_manifest(manifest: DeliveryManifest) -> str:
    payload = rfc8785.dumps(manifest.model_dump(mode="json"))
    return hashlib.sha256(payload).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return rfc8785.dumps(value)


def _entry_map(manifest: DeliveryManifest) -> dict[str, DeliveryManifestEntry]:
    return {entry.path: entry for entry in manifest.entries}


def _safe_package_file(root: Path, relative: str) -> Path:
    candidate = root.joinpath(*relative.split("/"))
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise DeliveryPackageError("package path escapes its root") from error
    return candidate


def _assert_safe_evidence_relative(relative: str) -> None:
    parts = relative.lower().split("/")
    basename = parts[-1]
    if (
        any(part == ".env" or part.startswith(".env.") for part in parts)
        or basename in {"id_rsa", "id_ed25519", "stdout", "stderr"}
        or basename.endswith((".key", ".pem", ".p12", ".pfx"))
        or any(part in {"private-keys", "private_keys", "secrets"} for part in parts)
    ):
        raise DeliveryPackageError("evidence allowlist contains a sensitive path")


def _assert_regular_file(path: Path, *, allow_hardlink: bool = False) -> None:
    try:
        stat = path.lstat()
    except OSError as error:
        raise DeliveryPackageError("required package file is missing") from error
    if path.is_symlink() or not path.is_file():
        raise DeliveryPackageError("delivery packages contain regular files only")
    if not allow_hardlink and stat.st_nlink != 1:
        raise DeliveryPackageError("delivery package hardlinks are forbidden")
    if stat.st_size > _MAX_FILE_BYTES:
        raise DeliveryPackageError("delivery package file is oversized")


def _read_bound(
    root: Path,
    manifest: DeliveryManifest,
    relative: str,
) -> bytes:
    entry = _entry_map(manifest).get(relative)
    if entry is None:
        raise DeliveryPackageError("required object is not manifest-bound")
    path = _safe_package_file(root, relative)
    _assert_regular_file(path)
    payload = path.read_bytes()
    if (
        len(payload) != entry.size_bytes
        or hashlib.sha256(payload).hexdigest() != entry.sha256
    ):
        raise DeliveryPackageError("manifest-bound file integrity failed")
    return payload


def _load_canonical_json(
    root: Path,
    manifest: DeliveryManifest,
    relative: str,
) -> object:
    payload = _read_bound(root, manifest, relative)
    try:
        parsed = json.loads(payload)
    except (TypeError, ValueError) as error:
        raise DeliveryPackageError("manifest-bound JSON is invalid") from error
    if _canonical_bytes(parsed) != payload:
        raise DeliveryPackageError("manifest-bound JSON is not canonical")
    return parsed


def load_and_verify_manifest(package_root: Path) -> DeliveryManifest:
    root = Path(package_root)
    if not root.is_dir() or root.is_symlink():
        raise DeliveryPackageError("delivery package root is unavailable")
    manifest_path = root / "manifest.json"
    _assert_regular_file(manifest_path)
    try:
        raw = manifest_path.read_bytes()
        parsed = json.loads(raw)
        manifest = DeliveryManifest.model_validate(parsed)
    except Exception as error:
        raise DeliveryPackageError("delivery manifest is invalid") from error
    if _canonical_bytes(manifest.model_dump(mode="json")) != raw:
        raise DeliveryPackageError("delivery manifest is not canonical")
    actual = set()
    for path in root.rglob("*"):
        if path.is_dir() and not path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        if relative == "manifest.json":
            continue
        _assert_regular_file(path)
        actual.add(relative)
    expected = set(_entry_map(manifest))
    if actual != expected:
        raise DeliveryPackageError("delivery package manifest file set is not exact")
    for entry in manifest.entries:
        payload = _read_bound(root, manifest, entry.path)
        if entry.required is not True:
            raise DeliveryPackageError("all emitted v0.1 package files are required")
        if entry.media_type != _media_type(entry.path):
            raise DeliveryPackageError("manifest media type does not match its path")
        if manifest.privacy_view == "public" and entry.privacy_class != "public":
            raise DeliveryPackageError("public delivery package leaks private content")
        if any(pattern.search(payload) for pattern in _SECRET_PATTERNS):
            raise DeliveryPackageError("delivery package contains a secret pattern")
    return manifest


def load_and_verify_anchors(
    package_root: Path,
    manifest: DeliveryManifest,
) -> tuple[PolicyAnchor | None, CommitmentAnchor | None]:
    root = Path(package_root)
    profile = VerificationProfileV02.model_validate(
        _load_canonical_json(root, manifest, "verification-profile.json")
    )
    values: list[PolicyAnchor | CommitmentAnchor | None] = []
    for expected, relative, model in (
        (
            profile.policy_anchor_digest,
            "anchors/policy-anchor.json",
            PolicyAnchor,
        ),
        (
            profile.commitment_anchor_digest,
            "anchors/commitment-anchor.json",
            CommitmentAnchor,
        ),
    ):
        present = relative in _entry_map(manifest)
        if (expected is None) != (not present):
            raise DeliveryPackageError("anchor presence does not match the profile")
        if expected is None:
            values.append(None)
            continue
        try:
            anchor = model.model_validate(_load_canonical_json(root, manifest, relative))
        except Exception as error:
            raise DeliveryPackageError("manifest-bound anchor is invalid") from error
        if external_anchor_digest(anchor) != expected:
            raise DeliveryPackageError("manifest-bound anchor digest mismatch")
        values.append(anchor)
    return values[0], values[1]


def _load_public_key_records(
    root: Path,
    manifest: DeliveryManifest,
) -> dict[str, dict[str, object]]:
    values = {}
    for entry in manifest.entries:
        if not entry.path.startswith("public-keys/"):
            continue
        try:
            raw = _load_canonical_json(root, manifest, entry.path)
            key_id = raw["key_id"]
        except Exception as error:
            raise DeliveryPackageError("public key record is invalid") from error
        expected_path = f"public-keys/{key_id.replace(':', '_')}.json"
        if entry.path != expected_path or key_id in values:
            raise DeliveryPackageError("public key record path is invalid")
        values[key_id] = raw
    return values


def _load_protocol_context(
    root: Path,
    manifest: DeliveryManifest,
) -> tuple[WorkOrder, SubjectClaim, VerificationProfileV02, VerificationDecision]:
    try:
        work_order = WorkOrder.model_validate(
            _load_canonical_json(root, manifest, "work-order.json")
        )
        claim = SubjectClaim.model_validate(
            _load_canonical_json(root, manifest, "subject-claim.json")
        )
        profile = VerificationProfileV02.model_validate(
            _load_canonical_json(root, manifest, "verification-profile.json")
        )
        decision = VerificationDecision.model_validate(
            _load_canonical_json(root, manifest, "verification-decision.json")
        )
    except Exception as error:
        raise DeliveryPackageError("delivery protocol object is invalid") from error
    if (
        work_order.digest != manifest.work_order_digest
        or claim.digest != manifest.subject_claim_digest
        or decision.digest != manifest.verification_decision_digest
        or claim.work_order_digest != work_order.digest
        or profile.work_order_digest != work_order.digest
        or profile.subject_claim_digest != claim.digest
        or profile.delivery_trust_level not in {2, 3}
        or decision.supersedes_decision_id is not None
    ):
        raise DeliveryPackageError("delivery protocol object binding failed")
    if not verify_work_order_identity_bindings(work_order):
        raise DeliveryPackageError("WorkOrder signature or identity binding failed")
    try:
        _validate_profile_authority(
            work_order=work_order,
            claim=claim,
            profile=profile,
        )
    except Exception as error:
        raise DeliveryPackageError("claim and profile authority binding failed") from error
    keys = _load_public_key_records(root, manifest)
    expected_keys: dict[str, dict[str, object]] = {
        binding.key_id: {
            "key_id": binding.key_id,
            "public_key_b64url": binding.public_key_b64url,
            "role": binding.role,
            "subject_id": binding.subject_id,
        }
        for binding in work_order.key_bindings
    }
    for binding in profile.verifier_bindings:
        expected_keys.setdefault(
            binding.verifier_key_id,
            {
                "key_id": binding.verifier_key_id,
                "public_key_b64url": binding.verifier_public_key_b64url,
                "role": "Verifier",
                "subject_id": binding.verifier_subject_id,
            },
        )
    if keys != expected_keys:
        raise DeliveryPackageError("public key set does not match signed bindings")
    manager = next(item for item in work_order.key_bindings if item.role == "Manager")
    manager_key = decode_and_verify_key_binding(manager)
    if not verify_payload("subject-claim", claim.model_dump(mode="json"), manager_key):
        raise DeliveryPackageError("SubjectClaim signature is invalid")
    if not verify_payload(
        "verification-profile", profile.model_dump(mode="json"), manager_key
    ):
        raise DeliveryPackageError("VerificationProfile signature is invalid")
    try:
        validate_verification_decision(profile=profile, decision=decision)
    except VerificationInputError as error:
        raise DeliveryPackageError("VerificationDecision is invalid") from error
    return work_order, claim, profile, decision


def _load_receipts(
    root: Path,
    manifest: DeliveryManifest,
    work_order: WorkOrder,
) -> tuple[object, ...]:
    raw_receipts = _load_canonical_json(
        root, manifest, "execution-ledger/receipts.json"
    )
    raw_parents = _load_canonical_json(
        root, manifest, "execution-ledger/receipt-parents.json"
    )
    if not isinstance(raw_receipts, list) or not isinstance(raw_parents, list):
        raise DeliveryPackageError("execution ledger arrays are invalid")
    sidecar = next(item for item in work_order.key_bindings if item.role == "Sidecar")
    sidecar_key = decode_and_verify_key_binding(sidecar)
    receipts = []
    by_id = {}
    for raw in raw_receipts:
        try:
            receipt = evidence.ACTION_RECEIPT_ADAPTER.validate_python(raw)
        except Exception as error:
            raise DeliveryPackageError("execution receipt is malformed") from error
        if (
            receipt.receipt_id in by_id
            or receipt.work_order_digest != work_order.digest
            or not verify_payload(
                "action-receipt", receipt.model_dump(mode="json"), sidecar_key
            )
        ):
            raise DeliveryPackageError("execution receipt integrity failed")
        receipts.append(receipt)
        by_id[receipt.receipt_id] = receipt
    if tuple(receipt.sequence for receipt in receipts) != tuple(
        sorted(receipt.sequence for receipt in receipts)
    ):
        raise DeliveryPackageError("execution receipts are not sequence ordered")
    expected_parents = sorted(
        (
            {"child_receipt_id": receipt.receipt_id, "parent_receipt_id": parent}
            for receipt in receipts
            for parent in receipt.parent_receipt_ids
        ),
        key=lambda item: (
            item["child_receipt_id"].encode("utf-8"),
            item["parent_receipt_id"].encode("utf-8"),
        ),
    )
    if raw_parents != expected_parents or any(
        item["parent_receipt_id"] not in by_id for item in raw_parents
    ):
        raise DeliveryPackageError("execution receipt causal graph is invalid")
    return tuple(receipts)


def _load_arm_results(
    root: Path,
    manifest: DeliveryManifest,
    profile: VerificationProfileV02,
    decision: VerificationDecision,
    receipts: tuple[object, ...],
) -> tuple[VerificationArmResult, ...]:
    receipt_ids = {item.receipt_id for item in receipts}
    arm_kinds = {
        profile.positive_arm.arm_id: "positive",
        **{arm.arm_id: "negative" for arm in profile.negative_arms},
    }
    values = []
    for reference in decision.arm_results:
        arm_kind = arm_kinds.get(reference.arm_id)
        if arm_kind is None:
            raise DeliveryPackageError("decision references an unknown verification arm")
        relative = f"evidence/{arm_kind}/arm-results/{reference.arm_result_id}.json"
        try:
            result = VerificationArmResult.model_validate(
                _load_canonical_json(root, manifest, relative)
            )
            _validate_single_arm_result(profile=profile, result=result)
        except Exception as error:
            raise DeliveryPackageError("verification arm result is invalid") from error
        if (
            result.arm_result_id != reference.arm_result_id
            or result.digest != reference.arm_result_digest
            or result.arm_id != reference.arm_id
            or result.arm_kind != arm_kind
            or any(item not in receipt_ids for item in result.action_receipt_ids)
        ):
            raise DeliveryPackageError("verification arm result binding failed")
        for evidence_ref in result.evidence_refs:
            _assert_safe_evidence_relative(evidence_ref.path)
            payload = _read_bound(
                root,
                manifest,
                f"evidence/{result.arm_kind}/{evidence_ref.path}",
            )
            if (
                len(payload) != evidence_ref.size_bytes
                or hashlib.sha256(payload).hexdigest() != evidence_ref.sha256
            ):
                raise DeliveryPackageError("verification evidence integrity failed")
        values.append(result)
    return tuple(values)


def _load_acceptance_history(
    root: Path,
    manifest: DeliveryManifest,
    work_order: WorkOrder,
    decision: VerificationDecision,
    receipts: tuple[object, ...],
) -> AcceptanceHistory:
    entries = _entry_map(manifest)
    acceptor = next(item for item in work_order.key_bindings if item.role == "Acceptor")
    acceptor_key = decode_and_verify_key_binding(acceptor)

    def load_optional(relative: str, model, domain: str):
        if relative not in entries:
            return None
        try:
            value = model.model_validate(_load_canonical_json(root, manifest, relative))
            value.validate_against_work_order(work_order)
        except Exception as error:
            raise DeliveryPackageError("acceptance lifecycle object is invalid") from error
        if not verify_payload(domain, value.model_dump(mode="json"), acceptor_key):
            raise DeliveryPackageError("acceptance lifecycle signature is invalid")
        return value

    acceptance = load_optional(
        "acceptance/acceptance-receipt.json",
        AcceptanceReceipt,
        "acceptance-receipt",
    )
    rejection = load_optional(
        "acceptance/rejection-receipt.json",
        AcceptanceRejectionReceipt,
        "acceptance-rejection-receipt",
    )
    withdrawal = load_optional(
        "acceptance/withdrawal-receipt.json",
        AcceptanceTransitionReceipt,
        "acceptance-transition",
    )
    supersession = load_optional(
        "acceptance/supersession-receipt.json",
        AcceptanceTransitionReceipt,
        "acceptance-transition",
    )
    receipt_by_id = {item.receipt_id: item for item in receipts}
    for terminal in (acceptance, rejection):
        if terminal is None:
            continue
        request = receipt_by_id.get(terminal.acceptance_request_receipt_id)
        if (
            request is None
            or request.digest != terminal.acceptance_request_receipt_digest
            or any(
                digest not in {item.digest for item in receipts}
                for digest in terminal.receipt_digests
            )
        ):
            raise DeliveryPackageError("acceptance causal receipt binding failed")
    for transition in (withdrawal, supersession):
        if transition is not None and (
            transition.verification_decision_id != decision.decision_id
            or transition.verification_decision_digest != decision.digest
        ):
            raise DeliveryPackageError("acceptance transition decision binding failed")
    try:
        return AcceptanceHistory.model_validate(
            {
                "acceptance": None if acceptance is None else acceptance.model_dump(mode="json"),
                "rejection": None if rejection is None else rejection.model_dump(mode="json"),
                "withdrawal": None if withdrawal is None else withdrawal.model_dump(mode="json"),
                "supersession": None if supersession is None else supersession.model_dump(mode="json"),
                "current_decision": decision.model_dump(mode="json"),
            }
        )
    except Exception as error:
        raise DeliveryPackageError("acceptance history is inconsistent") from error


def load_signed_history(
    package_root: Path,
    manifest: DeliveryManifest,
    anchors: tuple[PolicyAnchor | None, CommitmentAnchor | None],
) -> AcceptanceHistory:
    root = Path(package_root)
    work_order, claim, profile, decision = _load_protocol_context(root, manifest)
    policy_anchor, commitment_anchor = anchors
    if commitment_anchor is not None and (
        commitment_anchor.work_order_digest != work_order.digest
        or commitment_anchor.subject_claim_digest != claim.digest
    ):
        raise DeliveryPackageError("commitment anchor reverse binding failed")
    if (profile.policy_anchor_digest is None) != (policy_anchor is None) or (
        profile.commitment_anchor_digest is None
    ) != (commitment_anchor is None):
        raise DeliveryPackageError("anchor history is incomplete")
    receipts = _load_receipts(root, manifest, work_order)
    arm_results = _load_arm_results(root, manifest, profile, decision, receipts)
    publications = _load_canonical_json(
        root, manifest, "execution-ledger/evidence-publications.json"
    )
    if not isinstance(publications, list):
        raise DeliveryPackageError("evidence publication ledger is invalid")
    receipt_by_id = {item.receipt_id: item for item in receipts}
    expected_publications = {
        (receipt.receipt_id, reference.path): reference
        for receipt in receipts
        for reference in receipt.evidence_refs
    }
    seen_publications = set()
    for row in publications:
        if not isinstance(row, dict) or set(row) != {
            "publication_id",
            "receipt_id",
            "final_path",
            "sha256",
            "size_bytes",
            "media_type",
        }:
            raise DeliveryPackageError("evidence publication row is invalid")
        key = (row["receipt_id"], row["final_path"])
        reference = expected_publications.get(key)
        if (
            key in seen_publications
            or row["receipt_id"] not in receipt_by_id
            or reference is None
            or row["sha256"] != reference.sha256
            or row["size_bytes"] != reference.size_bytes
            or row["media_type"] != reference.media_type
        ):
            raise DeliveryPackageError("evidence publication binding failed")
        seen_publications.add(key)
    if seen_publications != set(expected_publications):
        raise DeliveryPackageError("evidence publication history is incomplete")
    history = _load_acceptance_history(root, manifest, work_order, decision, receipts)
    effective = effective_acceptance(history)
    readiness = settlement_readiness(
        decision=decision,
        acceptance=effective,
        rejection=history.rejection,
    )
    expected_readiness = {
        "current_decision_id": decision.decision_id,
        "effective_acceptance": effective.value,
        "settlement_readiness": readiness.value,
    }
    if _load_canonical_json(root, manifest, "settlement-readiness.json") != expected_readiness:
        raise DeliveryPackageError("settlement readiness is not derived truth")
    if _read_bound(root, manifest, "summary.html") != _summary_html(
        work_order=work_order,
        claim=claim,
        decision=decision,
        effective=effective,
        readiness=readiness,
        rejected=history.rejection is not None,
    ):
        raise DeliveryPackageError("delivery summary is not derived truth")
    if _read_bound(root, manifest, "verify.sh") != _VERIFY_SCRIPT:
        raise DeliveryPackageError("portable verifier entrypoint is invalid")
    expected_paths = {
        "subject-claim.json",
        "work-order.json",
        "verification-profile.json",
        "verification-decision.json",
        "execution-ledger/receipts.json",
        "execution-ledger/receipt-parents.json",
        "execution-ledger/evidence-publications.json",
        "settlement-readiness.json",
        "summary.html",
        "verify.sh",
    }
    if policy_anchor is not None:
        expected_paths.add("anchors/policy-anchor.json")
    if commitment_anchor is not None:
        expected_paths.add("anchors/commitment-anchor.json")
    for binding in work_order.key_bindings:
        expected_paths.add(
            f"public-keys/{binding.key_id.replace(':', '_')}.json"
        )
    for binding in profile.verifier_bindings:
        expected_paths.add(
            f"public-keys/{binding.verifier_key_id.replace(':', '_')}.json"
        )
    for result in arm_results:
        expected_paths.add(
            f"evidence/{result.arm_kind}/arm-results/{result.arm_result_id}.json"
        )
        expected_paths.update(
            f"evidence/{result.arm_kind}/{reference.path}"
            for reference in result.evidence_refs
        )
    for value, relative in (
        (history.acceptance, "acceptance/acceptance-receipt.json"),
        (history.rejection, "acceptance/rejection-receipt.json"),
        (history.withdrawal, "acceptance/withdrawal-receipt.json"),
        (history.supersession, "acceptance/supersession-receipt.json"),
    ):
        if value is not None:
            expected_paths.add(relative)
    entries = _entry_map(manifest)
    if "summary.pdf" in entries:
        expected_paths.add("summary.pdf")
    if set(entries) != expected_paths:
        raise DeliveryPackageError("manifest contains a path outside the evidence allowlist")
    for path, entry in entries.items():
        expected_privacy = (
            "customer_private" if path.startswith("acceptance/") else "public"
        )
        if entry.privacy_class != expected_privacy:
            raise DeliveryPackageError("manifest privacy class does not match the allowlist")
    return history


def replay_verification(history: AcceptanceHistory) -> VerificationDecision:
    decision = history.current_decision
    if decision is None:
        raise DeliveryPackageError("verification history has no current decision")
    return decision


def replay_acceptance(history: AcceptanceHistory) -> EffectiveAcceptance:
    return effective_acceptance(history)


def verify_delivery_package(package_root: Path) -> DeliveryVerificationResult:
    manifest = load_and_verify_manifest(package_root)
    anchors = load_and_verify_anchors(package_root, manifest)
    history = load_signed_history(package_root, manifest, anchors)
    decision = replay_verification(history)
    acceptance = replay_acceptance(history)
    readiness = settlement_readiness(
        decision=decision,
        acceptance=acceptance,
        rejection=history.rejection,
    )
    return DeliveryVerificationResult(
        current_decision=decision.decision,
        effective_acceptance=acceptance.value,
        settlement_readiness=readiness.value,
        manifest_digest=digest_manifest(manifest),
    )


_VERIFY_SCRIPT = b"""#!/bin/sh
set -eu
python -c 'from pathlib import Path; from openworkproof.delivery_package import verify_delivery_package; print(verify_delivery_package(Path("." )).model_dump_json())'
"""


_DELIVERY_ROOM_CSS = """
:root {
  color-scheme: light;
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: #17202a;
  background: #f5f7f8;
}
* { box-sizing: border-box; }
body { max-width: 920px; margin: 0 auto; padding: 48px 24px 72px; }
header { margin-bottom: 28px; }
h1 { margin: 0 0 8px; font-size: clamp(30px, 5vw, 48px); }
.lede { margin: 0; color: #52606d; font-size: 18px; }
.state-strip { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1px;
  margin: 28px 0; overflow: hidden; border: 1px solid #d8dee4; border-radius: 12px;
  background: #d8dee4; }
.state-strip div { padding: 14px 16px; background: #fff; }
.state-strip span { display: block; color: #687785; font-size: 13px; }
.state-strip strong { display: block; margin-top: 4px; overflow-wrap: anywhere; }
.customer-question { margin: 0 0 14px; padding: 22px 24px; border: 1px solid #d8dee4;
  border-radius: 12px; background: #fff; }
.customer-question h2 { margin: 0 0 8px; font-size: 20px; }
.customer-question p { margin: 5px 0; line-height: 1.65; }
.next-action { margin-top: 24px; padding: 18px 22px; border-left: 5px solid #16835d;
  background: #eaf7f1; font-weight: 700; }
.boundary { margin-top: 18px; color: #52606d; font-size: 14px; }
code { overflow-wrap: anywhere; }
@media (max-width: 680px) { .state-strip { grid-template-columns: 1fr; } }
""".strip()


def _decision_answer(decision: VerificationDecision) -> str:
    if decision.decision == "VERIFIED":
        return "已验证：正向执行与反证控制满足约定。"
    if decision.decision == "REFUTED":
        return "已否证：存在可复现反证，当前交付不能通过。"
    return (
        "尚无确定结论：证据缺失、基础设施故障或独立性不足，"
        "不能视为通过或失败。"
    )


def _falsification_answer(decision: VerificationDecision) -> str:
    if decision.decision == "VERIFIED":
        return "通过：负向或变异检查被正确识别，反证控制有效。"
    if decision.decision == "REFUTED":
        return "未通过：反证显示交付与约定不一致。"
    return "未得出结论：反证证据不完整或不可独立复核。"


def _readiness_answer(
    readiness: SettlementReadiness,
    *,
    rejected: bool,
) -> str:
    if rejected:
        return "客户已拒绝当前交付；当前不可进入验收或结算准备。"
    return {
        SettlementReadiness.NOT_READY: "当前不可进入验收或结算准备。",
        SettlementReadiness.READY_FOR_ACCEPTANCE: "验证已完成，可提交客户验收。",
        SettlementReadiness.ACCEPTED_FOR_SETTLEMENT: (
            "客户验收证据已生效，具备进入外部结算流程的证据条件。"
        ),
        SettlementReadiness.SUSPENDED: "验收已暂停，暂停原因解除前不可继续。",
        SettlementReadiness.WITHDRAWN: "验收已撤回，需要新的验收事实。",
        SettlementReadiness.SUPERSEDED: "原验收已被替代，应使用最新验收记录。",
    }[readiness]


def _next_action(
    decision: VerificationDecision,
    readiness: SettlementReadiness,
    *,
    rejected: bool,
) -> str:
    if rejected:
        return "下一步：处理拒绝原因，形成新版本后重新验证并提交验收。"
    if decision.decision == "REFUTED":
        return "下一步：修复被反证的问题，生成新版本并重新执行双臂验证。"
    if decision.decision == "UNKNOWN":
        return "下一步：补齐缺失证据或恢复独立执行环境后重新验证。"
    return {
        SettlementReadiness.NOT_READY: "下一步：补齐验收前置条件后重新计算状态。",
        SettlementReadiness.READY_FOR_ACCEPTANCE: (
            "下一步：由独立 Acceptor 审阅并签署验收结果。"
        ),
        SettlementReadiness.ACCEPTED_FOR_SETTLEMENT: (
            "下一步：按外部合同与支付系统执行结算；本协议不执行付款。"
        ),
        SettlementReadiness.SUSPENDED: (
            "下一步：解决暂停原因，由 Acceptor 签署新的状态转换。"
        ),
        SettlementReadiness.WITHDRAWN: "下一步：重新提交版本并启动新的验收。",
        SettlementReadiness.SUPERSEDED: (
            "下一步：切换到替代验收记录对应的最新交付包。"
        ),
    }[readiness]


def _summary_html(
    *,
    work_order: WorkOrder,
    claim: SubjectClaim,
    decision: VerificationDecision,
    effective: EffectiveAcceptance,
    readiness: SettlementReadiness,
    rejected: bool,
) -> bytes:
    def escape(value: object) -> str:
        return html.escape(str(value), quote=True)

    authority = (
        f"签发主体：{escape(work_order.issuer_id)}；已签名工作单："
        f"<code>{escape(work_order.digest)}</code>。"
    )
    target = (
        f"交付目标：{escape(claim.delivery_target)}；源码版本："
        f"<code>{escape(claim.source_revision)}</code>。"
    )
    agreed = (
        f"<strong>{escape(decision.decision)}</strong> — "
        f"{escape(_decision_answer(decision))}<br>约定声明："
        f"{escape(claim.claim_statement)}"
    )
    falsification = escape(_falsification_answer(decision))
    readiness_answer = escape(_readiness_answer(readiness, rejected=rejected))
    next_action = escape(_next_action(decision, readiness, rejected=rejected))
    sections = (
        ("谁授权了这项工作？", authority),
        ("验收的是哪个交付目标和版本？", target),
        ("约定结果是否达成？", agreed),
        ("反证检查是否通过？", falsification),
        ("当前能否进入验收或结算准备？", readiness_answer),
    )
    questions = "".join(
        '<section class="customer-question">'
        f"<h2>{escape(question)}</h2><p>{answer}</p></section>"
        for question, answer in sections
    )
    return (
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>OpenWorkProof 客户交付室</title>"
        f"<style>{_DELIVERY_ROOM_CSS}</style></head>"
        f'<body data-decision="{escape(decision.decision)}" '
        f'data-acceptance="{escape(effective.value)}" '
        f'data-readiness="{escape(readiness.value)}">'
        "<header><h1>客户交付室</h1>"
        "<p class=\"lede\">以下结论由交付包中的签名事实与离线回放结果生成。</p>"
        "</header><div class=\"state-strip\">"
        f"<div><span>验证结论</span><strong>{escape(decision.decision)}</strong></div>"
        f"<div><span>有效验收</span><strong>{escape(effective.value)}</strong></div>"
        f"<div><span>结算准备</span><strong>{escape(readiness.value)}</strong></div>"
        f"</div><main>{questions}</main>"
        f'<p class="next-action">{next_action}</p>'
        "<p class=\"boundary\">本页面不作为付款、资金托管或实际结算事实的证明；"
        "它只呈现可离线复核的授权、执行、验证与验收状态。</p>"
        "</body></html>"
    ).encode("utf-8")


def _media_type(path: str) -> str:
    if path.endswith(".json"):
        return "application/json"
    if path.endswith(".html"):
        return "text/html"
    if path.endswith(".sh"):
        return "text/x-shellscript"
    if path.endswith(".pdf"):
        return "application/pdf"
    return "application/octet-stream"


def _source_file(ledger: Path, relative: str) -> bytes:
    source = ledger.parent.joinpath(*relative.split("/"))
    _assert_regular_file(source)
    payload = source.read_bytes()
    if any(pattern.search(payload) for pattern in _SECRET_PATTERNS):
        raise DeliveryPackageError("evidence source contains a secret pattern")
    return payload


def _ledger_export_read(
    ledger: Path,
) -> tuple[
    WorkOrder,
    SubjectClaim,
    VerificationProfileV02,
    VerificationDecision,
    tuple[PolicyAnchor | None, CommitmentAnchor | None],
    tuple[VerificationArmResult, ...],
    tuple[object, ...],
    list[dict[str, object]],
    list[dict[str, object]],
    AcceptanceHistory,
]:
    from openworkproof import settlement, verification

    lock_descriptor: int | None = None
    connection = None
    try:
        lock_descriptor, _ = evidence._borrow_or_acquire_target_lock(ledger, None)
        connection = evidence.connect_ledger(ledger)
        connection.execute("BEGIN")
        work_order, claim, profile = verification._load_single_profile(connection)
        if profile.delivery_trust_level not in {2, 3}:
            raise DeliveryPackageError("Delivery Package export requires Level 2/3")
        decision = verification._load_current_decision(connection, profile=profile)
        if decision is None:
            raise DeliveryPackageError("Delivery Package export requires a decision")
        if decision.supersedes_decision_id is not None:
            raise DeliveryPackageError("decision-chain export is not yet closed")
        results = verification._load_arm_results(
            connection,
            profile=profile,
            selected_ids=tuple(item.arm_result_id for item in decision.arm_results),
        )
        anchors = []
        for digest, kind, model in (
            (profile.policy_anchor_digest, "policy", PolicyAnchor),
            (profile.commitment_anchor_digest, "commitment", CommitmentAnchor),
        ):
            if digest is None:
                anchors.append(None)
                continue
            row = connection.execute(
                "SELECT anchor_kind, anchor_json FROM external_anchors WHERE anchor_digest = ?",
                (digest,),
            ).fetchone()
            if row is None or row[0] != kind:
                raise DeliveryPackageError("ledger anchor is unavailable")
            anchor = model.model_validate_json(row[1])
            if external_anchor_digest(anchor) != digest:
                raise DeliveryPackageError("ledger anchor integrity failed")
            anchors.append(anchor)
        receipt_rows = tuple(
            connection.execute(
                "SELECT receipt_json FROM receipts ORDER BY sequence"
            )
        )
        receipts = tuple(
            evidence.ACTION_RECEIPT_ADAPTER.validate_json(row[0])
            for row in receipt_rows
        )
        parent_rows = [
            {"child_receipt_id": child, "parent_receipt_id": parent}
            for child, parent in connection.execute(
                "SELECT child_receipt_id, parent_receipt_id FROM receipt_parents ORDER BY child_receipt_id, parent_receipt_id"
            )
        ]
        publication_rows = [
            {
                "publication_id": publication_id,
                "receipt_id": receipt_id,
                "final_path": final_path,
                "sha256": digest,
                "size_bytes": size,
                "media_type": media_type,
            }
            for publication_id, receipt_id, final_path, digest, size, media_type, state
            in connection.execute(
                "SELECT publication_id, receipt_id, final_path, digest, size_bytes, media_type, state FROM evidence_publications ORDER BY final_path"
            )
            if state == "COMMITTED"
        ]
        acceptances = evidence._validated_acceptance_receipts(connection, work_order)
        rejections = evidence._validated_acceptance_rejections(connection, work_order)
        if len(acceptances) > 1 or len(rejections) > 1 or (acceptances and rejections):
            raise DeliveryPackageError("acceptance ledger history is invalid")
        acceptance = acceptances[0] if acceptances else None
        rejection = rejections[0] if rejections else None
        transition = settlement._load_transition(
            connection, work_order=work_order, acceptance=acceptance
        )
        history = AcceptanceHistory.model_validate(
            {
                "acceptance": None if acceptance is None else acceptance.model_dump(mode="json"),
                "rejection": None if rejection is None else rejection.model_dump(mode="json"),
                "withdrawal": (
                    transition.model_dump(mode="json")
                    if transition is not None and transition.transition == "withdrawn"
                    else None
                ),
                "supersession": (
                    transition.model_dump(mode="json")
                    if transition is not None and transition.transition == "superseded"
                    else None
                ),
                "current_decision": decision.model_dump(mode="json"),
            }
        )
        connection.execute("ROLLBACK")
        return (
            work_order,
            claim,
            profile,
            decision,
            (anchors[0], anchors[1]),
            results,
            receipts,
            parent_rows,
            publication_rows,
            history,
        )
    except DeliveryPackageError:
        evidence._best_effort_rollback(connection)
        raise
    except Exception as error:
        evidence._best_effort_rollback(connection)
        raise DeliveryPackageError("ledger cannot produce a delivery package") from error
    finally:
        close_error = evidence._best_effort_close(connection)
        _, release_errors = evidence._release_target_lock(lock_descriptor)
        if close_error is not None or release_errors:
            raise DeliveryPackageError("delivery ledger read lock cleanup failed")


def _write_file(root: Path, relative: str, payload: bytes) -> None:
    target = _safe_package_file(root, relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)


def _cleanup_temporary(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    try:
        shutil.rmtree(path)
    except Exception as cleanup_error:
        raise DeliveryPackageError("delivery package cleanup failed") from cleanup_error


def export_delivery_package(
    ledger: Path,
    output: Path,
    *,
    privacy_view: Literal["public", "customer_private"],
) -> DeliveryManifest:
    ledger_path = Path(ledger)
    output_path = Path(output)
    if privacy_view not in {"public", "customer_private"}:
        raise DeliveryPackageError("privacy view is invalid")
    if not ledger_path.is_file():
        raise DeliveryPackageError("delivery ledger is unavailable")
    if output_path.exists() or output_path.is_symlink():
        raise DeliveryPackageError("delivery package output already exists")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.parent / f".{output_path.name}.{uuid.uuid4().hex}.tmp"
    try:
        (
            work_order,
            claim,
            profile,
            decision,
            anchors,
            arm_results,
            receipts,
            parent_rows,
            publication_rows,
            history,
        ) = _ledger_export_read(ledger_path)
        temporary.mkdir(mode=0o700)
        files: dict[str, tuple[bytes, str]] = {
            "subject-claim.json": (_canonical_bytes(claim.model_dump(mode="json")), "public"),
            "work-order.json": (_canonical_bytes(work_order.model_dump(mode="json")), "public"),
            "verification-profile.json": (_canonical_bytes(profile.model_dump(mode="json")), "public"),
            "verification-decision.json": (_canonical_bytes(decision.model_dump(mode="json")), "public"),
            "execution-ledger/receipts.json": (
                _canonical_bytes([item.model_dump(mode="json") for item in receipts]),
                "public",
            ),
            "execution-ledger/receipt-parents.json": (_canonical_bytes(parent_rows), "public"),
            "execution-ledger/evidence-publications.json": (
                _canonical_bytes(publication_rows),
                "public",
            ),
        }
        policy_anchor, commitment_anchor = anchors
        if policy_anchor is not None:
            files["anchors/policy-anchor.json"] = (
                _canonical_bytes(policy_anchor.model_dump(mode="json")),
                "public",
            )
        if commitment_anchor is not None:
            files["anchors/commitment-anchor.json"] = (
                _canonical_bytes(commitment_anchor.model_dump(mode="json")),
                "public",
            )
        for result in arm_results:
            files[
                f"evidence/{result.arm_kind}/arm-results/{result.arm_result_id}.json"
            ] = (_canonical_bytes(result.model_dump(mode="json")), "public")
            for reference in result.evidence_refs:
                _assert_safe_evidence_relative(reference.path)
                payload = _source_file(ledger_path, reference.path)
                if (
                    len(payload) != reference.size_bytes
                    or hashlib.sha256(payload).hexdigest() != reference.sha256
                ):
                    raise DeliveryPackageError("ledger evidence payload integrity failed")
                files[f"evidence/{result.arm_kind}/{reference.path}"] = (
                    payload,
                    "public",
                )
        key_records: dict[str, dict[str, object]] = {
            binding.key_id: {
                "key_id": binding.key_id,
                "public_key_b64url": binding.public_key_b64url,
                "role": binding.role,
                "subject_id": binding.subject_id,
            }
            for binding in work_order.key_bindings
        }
        for binding in profile.verifier_bindings:
            key_records.setdefault(
                binding.verifier_key_id,
                {
                    "key_id": binding.verifier_key_id,
                    "public_key_b64url": binding.verifier_public_key_b64url,
                    "role": "Verifier",
                    "subject_id": binding.verifier_subject_id,
                },
            )
        for identifier, record in key_records.items():
            files[f"public-keys/{identifier.replace(':', '_')}.json"] = (
                _canonical_bytes(record),
                "public",
            )
        for value, relative in (
            (history.acceptance, "acceptance/acceptance-receipt.json"),
            (history.rejection, "acceptance/rejection-receipt.json"),
            (history.withdrawal, "acceptance/withdrawal-receipt.json"),
            (history.supersession, "acceptance/supersession-receipt.json"),
        ):
            if value is not None:
                files[relative] = (
                    _canonical_bytes(value.model_dump(mode="json")),
                    "customer_private",
                )
        effective = effective_acceptance(history)
        readiness = settlement_readiness(
            decision=decision,
            acceptance=effective,
            rejection=history.rejection,
        )
        files["settlement-readiness.json"] = (
            _canonical_bytes(
                {
                    "current_decision_id": decision.decision_id,
                    "effective_acceptance": effective.value,
                    "settlement_readiness": readiness.value,
                }
            ),
            "public",
        )
        files["summary.html"] = (
            _summary_html(
                work_order=work_order,
                claim=claim,
                decision=decision,
                effective=effective,
                readiness=readiness,
                rejected=history.rejection is not None,
            ),
            "public",
        )
        files["verify.sh"] = (_VERIFY_SCRIPT, "public")
        if privacy_view == "public":
            private_required = tuple(
                path for path, (_, privacy) in files.items() if privacy == "customer_private"
            )
            if private_required:
                raise DeliveryPackageError(
                    "public view cannot omit the current private acceptance history"
                )
        entries = []
        for relative in sorted(files, key=lambda value: value.encode("utf-8")):
            payload, privacy = files[relative]
            if len(payload) > _MAX_FILE_BYTES:
                raise DeliveryPackageError("delivery package file is oversized")
            if any(pattern.search(payload) for pattern in _SECRET_PATTERNS):
                raise DeliveryPackageError("delivery package contains a secret pattern")
            _write_file(temporary, relative, payload)
            entries.append(
                DeliveryManifestEntry(
                    path=relative,
                    sha256=hashlib.sha256(payload).hexdigest(),
                    size_bytes=len(payload),
                    media_type=_media_type(relative),
                    privacy_class=privacy,
                    required=True,
                )
            )
        manifest = DeliveryManifest.model_validate(
            {
                "schema_version": "openworkproof-delivery-manifest/0.1",
                "privacy_view": privacy_view,
                "work_order_digest": work_order.digest,
                "subject_claim_digest": claim.digest,
                "verification_decision_digest": decision.digest,
                "entries": [entry.model_dump(mode="json") for entry in entries],
            }
        )
        _write_file(
            temporary,
            "manifest.json",
            _canonical_bytes(manifest.model_dump(mode="json")),
        )
        verify_delivery_package(temporary)
        os.rename(temporary, output_path)
        return manifest
    except DeliveryPackageError:
        _cleanup_temporary(temporary)
        raise
    except Exception as error:
        _cleanup_temporary(temporary)
        raise DeliveryPackageError("delivery package export failed") from error


__all__ = [
    "DeliveryManifest",
    "DeliveryManifestEntry",
    "DeliveryPackageError",
    "DeliveryVerificationResult",
    "digest_manifest",
    "export_delivery_package",
    "load_and_verify_anchors",
    "load_signed_history",
    "replay_acceptance",
    "replay_verification",
    "verify_delivery_package",
]
