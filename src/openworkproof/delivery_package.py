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
from pydantic import Field, model_validator

import openworkproof.evidence as evidence
from openworkproof.models import (
    AcceptanceReceipt,
    AcceptanceRejectionReceipt,
    AcceptanceTransitionReceipt,
    CanonicalRoot,
    CommitmentAnchor,
    Digest64,
    EvaluationScopeManifest,
    Identifier,
    PolicyAnchor,
    ProtocolModel,
    SafeNonNegativeInt,
    SubjectClaim,
    VerificationArmResult,
    VerificationArmResultV03,
    VerificationDecision,
    VerificationDecisionV03,
    VerificationProfileV02,
    VerificationProfileV03,
    WorkOrder,
)
from openworkproof.scope import ObservedScope, compare_observed_scope
from openworkproof.settlement import (
    AcceptanceHistory,
    EffectiveAcceptance,
    SettlementReadiness,
    effective_acceptance,
    settlement_readiness,
)
from openworkproof.signing import (
    decode_and_verify_key_binding,
    verify_action_receipt_signature,
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


PrivacyClass = Literal["public", "diagnostic", "customer_private"]
PrivacyView = Literal["public", "diagnostic", "customer_private"]


class DeliveryManifestEntry(ProtocolModel):
    path: CanonicalRoot
    sha256: Digest64
    size_bytes: SafeNonNegativeInt
    media_type: Identifier
    privacy_class: PrivacyClass
    required: bool


class DeliveryManifest(ProtocolModel):
    schema_version: Literal["openworkproof-delivery-manifest/0.1"]
    privacy_view: PrivacyView
    work_order_digest: Digest64
    subject_claim_digest: Digest64
    verification_decision_digest: Digest64
    verification_protocol_version: Literal["0.2", "0.3", "0.5"] | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    scope_manifest_digest: Digest64 | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    full_offline_replay: bool | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    binding_protocol_version: Literal["0.4"] | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    judgment_commitment_digest: Digest64 | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    action_binding_manifest_digest: Digest64 | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    binding_decision_digest: Digest64 | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    binding_replay: Literal[
        "unavailable_in_this_view", "BOUND", "UNBOUND", "INDETERMINATE"
    ] | None = Field(default=None, exclude_if=lambda value: value is None)
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
        rank = {"public": 0, "diagnostic": 1, "customer_private": 2}
        if any(
            rank[entry.privacy_class] > rank[self.privacy_view]
            for entry in self.entries
        ):
            raise ValueError("manifest contains an entry outside its privacy view")
        if self.verification_protocol_version in {"0.3", "0.5"}:
            if self.scope_manifest_digest is None or self.full_offline_replay is None:
                raise ValueError(
                    "v0.3/v0.5 manifest requires scope and replay metadata"
                )
            if self.full_offline_replay != (
                self.privacy_view == "customer_private"
            ):
                raise ValueError("v0.3 full replay is customer-private only")
        elif any(
            value is not None
            for value in (
                self.scope_manifest_digest,
                self.full_offline_replay,
            )
        ):
            raise ValueError("v0.2 manifest forbids v0.3 replay metadata")
        if self.binding_protocol_version == "0.4":
            if (
                self.judgment_commitment_digest is None
                or self.action_binding_manifest_digest is None
                or self.binding_decision_digest is None
                or self.binding_replay is None
            ):
                raise ValueError(
                    "v0.4 manifest requires judgment, manifest, decision "
                    "digests and a binding replay marker"
                )
            if (
                self.binding_replay == "unavailable_in_this_view"
                and self.privacy_view == "customer_private"
            ):
                raise ValueError(
                    "customer-private v0.4 package must carry a real binding replay"
                )
        elif any(
            value is not None
            for value in (
                self.binding_protocol_version,
                self.judgment_commitment_digest,
                self.action_binding_manifest_digest,
                self.binding_decision_digest,
                self.binding_replay,
            )
        ):
            raise ValueError(
                "pre-v0.4 manifest forbids v0.4 binding metadata"
            )
        return self


class DeliveryVerificationResult(ProtocolModel):
    current_decision: Literal["VERIFIED", "REFUTED", "UNKNOWN", "UNAUTHENTICATED"]
    effective_acceptance: Literal[
        "NONE", "ACTIVE", "SUSPENDED", "WITHDRAWN", "SUPERSEDED"
    ]
    settlement_readiness: Literal[
        "NOT_READY",
        "READY_FOR_ACCEPTANCE",
        "ACCEPTED_FOR_SETTLEMENT",
        "READY_FOR_SETTLEMENT_REVIEW",
        "SUSPENDED",
        "WITHDRAWN",
        "SUPERSEDED",
    ]
    manifest_digest: Digest64
    full_offline_replay: bool | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    binding_replay: Literal[
        "unavailable_in_this_view", "BOUND", "UNBOUND", "INDETERMINATE"
    ] | None = Field(default=None, exclude_if=lambda value: value is None)
    binding_reason_codes: tuple[str, ...] | None = Field(
        default=None, exclude_if=lambda value: value is None
    )


def digest_manifest(manifest: DeliveryManifest) -> str:
    payload = rfc8785.dumps(
        manifest.model_dump(mode="json", exclude_unset=True)
    )
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
    if _canonical_bytes(
        manifest.model_dump(mode="json", exclude_unset=True)
    ) != raw:
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
        rank = {"public": 0, "diagnostic": 1, "customer_private": 2}
        if rank[entry.privacy_class] > rank[manifest.privacy_view]:
            raise DeliveryPackageError("delivery package leaks private content")
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
            receipt = evidence.parse_action_receipt(raw)
        except Exception as error:
            raise DeliveryPackageError("execution receipt is malformed") from error
        if (
            receipt.receipt_id in by_id
            or receipt.work_order_digest != work_order.digest
            or not verify_action_receipt_signature(receipt, sidecar_key)
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


def _scope_coverage_report_v03(
    *,
    claim: SubjectClaim,
    manifest: EvaluationScopeManifest,
    decision: VerificationDecisionV03,
    arm_results: tuple[VerificationArmResultV03, ...],
    privacy_view: PrivacyView,
) -> dict[str, object]:
    observed_counts = [result.observed_member_count for result in arm_results]
    observed_digests = {
        result.observed_population_digest for result in arm_results
    }
    missing = decision.scope_assessment.missing_required_target_ids
    claim_view: dict[str, object] = {"digest": claim.digest}
    if privacy_view == "customer_private":
        claim_view["statement"] = claim.claim_statement
    bounded = {
        "VERIFIED": (
            "VERIFIED within the signed Evaluation Scope: every observed arm "
            "matched the declared population, required targets were covered, "
            "and registered negative controls were caught."
        ),
        "REFUTED": (
            "REFUTED within the signed Evaluation Scope: a registered negative "
            "control survived or another conclusive contradiction was observed."
        ),
        "UNKNOWN": (
            "UNKNOWN within the signed Evaluation Scope: missing, inconsistent, "
            "or incomplete evidence prevents a conclusive result."
        ),
    }[decision.decision]
    report: dict[str, object] = {
        "schema_version": "openworkproof-scope-coverage-report/0.3",
        "privacy_view": privacy_view,
        "full_offline_replay": privacy_view == "customer_private",
        "claim": claim_view,
        "source_revision": manifest.source_revision,
        "candidate_commit": manifest.candidate_commit,
        "scope_manifest_digest": manifest.digest,
        "selector_engine_digests": sorted(
            {rule.selector_engine_digest for rule in manifest.selector_rules}
        ),
        "declared_member_count": manifest.member_count,
        "observed_member_counts": observed_counts,
        "population_digest": manifest.population_digest,
        "required_coverage": {
            "declared_count": len(manifest.required_target_ids),
            "missing_count": len(missing),
        },
        "excluded_count": len(manifest.excluded_locator_digests),
        "cross_arm_consistent": (
            len(observed_digests) == 1
            and observed_digests == {manifest.population_digest}
            and all(count == manifest.member_count for count in observed_counts)
        ),
        "decision": decision.decision,
        "reason_codes": list(decision.reason_codes),
        "signature_digests": [
            hashlib.sha256(
                _canonical_bytes(signature.model_dump(mode="json"))
            ).hexdigest()
            for signature in decision.verifier_signatures
        ],
        "bounded_conclusion": bounded,
        "replay_command": (
            "./verify.sh"
            if privacy_view == "customer_private"
            else None
        ),
        "boundary": (
            (
                "This is not a complete offline replay package. "
                if privacy_view != "customer_private"
                else ""
            )
            + "This report does not prove payment, automatic settlement, absolute "
            "correctness, regulatory compliance, customer adoption, or deployment."
        ),
    }
    if privacy_view == "customer_private":
        report["required_coverage"] = {
            "declared_count": len(manifest.required_target_ids),
            "missing_count": len(missing),
            "missing_target_ids": list(missing),
        }
    return report


def _scope_report_html_v03(report: dict[str, object]) -> bytes:
    encoded = html.escape(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True),
        quote=False,
    )
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<title>OpenWorkProof Scope Coverage Report</title>"
        "<style>body{font-family:system-ui;max-width:960px;margin:40px auto;"
        "padding:0 24px;color:#17202a}pre{white-space:pre-wrap;background:#f5f7f8;"
        "padding:20px;border-radius:10px}.boundary{color:#52606d}</style>"
        "</head><body><h1>Scope Coverage Report</h1>"
        f"<p><strong>{html.escape(str(report['bounded_conclusion']))}</strong></p>"
        f"<pre>{encoded}</pre><p class=\"boundary\">"
        f"{html.escape(str(report['boundary']))}</p></body></html>"
    ).encode("utf-8")


def _load_v03_protocol_objects(
    root: Path,
    manifest: DeliveryManifest,
) -> tuple[
    WorkOrder,
    SubjectClaim,
    EvaluationScopeManifest,
    VerificationProfileV03,
    VerificationDecisionV03,
]:
    from openworkproof import verification  # noqa: PLC0415

    try:
        work_order = WorkOrder.model_validate(
            _load_canonical_json(root, manifest, "work-order.json")
        )
        claim = SubjectClaim.model_validate(
            _load_canonical_json(root, manifest, "subject-claim.json")
        )
        scope_manifest = EvaluationScopeManifest.model_validate(
            _load_canonical_json(root, manifest, "evaluation-scope.json")
        )
        profile = VerificationProfileV03.model_validate(
            _load_canonical_json(root, manifest, "verification-profile.json")
        )
        decision = VerificationDecisionV03.model_validate(
            _load_canonical_json(root, manifest, "verification-decision.json")
        )
    except Exception as error:
        raise DeliveryPackageError("v0.3 delivery protocol object is invalid") from error
    if (
        work_order.digest != manifest.work_order_digest
        or claim.digest != manifest.subject_claim_digest
        or scope_manifest.digest != manifest.scope_manifest_digest
        or decision.digest != manifest.verification_decision_digest
        or claim.work_order_digest != work_order.digest
        or scope_manifest.work_order_digest != work_order.digest
        or scope_manifest.subject_claim_digest != claim.digest
    ):
        raise DeliveryPackageError("v0.3 delivery protocol binding failed")
    if not verify_work_order_identity_bindings(work_order):
        raise DeliveryPackageError("v0.3 WorkOrder identity binding failed")
    manager = next(item for item in work_order.key_bindings if item.role == "Manager")
    manager_key = decode_and_verify_key_binding(manager)
    if not verify_payload(
        "subject-claim", claim.model_dump(mode="json"), manager_key
    ) or not verify_payload(
        "evaluation-scope",
        scope_manifest.model_dump(mode="json"),
        manager_key,
        version="0.3",
    ) or not verify_payload(
        "verification-profile",
        profile.model_dump(mode="json"),
        manager_key,
        version="0.3",
    ):
        raise DeliveryPackageError("v0.3 manager signature binding failed")
    try:
        verification.validate_verification_profile_v03(profile, scope_manifest)
        verification.validate_verification_decision_v03(
            profile=profile,
            manifest=scope_manifest,
            decision=decision,
        )
    except Exception as error:
        raise DeliveryPackageError("v0.3 verification binding failed") from error
    return work_order, claim, scope_manifest, profile, decision


def _binding_report_html(report: dict) -> bytes:
    """Render the v0.4 binding report summary (derived truth)."""

    replay = report.get("binding_replay", "unavailable_in_this_view")
    codes = ", ".join(report.get("binding_reason_codes", []))
    return (
        "<html><body>"
        "<h1>Judgment-to-Action Binding Report</h1>"
        f"<p>binding_replay: <code>{html.escape(str(replay))}</code></p>"
        f"<p>binding_reason_codes: <code>{html.escape(codes)}</code></p>"
        "<p>本结果不证明付款或结算已发生。</p>"
        "</body></html>"
    ).encode("utf-8")


def _verify_v04_delivery_package(
    root: Path,
    manifest: DeliveryManifest,
) -> DeliveryVerificationResult:
    """Verify a v0.4 package: Layer 1 structure first, then the binding
    replay (Layer 2). A Layer 1 failure is a package verification failure;
    it is never reported as UNBOUND."""

    report = _load_canonical_json(root, manifest, "binding-report.json")
    if not isinstance(report, dict) or (
        report.get("schema_version")
        != "openworkproof-binding-report/0.4"
        or report.get("privacy_view") != manifest.privacy_view
        or report.get("judgment_commitment_digest")
        != manifest.judgment_commitment_digest
        or report.get("action_binding_manifest_digest")
        != manifest.action_binding_manifest_digest
        or report.get("binding_decision_digest")
        != manifest.binding_decision_digest
        or report.get("binding_replay") != manifest.binding_replay
        or report.get("verification_decision")
        not in {"VERIFIED", "REFUTED", "UNKNOWN"}
        or report.get("effective_acceptance")
        not in {"NONE", "ACTIVE", "SUSPENDED", "WITHDRAWN", "SUPERSEDED"}
        or report.get("settlement_readiness")
        not in {
            "NOT_READY",
            "READY_FOR_ACCEPTANCE",
            "ACCEPTED_FOR_SETTLEMENT",
            "READY_FOR_SETTLEMENT_REVIEW",
            "SUSPENDED",
            "WITHDRAWN",
            "SUPERSEDED",
        }
    ):
        raise DeliveryPackageError("v0.4 binding report binding failed")
    if manifest.privacy_view != "public":
        if _read_bound(root, manifest, "binding-report.html") != (
            _binding_report_html(report)
        ):
            raise DeliveryPackageError(
                "v0.4 binding report rendering is not derived truth"
            )

    if manifest.privacy_view == "customer_private":
        private_paths = {
            "binding-report.json",
            "binding-report.html",
            "binding-replay-inputs.json",
        }
        if set(_entry_map(manifest)) != private_paths:
            raise DeliveryPackageError(
                "customer-private v0.4 package file set is not exact"
            )
        inputs = _load_canonical_json(
            root, manifest, "binding-replay-inputs.json"
        )
        try:
            from openworkproof.adapters import (  # noqa: PLC0415
                CodeDeliveryAdapterProfile,
                CodeDeliveryJudgmentInput,
                CodeDeliveryReplayInput,
                ObservedAction,
                replay_code_delivery_binding,
            )

            replay = replay_code_delivery_binding(
                CodeDeliveryReplayInput(
                    judgment=CodeDeliveryJudgmentInput(
                        **inputs["judgment"]
                    ),
                    profile=CodeDeliveryAdapterProfile(
                        **inputs["profile"]
                    ),
                    observed=ObservedAction(**inputs["observed"]),
                )
            )
        except Exception as error:
            raise DeliveryPackageError(
                "v0.4 binding replay inputs are malformed"
            ) from error
        expected_codes = tuple(report.get("binding_reason_codes", []))
        if (
            replay.outcome != manifest.binding_replay
            or replay.reason_codes != expected_codes
        ):
            raise DeliveryPackageError(
                "v0.4 binding replay is not derived truth"
            )
        return DeliveryVerificationResult(
            current_decision=report["verification_decision"],
            effective_acceptance=report["effective_acceptance"],
            settlement_readiness=report["settlement_readiness"],
            manifest_digest=digest_manifest(manifest),
            binding_replay=replay.outcome,
            binding_reason_codes=replay.reason_codes,
        )

    if manifest.binding_replay != "unavailable_in_this_view":
        raise DeliveryPackageError(
            "non-private v0.4 package must declare replay unavailable"
        )
    if manifest.privacy_view == "diagnostic":
        expected = {
            "binding-report.json",
            "binding-report.html",
        }
    else:
        expected = {"binding-report.json"}
    if set(_entry_map(manifest)) != expected:
        raise DeliveryPackageError("redacted v0.4 package is not aggregate-only")
    return DeliveryVerificationResult(
        current_decision=report["verification_decision"],
        effective_acceptance=report["effective_acceptance"],
        settlement_readiness=report["settlement_readiness"],
        manifest_digest=digest_manifest(manifest),
        binding_replay="unavailable_in_this_view",
    )


def _verify_v03_delivery_package(
    root: Path,
    manifest: DeliveryManifest,
) -> DeliveryVerificationResult:
    report = _load_canonical_json(
        root, manifest, "scope-coverage-report.json"
    )
    if not isinstance(report, dict) or (
        report.get("schema_version")
        != "openworkproof-scope-coverage-report/0.3"
        or report.get("privacy_view") != manifest.privacy_view
        or report.get("scope_manifest_digest")
        != manifest.scope_manifest_digest
        or report.get("full_offline_replay")
        != manifest.full_offline_replay
        or report.get("decision") not in {"VERIFIED", "REFUTED", "UNKNOWN"}
    ):
        raise DeliveryPackageError("v0.3 scope report binding failed")
    if _read_bound(root, manifest, "scope-coverage-report.html") != (
        _scope_report_html_v03(report)
    ):
        raise DeliveryPackageError("v0.3 scope report rendering is not derived truth")
    base_paths = {
        "scope-coverage-report.json",
        "scope-coverage-report.html",
    }
    if manifest.privacy_view == "public":
        if set(_entry_map(manifest)) != base_paths:
            raise DeliveryPackageError("public v0.3 package is not aggregate-only")
        return DeliveryVerificationResult(
            current_decision=report["decision"],
            effective_acceptance="NONE",
            settlement_readiness=(
                "READY_FOR_ACCEPTANCE"
                if report["decision"] == "VERIFIED"
                else "NOT_READY"
            ),
            manifest_digest=digest_manifest(manifest),
            full_offline_replay=False,
        )
    if manifest.privacy_view == "diagnostic":
        if set(_entry_map(manifest)) != base_paths | {"scope-diagnostics.json"}:
            raise DeliveryPackageError("diagnostic v0.3 package is not redacted")
        diagnostics = _load_canonical_json(
            root, manifest, "scope-diagnostics.json"
        )
        if not isinstance(diagnostics, dict) or set(diagnostics) != {
            "arm_statuses",
            "decision_reason_codes",
            "scope_status",
        }:
            raise DeliveryPackageError("v0.3 diagnostics are invalid")
        return DeliveryVerificationResult(
            current_decision=report["decision"],
            effective_acceptance="NONE",
            settlement_readiness=(
                "READY_FOR_ACCEPTANCE"
                if report["decision"] == "VERIFIED"
                else "NOT_READY"
            ),
            manifest_digest=digest_manifest(manifest),
            full_offline_replay=False,
        )

    from openworkproof import verification  # noqa: PLC0415

    work_order, claim, scope_manifest, profile, decision = (
        _load_v03_protocol_objects(root, manifest)
    )
    receipts = _load_receipts(root, manifest, work_order)
    receipt_ids = {receipt.receipt_id for receipt in receipts}
    results: list[VerificationArmResultV03] = []
    for reference in decision.arm_results:
        raw = _load_canonical_json(
            root,
            manifest,
            f"evidence/arms/{reference.arm_result_id}.json",
        )
        try:
            result = VerificationArmResultV03.model_validate(raw)
        except Exception as error:
            raise DeliveryPackageError("v0.3 arm result is invalid") from error
        if (
            result.arm_result_id != reference.arm_result_id
            or result.digest != reference.arm_result_digest
            or any(item not in receipt_ids for item in result.action_receipt_ids)
        ):
            raise DeliveryPackageError("v0.3 arm result binding failed")
        for ref in result.evidence_refs:
            payload = _read_bound(
                root,
                manifest,
                f"evidence/results/{result.arm_kind}/{ref.path}",
            )
            if len(payload) != ref.size_bytes or hashlib.sha256(payload).hexdigest() != ref.sha256:
                raise DeliveryPackageError("v0.3 result evidence integrity failed")
        if len(result.scope_evidence_refs) != 1:
            raise DeliveryPackageError("v0.3 scope evidence set is invalid")
        scope_ref = result.scope_evidence_refs[0]
        raw_scope = _read_bound(
            root,
            manifest,
            f"evidence/scope/{result.arm_kind}/{scope_ref.path}",
        )
        if (
            len(raw_scope) != scope_ref.size_bytes
            or hashlib.sha256(raw_scope).hexdigest() != scope_ref.sha256
        ):
            raise DeliveryPackageError("v0.3 scope evidence integrity failed")
        try:
            observed = ObservedScope.model_validate_json(raw_scope)
        except Exception as error:
            raise DeliveryPackageError("v0.3 observed scope is invalid") from error
        comparison = compare_observed_scope(scope_manifest, observed)
        scope_reasons = tuple(
            code for code in result.reason_codes if code.startswith("SCOPE_")
        )
        if (
            result.observed_member_count != observed.member_count
            or result.observed_population_digest != observed.population_digest
            or result.observed_required_target_ids != observed.required_target_ids
            or result.scope_expectation_status != comparison.scope_status
            or scope_reasons != tuple(sorted(comparison.reason_codes))
        ):
            raise DeliveryPackageError("v0.3 scope evidence replay failed")
        results.append(result)
    try:
        ordered_results = tuple(
            sorted(results, key=lambda item: item.arm_result_id)
        )
        verification._validate_arm_results_v03(
            profile=profile,
            manifest=scope_manifest,
            arm_results=ordered_results,
        )
    except Exception as error:
        raise DeliveryPackageError("v0.3 arm result signature failed") from error
    expected_report = _scope_coverage_report_v03(
        claim=claim,
        manifest=scope_manifest,
        decision=decision,
        arm_results=ordered_results,
        privacy_view="customer_private",
    )
    if report != expected_report:
        raise DeliveryPackageError("v0.3 scope report is not derived truth")
    if _load_canonical_json(root, manifest, "scope/selector-rules.json") != [
        item.model_dump(mode="json") for item in scope_manifest.selector_rules
    ] or _load_canonical_json(root, manifest, "scope/members.json") != [
        item.model_dump(mode="json") for item in scope_manifest.members
    ]:
        raise DeliveryPackageError("v0.3 scope detail binding failed")
    selector_evidence_paths: set[str] = set()
    for rule in scope_manifest.selector_rules:
        payloads = []
        for relative in rule.required_evidence_paths:
            if relative in selector_evidence_paths:
                raise DeliveryPackageError(
                    "v0.3 selector evidence path is ambiguous"
                )
            selector_evidence_paths.add(relative)
            payloads.append(
                _read_bound(
                    root,
                    manifest,
                    f"scope/selector-evidence/{relative}",
                )
            )
        if not any(
            hashlib.sha256(payload).hexdigest()
            == rule.selector_spec_digest
            for payload in payloads
        ):
            raise DeliveryPackageError(
                "v0.3 selector specification evidence is unavailable"
            )
    key_records = _load_public_key_records(root, manifest)
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
    if key_records != expected_keys:
        raise DeliveryPackageError("v0.3 public key set is invalid")
    history = _load_acceptance_history(
        root, manifest, work_order, decision, receipts
    )
    effective = effective_acceptance(history)
    calculated_readiness = settlement_readiness(
        decision=decision,
        acceptance=effective,
        rejection=history.rejection,
    )
    readiness = _load_canonical_json(root, manifest, "settlement-readiness.json")
    expected_readiness = {
        "current_decision_id": decision.decision_id,
        "effective_acceptance": effective.value,
        "settlement_readiness": calculated_readiness.value,
    }
    if readiness != expected_readiness:
        raise DeliveryPackageError("v0.3 settlement snapshot is invalid")
    if _read_bound(root, manifest, "verify.sh") != _VERIFY_SCRIPT:
        raise DeliveryPackageError("portable verifier entrypoint is invalid")
    expected_paths = {
        "scope-coverage-report.json",
        "scope-coverage-report.html",
        "scope-diagnostics.json",
        "work-order.json",
        "subject-claim.json",
        "evaluation-scope.json",
        "verification-profile.json",
        "verification-decision.json",
        "scope/selector-rules.json",
        "scope/members.json",
        "execution-ledger/receipts.json",
        "execution-ledger/receipt-parents.json",
        "settlement-readiness.json",
        "verify.sh",
    }
    for result in ordered_results:
        expected_paths.add(f"evidence/arms/{result.arm_result_id}.json")
        expected_paths.update(
            f"evidence/results/{result.arm_kind}/{ref.path}"
            for ref in result.evidence_refs
        )
        expected_paths.update(
            f"evidence/scope/{result.arm_kind}/{ref.path}"
            for ref in result.scope_evidence_refs
        )
    expected_paths.update(
        f"public-keys/{identifier.replace(':', '_')}.json"
        for identifier in expected_keys
    )
    expected_paths.update(
        f"scope/selector-evidence/{relative}"
        for relative in selector_evidence_paths
    )
    for value, relative in (
        (history.acceptance, "acceptance/acceptance-receipt.json"),
        (history.rejection, "acceptance/rejection-receipt.json"),
        (history.withdrawal, "acceptance/withdrawal-receipt.json"),
        (history.supersession, "acceptance/supersession-receipt.json"),
    ):
        if value is not None:
            expected_paths.add(relative)
    if set(_entry_map(manifest)) != expected_paths:
        raise DeliveryPackageError("v0.3 manifest contains a path outside the allowlist")
    expected_privacy = {
        "scope-coverage-report.json": "public",
        "scope-coverage-report.html": "public",
        "scope-diagnostics.json": "diagnostic",
    }
    if any(
        entry.privacy_class
        != expected_privacy.get(entry.path, "customer_private")
        for entry in manifest.entries
    ):
        raise DeliveryPackageError("v0.3 manifest privacy class is invalid")
    return DeliveryVerificationResult(
        current_decision=decision.decision,
        effective_acceptance=effective.value,
        settlement_readiness=calculated_readiness.value,
        manifest_digest=digest_manifest(manifest),
        full_offline_replay=True,
    )


def verify_delivery_package(package_root: Path) -> DeliveryVerificationResult:
    manifest = load_and_verify_manifest(package_root)
    if manifest.binding_protocol_version == "0.4":
        return _verify_v04_delivery_package(Path(package_root), manifest)
    if manifest.verification_protocol_version == "0.3":
        return _verify_v03_delivery_package(Path(package_root), manifest)
    if manifest.verification_protocol_version == "0.5":
        return _verify_v05_delivery_package(Path(package_root), manifest)
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
        SettlementReadiness.READY_FOR_SETTLEMENT_REVIEW: (
            "验证与绑定均通过且验收有效，已具备结算复核证据条件；"
            "本结果不证明付款或结算已发生。"
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
        SettlementReadiness.READY_FOR_SETTLEMENT_REVIEW: (
            "下一步：由外部结算复核人核对商业证据后执行付款；"
            "本协议不证明付款或结算已发生。"
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
            evidence.parse_action_receipt_json(row[0])
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
            connection,
            work_order=work_order,
            acceptance=acceptance,
            protocol_version="0.2",
            decision=decision,
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


def _ledger_delivery_protocol(ledger: Path) -> Literal["0.2", "0.3", "0.5"]:
    connection = evidence.connect_ledger(ledger)
    try:
        v02 = connection.execute(
            "SELECT COUNT(*) FROM verification_profiles_v02"
        ).fetchone()[0]
        v03 = connection.execute(
            "SELECT COUNT(*) FROM verification_profiles_v03"
        ).fetchone()[0]
        v05 = connection.execute(
            "SELECT COUNT(*) FROM verification_profiles_v05"
        ).fetchone()[0]
    finally:
        connection.close()
    if (v02, v03, v05) == (1, 0, 0):
        return "0.2"
    if (v02, v03, v05) == (0, 1, 0):
        return "0.3"
    if (v02, v03, v05) == (0, 0, 1):
        return "0.5"
    raise DeliveryPackageError("delivery verification protocol is ambiguous")


def _ledger_export_read_v03(ledger: Path):
    from openworkproof import settlement, verification  # noqa: PLC0415

    lock_descriptor: int | None = None
    connection = None
    try:
        lock_descriptor, _ = evidence._borrow_or_acquire_target_lock(ledger, None)
        connection = evidence.connect_ledger(ledger)
        connection.execute("BEGIN")
        work_order, claim, scope_manifest, profile = (
            verification._load_single_profile_v03(connection)
        )
        decision = verification._load_current_decision_v03(
            connection, profile=profile, manifest=scope_manifest
        )
        if decision is None:
            raise DeliveryPackageError("v0.3 package export requires a decision")
        if decision.supersedes_decision_id is not None:
            raise DeliveryPackageError("v0.3 decision-chain export is not yet closed")
        arm_results = verification._load_arm_results_v03(
            connection,
            path=ledger,
            work_order=work_order,
            profile=profile,
            manifest=scope_manifest,
            selected_ids=tuple(
                item.arm_result_id for item in decision.arm_results
            ),
        )
        receipts = tuple(
            evidence.parse_action_receipt_json(row[0])
            for row in connection.execute(
                "SELECT receipt_json FROM receipts ORDER BY sequence"
            )
        )
        parent_rows = [
            {"child_receipt_id": child, "parent_receipt_id": parent}
            for child, parent in connection.execute(
                """
                SELECT child_receipt_id, parent_receipt_id
                FROM receipt_parents
                ORDER BY child_receipt_id, parent_receipt_id
                """
            )
        ]
        acceptances = evidence._validated_acceptance_receipts(
            connection, work_order
        )
        rejections = evidence._validated_acceptance_rejections(
            connection, work_order
        )
        if len(acceptances) > 1 or len(rejections) > 1 or (
            acceptances and rejections
        ):
            raise DeliveryPackageError("v0.3 acceptance history is invalid")
        accepted = acceptances[0] if acceptances else None
        rejected = rejections[0] if rejections else None
        transition = settlement._load_transition(
            connection,
            work_order=work_order,
            acceptance=accepted,
            protocol_version="0.3",
            decision=decision,
        )
        history = AcceptanceHistory.model_validate(
            {
                "acceptance": (
                    None if accepted is None else accepted.model_dump(mode="json")
                ),
                "rejection": (
                    None if rejected is None else rejected.model_dump(mode="json")
                ),
                "withdrawal": (
                    transition.model_dump(mode="json")
                    if transition is not None
                    and transition.transition == "withdrawn"
                    else None
                ),
                "supersession": (
                    transition.model_dump(mode="json")
                    if transition is not None
                    and transition.transition == "superseded"
                    else None
                ),
                "current_decision": decision.model_dump(mode="json"),
            }
        )
        connection.execute("ROLLBACK")
        return (
            work_order,
            claim,
            scope_manifest,
            profile,
            decision,
            arm_results,
            receipts,
            parent_rows,
            history,
        )
    except DeliveryPackageError:
        evidence._best_effort_rollback(connection)
        raise
    except Exception as error:
        evidence._best_effort_rollback(connection)
        raise DeliveryPackageError(
            "v0.3 ledger cannot produce a delivery package"
        ) from error
    finally:
        close_error = evidence._best_effort_close(connection)
        _, release_errors = evidence._release_target_lock(lock_descriptor)
        if close_error is not None or release_errors:
            raise DeliveryPackageError("v0.3 delivery read cleanup failed")


def _export_delivery_package_v03(
    ledger: Path,
    output: Path,
    *,
    privacy_view: PrivacyView,
) -> DeliveryManifest:
    temporary = output.parent / f".{output.name}.{uuid.uuid4().hex}.tmp"
    try:
        (
            work_order,
            claim,
            scope_manifest,
            profile,
            decision,
            arm_results,
            receipts,
            parent_rows,
            history,
        ) = _ledger_export_read_v03(ledger)
        temporary.mkdir(mode=0o700)
        report = _scope_coverage_report_v03(
            claim=claim,
            manifest=scope_manifest,
            decision=decision,
            arm_results=arm_results,
            privacy_view=privacy_view,
        )
        files: dict[str, tuple[bytes, PrivacyClass]] = {
            "scope-coverage-report.json": (
                _canonical_bytes(report),
                "public",
            ),
            "scope-coverage-report.html": (
                _scope_report_html_v03(report),
                "public",
            ),
            "scope-diagnostics.json": (
                _canonical_bytes(
                    {
                        "arm_statuses": [
                            {
                                "arm_kind": result.arm_kind,
                                "expectation_status": result.expectation_status,
                                "reason_codes": list(result.reason_codes),
                                "scope_expectation_status": result.scope_expectation_status,
                            }
                            for result in arm_results
                        ],
                        "decision_reason_codes": list(decision.reason_codes),
                        "scope_status": decision.scope_assessment.scope_status,
                    }
                ),
                "diagnostic",
            ),
            "work-order.json": (
                _canonical_bytes(work_order.model_dump(mode="json")),
                "customer_private",
            ),
            "subject-claim.json": (
                _canonical_bytes(claim.model_dump(mode="json")),
                "customer_private",
            ),
            "evaluation-scope.json": (
                _canonical_bytes(scope_manifest.model_dump(mode="json")),
                "customer_private",
            ),
            "verification-profile.json": (
                _canonical_bytes(profile.model_dump(mode="json")),
                "customer_private",
            ),
            "verification-decision.json": (
                _canonical_bytes(decision.model_dump(mode="json")),
                "customer_private",
            ),
            "scope/selector-rules.json": (
                _canonical_bytes(
                    [item.model_dump(mode="json") for item in scope_manifest.selector_rules]
                ),
                "customer_private",
            ),
            "scope/members.json": (
                _canonical_bytes(
                    [item.model_dump(mode="json") for item in scope_manifest.members]
                ),
                "customer_private",
            ),
            "execution-ledger/receipts.json": (
                _canonical_bytes(
                    [item.model_dump(mode="json") for item in receipts]
                ),
                "customer_private",
            ),
            "execution-ledger/receipt-parents.json": (
                _canonical_bytes(parent_rows),
                "customer_private",
            ),
            "verify.sh": (_VERIFY_SCRIPT, "customer_private"),
        }
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
            "customer_private",
        )
        for result in arm_results:
            files[f"evidence/arms/{result.arm_result_id}.json"] = (
                _canonical_bytes(result.model_dump(mode="json")),
                "customer_private",
            )
            for ref in result.evidence_refs:
                _assert_safe_evidence_relative(ref.path)
                payload = _source_file(ledger, ref.path)
                if len(payload) != ref.size_bytes or hashlib.sha256(payload).hexdigest() != ref.sha256:
                    raise DeliveryPackageError("v0.3 result evidence integrity failed")
                files[f"evidence/results/{result.arm_kind}/{ref.path}"] = (
                    payload,
                    "customer_private",
                )
            for ref in result.scope_evidence_refs:
                _assert_safe_evidence_relative(ref.path)
                payload = _source_file(ledger, ref.path)
                if len(payload) != ref.size_bytes or hashlib.sha256(payload).hexdigest() != ref.sha256:
                    raise DeliveryPackageError("v0.3 scope evidence integrity failed")
                files[f"evidence/scope/{result.arm_kind}/{ref.path}"] = (
                    payload,
                    "customer_private",
                )
        selector_paths: set[str] = set()
        for rule in scope_manifest.selector_rules:
            for relative in rule.required_evidence_paths:
                if relative in selector_paths:
                    raise DeliveryPackageError(
                        "v0.3 selector evidence path is ambiguous"
                    )
                selector_paths.add(relative)
                _assert_safe_evidence_relative(relative)
                files[f"scope/selector-evidence/{relative}"] = (
                    _source_file(ledger, relative),
                    "customer_private",
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
                "customer_private",
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
        rank = {"public": 0, "diagnostic": 1, "customer_private": 2}
        visible = {
            path: value
            for path, value in files.items()
            if rank[value[1]] <= rank[privacy_view]
        }
        entries = []
        for relative in sorted(visible, key=lambda value: value.encode("utf-8")):
            payload, privacy_class = visible[relative]
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
                    privacy_class=privacy_class,
                    required=True,
                )
            )
        package_manifest = DeliveryManifest.model_validate(
            {
                "schema_version": "openworkproof-delivery-manifest/0.1",
                "privacy_view": privacy_view,
                "work_order_digest": work_order.digest,
                "subject_claim_digest": claim.digest,
                "verification_decision_digest": decision.digest,
                "verification_protocol_version": "0.3",
                "scope_manifest_digest": scope_manifest.digest,
                "full_offline_replay": privacy_view == "customer_private",
                "entries": [entry.model_dump(mode="json") for entry in entries],
            }
        )
        _write_file(
            temporary,
            "manifest.json",
            _canonical_bytes(
                package_manifest.model_dump(mode="json", exclude_unset=True)
            ),
        )
        verify_delivery_package(temporary)
        os.rename(temporary, output)
        return package_manifest
    except DeliveryPackageError:
        _cleanup_temporary(temporary)
        raise
    except Exception as error:
        _cleanup_temporary(temporary)
        raise DeliveryPackageError("v0.3 delivery package export failed") from error


def export_delivery_package(
    ledger: Path,
    output: Path,
    *,
    privacy_view: PrivacyView,
) -> DeliveryManifest:
    ledger_path = Path(ledger)
    output_path = Path(output)
    if privacy_view not in {"public", "diagnostic", "customer_private"}:
        raise DeliveryPackageError("privacy view is invalid")
    if not ledger_path.is_file():
        raise DeliveryPackageError("delivery ledger is unavailable")
    if output_path.exists() or output_path.is_symlink():
        raise DeliveryPackageError("delivery package output already exists")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    protocol = _ledger_delivery_protocol(ledger_path)
    if protocol == "0.3":
        return _export_delivery_package_v03(
            ledger_path, output_path, privacy_view=privacy_view
        )
    if protocol == "0.5":
        return _export_delivery_package_v05(
            ledger_path, output_path, privacy_view=privacy_view
        )
    if privacy_view == "diagnostic":
        raise DeliveryPackageError("v0.2 diagnostic view is unavailable")
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
            _canonical_bytes(
                manifest.model_dump(mode="json", exclude_unset=True)
            ),
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


# ---------------------------------------------------------------------------
# v0.5 verification-integrity delivery packages.
# ---------------------------------------------------------------------------

def _load_v05_objects_and_evidence(root: Path, manifest: DeliveryManifest):
    """Load the packaged v0.5 protocol objects and replayable evidence."""
    from openworkproof import integrity, verification  # noqa: PLC0415
    from openworkproof.models import (  # noqa: PLC0415
        DecisionDraftRequest,
        EvaluationScopeManifest,
        SubjectClaim,
        VerificationArmResultV05,
        VerificationDecisionV05,
        VerificationProfileV05,
        WorkOrder,
    )
    from openworkproof.scope import ObservedScope, compare_observed_scope  # noqa: PLC0415
    from openworkproof.signing import (  # noqa: PLC0415
        decode_and_verify_key_binding,
        verify_payload,
        verify_work_order_identity_bindings,
    )

    def load(model_type, relative):
        try:
            return model_type.model_validate(
                _load_canonical_json(root, manifest, relative)
            )
        except Exception as error:
            raise DeliveryPackageError("v0.5 package object is invalid") from error

    work_order = load(WorkOrder, "work-order.json")
    claim = load(SubjectClaim, "subject-claim.json")
    scope_manifest = load(EvaluationScopeManifest, "evaluation-scope.json")
    profile = load(VerificationProfileV05, "verification-profile.json")
    decision = load(VerificationDecisionV05, "verification-decision.json")
    try:
        if not verify_work_order_identity_bindings(work_order):
            raise DeliveryPackageError("v0.5 WorkOrder identity is invalid")
    except DeliveryPackageError:
        raise
    except Exception as error:
        raise DeliveryPackageError("v0.5 WorkOrder identity is invalid") from error
    manager = next(
        (
            binding
            for binding in work_order.key_bindings
            if binding.role == "Manager"
        ),
        None,
    )
    if manager is None:
        raise DeliveryPackageError("v0.5 WorkOrder Manager binding is missing")
    manager_key = decode_and_verify_key_binding(manager)
    if (
        work_order.digest != manifest.work_order_digest
        or claim.digest != manifest.subject_claim_digest
        or decision.digest != manifest.verification_decision_digest
        or scope_manifest.digest != manifest.scope_manifest_digest
        or scope_manifest.work_order_digest != work_order.digest
        or scope_manifest.subject_claim_digest != claim.digest
        or claim.work_order_digest != work_order.digest
        or profile.work_order_digest != work_order.digest
        or profile.subject_claim_digest != claim.digest
        or profile.evaluation_scope_id != scope_manifest.scope_id
        or profile.evaluation_scope_digest != scope_manifest.digest
        or decision.profile_digest != profile.digest
        or decision.scope_manifest_digest != scope_manifest.digest
        or claim.signer_key_id != manager.key_id
        or not verify_payload("subject-claim", claim.model_dump(mode="json"), manager_key)
        or not verify_payload(
            "evaluation-scope", scope_manifest.model_dump(mode="json"), manager_key, version="0.3"
        )
        or profile.signer_key_id != manager.key_id
        or not verify_payload(
            "verification-profile", profile.model_dump(mode="json"), manager_key, version="0.5"
        )
    ):
        raise DeliveryPackageError("v0.5 package object digests do not bind")
    integrity.validate_population_contracts(
        profile,
        scope_manifest,
        rule_outputs=_packaged_rule_outputs(root, manifest, profile, scope_manifest),
    )
    integrity.validate_control_contracts(profile)
    verification.validate_verification_decision_v05(
        profile=profile, manifest=scope_manifest, decision=decision
    )
    for name in (
        "verification-profile.schema.json",
        "verification-arm-result.schema.json",
        "verification-decision.schema.json",
        "schema-registry.json",
    ):
        packaged = _read_bound(root, manifest, f"schemas/{name}")
        runtime = (
            Path(__import__("openworkproof").__file__).parent
            / "schemas"
            / "v0.5"
            / name
        ).read_bytes()
        if packaged != runtime:
            raise DeliveryPackageError("v0.5 packaged schema drifted from runtime")
    receipts = _load_receipts(root, manifest, work_order)
    receipt_ids = {receipt.receipt_id for receipt in receipts}
    results: list[VerificationArmResultV05] = []
    inventory: dict[str, bytes] = {}
    for reference in decision.arm_results:
        try:
            result = VerificationArmResultV05.model_validate(
                _load_canonical_json(
                    root, manifest, f"evidence/arms/{reference.arm_result_id}.json"
                )
            )
        except Exception as error:
            raise DeliveryPackageError("v0.5 arm result is invalid") from error
        if (
            result.arm_result_id != reference.arm_result_id
            or result.digest != reference.arm_result_digest
            or any(item not in receipt_ids for item in result.action_receipt_ids)
        ):
            raise DeliveryPackageError("v0.5 arm result binding failed")
        for ref in result.evidence_refs:
            payload = _read_bound(
                root,
                manifest,
                f"evidence/results/{result.arm_kind}/{ref.path}",
            )
            if (
                len(payload) != ref.size_bytes
                or hashlib.sha256(payload).hexdigest() != ref.sha256
            ):
                raise DeliveryPackageError(
                    "v0.5 arm result evidence integrity failed"
                )
        scope_ref = result.scope_evidence_refs[0]
        raw_scope = _read_bound(
            root,
            manifest,
            f"evidence/scope/{result.arm_kind}/{scope_ref.path}",
        )
        if (
            len(raw_scope) != scope_ref.size_bytes
            or hashlib.sha256(raw_scope).hexdigest() != scope_ref.sha256
        ):
            raise DeliveryPackageError("v0.5 scope evidence integrity failed")
        try:
            observed = ObservedScope.model_validate_json(raw_scope)
        except Exception as error:
            raise DeliveryPackageError("v0.5 observed scope is invalid") from error
        comparison = compare_observed_scope(scope_manifest, observed)
        scope_reasons = tuple(
            code for code in result.reason_codes if code.startswith("SCOPE_")
        )
        if (
            result.observed_member_count != observed.member_count
            or result.observed_population_digest != observed.population_digest
            or result.observed_required_target_ids != observed.required_target_ids
            or result.scope_expectation_status != comparison.scope_status
            or scope_reasons != tuple(sorted(comparison.reason_codes))
        ):
            raise DeliveryPackageError("v0.5 scope evidence replay failed")
        for observation in result.population_observations:
            for ref in observation.evidence_refs:
                payload = _read_bound(
                    root,
                    manifest,
                    f"evidence/populations/{result.arm_kind}/{ref.path}",
                )
                if (
                    len(payload) != ref.size_bytes
                    or hashlib.sha256(payload).hexdigest() != ref.sha256
                ):
                    raise DeliveryPackageError(
                        "v0.5 population evidence integrity failed"
                    )
                inventory[ref.sha256] = payload
        if result.control_observation is not None:
            for ref in result.control_observation.evidence_refs:
                payload = _read_bound(
                    root,
                    manifest,
                    f"evidence/controls/{result.arm_kind}/{ref.path}",
                )
                if (
                    len(payload) != ref.size_bytes
                    or hashlib.sha256(payload).hexdigest() != ref.sha256
                ):
                    raise DeliveryPackageError(
                        "v0.5 control evidence integrity failed"
                    )
        results.append(result)
    population = integrity.assess_population_integrity(
        profile,
        scope_manifest,
        tuple(results),
        rule_outputs=_packaged_rule_outputs(root, manifest, profile, scope_manifest),
        evidence_inventory=inventory,
    )
    control = integrity.assess_control_integrity(profile, tuple(results))
    if (
        population.status != decision.integrity_assessment.population_status
        or control.status != decision.integrity_assessment.control_status
        or set(population.reason_codes) | set(control.reason_codes)
        != set(decision.integrity_assessment.reason_codes)
    ):
        raise DeliveryPackageError("v0.5 integrity assessment replay failed")
    draft = integrity.compose_verification_decision_v05(
        profile=profile,
        manifest=scope_manifest,
        arm_results=tuple(results),
        request=DecisionDraftRequest(
            decision_id=decision.decision_id,
            decided_at=decision.model_dump(mode="json")["decided_at"],
            nonce=decision.nonce,
        ),
        rule_outputs=_packaged_rule_outputs(root, manifest, profile, scope_manifest),
        evidence_inventory=inventory,
    )
    if verification.verification_decision_signing_bytes_v05(
        draft
    ) != verification.verification_decision_signing_bytes_v05(decision):
        raise DeliveryPackageError("v0.5 decision replay failed")
    return work_order, claim, scope_manifest, profile, decision, results, inventory


def _packaged_rule_outputs(root, manifest, profile, scope_manifest):
    """Replay rule outputs from the packaged selector specification files."""
    members_by_locator = {
        member.locator: member.member_id for member in scope_manifest.members
    }
    kind_partition = {
        kind: tuple(
            sorted(
                member.member_id
                for member in scope_manifest.members
                if member.member_kind == kind
            )
        )
        for kind in ("source_file", "test_case")
    }
    outputs: dict[str, tuple[str, ...]] = {}
    for rule in scope_manifest.selector_rules:
        matched = None
        for relative in rule.required_evidence_paths:
            payload = _read_bound(
                root, manifest, f"scope/selectors/{relative}"
            )
            if hashlib.sha256(payload).hexdigest() == rule.selector_spec_digest:
                matched = payload
                break
        if matched is None:
            raise DeliveryPackageError("v0.5 selector specification is unavailable")
        import json as _json

        document = _json.loads(matched.decode("utf-8"))
        kind = document.get("selector_kind")
        if kind in {"git_diff_closure", "pytest_collection"}:
            outputs[rule.rule_id] = kind_partition[
                "source_file" if kind == "git_diff_closure" else "test_case"
            ]
        elif kind == "explicit":
            locators = set(document.get("locators") or [])
            outputs[rule.rule_id] = tuple(
                sorted(
                    member_id
                    for locator, member_id in members_by_locator.items()
                    if locator in locators
                )
            )
        else:
            raise DeliveryPackageError("v0.5 selector kind is unsupported")
    return outputs


def _ledger_export_read_v05(ledger: Path):
    from openworkproof import settlement, verification  # noqa: PLC0415

    lock_descriptor: int | None = None
    connection = None
    try:
        lock_descriptor, _ = evidence._borrow_or_acquire_target_lock(ledger, None)
        connection = evidence.connect_ledger(ledger)
        connection.execute("BEGIN")
        rows = tuple(
            connection.execute(
                "SELECT profile_digest FROM verification_profiles_v05"
            )
        )
        if len(rows) != 1:
            raise DeliveryPackageError("v0.5 package export requires one profile")
        work_order, claim, scope_manifest, profile = (
            verification._load_profile_context_v05(
                connection, profile_digest=rows[0][0], path=ledger
            )
        )
        decision = verification._load_current_decision_v05(
            connection,
            profile=profile,
            manifest=scope_manifest,
            path=ledger,
            work_order=work_order,
        )
        if decision is None:
            raise DeliveryPackageError("v0.5 package export requires a decision")
        if decision.supersedes_decision_id is not None:
            raise DeliveryPackageError("v0.5 decision-chain export is not yet closed")
        arm_results = verification._load_arm_results_v05(
            connection,
            path=ledger,
            work_order=work_order,
            profile=profile,
            manifest=scope_manifest,
            selected_ids=tuple(
                item.arm_result_id for item in decision.arm_results
            ),
        )
        receipts = tuple(
            evidence.parse_action_receipt_json(row[0])
            for row in connection.execute(
                "SELECT receipt_json FROM receipts ORDER BY sequence"
            )
        )
        parent_rows = [
            {"child_receipt_id": child, "parent_receipt_id": parent}
            for child, parent in connection.execute(
                "SELECT child_receipt_id, parent_receipt_id FROM receipt_parents "
                "ORDER BY child_receipt_id, parent_receipt_id"
            )
        ]
        acceptances = evidence._validated_acceptance_receipts(
            connection, work_order
        )
        rejections = evidence._validated_acceptance_rejections(
            connection, work_order
        )
        history = settlement.AcceptanceHistory.model_validate(
            {
                "acceptance": (
                    None
                    if not acceptances
                    else acceptances[0].model_dump(mode="json")
                ),
                "rejection": (
                    None if not rejections else rejections[0].model_dump(mode="json")
                ),
                "withdrawal": None,
                "supersession": None,
                "current_decision": __import__("json").loads(
                    __import__("json").dumps(decision.model_dump(mode="json"))
                ),
            }
        )
        spec_files: dict[str, bytes] = {}
        for rule in scope_manifest.selector_rules:
            for relative in rule.required_evidence_paths:
                target = ledger.parent / relative
                payload = target.read_bytes()
                if hashlib.sha256(payload).hexdigest() == rule.selector_spec_digest:
                    spec_files[relative] = payload
        population_files: dict[str, bytes] = {}
        control_files: dict[str, bytes] = {}
        for result in arm_results:
            for observation in result.population_observations:
                for ref in observation.evidence_refs:
                    target = ledger.parent / ref.path
                    payload = target.read_bytes()
                    if (
                        hashlib.sha256(payload).hexdigest() != ref.sha256
                        or len(payload) != ref.size_bytes
                    ):
                        raise DeliveryPackageError(
                            "v0.5 population evidence is unavailable"
                        )
                    population_files[
                        f"evidence/populations/{result.arm_kind}/{ref.path}"
                    ] = payload
            if result.control_observation is not None:
                for ref in result.control_observation.evidence_refs:
                    target = ledger.parent / ref.path
                    payload = target.read_bytes()
                    if (
                        hashlib.sha256(payload).hexdigest() != ref.sha256
                        or len(payload) != ref.size_bytes
                    ):
                        raise DeliveryPackageError(
                            "v0.5 control evidence is unavailable"
                        )
                    control_files[
                        f"evidence/controls/{result.arm_kind}/{ref.path}"
                    ] = payload
        return (
            work_order,
            claim,
            scope_manifest,
            profile,
            decision,
            arm_results,
            receipts,
            parent_rows,
            history,
            spec_files,
            population_files,
            control_files,
        )
    except DeliveryPackageError:
        evidence._best_effort_rollback(connection)
        raise
    except Exception as error:
        evidence._best_effort_rollback(connection)
        raise DeliveryPackageError("v0.5 package export failed") from error
    finally:
        close_error = evidence._best_effort_close(connection)
        _, release_errors = evidence._release_target_lock(lock_descriptor)
        cleanup = tuple(
            item
            for item in (close_error, *release_errors)
            if item is not None
        )
        if cleanup:
            raise DeliveryPackageError("v0.5 package export cleanup failed") from cleanup[0]


def _export_delivery_package_v05(
    ledger: Path,
    output: Path,
    *,
    privacy_view: PrivacyView,
) -> DeliveryManifest:
    from openworkproof import settlement  # noqa: PLC0415

    temporary = output.parent / f".{output.name}.{uuid.uuid4().hex}.tmp"
    try:
        (
            work_order,
            claim,
            scope_manifest,
            profile,
            decision,
            arm_results,
            receipts,
            parent_rows,
            history,
            spec_files,
            population_files,
            control_files,
        ) = _ledger_export_read_v05(ledger)
        temporary.mkdir(mode=0o700)
        report = {
            "schema_version": "openworkproof-scope-coverage-report/0.5",
            "privacy_view": privacy_view,
            "scope_manifest_digest": scope_manifest.digest,
            "full_offline_replay": privacy_view == "customer_private",
            "decision": decision.decision,
            "population_status": decision.integrity_assessment.population_status,
            "control_status": decision.integrity_assessment.control_status,
            "integrity_reason_codes": list(
                decision.integrity_assessment.reason_codes
            ),
        }
        files: dict[str, tuple[bytes, PrivacyClass]] = {
            "scope-coverage-report.json": (_canonical_bytes(report), "public"),
        }
        if privacy_view == "diagnostic":
            files["scope-diagnostics.json"] = (
                _canonical_bytes(
                    {
                        "arm_statuses": [
                            {
                                "arm_kind": result.arm_kind,
                                "expectation_status": result.expectation_status,
                            }
                            for result in arm_results
                        ],
                        "decision_reason_codes": list(decision.reason_codes),
                        "population_status": decision.integrity_assessment.population_status,
                        "control_status": decision.integrity_assessment.control_status,
                    }
                ),
                "diagnostic",
            )
        if privacy_view == "customer_private":
            files.update(
                {
                    "work-order.json": (
                        _canonical_bytes(work_order.model_dump(mode="json")),
                        "customer_private",
                    ),
                    "subject-claim.json": (
                        _canonical_bytes(claim.model_dump(mode="json")),
                        "customer_private",
                    ),
                    "evaluation-scope.json": (
                        _canonical_bytes(scope_manifest.model_dump(mode="json")),
                        "customer_private",
                    ),
                    "verification-profile.json": (
                        _canonical_bytes(profile.model_dump(mode="json")),
                        "customer_private",
                    ),
                    "verification-decision.json": (
                        _canonical_bytes(decision.model_dump(mode="json")),
                        "customer_private",
                    ),
                    "scope/selector-rules.json": (
                        _canonical_bytes(
                            [
                                item.model_dump(mode="json")
                                for item in scope_manifest.selector_rules
                            ]
                        ),
                        "customer_private",
                    ),
                    "scope/members.json": (
                        _canonical_bytes(
                            [
                                item.model_dump(mode="json")
                                for item in scope_manifest.members
                            ]
                        ),
                        "customer_private",
                    ),
                    "execution-ledger/receipts.json": (
                        _canonical_bytes(
                            [item.model_dump(mode="json") for item in receipts]
                        ),
                        "customer_private",
                    ),
                    "execution-ledger/receipt-parents.json": (
                        _canonical_bytes(parent_rows),
                        "customer_private",
                    ),
                    "verify.sh": (_VERIFY_SCRIPT, "customer_private"),
                }
            )
            schema_files = {}
            schema_dir = Path(__import__("openworkproof").__file__).parent / "schemas" / "v0.5"
            for name in (
                "verification-profile.schema.json",
                "verification-arm-result.schema.json",
                "verification-decision.schema.json",
                "schema-registry.json",
            ):
                schema_files[f"schemas/{name}"] = (schema_dir / name).read_bytes()
            files.update(
                {
                    relative: (payload, "customer_private")
                    for relative, payload in schema_files.items()
                }
            )
            for relative, payload in spec_files.items():
                files[f"scope/selectors/{relative}"] = (payload, "customer_private")
            files.update(
                {
                    relative: (payload, "customer_private")
                    for relative, payload in population_files.items()
                }
            )
            files.update(
                {
                    relative: (payload, "customer_private")
                    for relative, payload in control_files.items()
                }
            )
            for result in arm_results:
                files[f"evidence/arms/{result.arm_result_id}.json"] = (
                    _canonical_bytes(result.model_dump(mode="json")),
                    "customer_private",
                )
                for ref in result.evidence_refs:
                    target = ledger.parent / ref.path
                    payload = target.read_bytes()
                    if (
                        len(payload) != ref.size_bytes
                        or hashlib.sha256(payload).hexdigest() != ref.sha256
                    ):
                        raise DeliveryPackageError(
                            "v0.5 arm result evidence is unavailable"
                        )
                    files[f"evidence/results/{result.arm_kind}/{ref.path}"] = (
                        payload,
                        "customer_private",
                    )
                scope_ref = result.scope_evidence_refs[0]
                files[f"evidence/scope/{result.arm_kind}/{scope_ref.path}"] = (
                    (ledger.parent / scope_ref.path).read_bytes(),
                    "customer_private",
                )
            effective = settlement.effective_acceptance(history)
            readiness = settlement.settlement_readiness(
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
                "customer_private",
            )
        entries = []
        for relative in sorted(files, key=lambda value: value.encode("utf-8")):
            payload, privacy_class = files[relative]
            if len(payload) > _MAX_FILE_BYTES:
                raise DeliveryPackageError("delivery package file is oversized")
            if any(pattern.search(payload) for pattern in _SECRET_PATTERNS):
                raise DeliveryPackageError("delivery package contains a secret pattern")
            target = temporary / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            entries.append(
                DeliveryManifestEntry(
                    path=relative,
                    sha256=hashlib.sha256(payload).hexdigest(),
                    media_type=_media_type(relative),
                    size_bytes=len(payload),
                    privacy_class=privacy_class,
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
                "verification_protocol_version": "0.5",
                "scope_manifest_digest": scope_manifest.digest,
                "full_offline_replay": privacy_view == "customer_private",
                "entries": [
                    entry.model_dump(mode="json") for entry in entries
                ],
            }
        )
        (temporary / "manifest.json").write_bytes(
            _canonical_bytes(manifest.model_dump(mode="json"))
        )
        verify_delivery_package(temporary)
        temporary.replace(output)
        return manifest
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _verify_v05_delivery_package(
    root: Path,
    manifest: DeliveryManifest,
) -> DeliveryVerificationResult:
    report = _load_canonical_json(root, manifest, "scope-coverage-report.json")
    if not isinstance(report, dict) or (
        set(report)
        != {
            "schema_version",
            "privacy_view",
            "scope_manifest_digest",
            "full_offline_replay",
            "decision",
            "population_status",
            "control_status",
            "integrity_reason_codes",
        }
        or report.get("schema_version")
        != "openworkproof-scope-coverage-report/0.5"
        or report.get("privacy_view") != manifest.privacy_view
        or report.get("scope_manifest_digest") != manifest.scope_manifest_digest
        or report.get("full_offline_replay") != manifest.full_offline_replay
        or report.get("decision") not in {"VERIFIED", "REFUTED", "UNKNOWN"}
    ):
        raise DeliveryPackageError("v0.5 scope report binding failed")
    if manifest.privacy_view == "public":
        if set(_entry_map(manifest)) != {"scope-coverage-report.json"}:
            raise DeliveryPackageError("public v0.5 package is not aggregate-only")
        # The public report is plain JSON with no signed redacted
        # attestation; its decision claims are unauthenticated and must
        # never surface as READY_FOR_ACCEPTANCE.
        return DeliveryVerificationResult(
            current_decision="UNAUTHENTICATED",
            effective_acceptance="NONE",
            settlement_readiness="NOT_READY",
            manifest_digest=digest_manifest(manifest),
            full_offline_replay=False,
        )
    if manifest.privacy_view == "diagnostic":
        if set(_entry_map(manifest)) != {
            "scope-coverage-report.json",
            "scope-diagnostics.json",
        }:
            raise DeliveryPackageError("diagnostic v0.5 package is not redacted")
        return DeliveryVerificationResult(
            current_decision="UNAUTHENTICATED",
            effective_acceptance="NONE",
            settlement_readiness="NOT_READY",
            manifest_digest=digest_manifest(manifest),
            full_offline_replay=False,
        )
    _work_order, _claim, _scope, _profile, decision, _results, _inventory = (
        _load_v05_objects_and_evidence(root, manifest)
    )
    replayed = {
        "decision": decision.decision,
        "population_status": decision.integrity_assessment.population_status,
        "control_status": decision.integrity_assessment.control_status,
        "integrity_reason_codes": list(
            decision.integrity_assessment.reason_codes
        ),
    }
    if any(report.get(key) != replayed[key] for key in replayed):
        raise DeliveryPackageError(
            "v0.5 scope report diverges from the replayed decision"
        )
    return DeliveryVerificationResult(
        current_decision=decision.decision,
        effective_acceptance="NONE",
        settlement_readiness=(
            "READY_FOR_ACCEPTANCE"
            if decision.decision == "VERIFIED"
            else "NOT_READY"
        ),
        manifest_digest=digest_manifest(manifest),
        full_offline_replay=True,
    )


def explain_integrity_package(package_root: Path) -> dict[str, object]:
    """Derive the human-readable v0.5 integrity explanation from package bytes."""
    from openworkproof.models import (  # noqa: PLC0415
        VerificationArmResultV05,
        VerificationDecisionV05,
        VerificationProfileV05,
    )

    root = Path(package_root)
    manifest = load_and_verify_manifest(root)
    if manifest.verification_protocol_version != "0.5":
        raise DeliveryPackageError("explain_integrity_package requires a v0.5 package")
    (
        _work_order,
        _claim,
        scope_manifest,
        profile,
        decision,
        results,
        _inventory,
    ) = _load_v05_objects_and_evidence(root, manifest)
    return {
        "decision": decision.decision,
        "population_status": decision.integrity_assessment.population_status,
        "control_status": decision.integrity_assessment.control_status,
        "reason_codes": list(decision.reason_codes),
        "contracts": [
            {
                "member_kind": contract.member_kind,
                "minimum_capture": f"{contract.minimum_capture_numerator}/"
                f"{contract.minimum_capture_denominator}",
                "eligible_seen": next(
                    (
                        observation.eligible_seen
                        for result in results
                        for observation in result.population_observations
                        if observation.contract_id == contract.contract_id
                    ),
                    None,
                ),
                "selected_count": next(
                    (
                        observation.selected_count
                        for result in results
                        for observation in result.population_observations
                        if observation.contract_id == contract.contract_id
                    ),
                    None,
                ),
                "capture": next(
                    (
                        f"{observation.capture_numerator}/"
                        f"{observation.capture_denominator}"
                        for result in results
                        for observation in result.population_observations
                        if observation.contract_id == contract.contract_id
                    ),
                    None,
                ),
            }
            for contract in profile.population_contracts
        ],
        "controls": [
            {
                "control_target": contract.control_target,
                "arm_id": contract.arm_id,
                "control_status": next(
                    (
                        result.control_observation.control_status
                        for result in results
                        if result.arm_id == contract.arm_id
                        and result.control_observation is not None
                    ),
                    None,
                ),
            }
            for contract in profile.control_contracts
        ],
        "boundary": (
            "verification evidence does not prove payment or customer acceptance"
        ),
    }


def compare_integrity_packages(
    left_root: Path, right_root: Path
) -> dict[str, object]:
    """Compare two v0.5 packages on rule, engine, population, and control axes."""
    from openworkproof.models import VerificationProfileV05  # noqa: PLC0415

    def profile_of(root: Path):
        manifest = load_and_verify_manifest(root)
        _load_v05_objects_and_evidence(root, manifest)
        return VerificationProfileV05.model_validate(
            _load_canonical_json(root, manifest, "verification-profile.json")
        )

    left = profile_of(Path(left_root))
    right = profile_of(Path(right_root))
    left_rules = {item.selector_rule_id: item for item in left.population_contracts}
    right_rules = {item.selector_rule_id: item for item in right.population_contracts}
    rule_changes = [
        rule_id
        for rule_id in set(left_rules) | set(right_rules)
        if left_rules.get(rule_id) is None
        or right_rules.get(rule_id) is None
        or left_rules[rule_id].selector_spec_digest
        != right_rules[rule_id].selector_spec_digest
        or left_rules[rule_id].selector_engine_digest
        != right_rules[rule_id].selector_engine_digest
    ]
    left_controls = {item.arm_id: item for item in left.control_contracts}
    right_controls = {item.arm_id: item for item in right.control_contracts}
    control_changes = [
        arm_id
        for arm_id in set(left_controls) | set(right_controls)
        if left_controls.get(arm_id) is None
        or right_controls.get(arm_id) is None
        or left_controls[arm_id].fixture_digest
        != right_controls[arm_id].fixture_digest
        or left_controls[arm_id].provocation_digest
        != right_controls[arm_id].provocation_digest
        or left_controls[arm_id].expected_failure_signature_digest
        != right_controls[arm_id].expected_failure_signature_digest
    ]
    def assessments(root: Path):
        manifest = load_and_verify_manifest(root)
        loaded = _load_v05_objects_and_evidence(root, manifest)
        return loaded[4], loaded[5], loaded[6]

    left_decision, left_results, _ = assessments(Path(left_root))
    right_decision, right_results, _ = assessments(Path(right_root))
    left_observations = {
        (result.arm_id, observation.contract_id): observation
        for result in left_results
        for observation in result.population_observations
    }
    right_observations = {
        (result.arm_id, observation.contract_id): observation
        for result in right_results
        for observation in result.population_observations
    }
    population_changes = sorted(
        key
        for key in set(left_observations) | set(right_observations)
        if key not in left_observations
        or key not in right_observations
        or left_observations[key].eligible_population_digest
        != right_observations[key].eligible_population_digest
        or left_observations[key].selected_population_digest
        != right_observations[key].selected_population_digest
        or left_observations[key].capture_numerator
        != right_observations[key].capture_numerator
        or left_observations[key].capture_denominator
        != right_observations[key].capture_denominator
    )
    return {
        "selector_rule_changes": sorted(rule_changes),
        "selector_engine_changes": sorted(
            rule_id
            for rule_id in set(left_rules) | set(right_rules)
            if left_rules.get(rule_id) is not None
            and right_rules.get(rule_id) is not None
            and left_rules[rule_id].selector_spec_digest
            == right_rules[rule_id].selector_spec_digest
            and left_rules[rule_id].selector_engine_digest
            != right_rules[rule_id].selector_engine_digest
        ),
        "control_changes": sorted(control_changes),
        "population_changes": population_changes,
        "population_status_left": left_decision.integrity_assessment.population_status,
        "population_status_right": right_decision.integrity_assessment.population_status,
    }
