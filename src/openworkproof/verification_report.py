"""Deterministic verification report derivation (0.1).

The VerificationReportV01 is a derived offline-replay view, not a new
authorization or acceptance truth.  It combines verified v0.5 delivery surface
facts with signed execution-environment fingerprints and renders a fail-closed
three-state result (VERIFIED / REFUTED / UNKNOWN) plus a static, script-free
HTML view.  Every fact is sourced from ``load_surface_facts``, every fingerprint
signature is checked against ``facts.trusted_verifier_keys``, and no wall clock
or caller metadata participates in the outcome.
"""

from __future__ import annotations

import hashlib
import html
import re
from collections.abc import Sequence
from datetime import datetime
from typing import Annotated, Any, Literal

import rfc8785
from pydantic import BeforeValidator, ConfigDict, model_validator

from openworkproof.delivery_package import DeliverySurfaceFacts
from openworkproof.environment_fingerprint import (
    SignedEnvironmentFingerprintV01,
    verify_environment_fingerprint,
)
from openworkproof.models import CanonicalUTCTime, Digest64, ProtocolModel


__all__ = [
    "ReportReasonCode",
    "VerificationReportV01",
    "compose_verification_report",
    "render_report_html",
]

_SCHEMA_VERSION = "openworkproof-verification-report/0.1"
_RENDERER_VERSION = "openworkproof-report-renderer/0.1"

ReportReasonCode = Literal[
    "DELIVERY_REFUTED",
    "DELIVERY_UNKNOWN",
    "DELIVERY_UNAUTHENTICATED",
    "ENVIRONMENT_INCOMPLETE",
    "ENVIRONMENT_COUNT_INSUFFICIENT",
    "ENVIRONMENT_SOURCE_MISMATCH",
    "ENVIRONMENT_SIGNATURE_INVALID",
    "ENVIRONMENT_SUBJECT_MISMATCH",
]

_ReportDecisionStatus = Literal["VERIFIED", "REFUTED", "UNKNOWN"]

_LOWER_HEX_40 = re.compile(r"^[0-9a-f]{40}$")

_REPORT_CONFIG = ConfigDict(
    extra="forbid",
    frozen=True,
    strict=True,
    validate_assignment=True,
    revalidate_instances="subclass-instances",
)


def _source_revision(value: Any) -> str:
    if type(value) is not str or _LOWER_HEX_40.fullmatch(value) is None:
        raise ValueError(
            "source revision must be 40 lowercase hexadecimal characters"
        )
    return value


def _sorted_reason_codes(codes: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted(set(codes), key=lambda item: item.encode("utf-8")))


class VerificationReportV01(ProtocolModel):
    model_config = _REPORT_CONFIG

    schema_version: Literal["openworkproof-verification-report/0.1"]
    bundle_digest: Digest64
    replay_result_digest: Digest64
    decision_status: _ReportDecisionStatus
    reason_codes: tuple[ReportReasonCode, ...]
    work_order_digest: Digest64
    source_revision: Annotated[str, BeforeValidator(_source_revision)]
    environment_fingerprint_digests: tuple[Digest64, ...]
    verification_decision_digests: tuple[Digest64, ...]
    acceptance_receipt_digest: Digest64 | None
    evidence_closed_at: CanonicalUTCTime
    renderer_version: Literal["openworkproof-report-renderer/0.1"]

    @model_validator(mode="after")
    def _validate_replay_digest(self) -> VerificationReportV01:
        if self.reason_codes != _sorted_reason_codes(self.reason_codes):
            raise ValueError("report reason codes must be sorted and unique")
        if self.environment_fingerprint_digests != tuple(
            sorted(set(self.environment_fingerprint_digests))
        ):
            raise ValueError(
                "environment fingerprint digests must be sorted and unique"
            )
        if (
            not self.verification_decision_digests
            or self.verification_decision_digests
            != tuple(sorted(set(self.verification_decision_digests)))
        ):
            raise ValueError(
                "verification decision digests must be non-empty, sorted, and unique"
            )
        if self.decision_status == "VERIFIED" and self.reason_codes:
            raise ValueError("VERIFIED report must carry no reason codes")
        if self.decision_status == "REFUTED" and (
            "DELIVERY_REFUTED" not in self.reason_codes
            or "DELIVERY_UNKNOWN" in self.reason_codes
        ):
            raise ValueError("REFUTED report requires DELIVERY_REFUTED")
        if self.decision_status == "UNKNOWN" and (
            not self.reason_codes or "DELIVERY_REFUTED" in self.reason_codes
        ):
            raise ValueError("UNKNOWN report requires non-refutation reasons")
        payload = self.model_dump(mode="json", exclude={"replay_result_digest"})
        expected = hashlib.sha256(rfc8785.dumps(payload)).hexdigest()
        if self.replay_result_digest != expected:
            raise ValueError(
                "replay_result_digest does not match canonical report payload"
            )
        return self


def _coerce_fingerprints(
    fingerprints: Sequence[Any],
) -> tuple[SignedEnvironmentFingerprintV01, ...]:
    if type(fingerprints) not in {tuple, list}:
        raise ValueError("fingerprints must be an exact tuple or list")
    if len(fingerprints) > 2:
        raise ValueError("fingerprints may contain at most two entries")
    items = tuple(fingerprints)
    for item in items:
        if not isinstance(item, SignedEnvironmentFingerprintV01):
            raise ValueError(
                "each fingerprint must be a SignedEnvironmentFingerprintV01"
            )
    return items


def _evaluate_fingerprints(
    facts: DeliverySurfaceFacts,
    fingerprints: tuple[SignedEnvironmentFingerprintV01, ...],
) -> tuple[set[str], set[str]]:
    usable: set[str] = set()
    reason_codes: set[str] = set()

    for fingerprint in fingerprints:
        try:
            rebuilt = SignedEnvironmentFingerprintV01.model_validate(
                fingerprint.model_dump(mode="json", warnings="error")
            )
        except Exception:
            reason_codes.add("ENVIRONMENT_SIGNATURE_INVALID")
            continue
        source_ok = rebuilt.payload.source_revision == facts.source_revision
        if not source_ok:
            reason_codes.add("ENVIRONMENT_SOURCE_MISMATCH")
        signature_ok = verify_environment_fingerprint(
            rebuilt, facts.trusted_verifier_keys
        )
        if not signature_ok:
            reason_codes.add("ENVIRONMENT_SIGNATURE_INVALID")
        try:
            subject_ok = signature_ok and (
                facts.trusted_verifier_subjects.get(rebuilt.collector_key_id)
                == rebuilt.payload.collector_actor_id
            )
        except Exception:
            subject_ok = False
        if signature_ok and not subject_ok:
            reason_codes.add("ENVIRONMENT_SUBJECT_MISMATCH")
        complete = rebuilt.payload.collection_status == "complete"
        if not complete:
            reason_codes.add("ENVIRONMENT_INCOMPLETE")
        if source_ok and signature_ok and subject_ok and complete:
            usable.add(rebuilt.collector_key_id)

    return usable, reason_codes


def compose_verification_report(
    facts: DeliverySurfaceFacts,
    fingerprints: Sequence[SignedEnvironmentFingerprintV01],
    *,
    bundle_digest: str,
) -> VerificationReportV01:
    """Derive a deterministic VerificationReportV01 from verified facts.

    ``facts`` must come from ``load_surface_facts``; every environment
    fingerprint signature is re-verified against ``facts.trusted_verifier_keys``
    and every fingerprint's source revision must match ``facts.source_revision``.
    """
    if not isinstance(facts, DeliverySurfaceFacts):
        raise ValueError("facts must come from load_surface_facts")
    if not isinstance(bundle_digest, str):
        raise ValueError("bundle_digest must be a string")
    if facts.decision not in {"VERIFIED", "REFUTED", "UNKNOWN"}:
        raise ValueError("facts decision must be VERIFIED, REFUTED, or UNKNOWN")
    if facts.risk_class not in {"standard", "high_risk"}:
        raise ValueError("facts risk_class must be standard or high_risk")

    items = _coerce_fingerprints(fingerprints)
    fingerprint_digests = tuple(sorted({item.digest for item in items}))
    usable, environment_reasons = _evaluate_fingerprints(facts, items)

    if facts.decision == "REFUTED":
        decision_status = "REFUTED"
        reason_codes: tuple[str, ...] = _sorted_reason_codes(
            {"DELIVERY_REFUTED", *environment_reasons}
        )
    elif facts.decision == "UNKNOWN":
        decision_status = "UNKNOWN"
        reason_codes = _sorted_reason_codes(
            {"DELIVERY_UNKNOWN", *environment_reasons}
        )
    else:
        required = 2 if facts.risk_class == "high_risk" else 1
        if len(usable) >= required and not environment_reasons:
            decision_status = "VERIFIED"
            reason_codes = ()
        else:
            decision_status = "UNKNOWN"
            codes = set(environment_reasons)
            if len(usable) < required:
                codes.add("ENVIRONMENT_COUNT_INSUFFICIENT")
            reason_codes = _sorted_reason_codes(codes)

    fields: dict[str, Any] = {
        "schema_version": _SCHEMA_VERSION,
        "bundle_digest": bundle_digest,
        "decision_status": decision_status,
        "reason_codes": reason_codes,
        "work_order_digest": facts.work_order_digest,
        "source_revision": facts.source_revision,
        "environment_fingerprint_digests": fingerprint_digests,
        "verification_decision_digests": facts.decision_digests,
        "acceptance_receipt_digest": facts.acceptance_receipt_digest,
        "evidence_closed_at": facts.evidence_closed_at,
        "renderer_version": _RENDERER_VERSION,
    }
    replay_result_digest = hashlib.sha256(rfc8785.dumps(fields)).hexdigest()
    fields["replay_result_digest"] = replay_result_digest
    return VerificationReportV01.model_validate(fields)


def render_report_html(report: VerificationReportV01) -> bytes:
    """Render a static, script-free HTML view of the report.

    The HTML contains no scripts and no external resources; every rendered
    value is passed through ``html.escape``.  It only renders report model
    fields and never accepts free adapter metadata.
    """

    def esc(value: object) -> str:
        return html.escape(str(value), quote=True)

    closed_at = report.evidence_closed_at
    closed_at_text = (
        closed_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        if isinstance(closed_at, datetime)
        else str(closed_at)
    )

    reason_items = "".join(
        f"<li>{esc(code)}</li>" for code in report.reason_codes
    )
    fingerprint_items = "".join(
        f"<li>{esc(digest)}</li>"
        for digest in report.environment_fingerprint_digests
    )
    decision_items = "".join(
        f"<li>{esc(digest)}</li>"
        for digest in report.verification_decision_digests
    )
    acceptance = (
        "无"
        if report.acceptance_receipt_digest is None
        else esc(report.acceptance_receipt_digest)
    )

    return (
        "<!doctype html><meta charset='utf-8'>"
        "<title>OpenWorkProof Verification Report</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:48rem;"
        "margin:2rem auto;padding:0 1rem;color:#111}"
        "code{word-break:break-all}li{margin:0.25rem 0}</style>"
        f"<h1>{esc(report.decision_status)}</h1>"
        f"<ul>{reason_items}</ul>"
        "<dl>"
        f"<dt>Work Order</dt><dd><code>{esc(report.work_order_digest)}</code></dd>"
        f"<dt>Source Revision</dt><dd><code>{esc(report.source_revision)}</code></dd>"
        f"<dt>Bundle Digest</dt><dd><code>{esc(report.bundle_digest)}</code></dd>"
        "<dt>Replay Result Digest</dt>"
        f"<dd><code>{esc(report.replay_result_digest)}</code></dd>"
        f"<dt>Environment Fingerprints</dt><dd><ul>{fingerprint_items}</ul></dd>"
        f"<dt>Verification Decisions</dt><dd><ul>{decision_items}</ul></dd>"
        f"<dt>Acceptance Receipt</dt><dd>{acceptance}</dd>"
        f"<dt>Evidence Closed At</dt><dd>{esc(closed_at_text)}</dd>"
        f"<dt>Renderer</dt><dd>{esc(report.renderer_version)}</dd>"
        "</dl>"
        "<p>该报告不证明付款、合同履行或客户验收已经发生。</p>"
    ).encode("utf-8")
