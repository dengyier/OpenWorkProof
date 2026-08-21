"""Deterministic JSON/Markdown rendering for Verified Delivery Case results.

This module is a pure projection of ``DeliveryCaseResultV01``. It never reads
the filesystem, never touches the network and never consults the wall clock:
the same result always renders to the same bytes.
"""

from __future__ import annotations

import rfc8785

from openworkproof.delivery_case import DeliveryCaseResultV01


__all__ = [
    "render_delivery_result",
    "render_delivery_summary",
]


_BOUNDARY = "not payment, completed settlement, legal audit, or customer adoption"


def render_delivery_result(result: DeliveryCaseResultV01) -> bytes:
    """Return the canonical JSON bytes for one derived delivery result."""

    return rfc8785.dumps(result.model_dump(mode="json"))


def _display(value: object | None) -> str:
    return "—" if value is None else str(value)


def render_delivery_summary(result: DeliveryCaseResultV01) -> str:
    """Render one fixed-order UTF-8 Markdown summary for a human Buyer."""

    case_id_prefix = result.case_id[:12]
    reasons = ", ".join(result.reason_codes) or "—"
    lines = [
        "# OpenWorkProof Verified Agent Delivery",
        "",
        "| Question | Answer |",
        "|---|---|",
        "| Who authorized | The WorkOrder authority chain in the surface bundle |",
        "| What was executed | The action receipts and evidence index in the delivery package |",
        "| Who verified | The independent Verifier environment fingerprint and key binding |",
        (
            "| Can the buyer accept | "
            f"{_display(result.acceptance_decision)} |"
        ),
        (
            "| Settlement review | "
            f"{_display(result.settlement_readiness)} |"
        ),
        "",
        f"- Case id: `{case_id_prefix}`",
        f"- Case stage: `{_display(result.case_stage)}`",
        f"- Verification decision: `{_display(result.verification_decision)}`",
        f"- Human acceptance: `{_display(result.acceptance_decision)}`",
        f"- Settlement review status: `{_display(result.settlement_readiness)}`",
        f"- SOW evidence: `{result.sow_evidence}`",
        f"- Payment evidence: `{result.payment_evidence}`",
        f"- Reason codes: `{reasons}`",
        "",
        f"Boundary: {_BOUNDARY}.",
        "",
        "This summary is derived from the offline-verifiable Surface Bundle, "
        "Acceptance Bundle and settlement status. It is not an authorization, "
        "acceptance, payment receipt, legal audit or evidence of customer "
        "adoption.",
        "",
    ]
    return "\n".join(lines)
