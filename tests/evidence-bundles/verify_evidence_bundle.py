#!/usr/bin/env python3
"""Standalone offline verifier for OpenWorkProof evidence bundles.

This script verifies an evidence bundle JSON file without any live ledger,
network access, or trusting the runtime. It only needs the ``openworkproof``
package installed (``pip install openworkproof``) and the bundle JSON file.

Usage::

    python verify_evidence_bundle.py <bundle.json>

Exit codes:
    0 — verification passed
    1 — verification failed
    2 — usage error
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path


def verify_bundle(bundle_path: str) -> bool:
    """Verify an evidence bundle and print the results."""
    import rfc8785

    from openworkproof.models import (
        ACTION_RECEIPT_ADAPTER,
        AcceptanceReceipt,
        CapabilityGrant,
        CompositionReport,
        WorkOrder,
        EvidenceRef,
    )
    from openworkproof.policy import CommittedEvidence
    from openworkproof.signing import decode_and_verify_key_binding, verify_payload
    import openworkproof.acceptance as acceptance

    # --- Load bundle ---
    bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    meta = bundle["metadata"]
    print(f"\n{'=' * 60}")
    print(f"Evidence Bundle: {meta['bug_id']}")
    print(f"Bug URL: {meta['bug_url']}")
    print(f"Pinned commit: {meta['pinned_commit']}")
    if meta.get("fix_commit"):
        print(f"Fix commit: {meta['fix_commit']}")
    print(f"Protocol: {meta['protocol_version']}")
    print(f"Signature: {meta['signature_algorithm']}")
    print(f"Canonicalization: {meta['canonicalization']}")
    print(f"{'=' * 60}\n")

    # --- Reconstruct typed objects ---
    work_order = WorkOrder.model_validate(bundle["work_order"])

    # Public keys from WorkOrder key bindings
    public_keys = {}
    for binding in work_order.key_bindings:
        public_keys[binding.key_id] = decode_and_verify_key_binding(binding)

    # Grants
    grants = tuple(
        CapabilityGrant.model_validate(g)
        for g in sorted(
            bundle["effective_grants"], key=lambda g: g["grant_id"]
        )
    )

    # Grant attempts (they are CapabilityGrant objects)
    grant_attempts = tuple(
        CapabilityGrant.model_validate(a)
        for a in sorted(
            bundle["grant_attempts"], key=lambda a: a["digest"]
        )
    )

    # Receipts — use the adapter because ActionReceipt is a Union type
    receipts = tuple(
        ACTION_RECEIPT_ADAPTER.validate_python(r)
        for r in bundle["receipts"]
    )

    # Composition reports
    reports = tuple(
        CompositionReport.model_validate(r)
        for r in bundle["composition_reports"]
    )

    # Acceptance receipt
    acceptance_receipt = AcceptanceReceipt.model_validate(
        bundle["acceptance_receipt"]
    )

    # Committed evidence
    committed_evidence = tuple(
        CommittedEvidence(
            reference=EvidenceRef.model_validate(ce["reference"]),
            payload=base64.b64decode(ce["payload_b64"]),
        )
        for ce in bundle["committed_evidence"]
    )

    # --- Verify evidence payload hashes ---
    print("Step 1: Verify committed evidence hashes...")
    for i, ce in enumerate(bundle["committed_evidence"]):
        payload = base64.b64decode(ce["payload_b64"])
        actual = hashlib.sha256(payload).hexdigest()
        expected = ce["reference"]["sha256"]
        assert actual == expected, (
            f"Evidence file {i} ({ce['reference']['path']}): "
            f"hash mismatch! expected={expected}, actual={actual}"
        )
        print(f"  ✓ {ce['reference']['path']} — SHA-256 verified")

    # --- Verify WorkOrder signature ---
    print("\nStep 2: Verify WorkOrder signature...")
    verify_payload(
        "work-order",
        work_order.model_dump(mode="json"),
        public_keys[work_order.signer_key_id],
    )
    print(f"  ✓ WorkOrder signed by {work_order.signer_key_id}")
    print(f"  ✓ WorkOrder digest: {work_order.digest}")

    # --- Verify all grant signatures ---
    print(f"\nStep 3: Verify {len(grants)} CapabilityGrant signatures...")
    for grant in grants:
        verify_payload(
            "capability-grant",
            grant.model_dump(mode="json"),
            public_keys[grant.issuer_key_id],
        )
        print(f"  ✓ Grant {grant.grant_id[:16]}... signed by {grant.issuer_key_id}")

    # --- Verify all receipt signatures ---
    print(f"\nStep 4: Verify {len(receipts)} ActionReceipt signatures...")
    for receipt in receipts:
        verify_payload(
            "action-receipt",
            receipt.model_dump(mode="json"),
            public_keys[receipt.signer_key_id],
        )
        # Different receipt types have different descriptive fields
        desc = getattr(receipt, "tool_name", None) or \
              getattr(receipt, "event_type", None) or \
              type(receipt).__name__
        print(
            f"  ✓ Receipt #{receipt.sequence} ({desc}) "
            f"signed by {receipt.signer_key_id}"
        )

    # --- Verify composition report chain ---
    print(f"\nStep 5: Verify {len(reports)} composition reports...")
    for i, report in enumerate(reports):
        conclusion = report.verifier_conclusion
        print(f"  ✓ Report {i + 1}: verifier_conclusion = {conclusion}")

    # --- Full offline verification ---
    print("\nStep 6: Full offline verification (verify_acceptance_bundle)...")
    final_report = reports[-1]

    verified = acceptance.verify_acceptance_bundle(
        work_order=work_order,
        report=final_report,
        effective_grants=grants,
        grant_attempts=grant_attempts,
        receipts=receipts,
        committed_evidence=committed_evidence,
        acceptance_receipt=acceptance_receipt,
        public_keys=public_keys,
        reports=reports,
    )

    print(f"\n{'=' * 60}")
    print(f"✅ VERIFICATION PASSED")
    print(f"   Acceptance ID: {verified.acceptance_id}")
    print(f"   Final conclusion: {final_report.verifier_conclusion}")
    print(f"   Receipts verified: {len(receipts)}")
    print(f"   Grants verified: {len(grants)}")
    print(f"   Evidence files verified: {len(committed_evidence)}")
    print(f"   Composition reports: {len(reports)}")
    print(f"{'=' * 60}\n")
    return True


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <bundle.json>")
        return 2

    bundle_path = sys.argv[1]
    if not Path(bundle_path).exists():
        print(f"Error: file not found: {bundle_path}")
        return 2

    try:
        verify_bundle(bundle_path)
        return 0
    except Exception as e:
        print(f"\n❌ VERIFICATION FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
