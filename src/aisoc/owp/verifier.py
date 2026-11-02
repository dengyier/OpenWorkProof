"""Shared verification of signed SOC evidence and caller-pinned trust anchors.

A bundle's keys and checkpoints can establish internal consistency only. An
independent caller must supply both trusted keys and witnessed checkpoints to
establish the expected identities and the committed history. The verifier does
not establish how those pins were obtained or whether administrators differ.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable, List, Optional

from ..canonical import digest
from ..crypto import Clock, Ed25519Signer, TrustedKeys, parse_iso
from .ledger import GENESIS, HashChainLedger, merkle_root
from .objects import Signed, VerificationDecision, new_id

_VERIFICATION_SCOPE = (
    "Checks signatures, receipt reconciliation, authorization ordering, same-case prior "
    "work-order/policy ledger digest commitments and caller-pinned checkpoint coverage. "
    "Does not reconstruct original work-order/policy payloads, re-derive their evidence "
    "semantics, establish clock truth, or replay frozen OpenWorkProof Core semantics."
)


def _registry(keys: Dict[str, Any]) -> TrustedKeys:
    trusted = TrustedKeys()
    for kid, info in keys.items():
        trusted.trust_raw(kid, info["role"], bytes.fromhex(info["public_raw_hex"]))
    return trusted


def _signed_valid(obj: Dict[str, Any], trusted: TrustedKeys, role: str, identity: str) -> bool:
    return any(s.get("key_id") == identity and trusted.verify(obj["payload"], s, expected_role=role)
               for s in obj["signatures"])


def verify_bundle(
    bundle: Dict[str, Any],
    trusted_keys: Optional[Dict[str, Any]] = None,
    trusted_checkpoints: Optional[List[Dict[str, Any]]] = None,
    *,
    case_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify data keyed by export filenames, without filesystem or network I/O.

    ``trusted_keys`` and ``trusted_checkpoints`` must come from caller-controlled
    configuration outside the bundle. Copying bundled material into these
    arguments does not create an independent trust source. VERIFIED is relative
    to the supplied pins, not a certification of their provenance or deployment.
    """
    try:
        return _verify_bundle(bundle, trusted_keys, trusted_checkpoints, case_id)
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError) as exc:
        return {"status": "FAILED", "entries": 0, "checkpoints": 0, "receipts": 0,
                "checked_entries": 0, "witnessed_entries": 0,
                "problems": [f"malformed proof bundle: {type(exc).__name__}"],
                "verification_scope": _VERIFICATION_SCOPE,
                "trust_scope": "caller-supplied pins; provenance and administrative independence are not established"}


def _verify_bundle(bundle, trusted_keys, trusted_checkpoints, case_id):
    entries = bundle["ledger.json"]
    cps = bundle["witness-checkpoints.json"]
    receipts = bundle["tool-side-receipts.json"]
    authorizations = bundle.get("authorizations.json", [])
    if not all(isinstance(v, list) for v in (entries, cps, receipts, authorizations)):
        raise ValueError("proof collections must be lists")
    trusted = _registry(bundle.get("trusted-keys.json", {}) if trusted_keys is None else trusted_keys)
    failures: List[str] = []
    unknown: List[str] = []
    if trusted_keys is None:
        unknown.append("identity: no caller-pinned keys outside the bundle; bundled keys establish consistency only")
    if not trusted_checkpoints:
        unknown.append("witness: no caller-pinned external checkpoint; history is UNKNOWN")

    prev = GENESIS
    for i, entry in enumerate(entries):
        body = {k: v for k, v in entry.items() if k != "entry_hash"}
        if entry["index"] != i or entry["prev_hash"] != prev or digest(body) != entry["entry_hash"]:
            failures.append(f"chain broken at {i}")
        prev = entry["entry_hash"]
    hashes = [e["entry_hash"] for e in entries]
    witnessed = 0
    for external, checkpoints in ((False, cps), (True, trusted_checkpoints or [])):
        for cp in checkpoints:
            payload = cp["payload"]
            if not any(trusted.verify(payload, s, expected_role="ledger") for s in cp["signatures"]):
                failures.append("checkpoint signature invalid")
                continue
            length = payload["length"]
            if type(length) is not int or length < 0:
                failures.append("checkpoint length invalid")
            elif length > len(entries):
                failures.append(f"ledger truncated below witnessed length {length}")
            elif merkle_root(hashes[:length]) != payload["merkle_root"]:
                failures.append(f"merkle mismatch at witnessed length {length}")
            elif payload["head_hash"] != (hashes[length - 1] if length else GENESIS):
                failures.append(f"head hash mismatch at witnessed length {length}")
            elif external:
                witnessed = max(witnessed, length)

    scoped = [e for e in entries if case_id is None or e["case_id"] == case_id]
    required_length = len(entries) if case_id is None else max((e["index"] + 1 for e in scoped), default=0)
    if witnessed < required_length:
        unknown.append(f"witness: checkpoint covers {witnessed} entries; required prefix is {required_length}; uncovered suffix is UNKNOWN")
    scoped_receipts = [r for r in receipts if case_id is None or r["payload"]["case_id"] == case_id]
    scoped_auths = [a for a in authorizations if case_id is None or a["payload"]["case_id"] == case_id]
    egress = {}
    requests = {}
    commitments = {"work_order": {}, "policy_decision": {}}
    auth_entries = {}
    receipt_entries = {}
    for entry in scoped:
        key = (entry["case_id"], entry["object_digest"])
        typ = entry["entry_type"]
        if typ in commitments:
            commitments[typ].setdefault(key, entry["index"])
        elif typ == "agent_egress":
            egress.setdefault((entry["case_id"], entry["refs"].get("msg_digest")), entry["index"])
        elif typ == "action_request":
            seen = egress.get(key)
            if seen is None or seen >= entry["index"]:
                failures.append(f"entry {entry['index']}: action_request did not pass through the audited egress channel")
            requests.setdefault(key, entry["index"])
        elif typ == "authorization":
            auth_entries.setdefault(key, []).append(entry)
        elif typ == "action_receipt":
            receipt_entries.setdefault(key, []).append(entry)

    auth_counts = Counter((a["payload"]["case_id"], digest(a["payload"])) for a in scoped_auths)
    valid_auths = {}
    for obj in scoped_auths:
        payload = obj["payload"]
        key = (payload["case_id"], digest(payload))
        if auth_counts[key] != 1 or len(auth_entries.get(key, [])) != 1:
            failures.append(f"authorization {key[1]}: signed object and ledger must match exactly once")
            continue
        if not _signed_valid(obj, trusted, "authorizer", payload.get("signer_identity", "")):
            failures.append(f"authorization {key[1]}: authorizer signature invalid")
            continue
        entry = auth_entries[key][0]
        if entry["refs"].get("request_digest") != payload.get("request_digest"):
            failures.append(f"authorization {key[1]}: request reference differs from signed payload")
            continue
        request_index = requests.get((payload["case_id"], payload.get("request_digest")))
        if request_index is None or request_index >= entry["index"]:
            failures.append(f"authorization {key[1]}: no matching prior action_request")
            continue
        bound = True
        for typ, field in (("work_order", "task_digest"), ("policy_decision", "policy_decision_digest")):
            prior = commitments[typ].get((payload["case_id"], payload.get(field)))
            if prior is None or prior >= entry["index"]:
                failures.append(f"authorization {key[1]}: no matching same-case prior {typ}")
                bound = False
        if bound:
            valid_auths[key] = (payload, entry)
    for key, matches in auth_entries.items():
        if auth_counts[key] != 1 or len(matches) != 1:
            failures.append(f"ledger authorization {key[1]}: missing or duplicate signed authorization")

    receipt_counts = Counter((r["payload"]["case_id"], digest(r["payload"])) for r in scoped_receipts)
    receipt_ids = Counter((r["payload"]["case_id"], r["payload"].get("receipt_id")) for r in scoped_receipts)
    for obj in scoped_receipts:
        payload = obj["payload"]
        key = (payload["case_id"], digest(payload))
        label = f"receipt {payload.get('receipt_id')}"
        if not _signed_valid(obj, trusted, "executor", payload.get("executor_identity", "")):
            failures.append(f"{label}: executor signature invalid")
        matches = receipt_entries.get(key, [])
        if receipt_counts[key] != 1 or receipt_ids[(payload["case_id"], payload.get("receipt_id"))] != 1 or len(matches) != 1:
            failures.append(f"{label}: tool side and ledger must match exactly once (bypass or duplicate)")
            continue
        if payload.get("outcome") != "executed":
            continue
        auth = valid_auths.get((payload["case_id"], payload.get("envelope_digest")))
        if auth is None:
            failures.append(f"{label}: executed without matching signed authorization (bypass)")
            continue
        env, auth_entry = auth
        if auth_entry["index"] >= matches[0]["index"]:
            failures.append(f"{label}: authorization recorded after execution")
        if any(env.get(k) != payload.get(k) for k in ("case_id", "request_digest", "action", "resource")):
            failures.append(f"{label}: execution differs from signed authorization")
        executed_at = parse_iso(payload["executed_at"])
        if parse_iso(auth_entry["recorded_at"]) > executed_at:
            failures.append(f"{label}: authorization recorded after signed execution time")
        if not parse_iso(env["issued_at"]) <= executed_at < parse_iso(env["expires_at"]):
            failures.append(f"{label}: execution outside signed authorization validity")
    for key, matches in receipt_entries.items():
        if receipt_counts[key] != 1 or len(matches) != 1:
            failures.append(f"ledger entry {matches[0]['index']}: execution recorded but no unique matching tool-side receipt")

    return {"status": "FAILED" if failures else ("UNKNOWN" if unknown else "VERIFIED"),
            "entries": len(entries), "checkpoints": len(cps), "receipts": len(scoped_receipts),
            "checked_entries": len(scoped), "witnessed_entries": witnessed,
            "problems": failures + unknown,
            "verification_scope": _VERIFICATION_SCOPE,
            "trust_scope": "caller-supplied pins; provenance and administrative independence are not established"}


class Verifier:
    def __init__(self, signer: Ed25519Signer, trusted: TrustedKeys, clock: Clock,
                 authorizations: Optional[List[Signed]] = None) -> None:
        self.signer = signer
        self.trusted = trusted
        self.clock = clock
        self.authorizations = authorizations if authorizations is not None else []

    def verify_case(self, case_id: str, ledger: HashChainLedger, tool_receipts: Iterable[Signed],
                    authorizations: Optional[Iterable[Signed]] = None) -> Signed:
        checkpoints = ledger.witness.checkpoints() if ledger.witness is not None else []
        result = verify_bundle({"ledger.json": [e.to_dict() for e in ledger.entries],
                                "witness-checkpoints.json": checkpoints,
                                "tool-side-receipts.json": [r.to_dict() for r in tool_receipts],
                                "authorizations.json": [a.to_dict() for a in (self.authorizations if authorizations is None else authorizations)]},
                               self.trusted.export(), checkpoints, case_id=case_id)
        vd = VerificationDecision(new_id("vd"), case_id, result["status"], result["problems"],
                                  result["checked_entries"], self.clock.iso(), self.signer.key_id)
        payload = vd.to_dict()
        return Signed(payload, [self.signer.sign_payload(payload)])
