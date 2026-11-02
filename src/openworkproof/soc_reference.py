"""Bounded reference SOC workflows; no live host or external HTTP operations."""
from __future__ import annotations

import json
from typing import Any

_LIMIT = 128 * 1024
_BUNDLE_LIMIT = 8 * 1024 * 1024
_SCOPE = (
    "Reference integration: supplied Slips alerts, synthetic-trained release model, "
    "deterministic investigation stub and in-memory simulated actions. No live host "
    "remediation, OS isolation, HSM, or production detection accuracy is established. "
    "Connecting this MCP server does not activate OWP Guard."
)


def sample_alerts() -> dict[str, Any]:
    from aisoc.adapters.slips import sample_alerts_json_lines
    return {"mode": "reference_only", "scope": _SCOPE,
            "alerts_jsonl": "\n".join(sample_alerts_json_lines()), "synthetic": True}


def analyze_slips(alerts_jsonl: str, tenant: str = "local-review") -> dict[str, Any]:
    """Analyze bounded user-supplied records locally with simulated actions only."""
    if not isinstance(alerts_jsonl, str) or not alerts_jsonl.strip():
        raise ValueError("alerts_jsonl must contain supported Slips JSONL records")
    if len(alerts_jsonl.encode("utf-8")) > _LIMIT:
        raise ValueError("alerts_jsonl exceeds 128 KiB")
    lines = alerts_jsonl.splitlines()
    if len(lines) > 500:
        raise ValueError("alerts_jsonl exceeds 500 lines")
    if not isinstance(tenant, str) or not tenant.strip() or len(tenant) > 128:
        raise ValueError("tenant must be a nonempty identifier of at most 128 characters")

    from aisoc.adapters.slips import SlipsAdapter, parse_alerts_json, run_slips_parsed
    from aisoc.canonical import digest
    from aisoc.crypto import Clock, Ed25519Signer, TrustedKeys
    from aisoc.idps import MODEL_RELEASE_ROLE, DualModel, release_model
    from aisoc.sandbox import HeuristicStubAgent
    from aisoc.simulate import generate
    from aisoc.soc import AISOC

    parsed = parse_alerts_json(lines)
    cases = SlipsAdapter(tenant).build_cases(parsed)
    if not cases:
        raise ValueError("no supported Slips cases found")
    if len(cases) > 50:
        raise ValueError("at most 50 source windows may be reviewed per call")
    data = generate(n=800, seed=17)
    model = DualModel.train(data.train, data.val, model_version="owp-soc-reference/synthetic-17")
    clock = Clock(start=Clock().now())
    release_signer = Ed25519Signer(MODEL_RELEASE_ROLE)
    release_trust = TrustedKeys()
    release_trust.trust(release_signer)
    manifest = release_model(model, digest([f.__dict__ for f in data.train]),
                             release_signer, clock, approved_by="reference-only")
    soc = AISOC.from_release(model.to_bytes(), manifest, release_trust,
                            HeuristicStubAgent(clock), clock=clock,
                            human_policy=lambda view: (False, "MCP reference does not approve real actions"))
    summary = run_slips_parsed(soc, parsed, tenant=tenant, use_internal_normality=False)
    reviewed_cases = summary.export_cases()
    for case in reviewed_cases:
        case["simulated_acceptance_status"] = case.pop("acceptance_status", None)
        case["internal_reference_verification_status"] = case.pop("verification_status", None)
        case["human_acceptance_obtained"] = False
    return {"mode": "reference_only", "scope": _SCOPE, "real_host_actions": False,
            "summary": summary.to_dict(), "cases": reviewed_cases,
            "bundle": soc.export_bundle(),
            "trust_notice": "Bundle keys/checkpoints are self-supplied evidence, not independent trust. "
                            "Acquire expected keys and checkpoints through a separate trusted channel."}


def _decode(text: str, expected_type: type, name: str) -> Any:
    if not isinstance(text, str) or len(text.encode("utf-8")) > _BUNDLE_LIMIT:
        raise ValueError(f"{name} must be JSON text of at most 8 MiB")
    try:
        value = json.loads(text)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} is not valid JSON") from exc
    if not isinstance(value, expected_type):
        raise ValueError(f"{name} must be a JSON {expected_type.__name__}")
    return value


def verify_soc_bundle(bundle_json: str, trusted_keys_json: str = "",
                      trusted_checkpoints_json: str = "") -> dict[str, Any]:
    """Check signed evidence; VERIFIED requires caller-supplied external pins."""
    from aisoc.owp.verifier import verify_bundle
    bundle = _decode(bundle_json, dict, "bundle_json")
    keys = _decode(trusted_keys_json, dict, "trusted_keys_json") if trusted_keys_json else None
    checkpoints = (_decode(trusted_checkpoints_json, list, "trusted_checkpoints_json")
                   if trusted_checkpoints_json else None)
    result = verify_bundle(bundle, trusted_keys=keys, trusted_checkpoints=checkpoints)
    return {**result, "scope": _SCOPE}
