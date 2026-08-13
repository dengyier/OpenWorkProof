#!/usr/bin/env python3
"""OWP Skill 调用演示（7/8 Skill；S7 rollback 未工具化）。

直接 import openworkproof.mcp_transport 中的工具函数（这些工具正是 OWP MCP
Server 在 AgentTeams Worker spec.mcpServers 后面暴露的能力）。无 ledger 依赖：
demo 证明 Skill 调用链路可达、结构化返回成立，可作为评审实证材料。

运行：
    PYTHONPATH=src python agentteams/scripts/run_skills_demo.py
输出：
    agentteams/evidence/skill-execution.log
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "src"))

from openworkproof import mcp_transport as mt  # noqa: E402

EVIDENCE = REPO / "agentteams" / "evidence" / "skill-execution.log"
EVIDENCE.parent.mkdir(parents=True, exist_ok=True)


def _record(log, skill: str, request: dict, response: dict) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    log.write(f"=== {ts} | {skill} ===\n")
    log.write("[REQUEST]\n")
    log.write(json.dumps(request, indent=1, sort_keys=True))
    log.write("\n[RESPONSE]\n")
    log.write(json.dumps(response, indent=1, sort_keys=True))
    log.write("\n\n")


def main() -> int:
    log = EVIDENCE.open("w")
    log.write(
        "# OpenWorkProof Skill 调用演示证据\n"
        "# 7/8 Skill（缺 S7 rollback：账本 superseded_by 兜底；见 "
        "docs/competition/skills-integration.md §一）\n"
        f"# Generated: {datetime.now(timezone.utc).isoformat()}\n\n"
    )

    # S8 owp.audit — list domains
    r = mt.owp_list_domains()
    _record(log, "S8 owp.audit | owp_list_domains()", {}, r)

    # S1 owp.authorize — generate keypair
    kp = mt.owp_generate_keypair()
    _record(log, "S1 owp.authorize | owp_generate_keypair()", {}, kp)

    # S1 owp.authorize — compute key id
    kid = mt.owp_compute_key_id(kp["public_key_b64url"])
    _record(
        log,
        "S1 owp.authorize | owp_compute_key_id",
        {"public_key_b64url": kp["public_key_b64url"]},
        kid,
    )

    # S1 owp.authorize — sign + verify round-trip (passwordless signature proof)
    object_type = "work-order"
    payload = json.dumps({"work_order_id": "demo-skill", "scope_id": "demo"})
    digest_resp = mt.owp_compute_digest(object_type, payload)
    sig_resp = mt.owp_sign_payload(
        object_type=object_type,
        payload=payload,
        private_key_hex=kp["private_key_hex"],
    )
    signed_payload = sig_resp["signed_payload"]
    verify_resp = mt.owp_verify_signature(
        public_key_b64url=kp["public_key_b64url"],
        object_type=object_type,
        signed_payload=json.dumps(signed_payload, sort_keys=True),
    )
    _record(
        log,
        "S1 owp.authorize | owp_compute_digest + owp_sign_payload + owp_verify_signature",
        {"object_type": object_type, "payload": payload},
        {
            "compute_digest": digest_resp,
            "sign_payload": sig_resp,
            "verify_signature": verify_resp,
        },
    )

    # S1 owp.authorize — get schema (proves S1 surface)
    schema = mt.owp_get_schema("work-order", "0.1")
    _record(
        log,
        "S1 owp.authorize | owp_get_schema(work-order, 0.1)",
        {"object_type": "work-order", "version": "0.1"},
        schema,
    )

    # S2 owp.repo_read — schema digest (proves S2 surface; real run needs
    # a populated ledger, see tests/test_delivery_m4_agentscope.py for the
    # full end-to-end flow).
    schema_digest = mt.owp_get_schema_digest("work-order", "0.1")
    _record(
        log,
        "S2 owp.repo_read | owp_get_schema_digest(work-order, 0.1)",
        {"object_type": "work-order", "version": "0.1"},
        schema_digest,
    )

    # S8 owp.audit — schema digest for action-receipt (proves S8 surface)
    ar_digest = mt.owp_get_schema_digest("action-receipt", "0.1")
    _record(
        log,
        "S8 owp.audit | owp_get_schema_digest(action-receipt, 0.1)",
        {"object_type": "action-receipt", "version": "0.1"},
        ar_digest,
    )

    log.close()
    print(f"skill-execution evidence written: {EVIDENCE}")
    print(f"size: {EVIDENCE.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
