"""External policy engine: allowed / reserved / denied.

Effective capability (paper §IX-A):
    C_eff = C_task ∩ C_grant ∩ C_human ∩ C_runtime
The agent can only shrink this set by asking for less; it can never widen it.
``reserved`` means a human must approve a decision bound to the exact request.
"""

from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..crypto import Clock, parse_iso
from ..owp.objects import ActionRequest, CapabilityGrant, PolicyDecision, WorkOrder, new_id
from .agent import FORBIDDEN_FOR_AGENT, HIGH_IMPACT_ACTIONS, LOW_IMPACT_ACTIONS, ACTION_BLOCK_HOST, ACTION_EGRESS_CONNECT

POLICY_VERSION = "soc-policy/2026-11-01.1"


@dataclass
class RuntimeConstraints:
    """C_runtime: deployment-wide ceilings independent of any one task."""

    max_block_ttl_s: int = 24 * 3600
    egress_default_deny: bool = True
    max_requests_per_case: int = 5
    high_impact_requires_evidence: bool = True


# ── 【老師註解】PolicyEngine ──────────────────────────────────────
# 做什麼：沙箱「外面」的政策引擎。Agent 送來一個 ActionRequest，它對照四個集合算交集，回傳 allowed / reserved / denied。
# 為什麼：論文 §IX-A：C_eff = C_task ∩ C_grant ∩ C_human ∩ C_runtime。Agent 只能「要得更少」，永遠不能「要得更多」；
#         放在沙箱外是因為沙箱裡的東西都可能已被攻陷，政策若放在裡面就等於讓嫌疑人自己寫判決書。
# 怎麼看：decide() 裡每個 deny(...) 都對應一條集合邊界；最後只有「沒被 deny 且屬於低影響」才是 allowed，
#         高影響或出站一律 reserved（必須人簽）。
# 拿掉會怎樣：跨租戶封鎖、把整個 10.0.0.0/8 封掉、把資料送到外部 URL——這些「技術上合法」的請求會直接過關。
# 對應：準則 #3、#4；測試 tests/test_policy_pep.py::test_policy_classification / test_policy_denies_scope_violations
@dataclass
class PolicyEngine:
    clock: Clock
    runtime: RuntimeConstraints = field(default_factory=RuntimeConstraints)
    policy_version: str = POLICY_VERSION
    _request_count: Dict[str, int] = field(default_factory=dict)

    # ── 【老師註解】PolicyEngine.decide ───────────────────────────
    # 做什麼：依序套四層約束（C_task → C_grant → C_runtime → C_human），任何一層不符就 deny；全部通過才分級。
    # 怎麼看：回傳的 PolicyDecision 帶 request_digest / task_digest / grant_id，把「這個判決是針對哪個請求」釘死，
    #         後面的簽名器與 PEP 都靠這些摘要比對，請求改一個字元判決就失效。
    # 判讀要點：status 只有三種——allowed（低影響、可逆、在範圍內）、reserved（高影響或出站，等人簽）、denied。
    def decide(self, request: ActionRequest, order: WorkOrder, grant: CapabilityGrant) -> PolicyDecision:
        reasons: List[str] = []
        status = "allowed"

        def deny(msg: str) -> None:
            nonlocal status
            status = "denied"
            reasons.append(msg)

        # C_task: frozen work order
        # 第 1 層 C_task：請求必須落在「凍結的工作單」裡——同一案件、同一租戶、動作在任務詞彙表內、只引用凍結過的證據
        if request.case_id != order.case_id:
            deny("request case_id does not match work order")
        if request.tenant != order.tenant:
            deny(f"tenant mismatch: request={request.tenant} order={order.tenant}")
        if request.action not in order.allowed_action_types:
            deny(f"action {request.action} outside task scope")
        if request.action in FORBIDDEN_FOR_AGENT:
            deny(f"action {request.action} can never be requested by the agent")  # 改政策／關審計／寫標籤：Agent 永遠不能要
        if set(request.evidence_ids) - set(order.evidence_ids):
            deny("request cites evidence outside the frozen evidence scope")

        # C_grant: minimal capability
        # 第 2 層 C_grant：能力授予必須綁定這張工作單（task_digest）、未過期、動作與資源樣式都在授予範圍內
        now = self.clock.now()
        if grant.case_id != order.case_id or grant.task_digest != order.digest():
            deny("grant is not bound to this work order")
        if parse_iso(grant.expires_at) <= now:
            deny("capability grant expired")
        if request.action not in grant.allowed_actions:
            deny(f"action {request.action} not in capability grant")
        if not any(fnmatch.fnmatch(request.resource, p) for p in grant.resource_patterns):
            deny(f"resource {request.resource} not covered by grant patterns {grant.resource_patterns}")

        # C_runtime
        # 第 3 層 C_runtime：部署層級的天花板——每案請求數、封鎖 TTL 上限、出站必須給精確 ip:port 且 scope 不能自報
        n = self._request_count.get(request.case_id, 0) + 1
        self._request_count[request.case_id] = n
        if n > self.runtime.max_requests_per_case:
            deny("per-case request budget exhausted")
        if request.action == ACTION_BLOCK_HOST:
            ttl = int(request.params.get("ttl_s", 0) or 0)
            if ttl <= 0 or ttl > self.runtime.max_block_ttl_s:
                deny(f"block ttl {ttl}s outside runtime ceiling")
        if request.action == ACTION_EGRESS_CONNECT:
            dest = request.destination or {}
            try:
                ip = ipaddress.ip_address(str(dest.get("ip", "")))
            except ValueError:
                ip = None
            if ip is None or not dest.get("port"):
                deny("egress request lacks a precise ip:port destination")
            else:
                actual_scope = "private" if ip.is_private else "public"  # scope 由程式重新判定，不信 Agent 自稱的 public/private
                if dest.get("scope") != actual_scope:
                    deny(f"declared scope {dest.get('scope')} does not match resolved {actual_scope}")
                if not dest.get("ttl_s") or int(dest["ttl_s"]) > 3600:
                    deny("egress ttl missing or above 3600s")
        if self.runtime.high_impact_requires_evidence and request.action in HIGH_IMPACT_ACTIONS and not request.evidence_ids:
            deny("high impact action without cited evidence")

        # C_human: anything high-impact or outbound is reserved for a human decision
        # 第 4 層 C_human：前三層都過了，才決定「要不要人簽」——高影響或出站 ⇒ reserved；低影響 ⇒ allowed；其他 ⇒ denied
        if status != "denied":
            if request.action in HIGH_IMPACT_ACTIONS or (
                request.action == ACTION_EGRESS_CONNECT and self.runtime.egress_default_deny
            ):
                status = "reserved"
                reasons.append("high impact / outbound: human approval bound to this request is required")
            elif request.action in LOW_IMPACT_ACTIONS:
                reasons.append("low impact reversible action within C_task ∩ C_grant ∩ C_runtime")
            else:
                deny("unclassified action")

        c_eff = {
            "tenant": order.tenant,
            "actions": sorted(set(order.allowed_action_types) & set(grant.allowed_actions) - FORBIDDEN_FOR_AGENT),
            "resource_patterns": list(grant.resource_patterns),
            "expires_at": grant.expires_at,
            "max_block_ttl_s": self.runtime.max_block_ttl_s,
            "egress_default_deny": self.runtime.egress_default_deny,
        }
        return PolicyDecision(
            decision_id=new_id("pd"),
            case_id=request.case_id,
            request_digest=request.digest(),
            task_digest=order.digest(),
            grant_id=grant.grant_id,
            policy_version=self.policy_version,
            status=status,
            reasons=reasons,
            effective_capability=c_eff,
            decided_at=self.clock.iso(),
        )
