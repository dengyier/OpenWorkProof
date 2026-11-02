"""Human approval and the authorization signing service.

The signer never blind-signs agent output. It requires a PolicyDecision of
``allowed``, or ``reserved`` plus a valid HumanApproval whose digests bind the
exact request, evidence and parameters. Ed25519 + JCS only prove *who*
committed to *which bytes*; legality comes from the policy check performed
here before signing (paper §VIII-B).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Dict, List, Optional

from ..canonical import digest
from ..crypto import Clock, Ed25519Signer, TrustedKeys, parse_iso, utc_iso
from ..owp.objects import (
    ActionRequest,
    AuthorizationEnvelope,
    HumanApproval,
    PolicyDecision,
    Signed,
    WorkOrder,
    new_id,
    new_nonce,
)
from .agent import InvestigationReport


# ── 【老師註解】ApprovalView ──────────────────────────────────────
# 做什麼：審批人在按下「批准」前「必須」看到的全部資訊，故意同時列出「支持的證據」和「缺少的證據」。
# 為什麼：論文 §IX-B 反橡皮圖章——若只給人看 Agent 的結論與信心值，人會傾向照單全收。
#         把「缺什麼證據」「日誌裡有沒有注入句型」「可不可逆」「業務影響」攤開，才是有意義的人類判斷。
# 怎麼看：agent_self_reported_confidence_uncalibrated 欄位名刻意寫明「未校準」，提醒審批人這個數字不是機率。
# 對應：準則 #4、#11
@dataclass
class ApprovalView:
    """Everything a human must see before approving (paper §IX-B)."""

    case_id: str
    action: str
    resource: str
    destination: Optional[Dict[str, Any]]
    params: Dict[str, Any]
    supporting_evidence: List[str]
    missing_evidence: List[str]
    agent_verdict: str
    agent_self_reported_confidence_uncalibrated: float
    injection_flags_seen: List[str]
    policy_reasons: List[str]
    effective_capability: Dict[str, Any]
    reversible: bool
    business_impact: str

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


def build_approval_view(request: ActionRequest, report: InvestigationReport, decision: PolicyDecision) -> ApprovalView:
    reversible = bool(request.params.get("reversible", request.action != "egress_connect"))
    impact = {
        "block_host": "host loses connectivity for ttl; reversible by unblock",
        "egress_connect": "data leaves the environment; NOT reversible",
    }.get(request.action, "low")
    return ApprovalView(
        case_id=request.case_id,
        action=request.action,
        resource=request.resource,
        destination=request.destination,
        params=request.params,
        supporting_evidence=report.evidence_ids,
        missing_evidence=report.missing_evidence,
        agent_verdict=report.verdict,
        agent_self_reported_confidence_uncalibrated=report.self_reported_confidence,
        injection_flags_seen=report.injection_flags_seen,
        policy_reasons=decision.reasons,
        effective_capability=decision.effective_capability,
        reversible=reversible,
        business_impact=impact,
    )


# ── 【老師註解】HumanApprover ─────────────────────────────────────
# 做什麼：代表「一位審批人的簽名鑰匙」。decide() 把人的決定（approve / reject）簽成 HumanApproval。
# 為什麼：人的決定也要能被驗證、也要綁定請求——否則「某人口頭說可以」無法事後追責。
# 怎麼看：HumanApproval 同時記下 request_digest、evidence_digest、params_digest、policy_decision_digest 四個指紋，
#         等於說「我批准的是：這個請求、基於這些證據、這些參數、這個政策判決」——改任何一樣，批准就失效。
#         預設 ttl_s=900（15 分鐘）：批准是短效的，不能拿昨天的批准做今天的事。
# 注意：這個類別「不做決定」，決定由呼叫者提供（本地 stub 或 AiSOC 審批收件匣）；它只負責把決定簽起來。
# 對應：準則 #4、#6；測試 tests/test_policy_pep.py::test_signer_refuses_without_or_with_bad_approval
class HumanApprover:
    """Represents an approver's signing key. The decision logic is supplied by the caller."""

    def __init__(self, approver_id: str, signer: Ed25519Signer, clock: Clock, ttl_s: int = 900) -> None:
        self.approver_id = approver_id
        self.signer = signer
        self.clock = clock
        self.ttl_s = ttl_s

    def decide(self, request: ActionRequest, order: WorkOrder, decision: PolicyDecision, approve: bool, rationale: str) -> Signed:
        now = self.clock.now()
        approval = HumanApproval(
            approval_id=new_id("hap"),
            case_id=request.case_id,
            request_digest=request.digest(),
            evidence_digest=order.evidence_digest,
            params_digest=digest(request.params),
            policy_decision_digest=decision.digest(),
            decision="approve" if approve else "reject",
            approver_id=self.approver_id,
            rationale=rationale,
            issued_at=utc_iso(now),
            expires_at=utc_iso(now + timedelta(seconds=self.ttl_s)),
        )
        payload = approval.to_dict()
        return Signed(payload=payload, signatures=[self.signer.sign_payload(payload)])


class AuthorizationError(Exception):
    pass


# ── 【老師註解】AuthorizationSigner ───────────────────────────────
# 做什麼：授權簽名服務。只有在「政策說 allowed」或「政策說 reserved 且附上有效的人簽」時，才簽出一張 AuthorizationEnvelope。
# 為什麼：簽名本身只證明「誰對哪些位元組做了承諾」，不證明「這件事合法」。合法性來自簽名「之前」的政策檢查，
#         所以這個類別被設計成「絕不盲簽」：拒絕 denied、拒絕沒人簽的 reserved、拒絕綁錯對象的審批。
# 怎麼看：信封預設 ttl_s=300（5 分鐘）、單次 nonce、綁定 request/params/task/evidence/policy_decision 五個指紋。
#         消融情境「PEP no longer requires approval」之所以還是零執行，就是因為這裡也會拒簽——雙重保險。
# 對應：準則 #4、#6；測試 tests/test_policy_pep.py::test_signer_refuses_denied
class AuthorizationSigner:
    def __init__(self, signer: Ed25519Signer, trusted: TrustedKeys, clock: Clock, ttl_s: int = 300) -> None:
        self.signer = signer
        self.trusted = trusted
        self.clock = clock
        self.ttl_s = ttl_s

    # ── 【老師註解】AuthorizationSigner.issue ─────────────────────
    # 做什麼：簽發授權信封前的守門邏輯。順序：判決是否針對這個請求 → 是否綁定這張工作單 → denied 直接拒 →
    #         reserved 必須驗人簽 → 才產生帶 nonce 與 5 分鐘時效的信封。
    # 拿掉會怎樣：Agent 可以拿「別的請求」的 allowed 判決來套在惡意請求上（判決與請求脫鉤）。
    def issue(
        self,
        request: ActionRequest,
        order: WorkOrder,
        decision: PolicyDecision,
        approval: Optional[Signed] = None,
    ) -> Signed:
        if decision.request_digest != request.digest():
            raise AuthorizationError("policy decision is not about this request")  # 判決必須是「這個」請求的
        if decision.task_digest != order.digest():
            raise AuthorizationError("policy decision is not bound to this work order")
        if decision.status == "denied":
            raise AuthorizationError("refusing to sign a denied request")  # 絕不盲簽被拒的請求
        approval_digest: Optional[str] = None
        if decision.status == "reserved":
            if approval is None:
                raise AuthorizationError("reserved request requires a human approval")  # 保留動作沒人簽 ⇒ 拒簽
            self._check_approval(approval, request, order, decision)
            approval_digest = approval.payload_digest()  # 把人簽的指紋也寫進信封，PEP 會再查一次
        elif decision.status != "allowed":
            raise AuthorizationError(f"unknown policy status {decision.status}")

        now = self.clock.now()
        env = AuthorizationEnvelope(
            case_id=request.case_id,
            tenant=request.tenant,
            task_digest=order.digest(),
            evidence_digest=order.evidence_digest,
            policy_version=decision.policy_version,
            policy_decision_digest=decision.digest(),
            action=request.action,
            resource=request.resource,
            destination=request.destination,
            params_digest=digest(request.params),
            request_digest=request.digest(),
            issued_at=utc_iso(now),
            expires_at=utc_iso(now + timedelta(seconds=self.ttl_s)),
            nonce=new_nonce(),
            approval_digest=approval_digest,
            signer_identity=self.signer.key_id,
        )
        payload = env.to_dict()
        return Signed(payload=payload, signatures=[self.signer.sign_payload(payload)])

    # ── 【老師註解】AuthorizationSigner._check_approval ───────────
    # 做什麼：七項檢查驗一張人簽：approver 角色簽名 → 決定是 approve → 綁同一請求 → 參數沒變 → 證據範圍相同 →
    #         針對同一政策判決 → 尚未過期。任何一項不符就 raise，不會「部分通過」。
    # 怎麼看：第 4 項 params_digest 就是情境「parameter change after approval」被擋下的地方——
    #         人批准封鎖 1 小時，Agent 事後把 ttl 改成 24 小時，指紋立刻不同。
    # 對應：準則 #4；測試 tests/test_policy_pep.py::test_pep_happy_path_then_replay_and_tamper
    def _check_approval(self, approval: Signed, request: ActionRequest, order: WorkOrder, decision: PolicyDecision) -> None:
        p = approval.payload
        if not any(self.trusted.verify(p, s, expected_role="approver") for s in approval.signatures):
            raise AuthorizationError("approval signature invalid or signer not an approver")
        if p.get("decision") != "approve":
            raise AuthorizationError("human rejected the request")
        if p.get("request_digest") != request.digest():
            raise AuthorizationError("approval is bound to a different request")
        if p.get("params_digest") != digest(request.params):
            raise AuthorizationError("parameters changed after approval; re-authorization required")
        if p.get("evidence_digest") != order.evidence_digest:
            raise AuthorizationError("approval evidence scope mismatch")
        if p.get("policy_decision_digest") != decision.digest():
            raise AuthorizationError("approval refers to a different policy decision")
        if parse_iso(p["expires_at"]) <= self.clock.now():
            raise AuthorizationError("human approval expired")
