"""End-to-end AI SOC orchestrator.

Wires: dual_model detection -> frozen WorkOrder -> minimal CapabilityGrant ->
constrained agent investigation -> external PolicyDecision -> (human approval)
-> signed authorization -> PEP execution -> tool-side receipt -> ledger ->
independent verification -> human acceptance.

Five distinct signing identities are used (ledger, authorizer, executor,
verifier, approver) so that no single key can both authorize and attest.
In this reference implementation they live in one process; the paper's trust
assumptions require them to be in separately administered domains.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .canonical import digest
from .crypto import Clock, Ed25519Signer, TrustedKeys, utc_iso
from .idps import CaseDecision, CaseStatus, DualModel, ExternalAnomaly, ExternalKnown, FlowRecord, load_verified_model
from .owp import (
    AcceptanceDecision,
    ActionRequest,
    CapabilityGrant,
    EncryptedEvidenceStore,
    ExternalEvidenceRef,
    ExternalWitness,
    HashChainLedger,
    PolicyDecision,
    Signed,
    Verifier,
    WorkOrder,
    new_id,
)
from .sandbox import (
    ACTION_ADD_WATCHLIST,
    ACTION_BLOCK_HOST,
    ACTION_EGRESS_CONNECT,
    ACTION_TAG_CASE,
    MSG_ACTION_REQUEST,
    MSG_INVESTIGATION_REPORT,
    ApprovalView,
    AuthorizationError,
    AuthorizationSigner,
    BoundedExecutor,
    ControlledEgressProxy,
    EgressConfig,
    HumanApprover,
    InvestigationAgent,
    PEPConfig,
    PolicyEnforcementPoint,
    PolicyEngine,
    ReadOnlyTools,
    RuntimeConstraints,
    TelemetryStore,
    ToolSideLog,
    build_approval_view,
)

HumanPolicy = Callable[[ApprovalView], Tuple[bool, str]]
# Produces a *signed* HumanApproval for a reserved request. The default wraps the local
# HumanApprover; an external inbox (e.g. AiSOC approvals) can be plugged in instead.
ApprovalProvider = Callable[[ApprovalView, ActionRequest, WorkOrder, PolicyDecision], Signed]


# ── 【老師註解】conservative_human ────────────────────────────────
# 做什麼：示範用的「保守審批人」。看到注入旗標就拒、看到出站就拒、只有「判定惡意 + 至少兩條獨立證據 + 可逆封鎖」才批。
# 為什麼：模擬需要一個確定性的人類替身；它刻意保守，讓演示結果可重現。正式環境這個位置是真人（或 AiSOC 審批收件匣）。
# 怎麼看：這個函數的回傳值會交給 HumanApprover.decide 簽名；函數本身沒有鑰匙，換成別的決策邏輯不影響簽名鏈。
# 對應：準則 #4、#13
def conservative_human(view: ApprovalView) -> Tuple[bool, str]:
    """Simulated approver used by the demo. A real deployment has a person here."""
    if view.injection_flags_seen:
        return False, "injection indicators present in evidence; refusing until reviewed"
    if view.action == ACTION_EGRESS_CONNECT:
        return False, "outbound transfer not justified by case"
    if view.action == ACTION_BLOCK_HOST and view.agent_verdict == "malicious" and len(view.supporting_evidence) >= 2:
        return True, "multiple independent evidence items; reversible block within ttl"
    return False, "insufficient evidence for high-impact action"


# ── 【老師註解】RequestOutcome / CaseResult ───────────────────────
# 做什麼：給人看的「結果摘要」，就是 cases.json 裡每一筆的內容。RequestOutcome 記一個動作請求過了哪幾道閘門；
#         CaseResult 記一個案件的偵測、是否派 Agent、是否去重、報告、所有請求、驗證狀態、接受狀態、被出口丟棄的訊息。
# 為什麼：帳本是給機器驗的，這個結構是給人（和評審）快速判讀用的。
# 判讀要點：policy_status ∈ {allowed, reserved, denied, dropped_by_egress}；human_decision 只有 reserved 才有值；
#           authorized=True 但 executed=False 代表「簽名器簽了、PEP 擋了」——情境測試就是用這組欄位當證據。
# 對應：準則 #5；測試 tests/test_end_to_end.py::test_scenarios_behave_as_specified
@dataclass
class RequestOutcome:
    request_id: str
    action: str
    tenant: str
    policy_status: str
    human_decision: Optional[str]
    authorized: bool
    executed: bool
    reason: str


@dataclass
class CaseResult:
    case_id: str
    flow_id: str
    decision: CaseDecision
    investigated: bool
    deduplicated: bool = False
    report: Optional[Dict[str, Any]] = None
    requests: List[RequestOutcome] = field(default_factory=list)
    verification_status: Optional[str] = None
    verification_findings: List[str] = field(default_factory=list)
    acceptance_status: Optional[str] = None
    egress_dropped: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "flow_id": self.flow_id,
            "decision": self.decision.to_dict(),
            "investigated": self.investigated,
            "deduplicated": self.deduplicated,
            "report": self.report,
            "requests": [r.__dict__ for r in self.requests],
            "verification_status": self.verification_status,
            "verification_findings": self.verification_findings,
            "acceptance_status": self.acceptance_status,
            "egress_dropped": self.egress_dropped,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CaseResult":
        return cls(
            case_id=d["case_id"],
            flow_id=d["flow_id"],
            decision=CaseDecision.from_dict(d["decision"]),
            investigated=bool(d.get("investigated", False)),
            deduplicated=bool(d.get("deduplicated", False)),
            report=d.get("report"),
            requests=[RequestOutcome(**r) for r in d.get("requests", [])],
            verification_status=d.get("verification_status"),
            verification_findings=list(d.get("verification_findings", [])),
            acceptance_status=d.get("acceptance_status"),
            egress_dropped=list(d.get("egress_dropped", [])),
        )


# ── 【老師註解】AISOC ─────────────────────────────────────────────
# 做什麼：整個系統唯一的「編排者」。建構時造出五把角色鑰匙、帳本、見證、證據庫、工具、政策、審批、簽名器、執行器、PEP、
#         驗證器、出口代理；之後每個案件都走 _run_case 這一條固定流程。
# 為什麼：把所有元件在同一個地方接線，讀者才能一眼看到「資料從偵測到執行到驗證」的完整路徑，確認沒有旁路。
# 怎麼看：self.keys 五把鑰匙各司其職（準則 #9）；model_release 鑰匙「不在」這裡——訓練域只交公鑰給 SOC。
#         建構時第一筆帳本就是 model_release：記錄「這次用的模型有沒有通過簽名發布閘門」。
# 誠實提醒：五個信任域在同一個 Python 進程裡；論文的保證需要它們在不同管理員手上（準則 #13）。
# 對應：全部準則；測試 tests/test_end_to_end.py::test_happy_path_is_fully_recorded_and_verified
class AISOC:
    def __init__(
        self,
        model: DualModel,
        agent: InvestigationAgent,
        clock: Optional[Clock] = None,
        witness: Optional[ExternalWitness] = None,
        pep_config: Optional[PEPConfig] = None,
        human_policy: HumanPolicy = conservative_human,
        runtime: Optional[RuntimeConstraints] = None,
        dedup_window_s: int = 300,
        egress_config: Optional[EgressConfig] = None,
        approval_provider: Optional[ApprovalProvider] = None,
        model_manifest: Optional[Signed] = None,
    ) -> None:
        self.clock = clock or Clock()
        self.model = model
        self.agent = agent
        self.human_policy = human_policy
        self.dedup_window_s = dedup_window_s
        self._approval_provider = approval_provider

        self.keys = {
            role: Ed25519Signer(role) for role in ("ledger", "authorizer", "executor", "verifier", "approver")
        }
        self.trusted = TrustedKeys()
        for s in self.keys.values():
            self.trusted.trust(s)

        self.witness = witness if witness is not None else ExternalWitness()
        self.ledger = HashChainLedger(self.keys["ledger"], self.clock, self.witness)
        self.evidence = EncryptedEvidenceStore()
        self.telemetry = TelemetryStore()
        self.tool_log = ToolSideLog()
        self.tools = ReadOnlyTools(self.telemetry, self.tool_log, self.clock)
        self.policy = PolicyEngine(self.clock, runtime or RuntimeConstraints())
        self.approver = HumanApprover("analyst-1", self.keys["approver"], self.clock)
        self.signer = AuthorizationSigner(self.keys["authorizer"], self.trusted, self.clock)
        self.executor = BoundedExecutor(self.keys["executor"], self.clock)
        self.pep = PolicyEnforcementPoint(self.trusted, self.executor, self.tool_log, self.clock, pep_config)
        self.verifier = Verifier(self.keys["verifier"], self.trusted, self.clock)

        # The sandbox's only channel out. Identity is bound to the channel, not claimed by the agent.
        self.egress = ControlledEgressProxy(self.ledger, getattr(agent, "name", type(agent).__name__), self.clock, egress_config or EgressConfig())

        self._recent: Dict[Tuple[str, str, str], Any] = {}
        self.results: List[CaseResult] = []
        # Introspection hooks used by scenarios/tests; they expose no extra authority.
        self.last_order_grant: Optional[Tuple[WorkOrder, CapabilityGrant]] = None
        self.captured_authorizations: Dict[str, Tuple[Any, Signed]] = {}

        if model_manifest is not None:
            self.ledger.append("model_release", "-", {"status": "verified", "manifest": model_manifest.payload},
                               {"model_version": model.model_version})
        else:
            self.ledger.append("model_release", "-", {"status": "unverified", "model_version": model.model_version})

    # ── 【老師註解】AISOC.from_release ────────────────────────────
    # 做什麼：用「模型位元組 + 簽名發布清單 + 訓練域公鑰」建 SOC。load_verified_model 會驗哈希與 model_release 角色簽名，
    #         不符就 raise——SOC 根本不會被建出來（fail-closed）。
    # 為什麼：模型是會被投毒、被替換的製品。沒有這道閘門，任何人把一個壞模型檔放到路徑上，SOC 就會照用。
    # 對應：準則 #10；測試 tests/test_egress_release_grant.py::test_soc_from_release_records_verified_manifest_and_plain_init_records_unverified
    @classmethod
    def from_release(
        cls,
        model_bytes: bytes,
        manifest: Signed,
        release_trust: TrustedKeys,
        agent: InvestigationAgent,
        **kwargs: Any,
    ) -> "AISOC":
        """Construct a SOC whose model passed the signed release gate (fails closed otherwise)."""
        model = load_verified_model(model_bytes, manifest, release_trust)
        return cls(model, agent, model_manifest=manifest, **kwargs)

    # ------------------------------------------------------------------ pipeline
    # ── 【老師註解】AISOC.ingest / ingest_external ────────────────
    # 做什麼：兩個入口。ingest 用內建 dual_model 判定一筆流量；ingest_external 用外部偵測器（Slips）的結果當已知／異常分支。
    # 為什麼：論文架構不綁死偵測器——換偵測器只是換「誰提供 c_k 與 s_a」，後面的沙箱、政策、帳本完全不變。
    # 怎麼看：ingest_external 會把 Slips 原始紀錄的指紋寫進 refs.source_record_digest，日後可證明「當時 Slips 到底說了什麼」。
    # 對應：準則 #12；測試 tests/test_slips_adapter.py::test_run_through_soc_statuses_and_untrusted_description
    def ingest(self, flow: FlowRecord) -> CaseResult:
        """Detect with the internal dual_model and run the case."""
        self.telemetry.add_flow(flow)
        decision = self.model.decide(flow)
        return self._run_case(flow, decision)

    def ingest_external(
        self,
        flow: FlowRecord,
        known: ExternalKnown,
        anomaly: Optional[ExternalAnomaly] = None,
        use_internal_normality: bool = False,
        source_record: Optional[Dict[str, Any]] = None,
    ) -> CaseResult:
        """Run a case whose known branch comes from an external detector (e.g. Slips).

        The external detector's raw record is committed to the ledger by digest so the
        decision can later be tied to exactly what the detector emitted.
        """
        self.telemetry.add_flow(flow)
        decision = self.model.decide_external(flow, known, anomaly, use_internal_normality)
        refs = {"flow_id": flow.flow_id, "detector": known.source}
        if source_record is not None:
            refs["source_record_digest"] = digest(source_record)
        return self._run_case(flow, decision, refs)

    # ── 【老師註解】AISOC._run_case ───────────────────────────────
    # 做什麼：一個案件的完整生命週期，順序固定：
    #   記錄偵測 → (不需調查就結束) → 去重 → 凍結任務與能力授予 → Agent 調查 → 報告經出口代理 →
    #   每個請求經出口代理 → _handle_request → 帳本檢查點 → 驗證器 → 記錄驗證 → 接受決定 → 記錄接受
    # 為什麼：這是論文「三道閘門」在程式碼中的具體排列。任何一個步驟被跳過，驗證器都會在對賬時發現。
    # 怎麼看：egress.forward 回 ok=False 時「什麼都不做」，只把原因記到 result.egress_dropped——這就是 fail-closed。
    #         每個案件結束都呼叫 ledger.checkpoint()，所以案件數 = 檢查點數。
    # 對應：準則 #1、#2、#7、#8；測試 tests/test_end_to_end.py::test_compromised_agent_cannot_cause_side_effects
    def _run_case(self, flow: FlowRecord, decision: CaseDecision, refs: Optional[Dict[str, str]] = None) -> CaseResult:
        case_id = new_id("case")
        self.ledger.append("detection", case_id, decision.to_dict(), refs or {"flow_id": flow.flow_id})  # 步驟 1：偵測先上帳
        result = CaseResult(case_id=case_id, flow_id=flow.flow_id, decision=decision, investigated=False)

        if not decision.requires_agent_investigation:
            self.results.append(result)  # 步驟 2：低風險觀察／證據不足等狀態不派 Agent
            return result

        key = (flow.tenant, flow.src_host, decision.status.value)
        last = self._recent.get(key)
        now = self.clock.now()
        if last is not None and (now - last).total_seconds() < self.dedup_window_s:
            result.deduplicated = True  # 步驟 3：同租戶、同主機、同狀態在視窗內重複 ⇒ 抑制，避免 Agent 被洪水攻擊
            self.ledger.append("dedup_suppressed", case_id, {"key": list(key)})
            self.results.append(result)
            return result
        self._recent[key] = now

        order, grant = self._freeze_task(case_id, flow, decision)  # 步驟 4：凍結工作單與最小能力授予
        report = self.agent.investigate(order, decision, self.tools)  # 步驟 5：Agent 在沙箱內調查（只讀工具）
        result.investigated = True

        fwd = self.egress.forward(MSG_INVESTIGATION_REPORT, report.to_dict(), case_id)  # 步驟 6：報告必須經出口代理
        if not fwd.ok:
            # Fail closed: an un-audited report is as if the agent said nothing.
            result.egress_dropped.append(f"{MSG_INVESTIGATION_REPORT}:{fwd.code}")
        else:
            self.ledger.append("investigation_report", case_id, report.to_dict(), {"agent_id": fwd.agent_id})
            result.report = report.to_dict()
            for req in report.proposed_requests:
                f2 = self.egress.forward(MSG_ACTION_REQUEST, req.to_dict(), case_id)  # 步驟 7：每個請求也要各自過出口
                if not f2.ok:
                    result.egress_dropped.append(f"{MSG_ACTION_REQUEST}:{f2.code}")
                    result.requests.append(RequestOutcome(req.request_id, req.action, req.tenant, "dropped_by_egress", None, False, False, f2.code))
                    continue
                result.requests.append(self._handle_request(req, order, grant, report))  # 步驟 8：政策→人簽→簽名→PEP

        self.ledger.checkpoint()  # 步驟 9：簽 Merkle 根、送外部見證
        vd = self.verifier.verify_case(case_id, self.ledger, self.tool_log.receipts)  # 步驟 10：獨立驗證器對賬
        self.ledger.append("verification_decision", case_id, vd.payload)
        result.verification_status = vd.payload["status"]
        result.verification_findings = list(vd.payload["findings"])

        acc = self._accept(case_id, vd)  # 步驟 11：接受決定（VERIFIED→ACCEPTED／UNKNOWN→DEFERRED／FAILED→REJECTED）
        self.ledger.append("acceptance_decision", case_id, acc.payload)
        result.acceptance_status = acc.payload["status"]
        self.results.append(result)
        return result

    # ── 【老師註解】AISOC._freeze_task ────────────────────────────
    # 做什麼：產生「凍結的工作單」(WorkOrder) 與「最小能力授予」(CapabilityGrant)，兩者都上帳。
    # 為什麼：Agent 開始工作前，任務範圍與可用動作就已經定死且簽進帳本——它事後說「我以為可以封整個網段」沒有用。
    # 怎麼看：KNOWN_SUSPICIOUS 才給 block_host；疑似零日／衝突只給可逆動作（tag、watchlist），因為人審是必須的。
    #         資源樣式只有 host:<來源主機> 與 case:<案件>；授予 1 小時、最多 3 次。原始證據放加密庫，工作單只帶指紋。
    # 對應：準則 #3、#6、#12；測試 tests/test_policy_pep.py::test_policy_denies_scope_violations
    def _freeze_task(self, case_id: str, flow: FlowRecord, decision: CaseDecision) -> Tuple[WorkOrder, CapabilityGrant]:
        evidence_ids = [flow.flow_id, f"hostwin:{flow.src_host}", f"ioc:{flow.dst_ip}"]
        # Sensitive originals go to the encrypted store; the order carries only the digest.
        ev_digest = self.evidence.put({"flow": flow.__dict__, "decision": decision.to_dict()})
        if decision.status == CaseStatus.KNOWN_SUSPICIOUS:
            allowed = [ACTION_TAG_CASE, ACTION_ADD_WATCHLIST, ACTION_BLOCK_HOST]
        else:
            # suspected-unknown / conflict: human review mandatory, agent limited to reversible actions
            allowed = [ACTION_TAG_CASE, ACTION_ADD_WATCHLIST]
        order = WorkOrder(
            case_id=case_id,
            tenant=flow.tenant,
            task_description=f"Investigate flow {flow.flow_id} ({decision.status.value})",
            allowed_action_types=allowed,
            evidence_ids=evidence_ids,
            evidence_digest=ev_digest,
            detection_status=decision.status.value,
            model_version=decision.model_version,
            created_at=self.clock.iso(),
        )
        self.ledger.append("work_order", case_id, order.to_dict())
        now = self.clock.now()
        grant = CapabilityGrant(
            grant_id=new_id("grant"),
            case_id=case_id,
            tenant=flow.tenant,
            task_digest=order.digest(),
            allowed_actions=list(allowed),
            resource_patterns=[f"host:{flow.src_host}", f"case:{case_id}"],
            max_uses=3,
            usage_mode="bounded",
            issued_at=utc_iso(now),
            expires_at=utc_iso(now + timedelta(hours=1)),
        )
        self.ledger.append("capability_grant", case_id, grant.to_dict(), {"task_digest": order.digest()})
        self.last_order_grant = (order, grant)
        return order, grant

    # ── 【老師註解】AISOC._handle_request ─────────────────────────
    # 做什麼：單一 ActionRequest 的審批鏈：上帳 → 政策判決（上帳）→ denied 結束 → reserved 則取人簽（上帳）→
    #         人拒結束 → 簽名器簽發（拒簽也上帳）→ 授權上帳（含 nonce）→ PEP 執行 → 收據上帳。
    # 為什麼：每一個「決定」都緊接著一筆帳本紀錄，所以事後能重建「誰、在哪一步、為什麼」放行或擋下。
    # 怎麼看：RequestOutcome 的 policy_status / human_decision / authorized / executed 四個欄位就是四道閘門的通過紀錄；
    #         情境測試用「executed 全部為 False」證明被攻陷的 Agent 造不成任何副作用。
    # 對應：準則 #3、#4、#5；測試 tests/test_end_to_end.py::test_scenarios_behave_as_specified
    def _handle_request(self, req, order: WorkOrder, grant: CapabilityGrant, report) -> RequestOutcome:
        case_id = order.case_id
        self.ledger.append("action_request", case_id, req.to_dict())  # 請求本身先上帳（驗證器會比對它有無 agent_egress）
        pd = self.policy.decide(req, order, grant)  # 閘門 1：外部政策
        self.ledger.append("policy_decision", case_id, pd.to_dict(), {"request_digest": pd.request_digest})
        out = RequestOutcome(req.request_id, req.action, req.tenant, pd.status, None, False, False, "; ".join(pd.reasons))
        if pd.status == "denied":
            return out

        approval: Optional[Signed] = None
        if pd.status == "reserved":
            view = build_approval_view(req, report, pd)  # 閘門 2：人類審批（看到完整 ApprovalView）
            approval = self._approve(view, req, order, pd)
            self.ledger.append("human_approval", case_id, approval.payload, {"request_digest": pd.request_digest})
            out.human_decision = approval.payload["decision"]
            if approval.payload["decision"] != "approve":
                out.reason = f"human rejected: {approval.payload['rationale']}"
                return out

        try:
            auth = self.signer.issue(req, order, pd, approval)  # 閘門 3：簽名器（絕不盲簽）
        except AuthorizationError as exc:
            self.ledger.append("authorization_refused", case_id, {"request_digest": pd.request_digest, "error": str(exc)})
            out.reason = f"signer refused: {exc}"
            return out
        out.authorized = True
        self.ledger.append("authorization", case_id, auth.payload, {"request_digest": pd.request_digest, "nonce": auth.payload["nonce"]})

        outcome = self.pep.execute(req, auth)  # 閘門 4：PEP 重驗一遍再執行
        if outcome.executed:
            self.captured_authorizations[case_id] = (req, auth)  # 僅供情境測試拿去「重放」用，不給任何額外權力
        if outcome.receipt is not None:
            self.ledger.append("action_receipt", case_id, outcome.receipt.payload, {"request_digest": pd.request_digest})
        out.executed = outcome.executed
        out.reason = outcome.reason
        return out

    # ── 【老師註解】AISOC._approve / set_approval_provider ────────
    # 做什麼：審批來源可插拔。預設用本地 human_policy + HumanApprover 簽；set_approval_provider 可換成 AiSOC 審批收件匣橋接。
    # 為什麼：「誰來批」是部署決定，「批了要簽、要綁定請求」是架構決定；把兩者分開，換 SOC 平台不必改信任鏈。
    # 對應：準則 #4；測試 tests/test_aisoc_stack.py::test_bridge_approved_decision_executes_and_records_external_ref
    def _approve(self, view: ApprovalView, req: ActionRequest, order: WorkOrder, pd: PolicyDecision) -> Signed:
        if self._approval_provider is not None:
            return self._approval_provider(view, req, order, pd)
        approve, rationale = self.human_policy(view)
        return self.approver.decide(req, order, pd, approve, rationale)

    def set_approval_provider(self, provider: Optional[ApprovalProvider]) -> None:
        """Route reserved actions to an external approval system (e.g. the AiSOC inbox bridge)."""
        self._approval_provider = provider

    # ── 【老師註解】AISOC.anchor_external_evidence ────────────────
    # 做什麼：把外部系統（AiSOC）證據包的指紋寫進帳本，並「立刻」做一次檢查點送外部見證。
    # 為什麼：AiSOC 的 HMAC 只對持有金鑰的人有意義（伺服器自己可以造任何包）；寫進 Ed25519 帳本並見證後，
    #         證據內容就被「第三方」釘住，從「篡改可偵測」升級為「對外可承諾」。
    # 對應：準則 #7；測試 tests/test_aisoc_stack.py::test_anchor_commits_only_digests_and_refuses_bad_bundles
    def anchor_external_evidence(self, ref: ExternalEvidenceRef) -> Dict[str, Any]:
        """Commit a foreign artefact's digest to the ledger and witness it immediately."""
        self.ledger.append("external_evidence", ref.case_id, ref.to_dict(),
                           {"system": ref.system, "external_id": ref.external_id, "payload_sha256": ref.payload_sha256})
        return self.ledger.checkpoint()

    # ── 【老師註解】AISOC._accept ─────────────────────────────────
    # 做什麼：根據驗證結果產生 AcceptanceDecision：VERIFIED → ACCEPTED、UNKNOWN → DEFERRED（擱置）、FAILED → REJECTED。
    # 為什麼：驗證器是機器，接受與否是人的責任；這裡用 approver 鑰匙簽名，代表「有人為這個結論負責」。
    # 誠實提醒：rationale 寫明是模擬——正式環境必須由真人按下接受。
    # 對應：準則 #8；消融「no external witness」⇒ 這裡只會出現 DEFERRED，不會 ACCEPTED
    def _accept(self, case_id: str, vd: Signed) -> Signed:
        status = "ACCEPTED" if vd.payload["status"] == "VERIFIED" else ("DEFERRED" if vd.payload["status"] == "UNKNOWN" else "REJECTED")
        acc = AcceptanceDecision(
            acceptance_id=new_id("acc"),
            case_id=case_id,
            verification_digest=digest(vd.payload),
            status=status,
            accepted_by=self.approver.approver_id,
            rationale="simulated acceptance follows verification status; a human must own this in production",
            accepted_at=self.clock.iso(),
        )
        payload = acc.to_dict()
        return Signed(payload=payload, signatures=[self.keys["approver"].sign_payload(payload)])

    # ------------------------------------------------------------------ export
    # ── 【老師註解】AISOC.export ──────────────────────────────────
    # 做什麼：把可離線驗證所需的一切寫成 JSON：帳本、受信公鑰、工具側收據、工具呼叫、見證檢查點、案件結果、模型卡。
    # 為什麼：監管者／評審不需要接觸原始流量，也不需要跑 SOC；拿這幾個檔案 + `aisoc verify` 就能獨立驗證。
    # 怎麼看：`python -m aisoc verify <dir>` 讀的就是這裡寫出的檔案。
    # 對應：準則 #8；測試 tests/test_egress_release_grant.py::test_cli_slips_ingest_verify_bundle_and_push_dry_run
    def export(self, out_dir: Path) -> None:
        import json

        out_dir.mkdir(parents=True, exist_ok=True)
        self.ledger.export(out_dir / "ledger.json")
        (out_dir / "trusted-keys.json").write_text(json.dumps(self.trusted.export(), indent=2, sort_keys=True))
        (out_dir / "tool-side-receipts.json").write_text(
            json.dumps([r.to_dict() for r in self.tool_log.receipts], indent=2, sort_keys=True)
        )
        (out_dir / "tool-calls.json").write_text(
            json.dumps([c.__dict__ for c in self.tool_log.calls], indent=2, sort_keys=True)
        )
        (out_dir / "witness-checkpoints.json").write_text(json.dumps(self.witness.checkpoints(), indent=2, sort_keys=True))
        (out_dir / "cases.json").write_text(json.dumps([r.to_dict() for r in self.results], indent=2, sort_keys=True))
        (out_dir / "model-card.json").write_text(json.dumps(self.model.describe(), indent=2, sort_keys=True))
