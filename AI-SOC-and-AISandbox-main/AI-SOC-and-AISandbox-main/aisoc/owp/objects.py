"""OpenWorkProof-aligned protocol objects for the SOC workflow.

Object chain (paper §VIII-A):
    WorkOrder -> CapabilityGrant -> PolicyDecision -> (HumanApproval)
    -> SignedAuthorization -> ActionReceipt -> VerificationDecision -> AcceptanceDecision

Every object is a plain dict-serialisable dataclass with a ``schema_version``
and a deterministic ``digest()`` over its canonical JSON. The schema strings
are this project's SOC-extension proposals; they are *not* claimed to be the
upstream OpenWorkProof schema.
"""

from __future__ import annotations

import secrets
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Dict, List, Optional

from ..canonical import digest
from ..crypto import parse_iso

# ── 【老師註解】物件鏈總覽（aisoc/owp/objects.py）──────────────────────────────
# 這個檔案定義 SOC 工作流程裡會被簽名、被記帳、被驗證的「物件」。它們按時間順序串成一條鏈：
#   WorkOrder（案件任務＋證據範圍，凍結）
#     → CapabilityGrant（為這張工單發的最小能力：能做哪些動作、對哪些資源、幾次、到幾點）
#     → [ActionRequest]（沙箱 agent 的「請求」，本身沒有任何權力）
#     → PolicyDecision（沙箱外的政策引擎對請求的判定：allowed / reserved / denied）
#     → HumanApproval（保留動作需要的人簽，綁定請求／參數／證據摘要）
#     → AuthorizationEnvelope（授權簽署者簽出的一次性、短時效、綁定摘要的信封）
#     → ActionReceipt（執行端用「自己的」金鑰簽的收據，獨立於帳本）
#     → VerificationDecision（離線驗證器對帳本＋見證＋收據對帳的結論）
#     → AcceptanceDecision（人根據驗證結論決定接受／拒絕／暫緩）
#   ExternalEvidenceRef 則是把外部系統（AiSOC）產物的摘要錨進鏈裡。
# 每個物件都是 dataclass，有 schema_version 與 digest()（canonical JSON 的 SHA-256）。
# 帳本「只存摘要與參照」，所以下游任何人都能用 digest() 重算並比對，而不必看到原文。
# 為什麼要這麼多層：每一層都是一個獨立角色、獨立金鑰的簽名點；任何一層被跳過，離線驗證器就會看出鏈斷了。
# 對應：準則 #1、#3、#4、#6、#7、#9；測試 tests/test_end_to_end.py::test_happy_path_is_fully_recorded_and_verified
SCHEMA_PREFIX = "owp-soc"


# ── 【老師註解】schema ──────────────────────────────
# 做什麼：組出 "owp-soc/<name>/0.1" 這樣的 schema 字串。
# 為什麼：前綴 owp-soc 明示這是本專案的 SOC 擴充提案，不是上游 OpenWorkProof 的正式 schema（誠實範圍）。
# 對應：準則 #13（此處無直接測試）
def schema(name: str, version: str = "0.1") -> str:
    return f"{SCHEMA_PREFIX}/{name}/{version}"


# ── 【老師註解】_Obj ──────────────────────────────
# 做什麼：所有協定物件的共同基底：to_dict()（dataclass → 字典）與 digest()（canonical JSON → SHA-256 十六進位）。
# 為什麼：鏈上每個「*_digest」欄位都是用這個 digest() 算的；只要 canonical 化規則固定，任何人都能重算驗證。
# 對應：準則 #7；測試 tests/test_canonical_crypto.py::test_digest_stable_across_ordering
class _Obj:
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)  # type: ignore[arg-type]

    def digest(self) -> str:
        return digest(self.to_dict())


# ── 【老師註解】WorkOrder ──────────────────────────────
# 鏈中角色：起點。凍結這個案件「要做什麼、能用哪些動作詞彙、看哪些證據」，之後 agent 的任何請求都不得超出這個範圍。
# 怎麼看：allowed_action_types 是 agent 請求的詞彙表；evidence_digest 鎖住證據集合；detection_status / model_version 記下是哪個模型、什麼狀態開的案。
# 對應：準則 #1、#3；測試 tests/test_policy_pep.py::test_policy_denies_scope_violations
@dataclass
class WorkOrder(_Obj):
    """Frozen case task and evidence scope. Nothing outside this scope may be requested."""

    case_id: str
    tenant: str
    task_description: str
    allowed_action_types: List[str]
    evidence_ids: List[str]
    evidence_digest: str
    detection_status: str
    model_version: str
    created_at: str
    schema_version: str = schema("work-order")


# ── 【老師註解】CapabilityGrant ──────────────────────────────
# 鏈中角色：為單一 WorkOrder 發的「最小能力」——租戶、動作、資源樣式、次數上限、時效，全部有界。
# 怎麼看：task_digest 把授予綁到那張工單；usage_mode 區分一次性與有限次；parent_grant_id 用來追溯它是從哪個父授予收窄而來。
# 對應：準則 #3、#6；測試 tests/test_policy_pep.py::test_grant_expiry_denies
@dataclass
class CapabilityGrant(_Obj):
    """Minimal capability issued for one WorkOrder (tenant/resource/time/count bounded)."""

    grant_id: str
    case_id: str
    tenant: str
    task_digest: str
    allowed_actions: List[str]
    resource_patterns: List[str]
    max_uses: int
    usage_mode: str  # "single_use" | "bounded"
    issued_at: str
    expires_at: str
    parent_grant_id: Optional[str] = None
    schema_version: str = schema("capability-grant")

    # ── 【老師註解】CapabilityGrant.attenuate ──────────────────────────────
    # 做什麼：由現有授予「衍生」一個子授予給子任務。四個維度（動作、資源樣式、次數、到期）每一個都只能變小或不變。
    # 為什麼只准收窄：能力授予像一條鏈，父 ⊇ 子 ⊇ 孫；如果任何一環能放大，拿到小權限的人就能自己長出大權限，整條鏈的「最小權限」就假了。
    # 怎麼看（什麼會 raise ValueError）：
    #   · allowed_actions 不是父集合的子集 ⇒ "cannot add actions"
    #   · resource_patterns 不是父集合的子集 ⇒ "cannot add resource patterns"（注意是字串集合比對，"host:*" 不會被當成 "host:h1" 的子集）
    #   · max_uses 大於父值或為負 ⇒ "cannot increase max_uses"
    #   · expires_at 晚於父到期 ⇒ "cannot extend expiry"
    #   通過後用 replace() 複製一份，換新 grant_id，parent_grant_id 指回父；tenant / task_digest / case_id 原樣保留，不可改。
    # 拿掉會怎樣：子任務的授予可以比父任務更寬，PEP 只看到「一張合法簽過的授予」，無從得知它越界。
    # 對應：準則 #3、#6；測試 tests/test_egress_release_grant.py::test_attenuate_narrows_only
    def attenuate(
        self,
        allowed_actions: Optional[List[str]] = None,
        resource_patterns: Optional[List[str]] = None,
        max_uses: Optional[int] = None,
        expires_at: Optional[str] = None,
    ) -> "CapabilityGrant":
        """Derive a child grant. Capabilities can only shrink; any attempt to widen raises."""
        # 檢查 1：動作只能是父集合的子集
        actions = list(allowed_actions) if allowed_actions is not None else list(self.allowed_actions)
        if not set(actions) <= set(self.allowed_actions):
            raise ValueError("attenuation cannot add actions")
        # 檢查 2：資源樣式只能是父集合的子集
        patterns = list(resource_patterns) if resource_patterns is not None else list(self.resource_patterns)
        if not set(patterns) <= set(self.resource_patterns):
            raise ValueError("attenuation cannot add resource patterns")
        # 檢查 3：次數不能變多、不能為負
        uses = max_uses if max_uses is not None else self.max_uses
        if uses > self.max_uses or uses < 0:
            raise ValueError("attenuation cannot increase max_uses")
        # 檢查 4：到期不能延後（用 parse_iso 比時間，不是比字串）
        exp = expires_at if expires_at is not None else self.expires_at
        if parse_iso(exp) > parse_iso(self.expires_at):
            raise ValueError("attenuation cannot extend expiry")
        # 全部通過：複製、換新 id、記住父 id
        return replace(
            self,
            grant_id=new_id("grant"),
            allowed_actions=actions,
            resource_patterns=patterns,
            max_uses=uses,
            expires_at=exp,
            parent_grant_id=self.grant_id,
        )


# ── 【老師註解】ActionRequest ──────────────────────────────
# 鏈中角色：沙箱 agent 唯一能「說出口」的東西——我想對哪個資源做哪個動作、參數是什麼、依據哪些證據。它本身沒有任何權力。
# 怎麼看：destination 只有 egress 類動作才有，必須是精確 ip:port + scope + ttl；idempotency_key 讓重送同一請求不會重複執行。
# 對應：準則 #1、#2；測試 tests/test_end_to_end.py::test_compromised_agent_cannot_cause_side_effects
@dataclass
class ActionRequest(_Obj):
    """What the agent *asks* for. It carries no authority by itself."""

    request_id: str
    case_id: str
    tenant: str
    action: str
    resource: str
    destination: Optional[Dict[str, Any]]  # {"ip","port","scope":"public|private","ttl_s"} for egress
    params: Dict[str, Any]
    evidence_ids: List[str]
    idempotency_key: str
    requested_at: str
    schema_version: str = schema("action-request")


# ── 【老師註解】PolicyDecision ──────────────────────────────
# 鏈中角色：沙箱「外」的政策引擎對一個請求的判定：allowed（可直接授權）、reserved（要人簽）、denied（擋下）。
# 怎麼看：request_digest / task_digest / grant_id 把判定綁到具體請求、工單、授予；effective_capability 就是 C_eff = C_task ∩ C_grant ∩ C_human ∩ C_runtime 的落地結果。
# 對應：準則 #3；測試 tests/test_policy_pep.py::test_policy_classification
@dataclass
class PolicyDecision(_Obj):
    decision_id: str
    case_id: str
    request_digest: str
    task_digest: str
    grant_id: str
    policy_version: str
    status: str  # allowed | reserved | denied
    reasons: List[str]
    effective_capability: Dict[str, Any]
    decided_at: str
    schema_version: str = schema("policy-decision")


# ── 【老師註解】HumanApproval ──────────────────────────────
# 鏈中角色：保留動作（高影響、所有對外連線）的人類簽核。它不是「同意這個案子」，而是「同意這一個請求、這一組參數、這一份證據」。
# 怎麼看：request_digest / evidence_digest / params_digest / policy_decision_digest 四個摘要把人簽釘死在當下看到的內容上；
#   事後改參數 ⇒ params_digest 變 ⇒ 人簽失效。decision 只有 approve / reject；有 expires_at，人簽也會過期。
# external_ref：當決定是從外部系統（AiSOC 審批收件匣）蒐集來的，這裡記下系統名、該系統的記錄 id、審批人、時間——
#   讓「誰在哪個系統按了同意」留在鏈上可稽核；但要注意：簽在這個物件上的是橋接金鑰，不是那位分析師的金鑰，
#   所以「是哪位分析師」的不可否認性仍要靠 AiSOC 自己的稽核日誌（誠實範圍）。
# 拿掉會怎樣：少了摘要綁定，人只要簽過一次，攻擊者就能換參數／換目的地重用那張簽核。
# 對應：準則 #4、#13；測試 tests/test_policy_pep.py::test_signer_refuses_without_or_with_bad_approval、tests/test_aisoc_stack.py::test_bridge_approved_decision_executes_and_records_external_ref
@dataclass
class HumanApproval(_Obj):
    """A human decision bound to the exact request, evidence and parameters."""

    approval_id: str
    case_id: str
    request_digest: str
    evidence_digest: str
    params_digest: str
    policy_decision_digest: str
    decision: str  # approve | reject
    approver_id: str
    rationale: str
    issued_at: str
    expires_at: str
    # Set when the decision was collected from an external system (e.g. an AiSOC
    # approval inbox). Names the system and its record so the chain stays auditable.
    external_ref: Optional[Dict[str, Any]] = None
    schema_version: str = schema("human-approval")


# ── 【老師註解】AuthorizationEnvelope ──────────────────────────────
# 鏈中角色：授權簽署者（authorizer 角色）簽出的「通行證」，PEP 只認它。沒有它，任何動作都不會執行。
# 怎麼看三組關鍵欄位：
#   · nonce：單次使用。PEP 以原子操作記下已用過的 nonce，同一信封第二次送來就被拒 ⇒ 防重放。
#   · issued_at / expires_at：短時效（TTL）。過期即失效，且可被撤銷清單撤回。
#   · 綁定摘要 task_digest / evidence_digest / policy_decision_digest / params_digest / request_digest / approval_digest：
#     PEP 會重算實際送來的請求與參數的摘要去比對，任何一個對不上就拒絕——所以「先簽後改參數」行不通。
#   approval_digest 在保留動作上必須存在，簽署者看不到有效人簽就拒簽（準則 #4）。
# 拿掉會怎樣：少 nonce ⇒ 重放成功（消融實驗 test_ablation_flag_restores_replay 就是故意拿掉它）；少摘要 ⇒ 同一張授權可挪作他用。
# 對應：準則 #4、#5、#6；測試 tests/test_policy_pep.py::test_pep_happy_path_then_replay_and_tamper、tests/test_policy_pep.py::test_pep_requires_approval_digest_for_high_impact
@dataclass
class AuthorizationEnvelope(_Obj):
    """SOC extension envelope signed by the authorization signer (paper §VIII-B)."""

    case_id: str
    tenant: str
    task_digest: str
    evidence_digest: str
    policy_version: str
    policy_decision_digest: str
    action: str
    resource: str
    destination: Optional[Dict[str, Any]]
    params_digest: str
    request_digest: str
    issued_at: str
    expires_at: str
    nonce: str
    approval_digest: Optional[str]
    signer_identity: str
    schema_version: str = schema("authorization-envelope")


# ── 【老師註解】ActionReceipt ──────────────────────────────
# 鏈中角色：動作真的執行（或被拒、或因冪等而略過）之後，由「執行端」簽出的收據——這是鏈上第二份獨立紀錄。
# 為什麼要用執行端金鑰而不是授權者金鑰：如果同一把鑰匙既能簽授權又能簽收據，那它可以「自己授權、自己說做完了」，
#   帳本就只剩一個聲音。兩把鑰匙分開，離線驗證器才能做對帳：有收據卻沒授權 ⇒ 繞過（bypass）；有授權卻沒收據 ⇒ 不一致。
# 怎麼看：executor_identity 是執行端的 key_id；envelope_digest 指回它憑哪張信封執行；outcome 三值 executed / rejected / noop_idempotent。
# 對應：準則 #7、#9；測試 tests/test_end_to_end.py::test_happy_path_is_fully_recorded_and_verified
@dataclass
class ActionReceipt(_Obj):
    """Produced by the *tool/executor side*, independently of the ledger."""

    receipt_id: str
    case_id: str
    request_digest: str
    envelope_digest: Optional[str]
    action: str
    resource: str
    outcome: str  # executed | rejected | noop_idempotent
    detail: str
    executed_at: str
    executor_identity: str
    schema_version: str = schema("action-receipt")


# ── 【老師註解】VerificationDecision ──────────────────────────────
# 鏈中角色：離線、獨立的驗證器（verifier 角色）檢查「帳本哈希鏈 + Merkle 檢查點 + 外部見證 + 收據對帳」之後的結論。
# 怎麼看：status 三值——VERIFIED（全部吻合）、FAILED（發現竄改、截斷、繞過或不一致）、UNKNOWN（沒有外部見證可比對，不敢說好也不敢說壞）。
#   findings 是人可讀的逐條發現；checked_entries 讓人知道驗了多少筆。
# 拿掉會怎樣：沒有獨立驗證，帳本「自己說自己沒問題」；若允許無見證也回 VERIFIED，帳本維護者就能偷偷重寫歷史。
# 對應：準則 #8；測試 tests/test_ledger_verifier.py::test_verifier_unknown_without_witness、tests/test_ledger_verifier.py::test_modification_detected
@dataclass
class VerificationDecision(_Obj):
    verification_id: str
    case_id: str
    status: str  # VERIFIED | FAILED | UNKNOWN
    findings: List[str]
    checked_entries: int
    verified_at: str
    verifier_identity: str
    schema_version: str = schema("verification-decision")


# ── 【老師註解】AcceptanceDecision ──────────────────────────────
# 鏈中角色：終點。人（或代表人的接受者）看過 VerificationDecision 後決定 ACCEPTED / REJECTED / DEFERRED。
# 怎麼看：verification_digest 綁到那份驗證結論；soc.py 的對應規則是 VERIFIED→ACCEPTED、UNKNOWN→DEFERRED、其餘→REJECTED。
#   DEFERRED 很重要：見證還沒到位時不是「先當通過」，而是「暫緩」。
# 對應：準則 #8；測試 tests/test_end_to_end.py::test_happy_path_is_fully_recorded_and_verified
@dataclass
class AcceptanceDecision(_Obj):
    acceptance_id: str
    case_id: str
    verification_digest: str
    status: str  # ACCEPTED | REJECTED | DEFERRED
    accepted_by: str
    rationale: str
    accepted_at: str
    schema_version: str = schema("acceptance-decision")


# ── 【老師註解】ExternalEvidenceRef ──────────────────────────────
# 鏈中角色：把「別的系統產的東西」（例如 AiSOC 證據包）錨進我們的帳本——只錨摘要，不搬原文。
# 怎麼看：payload_sha256 是外部系統自己宣告的內容哈希；artefact_digest 是我們對整個製品算的摘要；
#   integrity_checked 誠實記下「我們到底驗了它哪些完整性機制」（例如 HMAC 有沒有重算、沒有金鑰就寫明沒驗）。
# 為什麼：外部系統的 HMAC 只能防「別人改」，不能防「它自己改」；一旦摘要進了有外部見證的哈希鏈，就升級成有第三方背書的承諾。
# 對應：準則 #7；測試 tests/test_aisoc_stack.py::test_anchor_commits_only_digests_and_refuses_bad_bundles、tests/test_aisoc_stack.py::test_anchor_without_key_records_that_hmac_was_not_checked
@dataclass
class ExternalEvidenceRef(_Obj):
    """Commitment to an artefact produced by another system (e.g. an AiSOC evidence bundle).

    Only digests travel into the ledger. ``integrity_checked`` records which of the
    foreign system's own integrity mechanisms this SOC verified before anchoring.
    """

    ref_id: str
    case_id: str
    system: str
    kind: str
    external_id: str
    payload_sha256: str
    artefact_digest: str
    integrity_checked: Dict[str, Any]
    anchored_at: str
    schema_version: str = schema("external-evidence")


# ── 【老師註解】Signed ──────────────────────────────
# 做什麼：「payload + 一串分離式簽名」的容器。簽名是對 payload 的 canonical JSON bytes 算的，不是對任意字串。
# 為什麼：分離式簽名讓同一份 payload 可以被多個角色各自簽（例如多簽），也讓驗證端可以只拿 payload_digest 當參照。
# 怎麼看：signatures 裡每一項含 key_id / role / alg / sig；TrustedKeys.verify 會再核對 role 是否符合預期。
# 對應：準則 #7、#9；測試 tests/test_canonical_crypto.py::test_signature_roundtrip_and_role_check
@dataclass
class Signed:
    """Payload + detached signatures (JCS canonical bytes are what is signed)."""

    payload: Dict[str, Any]
    signatures: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"payload": self.payload, "signatures": self.signatures}

    def payload_digest(self) -> str:
        return digest(self.payload)


# ── 【老師註解】new_id / new_nonce ──────────────────────────────
# 做什麼：用 secrets（密碼學安全亂數）產生識別碼與一次性 nonce。
# 為什麼：nonce 若可預測，攻擊者就能預先偽造或撞出重放；識別碼用 secrets 也避免被猜中而碰撞。
# 怎麼看：new_id 是 6 bytes（12 個 hex 字元），new_nonce 是 16 bytes（32 個 hex 字元）——nonce 更長，因為它承擔防重放的責任。
# 對應：準則 #6（此處無直接測試）
def new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(6)}"


def new_nonce() -> str:
    return secrets.token_hex(16)
