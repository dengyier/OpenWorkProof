"""Policy Enforcement Point and bounded executor (paper §VIII-C).

Order of checks: signature -> binding to the presented request -> expiry ->
revocation -> approval presence for reserved decisions -> atomic single-use
nonce -> idempotency -> bounded execution with egress default-deny. The
executor signs its own ActionReceipt with a key that is *not* the
authorization key, so the tool side produces independent evidence.

``PEPConfig`` flags exist only to run the ablations described in §XI-A. In
any real deployment they must all stay ``True``.
"""

from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from ..canonical import digest
from ..crypto import Clock, Ed25519Signer, TrustedKeys, parse_iso
from ..owp.objects import ActionReceipt, ActionRequest, Signed, new_id
from .agent import ACTION_ADD_WATCHLIST, ACTION_BLOCK_HOST, ACTION_EGRESS_CONNECT, ACTION_TAG_CASE, HIGH_IMPACT_ACTIONS
from .tools import ToolSideLog


# ── 【老師註解】PEPConfig ─────────────────────────────────────────
# 做什麼：PEP 八道檢查的開關。全部預設 True。
# 為什麼：只為了「消融實驗」存在——把某一道關掉，證明對應的攻擊（重放、無審批執行…）會重新成功。
# 判讀要點：正式部署任何一個 False 都是重大缺陷；看到有人改這裡就要問為什麼。
# 對應：準則 #5、#13；測試 tests/test_policy_pep.py::test_ablation_flag_restores_replay
@dataclass
class PEPConfig:
    verify_signature: bool = True
    verify_binding: bool = True
    verify_expiry: bool = True
    verify_revocation: bool = True
    require_approval_for_high_impact: bool = True
    single_use_nonce: bool = True
    idempotency: bool = True
    egress_default_deny: bool = True


# ── 【老師註解】NonceStore ────────────────────────────────────────
# 做什麼：記錄「已用過的 nonce」。consume() 在鎖裡做「查 + 記」兩個動作，所以同一個 nonce 只有第一次會回 True。
# 為什麼：授權信封是一張「一次性門票」。沒有這個紀錄，同一張有效信封可以被重複送進來執行十次（重放攻擊）。
# 怎麼看：threading.Lock 讓「檢查」與「加入」是原子的；否則兩個執行緒同時檢查都沒用過，就會同時放行。
# 誠實提醒：這裡是單機記憶體；多副本部署必須改用共享儲存（Redis／DB 的原子操作），否則各副本各自記帳形同沒記。
# 對應：準則 #6；測試 tests/test_policy_pep.py::test_pep_happy_path_then_replay_and_tamper
class NonceStore:
    """Atomic consume. Multi-replica deployments must back this with a shared store."""

    def __init__(self) -> None:
        self._used: Set[str] = set()
        self._lock = threading.Lock()

    def consume(self, nonce: str) -> bool:
        with self._lock:
            if nonce in self._used:
                return False
            self._used.add(nonce)
            return True


# ── 【老師註解】RevocationList ────────────────────────────────────
# 做什麼：撤銷名單，可以撤「一張票（nonce）」、「整個案件」或「某把簽名鑰匙簽的全部」。
# 為什麼：授權有 5 分鐘時效，但 5 分鐘內若發現 Agent 被攻陷或鑰匙外洩，不能乾等它過期——要能立刻作廢。
# 怎麼看：revoke_signer 對應「私鑰被盜怎麼辦」——把那把鑰匙的 key_id 丟進來，它簽過的所有信封瞬間失效。
# 對應：準則 #6；測試 tests/test_policy_pep.py::test_pep_rejects_untrusted_signer_and_expiry_and_revocation
class RevocationList:
    def __init__(self) -> None:
        self._nonces: Set[str] = set()
        self._cases: Set[str] = set()
        self._signers: Set[str] = set()

    def revoke_nonce(self, nonce: str) -> None:
        self._nonces.add(nonce)

    def revoke_case(self, case_id: str) -> None:
        self._cases.add(case_id)

    def revoke_signer(self, key_id: str) -> None:
        self._signers.add(key_id)

    def is_revoked(self, env: Dict[str, Any]) -> bool:
        return (
            env.get("nonce") in self._nonces
            or env.get("case_id") in self._cases
            or env.get("signer_identity") in self._signers
        )


@dataclass
class ExecutionOutcome:
    executed: bool
    reason: str
    receipt: Optional[Signed]
    side_effect: Optional[Dict[str, Any]] = None


# ── 【老師註解】BoundedExecutor ───────────────────────────────────
# 做什麼：模擬的「執行器」：真正動手封鎖、加監控名單、打標籤、放行一條出站連線。每種動作的副作用都是明確、有界的。
# 為什麼：它有自己的鑰匙（executor 角色），簽的收據和授權者的鑰匙無關——所以「授權方」和「執行方」各有一份獨立證據，
#         驗證器才能拿兩份互相對賬。
# 怎麼看：egress_default_deny=True 時，出站白名單「只來自授權信封裡的目的地」；沒有信封就沒有任何可達的地方。
#         在真實部署，這一層對應防火牆 API／EDR／出站網關。
# 對應：準則 #5、#9；測試 tests/test_end_to_end.py::test_happy_path_is_fully_recorded_and_verified
@dataclass
class BoundedExecutor:
    """Simulated effectors. Each action has an explicit, bounded side effect."""

    signer: Ed25519Signer
    clock: Clock
    egress_allowlist: Set[str] = field(default_factory=set)  # "ip:port" entries authorized by envelopes
    blocked_hosts: Dict[str, int] = field(default_factory=dict)
    watchlist: Dict[str, int] = field(default_factory=dict)
    tags: Dict[str, List[str]] = field(default_factory=dict)
    egress_log: List[Dict[str, Any]] = field(default_factory=list)

    def run(self, request: ActionRequest, env: Dict[str, Any], egress_default_deny: bool) -> Dict[str, Any]:
        a = request.action
        if a == ACTION_TAG_CASE:
            self.tags.setdefault(request.resource, []).append(str(request.params.get("tag", "")))
            return {"tagged": request.resource}
        if a == ACTION_ADD_WATCHLIST:
            self.watchlist[request.resource] = int(request.params.get("ttl_s", 0))
            return {"watchlisted": request.resource}
        if a == ACTION_BLOCK_HOST:
            self.blocked_hosts[request.resource] = int(request.params["ttl_s"])
            return {"blocked": request.resource, "ttl_s": self.blocked_hosts[request.resource]}
        if a == ACTION_EGRESS_CONNECT:
            dest = env.get("destination") or {}
            key = f"{dest.get('ip')}:{dest.get('port')}"
            if egress_default_deny:
                # The envelope *is* the allow entry; nothing else is reachable.
                ipaddress.ip_address(str(dest.get("ip")))
                self.egress_allowlist.add(key)
            self.egress_log.append({"dest": key, "case_id": request.case_id, "ttl_s": dest.get("ttl_s")})
            return {"egress": key}
        raise ValueError(f"executor has no effector for {a}")


# ── 【老師註解】PolicyEnforcementPoint ────────────────────────────
# 做什麼：「策略執行點」——所有動作在真正執行前的最後一道、也是唯一一道閘門。拿到 (請求, 授權信封) 後依固定順序檢查，
#         全過才叫 executor 動手，並且不論結果如何都簽一張收據留底。
# 為什麼：前面的政策、人簽、簽名器都可能被繞過（例如有人直接拿一張信封來）；PEP 不信任任何上游，自己重驗一遍。
# 怎麼看：rejections 清單記錄每次拒絕的原因，情境測試用它證明攻擊「在哪一關」被擋下。
# 拿掉會怎樣：等於沒有門——有信封（哪怕過期、重放、改過參數）就執行。
# 對應：準則 #5；測試 tests/test_policy_pep.py::test_pep_happy_path_then_replay_and_tamper
class PolicyEnforcementPoint:
    def __init__(
        self,
        trusted: TrustedKeys,
        executor: BoundedExecutor,
        tool_log: ToolSideLog,
        clock: Clock,
        config: Optional[PEPConfig] = None,
        revocations: Optional[RevocationList] = None,
    ) -> None:
        self.trusted = trusted
        self.executor = executor
        self.tool_log = tool_log
        self.clock = clock
        self.config = config or PEPConfig()
        self.revocations = revocations or RevocationList()
        self.nonces = NonceStore()
        self._idem: Dict[str, Signed] = {}
        self.rejections: List[Dict[str, str]] = []

    # ── 【老師註解】PolicyEnforcementPoint.execute ────────────────
    # 做什麼：八道檢查，順序固定、不可重排：
    #   ① 簽名（必須是 authorizer 角色）② 綁定（request/params/action/resource/tenant/destination 全部對得上）
    #   ③ 時效 ④ 撤銷 ⑤ 高影響必須帶 approval_digest ⑥ 冪等（同 idempotency_key ⇒ 回舊收據、不重做）
    #   ⑦ 單次 nonce（原子消耗）⑧ 受限執行 → 簽收據
    # 為什麼這個順序：便宜且能排除最多攻擊的檢查放前面；nonce 消耗放在「所有檢查都過」之後，否則一張會被拒的票
    #         也會把 nonce 燒掉。冪等放在 nonce 之前，重送同一請求會拿回原收據而不是被當成重放。
    # 對應：準則 #5、#6；測試 tests/test_policy_pep.py::test_pep_requires_approval_digest_for_high_impact
    def execute(self, request: ActionRequest, authorization: Signed) -> ExecutionOutcome:
        env = authorization.payload
        c = self.config

        def reject(reason: str) -> ExecutionOutcome:
            # 每次拒絕也簽一張 "rejected" 收據——拒絕本身也是要留底的事件
            self.rejections.append({"case_id": request.case_id, "request_id": request.request_id, "reason": reason})
            receipt = self._receipt(request, env, "rejected", reason)
            return ExecutionOutcome(False, reason, receipt)

        if c.verify_signature and not any(
            self.trusted.verify(env, s, expected_role="authorizer") for s in authorization.signatures
        ):
            return reject("authorization signature invalid or signer not trusted as authorizer")  # 檢查 ①
        if c.verify_binding:
            # 檢查 ②：信封必須和「現在送來的這個請求」逐欄吻合；改參數、換目標、換租戶都會在這裡被擋
            if env.get("request_digest") != request.digest():
                return reject("envelope not bound to presented request")
            if env.get("params_digest") != digest(request.params):
                return reject("parameters differ from authorized parameters")
            if (env.get("action"), env.get("resource"), env.get("tenant")) != (request.action, request.resource, request.tenant):
                return reject("action/resource/tenant differ from envelope")
            if env.get("destination") != request.destination:
                return reject("destination differs from authorized destination")
        if c.verify_expiry and parse_iso(env["expires_at"]) <= self.clock.now():
            return reject("authorization expired")  # 檢查 ③
        if c.verify_revocation and self.revocations.is_revoked(env):
            return reject("authorization revoked")  # 檢查 ④
        if c.require_approval_for_high_impact and request.action in HIGH_IMPACT_ACTIONS and not env.get("approval_digest"):
            return reject("high impact action lacks bound human approval")  # 檢查 ⑤
        if c.idempotency and request.idempotency_key in self._idem:
            prior = self._idem[request.idempotency_key]
            return ExecutionOutcome(False, "idempotent replay: returning prior receipt, no new side effect", prior)  # 檢查 ⑥
        if c.single_use_nonce and not self.nonces.consume(env["nonce"]):
            return reject("nonce already consumed (replay)")  # 檢查 ⑦：同一張票第二次進來

        try:
            effect = self.executor.run(request, env, c.egress_default_deny)  # 檢查 ⑧：受限執行
        except Exception as exc:
            return reject(f"executor error: {type(exc).__name__}: {exc}")
        receipt = self._receipt(request, env, "executed", str(effect))
        if c.idempotency:
            self._idem[request.idempotency_key] = receipt
        return ExecutionOutcome(True, "executed", receipt, effect)

    # ── 【老師註解】PolicyEnforcementPoint._receipt ───────────────
    # 做什麼：產生一張 ActionReceipt（執行或拒絕都有），用 executor 鑰匙簽名，並且同時寫進獨立的 ToolSideLog。
    # 為什麼：ToolSideLog 是「第二本帳」。帳本若被繞過，驗證器拿這裡的收據就能發現「有做卻沒記」（bypass）。
    # 對應：準則 #7、#9；情境「execution that bypasses the ledger」
    def _receipt(self, request: ActionRequest, env: Dict[str, Any], outcome: str, detail: str) -> Signed:
        r = ActionReceipt(
            receipt_id=new_id("rcpt"),
            case_id=request.case_id,
            request_digest=request.digest(),
            envelope_digest=digest(env) if env else None,
            action=request.action,
            resource=request.resource,
            outcome=outcome,
            detail=detail,
            executed_at=self.clock.iso(),
            executor_identity=self.executor.signer.key_id,
        )
        payload = r.to_dict()
        signed = Signed(payload=payload, signatures=[self.executor.signer.sign_payload(payload)])
        self.tool_log.record_receipt(signed)
        return signed
