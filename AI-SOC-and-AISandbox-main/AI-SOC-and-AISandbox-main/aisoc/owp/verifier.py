"""Independent verifier: chain integrity, witness anchoring and tool-side reconciliation.

The verifier never trusts the ledger alone. Each executed tool receipt must be
preceded by a recorded authorization that binds the same request digest, and
every ledger execution record must be matched by a tool-side receipt. A
receipt without authorization is a *bypass*; an authorization without any
receipt is reported but is not by itself a failure (an action may legitimately
not have been executed).
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from ..canonical import digest
from ..crypto import Clock, Ed25519Signer, TrustedKeys
from .ledger import HashChainLedger
from .objects import Signed, VerificationDecision, new_id


# ── 【老師註解】Verifier ──────────────────────────────────────────
# 做什麼：獨立驗證器。它「不信任帳本本身」，而是把三份紀錄互相對賬：帳本哈希鏈、外部見證的 Merkle 根、工具側收據。
# 為什麼：帳本管理員若能改帳本，單看帳本就毫無意義；所以要拿「帳本以外」的兩樣東西來對：
#         (1) 外部見證早已拿到的檢查點簽名——證明帳本沒被改寫或截短；
#         (2) 執行工具自己簽的收據——證明「有做的事都有授權、有記錄」。
# 怎麼看：它用 verifier 角色的鑰匙簽 VerificationDecision，之後人類據此做 AcceptanceDecision。
#         沒有外部見證 ⇒ 最多只能回 UNKNOWN，永遠不會 VERIFIED（準則 #8）。
# 拿掉會怎樣：繞過帳本直接執行、事後補授權、改帳本數字——全部沒人發現。
# 對應：準則 #7、#8；測試 tests/test_ledger_verifier.py::test_verifier_unknown_without_witness
class Verifier:
    def __init__(self, signer: Ed25519Signer, trusted: TrustedKeys, clock: Clock) -> None:
        self.signer = signer
        self.trusted = trusted
        self.clock = clock

    # ── 【老師註解】Verifier.verify_case ─────────────────────────
    # 做什麼：對一個案件做五項檢查，任何 finding 都寫進回傳物件：
    #   ① 哈希鏈每一環是否接得上 ② 見證過的 Merkle 根是否吻合 ③ 每個 action_request 之前是否有同摘要的 agent_egress
    #   ④ 每張「executed」收據是否在帳本裡、且授權記錄在執行「之前」 ⑤ 帳本裡每筆執行是否都有對應收據
    # 怎麼看：status 判定——有任何非見證類 finding ⇒ FAILED；只有「缺見證」這類 finding ⇒ UNKNOWN；全空 ⇒ VERIFIED。
    # 拿掉會怎樣：少了 ③ 就看不出消融「egress fail-open」；少了 ④ 就看不出「tool-side receipt without authorization」繞過。
    # 對應：準則 #2、#7、#8；測試 tests/test_egress_release_grant.py::test_verifier_flags_action_request_without_egress_record
    def verify_case(
        self,
        case_id: str,
        ledger: HashChainLedger,
        tool_receipts: Iterable[Signed],
    ) -> Signed:
        findings: List[str] = []
        unknown = False

        chain_problems = ledger.verify_chain()  # 檢查 ①：重算每一環 entry_hash，比對 prev_hash
        findings.extend(f"chain: {p}" for p in chain_problems)

        witness_problems = ledger.verify_against_witness(self.trusted)  # 檢查 ②：見證過的 Merkle 根 vs 現在重算的根
        for p in witness_problems:
            findings.append(f"witness: {p}")
            if "UNKNOWN" in p or "no external witness" in p:
                unknown = True

        entries = ledger.entries_for_case(case_id)
        auth_by_request: Dict[str, int] = {}
        exec_entries: Dict[str, int] = {}
        egress_digests: Dict[str, int] = {}
        for e in entries:
            if e.entry_type == "authorization":
                auth_by_request[e.refs.get("request_digest", "")] = e.index
            elif e.entry_type == "action_receipt":
                exec_entries[e.object_digest] = e.index
            elif e.entry_type == "agent_egress":
                egress_digests.setdefault(e.refs.get("msg_digest", ""), e.index)
            elif e.entry_type == "action_request":
                # Complete mediation: a request the control plane acted on must have entered
                # through the audited egress channel first (paper §VII).
                # 檢查 ③：這個請求的摘要必須「先」出現在某筆 agent_egress 裡，否則它不是從受控出口進來的
                seen = egress_digests.get(e.object_digest)
                if seen is None or seen > e.index:
                    findings.append(f"ledger entry {e.index}: action_request did not pass through the audited egress channel")

        receipts = [r for r in tool_receipts if r.payload.get("case_id") == case_id]
        for r in receipts:
            p = r.payload
            if not any(self.trusted.verify(p, s, expected_role="executor") for s in r.signatures):
                findings.append(f"receipt {p.get('receipt_id')}: executor signature invalid")  # 收據必須是 executor 角色簽的
                continue
            if p.get("outcome") != "executed":
                continue
            rd = p.get("request_digest", "")
            d = digest(p)
            if d not in exec_entries:
                # 檢查 ④a：工具側說「做了」，帳本卻沒有這張收據 ⇒ 有人繞過帳本執行
                findings.append(f"receipt {p['receipt_id']}: executed on tool side but NOT recorded in ledger (bypass)")
                continue
            if rd not in auth_by_request:
                # 檢查 ④b：做了，但帳本裡找不到針對同一 request_digest 的授權 ⇒ 無授權執行
                findings.append(f"receipt {p['receipt_id']}: executed without any recorded authorization (bypass)")
            elif auth_by_request[rd] > exec_entries[d]:
                # 檢查 ④c：授權的帳本序號比執行晚 ⇒ 先斬後奏、事後補簽
                findings.append(f"receipt {p['receipt_id']}: authorization recorded after execution")

        receipt_digests = {digest(r.payload) for r in receipts}
        for d, idx in exec_entries.items():
            if d not in receipt_digests:
                # 檢查 ⑤：帳本說有執行，工具側卻拿不出收據 ⇒ 兩份紀錄不一致
                findings.append(f"ledger entry {idx}: execution recorded but no matching tool-side receipt")

        # 判定：只有「缺見證」類的 finding 時是 UNKNOWN；其他任何 finding 都是 FAILED；什麼都沒有才是 VERIFIED
        if findings and not (unknown and all(f.startswith("witness:") for f in findings)):
            status = "FAILED"
        elif unknown:
            status = "UNKNOWN"
        else:
            status = "VERIFIED"

        vd = VerificationDecision(
            verification_id=new_id("vd"),
            case_id=case_id,
            status=status,
            findings=findings,
            checked_entries=len(entries),
            verified_at=self.clock.iso(),
            verifier_identity=self.signer.key_id,
        )
        payload = vd.to_dict()
        return Signed(payload=payload, signatures=[self.signer.sign_payload(payload)])
