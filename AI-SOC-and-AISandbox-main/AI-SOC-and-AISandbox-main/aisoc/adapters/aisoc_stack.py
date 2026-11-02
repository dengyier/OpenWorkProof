"""beenuar/AiSOC as the SOC platform around the verifiable core.

AiSOC (https://github.com/beenuar/AiSOC, MIT) is an open-source autonomous SOC
with alert ingest, case management, an agentic investigation runtime, an
approval inbox and exportable *evidence bundles*. This module bridges it to
the paper's design in three places, each of which is deliberately *thin*:

1. **Alert submission** — a :class:`~aisoc.soc.CaseResult` is pushed to AiSOC
   (``POST /api/v1/alerts/submit``, or the streaming ``/v1/ingest/batch``)
   using only the generic field names AiSOC's normalizer understands
   (``time``, ``severity``, ``title``, ``description``, ``host``, ``src_ip``,
   ``external_id``, ``mitre_techniques``, ``tags``). The ledger head and
   witness root are embedded so an AiSOC analyst can check the case against
   the ledger offline.
2. **Approval bridge** — when the policy engine *reserves* an action for a
   human, the request is written to AiSOC's approval inbox
   (``POST /api/v1/approvals``) and the bridge waits for a decision. AiSOC
   approvals are **not** signed by the approving human's own key, so the
   bridge turns the decision into a :class:`~aisoc.owp.objects.HumanApproval`
   signed with the bridge's approver-role key and records the AiSOC approval
   id / user id / timestamp in ``external_ref``. Non-repudiation then rests on
   the bridge key *plus* AiSOC's audit log — weaker than the paper's native
   per-human key, and said so in :mod:`docs/INTEGRATION.md`.
3. **Evidence-bundle anchoring** — AiSOC's investigation bundle is protected
   by ``sha256(payload)`` and an **HMAC-SHA256** over the canonical payload.
   HMAC gives tamper-evidence against anyone without the key, but not
   non-repudiation (whoever can verify can also forge). This adapter verifies
   the bundle and commits its digests to the hash-chained, Ed25519-signed,
   externally witnessed ledger, which is the upgrade the paper argues for.

No AiSOC code is vendored; the wire formats were taken from AiSOC's OpenAPI
document and ``evidence_bundle.py`` (v21.x). Endpoint paths are configurable
because the API port is deployment-specific.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple

from ..canonical import digest
from ..crypto import Clock, Ed25519Signer, parse_iso, utc_iso
from ..idps import FlowRecord
from ..owp.objects import (
    ActionRequest,
    ExternalEvidenceRef,
    HumanApproval,
    PolicyDecision,
    Signed,
    WorkOrder,
    new_id,
)
from ..sandbox.authorization import ApprovalView
from ..soc import AISOC, CaseResult

# ── 【老師註解】aisoc/adapters/aisoc_stack.py（模組總覽）─────────
# 做什麼：把 AiSOC（beenuar/AiSOC，一套 MIT 授權的開源 SOC 平台）接到論文架構的三個位置：
#         (1) 把案子推成 AiSOC 警報；(2) 把「保留動作需要人批」這件事搬到 AiSOC 的審批收件匣；(3) 把 AiSOC 匯出的調查證據包釘進我們的帳本。
# 為什麼：分析師日常是在 SOC 平台工作，不是在我們的終端機；但信任鏈（Agent 無權力 → 政策 → 人簽 → 簽名器 → PEP → 帳本）一個環節都不能少。
# 怎麼看：這個模組「刻意很薄」——只用 HTTP API、只用 AiSOC 自己的欄位名，不搬任何 AiSOC 程式碼。
#         要特別留意兩個誠實聲明：審批是由「橋接器的 approver 金鑰」代簽，不是分析師本人的金鑰；證據包的 HMAC 是對稱金鑰，
#         只能證明「持鑰者沒改過」，不能證明「是誰做的」（不可否認性），所以才要再釘進 Ed25519 帳本。
# 拿掉會怎樣：少了這層，就只能用本地的 stub 審批者；或把 AiSOC 的 HMAC 當成簽名來信任——兩者都是論文明確反對的。
# 對應：準則 #4、#7、#9、#13；docs/INTEGRATION.md §2
AISOC_SYSTEM = "aisoc"
AISOC_BUNDLE_SCHEMA = "1.0"
IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")

SEVERITY_BY_STATUS = {
    "KNOWN_SUSPICIOUS": "high",
    "SUSPECTED_UNKNOWN": "high",
    "MODEL_CONFLICT": "medium",
    "UNKNOWN": "medium",
    "LOW_RISK_OBSERVE": "low",
    "INSUFFICIENT_EVIDENCE": "low",
}


# ── 【老師註解】AiSOCError / AiSOCBundleError ─────────────────────
# 做什麼：兩個例外型別。AiSOCError 代表「和 AiSOC 溝通出了問題」（HTTP ≥ 400、設定缺漏）；AiSOCBundleError 代表「證據包不合格」。
# 為什麼：審批橋接器要能「只捕捉 AiSOCError」然後產出簽名拒絕；anchor_aisoc_bundle 則用 AiSOCBundleError 拒絕寫帳本。
#         型別分開，呼叫端才不會把「網路壞了」和「證據被竄改」混為一談。
class AiSOCError(Exception):
    pass


class AiSOCBundleError(AiSOCError):
    pass


# ----------------------------------------------------------------------------- transport
# ── 【老師註解】HttpClient（Protocol）────────────────────────────
# 做什麼：HTTP 傳輸層的「介面規格」：只要有 request(method, url, headers, body) → (狀態碼, JSON) 就算符合。
# 為什麼：這樣 AiSOCClient 可以被注入真實的 UrllibHttpClient，也可以被注入 FakeAiSOCServer——
#         整套測試與情境都不需要網路、Docker 或真正的 AiSOC（準則 #13 的誠實範圍）。
class HttpClient(Protocol):
    def request(self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> Tuple[int, Dict[str, Any]]:
        """Return (status_code, parsed_json_or_{})."""


# ── 【老師註解】UrllibHttpClient ──────────────────────────────────
# 做什麼：HttpClient 的真實實作，只用標準函式庫 urllib（不引入第三方依賴）。
# 怎麼看：HTTP 4xx／5xx 在 urllib 會變成例外；這裡把它「接住並轉回 (狀態碼, 內容)」，讓上層 _call 用統一方式判斷 status >= 400。
#         回應若不是 JSON，就把原文放進 {"detail": ...}，錯誤訊息才不會遺失。
class UrllibHttpClient:
    def __init__(self, timeout_s: float = 10.0) -> None:
        self.timeout_s = timeout_s

    def request(self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> Tuple[int, Dict[str, Any]]:
        import urllib.error
        import urllib.request

        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:  # noqa: S310 (operator-configured URL)
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, (json.loads(raw) if raw else {})
            except ValueError:
                return exc.code, {"detail": raw.decode("utf-8", "replace")}


# ── 【老師註解】AiSOCConfig ───────────────────────────────────────
# 做什麼：連 AiSOC 需要的所有設定：API 位址、bearer token、串流 ingest 位址／token、connector 識別、審批輪詢間隔／逾時／TTL。
# 為什麼：端點與埠號是部署相關的（AiSOC 的 API 和串流 ingest 通常在不同埠），寫死會讓部署者改程式碼。
# 怎麼看：approval_timeout_s（橋接器最多等多久）和 approval_ttl_s（送去 AiSOC 的審批單幾秒後過期）是兩個不同的時間；
#         預設都是 900 秒。短時效是準則 #6 的一部分——審批不是「永久授權」。
@dataclass
class AiSOCConfig:
    base_url: str = "http://localhost:8000"
    token: str = ""
    ingest_url: Optional[str] = None  # e.g. http://localhost:8081/v1/ingest/batch
    ingest_token: Optional[str] = None
    connector_id: str = "owp-soc"
    connector_type: str = "custom"
    source_format: str = "generic_json"
    approval_poll_s: float = 2.0
    approval_timeout_s: float = 900.0
    approval_ttl_s: int = 900

    # ── 【老師註解】AiSOCConfig.headers ────────────────────────────
    # 做什麼：組 HTTP 標頭：JSON 內容型別、Authorization（bearer token）、以及可選的 Idempotency-Key。
    # 為什麼：Idempotency-Key 是「同一個案子重送不會產生第二筆警報」的關鍵；AiSOC 以它去重。
    # 怎麼看：鍵值格式先在客戶端檢查（8–128 字元、只允許英數和 ._:-），不合格直接拋 AiSOCError，而不是送出去等伺服器拒絕。
    # 對應：測試 tests/test_aisoc_stack.py::test_push_case_is_idempotent_and_authenticated
    def headers(self, token: Optional[str] = None, idempotency_key: Optional[str] = None) -> Dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        tok = token if token is not None else self.token
        if tok:
            h["Authorization"] = f"Bearer {tok}"
        if idempotency_key:
            if not IDEMPOTENCY_KEY_RE.match(idempotency_key):
                raise AiSOCError("Idempotency-Key must be 8-128 chars of [A-Za-z0-9._:-]")
            h["Idempotency-Key"] = idempotency_key
        return h


# ── 【老師註解】AiSOCClient ───────────────────────────────────────
# 做什麼：AiSOC HTTP API 的薄包裝：送警報、串流 ingest、建立／查詢／決定審批單、下載證據包。
# 為什麼：所有和 AiSOC 的往來集中在一個類別，端點路徑一目了然；要對照 AiSOC 的 OpenAPI 文件時只需看這裡。
# 怎麼看：它「沒有」任何金鑰、不會簽任何東西——它只是傳聲筒。簽名發生在 AiSOCApprovalBridge（用 approver 金鑰）。
# 對應：準則 #1、#9
class AiSOCClient:
    def __init__(self, config: AiSOCConfig, http: Optional[HttpClient] = None) -> None:
        self.config = config
        self.http = http or UrllibHttpClient()

    # ── 【老師註解】AiSOCClient._call ──────────────────────────────
    # 做什麼：所有 API 呼叫的共同底層：組完整 URL、把 body 以 sort_keys 序列化、送出、狀態碼 ≥ 400 就拋 AiSOCError。
    # 怎麼看：path_or_url 可以是相對路徑（接在 base_url 後）或完整 URL（串流 ingest 在另一個埠）；**hdr 會原樣傳給 headers()。
    # 拿掉會怎樣：每個方法各自處理錯誤，就會有某個路徑忘了檢查狀態碼，把 401 的錯誤 JSON 當成成功結果往下傳。
    def _call(self, method: str, path_or_url: str, body: Optional[Dict[str, Any]] = None, **hdr: Any) -> Dict[str, Any]:
        url = path_or_url if path_or_url.startswith("http") else f"{self.config.base_url.rstrip('/')}{path_or_url}"
        data = json.dumps(body, sort_keys=True).encode("utf-8") if body is not None else None
        status, payload = self.http.request(method, url, self.config.headers(**hdr), data)
        # 任何 4xx／5xx 一律轉成例外，呼叫端只需 try/except AiSOCError
        if status >= 400:
            raise AiSOCError(f"{method} {url} -> {status}: {payload.get('detail', payload)}")
        return payload

    # ── 【老師註解】AiSOCClient.submit_alert ───────────────────────
    # 做什麼：POST /api/v1/alerts/submit——把一批事件連同標題、描述、嚴重度、標籤送成一則 AiSOC 警報。
    # 為什麼：這是「推案子到 SOC 平台」的標準路徑；帶 Idempotency-Key 時重送同一案不會重複建警報。
    # 怎麼看：欄位名（connector_id、source_format…）照 AiSOC 的 normalizer 規格，讓 AiSOC 能用通用 JSON 流程解析。
    # 對應：測試 tests/test_aisoc_stack.py::test_push_case_is_idempotent_and_authenticated
    def submit_alert(self, events: List[Dict[str, Any]], title: str, description: str, severity: str,
                     tags: Optional[List[str]] = None, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        body = {
            "events": events,
            "connector_id": self.config.connector_id,
            "connector_type": self.config.connector_type,
            "source_format": self.config.source_format,
            "title": title,
            "description": description,
            "severity": severity,
            "tags": tags or [],
        }
        return self._call("POST", "/api/v1/alerts/submit", body, idempotency_key=idempotency_key)

    # ── 【老師註解】AiSOCClient.ingest_batch ───────────────────────
    # 做什麼：POST 到串流 ingest 端點（通常是另一個埠的 /v1/ingest/batch），一次送一批事件。
    # 為什麼：高流量部署會走串流 ingest 而不是逐則 alerts/submit；token 可以和主 API 不同（ingest_token）。
    # 怎麼看：沒有設定 ingest_url 就直接拒絕（AiSOCError），不會偷偷退回 alerts/submit——部署者要明確選擇路徑。
    # 對應：測試 tests/test_aisoc_stack.py::test_streaming_ingest_path
    def ingest_batch(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not self.config.ingest_url:
            raise AiSOCError("ingest_url not configured")
        body = {"connector_id": self.config.connector_id, "connector_type": self.config.connector_type, "events": events}
        return self._call("POST", self.config.ingest_url, body, token=self.config.ingest_token or self.config.token)

    # ── 【老師註解】AiSOCClient.create_approval ────────────────────
    # 做什麼：POST /api/v1/approvals——在 AiSOC 的審批收件匣開一張單：標題、摘要（給人看的 ApprovalView）、風險等級、
    #         action 物件（內含 request_digest 等摘要）、關聯案子、到期時間。
    # 為什麼：這張單就是論文裡「保留動作等人簽」在 SOC 平台上的具體形態。action 裡放摘要，是為了稍後能核對 AiSOC 回傳的是同一件事。
    # 怎麼看：requested_by 固定寫 "agent"，誠實標示這是 Agent 發起的請求；title／case_id 截到 200 字以符合 AiSOC 欄位長度。
    # 對應：準則 #4；測試 tests/test_aisoc_stack.py::test_bridge_approved_decision_executes_and_records_external_ref
    def create_approval(self, title: str, summary: str, risk_level: str, action: Dict[str, Any],
                        case_id: Optional[str] = None, expires_at: Optional[str] = None) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "requested_by": "agent",
            "title": title[:200],
            "summary": summary,
            "risk_level": risk_level,
            "action": action,
        }
        if case_id:
            body["case_id"] = case_id[:200]
        if expires_at:
            body["expires_at"] = expires_at
        return self._call("POST", "/api/v1/approvals", body)

    # ── 【老師註解】AiSOCClient.get_approval ───────────────────────
    # 做什麼：GET /api/v1/approvals/{id}——讀一張審批單目前的狀態（pending／approved／denied…）與決定者、時間、評語。
    # 為什麼：橋接器靠輪詢這個端點等人決定。
    def get_approval(self, approval_id: str) -> Dict[str, Any]:
        return self._call("GET", f"/api/v1/approvals/{approval_id}")

    # ── 【老師註解】AiSOCClient.decide_approval ────────────────────
    # 做什麼：POST /api/v1/approvals/{id}/decide——「替分析師按下批准／拒絕」。
    # 怎麼看：AiSOCApprovalBridge 從來不呼叫這個方法——橋接器只能「問」不能「答」，否則就是自己批自己（違反一角色一鑰匙）。
    #         它存在是為了測試與操作工具（例如在 FakeAiSOCServer 上扮演分析師）。
    # 對應：準則 #9；測試 tests/test_aisoc_stack.py::test_fake_server_refuses_flipping_a_decision
    def decide_approval(self, approval_id: str, approve: bool, comment: str = "") -> Dict[str, Any]:
        return self._call("POST", f"/api/v1/approvals/{approval_id}/decide",
                          {"decision": "approve" if approve else "deny", "comment": comment})

    # ── 【老師註解】AiSOCClient.get_bundle ─────────────────────────
    # 做什麼：GET /api/v1/investigations/{run_id}/bundle——下載 AiSOC 的調查證據包（payload＋integrity）。
    # 怎麼看：拿到後要交給 verify_aisoc_bundle／anchor_aisoc_bundle，不要直接信任 integrity 欄位。
    def get_bundle(self, run_id: str) -> Dict[str, Any]:
        return self._call("GET", f"/api/v1/investigations/{run_id}/bundle")


# ----------------------------------------------------------------------------- alert mapping
# ── 【老師註解】case_to_event ─────────────────────────────────────
# 做什麼：一個 CaseResult → 一則 AiSOC 看得懂的事件：通用欄位（time、severity、title、host、src_ip、external_id、mitre_techniques、tags）
#         ＋ 自訂區塊 aisoc_owp（兩條分支的分數、人審旗標、驗證／接受狀態、被丟掉的出口訊息、帳本頭雜湊、見證根）。
# 為什麼：分析師在 AiSOC 看到警報時，要能直接對到帳本的確切位置（ledger_head、witness_root），離線核對。
# 怎麼看：這裡只放「摘要與結構化欄位」，刻意沒有 log_excerpt——不可信的原文不隨警報外流（有測試檢查整個事件 JSON 裡找不到它）。
#         severity 由案子狀態查表而來，不是由 Agent 自報的信心值決定。
# 拿掉會怎樣：若把原始日誌一併送出，提示注入文字就會出現在 SOC 平台上、被其他自動化（或人）再讀一次。
# 對應：準則 #7、#11；測試 tests/test_aisoc_stack.py::test_case_to_event_uses_generic_fields_and_embeds_ledger_anchors
def case_to_event(result: CaseResult, flow: FlowRecord, ledger_head: Optional[str] = None,
                  witness_root: Optional[str] = None, techniques: Optional[List[str]] = None) -> Dict[str, Any]:
    """One AiSOC-normalizable event per case. Only digests and structured fields; no raw log text."""
    d = result.decision
    status = d.status.value
    techniques = [t for t in (techniques or []) if isinstance(t, str)]
    ev = {
        "time": flow.observed_at or None,
        "severity": SEVERITY_BY_STATUS.get(status, "medium"),
        "title": f"[OWP-SOC] {status} on {flow.src_host}",
        "description": "; ".join(d.reasons)[:2000],
        "host": flow.src_host,
        "src_ip": flow.src_host,
        "dest_ip": flow.dst_ip,
        "dest_port": flow.dst_port,
        "external_id": result.case_id,
        "mitre_techniques": techniques,
        "tags": ["owp-soc", status.lower(), f"tenant:{flow.tenant}"] + (["requires-human-review"] if d.requires_human_review else []),
        "aisoc_owp": {
            "case_id": result.case_id,
            "flow_id": result.flow_id,
            "model_version": d.model_version,
            "known_label": d.known_label,
            "known_score": d.known_score,
            "anomaly_score": d.anomaly_score,
            "anomaly_threshold": d.anomaly_threshold,
            "requires_human_review": d.requires_human_review,
            "verification_status": result.verification_status,
            "acceptance_status": result.acceptance_status,
            "egress_dropped": list(result.egress_dropped),
            "requests": [r.__dict__ for r in result.requests],
            "ledger_head": ledger_head,
            "witness_root": witness_root,
        },
    }
    return {k: v for k, v in ev.items() if v is not None}


# ── 【老師註解】idempotency_key_for ───────────────────────────────
# 做什麼：由 case_id 衍生固定的 Idempotency-Key（"owp:<case_id>"）。
# 為什麼：同一個案子不管重送幾次，AiSOC 都只會有一則警報；鍵值由案子決定而不是隨機產生，重跑 CLI 也能去重。
def idempotency_key_for(result: CaseResult) -> str:
    return f"owp:{result.case_id}"[:128]


# ── 【老師註解】ledger_anchors ────────────────────────────────────
# 做什麼：取目前帳本「最後一筆的雜湊」與「最後一個已見證檢查點的 Merkle 根」。
# 為什麼：這兩個值放進警報後，任何人都能離線問：這個案子是不是在這個已見證的帳本狀態之內？
# 怎麼看：帳本空或還沒有檢查點時回 None，不會編造；事件裡的欄位會被 case_to_event 的過濾拿掉。
# 對應：準則 #7、#8
def ledger_anchors(soc: AISOC) -> Tuple[Optional[str], Optional[str]]:
    head = soc.ledger.entries[-1].entry_hash if soc.ledger.entries else None
    cps = soc.witness.checkpoints()
    root = cps[-1]["payload"]["merkle_root"] if cps else None
    return head, root


# ── 【老師註解】push_case ─────────────────────────────────────────
# 做什麼：把一個案子推到 AiSOC：先取帳本錨點，做成事件，再依 streaming 旗標走串流 ingest 或 alerts/submit（帶 Idempotency-Key）。
# 為什麼：這是程式內「推一案」的標準入口；CLI 的 aisoc-push 是它的離線檔案版（從 slips-summary.json 重建事件）。
# 對應：測試 tests/test_aisoc_stack.py::test_push_case_is_idempotent_and_authenticated、::test_streaming_ingest_path
def push_case(client: AiSOCClient, soc: AISOC, result: CaseResult, flow: FlowRecord, streaming: bool = False) -> Dict[str, Any]:
    head, root = ledger_anchors(soc)
    event = case_to_event(result, flow, head, root)
    if streaming:
        return client.ingest_batch([event])
    return client.submit_alert([event], event["title"], event["description"], event["severity"], event["tags"],
                               idempotency_key=idempotency_key_for(result))


# ----------------------------------------------------------------------------- approval bridge
# ── 【老師註解】APPROVED / DENIED / RISK_BY_ACTION ─────────────────
# 做什麼：AiSOC 審批狀態字串的「同義詞集合」，以及動作 → 風險等級的對照（送單時顯示給分析師）。
# 怎麼看：AiSOC 文件沒有明確定義狀態字串，所以這裡同時接受 approve／approved、deny／denied／reject／rejected（寬鬆解析，見 INTEGRATION.md §4）。
#         不在這兩個集合的狀態（例如 pending）一律視為「還沒決定」，繼續等——絕不會被當成批准。
APPROVED = {"approve", "approved"}
DENIED = {"deny", "denied", "rejected", "reject"}
RISK_BY_ACTION = {"egress_connect": "critical", "block_host": "high", "add_watchlist": "low", "tag_case": "low"}


# ── 【老師註解】AiSOCApprovalBridge ───────────────────────────────
# 做什麼：實作 SOC 的 ApprovalProvider 介面：當政策引擎把一個動作標成「保留」（要人批），它負責把審批單送進 AiSOC 收件匣、
#         等人決定、再把結果簽成 HumanApproval 交還給授權簽名器。用 soc.set_approval_provider(bridge) 掛上。
# 為什麼：人工審批是論文的核心閘門，但分析師在 SOC 平台工作，所以把閘門搬到他們眼前；同時信任鏈不能因此出現「未簽名」的縫隙。
# 怎麼看：它持有 approver 角色的金鑰（不是 authorizer、不是 executor），只能產生 HumanApproval，不能產生授權信封或收據。
#         sleep／wait_clock 可注入，測試才能把「等 15 分鐘」壓縮成幾個迴圈。
#         誠實聲明：簽的是橋接器的金鑰，approver_id 寫 "aisoc:<使用者>"——「那個使用者真的是誰」要靠 AiSOC 自己的稽核日誌。
# 拿掉會怎樣：只能用本地 stub 審批者，或讓分析師在兩套系統間手動抄摘要——後者幾乎保證有人會跳過核對。
# 對應：準則 #4、#9、#13；測試 tests/test_aisoc_stack.py::test_bridge_approved_decision_executes_and_records_external_ref
class AiSOCApprovalBridge:
    """Implements :data:`aisoc.soc.ApprovalProvider` on top of AiSOC's approval inbox.

    Fail-closed: a timeout, an expired approval, an unknown status or a transport
    error becomes a signed *reject* so the authorization signer never sees an
    unsigned or ambiguous decision.
    """

    def __init__(self, client: AiSOCClient, signer: Ed25519Signer, clock: Clock, approver_prefix: str = "aisoc",
                 sleep: Callable[[float], None] = time.sleep, wait_clock: Callable[[], float] = time.monotonic) -> None:
        self.client = client
        self.signer = signer
        self.clock = clock
        self.approver_prefix = approver_prefix
        self._sleep = sleep
        self._wait_clock = wait_clock
        self.created: List[Dict[str, Any]] = []

    # ── 【老師註解】AiSOCApprovalBridge._sign ──────────────────────
    # 做什麼：組一份 HumanApproval 並用 approver 金鑰簽名。所有出路（批准或各種拒絕）最後都走這裡。
    # 為什麼：簽名要「綁定」四個摘要——request_digest（這個請求）、evidence_digest（凍結的證據範圍）、params_digest（參數）、
    #         policy_decision_digest（政策結論）。之後 PEP 比對這些摘要，參數被偷改就對不上。
    # 怎麼看：decision 只有 "approve"／"reject" 兩值；external_ref 記 AiSOC 的審批單 id、決定者、時間，把兩套系統縫起來。
    # 拿掉會怎樣：若只簽「批准」兩個字而不綁摘要，攻擊者可以拿一張批准單去執行另一個請求。
    # 對應：準則 #4；測試 tests/test_policy_pep.py::test_pep_happy_path_then_replay_and_tamper（綁定在 PEP 端被驗）
    def _sign(self, req: ActionRequest, order: WorkOrder, pd: PolicyDecision, approve: bool, approver_id: str,
              rationale: str, external_ref: Dict[str, Any], expires_at: str) -> Signed:
        now = self.clock.now()
        approval = HumanApproval(
            approval_id=new_id("hap"),
            case_id=req.case_id,
            request_digest=req.digest(),
            evidence_digest=order.evidence_digest,
            params_digest=digest(req.params),
            policy_decision_digest=pd.digest(),
            decision="approve" if approve else "reject",
            approver_id=approver_id,
            rationale=rationale,
            issued_at=utc_iso(now),
            expires_at=expires_at,
            external_ref=external_ref,
        )
        payload = approval.to_dict()
        return Signed(payload=payload, signatures=[self.signer.sign_payload(payload)])

    # ── 【老師註解】AiSOCApprovalBridge.__call__ ───────────────────
    # 做什麼：一次完整的審批流程：建單 → 輪詢等決定 → 核對回顯的 request_digest → 檢查到期 → 簽成 HumanApproval。
    # 為什麼：這是「保留動作必須人簽」在外部系統上的落實；每一條出路都要產出「有簽名」的結果，沒有「不知道」。
    # 怎麼看：六條出路，只有最後一條可能是批准——
    #         ① 建單失敗（網路／401）→ 簽名拒絕「approval inbox unavailable」；
    #         ② 等到逾時還是 pending → 簽名拒絕「no decision before timeout」；
    #         ③ 輪詢途中出錯 → 簽名拒絕「approval poll failed」；
    #         ④ AiSOC 回傳的 action.request_digest 和我們送出的不同 → 簽名拒絕「about a different request」（防止拿別張批准單來用）；
    #         ⑤ 審批單已過期（取本地 TTL 與 AiSOC expires_at 較早者）→ 簽名拒絕「expired before use」；
    #         ⑥ 狀態在 APPROVED → 簽名批准；在 DENIED → 簽名拒絕；approver_id 都是 "aisoc:<決定者>"。
    #         注意 ④ 容忍 request_digest 為 None（AiSOC 可能不回顯 action）；若真實 AiSOC 不回顯，這道檢查就不生效——這是寬鬆解析的代價。
    # 拿掉會怎樣：若逾時回傳未簽名的 None，下游可能把「沒人回答」誤當成「沒人反對」；若不核對回顯摘要，
    #         一張對無害動作的批准可能被貼到高風險請求上。
    # 對應：準則 #2、#4、#6；測試 tests/test_aisoc_stack.py::test_bridge_denied_or_undecided_is_signed_reject、
    #       ::test_bridge_transport_failure_fails_closed、::test_bridge_rejects_record_about_a_different_request、
    #       ::test_bridge_expired_aisoc_record_is_rejected
    def __call__(self, view: ApprovalView, req: ActionRequest, order: WorkOrder, pd: PolicyDecision) -> Signed:
        cfg = self.client.config
        now = self.clock.now()
        local_exp = now + timedelta(seconds=cfg.approval_ttl_s)
        # 給人看的摘要（ApprovalView：支持與缺失的證據、注入旗標、影響、可逆性）與要被核對的 action 物件
        summary = json.dumps(view.to_dict(), sort_keys=True, default=str)
        action = {
            "type": req.action,
            "resource": req.resource,
            "destination": req.destination,
            "params": req.params,
            "request_digest": req.digest(),
            "policy_decision_digest": pd.digest(),
            "evidence_digest": order.evidence_digest,
            "case_id": req.case_id,
        }
        ext: Dict[str, Any] = {"system": AISOC_SYSTEM}
        # 出路 ①：建單失敗 → 簽名拒絕（fail-closed）
        try:
            created = self.client.create_approval(
                title=f"{req.action} {req.resource} (case {req.case_id})",
                summary=summary,
                risk_level=RISK_BY_ACTION.get(req.action, "medium"),
                action=action,
                case_id=req.case_id,
                expires_at=utc_iso(local_exp),
            )
        except AiSOCError as exc:
            return self._sign(req, order, pd, False, f"{self.approver_prefix}:bridge", f"approval inbox unavailable: {exc}", ext, utc_iso(local_exp))
        self.created.append(created)
        approval_id = str(created.get("id", ""))
        ext["approval_id"] = approval_id
        deadline = self._wait_clock() + cfg.approval_timeout_s
        record = created
        # 輪詢：直到狀態落在 APPROVED／DENIED，或逾時（出路 ②），或查詢出錯（出路 ③）
        while True:
            status = str(record.get("status", "")).lower()
            if status in APPROVED or status in DENIED:
                break
            if self._wait_clock() >= deadline:
                return self._sign(req, order, pd, False, f"{self.approver_prefix}:bridge", "no decision before timeout", ext, utc_iso(local_exp))
            self._sleep(cfg.approval_poll_s)
            try:
                record = self.client.get_approval(approval_id)
            except AiSOCError as exc:
                return self._sign(req, order, pd, False, f"{self.approver_prefix}:bridge", f"approval poll failed: {exc}", ext, utc_iso(local_exp))

        ext.update({"status": record.get("status"), "decided_by_id": record.get("decided_by_id"),
                    "decided_at": record.get("decided_at"), "comment": record.get("decision_comment")})
        # The decision must be about *this* request: AiSOC echoes the action object back.
        # 出路 ④：回顯的 request_digest 若存在且不等於我們送出的 → 這張單不是在講這個請求
        echoed = record.get("action") or {}
        if echoed.get("request_digest") not in (None, req.digest()):
            return self._sign(req, order, pd, False, f"{self.approver_prefix}:bridge", "approval record is about a different request", ext, utc_iso(local_exp))
        # 出路 ⑤：到期時間取「本地 TTL」與「AiSOC 回傳 expires_at」較早者；已過期就拒絕
        exp = local_exp
        if record.get("expires_at"):
            try:
                exp = min(exp, parse_iso(str(record["expires_at"])))
            except ValueError:
                pass
        if exp <= self.clock.now():
            return self._sign(req, order, pd, False, f"{self.approver_prefix}:bridge", "approval expired before use", ext, utc_iso(exp))
        # 出路 ⑥：依狀態簽批准或拒絕；approver_id 記 AiSOC 的決定者
        approve = status in APPROVED
        who = record.get("decided_by_id") or "unknown"
        return self._sign(req, order, pd, approve, f"{self.approver_prefix}:{who}",
                          str(record.get("decision_comment") or f"decided in AiSOC inbox ({status})"), ext, utc_iso(exp))


# ----------------------------------------------------------------------------- evidence bundles
# ── 【老師註解】aisoc_canonical_bytes ─────────────────────────────
# 做什麼：以 AiSOC 自己的規則把 payload 變成唯一位元組：鍵排序、無空白分隔、ensure_ascii=False。
# 為什麼：雜湊與 HMAC 都是對「位元組」算的；若我們的序列化和 AiSOC 差一個空格，重算出來的值就永遠對不上。
# 怎麼看：這和本專案自己的 canonical（RFC 8785 子集）是「兩套」規範化——對 AiSOC 的東西用 AiSOC 的規則，對帳本用我們的。
# 對應：測試 tests/test_aisoc_stack.py::test_canonical_form_matches_aisoc_json_dumps_rules
def aisoc_canonical_bytes(payload: Dict[str, Any]) -> bytes:
    """AiSOC's canonical form (json.dumps sort_keys, compact separators, ensure_ascii=False)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ── 【老師註解】aisoc_sign_envelope ───────────────────────────────
# 做什麼：用給定的對稱金鑰，替一個 payload 做出 AiSOC 格式的 {"payload", "integrity"} 證據包（測試夾具與情境用）。
# 為什麼：我們能在這裡「製造」合法證據包，本身就說明了 HMAC 的侷限——任何持鑰者都能造，所以它不是不可否認的簽名。
# 對應：準則 #7；情境 scenario_aisoc_bundle_anchor
def aisoc_sign_envelope(payload: Dict[str, Any], signing_key: str) -> Dict[str, Any]:
    """Build an AiSOC-compatible ``{"payload","integrity"}`` bundle (used to create test fixtures)."""
    canonical = aisoc_canonical_bytes(payload)
    sha = hashlib.sha256(canonical).hexdigest()
    sig = hmac.new(signing_key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    return {
        "payload": payload,
        "integrity": {
            "algorithm": "HMAC-SHA256",
            "algorithm_note": "HMAC gives tamper-evidence to key holders only; it is not a non-repudiable signature.",
            "payload_sha256": sha,
            "signature": sig,
            "attestation_list": [{
                "fingerprint": {"algorithm": "SHA-256", "algorithm_id": 3, "value": sha},
                "signatures": [{"algorithm": "HMAC-SHA256", "algorithm_id": 99}],
            }],
        },
    }


# ── 【老師註解】BundleCheck ───────────────────────────────────────
# 做什麼：verify_aisoc_bundle 的結果單：run id、案子 id、我們重算的 payload_sha256、sha256 對不對、有沒有檢查 HMAC、HMAC 對不對、問題清單。
# 怎麼看：ok 的定義是「sha256 正確 且 HMAC 不是 False 且 沒有問題」。注意 hmac_ok 是三值：None（沒給金鑰，沒檢查）／True／False。
#         沒檢查 ≠ 通過——anchor_aisoc_bundle 會把 hmac_sha256=False 老實寫進帳本，CLI 也會印出提醒。
# 對應：準則 #13
@dataclass
class BundleCheck:
    run_id: str
    case_id: Optional[str]
    payload_sha256: str
    sha256_ok: bool
    hmac_checked: bool
    hmac_ok: Optional[bool]
    problems: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.sha256_ok and (self.hmac_ok is not False) and not self.problems

    def to_dict(self) -> Dict[str, Any]:
        return {**self.__dict__, "ok": self.ok}


# ── 【老師註解】verify_aisoc_bundle ───────────────────────────────
# 做什麼：拿到 AiSOC 證據包後，「自己重算」它的完整性欄位：payload 的 sha256 一定重算；有給金鑰才重算 HMAC-SHA256 並比對。
# 為什麼：integrity 欄位是 AiSOC 寫的，不能因為它「寫著正確」就信。重算對得上，才表示 payload 自簽發後沒被動過。
# 怎麼看：HMAC 的意義要講清楚——它用的是「對稱」金鑰，伺服器和驗證者拿同一把；所以它能證明「持鑰者之外沒人改過」，
#         不能證明「是 AiSOC 伺服器而不是某個持鑰者做的」（沒有不可否認性）。這就是為什麼之後還要 anchor 進 Ed25519 帳本。
#         比對一律用 hmac.compare_digest（常數時間），避免用 == 洩漏「前幾個字元對了」的時間差。
#         形狀不對（缺 payload／integrity、不是物件）直接拋 AiSOCBundleError；內容問題（版本不支援、run.id 缺、雜湊不符）記進 problems。
# 拿掉會怎樣：直接相信 integrity 欄位，等於讓任何能改檔案的人同時改內容和「校驗碼」。
# 對應：準則 #7、#8；測試 tests/test_aisoc_stack.py::test_bundle_fixture_verifies_with_and_without_key、
#       ::test_tampered_bundle_detected_and_unsupported_shapes_raise
def verify_aisoc_bundle(bundle: Dict[str, Any], signing_key: Optional[str] = None) -> BundleCheck:
    """Re-derive AiSOC's own integrity fields. HMAC is only checked when a key is supplied."""
    # 步驟 1：形狀檢查——不是證據包就直接拒絕，不往下猜
    if not isinstance(bundle, dict) or "payload" not in bundle or "integrity" not in bundle:
        raise AiSOCBundleError("not an AiSOC bundle: expected top-level 'payload' and 'integrity'")
    payload, integrity = bundle["payload"], bundle["integrity"]
    if not isinstance(payload, dict) or not isinstance(integrity, dict):
        raise AiSOCBundleError("payload/integrity must be objects")
    problems: List[str] = []
    # 步驟 2：schema 版本與 run.id——只接受我們看得懂的版本
    if str(payload.get("bundle_schema_version", "")) != AISOC_BUNDLE_SCHEMA:
        problems.append(f"unsupported bundle_schema_version {payload.get('bundle_schema_version')!r}")
    run = payload.get("run") or {}
    run_id = str(run.get("id", "")) if isinstance(run, dict) else ""
    if not run_id:
        problems.append("payload.run.id missing")
    # 步驟 3：用 AiSOC 的規範化規則重算 sha256，和宣稱值做常數時間比對
    canonical = aisoc_canonical_bytes(payload)
    sha = hashlib.sha256(canonical).hexdigest()
    claimed = str(integrity.get("payload_sha256", ""))
    sha_ok = hmac.compare_digest(sha, claimed)
    if not sha_ok:
        problems.append("payload_sha256 does not match the payload")
    # 步驟 4：只有給了金鑰才驗 HMAC；演算法不是 HMAC-SHA256 也算失敗
    hmac_ok: Optional[bool] = None
    if signing_key is not None:
        if str(integrity.get("algorithm", "")).upper() != "HMAC-SHA256":
            problems.append(f"unexpected integrity algorithm {integrity.get('algorithm')!r}")
            hmac_ok = False
        else:
            expected = hmac.new(signing_key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
            hmac_ok = hmac.compare_digest(expected, str(integrity.get("signature", "")))
            if not hmac_ok:
                problems.append("HMAC-SHA256 signature does not verify under the supplied key")
    case_id = run.get("case_id") if isinstance(run, dict) else None
    return BundleCheck(run_id, str(case_id) if case_id else None, sha, sha_ok, signing_key is not None, hmac_ok, problems)


# ── 【老師註解】anchor_aisoc_bundle ───────────────────────────────
# 做什麼：先 verify_aisoc_bundle，通過才建一筆 ExternalEvidenceRef（系統、run id、案子、payload_sha256、整包摘要、檢查了哪些項目）
#         寫進帳本，並立刻做一個檢查點送外部見證。
# 為什麼：這一步把「AiSOC 的 HMAC 防竄改」升級成「Ed25519 簽名＋哈希鏈＋外部見證的承諾」——之後連 AiSOC 伺服器自己也改不了這包內容。
# 怎麼看：帳本裡存的是摘要，不是證據包本身（準則 #7）。integrity_checked 誠實記錄 hmac_sha256 是 True 還是 False（沒給金鑰就是 False）。
#         任何問題都拋 AiSOCBundleError 且「帳本不會多一筆」——情境會檢查「refused 且 ledger 沒長大」。
# 拿掉會怎樣：證據包只靠 HMAC 保護，持鑰者（包含伺服器管理員）可以事後改寫調查內容而無人能察覺。
# 對應：準則 #7、#8；測試 tests/test_aisoc_stack.py::test_anchor_commits_only_digests_and_refuses_bad_bundles、
#       ::test_anchor_without_key_records_that_hmac_was_not_checked
def anchor_aisoc_bundle(soc: AISOC, bundle: Dict[str, Any], case_id: str, signing_key: Optional[str] = None) -> ExternalEvidenceRef:
    """Verify an AiSOC bundle, then commit its digests to the OWP ledger. Refuses on any problem."""
    check = verify_aisoc_bundle(bundle, signing_key)
    # 驗證不過就拒絕，帳本不寫任何東西
    if not check.ok:
        raise AiSOCBundleError("; ".join(check.problems) or "bundle failed integrity check")
    ref = ExternalEvidenceRef(
        ref_id=new_id("xref"),
        case_id=case_id,
        system=AISOC_SYSTEM,
        kind="investigation_bundle",
        external_id=check.run_id,
        payload_sha256=check.payload_sha256,
        artefact_digest=digest(bundle),
        integrity_checked={"payload_sha256": True, "hmac_sha256": bool(check.hmac_ok), "bundle_schema_version": AISOC_BUNDLE_SCHEMA},
        anchored_at=soc.clock.iso(),
    )
    soc.anchor_external_evidence(ref)
    return ref


# ----------------------------------------------------------------------------- test double
# ── 【老師註解】FakeAiSOCServer ───────────────────────────────────
# 做什麼：一個「假的 AiSOC 伺服器」，實作 HttpClient 介面，把 HTTP 請求在記憶體裡模擬：alerts/submit（含 Idempotency-Key 去重）、
#         串流 ingest、建立／查詢／決定審批單。decide() 或 auto_decide 回呼扮演「按下批准／拒絕的分析師」。
# 為什麼：整套測試與情境都能在沒有網路、沒有 Docker、沒有真 AiSOC 的情況下跑；而且測試可以精準操控「分析師逾時不回」「伺服器回顯錯的摘要」。
# 怎麼看：它是依 AiSOC 的 OpenAPI 文件寫的「測試替身」，不是 AiSOC 本體，也不保證和真實產品行為一致（特別是狀態字串）。
#         和真伺服器一樣的地方刻意保留：沒帶正確 token 回 401；已決定的審批單不能翻案（409）；同一 Idempotency-Key 回同一個結果。
#         測試會把 fake.request 換成「竄改回應」的版本，來模擬回顯錯誤的 request_digest 或已過期的 expires_at。
# 拿掉會怎樣：審批橋接器的六條出路就只能靠真實 AiSOC 手動測，等於沒有回歸測試。
# 對應：準則 #13；測試 tests/test_aisoc_stack.py::test_fake_server_refuses_flipping_a_decision、::test_bridge_transport_failure_fails_closed
class FakeAiSOCServer:
    """In-memory stand-in for the AiSOC API, driven through :class:`HttpClient`.

    ``decide(approval_id, approve)`` or an ``auto_decide`` callback plays the analyst.
    """

    def __init__(self, auto_decide: Optional[Callable[[Dict[str, Any]], Optional[bool]]] = None, token: str = "t") -> None:
        self.auto_decide = auto_decide
        self.token = token
        self.alerts: List[Dict[str, Any]] = []
        self.ingested: List[Dict[str, Any]] = []
        self.approvals: Dict[str, Dict[str, Any]] = {}
        self.idempotency: Dict[str, Dict[str, Any]] = {}
        self.calls: List[Tuple[str, str]] = []
        self._n = 0

    def _id(self, prefix: str) -> str:
        self._n += 1
        return f"{prefix}-{self._n:04d}"

    # 扮演分析師：只能對 pending 的單做決定，已決定的單不能翻案（和真實 AiSOC 的 409 一致）
    def decide(self, approval_id: str, approve: bool, user_id: str = "user-7", comment: str = "ok") -> Dict[str, Any]:
        rec = self.approvals[approval_id]
        if rec["status"] != "pending":
            raise AiSOCError("409 already decided")
        rec.update({"status": "approved" if approve else "denied", "decided_by_id": user_id,
                    "decided_at": "2026-11-01T00:00:00Z", "decision_comment": comment})
        return rec

    def request(self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> Tuple[int, Dict[str, Any]]:
        self.calls.append((method, url))
        if headers.get("Authorization") != f"Bearer {self.token}":
            return 401, {"detail": "unauthorized"}
        data = json.loads(body) if body else {}
        path = url.split("//", 1)[-1].split("/", 1)[1] if "//" in url else url
        path = "/" + path
        # 路由 1：alerts/submit——同一個 Idempotency-Key 回同一個結果，不會建第二則警報
        if method == "POST" and path == "/api/v1/alerts/submit":
            key = headers.get("Idempotency-Key")
            if key and key in self.idempotency:
                return 200, self.idempotency[key]
            if not data.get("events"):
                return 422, {"detail": "events required"}
            resp = {"id": self._id("alert"), "tenant_id": "tenant-1", "title": data.get("title"), "severity": data.get("severity"),
                    "status": "new", "case_id": self._id("case"), "mitre_techniques": data["events"][0].get("mitre_techniques", []),
                    "affected_ips": [data["events"][0].get("src_ip")]}
            self.alerts.append({"request": data, "response": resp})
            if key:
                self.idempotency[key] = resp
            return 201, resp
        # 路由 2：串流 ingest——只是收下事件
        if method == "POST" and path.endswith("/v1/ingest/batch"):
            self.ingested.extend(data.get("events", []))
            return 202, {"accepted": len(data.get("events", []))}
        # 路由 3：建立審批單——狀態 pending；若有 auto_decide 回呼且它回 True/False，就立刻決定（回 None 代表「分析師還沒回」）
        if method == "POST" and path == "/api/v1/approvals":
            rec = {"id": self._id("appr"), "status": "pending", "decided_by_id": None, "decided_at": None,
                   "decision_comment": None, "expires_at": data.get("expires_at"), "action": data.get("action"),
                   "title": data.get("title"), "risk_level": data.get("risk_level"), "case_id": data.get("case_id")}
            self.approvals[rec["id"]] = rec
            if self.auto_decide is not None:
                verdict = self.auto_decide(rec)
                if verdict is not None:
                    self.decide(rec["id"], verdict)
            return 201, dict(rec)
        # 路由 4：查詢審批單（橋接器輪詢的就是這裡）；路由 5：決定審批單（測試用，橋接器不會呼叫）
        m = re.match(r"^/api/v1/approvals/([^/]+)$", path)
        if method == "GET" and m:
            rec = self.approvals.get(m.group(1))
            return (200, dict(rec)) if rec else (404, {"detail": "not found"})
        m = re.match(r"^/api/v1/approvals/([^/]+)/decide$", path)
        if method == "POST" and m:
            rec = self.approvals.get(m.group(1))
            if not rec:
                return 404, {"detail": "not found"}
            if rec["status"] != "pending":
                return 409, {"detail": "already decided"}
            self.decide(rec["id"], data.get("decision") == "approve", comment=data.get("comment", ""))
            return 200, dict(rec)
        return 404, {"detail": f"no route {method} {path}"}
