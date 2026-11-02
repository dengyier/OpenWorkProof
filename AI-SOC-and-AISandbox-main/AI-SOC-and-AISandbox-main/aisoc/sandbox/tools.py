"""Read-only investigation tools with an independent tool-side log.

The agent only ever receives ``Untrusted`` results. Every call is recorded in
``ToolSideLog`` which is *not* the ledger: it is the second, independent
record used for reconciliation (paper §VIII-D). Rate limits are per case so a
flood of alerts cannot exhaust shared resources.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..crypto import Clock
from ..idps import FlowRecord
from .untrusted import Untrusted, wrap


# ── 【老師註解】ToolError ────────────────────────────────────────
# 做什麼：工具層唯一的例外型別：查不到、不在租戶範圍、預算用完、工具名不存在，全部丟這個。
# 為什麼：agent 只需要知道「這次拿不到資料」，不需要（也不該）知道底層細節；資料缺失要被記成 missing_evidence，而不是被猜成「正常」。
# 對應：準則 #11；（此處無直接測試）
class ToolError(Exception):
    pass


# ── 【老師註解】ToolCallRecord ───────────────────────────────────
# 做什麼：一筆「工具被呼叫」的紀錄：哪個案件、哪個工具、什麼參數、成功與否、什麼時候、觸發了哪些旗標（rate_limited／unknown_tool／注入篩檢）。
# 為什麼：這是工具側（不是帳本側）留下的獨立足跡；事後可以回答「agent 到底查了什麼、被擋了幾次」。
# 怎麼看：flags 裡若有注入旗標，代表那次回傳的內容含有「像指令的文字」，人審時應優先看。
# 對應：準則 #7、#11；（此處無直接測試）
@dataclass
class ToolCallRecord:
    case_id: str
    tool: str
    args: Dict[str, Any]
    ok: bool
    at: str
    flags: List[str] = field(default_factory=list)


# ── 【老師註解】ToolSideLog ──────────────────────────────────────
# 做什麼：「第二本帳」。存兩種東西：(1) 每次工具呼叫的紀錄 calls；(2) 執行器簽過名的 ActionReceipt（receipts）。
# 為什麼：主帳本（OWP ledger）可能被繞過——例如有人直接呼叫執行器、不經 PEP 記帳。若只有一本帳，「沒記」就等於「沒發生」。
#         有了獨立的第二本帳，離線驗證器就能對賬：帳本有「執行」卻沒收據 ⇒ 帳本造假；有收據卻帳本沒「授權」⇒ 繞過（bypass）。
# 怎麼看：它刻意不做雜湊鏈、不簽名、不做任何「聰明」的事——它的價值在於「獨立」，和帳本由不同路徑寫入。
#         receipts 是由 PEP._receipt 寫進來的（pep.py），不是 agent；agent 根本碰不到這個物件的寫入面。
# 拿掉會怎樣：scenario_bypass 那種「直接打執行器」的攻擊就再也查不出來，驗證器會把帳本當成唯一真相。
# 對應：準則 #2、#7、#8；測試 tests/test_end_to_end.py::test_scenarios_behave_as_specified[scenario_bypass]、
#       tests/test_egress_release_grant.py::test_verifier_flags_action_request_without_egress_record
class ToolSideLog:
    def __init__(self) -> None:
        self.calls: List[ToolCallRecord] = []
        self.receipts: List[Any] = []  # Signed ActionReceipt objects from the executor

    # 工具呼叫足跡（由 ReadOnlyTools.call 寫入）
    def record_call(self, rec: ToolCallRecord) -> None:
        self.calls.append(rec)

    # 執行器簽名收據（由 PEP 寫入；驗證器拿這個清單和帳本對賬）
    def record_receipt(self, signed_receipt: Any) -> None:
        self.receipts.append(signed_receipt)


# ── 【老師註解】TelemetryStore ───────────────────────────────────
# 做什麼：唯讀工具背後的「假資料庫」：流量、主機行為視窗、登入紀錄、IOC 情報，全部放在記憶體 dict 裡。
# 為什麼：真實部署會接 SIEM／EDR／TI 平台；這裡用合成資料是為了可重現、可離線測試（準則 #13 的誠實範圍）。
# 怎麼看：host_windows 與 logins 的鍵是 "租戶/主機"，租戶隔離從「資料鍵」就開始做，不是靠查完再過濾。
# 對應：準則 #13；（此處無直接測試）
class TelemetryStore:
    """Synthetic backing store for the read-only tools."""

    def __init__(self) -> None:
        self.flows: Dict[str, FlowRecord] = {}
        self.host_windows: Dict[str, Dict[str, Any]] = {}
        self.logins: Dict[str, List[Dict[str, Any]]] = {}
        self.ioc: Dict[str, Dict[str, Any]] = {}

    def add_flow(self, f: FlowRecord) -> None:
        self.flows[f.flow_id] = f


# ── 【老師註解】ReadOnlyTools ────────────────────────────────────
# 做什麼：agent 能碰到的「全部能力」：四個唯讀查詢（流量、主機視窗、最近登入、IOC），每案有呼叫預算，
#         每次回傳都包成 Untrusted（含注入篩檢旗標），每次呼叫都寫進 ToolSideLog。
# 為什麼：沙箱的原則是「agent 能讀、不能寫、不能出網」；工具層就是這條界線的具體實作——這裡沒有任何會產生副作用的函式。
# 怎麼看：_registry 是封閉清單，agent 用字串點名工具，點不到就 ToolError；所有工具都強制帶 tenant，資料查詢在租戶範圍內進行。
#         預算是「每案」計，不是全域，所以一個案件狂查不會把別的案件的額度吃光。
# 拿掉會怎樣：若 agent 能直接拿到 TelemetryStore 或網路，Untrusted 包裝與租戶範圍都形同虛設。
# 對應：準則 #1、#11；測試 tests/test_end_to_end.py::test_happy_path_is_fully_recorded_and_verified（間接）
class ReadOnlyTools:
    def __init__(self, store: TelemetryStore, log: ToolSideLog, clock: Clock, max_calls_per_case: int = 20) -> None:
        self.store = store
        self.log = log
        self.clock = clock
        self.max_calls_per_case = max_calls_per_case
        self._calls: Dict[str, int] = {}
        self._registry: Dict[str, Callable[..., Any]] = {
            "get_flow": self._get_flow,
            "get_host_window": self._get_host_window,
            "get_recent_logins": self._get_recent_logins,
            "lookup_ioc": self._lookup_ioc,
        }

    @property
    def names(self) -> List[str]:
        return sorted(self._registry)

    # ── 【老師註解】ReadOnlyTools.call ──────────────────────────────
    # 做什麼：agent 呼叫工具的唯一入口。順序固定：查預算 → 查工具名 → 執行（帶 tenant）→ 包成 Untrusted → 記錄到 ToolSideLog → 回傳。
    # 為什麼：把「預算、租戶、包裝、記錄」集中在一個入口，agent 就沒有任何旁路可以拿到「沒包裝」或「沒記錄」的資料。
    # 怎麼看：預算用完、工具不存在、底層查不到，三種失敗都先寫紀錄再丟 ToolError——失敗也要留下足跡。
    #         wrap() 會跑注入篩檢（啟發式，不是安全邊界），旗標一起寫進紀錄，讓人審看得到。
    # 拿掉會怎樣：沒有預算 ⇒ 被挾持的 agent 可以用無限查詢拖垮共享資源；沒有 wrap ⇒ 日誌文字會以「乾淨資料」的身分進到 agent。
    # 對應：準則 #1、#11；（預算與 unknown_tool 分支此處無直接測試；包裝旗標見 tests/test_end_to_end.py::test_compromised_agent_cannot_cause_side_effects）
    def call(self, case_id: str, tenant: str, tool: str, **args: Any) -> Untrusted[Any]:
        n = self._calls.get(case_id, 0)
        # 步驟 1：每案呼叫預算（預設 20 次）；超過就記一筆 rate_limited 並拒絕
        if n >= self.max_calls_per_case:
            self.log.record_call(ToolCallRecord(case_id, tool, args, False, self.clock.iso(), ["rate_limited"]))
            raise ToolError("per-case tool budget exhausted")
        self._calls[case_id] = n + 1
        fn = self._registry.get(tool)
        # 步驟 2：工具名必須在封閉清單裡
        if fn is None:
            self.log.record_call(ToolCallRecord(case_id, tool, args, False, self.clock.iso(), ["unknown_tool"]))
            raise ToolError(f"unknown tool {tool}")
        # 步驟 3：真正執行——tenant 由呼叫端（工單）決定，agent 不能自己填
        try:
            result = fn(tenant=tenant, **args)
        except ToolError:
            self.log.record_call(ToolCallRecord(case_id, tool, args, False, self.clock.iso()))
            raise
        # 步驟 4：回傳前一律包成 Untrusted（含注入篩檢旗標），再把這次呼叫連同旗標寫進第二本帳
        wrapped = wrap(f"tool:{tool}", result)
        self.log.record_call(ToolCallRecord(case_id, tool, args, True, self.clock.iso(), wrapped.flags))
        return wrapped

    # --- tool implementations: tenant-scoped, read-only -------------------------------
    # ── 【老師註解】ReadOnlyTools._get_flow ─────────────────────────
    # 做什麼：依 flow_id 取一筆流量，但「不在同一租戶」就當作不存在（同一個錯誤訊息，不洩漏別租戶有沒有這筆資料）。
    # 為什麼：租戶隔離在資料層就要做；agent 拿到的工單屬於哪個租戶，就只能看那個租戶的資料。
    # 怎麼看：回傳欄位裡有 log_excerpt——這是「不可信文字」進入 agent 的唯一入口，也是注入攻擊的載體；
    #         守規矩的 agent 只看數字欄位，被挾持的 agent 會去讀它。
    # 拿掉會怎樣：少了 tenant 比對，跨租戶的資料就會流到別人的案件裡。
    # 對應：準則 #3、#11；（此處無直接測試，間接由 test_compromised_agent_cannot_cause_side_effects 覆蓋 log_excerpt 路徑）
    def _get_flow(self, tenant: str, flow_id: str) -> Dict[str, Any]:
        f = self.store.flows.get(flow_id)
        if f is None or f.tenant != tenant:
            raise ToolError("flow not found in tenant scope")
        return {
            "flow_id": f.flow_id, "src_host": f.src_host, "dst_ip": f.dst_ip, "dst_port": f.dst_port,
            "bytes_in": f.bytes_in, "bytes_out": f.bytes_out, "duration_s": f.duration_s,
            "conn_failures": f.conn_failures, "login_failures": f.login_failures,
            "distinct_dst_ports": f.distinct_dst_ports, "log_excerpt": f.log_excerpt,
        }

    # ── 【老師註解】ReadOnlyTools._get_host_window ──────────────────
    # 做什麼：取某主機在觀察視窗內的行為統計（例如 new_process_count）；鍵是 "租戶/主機"，查不到就 ToolError。
    # 為什麼：主機側證據是「第二路徑」，讓 agent 不會只憑一筆流量下結論；查不到時要誠實回報缺資料，而不是回空 dict 假裝正常。
    # 對應：準則 #11；（此處無直接測試）
    def _get_host_window(self, tenant: str, host: str) -> Dict[str, Any]:
        w = self.store.host_windows.get(f"{tenant}/{host}")
        if w is None:
            raise ToolError("no host window")
        return dict(w)

    # ── 【老師註解】ReadOnlyTools._get_recent_logins ────────────────
    # 做什麼：列出某主機最近的登入事件（同樣以 "租戶/主機" 為鍵）；沒有就回空清單。
    # 怎麼看：目前的 stub agent 沒有用到它，但它展示了工具清單可以擴充而不必改任何外層控制。
    # 對應：準則 #1；（此處無直接測試）
    def _get_recent_logins(self, tenant: str, host: str) -> Dict[str, Any]:
        return {"host": host, "logins": list(self.store.logins.get(f"{tenant}/{host}", []))}

    # ── 【老師註解】ReadOnlyTools._lookup_ioc ──────────────────────
    # 做什麼：查某指標（這裡是目的 IP）是否在威脅情報裡；沒命中就回 match=False。
    # 怎麼看：IOC 情報是跨租戶共用的（鍵沒有租戶前綴），因為情報本身不含租戶資料；但回傳仍會經過 Untrusted 包裝。
    #         情境測試會用 _seed_ioc 塞一筆命中，讓 HeuristicStubAgent 的分數跨過 block_host 門檻。
    # 對應：準則 #11；（此處無直接測試）
    def _lookup_ioc(self, tenant: str, indicator: str) -> Dict[str, Any]:
        return dict(self.store.ioc.get(indicator, {"indicator": indicator, "match": False}))
