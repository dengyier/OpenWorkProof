"""Slips (Stratosphere Linux IPS) as the AI-IDPS front end.

Slips (https://github.com/stratosphereips/StratosphereLinuxIPS) is a
behaviour-based IDS/IPS with heuristic, threat-intelligence and machine
learning detection modules. It writes every piece of *evidence* and every
*alert* to ``<output>/alerts.json`` as one IDMEFv2 message per line (Slips
>= 1.1, ``Version: 2.D.V03``).

This adapter reads that file (and optionally the Zeek ``conn.log`` Slips keeps
next to it) and maps Slips output onto the paper's dual_model branches:

* **known branch** — evidence types that name a concrete attack behaviour
  (port scans, password guessing, C&C, data upload, TI hits, ...) become an
  :class:`~aisoc.idps.ExternalKnown` verdict with a family label and, where
  the mapping is unambiguous, an ATT&CK technique id;
* **normality branch** — Slips' ML/anomaly modules (``ANOMALOUS_FLOW``,
  ``ML_*_MALICIOUS_FLOW``, ``MALICIOUS_FLOW``) are "something is wrong but it
  is not a named class" signals and become an
  :class:`~aisoc.idps.ExternalAnomaly`;
* everything else (young domains, unknown ports, long connections, ...) is a
  weak indicator: the known branch *rejects* it, so without an anomaly signal
  the case is ``UNKNOWN`` and goes to a human. Missing data is never normal.

Evidence lines are grouped per Slips profile and time window (``Source IP`` +
``Note.timewindow``), the same unit Slips uses to raise an alert. The free
text ``Description`` is kept only as *untrusted* ``log_excerpt``.

Slips is GPL-2.0; this module consumes its output files and contains no
Slips code. Scores produced here are Slips' own confidence values, which are
**not** calibrated probabilities in the sense of paper §V; ``tau_k`` for this
branch therefore defaults to 0.5 and must be tuned per deployment.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

from ..canonical import digest
from ..idps import ExternalAnomaly, ExternalKnown, FlowRecord
from ..soc import AISOC, CaseResult

# ── 【老師註解】aisoc/adapters/slips.py（模組總覽）────────────────
# 做什麼：把 Slips（Stratosphere Linux IPS，一套開源的行為式入侵偵測系統）寫出來的檔案，翻譯成論文裡
#         dual_model 的兩條分支：「已知分支」（ExternalKnown）和「異常分支」（ExternalAnomaly）。
# 為什麼：論文的架構不應該綁死在我們自己訓練的合成模型上；換成真正的偵測器時，後面的沙箱、PEP、帳本都不用改。
# 怎麼看：Slips 在自己的容器裡跑，我們只「讀它寫出的檔案」（alerts.json 是 IDMEFv2 格式、conn.log 是 Zeek 流量摘要），
#         不 import、不連結任何 Slips 程式碼（Slips 是 GPL-2.0，這樣授權邊界才乾淨）。
#         信任分級要記牢：結構化欄位（evidence_type、Confidence、threat_level、IP、port、uids）當作「Slips 的主張」來用；
#         自由文字 Description 一律不可信，只能包成 Untrusted 的 log_excerpt 給人看，絕不拿來做判斷。
#         資料缺了（例如 conn.log 沒有對應行）就填 None，讓後面判成 UNKNOWN，而不是猜一個數字。
# 拿掉會怎樣：沒有這一層，真實偵測器的自由文字就會直接流進 Agent 的判斷，等於把提示注入的門打開。
# 對應：準則 #11、#12、#13；docs/INTEGRATION.md §1
SLIPS_SOURCE = "slips"
IDMEF_EVENT = "Event"        # one Slips evidence
IDMEF_INCIDENT = "Incident"  # one Slips alert (accumulated evidence over a time window)

THREAT_LEVEL_WEIGHT: Dict[str, float] = {"info": 0.0, "low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}

# Slips EvidenceType -> (family label for the known branch, ATT&CK technique or None).
# Only behaviours that name a concrete attack class are listed; the rest are weak indicators.
# ── 【老師註解】KNOWN_FAMILY_MAP ──────────────────────────────────
# 做什麼：查表。Slips 的 evidence_type（例如 PASSWORD_GUESSING）→（家族標籤 bruteforce，ATT&CK 技術 T1110）。
# 為什麼：論文的「已知分支」要回答的是「這是哪一類已知攻擊？」。只有能明確指名攻擊行為的類型才列進來；
#         像 YOUNG_DOMAIN、UNKNOWN_PORT 這類「有點可疑但說不出是什麼」的弱指標故意不列，讓已知分支「拒絕」它們。
# 怎麼看：technique 可以是 None（例如威脅情報黑名單命中，知道壞但不知道手法）；後面取技術時會回退到同組其他證據。
#         這張表是人手整理的對照，不是 Slips 官方提供的；新增 Slips 類型時要在這裡決定它屬於哪一類或留作弱指標。
# 拿掉會怎樣：所有 Slips 證據都變成 unclassified → 全部 UNKNOWN，Agent 永遠不會被派去調查任何已知攻擊。
# 對應：準則 #12；測試 tests/test_slips_adapter.py::test_known_family_map_and_anomaly_types_are_disjoint
KNOWN_FAMILY_MAP: Dict[str, Tuple[str, Optional[str]]] = {
    "HORIZONTAL_PORT_SCAN": ("port_scan", "T1046"),
    "VERTICAL_PORT_SCAN": ("port_scan", "T1046"),
    "DHCP_SCAN": ("port_scan", "T1046"),
    "GRE_SCAN": ("port_scan", "T1046"),
    "ARP_SCAN": ("recon", "T1018"),
    "DNS_ARPA_SCAN": ("recon", "T1018"),
    "ICMP_TIMESTAMP_SCAN": ("recon", "T1018"),
    "ICMP_ADDRESS_SCAN": ("recon", "T1018"),
    "ICMP_ADDRESS_MASK_SCAN": ("recon", "T1018"),
    "PASSWORD_GUESSING": ("bruteforce", "T1110"),
    "SMTP_LOGIN_BRUTEFORCE": ("bruteforce", "T1110"),
    "DATA_UPLOAD": ("exfiltration", "T1041"),
    "COMMAND_AND_CONTROL_CHANNEL": ("c2", "T1071"),
    "DGA_NXDOMAINS": ("c2", "T1568.002"),
    "HIGH_ENTROPY_DNS_ANSWER": ("c2", "T1071.004"),
    "MALICIOUS_JA3": ("c2", "T1573"),
    "MALICIOUS_JA3S": ("c2", "T1573"),
    "MALICIOUS_JARM": ("c2", "T1573"),
    "MALICIOUS_SSL_CERT": ("c2", "T1573"),
    "TOR_EXIT_NODE": ("c2", "T1090.003"),
    "MALICIOUS_DOWNLOADED_FILE": ("malware_download", "T1105"),
    "EXECUTABLE_MIME_TYPE": ("malware_download", "T1105"),
    "PASTEBIN_DOWNLOAD": ("malware_download", "T1102"),
    "MITM_ARP_ATTACK": ("mitm", "T1557.002"),
    "GRE_TUNNEL": ("tunnel", "T1572"),
    "THREAT_INTELLIGENCE_BLACKLISTED_ASN": ("threat_intel", None),
    "THREAT_INTELLIGENCE_FROM_BLACKLISTED_IP": ("threat_intel", None),
    "THREAT_INTELLIGENCE_TO_BLACKLISTED_IP": ("threat_intel", None),
    "THREAT_INTELLIGENCE_BLACKLISTED_DNS_ANSWER": ("threat_intel", None),
    "THREAT_INTELLIGENCE_BLACKLISTED_DOMAIN": ("threat_intel", None),
    "THREAT_INTELLIGENCE_ANSWER_OF_BLACKLISTED_QUERY": ("threat_intel", None),
    "THREAT_INTELLIGENCE_MALICIOUS_URL": ("threat_intel", None),
    "MALICIOUS_IP_FROM_P2P_NETWORK": ("threat_intel", None),
}

# Evidence produced by Slips' learned/anomaly detectors: no named class, "unlike normal".
# ── 【老師註解】ANOMALY_TYPES ─────────────────────────────────────
# 做什麼：Slips 的機器學習／流量異常模組產生的證據類型。它們只說「這不像正常」，不指名是哪種攻擊。
# 為什麼：這正好對應論文的「異常分支」。已知分支拒絕 且 異常分支說高 ⇒ SUSPECTED_UNKNOWN（疑似零日）⇒ 必須人審。
# 怎麼看：這個集合和 KNOWN_FAMILY_MAP 必須互斥（有測試保證），否則同一筆證據會同時餵兩條分支，判定表就失去意義。
# 對應：準則 #12；測試 tests/test_slips_adapter.py::test_known_family_map_and_anomaly_types_are_disjoint
ANOMALY_TYPES: Set[str] = {"ANOMALOUS_FLOW", "MALICIOUS_FLOW", "ML_LINEAR_MALICIOUS_FLOW", "ML_ONLINE_MALICIOUS_FLOW"}

UNCLASSIFIED = "unclassified"
_FAILED_CONN_STATES = {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"}


# ── 【老師註解】_enum_name ────────────────────────────────────────
# 做什麼：把 Slips 寫法不一的列舉值統一成大寫名字："EvidenceType.PASSWORD_GUESSING"、"password_guessing" 都變 PASSWORD_GUESSING。
# 為什麼：Slips 不同版本把 enum 序列化的方式不同；若不先統一，查 KNOWN_FAMILY_MAP 時會因為大小寫或前綴而查不到。
# 拿掉會怎樣：同一種攻擊在某些版本被辨識、在另一些版本變成「弱指標」，判定結果會隨 Slips 版本飄移。
# 對應：測試 tests/test_slips_adapter.py::test_enum_string_forms_and_threat_levels_are_normalised
def _enum_name(value: Any) -> str:
    """'EvidenceType.PASSWORD_GUESSING' | 'password_guessing' | 'ThreatLevel.HIGH' -> upper name."""
    s = str(value).strip()
    if "." in s:
        s = s.rsplit(".", 1)[1]
    return s.upper()


# ── 【老師註解】threat_level_weight ───────────────────────────────
# 做什麼：把 Slips 的威脅等級（info/low/medium/high/critical 或直接是數字）換成 0～1 的權重。
# 為什麼：已知分支除了看信心值，還要看「Slips 自己覺得多嚴重」；info/low 的證據權重 ≤ 0.2，不足以單獨成立一個已知類別。
# 怎麼看：看不懂的字串一律回 0.0（最低權重），也就是「不認得就當不夠嚴重」，而不是猜一個中間值。
# 對應：準則 #11；測試 tests/test_slips_adapter.py::test_enum_string_forms_and_threat_levels_are_normalised
def threat_level_weight(value: Any) -> float:
    if isinstance(value, (int, float)):
        return max(0.0, min(1.0, float(value)))
    return THREAT_LEVEL_WEIGHT.get(_enum_name(value).lower(), 0.0)


# ── 【老師註解】SlipsEvidence ─────────────────────────────────────
# 做什麼：一條 Slips「證據」（IDMEFv2 的 Status: Event）解析後的結構化版本——誰（source_ip）、對誰（target_ip、dst_port）、
#         哪個模組、什麼類型、多嚴重（threat_level）、多有把握（confidence）、對應哪些 Zeek 連線（uids）。
# 為什麼：之後所有判斷只看這些「欄位」。description 雖然也存著，但它只是給人看的原文，不會進任何 if 判斷。
# 怎麼看：family／technique／is_anomaly_signal 三個屬性就是查表結果——這筆證據走「已知分支」還是「異常分支」，或兩者皆非（弱指標）。
#         raw 保留整筆原始 JSON，稍後會被整組做摘要寫進帳本，讓判定能回溯到「Slips 當時到底吐了什麼」。
# 對應：準則 #11；測試 tests/test_slips_adapter.py::test_parse_fixture_events_incidents_and_malformed_lines
@dataclass
class SlipsEvidence:
    """One Slips evidence line (IDMEFv2 ``Status: Event``)."""

    id: str
    evidence_type: str
    source_module: str
    threat_level: float
    confidence: float
    description: str
    source_ip: str
    source_kind: str  # IP | Hostname | URL
    target_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    proto: Optional[str]
    timewindow: Optional[int]
    uids: List[str]
    start_time: str
    slips_version: str
    priority: str
    ti_sources: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    # ── 【老師註解】SlipsEvidence.family / technique / is_anomaly_signal
    # 做什麼：三個查表屬性。family／technique 查 KNOWN_FAMILY_MAP（查不到都是 None）；is_anomaly_signal 查 ANOMALY_TYPES。
    # 怎麼看：一條證據最多只會走一條分支：有 family 的走已知分支，在 ANOMALY_TYPES 的走異常分支，兩者皆否就是弱指標。
    @property
    def family(self) -> Optional[str]:
        m = KNOWN_FAMILY_MAP.get(self.evidence_type)
        return m[0] if m else None

    @property
    def technique(self) -> Optional[str]:
        m = KNOWN_FAMILY_MAP.get(self.evidence_type)
        return m[1] if m else None

    @property
    def is_anomaly_signal(self) -> bool:
        return self.evidence_type in ANOMALY_TYPES


# ── 【老師註解】SlipsIncident ─────────────────────────────────────
# 做什麼：一條 Slips「警報」（Status: Incident）：某個來源 IP 在某個時間窗累積的威脅分數超過門檻時 Slips 才會發。
#         correl_ids 列出它是由哪幾條證據累積而成。
# 為什麼：我們不用 Slips 的警報來做判定（判定看證據本身），但把它一起附進 source_record，方便分析師對照 Slips 的原始結論。
# 對應：測試 tests/test_slips_adapter.py::test_parse_fixture_events_incidents_and_malformed_lines
@dataclass
class SlipsIncident:
    """One Slips alert (IDMEFv2 ``Status: Incident``)."""

    id: str
    source_ip: str
    correl_ids: List[str]
    accumulated_threat_level: Optional[float]
    timewindow: Optional[int]
    start_time: str
    end_time: Optional[str]
    raw: Dict[str, Any] = field(default_factory=dict)


# ── 【老師註解】SlipsParseResult ──────────────────────────────────
# 做什麼：整個 alerts.json 讀完後的統計容器：證據列表、警報列表、壞掉的行數（malformed）、看到過哪些 Slips 版本。
# 為什麼：malformed 要「數出來並寫進摘要」而不是默默丟掉——資料缺了多少，審核的人有權知道（準則 #11、#13）。
@dataclass
class SlipsParseResult:
    evidence: List[SlipsEvidence] = field(default_factory=list)
    incidents: List[SlipsIncident] = field(default_factory=list)
    malformed: int = 0
    slips_versions: Set[str] = field(default_factory=set)


# ── 【老師註解】_first_endpoint ───────────────────────────────────
# 做什麼：IDMEFv2 的 Source／Target 是「列表」；這裡只取第一個端點，依序找 IP → Hostname → URL，再取第一個 Port、第一個 Protocol、TI 來源。
# 為什麼：Slips 實際上每條證據只寫一個端點；寫成防禦式解析是因為格式不對（不是列表、空列表、Port 不是數字）時要安全地回「不知道」。
# 怎麼看：回傳的五元組裡任何一格都可能是空字串／None，呼叫端不會拿空值去猜。
# 對應：準則 #11；（此處無直接測試，由 parse_idmef_record 的測試間接覆蓋）
def _first_endpoint(entries: Any) -> Tuple[str, str, Optional[int], Optional[str], List[str]]:
    if not isinstance(entries, list) or not entries or not isinstance(entries[0], dict):
        return "", "", None, None, []
    e = entries[0]
    kind, value = "", ""
    for k in ("IP", "Hostname", "URL"):
        if e.get(k):
            kind, value = k, str(e[k])
            break
    port = None
    if isinstance(e.get("Port"), list) and e["Port"]:
        try:
            port = int(e["Port"][0])
        except (TypeError, ValueError):
            port = None
    proto = None
    if isinstance(e.get("Protocol"), list) and e["Protocol"]:
        proto = str(e["Protocol"][0]).lower()
    ti = [str(x) for x in e.get("TI", [])] if isinstance(e.get("TI"), list) else []
    return kind, value, port, proto, ti


# ── 【老師註解】parse_idmef_record ────────────────────────────────
# 做什麼：把 alerts.json 的「一行」JSON 物件，變成 SlipsEvidence（證據）、SlipsIncident（警報），或 None（認不得）。
# 為什麼：這是 Slips 資料進入系統的第一道門。這裡的原則是「認不得就回 None，不要硬湊」；
#         每個欄位都用 try／isinstance 防守，因為外部檔案的格式不是我們控制的。
# 怎麼看：注意 Note 欄位——Slips 把真正有用的結構（evidence_type、timewindow、uids…）塞成一個 JSON「字串」，
#         所以要先 json.loads 一次；若解不開，note 當空 dict，證據類型就是空字串 → 查表不到 → 弱指標 → 後面判 UNKNOWN。
#         Description 只被 str() 一下原樣保存，整個函式沒有任何一行去「讀懂」它。
# 拿掉會怎樣：直接用 rec["Note"]["evidence_type"] 會在第一筆格式稍異的資料上整支程式崩潰，或更糟——把錯的值當真。
# 對應：準則 #11；測試 tests/test_slips_adapter.py::test_unrecognised_records_are_rejected_not_guessed、
#       ::test_enum_string_forms_and_threat_levels_are_normalised
def parse_idmef_record(rec: Dict[str, Any]) -> Union[SlipsEvidence, SlipsIncident, None]:
    """Parse one IDMEFv2 dict as written by Slips. Returns None if it is not recognisable."""
    # 步驟 1：必須是 dict，且 Version 以 "2" 開頭（IDMEFv2），否則直接回 None
    if not isinstance(rec, dict) or str(rec.get("Version", "")).split(".")[0] != "2":
        return None
    # 步驟 2：Note 可能是 JSON 字串（Slips 實際寫法）或 dict；解不開就當空的，不丟整筆紀錄
    note: Dict[str, Any] = {}
    raw_note = rec.get("Note")
    if isinstance(raw_note, str) and raw_note:
        try:
            note = json.loads(raw_note)
        except ValueError:
            note = {}
    elif isinstance(raw_note, dict):
        note = raw_note
    # 步驟 3：Analyzer.Model 是 Slips 版本號，之後會記進 model_version 當來源證明
    analyzer = rec.get("Analyzer") or {}
    version = str(analyzer.get("Model", "")) if isinstance(analyzer, dict) else ""
    status = rec.get("Status")
    # 步驟 4：來源端點（IP／port／協定／威脅情報來源）與時間窗編號；轉不成整數就是 None
    src_kind, src_value, src_port, proto, src_ti = _first_endpoint(rec.get("Source"))
    tw = note.get("timewindow")
    try:
        tw_int: Optional[int] = int(tw) if tw is not None else None
    except (TypeError, ValueError):
        tw_int = None

    # 步驟 5：Status 是 Incident → 這是一條「警報」，只收集關聯證據 id 與累積威脅分數
    if status == IDMEF_INCIDENT:
        atl = note.get("accumulated_threat_level")
        return SlipsIncident(
            id=str(rec.get("ID", "")),
            source_ip=src_value,
            correl_ids=[str(c) for c in rec.get("CorrelID", []) or []],
            accumulated_threat_level=float(atl) if isinstance(atl, (int, float)) else None,
            timewindow=tw_int,
            start_time=str(rec.get("StartTime", "")),
            end_time=note.get("EndTime"),
            raw=rec,
        )
    # 步驟 6：既不是 Incident 也不是 Event（例如 Heartbeat）→ 認不得，回 None
    if status != IDMEF_EVENT:
        return None
    # 步驟 7：Event → 這是一條「證據」。目標端點、統一後的類型名、夾在 [0,1] 的信心值、Zeek uids
    _, tgt_value, dst_port, _, tgt_ti = _first_endpoint(rec.get("Target"))
    etype = _enum_name(note.get("evidence_type", "")) if note.get("evidence_type") else ""
    try:
        confidence = float(rec.get("Confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    uids = note.get("uids") or []
    # 步驟 8：組裝。description 只是原樣字串；threat_level 先看 Note，沒有才退回 Priority
    return SlipsEvidence(
        id=str(rec.get("ID", "")),
        evidence_type=etype,
        source_module=str(note.get("source_module", "")),
        threat_level=threat_level_weight(note.get("threat_level", rec.get("Priority", "info"))),
        confidence=max(0.0, min(1.0, confidence)),
        description=str(rec.get("Description", "")),
        source_ip=src_value,
        source_kind=src_kind,
        target_ip=tgt_value or None,
        src_port=src_port,
        dst_port=dst_port,
        proto=proto,
        timewindow=tw_int,
        uids=[str(u) for u in uids] if isinstance(uids, list) else [],
        start_time=str(rec.get("StartTime", "")),
        slips_version=version,
        priority=str(rec.get("Priority", "")),
        ti_sources=src_ti + tgt_ti,
        raw=rec,
    )


# ── 【老師註解】parse_alerts_json ─────────────────────────────────
# 做什麼：逐行讀 alerts.json（一行一個 JSON 物件），每行交給 parse_idmef_record，分裝進證據／警報，壞行計數。
# 為什麼：Slips 是邊跑邊 append 這個檔，最後一行常常是寫到一半的；逐行容錯才不會因為一行壞掉就整檔報廢。
# 怎麼看：兩種情況都算 malformed——JSON 根本解不開，或解開了但 parse_idmef_record 認不得（回 None）。
#         這個數字會一路傳到 slips-summary.json，讓人知道「有多少資料被忽略」。
# 對應：準則 #11、#13；測試 tests/test_slips_adapter.py::test_parse_fixture_events_incidents_and_malformed_lines
def parse_alerts_json(lines: Iterable[str]) -> SlipsParseResult:
    out = SlipsParseResult()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # JSON 解不開 → 計入 malformed，繼續下一行
        try:
            rec = json.loads(line)
        except ValueError:
            out.malformed += 1
            continue
        parsed = parse_idmef_record(rec)
        if isinstance(parsed, SlipsEvidence):
            out.evidence.append(parsed)
            if parsed.slips_version:
                out.slips_versions.add(parsed.slips_version)
        elif isinstance(parsed, SlipsIncident):
            out.incidents.append(parsed)
        else:
            # 合法 JSON 但不是我們認得的 IDMEFv2 Event／Incident → 同樣計入 malformed
            out.malformed += 1
    return out


# ── 【老師註解】read_alerts_json ──────────────────────────────────
# 做什麼：parse_alerts_json 的「讀檔」包裝：以 UTF-8 讀入，遇到壞位元組用替代字元而不是拋例外。
# 為什麼：真實環境的日誌檔難免夾雜非 UTF-8 位元組；這裡的目標是「盡量讀，讀不懂的計數」而不是中斷整個 ingest。
def read_alerts_json(path: Union[str, Path]) -> SlipsParseResult:
    return parse_alerts_json(Path(path).read_text(encoding="utf-8", errors="replace").splitlines())


# ----------------------------------------------------------------------------- Zeek conn.log
# ── 【老師註解】ZeekConnIndex ─────────────────────────────────────
# 做什麼：把 Zeek 的 conn.log 讀成「uid → 這條連線的那一列」索引。Slips 每條證據的 Note.uids 就是指向這些 uid。
# 為什麼：alerts.json 只有「發生了什麼」，沒有「傳了多少位元組、幾個封包、連線成功與否」；這些量化欄位（volumetrics）
#         要從 conn.log 補，FlowRecord 才有內容可以給內部常態模型（若啟用）或給人看。
# 怎麼看：這只是查表，沒有任何推論。找不到的 uid 就是找不到，aggregate() 會回 None，不會補 0。
# 對應：準則 #11；測試 tests/test_slips_adapter.py::test_zeek_conn_index_json_and_tsv
@dataclass
class ZeekConnIndex:
    """uid -> conn.log row (JSON-lines or Zeek TSV). Gives the FlowRecord its volumetrics."""

    rows: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # ── 【老師註解】ZeekConnIndex.load ─────────────────────────────
    # 做什麼：讀 conn.log，同時支援兩種格式——每行一個 JSON（Zeek 的 json 輸出）或傳統 TSV（#fields 標頭 + Tab 分隔）。
    # 為什麼：Slips 的 Zeek 可能以任一種格式輸出，取決於部署設定；寫死一種就會在另一種環境下讀到空索引（然後一切變 UNKNOWN）。
    # 怎麼看：TSV 模式要先遇到 #fields 行才知道欄位名；"-" 與 "(empty)" 是 Zeek 的「無值」寫法，一律轉成 None（不是 0）。
    #         #separator 行可能寫成 "\x09" 這種跳脫形式，所以多一步 unicode_escape 解碼。
    # 拿掉會怎樣：若不把 "-" 轉成 None，distinct_dst_ports 會把「無值」當成一個埠號來數，統計就失真；
    #         若讀不到 #fields 標頭，TSV 資料行會全部跳過，索引為空 → 所有量化欄位維持 None（這是安全的一邊）。
    @classmethod
    def load(cls, path: Union[str, Path]) -> "ZeekConnIndex":
        idx = cls()
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        fields: Optional[List[str]] = None
        sep = "\t"
        for line in text.splitlines():
            if not line.strip():
                continue
            # 註解行：只關心 #fields（欄位名）與 #separator（分隔符），其他 # 行跳過
            if line.startswith("#"):
                if line.startswith("#fields"):
                    fields = line.split(sep)[1:]
                elif line.startswith("#separator"):
                    tok = line.split(" ", 1)[1].strip()
                    sep = bytes(tok, "utf-8").decode("unicode_escape") if tok.startswith("\\x") else tok
                continue
            # 資料行：以 "{" 開頭當 JSON；否則若已有欄位名就當 TSV；兩者皆非就跳過
            if line.startswith("{"):
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
            elif fields is not None:
                vals = line.split(sep)
                row = {k: (None if v in ("-", "(empty)") else v) for k, v in zip(fields, vals)}
            else:
                continue
            uid = row.get("uid")
            if uid:
                idx.rows[str(uid)] = row
        return idx

    # ── 【老師註解】ZeekConnIndex._num ─────────────────────────────
    # 做什麼：安全地把某一列的某欄轉成 float；None 或轉不了都回 0.0。
    # 怎麼看：這個 0.0 只用在「加總」裡（有些列有值、有些沒有），不代表整組缺值——整組缺值由 aggregate() 回 None 處理。
    @staticmethod
    def _num(row: Dict[str, Any], key: str) -> float:
        v = row.get(key)
        try:
            return float(v) if v is not None else 0.0
        except (TypeError, ValueError):
            return 0.0

    # ── 【老師註解】ZeekConnIndex.aggregate ────────────────────────
    # 做什麼：給一組 uid，把找得到的 conn.log 列加總成 FlowRecord 需要的量化欄位：進出位元組、封包、總時長、平均間隔、
    #         失敗連線數、連線數、不同目的埠數。
    # 為什麼：Slips 一個時間窗裡可能有多條連線；FlowRecord 是「一個窗一筆」，所以要聚合。
    # 怎麼看：第一行最重要——一個 uid 都找不到就回 None，呼叫端會讓所有量化欄位維持 None（缺值 ≠ 0）。
    #         mean_iat_ms 有兩種算法：≥2 條連線用「首尾時間差 ÷ (n-1)」；只有 1 條就用「時長 ÷ (封包數-1)」近似。
    #         conn_failures 數的是 Zeek conn_state 落在 S0／REJ／RSTOS0… 這些「沒握手成功」的狀態。
    # 對應：準則 #11；測試 tests/test_slips_adapter.py::test_zeek_conn_index_json_and_tsv
    def aggregate(self, uids: Sequence[str]) -> Optional[Dict[str, float]]:
        rows = [self.rows[u] for u in uids if u in self.rows]
        # 完全對不到任何一列 → None（讓上層把欄位留空，不是填零）
        if not rows:
            return None
        ts = sorted(self._num(r, "ts") for r in rows)
        pkts = sum(self._num(r, "orig_pkts") + self._num(r, "resp_pkts") for r in rows)
        duration = sum(self._num(r, "duration") for r in rows)
        if len(ts) >= 2:
            mean_iat_ms = 1000.0 * (ts[-1] - ts[0]) / (len(ts) - 1)
        else:
            mean_iat_ms = 1000.0 * duration / max(pkts - 1.0, 1.0)
        return {
            "bytes_out": sum(self._num(r, "orig_bytes") for r in rows),
            "bytes_in": sum(self._num(r, "resp_bytes") for r in rows),
            "pkts_out": sum(self._num(r, "orig_pkts") for r in rows),
            "pkts_in": sum(self._num(r, "resp_pkts") for r in rows),
            "duration_s": duration,
            "mean_iat_ms": mean_iat_ms,
            "conn_failures": float(sum(1 for r in rows if str(r.get("conn_state", "")) in _FAILED_CONN_STATES)),
            "short_window_conns": float(len(rows)),
            "distinct_dst_ports": float(len({r.get("id.resp_p") for r in rows if r.get("id.resp_p") is not None})),
        }


# ----------------------------------------------------------------------------- cases
# ── 【老師註解】SlipsCase ─────────────────────────────────────────
# 做什麼：一個「案子」的完整包裹：FlowRecord（給沙箱工具看的流量摘要）、已知分支結論、異常分支結論（可能沒有）、
#         這組的原始證據與警報、以及要寫進帳本摘要的 source_record。
# 為什麼：判定（decide_external）只需要 flow＋known＋anomaly；其餘是為了「可回溯」——帳本只存 source_record 的摘要，
#         但有了原始紀錄就能在事後證明摘要對應的是什麼。
# 對應：準則 #7
@dataclass
class SlipsCase:
    """Everything the SOC needs for one (profile, time window) group of Slips evidence."""

    flow: FlowRecord
    known: ExternalKnown
    anomaly: Optional[ExternalAnomaly]
    evidence: List[SlipsEvidence]
    incidents: List[SlipsIncident]
    source_record: Dict[str, Any]


# ── 【老師註解】_service_group ────────────────────────────────────
# 做什麼：用目的埠猜服務群組（22→ssh、53→dns、80/443→web、25/587→mail，其他→default）。
# 為什麼：內部常態模型的門檻 τ_a 是「每個服務群組各一個」（論文 §VI）；要查門檻就要先知道群組。
# 怎麼看：這是粗略對照，只影響「若啟用內部常態模型」時用哪個門檻；預設不啟用時它只是個標籤。
def _service_group(port: Optional[int]) -> str:
    return {22: "ssh", 53: "dns", 80: "web", 443: "web", 25: "mail", 587: "mail"}.get(port or -1, "default")


# ── 【老師註解】SlipsAdapter ──────────────────────────────────────
# 做什麼：真正做「翻譯」的類別：一組證據 → known_verdict()（已知分支）＋ anomaly_signal()（異常分支）＋ build_flow()（FlowRecord），
#         build_cases() 負責先分組再逐組呼叫上面三個。
# 為什麼：把規則集中在一個物件裡，tau_k（已知分支的最低信心）與 min_threat_weight（最低威脅權重）成為可調參數，
#         而不是散落各處的魔術數字。
# 怎麼看：tenant 由部署者指定（Slips 本身沒有租戶概念），之後所有工具存取都以此做租戶隔離。
# 對應：準則 #12；測試 tests/test_slips_adapter.py::test_adapter_groups_by_profile_and_timewindow_and_builds_branches
class SlipsAdapter:
    def __init__(self, tenant: str, conn_index: Optional[ZeekConnIndex] = None, tau_k: float = 0.5, min_threat_weight: float = 0.5) -> None:
        self.tenant = tenant
        self.conn_index = conn_index
        self.tau_k = tau_k
        self.min_threat_weight = min_threat_weight

    # ── 【老師註解】SlipsAdapter.known_verdict ─────────────────────
    # 做什麼：從同一窗的證據裡產生「已知分支」的結論 ExternalKnown：標籤、分數、是否拒絕、來源模組、ATT&CK 技術、證據 id。
    # 為什麼：論文的已知分支要有「拒絕選項」（reject option）——不夠有把握就說「我不認得」，而不是硬給一個類別。
    # 怎麼看：三種結果——
    #         (a) 沒有任何可查表的證據 → 標籤 unclassified、rejected=True（弱指標不能單獨成案）；
    #         (b) 有可查表證據，取（信心, 威脅權重）最高的一條；信心 < tau_k 或 威脅權重 < min_threat_weight → rejected=True；
    #         (c) 否則接受，標籤就是那條證據的家族。技術若最佳證據沒有，退而取同組其他已映射證據的。
    #         注意分數就是 Slips 的 Confidence 原值，不是校準過的機率（模組開頭已聲明）。
    # 拿掉會怎樣：沒有拒絕選項，一條 low 等級、信心 0.3 的 YOUNG_DOMAIN 也會被當成已知攻擊派 Agent 去查，誤報會淹沒人力。
    # 對應：準則 #12；測試 tests/test_slips_adapter.py::test_low_confidence_mapped_evidence_is_rejected_by_tau
    def known_verdict(self, group: Sequence[SlipsEvidence]) -> ExternalKnown:
        mapped = [e for e in group if e.family is not None]
        ids = [e.id for e in group]
        # (a) 整組都是弱指標：unclassified 且一律拒絕；分數只是記錄「最高看到多少」
        if not mapped:
            best_conf = max((e.confidence for e in group), default=0.0)
            modules = sorted({e.source_module for e in group if e.source_module})
            return ExternalKnown(UNCLASSIFIED, best_conf, True, f"{SLIPS_SOURCE}/{'+'.join(modules) or 'unknown'}", None, ids)
        # (b)(c) 取最有把握的一條已映射證據，再套兩道門檻決定接受或拒絕
        best = max(mapped, key=lambda e: (e.confidence, e.threat_level))
        rejected = best.confidence < self.tau_k or best.threat_level < self.min_threat_weight
        technique = best.technique or next((e.technique for e in mapped if e.technique), None)
        return ExternalKnown(
            label=best.family or UNCLASSIFIED,
            score=best.confidence,
            rejected=rejected,
            source=f"{SLIPS_SOURCE}/{best.source_module or best.evidence_type.lower()}",
            technique=technique,
            evidence_ids=ids,
        )

    # ── 【老師註解】SlipsAdapter.anomaly_signal ────────────────────
    # 做什麼：同一窗裡若有 ANOMALY_TYPES 的證據，取信心最高的一條做成 ExternalAnomaly(high=True)；沒有就回 None。
    # 為什麼：Slips 的 ML 模組「發出證據」這件事本身就代表它判為異常，所以 high 直接為 True、門檻留空；
    #         回 None 代表「異常分支沒有資料」——後續 decide_external 會把它當成缺席，而不是「正常」。
    # 怎麼看：這條分支不看 tau_k；它和已知分支是獨立的兩條路，兩者的組合才由判定表決定狀態。
    # 對應：準則 #12；情境 scenario_slips_missing_branch（tests/test_end_to_end.py::test_scenarios_behave_as_specified）
    def anomaly_signal(self, group: Sequence[SlipsEvidence]) -> Optional[ExternalAnomaly]:
        sig = [e for e in group if e.is_anomaly_signal]
        if not sig:
            return None
        best = max(sig, key=lambda e: e.confidence)
        return ExternalAnomaly(score=best.confidence, high=True, source=f"{SLIPS_SOURCE}/{best.source_module or best.evidence_type.lower()}")

    # ── 【老師註解】SlipsAdapter.build_flow ────────────────────────
    # 做什麼：把一組證據摺成一筆 FlowRecord——沙箱裡的唯讀工具 get_flow 之後回給 Agent 的就是它。
    # 為什麼：下游（判定表、Agent 工具、AiSOC 事件）都以 FlowRecord 為單位；這裡是 Slips 世界與內部世界的交界。
    # 怎麼看：三個重點——
    #         1) 量化欄位預設全是 None；只有 conn.log 真的對得到 uid 才用 aggregate() 的結果覆蓋。None 讓 has_required_fields() 為 False，
    #            內部常態模型就不會被拿去替「看不見的流量」打分（缺值 ≠ 正常）。
    #         2) log_excerpt 是把每條證據的「[類型] Description」串起來、截 4000 字——這是全檔唯一讓 Description 流出去的地方，
    #            而它會被 get_flow 包成 Untrusted 並過注入篩查；它只給人看、給篩查器看，不給任何判斷邏輯看。
    #         3) flow_id 固定為 "slips:<來源IP>:tw<時間窗>"，所以同一窗重跑會得到同一個 id，可與情境、測試對照。
    # 拿掉會怎樣：若缺值補 0，一個完全沒有 conn.log 的窗會看起來像「零流量的正常連線」，異常分支會被誤導成低分。
    # 對應：準則 #11；測試 tests/test_slips_adapter.py::test_adapter_groups_by_profile_and_timewindow_and_builds_branches、
    #       ::test_internal_normality_only_used_when_opted_in_and_fields_present
    def build_flow(self, key: Tuple[str, Optional[int]], group: Sequence[SlipsEvidence], known: ExternalKnown) -> FlowRecord:
        src, tw = key
        # 「主證據」＝與已知分支標籤同家族的第一條；沒有就拿第一條，用它的目的端點當代表
        primary = next((e for e in group if e.family == known.label), group[0])
        # Missing volumetrics are None: has_required_fields() is then False and the internal
        # normality model is never asked to score a flow it cannot see (missing != normal).
        vol: Dict[str, Any] = {
            "bytes_in": None, "bytes_out": None, "pkts_in": None, "pkts_out": None, "duration_s": None, "mean_iat_ms": None,
            "conn_failures": 0.0, "short_window_conns": float(len(group)),
            "distinct_dst_ports": float(len({e.dst_port for e in group if e.dst_port is not None})),
        }
        # 有 conn.log 才嘗試補量化欄位；對不到任何 uid 時 agg 是 None，欄位維持 None
        if self.conn_index is not None:
            uids = sorted({u for e in group for u in e.uids})
            agg = self.conn_index.aggregate(uids)
            if agg:
                vol.update(agg)
        # Description 只在這裡出現：拼成不可信摘錄，之後由 Untrusted 包住，絕不解析
        excerpt = " | ".join(f"[{e.evidence_type}] {e.description}" for e in group)[:4000]
        return FlowRecord(
            flow_id=f"slips:{src}:tw{tw if tw is not None else 'na'}",
            tenant=self.tenant,
            src_host=src,
            dst_ip=primary.target_ip or "0.0.0.0",
            dst_port=primary.dst_port or 0,
            bytes_in=vol["bytes_in"], bytes_out=vol["bytes_out"], pkts_in=vol["pkts_in"], pkts_out=vol["pkts_out"],
            duration_s=vol["duration_s"], mean_iat_ms=vol["mean_iat_ms"],
            conn_failures=vol["conn_failures"], short_window_conns=vol["short_window_conns"],
            distinct_dst_ports=vol["distinct_dst_ports"],
            login_failures=0.0,
            service_group=_service_group(primary.dst_port),
            observed_at=min((e.start_time for e in group if e.start_time), default=""),
            log_excerpt=excerpt,
        )

    # ── 【老師註解】SlipsAdapter.build_cases ───────────────────────
    # 做什麼：整個解析結果 → 多個 SlipsCase。先以 (來源 IP, 時間窗) 分組，再對每組算已知分支、異常分支、FlowRecord，
    #         並把相關的 Slips 警報與原始紀錄掛上去。
    # 為什麼：分組單位刻意選得和 Slips 自己發警報的單位一樣（一個 profile 的一個時間窗），這樣我們的案子和 Slips 的警報一一對得上。
    # 怎麼看：警報有兩種對上方式——同 (IP, 窗)，或警報的 CorrelID 與本組證據 id 有交集。
    #         source_record 帶 schema_version、整組原始 JSON、以及「警報提到但檔案裡沒有的證據 id」（unresolved_correl_ids），
    #         誠實記錄資料不完整之處。最後依（觀察時間, flow_id）排序，讓輸出順序可重現。
    # 拿掉會怎樣：若按單條證據成案，同一台主機的掃描會變成幾十個案子，Agent 預算與人力都會被灌爆，也無法和 Slips 的警報對照。
    # 對應：準則 #7、#13；測試 tests/test_slips_adapter.py::test_adapter_groups_by_profile_and_timewindow_and_builds_branches
    def build_cases(self, parsed: SlipsParseResult) -> List[SlipsCase]:
        # 步驟 1：按 (來源 IP, 時間窗) 分組
        groups: Dict[Tuple[str, Optional[int]], List[SlipsEvidence]] = {}
        for e in parsed.evidence:
            groups.setdefault((e.source_ip, e.timewindow), []).append(e)
        by_evidence_id = {e.id: e for e in parsed.evidence}
        cases: List[SlipsCase] = []
        for key, group in groups.items():
            # 步驟 2：兩條分支各自獨立結論，再建 FlowRecord
            known = self.known_verdict(group)
            anomaly = self.anomaly_signal(group)
            flow = self.build_flow(key, group, known)
            # 步驟 3：掛上相關的 Slips 警報（同窗，或 CorrelID 有交集）
            ids = {e.id for e in group}
            incidents = [
                i for i in parsed.incidents
                if (i.source_ip == key[0] and i.timewindow == key[1]) or (ids & set(i.correl_ids))
            ]
            # 步驟 4：原始紀錄打包；之後帳本只存它的摘要（digest），原文留在這裡供回溯
            record = {
                "schema_version": "aisoc/slips-source-record/0.1",
                "evidence": [e.raw for e in group],
                "incidents": [i.raw for i in incidents],
                "unresolved_correl_ids": sorted({c for i in incidents for c in i.correl_ids if c not in by_evidence_id}),
            }
            cases.append(SlipsCase(flow, known, anomaly, list(group), incidents, record))
        # 步驟 5：固定排序，輸出可重現
        cases.sort(key=lambda c: (c.flow.observed_at, c.flow.flow_id))
        return cases


# ── 【老師註解】SlipsRunSummary ──────────────────────────────────
# 做什麼：一次 slips-ingest 跑完的總結：幾條證據／警報／壞行、幾個案子、狀態分佈、幾個要人審、已知家族分佈，
#         外加完整的 CaseResult 與 SlipsCase 列表（這兩個不進 to_dict，太大）。
# 為什麼：CLI 要把它寫成 slips-summary.json 給人看，也給 aisoc-push 當輸入。
# 對應：準則 #13
@dataclass
class SlipsRunSummary:
    evidence: int
    incidents: int
    malformed: int
    cases: int
    slips_versions: List[str]
    status_counts: Dict[str, int]
    requires_human_review: int
    known_families: Dict[str, int]
    results: List[CaseResult] = field(default_factory=list)
    slips_cases: List[SlipsCase] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items() if k not in ("results", "slips_cases")}
        d["case_ids"] = [r.case_id for r in self.results]
        return d

    # ── 【老師註解】SlipsRunSummary.export_cases ───────────────────
    # 做什麼：每個案子輸出一個 dict：CaseResult 的內容＋流量身分欄位（租戶、來源主機、目的 IP／埠、時間、服務群組）
    #         ＋ Slips 側的參照（證據 id、警報 id、兩條分支的結論、source_record 的摘要）。
    # 為什麼：這份輸出是 aisoc-push 產生 AiSOC 事件的唯一來源，而且它刻意「不含 log_excerpt」——不可信的原文不隨警報外流。
    # 怎麼看：source_record_digest 和帳本 detection 項目裡的 refs["source_record_digest"] 是同一個值，可互相核對。
    # 對應：準則 #7、#11；測試 tests/test_slips_adapter.py::test_export_cases_carries_flow_identity_and_slips_refs
    def export_cases(self) -> List[Dict[str, Any]]:
        """CaseResult dicts plus the flow identity fields and the Slips evidence ids behind each case."""
        out = []
        for r, c in zip(self.results, self.slips_cases):
            d = r.to_dict()
            d["flow"] = {"tenant": c.flow.tenant, "src_host": c.flow.src_host, "dst_ip": c.flow.dst_ip,
                         "dst_port": c.flow.dst_port, "observed_at": c.flow.observed_at, "service_group": c.flow.service_group}
            d["slips"] = {"evidence_ids": [e.id for e in c.evidence], "incident_ids": [i.id for i in c.incidents],
                          "known": c.known.__dict__, "anomaly": c.anomaly.__dict__ if c.anomaly else None,
                          "source_record_digest": digest(c.source_record)}
            out.append(d)
        return out


# ── 【老師註解】run_slips_parsed ──────────────────────────────────
# 做什麼：把已解析的 Slips 結果餵進 SOC：建案子 → 每個案子呼叫 soc.ingest_external()（判定表 → 沙箱 Agent → 政策 → PEP → 帳本）
#         → 統計狀態／家族／人審數量 → 回 SlipsRunSummary。
# 為什麼：這是 Slips 路徑和內建合成路徑（soc.ingest）的匯流點——從 ingest_external 之後，兩條路走的是完全相同的信任鏈。
# 怎麼看：use_internal_normality 預設 False：合成資料訓練的常態模型不該替真實流量打分，除非你用自己的基線重訓過。
#         每案之後把時鐘撥快 advance_clock_s 秒，是為了避免 SOC 的去重（同租戶、同主機、同狀態、短時間內）把所有案子疊成一個。
# 拿掉會怎樣：直接呼叫 soc.ingest 的話，案子會重新經過內部已知模型打分，Slips 的判斷就被丟掉了。
# 對應：準則 #12、#13；測試 tests/test_slips_adapter.py::test_run_through_soc_statuses_and_untrusted_description、
#       ::test_internal_normality_only_used_when_opted_in_and_fields_present
def run_slips_parsed(
    soc: AISOC,
    parsed: SlipsParseResult,
    tenant: str = "tenant-slips",
    conn_index: Optional[ZeekConnIndex] = None,
    use_internal_normality: bool = False,
    tau_k: float = 0.5,
    advance_clock_s: float = 7.0,
) -> SlipsRunSummary:
    adapter = SlipsAdapter(tenant, conn_index, tau_k=tau_k)
    cases = adapter.build_cases(parsed)
    results: List[CaseResult] = []
    status_counts: Dict[str, int] = {}
    families: Dict[str, int] = {}
    for c in cases:
        # 每個案子走完整信任鏈；source_record 的摘要會被寫進帳本的 detection 項目
        res = soc.ingest_external(c.flow, c.known, c.anomaly, use_internal_normality, c.source_record)
        results.append(res)
        status_counts[res.decision.status.value] = status_counts.get(res.decision.status.value, 0) + 1
        families[c.known.label] = families.get(c.known.label, 0) + 1
        # 撥快時鐘，避免去重視窗把不同案子合併
        soc.clock.advance(advance_clock_s)
    return SlipsRunSummary(
        evidence=len(parsed.evidence),
        incidents=len(parsed.incidents),
        malformed=parsed.malformed,
        cases=len(cases),
        slips_versions=sorted(parsed.slips_versions),
        status_counts=status_counts,
        requires_human_review=sum(1 for r in results if r.decision.requires_human_review),
        known_families=families,
        results=results,
        slips_cases=cases,
    )


# ── 【老師註解】run_slips_alerts ──────────────────────────────────
# 做什麼：run_slips_parsed 的「讀檔版」：讀 alerts.json，若有給 conn.log 就建索引，然後交給 run_slips_parsed。
# 為什麼：CLI 的 slips-ingest 子命令只需要給路徑；情境與測試則常用 run_slips_parsed 直接餵記憶體中的樣本。
# 對應：測試 tests/test_slips_adapter.py::test_run_through_soc_statuses_and_untrusted_description
def run_slips_alerts(
    soc: AISOC,
    alerts_path: Union[str, Path],
    tenant: str = "tenant-slips",
    conn_log: Optional[Union[str, Path]] = None,
    use_internal_normality: bool = False,
    tau_k: float = 0.5,
    advance_clock_s: float = 7.0,
) -> SlipsRunSummary:
    """Feed a Slips ``alerts.json`` through the SOC. Each (profile, time window) becomes one case."""
    parsed = read_alerts_json(alerts_path)
    index = ZeekConnIndex.load(conn_log) if conn_log else None
    return run_slips_parsed(soc, parsed, tenant, index, use_internal_normality, tau_k, advance_clock_s)


# ── 【老師註解】sample_alerts_json_lines ──────────────────────────
# 做什麼：在程式裡直接產生一小份「長得和 Slips 1.1.x 一模一樣」的 alerts.json 內容：4 條證據（C2、威脅情報、ML 異常、年輕網域）＋ 1 條警報。
# 為什麼：情境與展示不需要真的跑 Slips；這份樣本刻意涵蓋三種路徑——已知（C2＋TI）、只有異常（ML）、只有弱指標（YOUNG_DOMAIN）。
# 怎麼看：injection_text 會被接在 C2 那條的 Description 後面，用來演示「偵測器吐出的自由文字也可能是攻擊載體」；
#         它進系統後只會變成 Untrusted 的 log_excerpt，被篩查器標旗、給人看，而不會被執行。
# 對應：準則 #11、#13；情境 scenario_slips_description_injection、scenario_slips_missing_branch
def sample_alerts_json_lines(injection_text: str = "") -> List[str]:
    """Small in-code IDMEFv2 sample in the exact shape Slips 1.1.x writes (for demos and scenarios).

    ``injection_text`` is appended to one ``Description`` to show that free text coming
    from the detector is treated as untrusted content.
    """

    def event(eid: str, etype: str, module: str, tl: str, conf: float, desc: str, src: str, tw: int,
              uids: List[str], prio: str, target: str, dport: int) -> str:
        note = {"evidence_type": etype, "uids": uids, "accumulated_threat_level": 0, "threat_level": tl,
                "evidence_signal": "PAMP", "timewindow": tw, "source_module": module}
        rec = {
            "Version": "2.D.V03", "ID": eid, "Status": IDMEF_EVENT, "Priority": prio,
            "StartTime": f"2026-10-30T09:1{tw}:00.000Z", "CreateTime": "2026-10-30T09:20:00.000Z",
            "Confidence": conf, "Description": desc,
            "Analyzer": {"IP": "192.168.1.5", "Name": "Slips", "Model": "1.1.24", "Category": ["NIDS"],
                         "Data": ["Flow", "Network"], "Method": ["Heuristic"]},
            "Source": [{"IP": src, "Port": [], "Protocol": ["TCP"], "Note": json.dumps({"AS": {}, "rDNS": "", "SNI": ""})}],
            "Target": [{"IP": target, "Port": [dport]}],
            "Note": json.dumps(note),
        }
        return json.dumps(rec)

    c2_desc = "C&C channel, destination IP: 185.199.110.153 port: 443/tcp score: 0.9823" + (" " + injection_text if injection_text else "")
    lines = [
        event("ev-c2-0001", "COMMAND_AND_CONTROL_CHANNEL", "rnn_cc_detection", "high", 0.9, c2_desc, "10.0.0.23", 2,
              ["Cuid0001", "Cuid0002"], "High", "185.199.110.153", 443),
        event("ev-ti-0002", "THREAT_INTELLIGENCE_TO_BLACKLISTED_IP", "threat_intelligence", "high", 1.0,
              "connection to blacklisted IP 185.199.110.153. Source: feodotracker", "10.0.0.23", 2, ["Cuid0001"], "High",
              "185.199.110.153", 443),
        event("ev-ml-0003", "ANOMALOUS_FLOW", "flowmldetection", "low", 0.65,
              "Anomalous flow detected by ML model to 198.51.100.7:8443", "10.0.0.88", 4, ["Cuid0301"], "Low", "198.51.100.7", 8443),
        event("ev-yd-0004", "YOUNG_DOMAIN", "flowalerts", "low", 0.6,
              "Connection to a young domain: cdn-update-9f3a.top registered 3 days ago", "10.0.0.90", 5, ["Cuid0401"], "Low",
              "203.0.113.44", 80),
    ]
    incident = {
        "Version": "2.D.V03", "ID": "inc-0001", "Status": IDMEF_INCIDENT, "Priority": "High",
        "StartTime": "2026-10-30T09:12:00.000Z", "CreateTime": "2026-10-30T09:21:00.000Z",
        "Analyzer": {"IP": "192.168.1.5", "Name": "Slips", "Model": "1.1.24", "Category": ["NIDS"], "Data": ["Flow", "Network"], "Method": ["Heuristic"]},
        "Source": [{"IP": "10.0.0.23"}], "CorrelID": ["ev-c2-0001", "ev-ti-0002"],
        "Note": json.dumps({"accumulated_threat_level": 2.5, "accumulated_ratl": 2.5, "risk_level": "high", "timewindow": 2,
                            "EndTime": "2026-10-30T09:22:00.000Z"}),
    }
    return lines + [json.dumps(incident)]
