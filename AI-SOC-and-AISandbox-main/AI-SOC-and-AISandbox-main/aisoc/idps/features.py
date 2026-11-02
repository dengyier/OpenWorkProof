"""Flow records and the versioned feature schema shared by both branches.

Both the known-pattern branch and the normality branch must see exactly the
same feature vector computed from information available at decision time.
The schema is versioned so a model artefact can be tied to the features it
was trained with.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

# ── 【老師註解】FEATURE_SCHEMA_VERSION ──────────────────────────────
# 做什麼：替「特徵向量的定義」貼一個版本號字串，會被寫進模型製品與每一筆 CaseDecision。
# 為什麼：模型只認得它訓練時看過的那一組特徵；若日後改了特徵的順序或算法，舊模型就不能再用。
# 怎麼看：dual_model.from_params 與 release.load_verified_model 都會比對這個字串，不同就拒絕載入。
# 拿掉會怎樣：換了特徵定義卻沿用舊模型，分數會悄悄變成亂數，而且沒有任何地方會報錯。
# 對應：準則 #10；測試 tests/test_egress_release_grant.py::test_model_file_schema_is_checked
FEATURE_SCHEMA_VERSION = "aisoc/features/v1"

# ── 【老師註解】FEATURE_NAMES ──────────────────────────────
# 做什麼：列出 12 個特徵的名字，順序必須與下面 featurize() 回傳的清單一一對應。
# 為什麼：兩個分支（已知 f_k、異常 f_a）都吃同一個向量；名字清單讓人能對照「第 j 維是什麼」。
# 怎麼看：log_ 開頭代表取過 log1p 壓縮量級；比例、計數類則保留原值。
# 拿掉會怎樣：模型檔裡的 "features" 欄位會失去意義，稽核時無法解讀權重。
# 對應：準則 #10（此處無直接測試）
FEATURE_NAMES: List[str] = [
    "log_bytes_in",
    "log_bytes_out",
    "out_in_byte_ratio",
    "log_pkts_in",
    "log_pkts_out",
    "log_duration",
    "log_mean_iat_ms",
    "conn_failures",
    "log_short_window_conns",
    "distinct_dst_ports",
    "login_failures",
    "is_well_known_port",
]


# ── 【老師註解】FlowRecord ──────────────────────────────
# 做什麼：一筆「流量視窗」的結構化紀錄，是整個 IDPS 的輸入單位（Slips 匯入時一個 profile 視窗 = 一筆）。
# 為什麼：判定只能根據「決策當下拿得到」的數值欄位；文字欄位 log_excerpt 只是附帶，下游一律視為不可信內容。
# 怎麼看：label / family 是離線評估用的標準答案，推論程式碼絕不能讀它們；service_group 決定用哪一組 tau_a。
# 拿掉會怎樣：若模型能偷看 label，評估數字會虛高；若讀 log_excerpt 來判定，就等於讓攻擊者用日誌文字操控 SOC。
# 對應：準則 #11（此處無直接測試）
@dataclass
class FlowRecord:
    flow_id: str
    tenant: str
    src_host: str
    dst_ip: str
    dst_port: int
    bytes_in: float
    bytes_out: float
    pkts_in: float
    pkts_out: float
    duration_s: float
    mean_iat_ms: float
    conn_failures: float
    short_window_conns: float
    distinct_dst_ports: float
    login_failures: float
    service_group: str = "default"
    observed_at: str = ""
    # Ground truth is kept only for offline evaluation and is never visible to inference.
    label: Optional[str] = None
    family: Optional[str] = None
    # Raw log text attached to the flow. Treated as *untrusted content* downstream.
    log_excerpt: str = ""

    # ── 【老師註解】FlowRecord.has_required_fields ──────────────────────────────
    # 做什麼：檢查六個「量化欄位」是否齊全且合理（非 None、非 NaN、非負數）。
    # 為什麼：缺資料不等於「正常」；論文要求資料缺失時回 UNKNOWN 而不是猜。這個函數就是那條規則的守門員。
    # 怎麼看：任何一個欄位不合格就回 False；DualModel.decide 看到 False 直接出 UNKNOWN 並要求人審。
    # 拿掉會怎樣：壞掉的感測器（例如回傳 -1 或 NaN）會被模型當成極端值硬算，產出一個看似有信心的錯誤分數。
    # 對應：準則 #11；測試 tests/test_dual_model.py::test_missing_data_is_unknown_not_normal
    def has_required_fields(self) -> bool:
        for name in ("bytes_in", "bytes_out", "pkts_in", "pkts_out", "duration_s", "mean_iat_ms"):
            v = getattr(self, name)
            # 三種「壞值」都算缺失：None、NaN、負數
            if v is None or (isinstance(v, float) and math.isnan(v)) or v < 0:
                return False
        return True


# ── 【老師註解】featurize ──────────────────────────────
# 做什麼：把一筆 FlowRecord 轉成 12 維的數值向量（順序 = FEATURE_NAMES）。
# 為什麼：兩個分支必須看「同一個」向量，否則 Table III 的合成邏輯就無法比較；所以只寫一次、兩邊共用。
# 怎麼看：l() 是 log1p，先把負值夾成 0 再取對數，用來壓縮位元組／封包數這類跨好幾個數量級的欄位。
# 拿掉會怎樣：原始位元組數動輒百萬，直接餵邏輯迴歸會讓梯度爆掉、Isolation Forest 也會被少數巨量樣本主宰。
# 對應：準則 #10；間接測試 tests/test_egress_release_grant.py::test_model_round_trips_through_bytes_with_identical_decisions
def featurize(flow: FlowRecord) -> List[float]:
    # 小工具：log1p 並把負值夾成 0，避免對負數取 log 出錯
    def l(x: float) -> float:
        return math.log1p(max(x, 0.0))

    # +1 防止除以零
    denom = flow.bytes_in + 1.0
    return [
        l(flow.bytes_in),
        l(flow.bytes_out),
        # 出／入位元組比，封頂 1000 防極端值（外洩流量的典型特徵）
        min(flow.bytes_out / denom, 1000.0),
        l(flow.pkts_in),
        l(flow.pkts_out),
        l(flow.duration_s),
        l(flow.mean_iat_ms),
        float(flow.conn_failures),
        l(flow.short_window_conns),
        float(flow.distinct_dst_ports),
        float(flow.login_failures),
        # 是否打到常見埠（22/53/80/443）：埠掃描常打到不常見埠
        1.0 if flow.dst_port in (22, 53, 80, 443) else 0.0,
    ]


# ── 【老師註解】StandardScaler ──────────────────────────────
# 做什麼：把每一維特徵減平均、除標準差，讓所有維度大致落在同一尺度。
# 為什麼：邏輯迴歸對尺度敏感；Isolation Forest 的隨機切點也會被大尺度維度壟斷。
# 怎麼看：means / stds 是「從訓練集學來的參數」，會一起序列化進模型檔；推論時只呼叫 transform。
# 拿掉會怎樣：若在 train+val+test 全集上 fit，測試資料的統計量就漏進了模型（leakage），評估數字不可信。
# 對應：準則 #10、#13；測試 tests/test_dual_model.py::test_thresholds_are_fit_only_on_train_and_val
@dataclass
class StandardScaler:
    """Fit on training data only; applying it elsewhere is a leakage bug."""

    means: List[float] = field(default_factory=list)
    stds: List[float] = field(default_factory=list)

    # ── 【老師註解】StandardScaler.fit ──────────────────────────────
    # 做什麼：對每一維算平均與樣本標準差（分母 n−1），存進 self.means / self.stds。
    # 為什麼：只能用訓練集呼叫一次；DualModel.train 正是這樣做的（raw_train → fit → 再 transform val）。
    # 怎麼看：變異數小於 1e-12 時把 std 設成 1.0，避免常數特徵造成除以零。
    # 拿掉會怎樣：常數特徵會讓 transform 產生 inf/NaN，整個模型跟著壞掉。
    # 對應：準則 #10（此處無直接測試）
    def fit(self, rows: Sequence[Sequence[float]]) -> "StandardScaler":
        n = len(rows)
        d = len(rows[0])
        # 步驟 1：每一維的平均
        self.means = [sum(r[j] for r in rows) / n for j in range(d)]
        self.stds = []
        # 步驟 2：每一維的樣本標準差；幾乎為零時用 1.0 代替
        for j in range(d):
            var = sum((r[j] - self.means[j]) ** 2 for r in rows) / max(n - 1, 1)
            self.stds.append(math.sqrt(var) if var > 1e-12 else 1.0)
        return self

    # ── 【老師註解】StandardScaler.transform ──────────────────────────────
    # 做什麼：用已學到的 means / stds 把一列原始特徵標準化成 z 分數。
    # 為什麼：推論時每一筆流量都要經過這一步，才會和訓練時的分佈對得上。
    # 怎麼看：zip 按維度逐一配對；若還沒 fit（means 為空）會回傳空清單，下游模型會因此出錯而走到 UNKNOWN。
    # 對應：準則 #11（模型失敗 ⇒ UNKNOWN）（此處無直接測試）
    def transform(self, row: Sequence[float]) -> List[float]:
        return [(x - m) / s for x, m, s in zip(row, self.means, self.stds)]

    # ── 【老師註解】StandardScaler.to_dict ──────────────────────────────
    # 做什麼：把 scaler 參數轉成純 JSON 字典，好讓它跟模型一起被哈希、簽名、釘死。
    # 為什麼：模型製品必須「完整可重現」——少了 scaler 的平均／標準差，載入後的分數就和發佈時不同。
    # 對應：準則 #10；測試 tests/test_egress_release_grant.py::test_model_round_trips_through_bytes_with_identical_decisions
    def to_dict(self) -> Dict[str, List[float]]:
        return {"means": self.means, "stds": self.stds}

    # ── 【老師註解】StandardScaler.from_dict ──────────────────────────────
    # 做什麼：to_dict 的反向；每個值都顯式轉成 float，避免 JSON 帶進奇怪型別。
    # 對應：準則 #10（此處無直接測試）
    @classmethod
    def from_dict(cls, d: Dict[str, List[float]]) -> "StandardScaler":
        return cls(means=[float(x) for x in d["means"]], stds=[float(x) for x in d["stds"]])
