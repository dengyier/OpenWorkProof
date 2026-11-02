"""dual_model: combine the known branch and the normality branch (paper Table III).

The original single "low confidence AND high anomaly" gate is kept, and two
branches are added: a *model conflict* branch (confident-normal yet highly
anomalous) and an *insufficient evidence* branch. Missing data is never
treated as normal.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from .features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, FlowRecord, StandardScaler, featurize
from .known_model import BENIGN, KnownModel, KnownPrediction
from .normality_model import NormalityModel

# ── 【老師註解】MODEL_FILE_SCHEMA ──────────────────────────────
# 做什麼：模型「檔案格式」的版本字串，寫在 to_params 的 "schema" 欄位。
# 為什麼：與 FEATURE_SCHEMA_VERSION 是兩回事——前者管檔案長怎樣，後者管特徵向量長怎樣；兩者都要對上才能載入。
# 對應：準則 #10；測試 tests/test_egress_release_grant.py::test_model_file_schema_is_checked
MODEL_FILE_SCHEMA = "aisoc/dual_model_file/v1"


# ── 【老師註解】CaseStatus ──────────────────────────────
# 做什麼：Table III 的六種案件狀態。每一個都對應一條「接下來誰要做什麼」的路。
#   KNOWN_SUSPICIOUS      ：已知分支有信心說是某攻擊家族 ⇒ 交給沙箱 agent 調查，不必先人審。
#   SUSPECTED_UNKNOWN     ：已知分支拒答（或只弱弱地說正常）但異常分數高 ⇒ 疑似零日，人審必要 + agent 調查。
#   MODEL_CONFLICT        ：已知分支很有信心說「正常」、異常分支卻說很不正常 ⇒ 兩個模型打架，不准自動關案，人審。
#   LOW_RISK_OBSERVE      ：資料齊全、看起來正常、異常低 ⇒ 只做漂移監控，不開案。
#   INSUFFICIENT_EVIDENCE ：已知分支拒答、異常也不高 ⇒ 證據不足，抽樣複核，不派 agent。
#   UNKNOWN               ：資料缺失或模型出錯 ⇒ 不猜、不當正常，直接人審。
# 為什麼：把「不知道」拆成 SUSPECTED_UNKNOWN / INSUFFICIENT_EVIDENCE / UNKNOWN 三種，人才知道該緊張、該補資料、還是該修系統。
# 對應：準則 #11、#12；測試 tests/test_dual_model.py::test_decision_table_covers_known_attack
class CaseStatus(str, Enum):
    KNOWN_SUSPICIOUS = "KNOWN_SUSPICIOUS"        # known attack class, evidence consistent
    SUSPECTED_UNKNOWN = "SUSPECTED_UNKNOWN"      # low confidence / reject + high anomaly
    MODEL_CONFLICT = "MODEL_CONFLICT"            # confident normal + high anomaly
    LOW_RISK_OBSERVE = "LOW_RISK_OBSERVE"        # normal, enough data, low anomaly
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"  # low confidence + low anomaly
    UNKNOWN = "UNKNOWN"                          # missing data / model failure


# ── 【老師註解】CaseDecision ──────────────────────────────
# 做什麼：一筆判定的完整紀錄：狀態、兩個分支各自的分數與門檻、是否拒答、要不要人審／派 agent、理由字串、特徵與模型版本。
# 為什麼：c_k、s_a、tau_a 分開存（而不是只存結論），人才能複核「為什麼是這個狀態」；model_version 讓帳本知道是哪個模型說的。
# 怎麼看：requires_human_review 與 requires_agent_investigation 是兩個獨立旗標，Table III 每一列都明確指定這兩個值。
# 拿掉會怎樣：只存狀態的話，一旦門檻改了就無法回溯舊案子當初為何被放過或被升級。
# 對應：準則 #11、#12；測試 tests/test_dual_model.py::test_scores_are_kept_separately
@dataclass
class CaseDecision:
    flow_id: str
    tenant: str
    status: CaseStatus
    known_label: Optional[str]
    known_score: Optional[float]
    known_rejected: Optional[bool]
    anomaly_score: Optional[float]
    anomaly_threshold: Optional[float]
    anomaly_high: Optional[bool]
    requires_human_review: bool
    requires_agent_investigation: bool
    reasons: List[str] = field(default_factory=list)
    feature_schema: str = FEATURE_SCHEMA_VERSION
    model_version: str = ""

    # ── 【老師註解】CaseDecision.to_dict / from_dict ──────────────────────────────
    # 做什麼：Enum 轉字串（及反向），讓 CaseDecision 能寫進 cases.json 與帳本摘要。
    # 對應：（此處無直接測試）
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CaseDecision":
        kw = dict(d)
        kw["status"] = CaseStatus(kw["status"])
        return cls(**kw)


# ── 【老師註解】ExternalKnown ──────────────────────────────
# 做什麼：由「外部偵測器」（例如 Slips 的一條 evidence）提供的已知分支結論，欄位與內部 KnownPrediction 對齊。
# 為什麼：Table III 的合成邏輯不該綁死在自家模型上；只要外部系統能給 label / score / rejected，就能走同一張表。
# 怎麼看：source 會被接到 model_version 後面（如 "dual_model/dev+slips/x"），帳本因此能看出這個結論是誰講的；
#   rejected=True 代表外部系統「分不出屬於哪一類」，仍然不是正常。
# 對應：準則 #11、#12；測試 tests/test_egress_release_grant.py::test_decide_external_combinations
@dataclass
class ExternalKnown:
    """Known-branch verdict produced outside this package (e.g. a Slips evidence line).

    ``label`` uses the same vocabulary as the internal known branch (``benign`` or
    an attack family); ``rejected`` means the producer could not place the event in
    any known class with sufficient confidence. ``source`` names the producing
    system/module so the decision stays attributable.
    """

    label: str
    score: float
    rejected: bool
    source: str
    technique: Optional[str] = None
    evidence_ids: List[str] = field(default_factory=list)


# ── 【老師註解】ExternalAnomaly ──────────────────────────────
# 做什麼：外部提供的異常分支訊號：分數、是否超過門檻（high）、來源、以及門檻本身（可省略）。
# 為什麼：外部系統（Slips ML 模組）的分數尺度和我們的 Isolation Forest 不同，所以由它自己說「高不高」，我們只負責記錄與合成。
# 怎麼看：threshold 為 None 時 decide_external 會補一個「與 high 布林值一致」的假門檻，純粹為了填欄位、不改判定。
# 對應：準則 #12；測試 tests/test_egress_release_grant.py::test_decide_external_combinations
@dataclass
class ExternalAnomaly:
    """Normality-branch signal produced outside this package (e.g. Slips ML/anomaly modules)."""

    score: float
    high: bool
    source: str
    threshold: Optional[float] = None


# ── 【老師註解】DualModel ──────────────────────────────
# 做什麼：把 scaler、已知分支、異常分支綁在一起的「一個模型製品」；提供 train / decide / 序列化。
# 為什麼：三者必須一起版本化、一起簽名——scaler 配錯任何一個分支，分數就全錯。
# 怎麼看：high_confidence_normal=0.9 是 MODEL_CONFLICT 的門檻：benign 分數 ≥ 0.9 才叫「有信心的正常」。
# 對應：準則 #10、#12（此處無直接測試）
@dataclass
class DualModel:
    scaler: StandardScaler
    known: KnownModel
    normality: NormalityModel
    model_version: str = "dual_model/dev"
    high_confidence_normal: float = 0.9

    # ── 【老師註解】DualModel.train ──────────────────────────────
    # 做什麼：訓練流程的唯一入口：scaler 在 train 上 fit → 已知分支在 train 上 fit、val 上校準 → 異常分支只在 train 的 benign 上 fit、tau_a 在 val 的 benign 上定。
    # 為什麼：這是整個專案唯一會讀 label 的地方。agent 的調查結論永遠不會回流成標籤（防止「自我強化」的汙染）。
    # 怎麼看：注意每一步用的是哪個切分——測試集從頭到尾不出現在這個函數裡，呼叫端也不該把它傳進來。
    # 拿掉會怎樣：若 scaler 或門檻碰到測試集，report.json 的 FPR/recall 就是漏題後的成績。
    # 對應：準則 #10、#12、#13；測試 tests/test_dual_model.py::test_thresholds_are_fit_only_on_train_and_val
    @classmethod
    def train(
        cls,
        train: Sequence[FlowRecord],
        val: Sequence[FlowRecord],
        tau_k: float = 0.7,
        anomaly_quantile: float = 0.995,
        model_version: str = "dual_model/dev",
    ) -> "DualModel":
        """Fit scaler, known branch and normality branch on train, tune on val.

        Labels are only consumed here. The test split must never be passed in.
        """
        # 步驟 1：特徵化訓練集；scaler 只在這裡 fit
        raw_train = [featurize(f) for f in train]
        scaler = StandardScaler().fit(raw_train)
        x_train = [scaler.transform(r) for r in raw_train]
        y_train = [f.label or BENIGN for f in train]

        # 步驟 2：已知分支在 train 上學權重
        known = KnownModel(tau_k=tau_k).fit(x_train, y_train)
        x_val = [scaler.transform(featurize(f)) for f in val]
        y_val = [f.label or BENIGN for f in val]
        # 步驟 3：溫度校準只用 val
        known.calibrate(x_val, y_val)

        # 步驟 4：異常分支只看 benign 的訓練列（學「正常」長怎樣）
        normal_train = [x for x, y in zip(x_train, y_train) if y == BENIGN]
        normality = NormalityModel(quantile=anomaly_quantile).fit(normal_train)
        # 步驟 5：tau_a 取自 val 的 benign，分服務群組
        val_normal = [(x, f.service_group) for x, f, y in zip(x_val, val, y_val) if y == BENIGN]
        normality.set_thresholds([x for x, _ in val_normal], [g for _, g in val_normal])

        return cls(scaler=scaler, known=known, normality=normality, model_version=model_version)

    # ── 【老師註解】DualModel.decide ──────────────────────────────
    # 做什麼：對一筆 FlowRecord 跑完兩個分支，把 c_k、s_a、tau_a 交給 _combine 合成 CaseStatus（論文 Table III）。
    # 為什麼：單一模型只能回答「像不像已知攻擊」；兩路分開才能把「不像已知、但很不正常」標成疑似零日。
    # 怎麼看：兩個提前返回都是 UNKNOWN——欄位缺失（準則 #11）與模型拋例外（例如未 fit、維度不符）。兩者都要求人審、不派 agent。
    # 拿掉會怎樣：少了 try/except，一個壞掉的模型會讓整條管線崩潰；少了欄位檢查，壞資料會被當成正常放行。
    # 對應：準則 #11、#12；測試 tests/test_dual_model.py::test_missing_data_is_unknown_not_normal
    def decide(self, flow: FlowRecord) -> CaseDecision:
        base = dict(flow_id=flow.flow_id, tenant=flow.tenant, model_version=self.model_version)
        # 步驟 1：資料缺失 ⇒ UNKNOWN，不猜
        if not flow.has_required_fields():
            return CaseDecision(
                status=CaseStatus.UNKNOWN,
                known_label=None, known_score=None, known_rejected=None,
                anomaly_score=None, anomaly_threshold=None, anomaly_high=None,
                requires_human_review=True, requires_agent_investigation=False,
                reasons=["missing required telemetry; not treated as normal"],
                **base,
            )
        # 步驟 2：特徵化 → 已知分支 → 異常分支 → 查這個服務群組的門檻
        try:
            x = self.scaler.transform(featurize(flow))
            kp = self.known.predict(x)
            s_a = self.normality.score(x)
            tau_a = self.normality.threshold_for(flow.service_group)
        except Exception as exc:  # model failure must surface as UNKNOWN, not normal
            return CaseDecision(
                status=CaseStatus.UNKNOWN,
                known_label=None, known_score=None, known_rejected=None,
                anomaly_score=None, anomaly_threshold=None, anomaly_high=None,
                requires_human_review=True, requires_agent_investigation=False,
                reasons=[f"model failure: {type(exc).__name__}"],
                **base,
            )

        # 步驟 3：套 Table III
        return self._combine(kp, s_a, tau_a, base, anomaly_source="internal")

    # ── 【老師註解】DualModel.decide_external ──────────────────────────────
    # 做什麼：已知分支由外部偵測器（Slips）供應時的 Table III 入口；異常分支依序選：內部模型（需 opt-in 且欄位齊）→ 外部訊號 → 都沒有。
    # 為什麼：Slips 跑在真實網路上，但我們的 Isolation Forest 是用合成資料練的，所以「內部異常分支」預設關閉，避免拿錯基線硬比。
    # 怎麼看：最後兩個分支要分清——外部有信心說是攻擊 ⇒ 仍可 KNOWN_SUSPICIOUS，但 reasons 記下「異常分支不可用」；
    #   外部拒答或說正常、又沒異常訊號 ⇒ UNKNOWN（不是 LOW_RISK_OBSERVE！），因為「沒看到」不等於「正常」。
    # 拿掉會怎樣：若最後一行改回正常，Slips 分不出來的流量就會被靜默關案。
    # 對應：準則 #11、#12；測試 tests/test_egress_release_grant.py::test_decide_external_combinations、tests/test_slips_adapter.py::test_internal_normality_only_used_when_opted_in_and_fields_present
    def decide_external(
        self,
        flow: FlowRecord,
        known: ExternalKnown,
        anomaly: Optional[ExternalAnomaly] = None,
        use_internal_normality: bool = False,
    ) -> CaseDecision:
        """Table III with the known branch supplied by an external detector.

        The normality branch is, in order of preference: this model's own
        normality model when ``use_internal_normality`` is set *and* the flow
        carries the volumetric fields (only meaningful if the model was trained
        on the same network); otherwise the external anomaly signal; otherwise
        *unknown*, which is never treated as normal.
        """
        # model_version 加上外部來源，帳本能看出是誰說的
        base = dict(flow_id=flow.flow_id, tenant=flow.tenant, model_version=f"{self.model_version}+{known.source}")
        # 把外部結論包成內部同款物件，之後走同一個 _combine
        kp = KnownPrediction(label=known.label, score=known.score, scores={known.label: known.score}, rejected=known.rejected)
        # 路徑 A：呼叫端明確要求、且欄位齊全，才用自家異常分支
        if use_internal_normality and flow.has_required_fields():
            try:
                x = self.scaler.transform(featurize(flow))
                s_a = self.normality.score(x)
                tau_a = self.normality.threshold_for(flow.service_group)
            except Exception as exc:
                return self._unknown(base, f"normality model failure: {type(exc).__name__}")
            return self._combine(kp, s_a, tau_a, base, anomaly_source="internal")
        # 路徑 B：用外部異常訊號；threshold 缺時補一個與 high 一致的值（只為填欄位）
        if anomaly is not None:
            tau = anomaly.threshold if anomaly.threshold is not None else (anomaly.score if anomaly.high else anomaly.score + 1.0)
            return self._combine(kp, anomaly.score, tau, base, anomaly_source=anomaly.source, high_override=anomaly.high)
        # 路徑 C：沒有異常分支，但外部有信心指認攻擊家族 ⇒ 仍可派 agent，並記下異常分支不可用
        if kp.label != BENIGN and not kp.rejected:
            # A confident known-attack verdict stands on its own; the missing normality branch is recorded.
            return CaseDecision(
                status=CaseStatus.KNOWN_SUSPICIOUS,
                known_label=kp.label, known_score=round(kp.score, 6), known_rejected=False,
                anomaly_score=None, anomaly_threshold=None, anomaly_high=None,
                requires_human_review=False, requires_agent_investigation=True,
                reasons=[f"known class {kp.label} from {known.source} with score {kp.score:.3f}", "normality branch unavailable"],
                **base,
            )
        # 路徑 D：什麼都不確定 ⇒ UNKNOWN，人審（絕不當成正常）
        return self._unknown(base, "known branch rejected/benign and no normality signal; not treated as normal",
                             known_label=kp.label, known_score=round(kp.score, 6), known_rejected=kp.rejected)

    # ── 【老師註解】DualModel._unknown ──────────────────────────────
    # 做什麼：組一個 UNKNOWN 的 CaseDecision：異常欄位全 None、強制人審、不派 agent；已知分支欄位可選擇性保留。
    # 為什麼：decide_external 有兩處要回 UNKNOWN，抽成一個函數確保兩處的旗標完全一致。
    # 對應：準則 #11；測試 tests/test_egress_release_grant.py::test_decide_external_combinations
    def _unknown(self, base: Dict[str, Any], reason: str, **known_fields: Any) -> CaseDecision:
        fields = dict(known_label=None, known_score=None, known_rejected=None)
        fields.update(known_fields)
        return CaseDecision(
            status=CaseStatus.UNKNOWN,
            anomaly_score=None, anomaly_threshold=None, anomaly_high=None,
            requires_human_review=True, requires_agent_investigation=False,
            reasons=[reason],
            **fields, **base,
        )

    # ── 【老師註解】DualModel._combine ──────────────────────────────
    # 做什麼：論文 Table III 的本體。輸入已知分支結論 kp、異常分數 s_a 與門檻 tau_a，依序比對六條規則，第一條符合的就是答案。
    # 為什麼：順序很重要——先問「已知分支有沒有把握」，再問「異常高不高」，最後才敢說「正常」。先排除危險，才能放行。
    # 怎麼看（由上到下）：
    #   ① 非 benign 且未拒答 ⇒ KNOWN_SUSPICIOUS（派 agent，不必人審）
    #   ② 拒答 且 異常高 ⇒ SUSPECTED_UNKNOWN（疑似零日：人審 + agent）
    #   ③ benign 且 c_k ≥ 0.9 且 異常高 ⇒ MODEL_CONFLICT（兩模型打架：人審 + agent，禁止自動關案）
    #   ④ benign 未拒答（但 c_k < 0.9）且 異常高 ⇒ SUSPECTED_UNKNOWN（弱正常 + 高異常，比照零日）
    #   ⑤ 拒答 且 異常低 ⇒ INSUFFICIENT_EVIDENCE（抽樣複核，不派 agent）
    #   ⑥ 其餘（benign、異常低）⇒ LOW_RISK_OBSERVE（只做漂移監控）
    #   high_override 讓外部異常訊號自己決定「高不高」，不用我們的 s_a >= tau_a 比法。
    # 拿掉會怎樣：少了②④，零日被硬塞進最接近的舊類別，人類永遠看不到；少了③，異常分支的警告會被自信的已知分支壓掉。
    # 對應：準則 #11、#12；測試 tests/test_dual_model.py::test_decision_table_covers_known_attack、tests/test_egress_release_grant.py::test_decide_external_combinations
    def _combine(
        self,
        kp: KnownPrediction,
        s_a: float,
        tau_a: float,
        base: Dict[str, Any],
        anomaly_source: str,
        high_override: Optional[bool] = None,
    ) -> CaseDecision:
        # 異常高低：內部用 s_a >= tau_a；外部訊號可直接覆寫
        high = (s_a >= tau_a) if high_override is None else high_override
        # 兩個分支的分數與門檻分開存，供人複核
        common = dict(
            known_label=kp.label, known_score=round(kp.score, 6), known_rejected=kp.rejected,
            anomaly_score=round(s_a, 6), anomaly_threshold=round(tau_a, 6), anomaly_high=high,
        )
        src = "" if anomaly_source == "internal" else f" ({anomaly_source})"

        # 規則 ①：已知分支有信心指認攻擊
        if kp.label != BENIGN and not kp.rejected:
            return CaseDecision(
                status=CaseStatus.KNOWN_SUSPICIOUS,
                requires_human_review=False, requires_agent_investigation=True,
                reasons=[f"known class {kp.label} with calibrated score {kp.score:.3f}"],
                **common, **base,
            )
        # 規則 ②：拒答 + 高異常 ⇒ 疑似零日
        if kp.rejected and high:
            return CaseDecision(
                status=CaseStatus.SUSPECTED_UNKNOWN,
                requires_human_review=True, requires_agent_investigation=True,
                reasons=["known branch rejected", f"anomaly {s_a:.3f} >= tau_a {tau_a:.3f}{src}"],
                **common, **base,
            )
        # 規則 ③：很有信心正常 vs 很異常 ⇒ 模型衝突
        if kp.label == BENIGN and kp.score >= self.high_confidence_normal and high:
            return CaseDecision(
                status=CaseStatus.MODEL_CONFLICT,
                requires_human_review=True, requires_agent_investigation=True,
                reasons=["confident normal but highly anomalous; must not auto-close" + src],
                **common, **base,
            )
        # 規則 ④：弱正常 + 高異常 ⇒ 比照疑似零日
        if kp.label == BENIGN and not kp.rejected and high:
            # benign but not highly confident, and anomalous: escalate like unknown
            return CaseDecision(
                status=CaseStatus.SUSPECTED_UNKNOWN,
                requires_human_review=True, requires_agent_investigation=True,
                reasons=["weakly-normal with high anomaly" + src],
                **common, **base,
            )
        # 規則 ⑤：拒答但不異常 ⇒ 證據不足
        if kp.rejected and not high:
            return CaseDecision(
                status=CaseStatus.INSUFFICIENT_EVIDENCE,
                requires_human_review=False, requires_agent_investigation=False,
                reasons=["low confidence, low anomaly; sample for review"],
                **common, **base,
            )
        # 規則 ⑥：其餘（benign、異常低）才是低風險觀察
        return CaseDecision(
            status=CaseStatus.LOW_RISK_OBSERVE,
            requires_human_review=False, requires_agent_investigation=False,
            reasons=["normal with sufficient data; drift monitoring only"],
            **common, **base,
        )

    # ── 【老師註解】DualModel.describe ──────────────────────────────
    # 做什麼：給人看的模型摘要（版本、特徵表、scaler、兩分支的設定），不含權重與樹。
    # 為什麼：report.json 與 CLI 用它說明「這批判定是哪個模型、哪組門檻做的」。
    # 對應：（此處無直接測試）
    def describe(self) -> Dict[str, Any]:
        return {
            "model_version": self.model_version,
            "feature_schema": FEATURE_SCHEMA_VERSION,
            "features": FEATURE_NAMES,
            "scaler": self.scaler.to_dict(),
            "known_branch": self.known.to_dict(),
            "normality_branch": self.normality.to_dict(),
            "high_confidence_normal": self.high_confidence_normal,
        }

    # ------------------------------------------------------------------ persistence
    # ── 【老師註解】DualModel.to_params ──────────────────────────────
    # 做什麼：完整、可還原的模型字典：檔案 schema、模型版本、特徵 schema、特徵名、衝突門檻、scaler、兩分支的全部參數。
    # 為什麼：這就是「模型製品」的內容；release.py 釘住的 SHA-256 是算在它的 canonical JSON 上。
    # 怎麼看："schema" 與 "feature_schema" 兩個字串是載入時的第一道與第二道門。
    # 對應：準則 #10；測試 tests/test_egress_release_grant.py::test_model_round_trips_through_bytes_with_identical_decisions
    def to_params(self) -> Dict[str, Any]:
        return {
            "schema": MODEL_FILE_SCHEMA,
            "model_version": self.model_version,
            "feature_schema": FEATURE_SCHEMA_VERSION,
            "features": FEATURE_NAMES,
            "high_confidence_normal": self.high_confidence_normal,
            "scaler": self.scaler.to_dict(),
            "known": self.known.to_params(),
            "normality": self.normality.to_params(),
        }

    # ── 【老師註解】DualModel.from_params ──────────────────────────────
    # 做什麼：從字典重建 DualModel，先檢查檔案 schema，再檢查特徵 schema，任一不符就 ValueError。
    # 為什麼：模型檔可能來自舊版程式、或被人改過；載入端「不信任檔名與路徑」，只信內容裡的宣告是否與本次建置一致。
    # 怎麼看：特徵 schema 不符的錯誤訊息直接說明原因（trained against a different feature schema），方便排錯。
    # 拿掉會怎樣：用 v0 特徵練的模型配 v1 的 featurize，維度或順序對不上，分數變亂數卻不會報錯。
    # 對應：準則 #10；測試 tests/test_egress_release_grant.py::test_model_file_schema_is_checked
    @classmethod
    def from_params(cls, p: Dict[str, Any]) -> "DualModel":
        # 第一道門：檔案格式版本
        if p.get("schema") != MODEL_FILE_SCHEMA:
            raise ValueError(f"unsupported model file schema {p.get('schema')!r}")
        # 第二道門：特徵 schema 必須與本次推論建置一致
        if p.get("feature_schema") != FEATURE_SCHEMA_VERSION:
            raise ValueError("model was trained against a different feature schema")
        return cls(
            scaler=StandardScaler.from_dict(p["scaler"]),
            known=KnownModel.from_params(p["known"]),
            normality=NormalityModel.from_params(p["normality"]),
            model_version=str(p["model_version"]),
            high_confidence_normal=float(p["high_confidence_normal"]),
        )

    # ── 【老師註解】DualModel.to_bytes ──────────────────────────────
    # 做什麼：to_params 轉成「鍵排序、無空白」的 JSON bytes——同一個模型永遠得到同一串位元組。
    # 為什麼：SHA-256 是對 bytes 算的；若 JSON 鍵順序或空白不固定，同一模型會有不同哈希，簽名就釘不住。
    # 對應：準則 #10；測試 tests/test_egress_release_grant.py::test_release_gate_accepts_only_exact_signed_artefact
    def to_bytes(self) -> bytes:
        """Canonical model artefact bytes; a release manifest pins their SHA-256."""
        return json.dumps(self.to_params(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    # ── 【老師註解】DualModel.from_bytes ──────────────────────────────
    # 做什麼：bytes → JSON → from_params（含兩道 schema 檢查）。
    # 為什麼：release.load_verified_model 在「哈希與簽名都驗過之後」才呼叫它；能解析不代表可信任。
    # 對應：準則 #10；測試 tests/test_egress_release_grant.py::test_model_round_trips_through_bytes_with_identical_decisions
    @classmethod
    def from_bytes(cls, data: bytes) -> "DualModel":
        return cls.from_params(json.loads(data.decode("utf-8")))

    # ── 【老師註解】DualModel.save / load ──────────────────────────────
    # 做什麼：to_bytes / from_bytes 的檔案版便利函數。
    # 為什麼：注意 load() 本身「沒有」驗簽名——推論端應該走 release.load_verified_model；這裡只是給訓練域存檔用。
    # 對應：準則 #10（此處無直接測試）
    def save(self, path: Union[str, Path]) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.to_bytes())
        return path

    @classmethod
    def load(cls, path: Union[str, Path]) -> "DualModel":
        return cls.from_bytes(Path(path).read_bytes())
