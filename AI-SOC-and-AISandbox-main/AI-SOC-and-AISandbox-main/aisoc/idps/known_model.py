"""Known-pattern branch f_k(x): one-vs-rest logistic regression (pure Python).

Outputs a class label and a per-class calibrated score. Temperature scaling is
fit on the validation split; the reject threshold tau_k is a hyper-parameter
chosen on validation data, never on the test split.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple

BENIGN = "benign"


# ── 【老師註解】_sigmoid ──────────────────────────────
# 做什麼：標準 S 型函數 1/(1+e^−z)，把任意實數壓到 (0,1) 當作機率。
# 為什麼：寫成兩個分支是數值穩定技巧——z 很負時直接算 exp(−z) 會溢位，改算 exp(z) 就安全。
# 拿掉會怎樣：訓練初期權重亂跳時可能出現 OverflowError，整個 fit 中斷。
# 對應：（此處無直接測試）
def _sigmoid(z: float) -> float:
    if z >= 0:
        ez = math.exp(-z)
        return 1.0 / (1.0 + ez)
    ez = math.exp(z)
    return ez / (1.0 + ez)


# ── 【老師註解】KnownPrediction ──────────────────────────────
# 做什麼：已知分支的單筆輸出：預測類別 label、該類別的校準分數 score（即論文的 c_k）、全部類別的分數表、以及是否「拒答」。
# 為什麼：下游 Table III 不只看 label，還要看 score 夠不夠高、有沒有 rejected；三者分開存才能稽核。
# 怎麼看：rejected=True 表示 c_k < tau_k，意思是「我不確定這屬於任何已知類別」——不是「正常」。
# 對應：準則 #12；測試 tests/test_dual_model.py::test_scores_are_kept_separately
@dataclass
class KnownPrediction:
    label: str
    score: float  # calibrated probability of the predicted label
    scores: Dict[str, float]
    rejected: bool


# ── 【老師註解】KnownModel ──────────────────────────────
# 做什麼：論文的已知攻擊分支 f_k：一對多（one-vs-rest）邏輯迴歸，純 Python 實作，不依賴 sklearn。
# 為什麼：選這麼簡單的模型是為了讓參考實作可讀、可重現、可完整序列化；重點在「校準 + 拒答」的機制，不在模型強弱。
# 怎麼看：weights/bias 每個類別一組；temperature 是校準溫度（calibrate 學到）；tau_k 是拒答門檻（超參數，驗證集上選，絕不碰測試集）。
# 拿掉會怎樣：沒有 tau_k 的分類器對任何輸入都會「硬選一個最像的類別」，零日攻擊就被塞進某個舊類別裡消失了。
# 對應：準則 #12、#13（此處無直接測試）
@dataclass
class KnownModel:
    classes: List[str] = field(default_factory=list)
    weights: Dict[str, List[float]] = field(default_factory=dict)
    bias: Dict[str, float] = field(default_factory=dict)
    temperature: float = 1.0
    tau_k: float = 0.7
    lr: float = 0.1
    epochs: int = 60
    l2: float = 1e-3
    seed: int = 7

    # ── 【老師註解】KnownModel.fit ──────────────────────────────
    # 做什麼：對每一個類別各訓練一個二元邏輯迴歸（該類 vs 其他），用隨機梯度下降跑 epochs 輪。
    # 為什麼：OvR 讓「新增一個攻擊家族」只是多一組權重；而且每類獨立的 logit 之後可以一起做 softmax 校準。
    # 怎麼看：g 是預測機率與目標的差（梯度）；w[j] 更新裡的 self.l2 * w[j] 是 L2 正則化，防止權重無限膨脹。
    # 拿掉會怎樣：沒有 L2，少數可完美分開的特徵會讓權重爆大、機率全變 0/1，之後的溫度校準就救不回來。
    # 對應：準則 #13（合成資料、簡化模型）；測試 tests/test_dual_model.py::test_decision_table_covers_known_attack
    def fit(self, x: Sequence[Sequence[float]], y: Sequence[str]) -> "KnownModel":
        rng = random.Random(self.seed)
        # 類別排序固定，確保序列化後順序可重現
        self.classes = sorted(set(y))
        d = len(x[0])
        idx = list(range(len(x)))
        # 步驟 1：每個類別各練一個「是／不是」分類器
        for cls in self.classes:
            w = [0.0] * d
            b = 0.0
            # 本類別為 1、其他類別為 0
            target = [1.0 if label == cls else 0.0 for label in y]
            # 步驟 2：SGD 多輪，每輪打亂樣本順序
            for _ in range(self.epochs):
                rng.shuffle(idx)
                for i in idx:
                    z = b + sum(wj * xj for wj, xj in zip(w, x[i]))
                    # 梯度 = 預測機率 − 真值
                    g = _sigmoid(z) - target[i]
                    # 步驟 3：權重更新（含 L2 正則）
                    for j in range(d):
                        w[j] -= self.lr * (g * x[i][j] + self.l2 * w[j])
                    b -= self.lr * g
            self.weights[cls] = w
            self.bias[cls] = b
        return self

    # ── 【老師註解】KnownModel._logits ──────────────────────────────
    # 做什麼：算每個類別的線性分數 b + w·x（還沒經過機率轉換）。
    # 為什麼：把線性部分獨立出來，_probs 才能在上面套「溫度」而不動權重。
    # 對應：（此處無直接測試）
    def _logits(self, row: Sequence[float]) -> Dict[str, float]:
        return {
            cls: self.bias[cls] + sum(wj * xj for wj, xj in zip(self.weights[cls], row))
            for cls in self.classes
        }

    # ── 【老師註解】KnownModel._probs ──────────────────────────────
    # 做什麼：把各類 logit 除以 temperature 後做 softmax，得到加總為 1 的類別機率。
    # 為什麼：這就是「溫度縮放」校準——T>1 把機率拉平（模型太自信時用），T<1 把機率拉尖。校準後的最大機率才配叫 c_k。
    # 怎麼看：先減掉最大值 m 再取 exp，是避免溢位的標準寫法，不影響結果。
    # 拿掉會怎樣：未校準的 softmax 常常給 0.99 的假自信，tau_k 門檻就形同虛設。
    # 對應：準則 #12（此處無直接測試）
    def _probs(self, row: Sequence[float]) -> Dict[str, float]:
        logits = self._logits(row)
        # 減最大值防溢位；除以溫度做校準
        m = max(logits.values())
        exps = {c: math.exp((v - m) / self.temperature) for c, v in logits.items()}
        s = sum(exps.values())
        return {c: v / s for c, v in exps.items()}

    # ── 【老師註解】KnownModel.calibrate ──────────────────────────────
    # 做什麼：在驗證集上格點搜尋溫度 T ∈ {0.5 … 4.0}，選讓負對數概似（NLL）最小的那個。
    # 為什麼：訓練集上模型一定過度自信，所以校準必須用「沒練過」的驗證集；測試集則留著做最終量測，絕不拿來調任何東西。
    # 怎麼看：NLL 越小代表「模型說 70% 的事大約真的 70% 會發生」；回傳值 best_t 會被寫進模型檔。
    # 拿掉會怎樣：c_k 不可信 ⇒ tau_k 的拒答判斷不可信 ⇒ Table III 整張表的前提崩掉。
    # 對應：準則 #12、#13；測試 tests/test_dual_model.py::test_thresholds_are_fit_only_on_train_and_val
    def calibrate(self, x_val: Sequence[Sequence[float]], y_val: Sequence[str]) -> float:
        """Grid-search a softmax temperature minimising NLL on the validation split."""
        best_t, best_nll = 1.0, float("inf")
        # 試每一個候選溫度
        for t in [0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 4.0]:
            self.temperature = t
            nll = 0.0
            for row, label in zip(x_val, y_val):
                p = self._probs(row).get(label, 1e-9)
                # 累加 −log p(正確類別)；1e-9 防 log(0)
                nll -= math.log(max(p, 1e-9))
            if nll < best_nll:
                best_t, best_nll = t, nll
        # 留下最好的溫度
        self.temperature = best_t
        return best_t

    # ── 【老師註解】KnownModel.predict ──────────────────────────────
    # 做什麼：取機率最高的類別當 label，其機率當 c_k；若 c_k < tau_k 就標記 rejected（拒答）。
    # 為什麼：這是論文「reject option」的落點——模型有權說「我不知道」，而不是硬給答案。
    # 怎麼看：rejected 只是一個旗標，label 仍會保留，讓人看到「它最接近哪一類、但不夠像」。
    # 拿掉會怎樣：零日流量永遠會被貼上某個舊家族標籤，SUSPECTED_UNKNOWN 這條路就不可能被走到。
    # 對應：準則 #12；測試 tests/test_dual_model.py::test_leave_one_family_out_escalates_unseen_family_somewhere
    def predict(self, row: Sequence[float]) -> KnownPrediction:
        probs = self._probs(row)
        label, score = max(probs.items(), key=lambda kv: kv[1])
        return KnownPrediction(label=label, score=score, scores=probs, rejected=score < self.tau_k)

    # ── 【老師註解】KnownModel.to_dict ──────────────────────────────
    # 做什麼：只輸出「描述性」設定（類別、溫度、tau_k、超參數），不含權重；給 describe() 和稽核報表看。
    # 為什麼：讓人能一眼確認門檻與溫度，而不用翻幾百個浮點數。
    # 對應：（此處無直接測試）
    def to_dict(self) -> Dict[str, object]:
        return {
            "type": "ovr_logistic_regression",
            "classes": self.classes,
            "temperature": self.temperature,
            "tau_k": self.tau_k,
            "epochs": self.epochs,
            "lr": self.lr,
            "l2": self.l2,
        }

    # ── 【老師註解】KnownModel.to_params ──────────────────────────────
    # 做什麼：to_dict 再加上 weights / bias / seed，成為「可完整還原」的參數集。
    # 為什麼：發佈清單釘住的 SHA-256 是算在這個完整集合上；漏掉任何一項，載入後的模型就不是同一個模型。
    # 對應：準則 #10；測試 tests/test_egress_release_grant.py::test_model_round_trips_through_bytes_with_identical_decisions
    def to_params(self) -> Dict[str, object]:
        """Complete, loadable parameter set (what a release manifest must pin)."""
        d = self.to_dict()
        d.update({"weights": self.weights, "bias": self.bias, "seed": self.seed})
        return d

    # ── 【老師註解】KnownModel.from_params ──────────────────────────────
    # 做什麼：從參數字典重建 KnownModel；先驗 type 欄位，不是 ovr_logistic_regression 就拒絕。
    # 為什麼：載入端不能假設檔案一定是自己寫的；型別不符就報錯，而不是硬塞進欄位。
    # 怎麼看：每個欄位都顯式轉型（float/int/list），避免 JSON 帶進來的奇怪型別默默留下。
    # 對應：準則 #10、#11；測試 tests/test_egress_release_grant.py::test_model_file_schema_is_checked
    @classmethod
    def from_params(cls, p: Dict[str, object]) -> "KnownModel":
        # 第一道門：模型型別要對
        if p.get("type") != "ovr_logistic_regression":
            raise ValueError("unsupported known-model type")
        return cls(
            classes=list(p["classes"]),  # type: ignore[arg-type]
            weights={k: [float(v) for v in ws] for k, ws in dict(p["weights"]).items()},  # type: ignore[arg-type]
            bias={k: float(v) for k, v in dict(p["bias"]).items()},  # type: ignore[arg-type]
            temperature=float(p["temperature"]),  # type: ignore[arg-type]
            tau_k=float(p["tau_k"]),  # type: ignore[arg-type]
            lr=float(p["lr"]),  # type: ignore[arg-type]
            epochs=int(p["epochs"]),  # type: ignore[arg-type]
            l2=float(p["l2"]),  # type: ignore[arg-type]
            seed=int(p.get("seed", 7)),  # type: ignore[arg-type]
        )
