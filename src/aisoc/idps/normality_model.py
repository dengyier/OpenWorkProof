"""Normality branch f_a(x): Isolation Forest implemented in pure Python.

The model is fit on *vetted normal windows only*. The anomaly threshold tau_a
is taken from a quantile of validation-normal scores (per service group when
enough data exists). The 99.5 quantile is a development starting point, not a
deployment FPR guarantee.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence


# ── 【老師註解】_c ──────────────────────────────
# 做什麼：Isolation Forest 論文的正規化常數 c(n)：在 n 個點的隨機二元樹裡，一次「找不到的搜尋」的平均路徑長。
# 為什麼：score() 要把平均路徑長 e 除以 c(n)，分數才會落在 (0,1) 且不受樣本數影響。
# 怎麼看：0.5772… 是歐拉常數（調和數的近似）；n<=1 時回 0，因為單點樹沒有路徑可言。
# 拿掉會怎樣：換一個 sample_size，所有分數的尺度都變，之前選好的 tau_a 就全錯了。
# 對應：（此處無直接測試）
def _c(n: int) -> float:
    if n <= 1:
        return 0.0
    h = math.log(n - 1) + 0.5772156649
    return 2.0 * h - 2.0 * (n - 1) / n


# ── 【老師註解】_Node ──────────────────────────────
# 做什麼：一棵隔離樹的節點：切哪一維 (feature)、切在哪 (split)、左右子樹、以及落到這裡的樣本數 size。
# 為什麼：__slots__ 省記憶體——60 棵樹、每棵上百節點，全部要序列化進模型檔。
# 怎麼看：left 與 right 同時為 None 代表葉節點；葉節點的 size 會用在 _path_length 的 c(size) 補償。
# 對應：（此處無直接測試）
class _Node:
    __slots__ = ("feature", "split", "left", "right", "size")

    def __init__(self) -> None:
        self.feature: int = -1
        self.split: float = 0.0
        self.left: Optional["_Node"] = None
        self.right: Optional["_Node"] = None
        self.size: int = 0


# ── 【老師註解】_build ──────────────────────────────
# 做什麼：遞迴建一棵隔離樹：隨機挑一個「還有變化」的維度、在其 [min,max] 間隨機切一刀，左右各自再切。
# 為什麼：隔離樹的直覺是「異常點很孤立，幾刀就切開；正常點擠在一起，要切很多刀」。所以路徑越短越可疑。
# 怎麼看：停止條件有三：達到 max_depth、只剩 ≤1 筆、或所有維度都是常數（candidates 為空）。
# 拿掉會怎樣：少了 candidates 過濾，rng.uniform(lo, hi) 在 lo==hi 時會切出永遠一邊空的無效節點。
# 對應：（此處無直接測試）
def _build(rows: List[Sequence[float]], depth: int, max_depth: int, rng: random.Random) -> _Node:
    node = _Node()
    node.size = len(rows)
    # 停止條件 1、2：太深，或樣本只剩一筆
    if depth >= max_depth or len(rows) <= 1:
        return node
    d = len(rows[0])
    # 只挑「有差異」的維度來切
    candidates = [j for j in range(d) if min(r[j] for r in rows) < max(r[j] for r in rows)]
    # 停止條件 3：全是常數，切不開
    if not candidates:
        return node
    j = rng.choice(candidates)
    lo = min(r[j] for r in rows)
    hi = max(r[j] for r in rows)
    # 隨機切點
    split = rng.uniform(lo, hi)
    node.feature = j
    node.split = split
    # 遞迴：小於切點去左、其餘去右
    node.left = _build([r for r in rows if r[j] < split], depth + 1, max_depth, rng)
    node.right = _build([r for r in rows if r[j] >= split], depth + 1, max_depth, rng)
    return node


# ── 【老師註解】_path_length ──────────────────────────────
# 做什麼：沿著一棵樹往下走，回傳某筆資料到達葉節點的深度（加上葉節點內部的估計 c(size)）。
# 為什麼：葉節點可能還有多筆樣本沒切完（受 max_depth 限制），加 c(size) 是補估「如果繼續切還要幾刀」。
# 怎麼看：回傳值越小 ⇒ 越容易被隔離 ⇒ 越像異常。
# 對應：（此處無直接測試）
def _path_length(node: _Node, row: Sequence[float], depth: int = 0) -> float:
    if node.left is None or node.right is None:
        return depth + _c(node.size)
    if row[node.feature] < node.split:
        return _path_length(node.left, row, depth + 1)
    return _path_length(node.right, row, depth + 1)


# ── 【老師註解】NormalityModel ──────────────────────────────
# 做什麼：論文的正常性／異常分支 f_a：純 Python 的 Isolation Forest，外加「每個服務群組一個門檻 tau_a」。
# 為什麼只用乾淨（正常）資料：這個分支的任務是學「什麼叫正常」，再把偏離基線的東西挑出來；
#   如果訓練時混進攻擊樣本，攻擊會被當成基線的一部分，之後同型的攻擊就再也不「異常」了。
#   更重要的是它不需要任何攻擊標籤，所以對「從沒見過的攻擊家族」（零日）也有機會反應。
# 怎麼看：tau_a 是字典，鍵是 service_group（web/db/…），"default" 是後備；quantile=0.995 只是開發起點，不是部署 FPR 保證。
# 拿掉會怎樣：只剩已知分支 ⇒ 零日攻擊要嘛被硬分類、要嘛被拒答後無人理會，SUSPECTED_UNKNOWN 永遠不會亮。
# 對應：準則 #12、#13；測試 tests/test_dual_model.py::test_leave_one_family_out_escalates_unseen_family_somewhere
@dataclass
class NormalityModel:
    n_trees: int = 60
    sample_size: int = 128
    seed: int = 11
    trees: List[_Node] = field(default_factory=list)
    tau_a: Dict[str, float] = field(default_factory=dict)  # per service group, "default" fallback
    quantile: float = 0.995
    _sample_n: int = 0

    # ── 【老師註解】NormalityModel.fit ──────────────────────────────
    # 做什麼：用 n_trees 棵樹，每棵從「正常樣本」中隨機抽 sample_size 筆來建樹。
    # 為什麼：呼叫端（DualModel.train）只會傳 label == benign 的訓練列進來——見上方「為什麼只用乾淨資料」。
    # 怎麼看：max_depth = ceil(log2(n)) 是 Isolation Forest 的標準設定；_sample_n 存下來給 score() 的 c(n) 用。
    # 拿掉會怎樣：不記 _sample_n，序列化再載回後分數尺度會對不上，tau_a 就失效。
    # 對應：準則 #10（此處無直接測試）
    def fit(self, x_normal: Sequence[Sequence[float]]) -> "NormalityModel":
        rng = random.Random(self.seed)
        rows = [list(r) for r in x_normal]
        # 每棵樹的子樣本大小（資料不夠就全用）
        n = min(self.sample_size, len(rows))
        self._sample_n = n
        max_depth = int(math.ceil(math.log2(max(n, 2))))
        # 建 n_trees 棵樹，每棵各自隨機抽樣
        self.trees = [_build(rng.sample(rows, n), 0, max_depth, rng) for _ in range(self.n_trees)]
        return self

    # ── 【老師註解】NormalityModel.score ──────────────────────────────
    # 做什麼：算論文的異常分數 s_a = 2^(−E[h(x)] / c(n))，E[h] 是在所有樹上的平均路徑長。
    # 為什麼：這個公式把「路徑短」映成「分數接近 1」、「路徑長」映成「接近 0」，且與樣本數無關，才能跨模型比較門檻。
    # 怎麼看：s_a ≥ tau_a 視為「偏離基線」；未 fit 就呼叫會丟 RuntimeError，讓 DualModel.decide 轉成 UNKNOWN 而不是假正常。
    # 對應：準則 #11、#12；測試 tests/test_dual_model.py::test_scores_are_kept_separately
    def score(self, row: Sequence[float]) -> float:
        if not self.trees:
            raise RuntimeError("normality model not fitted")
        # 平均路徑長 → 正規化 → 2 的負次方
        e = sum(_path_length(t, row) for t in self.trees) / len(self.trees)
        return 2.0 ** (-e / max(_c(self._sample_n), 1e-9))

    # ── 【老師註解】NormalityModel.set_thresholds ──────────────────────────────
    # 做什麼：在「驗證集的正常樣本」上算分數，取第 quantile 分位數當 tau_a；資料夠多的服務群組再各自算一個。
    # 為什麼：web 伺服器和資料庫的「正常」長得不一樣，共用一個門檻會讓其中一邊誤報偏高；每群一條線更貼近實際。
    #   門檻只用驗證集（而非訓練集）是因為訓練樣本的分數天生偏低，用它定門檻會太鬆。
    # 怎麼看：min_group_size=50 以下的群組不另設門檻，退回 "default"——樣本太少算出來的分位數不可靠。
    # 拿掉會怎樣：若在測試集上選門檻，報告裡的 FPR 就是「調出來的」而非「量出來的」，數字不誠實。
    # 對應：準則 #12、#13；測試 tests/test_dual_model.py::test_thresholds_are_fit_only_on_train_and_val
    def set_thresholds(
        self,
        x_val_normal: Sequence[Sequence[float]],
        groups: Optional[Sequence[str]] = None,
        min_group_size: int = 50,
    ) -> Dict[str, float]:
        # 步驟 1：驗證集正常樣本的分數
        scores = [self.score(r) for r in x_val_normal]
        # 步驟 2：全體分位數 = 後備門檻
        self.tau_a = {"default": _quantile(scores, self.quantile)}
        # 步驟 3：樣本夠多的服務群組各自一條門檻
        if groups is not None:
            by_group: Dict[str, List[float]] = {}
            for s, g in zip(scores, groups):
                by_group.setdefault(g, []).append(s)
            for g, vals in by_group.items():
                if len(vals) >= min_group_size:
                    self.tau_a[g] = _quantile(vals, self.quantile)
        return self.tau_a

    # ── 【老師註解】NormalityModel.threshold_for ──────────────────────────────
    # 做什麼：查某個服務群組的 tau_a；查不到用 "default"；連 default 都沒有就回 1.0。
    # 為什麼：1.0 是分數的理論上限，意思是「沒設門檻時什麼都不算異常」——這是刻意保守，也提醒你一定要先呼叫 set_thresholds。
    # 對應：（此處無直接測試）
    def threshold_for(self, group: str) -> float:
        return self.tau_a.get(group, self.tau_a.get("default", 1.0))

    # ── 【老師註解】NormalityModel.is_anomalous ──────────────────────────────
    # 做什麼：score(row) >= threshold_for(group) 的布林捷徑。
    # 為什麼：DualModel 其實不用這個——它把 s_a 與 tau_a 分開記進 CaseDecision 讓人能複核；這個函數只是方便外部呼叫。
    # 對應：準則 #12（此處無直接測試）
    def is_anomalous(self, row: Sequence[float], group: str = "default") -> bool:
        return self.score(row) >= self.threshold_for(group)

    # ── 【老師註解】NormalityModel.to_dict ──────────────────────────────
    # 做什麼：只輸出描述性設定（樹數、抽樣大小、分位數、各群門檻），不含樹本身；給 describe() 與報表看。
    # 對應：（此處無直接測試）
    def to_dict(self) -> Dict[str, object]:
        return {
            "type": "isolation_forest",
            "n_trees": self.n_trees,
            "sample_size": self.sample_size,
            "quantile": self.quantile,
            "tau_a": self.tau_a,
        }

    # ── 【老師註解】NormalityModel.to_params ──────────────────────────────
    # 做什麼：to_dict 再加上 seed、sample_n 與「每一棵樹的每一刀」，成為可完整還原的參數集。
    # 為什麼：發佈清單釘住的 SHA-256 是算在這個完整集合上；少了任一棵樹，載回來的森林就不是同一座。
    # 對應：準則 #10；測試 tests/test_egress_release_grant.py::test_model_round_trips_through_bytes_with_identical_decisions
    def to_params(self) -> Dict[str, object]:
        """Complete, loadable parameter set including every tree."""
        d = self.to_dict()
        d.update({"seed": self.seed, "sample_n": self._sample_n, "trees": [_node_to_dict(t) for t in self.trees]})
        return d

    # ── 【老師註解】NormalityModel.from_params ──────────────────────────────
    # 做什麼：從參數字典重建森林；先驗 type 是 isolation_forest，再逐欄顯式轉型，最後遞迴還原每棵樹。
    # 為什麼：載入端不信任檔案來源；型別不符就報錯，而不是硬塞。sample_n 一定要還原，否則 score() 的 c(n) 尺度會錯。
    # 對應：準則 #10；測試 tests/test_egress_release_grant.py::test_model_round_trips_through_bytes_with_identical_decisions
    @classmethod
    def from_params(cls, p: Dict[str, object]) -> "NormalityModel":
        # 第一道門：模型型別要對
        if p.get("type") != "isolation_forest":
            raise ValueError("unsupported normality-model type")
        m = cls(
            n_trees=int(p["n_trees"]),  # type: ignore[arg-type]
            sample_size=int(p["sample_size"]),  # type: ignore[arg-type]
            seed=int(p.get("seed", 11)),  # type: ignore[arg-type]
            quantile=float(p["quantile"]),  # type: ignore[arg-type]
            tau_a={k: float(v) for k, v in dict(p["tau_a"]).items()},  # type: ignore[arg-type]
        )
        m._sample_n = int(p["sample_n"])  # type: ignore[arg-type]
        m.trees = [_node_from_dict(t) for t in list(p["trees"])]  # type: ignore[arg-type]
        return m


# ── 【老師註解】_node_to_dict ──────────────────────────────
# 做什麼：把一棵樹遞迴轉成巢狀字典；葉節點只存 size，內部節點多存 feature / split / left / right。
# 為什麼：模型檔必須含每一棵樹的每一刀，否則載回來的森林不是同一座，SHA-256 釘死就沒有意義。
# 對應：準則 #10；測試 tests/test_egress_release_grant.py::test_model_round_trips_through_bytes_with_identical_decisions
def _node_to_dict(n: _Node) -> Dict[str, object]:
    d: Dict[str, object] = {"size": n.size}
    if n.left is not None and n.right is not None:
        d.update({"feature": n.feature, "split": n.split, "left": _node_to_dict(n.left), "right": _node_to_dict(n.right)})
    return d


# ── 【老師註解】_node_from_dict ──────────────────────────────
# 做什麼：_node_to_dict 的反向；用「有沒有 left 鍵」判斷是內部節點還是葉節點。
# 對應：準則 #10（此處無直接測試）
def _node_from_dict(d: Dict[str, object]) -> _Node:
    n = _Node()
    n.size = int(d["size"])  # type: ignore[arg-type]
    if "left" in d:
        n.feature = int(d["feature"])  # type: ignore[arg-type]
        n.split = float(d["split"])  # type: ignore[arg-type]
        n.left = _node_from_dict(d["left"])  # type: ignore[arg-type]
        n.right = _node_from_dict(d["right"])  # type: ignore[arg-type]
    return n


# ── 【老師註解】_quantile ──────────────────────────────
# 做什麼：線性內插的分位數：排序後找位置 (n−1)·q，落在兩個值之間就按比例混合。
# 為什麼：不依賴 numpy；q=0.995 在 240 筆資料上大約落在倒數第 2 名附近，樣本太少時門檻會很不穩——這正是 min_group_size 存在的原因。
# 怎麼看：空清單回 1.0（最嚴格、等於「不設門檻」），與 threshold_for 的後備值一致。
# 對應：（此處無直接測試）
def _quantile(values: Sequence[float], q: float) -> float:
    if not values:
        return 1.0
    s = sorted(values)
    pos = (len(s) - 1) * q
    lo = int(math.floor(pos))
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)
