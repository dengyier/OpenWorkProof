"""Tamper-evident ledger: hash chain + Merkle checkpoints + external witness.

The ledger stores *digests and relational metadata only*. Sensitive raw content
is kept in a separate ``EncryptedEvidenceStore`` so that retention / deletion
policy can be applied to originals without breaking the commitment chain.

What this provides: detection of modification, truncation and forking relative
to a witnessed checkpoint. What it cannot provide: discovery of actions that
were never recorded. That gap is addressed by reconciliation against the
independent tool-side log (see ``verifier.py``).
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..canonical import canonical_bytes, digest, sha256_hex
from ..crypto import Clock, Ed25519Signer, TrustedKeys

GENESIS = "sha256:" + "0" * 64


# ── 【老師註解】LedgerEntry ───────────────────────────────────────
# 做什麼：帳本的一「環」。注意它只存 object_digest（物件的指紋）和 refs（引用），不存物件本身。
# 為什麼：帳本要能公開給監管者、能永久保存；若存原文就會洩漏流量內容，也無法依法刪除個資。
#         存指紋就夠了——誰想證明「當年提交的就是這份」，拿原文重算指紋比對即可。
# 怎麼看：entry_hash = digest(body)，而 body 裡含 prev_hash（前一環的 entry_hash），這就是「鏈」——
#         改第 5 環任何一個字元，第 5 環的 entry_hash 就變，第 6 環記的 prev_hash 立刻對不上。
# 對應：準則 #7；測試 tests/test_ledger_verifier.py::test_modification_detected
@dataclass
class LedgerEntry:
    index: int
    entry_type: str
    case_id: str
    object_digest: str
    refs: Dict[str, str]
    recorded_at: str
    prev_hash: str
    entry_hash: str = ""

    def body(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "entry_type": self.entry_type,
            "case_id": self.case_id,
            "object_digest": self.object_digest,
            "refs": self.refs,
            "recorded_at": self.recorded_at,
            "prev_hash": self.prev_hash,
        }

    def compute_hash(self) -> str:
        return digest(self.body())

    def to_dict(self) -> Dict[str, Any]:
        d = self.body()
        d["entry_hash"] = self.entry_hash
        return d


# ── 【老師註解】merkle_root ───────────────────────────────────────
# 做什麼：把一串 entry_hash 兩兩配對、逐層相加再哈希，最後收斂成一個根（root）。奇數時複製最後一個補齊。
# 為什麼：外部見證不需要保存整本帳，只要存一個 32 位元組的根；之後任何一環被改，重算的根就不同。
#         比起只存「最後一環的哈希」，Merkle 根讓以後可以做「只證明某一環存在」的小證明（本專案尚未用到）。
# 拿掉會怎樣：見證只能比對 head_hash，仍可抓竄改，但失去未來做局部證明的能力。
# 對應：準則 #7；測試 tests/test_ledger_verifier.py::test_merkle_root_edge_cases
def merkle_root(hashes: List[str]) -> str:
    if not hashes:
        return GENESIS
    layer = [h.split(":", 1)[1] for h in hashes]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [sha256_hex(bytes.fromhex(layer[i]) + bytes.fromhex(layer[i + 1])) for i in range(0, len(layer), 2)]
    return "sha256:" + layer[0]


# ── 【老師註解】ExternalWitness ───────────────────────────────────
# 做什麼：「外部見證人」——由另一位管理員控制、只能追加（append-only）的檢查點儲存，實作成 JSONL 檔。
# 為什麼：哈希鏈本身擋不住「帳本管理員整本重寫」：他可以改內容後把每一環哈希重算一遍。
#         唯一的辦法是把每個檢查點交給「他改不到」的第三方保存；之後對不上就是鐵證。
# 怎麼看：publish() 只會 open(..., "a") 追加，從不覆寫。測試會檢查檔案確實只增不改。
# 誠實提醒：程式碼只能提供 append-only 介面；「第三方真的獨立」是組織上的安排，不是程式能保證的（準則 #13）。
# 對應：準則 #7、#8；測試 tests/test_ledger_verifier.py::test_witness_file_is_append_only_jsonl
class ExternalWitness:
    """Append-only checkpoint store operated by a *different* administrator.

    Backed by a JSONL file when ``path`` is given, otherwise in memory. The
    separation of duties is organisational; this class only provides the
    append-only interface and the verification helper.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path
        self._mem: List[Dict[str, Any]] = []
        if path is not None and path.exists():
            self._mem = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def publish(self, checkpoint: Dict[str, Any]) -> None:
        self._mem.append(checkpoint)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(checkpoint, sort_keys=True) + "\n")

    def checkpoints(self) -> List[Dict[str, Any]]:
        return list(self._mem)


# ── 【老師註解】HashChainLedger ───────────────────────────────────
# 做什麼：整個系統的「只增不改」帳本。所有子系統（出口代理、政策、簽名器、PEP、驗證器）都往這裡 append。
# 為什麼：論文的可問責性建立在「每一步都留下不可抹去的紀錄」；這個類別就是那本紀錄。
# 怎麼看：append() 造鏈、checkpoint() 定期把 Merkle 根簽名後送外部見證、verify_chain() 自我檢查、
#         verify_against_witness() 和外部見證比對。threading.Lock 保證兩個執行緒不會寫出同一個 index。
# 對應：準則 #7；測試 tests/test_ledger_verifier.py::test_chain_and_witness_ok
class HashChainLedger:
    def __init__(self, signer: Ed25519Signer, clock: Clock, witness: Optional[ExternalWitness] = None) -> None:
        self.signer = signer
        self.clock = clock
        self.witness = witness
        self.entries: List[LedgerEntry] = []
        self._lock = threading.Lock()

    # ── 【老師註解】HashChainLedger.append ────────────────────────
    # 做什麼：新增一環：拿前一環的 entry_hash 當 prev_hash，算出物件指紋，蓋上時間戳，再算自己的 entry_hash。
    # 為什麼：obj 本身不存進帳本，只存 digest(obj)——這是「帳本只存摘要」的落實點。
    # 拿掉會怎樣：沒有 prev_hash 就只是一個普通 list，任何一筆都能被悄悄改掉或刪掉。
    def append(self, entry_type: str, case_id: str, obj: Dict[str, Any], refs: Optional[Dict[str, str]] = None) -> LedgerEntry:
        with self._lock:
            prev = self.entries[-1].entry_hash if self.entries else GENESIS  # 第一環接在固定的 GENESIS 之後
            entry = LedgerEntry(
                index=len(self.entries),
                entry_type=entry_type,
                case_id=case_id,
                object_digest=digest(obj),
                refs=refs or {},
                recorded_at=self.clock.iso(),
                prev_hash=prev,
            )
            entry.entry_hash = entry.compute_hash()
            self.entries.append(entry)
            return entry

    # ── 【老師註解】HashChainLedger.checkpoint ────────────────────
    # 做什麼：拍一張「帳本快照」：目前長度、最後一環哈希、Merkle 根、時間；用 ledger 角色鑰匙簽名後交給外部見證。
    # 為什麼：簽名證明「帳本方當時承認帳本長這樣」；交給外部見證證明「之後沒改過」。兩者缺一不可。
    # 怎麼看：soc.py 在每個案件結束時呼叫一次，所以 simulate 的 23 個案件 ⇒ 23 個 checkpoints。
    # 對應：準則 #7；測試 tests/test_ledger_verifier.py::test_truncation_and_fork_detected
    def checkpoint(self) -> Dict[str, Any]:
        with self._lock:
            payload = {
                "schema_version": "owp-soc/ledger-checkpoint/0.1",
                "length": len(self.entries),
                "head_hash": self.entries[-1].entry_hash if self.entries else GENESIS,
                "merkle_root": merkle_root([e.entry_hash for e in self.entries]),
                "issued_at": self.clock.iso(),
            }
            cp = {"payload": payload, "signatures": [self.signer.sign_payload(payload)]}
            if self.witness is not None:
                self.witness.publish(cp)
            return cp

    # ── 【老師註解】HashChainLedger.verify_chain ──────────────────
    # 做什麼：從 GENESIS 開始逐環重算：index 連號？prev_hash 等於上一環的 entry_hash？entry_hash 等於重算值？
    # 怎麼看：CLI `aisoc verify` 回報的 "chain broken at 5" 就是這裡發現第 5 環對不上。
    # 限制：它只能證明「鏈內部一致」；若有人整本重算，這裡看不出來——所以還要 verify_against_witness。
    def verify_chain(self) -> List[str]:
        """Return a list of problems (empty if the local chain is self-consistent)."""
        problems: List[str] = []
        prev = GENESIS
        for i, e in enumerate(self.entries):
            if e.index != i:
                problems.append(f"index mismatch at {i}")
            if e.prev_hash != prev:
                problems.append(f"prev_hash mismatch at {i}")
            if e.compute_hash() != e.entry_hash:
                problems.append(f"entry_hash mismatch at {i}")
            prev = e.entry_hash
        return problems

    # ── 【老師註解】HashChainLedger.verify_against_witness ────────
    # 做什麼：拿外部見證保存的每個檢查點，(1) 驗 ledger 角色簽名 (2) 本地帳本不能比見證的短（截短）
    #         (3) 前 n 環重算的 Merkle 根要等於見證的根（竄改／分叉）(4) 第 n 環哈希要等於見證的 head_hash。
    # 為什麼：這是「帳本管理員也改不了」的關鍵——他改得了本地檔案，改不了別人手上的檢查點。
    # 怎麼看：沒設見證 ⇒ 回 "no external witness configured"；有見證但沒檢查點 ⇒ UNKNOWN。兩者都不算 VERIFIED。
    # 對應：準則 #7、#8；測試 tests/test_ledger_verifier.py::test_truncation_and_fork_detected
    def verify_against_witness(self, trusted: TrustedKeys) -> List[str]:
        """Compare local state with witnessed checkpoints (tamper / truncation / fork)."""
        problems: List[str] = []
        if self.witness is None:
            return ["no external witness configured"]
        cps = self.witness.checkpoints()
        if not cps:
            return ["no witnessed checkpoint; integrity relative to external anchor is UNKNOWN"]
        for cp in cps:
            payload = cp["payload"]
            if not any(trusted.verify(payload, s, expected_role="ledger") for s in cp["signatures"]):
                problems.append("checkpoint signature invalid")
                continue
            n = payload["length"]
            if n > len(self.entries):
                problems.append(f"ledger truncated: witnessed length {n} > local {len(self.entries)}")
                continue
            prefix = self.entries[:n]
            if merkle_root([e.entry_hash for e in prefix]) != payload["merkle_root"]:
                problems.append(f"merkle root mismatch for witnessed prefix of length {n} (tamper or fork)")
            if prefix and prefix[-1].entry_hash != payload["head_hash"]:
                problems.append(f"head hash mismatch at witnessed length {n}")
        return problems

    def entries_for_case(self, case_id: str) -> List[LedgerEntry]:
        return [e for e in self.entries if e.case_id == case_id]

    def export(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([e.to_dict() for e in self.entries], indent=2, sort_keys=True))


# ── 【老師註解】EncryptedEvidenceStore ────────────────────────────
# 做什麼：原始證據（pcap 摘要、日誌原文…）的加密倉庫，用 AES-GCM 加密、以內容指紋當索引，每次讀取都記錄誰、為何讀。
# 為什麼：帳本只存指紋，原文必須另有地方放；分開放的好處是——到期刪除原文（GDPR／保留政策）不會破壞帳本的鏈。
# 怎麼看：put() 回傳的指紋就是帳本裡的 object_digest；get() 需要寫明 accessor 與 purpose，形成存取紀錄。
# 誠實提醒：金鑰仍在記憶體；正式環境要放 KMS／HSM，且與帳本鑰匙分開保管（準則 #13）。
# 對應：準則 #7；測試 tests/test_ledger_verifier.py::test_evidence_store_separation_and_deletion
class EncryptedEvidenceStore:
    """Sensitive originals, encrypted at rest and addressable by content digest.

    Deleting an item removes the plaintext commitment target, but the ledger
    digest (and therefore the chain) stays verifiable.
    """

    def __init__(self, key: Optional[bytes] = None) -> None:
        self._key = key or AESGCM.generate_key(bit_length=256)
        self._aead = AESGCM(self._key)
        self._items: Dict[str, bytes] = {}
        self.access_log: List[Dict[str, str]] = []

    def put(self, obj: Dict[str, Any]) -> str:
        data = canonical_bytes(obj)
        d = "sha256:" + sha256_hex(data)
        nonce = os.urandom(12)
        self._items[d] = nonce + self._aead.encrypt(nonce, data, d.encode())
        return d

    def get(self, d: str, accessor: str, purpose: str) -> Optional[Dict[str, Any]]:
        self.access_log.append({"digest": d, "accessor": accessor, "purpose": purpose})
        blob = self._items.get(d)
        if blob is None:
            return None
        plain = self._aead.decrypt(blob[:12], blob[12:], d.encode())
        return json.loads(plain.decode("utf-8"))

    def delete(self, d: str) -> bool:
        return self._items.pop(d, None) is not None

    def __contains__(self, d: str) -> bool:
        return d in self._items
