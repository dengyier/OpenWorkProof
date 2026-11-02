"""Ed25519 signing helpers and a deterministic clock.

``Ed25519Signer`` keeps the private key inside the object and exposes no
export method. This models the *interface* of an HSM-backed signer; it is an
in-memory stand-in and must not be mistaken for hardware key protection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .canonical import canonical_bytes, sha256_hex


def utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# ── 【老師註解】Clock ─────────────────────────────────────────────
# 做什麼：可注入的時鐘。平常回真實 UTC 時間；一旦呼叫 advance() 或給了起始時間就「凍結」，之後只會照指令前進。
# 為什麼：授權有時效（TTL）、審批有逾時，測試要能說「現在把時間撥快 10 分鐘，這張授權應該過期」。
#         用真實時鐘的話測試會不穩定，也無法重現論文裡的情境。
# 拿掉會怎樣：「expired authorization」情境無法可靠重現；模擬結果每次都不同，別人無法驗證你的數字。
# 對應：準則 #6、#13；測試 tests/test_policy_pep.py::test_grant_expiry_denies
class Clock:
    """Injectable clock so tests and simulations are deterministic."""

    def __init__(self, start: Optional[datetime] = None) -> None:
        self._now = start or datetime(2026, 11, 1, 0, 0, 0, tzinfo=timezone.utc)
        self.frozen = start is not None

    def now(self) -> datetime:
        if self.frozen:
            return self._now
        return datetime.now(timezone.utc)

    def advance(self, seconds: float) -> None:
        self.frozen = True
        self._now = self._now + timedelta(seconds=seconds)

    def iso(self) -> str:
        return utc_iso(self.now())


# ── 【老師註解】Ed25519Signer ─────────────────────────────────────
# 做什麼：持有「一把私鑰 + 一個角色名」的簽名器。只提供 sign_payload()，故意不提供任何匯出私鑰的方法。
# 為什麼：這是在模仿 HSM（硬體安全模組）的介面——程式可以「請它簽名」，但永遠拿不到私鑰本身。
#         沙箱裡的 Agent 連這個物件都碰不到（它在管理域 C／B），所以逃逸後也偽造不了簽名。
# 怎麼看：key_id 是公鑰的 SHA-256 前 32 字元，當作公鑰的「門牌號」；簽名結果同時寫明 role，但 role 不是
#         靠它自稱，而是靠 TrustedKeys 登記時的角色來驗（見下方 TrustedKeys.verify）。
# 誠實提醒：這裡私鑰只是在記憶體裡，不是硬體保護；論文的保證需要真正分開的管理域（準則 #13）。
# 對應：準則 #1、#9；測試 tests/test_canonical_crypto.py::test_signature_roundtrip_and_role_check
class Ed25519Signer:
    def __init__(self, role: str, private_key: Optional[ed25519.Ed25519PrivateKey] = None) -> None:
        self.role = role
        self._private_key = private_key or ed25519.Ed25519PrivateKey.generate()
        self.public_key = self._private_key.public_key()
        self.key_id = "ed25519:" + sha256_hex(self.public_bytes())[:32]

    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

    def public_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    # ── 【老師註解】Ed25519Signer.sign_payload ────────────────────
    # 做什麼：先把 payload 規範化成唯一位元組，再用私鑰簽，回傳 {key_id, role, alg, sig}。
    # 為什麼：簽的是「規範化位元組」而不是 Python dict 或原始字串，這樣任何人用任何語言重算都能驗。
    # 拿掉會怎樣：若直接簽 json.dumps(payload)，欄位順序一變簽名就失效，驗證器會把合法紀錄判成竄改。
    def sign_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        sig = self._private_key.sign(canonical_bytes(payload))
        return {"key_id": self.key_id, "role": self.role, "alg": "Ed25519", "sig": sig.hex()}


# ── 【老師註解】TrustedKeys ───────────────────────────────────────
# 做什麼：公鑰登記簿——記錄「哪把公鑰、被信任擔任哪個角色」（ledger / authorizer / executor / verifier /
#         approver / model_release）。驗證簽名時可以同時要求「必須是某個角色簽的」。
# 為什麼：論文要求職責分離：授權者不能自己當執行者、帳本鑰匙不能拿去簽審批。若只驗「簽名有效」而不驗
#         「誰的角色」，一把被偷的鑰匙就能冒充所有角色。
# 拿掉會怎樣：executor 鑰匙可以簽出一張「授權信封」，PEP 會照放——職責分離變成口號。
# 對應：準則 #9；測試 tests/test_ledger_verifier.py::test_witness_signature_from_wrong_role_rejected
@dataclass
class TrustedKeys:
    """Registry of public keys and the roles they are trusted for."""

    _keys: Dict[str, ed25519.Ed25519PublicKey] = field(default_factory=dict)
    _roles: Dict[str, str] = field(default_factory=dict)

    def trust(self, signer: Ed25519Signer) -> None:
        self._keys[signer.key_id] = signer.public_key
        self._roles[signer.key_id] = signer.role

    def trust_raw(self, key_id: str, role: str, raw_public: bytes) -> None:
        self._keys[key_id] = ed25519.Ed25519PublicKey.from_public_bytes(raw_public)
        self._roles[key_id] = role

    def role_of(self, key_id: str) -> Optional[str]:
        return self._roles.get(key_id)

    # ── 【老師註解】TrustedKeys.verify ────────────────────────────
    # 做什麼：三步驗證：(1) key_id 有沒有登記過 → (2) 登記的角色是否等於 expected_role → (3) 簽名數學上是否正確。
    # 怎麼看：任何一步失敗都回 False，而且「不丟例外」——呼叫者只需問一句 ok 與否，避免例外被誤吞後放行。
    #         注意角色是查「登記簿」(self._roles)，不是看簽名裡自稱的 "role" 欄位——自稱不算數。
    # 拿掉會怎樣：少了第 (2) 步就是「任何受信任鑰匙都能簽任何東西」，職責分離失效。
    def verify(self, payload: Dict[str, Any], signature: Dict[str, Any], expected_role: Optional[str] = None) -> bool:
        key = self._keys.get(signature.get("key_id", ""))
        if key is None:
            return False  # 步驟 1：沒登記過的鑰匙，一律不信
        if expected_role is not None and self._roles.get(signature["key_id"]) != expected_role:
            return False  # 步驟 2：鑰匙是真的，但不是這個角色的鑰匙 → 拒絕（準則 #9）
        try:
            key.verify(bytes.fromhex(signature["sig"]), canonical_bytes(payload))  # 步驟 3：數學驗簽
        except (InvalidSignature, ValueError, KeyError):
            return False
        return True

    def export(self) -> Dict[str, Dict[str, str]]:
        return {
            kid: {
                "role": self._roles[kid],
                "public_raw_hex": key.public_bytes(
                    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
                ).hex(),
            }
            for kid, key in self._keys.items()
        }
