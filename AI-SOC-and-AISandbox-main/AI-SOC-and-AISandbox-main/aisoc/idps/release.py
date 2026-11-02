"""Signed model release gate (training domain -> inference domain).

A model may only be loaded for inference if a *release manifest* signed by the
``model_release`` role pins the exact artefact bytes (SHA-256), the training
dataset digest and the feature schema. The inference side never trusts a model
file by its path or name. This is the "model registration + signature +
release gate" step of the paper's training-domain pipeline; the human approval
that precedes signing is organisational and is represented only by the
manifest's ``approved_by`` field.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..canonical import sha256_hex
from ..crypto import Clock, Ed25519Signer, TrustedKeys
from ..owp.objects import Signed, schema
from .dual_model import DualModel
from .features import FEATURE_SCHEMA_VERSION

# ── 【老師註解】MODEL_RELEASE_ROLE ──────────────────────────────
# 做什麼：發佈清單必須由這個角色（"model_release"）的金鑰簽名；其他角色（ledger、authorizer…）簽的一律無效。
# 為什麼 SOC 只拿公鑰：私鑰留在訓練域，推論域（SOC）的 TrustedKeys 只登記「公鑰 + 角色」。
#   這樣 SOC 這邊就算被攻破，攻擊者也造不出合法的清單去替換模型；而訓練域也不能冒充 SOC 其他角色去簽帳本或授權。
# 怎麼看：一角色一鑰匙——release_model 檢查 signer.role，load_verified_model 檢查 trusted.verify(..., expected_role=...)。
# 拿掉會怎樣：任何一把被信任的金鑰都能簽模型，「換模型」就變成所有角色共有的攻擊面。
# 對應：準則 #9、#10；測試 tests/test_egress_release_grant.py::test_release_gate_accepts_only_exact_signed_artefact
MODEL_RELEASE_ROLE = "model_release"
# ── 【老師註解】MANIFEST_SCHEMA ──────────────────────────────
# 做什麼：清單自己的格式版本（"owp-soc/model-manifest/0.1"）；load_verified_model 的第一道檢查就是比對它。
# 對應：準則 #10（此處無直接測試）
MANIFEST_SCHEMA = schema("model-manifest")


# ── 【老師註解】ModelReleaseError ──────────────────────────────
# 做什麼：發佈閘門專用的例外。任何一道檢查失敗都丟它，呼叫端（AISOC.from_release）不會拿到模型物件。
# 為什麼：用專屬型別讓「模型載入被拒」與一般程式錯誤分得開，測試與日誌都能精準比對。
# 對應：準則 #10；測試 tests/test_egress_release_grant.py::test_soc_from_release_records_verified_manifest_and_plain_init_records_unverified
class ModelReleaseError(Exception):
    pass


# ── 【老師註解】release_model ──────────────────────────────
# 做什麼：在訓練域產生「發佈清單」：模型版本、特徵 schema、模型 bytes 的 SHA-256、資料集摘要、時間、核准人、評估結果，然後用 model_release 金鑰簽名。
# 為什麼：模型是跨域製品（訓練域 → 推論域），跨域的東西必須「哈希釘死 + 角色簽名」，推論端不能只看檔名。
# 怎麼看：approved_by 只是個字串——人類核准在這個參考實作裡是組織流程，不是密碼學證明（誠實範圍）。
# 拿掉會怎樣：沒有清單，任何人把檔案放到對的路徑就能讓 SOC 載入一個被動過手腳的模型。
# 對應：準則 #9、#10、#13；測試 tests/test_egress_release_grant.py::test_release_gate_accepts_only_exact_signed_artefact
def release_model(
    model: DualModel,
    dataset_sha256: str,
    signer: Ed25519Signer,
    clock: Clock,
    approved_by: str = "unspecified",
    evaluation: Optional[Dict[str, Any]] = None,
) -> Signed:
    """Produce the signed manifest for ``model``. Call only from the training domain."""
    # 步驟 1：角色不對直接拒簽（一角色一鑰匙）
    if signer.role != MODEL_RELEASE_ROLE:
        raise ModelReleaseError(f"release manifests must be signed by the {MODEL_RELEASE_ROLE!r} role, not {signer.role!r}")
    # 步驟 2：清單內容——注意 model_sha256 是對 to_bytes() 的 canonical bytes 算的
    payload = {
        "schema_version": MANIFEST_SCHEMA,
        "model_version": model.model_version,
        "feature_schema": FEATURE_SCHEMA_VERSION,
        "model_sha256": sha256_hex(model.to_bytes()),
        "dataset_sha256": dataset_sha256,
        "released_at": clock.iso(),
        "approved_by": approved_by,
        "evaluation": evaluation or {},
    }
    # 步驟 3：簽在 canonical JSON 上，簽名裡附 key_id / role
    return Signed(payload=payload, signatures=[signer.sign_payload(payload)])


# ── 【老師註解】load_verified_model ──────────────────────────────
# 做什麼：推論域載入模型前的五道檢查，任何一道不過就丟 ModelReleaseError、模型不會被建立（fail-closed）。
# 為什麼：順序是「先便宜後昂貴、先信任後內容」：schema → 簽名與角色 → 哈希 → 特徵 schema → 解析後比對版本。
#   簽名擺在哈希之前，是因為沒驗簽之前，清單裡寫的哈希本身就不可信。
# 怎麼看：any(trusted.verify(...)) 表示多重簽名中有任一個「可信且角色正確」即可；expected_role 把角色綁死。
# 拿掉會怎樣：少哈希檢查 ⇒ 清單合法但檔案被換；少角色檢查 ⇒ 帳本金鑰可以簽模型；少版本比對 ⇒ 清單與製品說法不一致卻放行。
# 對應：準則 #8、#9、#10；測試 tests/test_egress_release_grant.py::test_release_gate_accepts_only_exact_signed_artefact、tests/test_egress_release_grant.py::test_soc_from_release_records_verified_manifest_and_plain_init_records_unverified
def load_verified_model(model_bytes: bytes, manifest: Signed, trusted: TrustedKeys) -> DualModel:
    """Fail closed: no valid manifest, wrong role, hash or schema mismatch -> no model."""
    p = manifest.payload
    # 檢查 1：清單格式
    if p.get("schema_version") != MANIFEST_SCHEMA:
        raise ModelReleaseError("unexpected manifest schema")
    # 檢查 2：簽名有效 且 簽名者被信任為 model_release 角色
    if not any(trusted.verify(p, s, expected_role=MODEL_RELEASE_ROLE) for s in manifest.signatures):
        raise ModelReleaseError("manifest signature invalid or signer not trusted for model release")
    # 檢查 3：製品 bytes 的哈希必須等於清單釘住的值
    actual = sha256_hex(model_bytes)
    if actual != p.get("model_sha256"):
        raise ModelReleaseError("model artefact hash does not match the signed manifest")
    # 檢查 4：清單宣告的特徵 schema 要和本次推論建置一致
    if p.get("feature_schema") != FEATURE_SCHEMA_VERSION:
        raise ModelReleaseError("manifest feature schema does not match this inference build")
    # 到這裡才解析（from_bytes 內還有檔案 schema 檢查）
    model = DualModel.from_bytes(model_bytes)
    # 檢查 5：製品內的版本必須與清單一致
    if model.model_version != p.get("model_version"):
        raise ModelReleaseError("model_version inside the artefact differs from the manifest")
    return model
