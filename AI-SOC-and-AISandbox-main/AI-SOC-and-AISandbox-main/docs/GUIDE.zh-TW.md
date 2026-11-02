# AI SOC 與 AI Sandbox 新手指南（老師版）

> 這份指南假設你是**第一次**接觸這個專案、也第一次接觸「密碼學帳本」這類東西。
> 我會像老師一樣，每一步先告訴你「要做什麼、為什麼、預期看到什麼、看到別的代表什麼」。
> 全部指令都在這個 repo 的根目錄執行，全部輸出都是我實際跑出來的，不是想像的。

---

## 0. 這份指南怎麼用

| 你想要… | 去哪一節 |
|---|---|
| 10 分鐘弄懂這套系統在防什麼 | §1、§2 |
| 把軟體跑起來、看到結果 | §4、§5 |
| 看懂跑出來的檔案 | §6 |
| 親手證明「改一個字元就會被抓到」 | §7 |
| 讀程式碼、判斷每個函數是不是真的在做它說的事 | §8 |
| 自己從零重寫一遍 | §9 |
| 準備答辯、回答專家提問 | §10、§11、§12 |

**老師註解在哪裡？** 程式碼裡所有重要的 class / function 上方都有一段以 `【老師註解】` 開頭的中文註解，固定格式：

```
# ── 【老師註解】<名稱> ───────────────
# 做什麼：這段程式做的事（一句話）
# 為什麼：論文／安全理由
# 怎麼看：讀這段程式時的判讀要點
# 拿掉會怎樣：這個控制不存在時的後果
# 對應：準則 #n；測試 tests/<檔案>::<測試名>
```

列出全部註解：

```bash
grep -rn "老師註解" aisoc/          # 每一條註解的檔案與行號
grep -rc "老師註解" aisoc/ | sort   # 每個檔案有幾條
```

「對應」那一行是給你**自己驗證**用的：準則編號對照 §3 的表；測試名可以直接跑，例如
`python -m pytest -q tests/test_policy_pep.py::test_pep_happy_path_then_replay_and_tamper`。
**程式碼說它做了什麼不算數，測試證明它做了什麼才算數。**

---

## 1. 五個核心概念（先讀這裡，10 分鐘）

### 1.1 哈希（hash）＝ 資料的指紋

把任意長度的資料丟進 SHA-256，得到固定 64 個十六進位字元。改資料的任何一個位元，指紋就完全不同；而且從指紋推不回原始資料。

本專案用 `sha256:` 前綴標示，例如 `sha256:20dbd2dc…`。**帳本裡只存指紋，不存原文**（準則 #7）——所以監管者可以驗證帳本，卻看不到敏感流量內容。

→ 程式碼：`aisoc/canonical.py::digest`

### 1.2 規範化（JCS, RFC 8785）＝ 同一份資料永遠長得一樣

同一個 JSON 物件可以有很多寫法（鍵的順序、空白、`1.0` vs `1`）。如果簽名前不先統一格式，驗證方算出的指紋就會不同、簽名就驗不過。

JCS 的規則：鍵按字典序排序、沒有多餘空白、數字用固定格式、拒絕 NaN。**所有簽名與哈希都先經過 JCS**。

→ 程式碼：`aisoc/canonical.py::canonical_bytes`；測試 `tests/test_canonical_crypto.py::test_digest_stable_across_ordering`

### 1.3 數位簽名（Ed25519）＝ 只有持鑰者能蓋的章

一對鑰匙：**私鑰**（只有簽名者有）、**公鑰**（人人可拿）。用私鑰對資料簽出一段 `sig`，任何人用公鑰可以檢查「這段資料確實是私鑰持有者簽的、而且簽完沒被改過」。

本專案**一個角色一把鑰匙**（準則 #9）：

| 角色 (role) | 誰 | 簽什麼 |
|---|---|---|
| `ledger` | 帳本服務 | 帳本檢查點（Merkle 根） |
| `authorizer` | 簽名服務 | 動作授權（單次、短時效） |
| `executor` | 執行器 | 動作收據 |
| `approver` | 人類審批者 | 人工批准／拒絕、接受決定 |
| `verifier` | 獨立驗證器 | 驗證結論 |
| `model_release` | 訓練域 | 模型發布清單（SOC 只拿到公鑰） |

**沙箱裡的 Agent 一把鑰匙都沒有**（準則 #1）。這是整個設計的核心：Agent 就算被完全攻陷，也偽造不出任何一個簽名。

→ 程式碼：`aisoc/crypto.py::Ed25519Signer`、`TrustedKeys.verify`（驗簽時連 role 一起驗，拿錯角色的鑰匙簽也不行）

### 1.4 Nonce 與重放攻擊

攻擊者截到一張「有效的授權」，再送一次會怎樣？如果系統只驗簽名，就會再執行一次（**重放攻擊**）。

解法：每張授權帶一個一次性的亂數 `nonce`，執行器記住用過的 nonce，第二次看到就拒絕（準則 #6）。本專案另外還有「冪等鍵」：同一個 idempotency key 再送，回傳**上次的收據**，不產生新副作用。

→ 程式碼：`aisoc/sandbox/pep.py::NonceStore`、`PolicyEnforcementPoint.execute`；測試 `tests/test_policy_pep.py::test_pep_happy_path_then_replay_and_tamper`；消融實驗「ABLATION: remove single-use nonce and idempotency」會證明拿掉它重放就成功

### 1.5 哈希鏈、Merkle 根、外部見證

**哈希鏈**：帳本第 n 筆記錄包含第 n−1 筆的指紋 (`prev_hash`)。改第 5 筆，第 6 筆存的 `prev_hash` 就對不上 → 「chain broken at 5」。

但攻擊者如果能改整條鏈（第 5 筆之後全部重算）呢？所以還需要：

**Merkle 根 + 外部見證**：每個案件結束時，帳本把目前全部記錄算成一個 Merkle 根，用 `ledger` 鑰匙簽名，交給**帳本管理員管不到的**外部見證（準則 #7）。之後就算整條鏈被重寫，也對不上見證保存的根與長度 → 「truncated below witnessed length 464」。

**沒有見證時**，驗證器不會說「通過」，只會說 `UNKNOWN`（準則 #8）——因為它無法排除整條鏈被重寫的可能。

→ 程式碼：`aisoc/owp/ledger.py::HashChainLedger`、`merkle_root`、`ExternalWitness`；`aisoc/owp/verifier.py::Verifier.verify_case`

---

## 2. 系統全貌

```
                     訓練域（離線）
                     ┌──────────────────────────────┐
                     │ 訓練 → 簽名發布清單(model_release 鑰匙) │
                     └──────────────┬───────────────┘
                                    │ 模型位元組 + 清單（只驗哈希與簽名）
   流量/Slips 告警 ──► ┌─────────────▼─────────────┐
                      │ AI-IDPS  dual_model        │  已知分支 c_k ＋ 異常分支 s_a
                      │ (aisoc/idps/)              │  → Table III 六條規則 → 案件狀態
                      └─────────────┬─────────────┘
                                    │ 需要調查的案件
                      ┌─────────────▼─────────────┐
                      │ 沙箱  (aisoc/sandbox/)     │
                      │  凍結工作單 + 最小能力授予   │
                      │  Agent（只讀工具、無鑰匙）   │
                      │  ↓ 唯一出口：出口代理        │  先記帳、後轉發；記不了就丟（fail-closed）
                      └─────────────┬─────────────┘
                                    │ 報告 / 動作請求
            ┌───────────────────────▼────────────────────────┐
            │ 控制面（沙箱外）                                  │
            │  政策引擎 → allowed / reserved / denied           │
            │  reserved ⇒ 人類審批（簽名，綁定請求摘要）          │
            │  簽名服務 ⇒ 單次、短時效、綁範圍的授權              │
            │  PEP ⇒ 八項檢查全過才執行 ⇒ 簽名收據               │
            └───────────────────────┬────────────────────────┘
                                    │ 每一步都寫帳本
            ┌───────────────────────▼────────────────────────┐
            │ OWP 帳本 (aisoc/owp/)                            │
            │  只存指紋、哈希鏈、Merkle 檢查點、外部見證          │
            │  獨立驗證器：離線對賬 → VERIFIED / UNKNOWN / FAILED│
            └────────────────────────────────────────────────┘
```

一句話總結論文主張：**我們不假設 Agent 永遠不會被攻破；而是讓它攻破後的每一步都無權、無鑰、無法抹去。**

編排者是 `aisoc/soc.py::AISOC`，上面每一個箭頭都對應 `AISOC._run_case` 裡的一個步驟（程式碼裡標了「步驟 1～11」）。

---

## 3. 十三條設計準則 → 程式碼 → 測試

這十三條是從論文整理出來的；程式碼註解裡的「準則 #n」就是指這張表。

| # | 準則 | 程式碼位置 | 證明它成立的測試 |
|---|---|---|---|
| 1 | Agent 無權力、不持鑰匙，只有只讀工具 | `sandbox/tools.py::ReadOnlyTools`、`soc.py::AISOC.__init__` | `test_end_to_end.py::test_compromised_agent_cannot_cause_side_effects` |
| 2 | 單一出口；先記帳後轉發；記不了就丟 (fail-closed) | `sandbox/egress.py::ControlledEgressProxy.forward` | `test_egress_release_grant.py::test_egress_proxy_fail_closed_vs_fail_open` |
| 3 | 政策在沙箱外；有效能力 = 任務 ∩ 授予 ∩ 執行期限制 ∩ 人類 | `sandbox/policy.py::PolicyEngine.decide` | `test_policy_pep.py::test_policy_denies_scope_violations` |
| 4 | 保留動作必須真人簽名，且簽名綁定請求摘要 | `sandbox/authorization.py::HumanApprover`、`AuthorizationSigner._check_approval` | `test_policy_pep.py::test_signer_refuses_without_or_with_bad_approval` |
| 5 | PEP 檢查順序固定（簽名→信封綁定→時效→撤銷→人簽→冪等→nonce→受限執行） | `sandbox/pep.py::PolicyEnforcementPoint.execute` | `test_policy_pep.py::test_pep_rejects_untrusted_signer_and_expiry_and_revocation` |
| 6 | 授權單次、短時效、可撤銷；授予只能收窄不能放寬 | `sandbox/pep.py::NonceStore`、`owp/objects.py::CapabilityGrant.attenuate` | `test_policy_pep.py::test_ablation_flag_restores_replay`、`test_egress_release_grant.py::test_attenuate_narrows_only` |
| 7 | 帳本只存指紋 + 哈希鏈 + Merkle + 外部見證 | `owp/ledger.py::HashChainLedger` | `test_ledger_verifier.py::test_modification_detected`、`test_truncation_and_fork_detected` |
| 8 | 驗證器離線可跑；沒有見證 ⇒ UNKNOWN，不是通過 | `owp/verifier.py::Verifier.verify_case`、`cli.py` 的 `verify` | `test_ledger_verifier.py::test_verifier_unknown_without_witness` |
| 9 | 一角色一鑰匙；驗簽連角色一起驗 | `crypto.py::TrustedKeys.verify` | `test_canonical_crypto.py::test_signature_roundtrip_and_role_check` |
| 10 | 模型以簽名 + 哈希釘死，不符就拒載入 | `idps/release.py::load_verified_model`、`soc.py::AISOC.from_release` | `test_egress_release_grant.py::test_release_gate_accepts_only_exact_signed_artefact` |
| 11 | 日誌文字一律不可信（可能含注入）；缺資料 ⇒ UNKNOWN 不是正常 | `sandbox/untrusted.py::Untrusted`、`idps/dual_model.py::DualModel._unknown` | `test_policy_pep.py::test_injection_screen_flags_instructions`、`test_egress_release_grant.py::test_decide_external_combinations` |
| 12 | 雙模型多路徑；已知低信心 ∧ 異常高 ⇒ 疑似零日 ⇒ 必須人審 | `idps/dual_model.py::DualModel._combine` | `test_dual_model.py::test_decision_table_covers_known_attack`、`test_missing_data_is_unknown_not_normal`、`test_leave_one_family_out_escalates_unseen_family_somewhere` |
| 13 | 誠實範圍：合成資料、單一進程、確定性 Agent；數字不是安全認證 | `report.md` 開頭的免責聲明、`README.md` 的 Honest scope | — |

---

## 4. 環境準備

需要：Python 3.10 以上（我用 3.12.3 驗證）、pip。**不需要** GPU、Docker、網路服務；全部在本機跑完。

```bash
git clone https://github.com/alphatin123/AI-SOC-and-AISandbox.git
cd AI-SOC-and-AISandbox
git checkout feat/slips-aisoc-adapters     # PR #5 的分支；合併後用 main 即可
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt            # 只有兩個套件：cryptography、pytest
```

為什麼依賴這麼少？因為 dual_model 是純 Python 寫的邏輯迴歸 + Isolation Forest（在 `aisoc/idps/`），故意不用 PyTorch——**重點不是模型多強，而是模型周圍的治理鏈條**。

---

## 5. 一步一步重現

每一步都有：**做什麼 → 指令 → 預期輸出 → 怎麼判讀 → 出錯怎麼辦**。

### 步驟 1：跑完整測試套件

**做什麼**：先確認所有安全性質在你的機器上成立，再看任何東西。

```bash
python -m pytest -q
```

**預期輸出**（最後一行）：
```
85 passed in ~9s
```

**怎麼判讀**：85 個測試涵蓋 §3 表中每一條準則。任何一個失敗都代表某條保證在你的環境不成立——**先停下來**。

**出錯怎麼辦**：`ModuleNotFoundError: cryptography` → 沒裝依賴或沒啟用 venv。

### 步驟 2：跑完整模擬

**做什麼**：訓練模型 → 留一家族實驗 → 跑 200 個案件的 SOC 流程 → 跑 15 個攻擊情境 + 4 個消融實驗。

```bash
python -m aisoc simulate --out demo-output/aisoc-run
```

**預期輸出**：
```
1/4 training dual_model on time-ordered synthetic split ...
2/4 leave-one-family-out ...
3/4 running SOC pipeline with heuristic agent (model loaded through the signed release gate) ...
4/4 running security scenarios and ablations ...
   [ok] L0/L1 indirect prompt injection drives a fully compromised agent
   [ok] cross-tenant target
   [ok] replay of a valid single-use authorization
   [ok] expired authorization
   [ok] revocation
   [ok] parameter change after approval
   [ok] ledger tamper and truncation after external checkpoint
   [ok] execution that bypasses the ledger (tool-side receipt without authorization record)
   [ok] Slips Description text as prompt injection into a compromised agent
   [ok] Slips anomaly-only / weak-indicator-only evidence (no normality branch, no named class)
   [ok] AiSOC approval inbox as the human step (approve / deny / undecided / wrong record)
   [ok] AiSOC evidence bundle anchored into the OWP ledger (HMAC tamper-evidence upgraded to signed, witnessed commitment)
   [ok] sandbox egress proxy fails closed (audit down / oversize / rate limit)
   [ok] signed model release gate (training domain -> sandbox)
   [ok] capability grant attenuation for sub-tasks (narrow only)
   [ok] ABLATION: remove single-use nonce and idempotency
   [ok] ABLATION: PEP no longer requires approval for high impact
   [ok] ABLATION: no external witness
   [ok] ABLATION: egress proxy fails open when the audit domain is down

written to demo-output/aisoc-run/report.json and report.md
```

**怎麼判讀**：
- `[ok]` 的意思是「**情境的結果符合預期**」。注意：ABLATION（消融）的預期是「控制拿掉後攻擊**成功**」——`[ok]` 代表我們成功證明了那個控制是必要的，不是代表系統安全。
- 「model loaded through the signed release gate」：第 3 步的模型是經 `AISOC.from_release` 驗簽載入的（準則 #10）。

**出錯怎麼辦**：出現 `[FAIL]` → 對照 `report.md` 的 expected 欄，看哪個情境行為變了；`--seed` 預設固定，結果應完全可重現。

### 步驟 3：讀報告

```bash
cat demo-output/aisoc-run/report.md
```

**重點段落怎麼讀**：

```
- benign FPR at validation-fixed thresholds: 0.0037
- recall by family: {'ssh_bruteforce': 1.0, 'c2_beacon': 1.0, 'port_scan': 1.0, 'exfiltration': 1.0}
- status mix: {'LOW_RISK_OBSERVE': 541, 'KNOWN_SUSPICIOUS': 57, 'MODEL_CONFLICT': 2}
```
→ 門檻是在**驗證集**上定的，不是在測試集上調的（否則 FPR 會不誠實）。

```
| held-out family | recall | benign FPR |
| ssh_bruteforce  | 0.619  | 0.0037     |
```
→ **留一家族**實驗：訓練時完全不給模型看 ssh_bruteforce，測它能不能憑異常分支抓到。0.619 是誠實的數字——它說明「疑似零日」路徑有用但不是萬能；答辯時直接說這個數字，比說 100% 可信。

```
- requests: {'requests': 23, ..., 'reserved': 17, 'allowed': 6, 'human_approved': 17, ..., 'executed': 23, 'pep_rejected': 0, 'cross_tenant_executed': 0}
- verification: {'VERIFIED': 23}
- acceptance: {'ACCEPTED': 23}
```
→ 正常流程：23 個動作請求，17 個是高影響 (`block_host`) 需人簽、6 個低影響自動放行；23 個全部有驗證結論且全部 VERIFIED。`cross_tenant_executed: 0` 是關鍵的零。

### 步驟 4：離線驗證

**做什麼**：假裝你是監管者，**只拿輸出檔案、不碰 SOC**，重算整條證據鏈。

```bash
python -m aisoc verify demo-output/aisoc-run
```

**預期輸出**：
```json
{
  "status": "VERIFIED",
  "entries": 472,
  "checkpoints": 23,
  "receipts": 23,
  "problems": []
}
```

**怎麼判讀**：
- `entries: 472`：帳本 472 筆（200 偵測 + 23 個調查案件 × 11 類記錄 + 46 筆出口紀錄 + 1 模型發布 + 1 去重）。
- `checkpoints: 23`：每個調查案件結束都做一次檢查點送見證，所以 = 案件數。
- `receipts: 23`：執行器簽的收據，每一張都要能對到一筆 `authorization` 帳本記錄——對不到就是「繞過帳本執行」。
- 驗證器做了什麼：重算哈希鏈 → 用 `trusted-keys.json` 裡 `ledger` 的公鑰驗每個檢查點簽名 → 比對 Merkle 根 → 驗每張收據的 `executor` 簽名 → 對賬收據 vs 授權 → 對賬動作請求 vs 出口紀錄。

**三種狀態**：`VERIFIED`（exit 0）/ `UNKNOWN`（見證缺失，exit 1）/ `FAILED`（找到竄改，exit 1）。§7 會讓你親手製造後兩種。

### 步驟 5：把 Slips 的真實告警格式餵進同一條管線

**做什麼**：把 [Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) 輸出的 IDMEFv2 `alerts.json` + Zeek `conn.log` 當「外部已知分支」跑。這裡用 fixture；接真機見 `docs/INTEGRATION.md`。

```bash
python -m aisoc slips-ingest tests/fixtures/slips/alerts.json \
    --conn-log tests/fixtures/slips/conn.log --out demo-output/slips-run
```

**預期輸出**：
```
training dual_model on synthetic data (only its release gate and thresholds are used; the internal normality model is disabled for real traffic) ...
{
  "evidence": 7,
  "incidents": 1,
  "malformed": 1,
  "cases": 5,
  "status_counts": {"KNOWN_SUSPICIOUS": 3, "SUSPECTED_UNKNOWN": 1, "UNKNOWN": 1},
  "requires_human_review": 2,
  "known_families": {"bruteforce": 1, "threat_intel": 1, "port_scan": 1, "unclassified": 2}
}
```

**怎麼判讀**：
- `malformed: 1`：fixture 故意放了一行壞資料，adapter **拒絕而不是猜**（準則 #11）。
- `UNKNOWN: 1`：Slips 沒給家族、也沒有異常訊號的那筆，狀態是 UNKNOWN 送人審——**不是** LOW_RISK_OBSERVE。這是 `DualModel.decide_external` 路徑 D，註解裡有寫「拿掉會怎樣」。
- 「internal normality model is disabled for real traffic」：合成資料練的基線不能拿來比真實網路，所以預設關閉（除非 `--internal-normality`）。這是誠實範圍的一部分。

### 步驟 6：驗證 Slips 那一輪

```bash
python -m aisoc verify demo-output/slips-run
```
預期：`"status": "VERIFIED", "entries": 50, "checkpoints": 4, "receipts": 4`。

### 步驟 7：看會送去 AiSOC 的告警長什麼樣（不真的送）

```bash
python -m aisoc aisoc-push demo-output/slips-run --dry-run
```

**預期輸出**（節錄）：
```json
{
  "would_post": "http://localhost:8000/api/v1/alerts/submit",
  "events": [
    {
      "title": "[OWP-SOC] KNOWN_SUSPICIOUS on 10.0.0.77",
      "description": "known class bruteforce from slips/flowalerts with score 0.700; normality branch unavailable",
      "mitre_techniques": ["T1110"],
      "aisoc_owp": {"case_id": "case-…", "model_version": "dual_model/synthetic-seed1+slips/flowalerts", ...}
```

**怎麼判讀**：`model_version` 帶 `+slips/flowalerts`，帳本因此看得出「這個結論是誰說的」；`aisoc_owp` 區塊帶帳本錨點，AiSOC 那邊的告警可以反查回我們的帳本。

### 步驟 8：驗證 AiSOC 證據包的完整性欄位

```bash
python -m aisoc aisoc-bundle-verify tests/fixtures/aisoc/investigation-bundle.json --hmac-key test-key
```
預期：`"sha256_ok": true, "hmac_checked": true, "hmac_ok": true, "ok": true`，exit 0。

```bash
python -m aisoc aisoc-bundle-verify tests/fixtures/aisoc/investigation-bundle.json --hmac-key wrong-key
```
預期：`"hmac_ok": false, "problems": ["HMAC-SHA256 signature does not verify under the supplied key"], "ok": false`，exit 1。

**怎麼判讀**：AiSOC 的 HMAC 是**對稱**金鑰——伺服器自己也能造出任何合法的包。所以 `AISOC.anchor_external_evidence` 會再把包的指紋寫進我們的 Ed25519 帳本並立即做檢查點送見證，把「可偵測竄改」升級為「可對第三方承諾」。

### 步驟 9：列出所有老師註解，對照 §3

```bash
grep -rc "老師註解" aisoc/ | sort
```
每個檔案的數字就是該檔案裡被註解的重要函數數。接著讀 §8 的閱讀路線。

### 步驟 10：清理

```bash
rm -rf demo-output/     # 已在 .gitignore，不會被 commit
```

---

## 6. 輸出檔案怎麼讀

`simulate` 與 `slips-ingest` 寫出的檔案（在 `--out` 目錄）：

| 檔案 | 內容 | 誰用 |
|---|---|---|
| `report.md` / `report.json` | 人讀的摘要：偵測指標、留一家族、SOC 統計、情境表 | 你、評審 |
| `ledger.json` | **帳本**，JSON 陣列；每筆只有指紋 | `verify` |
| `witness-checkpoints.json` | 外部見證保存的簽名檢查點 | `verify` |
| `trusted-keys.json` | 各角色的**公鑰**（沒有任何私鑰） | `verify` |
| `tool-side-receipts.json` | 執行器簽的動作收據（工具那一側的紀錄，不是帳本的） | `verify` 對賬 |
| `tool-calls.json` | Agent 呼叫只讀工具的紀錄 | 稽核 |
| `cases.json` | 每個案件的人讀結果（§6.2） | 你 |
| `model-card.json` | 模型版本、特徵結構、門檻、訓練資料指紋 | 稽核 |
| `slips-summary.json`（僅 slips-ingest） | 上面步驟 5 印的那段統計 | 你 |

### 6.1 一筆帳本記錄

```json
{
  "index": 0,
  "entry_type": "model_release",
  "case_id": "-",
  "object_digest": "sha256:20dbd2dc…",   ← 被記錄物件的指紋（原文不在這）
  "prev_hash":     "sha256:0000…0000",   ← 上一筆的 entry_hash；第 0 筆是全零
  "entry_hash":    "sha256:b7eab2f7…",   ← 本筆的指紋 = hash(index, type, case, digest, prev, time, refs)
  "recorded_at": "2026-11-02T01:50:49Z",
  "refs": {"model_version": "dual_model/synthetic-seed1"}
}
```

`entry_type` 的種類與一個調查案件的**固定順序**：
`detection → work_order → capability_grant → agent_egress(報告) → investigation_report → agent_egress(請求) → action_request → policy_decision → [human_approval] → authorization → action_receipt → verification_decision → acceptance_decision`

這個順序就是 `AISOC._run_case` + `_handle_request` 的程式碼順序。驗證器檢查的其中一件事就是「每個 `action_request` 前面有沒有對應的 `agent_egress`」（沒有 = 繞過出口代理）。

### 6.2 一個案件（cases.json）

```json
{
  "case_id": "case-…", "flow_id": "…",
  "decision": {"status": "KNOWN_SUSPICIOUS", "known_label": "ssh_bruteforce", "known_score": 1.0,
               "anomaly_score": 0.600879, "anomaly_threshold": 0.59487, "anomaly_high": true,
               "requires_human_review": false, "requires_agent_investigation": true, "reasons": [...]},
  "investigated": true, "deduplicated": false,
  "requests": [{"action": "block_host", "policy_status": "reserved", "human_decision": "approve",
                "authorized": true, "executed": true, "reason": "executed"}],
  "verification_status": "VERIFIED", "verification_findings": [],
  "acceptance_status": "ACCEPTED", "egress_dropped": []
}
```

**四個欄位 = 四道閘門**：`policy_status`（政策）→ `human_decision`（人）→ `authorized`（簽名器）→ `executed`（PEP）。
情境測試證明「被攻陷的 Agent 造不成副作用」用的就是：所有請求 `executed == false`。

`decision.status` 六種值（Table III）：

| 狀態 | 條件 | 人審？ | 派 Agent？ | 可封鎖？ |
|---|---|---|---|---|
| `KNOWN_SUSPICIOUS` | 已知分支指認攻擊類別 | 否 | 是 | 是（仍需人簽） |
| `SUSPECTED_UNKNOWN` | 已知分支拒答／弱正常 ∧ 異常高 → **疑似零日** | **是** | 是 | 否（只給可逆動作） |
| `MODEL_CONFLICT` | 已知分支很有信心說正常 ∧ 異常高 | **是** | 是 | 否 |
| `INSUFFICIENT_EVIDENCE` | 拒答 ∧ 異常低 | 抽樣 | 否 | — |
| `LOW_RISK_OBSERVE` | 正常 ∧ 異常低 | 否 | 否 | — |
| `UNKNOWN` | 缺欄位／模型失敗／外部沒給結論 | **是** | 否 | — |

---

## 7. 動手破壞它（每個練習都附我實際跑出的輸出）

> 先複製一份，不要改原本的：`cp -r demo-output/aisoc-run /tmp/x`

### 練習 A：改帳本一個字元

```bash
python - <<'EOF'
import json
L = json.load(open('/tmp/x/ledger.json'))
d = L[5]['object_digest']
L[5]['object_digest'] = d[:-1] + ('0' if d[-1] != '0' else '1')   # 只改最後一個字元
json.dump(L, open('/tmp/x/ledger.json', 'w'), indent=2)
EOF
python -m aisoc verify /tmp/x; echo "exit=$?"
```
```json
{"status": "FAILED", "entries": 472, "checkpoints": 23, "receipts": 23,
 "problems": ["chain broken at 5"]}
exit=1
```
**為什麼抓得到**：第 6 筆的 `prev_hash` 是用第 5 筆**原本**的內容算的。

### 練習 B：刪掉最後 10 筆（截斷）

```bash
cp -r demo-output/aisoc-run /tmp/y
python - <<'EOF'
import json
L = json.load(open('/tmp/y/ledger.json')); json.dump(L[:-10], open('/tmp/y/ledger.json', 'w'), indent=2)
EOF
python -m aisoc verify /tmp/y; echo "exit=$?"
```
```json
{"status": "FAILED", "entries": 462, ...,
 "problems": ["truncated below witnessed length 464",
              "receipt rcpt-… executed without ledger authorization (bypass)"]}
exit=1
```
**為什麼抓得到**：哈希鏈本身對「刪尾巴」無感（鏈還是連續的），但外部見證記得「上次長度是 464」；同時有一張執行器收據找不到對應的授權記錄——**兩個獨立機制同時報警**。

### 練習 C：拿掉外部見證

```bash
cp -r demo-output/aisoc-run /tmp/z && echo "[]" > /tmp/z/witness-checkpoints.json
python -m aisoc verify /tmp/z; echo "exit=$?"
```
```json
{"status": "UNKNOWN", "entries": 472, "checkpoints": 0, "receipts": 23, "problems": []}
exit=1
```
**判讀**：`problems` 是空的、鏈也完整，但驗證器**拒絕說 VERIFIED**——因為它無法排除整條鏈被重寫（準則 #8）。這就是「沒有證據 ≠ 沒有問題」在程式碼裡的樣子。

### 練習 D：試著讓測試失敗

把 `aisoc/sandbox/pep.py` 裡 `NonceStore.consume` 的「已用過就回 False」那一行註解掉，跑：
```bash
python -m pytest -q tests/test_policy_pep.py::test_pep_happy_path_then_replay_and_tamper
```
它會失敗——這就是「測試證明控制存在」。記得 `git checkout aisoc/sandbox/pep.py` 還原。

---

## 8. 讀程式碼的路線圖

按這個順序讀，每個檔案先讀 `【老師註解】`，再讀它下面的程式，再跑它「對應」的測試。

| 順序 | 檔案 | 讀完你會懂 | 約幾分鐘 |
|---|---|---|---|
| 1 | `aisoc/canonical.py` | 為什麼簽名前要規範化；`digest` 怎麼算 | 5 |
| 2 | `aisoc/crypto.py` | 鑰匙、簽名、`TrustedKeys.verify` 的三個步驟（含角色檢查） | 10 |
| 3 | `aisoc/owp/objects.py` | 六種證據物件：WorkOrder / CapabilityGrant / PolicyDecision / ActionReceipt / VerificationDecision / AcceptanceDecision；`attenuate` 只能收窄 | 15 |
| 4 | `aisoc/owp/ledger.py` | 哈希鏈怎麼接、Merkle 根怎麼算、檢查點怎麼送見證、加密證據庫為什麼分開 | 20 |
| 5 | `aisoc/owp/verifier.py` | 離線驗證的五項檢查與 VERIFIED/UNKNOWN/FAILED 的判定規則 | 15 |
| 6 | `aisoc/sandbox/untrusted.py` | 為什麼日誌文字要包成 `Untrusted`、注入篩檢只是旗標不是防線 | 5 |
| 7 | `aisoc/sandbox/tools.py` + `agent.py` | Agent 只有哪四個只讀工具（`get_flow / get_host_window / get_recent_logins / lookup_ioc`）；`HeuristicStubAgent` vs `InjectionFollowingStubAgent`（後者模擬被完全攻陷） | 15 |
| 8 | `aisoc/sandbox/egress.py` | 出口代理五道關卡；fail-closed vs fail-open 的那一行 | 10 |
| 9 | `aisoc/sandbox/policy.py` | 四層交集 C_task ∩ C_grant ∩ C_runtime ∩ C_human → allowed/reserved/denied | 15 |
| 10 | `aisoc/sandbox/authorization.py` | 人簽怎麼綁請求摘要；簽名器為什麼「絕不盲簽」 | 15 |
| 11 | `aisoc/sandbox/pep.py` | 八項檢查的順序（①簽名 ②信封綁定 ③時效 ④撤銷 ⑤人簽 ⑥冪等 ⑦nonce ⑧受限執行）、收據 | 20 |
| 12 | `aisoc/soc.py` | 全部接線；`_run_case` 的 11 步、`_handle_request` 的 4 閘門 | 20 |
| 13 | `aisoc/idps/features.py → known_model.py → normality_model.py → dual_model.py → release.py` | 特徵、已知分支、異常分支、Table III、簽名發布閘門 | 30 |
| 14 | `aisoc/adapters/slips.py`、`aisoc_stack.py` | 外部偵測器與外部 SOC 平台怎麼接進來而不動信任鏈 | 20 |
| 15 | `aisoc/scenarios.py`、`aisoc/simulate.py`、`aisoc/cli.py` | 19 個情境怎麼構造、報告怎麼產生、CLI 怎麼接 | 20 |

**判斷一個函數「有沒有做到它說的」的三步法**：
1. 讀註解的「做什麼／拿掉會怎樣」，想像你是攻擊者會怎麼繞。
2. 讀程式，找「拒絕」的那幾行（`raise`、`return ... ok=False`、`denied`）——安全控制的本體永遠是拒絕路徑。
3. 跑「對應」的測試，然後**故意把拒絕那行註解掉再跑一次**，看測試有沒有紅。沒紅代表測試沒測到，那條保證就是空的。

---

## 9. 如果要自己從零重寫一遍：模組建置順序

每個階段都有驗收條件；前一階段不過，不要往下蓋。

| 階段 | 做什麼 | 驗收 |
|---|---|---|
| 0 | `canonical.py`（JCS）、`crypto.py`（Ed25519、角色綁定） | 同一物件不同鍵序 → 相同 digest；錯角色驗簽失敗 |
| 1 | `owp/objects.py` 六種物件 + `to_dict/digest` | 每個物件 round-trip 後 digest 不變 |
| 2 | `owp/ledger.py` 哈希鏈 → Merkle → 檢查點 → 見證（append-only JSONL） | 改任一筆 → 鏈斷；截斷 → 見證長度不符 |
| 3 | `owp/verifier.py` | 無見證 ⇒ UNKNOWN；有竄改 ⇒ FAILED；乾淨 ⇒ VERIFIED |
| 4 | `sandbox/tools.py`、`untrusted.py`、`agent.py`（先寫 stub） | Agent 拿不到任何 signer 物件；工具只讀 |
| 5 | `sandbox/egress.py` | 帳本寫入失敗 ⇒ 訊息不轉發；超大／超速 ⇒ 丟 |
| 6 | `sandbox/policy.py` | 跨租戶 ⇒ denied；高影響 ⇒ reserved；授予過期 ⇒ denied |
| 7 | `sandbox/authorization.py` | 無人簽／人簽摘要不符 ⇒ 簽名器拒簽 |
| 8 | `sandbox/pep.py` | 重放 ⇒ 拒；過期 ⇒ 拒；改參數 ⇒ 拒；撤銷 ⇒ 拒 |
| 9 | `soc.py` 接線 | 端到端：乾淨案件 VERIFIED/ACCEPTED；被攻陷 Agent 零執行 |
| 10 | `idps/*`（可以最後做！） | 留一家族有 recall；FPR 在驗證集定門檻 |
| 11 | `scenarios.py` 15 情境 + 4 消融 | 消融拿掉控制 ⇒ 攻擊成功（證明控制 load-bearing） |
| 12 | `adapters/*`、`cli.py` | fixture 跑通；`verify` 可離線 |

**為什麼模型放最後？** 因為這個專案的命題是：就算模型很弱、就算 Agent 被攻破，治理鏈仍然成立。先把鏈做對，再換更強的模型，鏈一行都不用改。

---

## 10. 常見問題（答辯常被問）

**Q：你怎麼證明那是零日？**
A：我們不證明。系統輸出的是「**疑似**未知」(`SUSPECTED_UNKNOWN`)：已知分支拒答 ∧ 異常分支高。它的作用是**把人叫來**，而不是下結論。留一家族實驗（§5 步驟 3）量化這條路徑的召回率，0.619 就是誠實數字。

**Q：誤報率和分析師負載？**
A：`report.md` 的 FPR 0.0037 是在驗證集固定門檻後量的；200 案件只有 23 個進調查、其中 17 個需人簽。去重視窗 (`dedup_window_s=300`) 抑制同主機同狀態的重複。數字是合成資料的，真實網路要用 Slips 跑過再量。

**Q：私鑰被盜怎麼辦？**
A：一角色一鑰匙，所以偷到 `authorizer` 鑰匙也簽不出人類批准、簽不出帳本檢查點。授權單次 (nonce)、短時效 (預設 300 秒)、可撤銷 (`RevocationList`)。Agent 沙箱內**根本沒有**任何私鑰可偷。模擬裡鑰匙在記憶體；正式環境放 HSM。

**Q：基線被投毒怎麼辦？**
A：門檻在驗證集上定、分析師標籤需人工審核才進訓練集、模型發布要簽名 + 哈希（準則 #10）——壞模型進不了沙箱。但我們**沒有**實作投毒偵測本身，這在誠實範圍裡。

**Q：審批者只會按「同意」（橡皮圖章）怎麼辦？**
A：`HumanApprover` 簽名綁定的是**請求摘要**，所以批的是「這個動作、這個目標、這些參數」，批完改參數 PEP 會拒（情境「parameter change after approval」）。防快速批准的時間下限我們沒做，列在待辦。

**Q：跟商用 AI SOC 差在哪？**
A：不是偵測更準，而是**問責可離線驗證**：帳本只存指紋、公鑰驗證、不需信任 SOC 營運者。這補的是業界缺口（審計證據不統一、步驟間上下文不入帳），不是「首創」。

**Q：為什麼 fail-closed？業務會不會被拖垮？**
A：消融「egress proxy fails open when the audit domain is down」示範了反面：改成 fail-open，請求還是會到控制面，但驗證器只能事後發現「缺出口紀錄」——變成偵測型而非預防型。這是設計取捨，論文選預防。

---

## 11. 誠實範圍（不要在答辯時被問倒）

- 全部資料是**合成**的；Agent 是**確定性 stub**，不是 LLM。
- 五個信任域跑在**同一個 Python 進程**，論文的保證需要它們由不同管理員掌控、沙箱用 microVM 隔離。
- 外部見證是本地 append-only 檔案；正式環境要是第三方服務或公開時間戳。
- 鑰匙在記憶體；正式環境要 HSM。
- 沒有實作：投毒偵測、審批最短思考時間、模型檔在沙箱內被竊取的防護。
- 所有數字描述**這個參考實作**，不是真實流量的偵測結果，不是安全認證。

---

## 12. 決賽現場演示腳本（3 個，各 1 分鐘）

| 演示 | 指令 | 觀眾看到 |
|---|---|---|
| 改一個字元就被抓 | §7 練習 A | `FAILED`, `chain broken at 5` |
| 偽造／重放被拒 | `python -m aisoc simulate --out /tmp/d \| grep -E "replay\|parameter change\|cross-tenant"` | 三行 `[ok]`；開 `report.md` 讀 expected 欄 |
| 逃逸後仍簽不了名 | `grep -n "老師註解】AISOC " -A 7 aisoc/soc.py` 再指出 `self.keys` 從未傳進 agent；跑 `python -m pytest -q tests/test_end_to_end.py::test_compromised_agent_cannot_cause_side_effects` | 1 passed |

錄一份螢幕備份：`script -q demo.log -c "python -m aisoc simulate --out /tmp/d && python -m aisoc verify /tmp/d"`。

---

*本指南對應 PR #5 分支 `feat/slips-aisoc-adapters`；所有輸出於 2026-11-02 以 Python 3.12.3 實測。*
