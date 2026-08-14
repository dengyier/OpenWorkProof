# 离线验签说明(Offline Verification)

OpenWorkProof 的证据链设计允许**第三方不接入任何一方系统**、仅凭一份
复制的证据包离线复核全部事实。本文件说明验签的入口、输入与复现步骤。

## 1. 适用场景

- 纠纷复核:验收后,独立第三方拿证据包即可验证"这份 accepted/rejected
  结论是否由 WorkOrder 绑定的 Acceptor 真实签名、证据链是否完整";
- 交付审计:赛事评委或监管方无需运行任何一方服务,离线重放签名历史;
- 可复现性:证据包 + 本说明构成可独立执行的协议事实复核材料；它不证明
  外部客户决定、付款或部署在现实中已经发生。

## 2. 核心入口

### `verify_acceptance_bundle`(终态验收/拒绝)

位于 `src/openworkproof/acceptance.py`,接受**无活动账本**的完整证据快照:

```python
from openworkproof.acceptance import verify_acceptance_bundle

result = verify_acceptance_bundle(
    work_order=work_order,              # WorkOrder(含六角色绑定公钥)
    report=report,                      # CompositionReport(权威账本工件)
    effective_grants=grants,            # 规范化 Grant 前缀
    grant_attempts=attempts,            # 签发尝试
    receipts=receipts,                  # ActionReceipt 信封序列
    committed_evidence=evidence,        # (CommittedEvidence, ...)
    acceptance_receipt=signed,          # 终态验收收据(与 rejection 二选一)
    public_keys=public_keys,            # {key_id: Ed25519PublicKey}
    reports=reports,                    # 全部 CompositionReport(含 recomposition 链)
    rejection=rejection,                # 终态拒绝收据(与 acceptance 二选一)
)
```

**Exactly one** 终态决策(acceptance 或 rejection)必须绑定请求 tip;
`public_keys` 必须与 WorkOrder 绑定公钥一致。

### `verify_composition_bundle`(报告链复核)

位于 `src/openworkproof/acceptance.py`,复核报告一一对应与顺序唯一性,
并验证 composition/recomposition 链。

## 3. 输入如何收集(导出端)

证据包的导出由生产协调器完成(见 M2 演示 `test_delivery_m2.py` 的
step 9):从账本读 receipts/grants/attempts,从证据根读 committed
evidence 字节,从签名草稿取 AcceptanceReceipt。导出后:

1. 每个 EvidenceRef 的 `path` 指向证据根内文件,`sha256` 为文件内容摘要;
2. `CommittedEvidence(reference=ref, payload=bytes)` 保持原始字节;
3. receipts 按 sequence 排序,evidence 按 path 排序(可哈希稳定)。

## 4. 验证内容(验签器做什么)

1. **签名授权历史**:重建确定性索引,验证每条收据的 Ed25519 签名,
   父集精确匹配,genesis 唯一,active patch/rework/approval/
   composition/independent-result episode 语义正确;
2. **策略回放**:重算 Grant 衰减、余额、撤销、single-use、配额与拒绝
   优先级,验证证据引用与 publication 闭包;
3. **证据绑定**:逐字节重哈希 committed evidence,与 EvidenceRef.sha256
   和收据 output_digest 一致;
4. **报告绑定**:CompositionReport 与触发收据一一对应、顺序唯一;
   双报告链(recomposition)两段 signed report-to-trigger 绑定;
5. **终态互斥**:acceptance 与 rejection 二选一,与请求 tip 绑定,
   Acceptor 签名权威与 WorkOrder 绑定公钥一致;
6. **篡改拒绝**:报告/收据/关联因子/公钥/账本表任一字节被改即失败。

## 5. 快速复现(M2 演示)

```bash
./.venv/bin/python -m pytest tests/test_delivery_m2.py -q
```

`test_m2_full_chain_...` 的 step 9 演示完整导出 + `verify_acceptance_bundle`
离线验签通过;篡改测试验证任何单字节修改均被拒绝。

## 6. v0.2 Delivery Package

Evidence Lifecycle v0.2 在旧版签名回放之上增加 SubjectClaim、正负证据臂、
VerificationDecision、追加式验收历史、manifest 和结算就绪度快照。常用入口：

```bash
# 从权威 ledger 导出一个新目录；目标目录必须不存在
owp delivery-build --privacy-view public pilot.sqlite3 delivery-package/

# 三种纯离线读操作
owp audit-replay delivery-package/
owp audit-explain delivery-package/
owp audit-compare older-package/ delivery-package/

# 从 ledger 推导结算就绪度
owp settlement-status pilot.sqlite3
```

`audit-replay` 会重新哈希 manifest 和全部文件，验证签名、正负臂、决定及
验收历史。`VERIFIED` 表示冻结的正臂通过、至少一个真实负臂按预期失败且
证据/独立性要求闭合；它不等于客户接受。`READY_FOR_ACCEPTANCE` 表示可以
提交给绑定 Acceptor 决定；它不等于付款、资金释放或结算完成。

仓库内两份 additive v0.2 案例可直接离线回放：

```bash
./.venv/bin/python tests/evidence-bundles/verify_evidence_bundle.py \
  tests/evidence-bundles/rich-4196-v02-delivery-package.json
./.venv/bin/python tests/evidence-bundles/verify_evidence_bundle.py \
  tests/evidence-bundles/dify-33013-v02-delivery-package.json
```

它们是公开 Issue 的协议复现样本，不是客户采用、客户验收或商业收入证据。

## 7. v0.3 Scope Coverage Delivery Package

v0.3 在 v0.2 的正负臂验证之上增加签名 `EvaluationScopeManifest`，把
“验证了哪些文件、测试与交付对象”冻结为协议事实。导出端支持三种单调
隐私视图：

| 视图 | 可见内容 | 完整离线重放 |
|---|---|---|
| `public` | 聚合范围、计数、决定、原因码、Scope 摘要 | 否 |
| `diagnostic` | public + 双臂状态与诊断原因 | 否 |
| `customer_private` | diagnostic + 原始签名对象、成员、选择器、证据和公钥 | 是 |

Python 导出与复核入口：

```python
from pathlib import Path
from openworkproof.delivery_package import (
    export_delivery_package,
    verify_delivery_package,
)

manifest = export_delivery_package(
    Path("pilot.sqlite3"),
    Path("delivery-package-private"),
    privacy_view="customer_private",
)
result = verify_delivery_package(Path("delivery-package-private"))
assert manifest.full_offline_replay is True
assert result.full_offline_replay is True
```

公开包明确写入 `full_offline_replay: false`，只保留原始 Scope Manifest
摘要与聚合覆盖事实；它不包含 locator、pytest node ID、源码字节、客户
身份或选择器规格字节。只有客户私有包的 `verify.sh` 可以重算成员/选择器
绑定、双臂 ObservedScope、签名决定和验收/结算准备快照。

Scope Coverage Report 的 `VERIFIED` 结论严格限定在签名 Scope 内：声明
人口与各臂观察人口一致、必选目标已覆盖、已注册负向控制被捕获。它不表示
绝对正确、法规合规、客户采用、付款、自动结算或部署已经发生。

仓库提供一份自包含 v0.3 演示包，可在清空代理变量后独立复核，无需网络或
原始 ledger：

```bash
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
  ./.venv/bin/python tests/evidence-bundles/verify_evidence_bundle.py \
  tests/evidence-bundles/rich-4196-scope-v03-delivery-package.json
```

预期输出包含 `VERIFICATION PASSED` 与 `v0.3 scope: satisfied`。该包由
OpenWorkProof 构造，用于展示范围遗漏如何从旧绿灯变成 `UNKNOWN`，以及补齐
必选测试后如何形成有边界的 `VERIFIED`；它不是 Rich 上游采用或客户案例。
买方可读结构见
[Scope Coverage Report 示例](pilot/scope-coverage-report.example.md)。

## 8. 边界与诚实声明

- 离线验签**证明证据链与签名的有效性**,不证明"外部真实人类复核过"——
  外部个人签署属线下事件,不由本仓库保证;
- `public_keys` 由验证者自行获取;若 WorkOrder 绑定公钥本身不可信,
  验签结果仅在"信任该 WorkOrder 绑定"前提下成立。

## v0.4 包离线验证（binding replay）

v0.4 交付包通过 `verify_delivery_package` 离线验证，分两层：

1. **Layer 1（结构）**：manifest 精确文件集、引用绑定、报告渲染
   derived-truth 一致。失败即 `DeliveryPackageError`（package verification
   failure），**绝不以 UNBOUND 掩盖 Layer 1 失败**。
2. **Layer 2（绑定重放）**：客户私有视图从 `binding-replay-inputs.json`
   重放 judgment-to-action 映射，结果必须与报告一致（BOUND / UNBOUND /
   INDETERMINATE）；diagnostic/public 视图只报告
   `binding_replay: unavailable_in_this_view`，不暴露 Issue 文本、路径、
   测试名、客户密钥或商业证据。

```bash
python tests/evidence-bundles/verify_evidence_bundle.py \
  tests/evidence-bundles/rich-4196-binding-v04-delivery-package.json
```

CLI：`owp package replay --binding <package>`。

## v0.5 包离线验证（verification integrity）

v0.5 交付包通过 `verify_delivery_package` 离线验证。客户私有视图除 v0.3
对象外还携带：selector 规格证据（`scope/selectors/*`）、eligible/selected
总体证据（`evidence/populations/<arm>/<path>`）、负控证据
（`evidence/controls/<arm>/<path>`）与 settlement-readiness。

离线验证只读取包内字节：重放每条总体证据（sha256/size 精确比对）、从包内
selector 规格证据重放 rule-output witness、重算 population 与 control 评估，
并要求与签名决策中的 `integrity_assessment` 逐字段一致，再完整重放决策草案
（签名字节一致）。篡改任一 contract、observation、证据、签名或关系即
`DeliveryPackageError`。diagnostic/public 视图仅携带派生报告，不含任何
客户、路径或总体证据内容。

派生视图：`explain_integrity_package` 输出 eligible/selected 计数、capture
比例、population/control 状态、各负控 target 与状态、reason codes 与边界
声明（验证证据不证明付款或客户验收）；`compare_integrity_packages` 识别
rule/engine/population/fixture/provocation/failure-signature 变化。
