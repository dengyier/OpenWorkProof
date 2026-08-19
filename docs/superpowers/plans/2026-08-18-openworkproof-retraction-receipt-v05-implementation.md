# RetractionReceipt v0.5 实施计划

> 日期：2026-08-18
> 规格：`docs/superpowers/specs/2026-08-18-openworkproof-retraction-receipt-v05-design.md`
> 纪律：每 Task RED→最小修复→回归；Task 末独立双审；全程不动 v0.1–v0.5 冻结面。

## 范围裁剪（本阶段实现，其余留给 v0.6）

本阶段实现规格的核心闭环：

- ✅ `RetractionReceiptV05` 模型（`retraction_effect` 必选，本阶段仅 `refuted`
  与 `confidence_downgrade` 两值；reason 四选一闭合）。
- ✅ 签名域 `retraction-receipt`，Manager/Verifier 签发，WorkOrder 绑定。
- ✅ 事务 `commit_retraction_receipt`（append-only 表 + 不可变触发器 + 崩溃恢复）。
- ✅ 查询 `receipt_retraction_status` / `retraction_chain`。
- ✅ 决策兼容：被 `evidence_refuted` 撤销的收据 → 决策 UNKNOWN +
  `RECEIPT_RETRACTED`；正臂 contradicted 时 REFUTED 优先。
- ✅ 离线交付包重放可见 retraction 链。
- ⏭️ v0.6：撤销撤销（二次 retraction）、链式传播、refutes_decision_id 扩展、
  partial refutation 细分分类。

## Task 1：模型层

**文件**：`src/openworkproof/models.py`（新增，不改现有类）、
`src/openworkproof/schemas/v0.5/retraction-receipt.schema.json`、
`src/openworkproof/schema_registry.py`（注册 v0.5 新对象）。

**RED**：`tests/test_retraction_receipt_v05.py`——
- 合法 payload 通过 `model_validate`；
- digest 重算校验（domain `openworkproof/retraction-receipt/v0.5`）；
- `refutes_decision_id/digest` 成对约束；
- `causal_parent_ids` 必须含 target、排序、唯一；
- `evidence_refuted + confidence_downgrade` 拒绝；
- `retracted_at <= target occurred_at` 拒绝；
- 冻结 schema SHA 不变（新增对象不影响既有 digest）。

## Task 2：事务与查询层

**文件**：`src/openworkproof/retraction.py`（新模块，参照 acceptance.py 模式）。

**RED**：`tests/test_retraction_transactions_v05.py`——
- 成功提交 + 回读 exact committed truth；
- pre-COMMIT fault 零写入；COMMIT-ACK 回读；cleanup 失败不改变 truth；
- 并发同一 retraction_id 恰好一个 committed；
- UPDATE/DELETE 物理拒绝（触发器）；
- `receipt_retraction_status` 返回 standing / refuted / confidence_downgraded；
- 伪造 target digest、错误签名角色、时间倒置全部拒绝。

## Task 3：决策兼容层

**文件**：`src/openworkproof/verification.py`（`prepare_verification_decision_v05`
检查被撤销收据）、`src/openworkproof/delivery_package.py`（重放含 retraction）。

**RED**：`tests/test_retraction_decision_v05.py`——
- 提交 profile + arm results（引用一个已签发收据）+ 该收据的
  `evidence_refuted` retraction → 决策必须是 UNKNOWN + `RECEIPT_RETRACTED`
  （当前实现返回 VERIFIED，RED）；
- 正臂 contradicted → REFUTED 优先（即使有 retraction）；
- `confidence_downgrade` retraction → 决策不受影响（降级不反驳）；
- 离线包重放：retraction 链可见，篡改 retraction 字段失败关闭。

## Task 4：独立双审 + 门禁

- spec 审查 + quality/security 审查（独立 subagent）；
- focused 套件（含新测试）/ 冻结兼容 216 / candidate 两套件 /
  required-live 全量零失败零 skip 零 warning；
- pip check / compileall / git diff --check；
- Docker 零残留。

## 提交策略

- 本地 follow-up commits（不 push，等待外部重新审查授权）。
- 候选 inventory 在 Task 3 完成后重建（models.py 在 SOURCE_ALLOWLIST 内）。

## 诚实边界

不声称：客户采用、付费、上游采纳、撤销被真实使用、撤销正确性或下游行动。
