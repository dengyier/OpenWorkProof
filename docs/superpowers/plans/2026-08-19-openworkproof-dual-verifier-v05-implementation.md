# Dual Verifier v0.5 实施计划

> 日期：2026-08-19
> 规格：`docs/superpowers/specs/2026-08-19-openworkproof-dual-verifier-v05-design.md`
> 纪律：每 Task RED→最小修复→回归；Task 末独立双审；全程不动 v0.1–v0.5 冻结面。
> 状态：已完成（7 轮独立双审全部 APPROVE，最终 HEAD `837dbb1`，见"最终实现"）。

## 范围

high_risk 决策组合要求双验证者独立执行 + 结论字段交叉收敛；分歧 → 组合失败
（`VerificationInputError`，临时折中，见 spec §4.2，v0.6 用
`DUAL_VERIFIER_DIVERGENCE` 正式入账）。standard 语义不变。新 reason code
`DUAL_VERIFIER_DIVERGENCE`。

## Task 1：RED 攻击测试

**文件**：`tests/test_dual_verifier_v05.py`

- 撒谎验证者场景：high_risk profile（2 bindings）→ 单验证者伪造全部 arm
  results → 当前实现产出 VERIFIED（RED：应为 UNKNOWN / INDEPENDENCE_INSUFFICIENT）
- 单密钥冒充双验证者：同一 key 两套结果 → 当前接受（RED：应拒绝）
- 双验证者证据不一致：两个不同 verifier 各自结果，正臂 evidence snapshot
  不同 → 当前产出 VERIFIED（RED：应 UNKNOWN / DUAL_VERIFIER_DIVERGENCE）

最终 10 个测试覆盖：单验证者→UNKNOWN、分歧→VerificationInputError、
收敛→VERIFIED、split 覆盖拒绝、全链 commit+replay（双签名）、
联署无结果→UNKNOWN、离线包重放、追加轮重放稳定、导出、commit 拒绝
压制失败轮的手工引用攻击。

## Task 2：模型层（reason code）

- `DUAL_VERIFIER_DIVERGENCE` 加入 `VerificationReasonCodeV05`（顶层决策 reason
  code），**不加入** `VerificationIntegrityReasonCode`（避免污染 population/
  control assessment 集合；独立审查确认这是正确选择）。
- 走 schema-registry 流程（schema 变更时重新生成 + 更新锚点）。

## Task 3：组合层

- `compose_verification_decision_v05` high_risk 分支：
  - 接受双套 arm results（每 arm 每个 verifier 一套）；
  - 逐字段交叉验证全部承载结论的字段（expectation_status / execution_status /
    mutation_status / reason_codes / action_receipt_ids / observed_* /
    scope_expectation_status / population_observations / control_observation /
    evidence snapshot），任一不一致 → `VerificationInputError`（分歧不可得
    决策，重跑或降级；N9 拒绝每 (arm, verifier) 多余行）；
  - single_set 必须是同一 verifier 覆盖全部 arm（split 覆盖拒绝）；
  - 收敛 → 代表集（每 arm 一个结果，按 arm_result_id 排序）+ 双签名；
  - 决策引用**完整双套**（`decision_reference_results`）；replay/commit/离线包
    均从决策自身引用（`selected_ids=parents`）重跑交叉验证，不依赖签名数
    推导独立性（`assumed_independence_sufficient` 已删除——N1）；
  - prepare 加载 `latest_per_verifier`（每 (arm, verifier) 最新——N3/N7）。
- `prepare/commit_verification_decision_v05` 传导：commit stale 门要求决策
  引用集**精确等于** prepare 会加载的那一套（high_risk 每 (arm, verifier)
  最新 / standard 每 arm 最新——N8，手工挑选引用在 commit 被拒绝）。
- 导出/离线包使用决策自身引用集（N8-export）。

## Task 4：独立双审 + 门禁

- spec 审查 + quality/security 审查：**7 轮**（R1-R9/N1-N9/N13 等全部关闭，
  终审 APPROVE + APPROVE-WITH-NOTES 后按 Notes 清理提交 `837dbb1`）；
- focused / 冻结兼容 / candidate 两套件 / required-live 全量零失败零 skip 零 warning；
- pip check / compileall / git diff --check；Docker 零残留。
- 候选 inventory 在最终 HEAD 重建（`837dbb1`）。

## 最终实现

- 提交序列：`291df11`（组合层）→ `d9a2a19`（schema 重生成）→ `7a5bc82`
  （R1-R9）→ `afd689e`（N1/N2/N5）→ `3f6f351`（spec 对齐）→ `43d77f9`
  （B1/N7）→ `acca51f`（N8-export/N9）→ `fe8ed8e`（N8 stale 门）→ `837dbb1`
  （Notes 清理：imports 上移、形状门、报错文案、§4.2 注释、自报 created_at
  诚实边界）。
- 本地 follow-up commits（不 push，等待外部重新审查授权）。

## 提交策略

- 本地 follow-up commits（不 push，等待外部重新审查授权）。
- 候选 inventory 在最终 HEAD 重建（models.py 等 allowlist 文件变更）。
