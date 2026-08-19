# Dual Verifier v0.5 实施计划

> 日期：2026-08-19
> 规格：`docs/superpowers/specs/2026-08-19-openworkproof-dual-verifier-v05-design.md`
> 纪律：每 Task RED→最小修复→回归；Task 末独立双审；全程不动 v0.1–v0.5 冻结面。

## 范围

high_risk 决策组合要求双验证者独立执行 + 证据摘要交叉收敛；分歧 → UNKNOWN。
standard 语义不变。新 reason code `DUAL_VERIFIER_DIVERGENCE`。

## Task 1：RED 攻击测试

**文件**：`tests/test_dual_verifier_v05.py`

- 撒谎验证者场景：high_risk profile（2 bindings）→ 单验证者伪造全部 arm
  results → 当前实现产出 VERIFIED（RED：应为 UNKNOWN / INDEPENDENCE_INSUFFICIENT）
- 单密钥冒充双验证者：同一 key 两套结果 → 当前接受（RED：应拒绝）
- 双验证者证据不一致：两个不同 verifier 各自结果，正臂 evidence snapshot
  不同 → 当前产出 VERIFIED（RED：应 UNKNOWN / DUAL_VERIFIER_DIVERGENCE）

## Task 2：模型层（reason code）

- `DUAL_VERIFIER_DIVERGENCE` 加入 `VerificationReasonCodeV05`（顶层决策 reason
  code），**不加入** `VerificationIntegrityReasonCode`（避免污染 population/
  control assessment 集合；独立审查确认这是正确选择）。
- 走 schema-registry 流程（schema 变更时重新生成 + 更新锚点）。

## Task 3：组合层

- `compose_verification_decision_v05` high_risk 分支：
  - 接受双套 arm results（每 arm 每个 verifier 一套）；
  - 逐字段交叉验证全部承载结论的字段（expectation_status / execution_status /
    mutation_status / reason_codes / observed_* / scope_expectation_status /
    population_observations / control_observation / evidence snapshot），
    任一不一致 → `VerificationInputError`（分歧不可得决策，重跑或降级）；
  - single_set 必须是同一 verifier 覆盖全部 arm（split 覆盖拒绝）；
  - 收敛 → 代表集（每 arm 一个结果，按 arm_result_id 排序）+ 双签名；
  - replay/commit 以决策签名数（2）恢复独立性充分
    （`assumed_independence_sufficient`）；prepare 加载全部 arm results
    （`latest_only=False`）供双套判定。
- `prepare/commit_verification_decision_v05` 传导（commit stale 判定对
  high_risk 按每 arm 最新 created_at，容忍同批双 verifier）。

## Task 4：独立双审 + 门禁

- spec 审查 + quality/security 审查；
- focused / 冻结兼容 / candidate 两套件 / required-live 全量零失败零 skip 零 warning；
- pip check / compileall / git diff --check；Docker 零残留。

## 提交策略

- 本地 follow-up commits（不 push，等待外部重新审查授权）。
- 候选 inventory 在 Task 3 后重建（models.py 等 allowlist 文件变更）。
