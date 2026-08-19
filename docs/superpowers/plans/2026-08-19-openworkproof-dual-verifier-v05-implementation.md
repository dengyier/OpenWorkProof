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

- `DUAL_VERIFIER_DIVERGENCE` 加入 `VerificationIntegrityReasonCode` + 决策
  reason code 集合；走 schema-registry 流程（如 schema 变更）。

## Task 3：组合层

- `compose_verification_decision_v05` high_risk 分支：
  - 要求 2 个不同 verifier binding 覆盖全部 arm；
  - 交叉验证正臂 evidence_snapshot_digest；
  - 不满足 → UNKNOWN（INDEPENDENCE_INSUFFICIENT / DUAL_VERIFIER_DIVERGENCE）。
- `prepare/commit_verification_decision_v05` 传导新 reason code 到
  assessment + 顶层（与 RECEIPT_RETRACTED 同模式）。

## Task 4：独立双审 + 门禁

- spec 审查 + quality/security 审查；
- focused / 冻结兼容 / candidate 两套件 / required-live 全量零失败零 skip 零 warning；
- pip check / compileall / git diff --check；Docker 零残留。

## 提交策略

- 本地 follow-up commits（不 push，等待外部重新审查授权）。
- 候选 inventory 在 Task 3 后重建（models.py 等 allowlist 文件变更）。
