# 独立 Acceptor 操作清单（Acceptor Checklist）

Acceptor 是独立决定接受或拒绝交付的客户方角色，不替代验证者，也不由交付团队
代签。签署前请逐项完成以下清单。

## 签署前检查

1. 确认 WorkOrder 绑定的 Acceptor 密钥由客户自己控制；
2. 确认同一交付的 Surface Bundle 与 Acceptance Bundle 精确属于同一 WorkOrder；
3. 确认 Verifier 的 VerificationDecision 与自己的终态 receipt 都由
   AcceptanceDecisionBindingV01 精确绑定；
4. 确认验证结论为 `VERIFIED` 后才考虑接受；`REFUTED` 或 `UNKNOWN` 不得接受；
5. 确认验收条件、必选产物、允许工具与排除项与开工前冻结口径一致。

## 签署流程

1. 系统生成无密钥草稿（`prepare`）；
2. Acceptor 在外部独立环境签名（`sign`）；
3. 追加式事务提交（`commit`）。

## 合法拒绝

合法拒绝（`REJECTED`）是可验证终态：必须签署拒绝 receipt，不得被渲染成“交付
成功”。拒绝后不得回写或篡改历史验收事实。

## 停止条件

- 缺失或无法核验的 binding：拒绝并停止；
- 验证结论与交付不一致：拒绝并停止；
- 验收口径与冻结口径不一致：拒绝并停止。

签署不等于付款、不等于结算完成，也不构成法律审计。
