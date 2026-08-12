# Customer Acceptor 独立复核清单

> 用途：Customer Acceptor 在签署 JudgmentCommitment 与最终验收前逐项
> 独立核对。**本清单不替代客户判断**，Acceptor 可以拒绝或要求补证。

## A. 判断承诺（JudgmentCommitment）签署前

- [ ] 我确认理解 Issue 快照与验收条件；判断工件可确定性编码
- [ ] JudgmentCommitment 的 `action_constraint_digest` 可被 adapter profile 重算
- [ ] 有效期窗口（valid_from / expires_at）符合预期
- [ ] 我的签名密钥独立于 Manager/Agent/Sidecar 域

## B. 绑定与执行（ActionBindingManifest / AgentRequest / Receipt）

- [ ] Manifest 引用了我签署的 JudgmentCommitment（id/digest 精确匹配）
- [ ] allowed tools / action kinds / path roots 未扩大判断约束交集
- [ ] AgentRequest 与 ActionReceipt 原生绑定同一 Manifest（非 metadata）
- [ ] 执行收据形成完整因果链，required artifacts 摘要匹配

## C. 验证与绑定决定（VerificationDecision / BindingDecision）

- [ ] VerificationDecision = VERIFIED 且引用同一 Scope
- [ ] BindingDecision = BOUND 且 reason codes 为空
- [ ] 高风控场景 AuthorityCheckpoint 在行动发生时点（as-of）有效
- [ ] 决策历史无 fork / rollback / 未授权替代

## D. 验收与结算准备

- [ ] 双门：VERIFIED ∧ BOUND ∧ EffectiveAcceptance=ACTIVE
- [ ] 商业证据（SOW、定金、验收授权）是外部证据，协议未制造
- [ ] READY_FOR_SETTLEMENT_REVIEW 不等于已付款/已结算

## E. 最终决定

- [ ] 接受 / 拒绝 / 补证（三选一，签名决定并归档）
