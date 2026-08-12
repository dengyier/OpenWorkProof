# Judgment-to-Action Binding — 试点结果模板

> 每个字段要么由协议输出填充，要么标记 `not_evidenced`。商业证据字段只
> 引用外部证据 id，**协议状态绝不制造商业事实**。

## 协议输出（自动）

```text
work_order_digest: <协议>
judgment_commitment_digest: <协议>
action_binding_manifest_digest: <协议>
verification_decision: <协议: VERIFIED|REFUTED|UNKNOWN>
binding_decision: <协议: BOUND|UNBOUND|INDETERMINATE>
binding_reason_codes: <协议>
authority_status: <协议: not_required|current|missing|stale|forked|unavailable>
acceptance: <协议: NONE|ACTIVE|SUSPENDED|WITHDRAWN|SUPERSEDED>
settlement_readiness: <协议: NOT_READY|...|READY_FOR_SETTLEMENT_REVIEW>
binding_replay (客户私有视图): <协议>
```

## 外部商业证据（仅引用 id，未填充为 not_evidenced）

```text
sow_id: not_evidenced
deposit_reference: not_evidenced
acceptor_appointed_by: not_evidenced
acceptance_decision: not_evidenced
next_order_intent: not_evidenced
```

## 试点记录

```text
issue_id: <真实 Issue>
repository: <仓库>
baseline_revision: <40 字符>
agent_change: <候选提交/补丁>
judgment_artifact_digest: <协议>
acceptor_key_domain: <客户控制域，独立于交付团队>
attack_pre_registration: <A1–A18 或 holdout id>
resource_used: <人日 / 人民币，不得超过 8 人日或 ¥2,000>
```

## 结论

- 技术结论：正常链与注册攻击分类结果（BOUND / UNBOUND / INDETERMINATE）
- 商业结论：是否签署 SOW、收到定金、完成接受/拒绝/补证决定
- 下一步：接受下一单意向，或记录可复用的明确拒绝原因

> 本模板不构成付款证明、结算证明或客户验收证明。
