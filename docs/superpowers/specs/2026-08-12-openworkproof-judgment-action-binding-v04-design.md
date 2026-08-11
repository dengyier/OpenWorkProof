# OpenWorkProof Judgment-to-Action Binding v0.4 研发设计规格

**日期：** 2026-08-12

**状态：** 设计章节已获用户确认；正式文档待用户复核

**目标基线：** `main@7a98956eb3fb84a3046f3d18743148bdd7e6e44c`

**首个适配场景：** AI Agent 代码交付

**兼容基线：** Evidence Lifecycle v0.2、Scope-Bound Verification v0.3

## 1. 决策摘要

OpenWorkProof v0.4 增加 **Judgment-to-Action Binding（判断—行动绑定）**。

v0.1—v0.3 已能验证授权、执行、证据生命周期和检查范围，但尚不原生证明：

> Agent 实际执行的行动，是否仍然对应客户原先批准的业务判断。

v0.4 不把 OpenWorkProof 变成业务判断引擎。它新增一个通用绑定内核，并以
GitHub Issue/PR 代码交付作为首个领域适配器：

1. Customer Acceptor 在执行前签署 `JudgmentCommitment`；
2. Manager 用 `ActionBindingManifest` 将该判断、WorkOrder 和确定性适配规则
   绑定；
3. Agent 的 v0.4 请求和 ActionReceipt 必须引用同一个 Manifest；
4. 独立 Verifier 重算判断、行动和适配器映射，签署 `BindingDecision`；
5. 高风险交付可增加外部 `AuthorityCheckpoint`，提供截至某一时点的单调权威
   指针；
6. 可结算准备度必须同时满足当前 `VerificationDecision = VERIFIED`、当前
   `BindingDecision = BOUND` 和客户 `EffectiveAcceptance = ACTIVE`。

首版采用“最小通用内核 + 代码交付适配器”，不建设通用策略平台、资金托管、
自动结算或 hosted control plane。

## 2. 问题与外部验证输入

### 2.1 攻击模型

外部 Study 014 给出了一个明确边界：若判断批准行动 `250.00`，内部攻击者将
行动改为 `2500.00`，并使用合法密钥把受影响对象完整重签，则签名、摘要、
因果父节点和授权窗口都可能继续自洽。

签名只证明“这些字节由这个密钥签署”，不自动证明“这些字节仍表达原判断
批准的行动”。缺失的属性是跨判断层与执行层的语义绑定。

该研究固定在 OpenWorkProof 历史提交 `8eeca6f`，不是对当前 v0.3 的安全审计，
也不证明任一项目获得外部采用。它可以作为攻击模型和互操作证据，不能作为
当前版本认证。

### 2.2 当前能力与缺口

当前版本已覆盖：

- WorkOrder、Grant、AgentRequest 和 ActionReceipt 的签名与摘要绑定；
- 工具参数、因果父节点、授权窗口、角色、配额和证据引用；
- 正臂、真实负臂、独立 Verifier 与 `VERIFIED / REFUTED / UNKNOWN`；
- SubjectClaim、CommitmentAnchor、PolicyAnchor 和验收生命周期；
- EvaluationScopeManifest、声明/观察范围 exact-match 和范围敌对矩阵；
- 离线包、客户私有视图、撤回与替换。

当前版本不原生覆盖：

- 判断工件、规范化事实、Disposition 与精确行动的通用承诺；
- 判断到行动约束的确定性领域映射；
- 领域判断器的确定性重放；
- 两条分别自洽的 WorkOrder 链谁是当前权威链；
- 外部政策或判断截至验证时点是否仍有效；
- 普通 metadata 中的引用是否真正形成签名语义绑定。

### 2.3 最新本地验证边界

目标基线在 2026-08-12 fresh 验证中取得：

- 便携全量：`2647 passed、0 failed、7 skipped、7 warnings`；
- image supply-chain：`67 passed`；
- candidate artifact chain：`1 passed、83 deselected`；
- required-live：`2654 passed、0 failed、0 skipped、10 warnings`。

上述结果证明当前本地 v0.3 声明范围内的工程门，不证明 v0.4 已实现，也不证明
客户采用、付费、验收、部署或资金结算。

## 3. 目标与非目标

### 3.1 协议目标

1. 执行前存在由 Customer Acceptor 签署的、可确定性编码的业务判断承诺。
2. 每个 v0.4 AgentRequest 和 ActionReceipt 都绑定当前 ActionBindingManifest。
3. 独立第三方能离线重算“实际行动是否满足已批准行动约束”。
4. 判断、事实、Disposition、行动、参数、映射规则或重放器发生替换时失败关闭。
5. 明确区分密码学完整性、语义绑定、业务真理和当前权威状态。
6. 高风险模式能检测旧 checkpoint、回滚和已知分叉。
7. v0.1—v0.3 对象继续可读，不做静默升级或历史重写。

### 3.2 商业目标

1. 用一个真实 GitHub Issue、一个仓库和一名客户 Acceptor 完成 21 天付费试点。
2. 第一付费方假设为 Agent/AI 方案商、软件外包商或系统集成商。
3. 将技术结果转化为客户可读的判断—行动一致性报告和离线复核包。
4. 用付费 SOW、定金和客户验收决定验证商业价值，不用测试数、Star 或评论替代。

### 3.3 非目标

本轮不实现：

- 通用业务规则引擎或任意领域 policy language；
- LLM-as-judge 作为协议真理；
- 判断内容、客户事实或测试断言本身绝对正确；
- 区块链、Token、强制透明日志或全球政策注册表；
- 资金托管、支付、清分、仲裁或付款证明；
- 自动法律验收或自动取消合同；
- 多 Agent 平台 Dashboard、计费系统或 hosted SaaS；
- 非代码场景适配器；
- 在没有真实付费试点前构建 OEM 平台。

## 4. 术语与真理边界

### 4.1 Judgment

给定一组固定事实、规则和适配器，客户批准 Agent 执行的行动约束。判断可以由
人、规则系统或外部判断器产生，但必须由 Customer Acceptor 承诺。

### 4.2 Action

由 ActionReceipt 记录的真实协议行动，包括工具、规范化参数、输入、输出、
补丁、候选提交和执行上下文。

### 4.3 Binding

在固定适配器语义下，实际行动满足 JudgmentCommitment 中的全部行动约束，且
相关工件、事实、Disposition、规则和重放输入未发生未授权替换。

### 4.4 Binding 不是 Truth

`BOUND` 只表达“行动与记录判断一致”，不表达：

- 判断本身正确；
- 输入事实真实；
- 代码没有所有缺陷；
- 物理世界行动必然发生；
- 客户已经验收或付款；
- 合同、支付或结算已经生效。

### 4.5 Authority as-of

外部 checkpoint 只能证明截至一个明确时间点的权威状态。离线包不能永久证明
“现在仍是最新版本”。超过 checkpoint 有效期或无法取得所需权威状态时必须
返回 `INDETERMINATE`。

## 5. 角色与信任域

v0.4 不增加第七个 OpenWorkProof 角色：

| 角色 | v0.4 职责 | 禁止事项 |
|---|---|---|
| Maintainer | 维护协议与 WorkOrder 权威 | 不替客户签业务判断 |
| Manager | 生成 WorkOrder 与 ActionBindingManifest | 不代替 Acceptor 改写 Judgment |
| Developer/Agent | 执行被授权的代码行动 | 不签 BindingDecision |
| Verifier | 独立重算范围、证据和绑定 | 不作客户验收决定 |
| Sidecar | 记录精确 AgentRequest 与 ActionReceipt | 不决定业务判断是否正确 |
| Acceptor | 签署 JudgmentCommitment 与最终验收 | 不由交付团队代签 |

高风险模式中的 checkpoint authority 是外部信任输入，不成为 OWP 内部角色。其
签名密钥必须与 Manager、Sidecar 和执行 Agent 不同；真实客户试点中应属于客户
控制域。

## 6. 核心协议对象

### 6.1 `JudgmentCommitment`

`JudgmentCommitment` 是 Acceptor 签名的 `SignedProtocolModel`，在 WorkOrder 和
Agent 执行前形成。

建议字段：

```text
schema_version = openworkproof-judgment-commitment/0.4
commitment_id
authority_namespace
subject_id
judgment_kind
judgment_artifact_uri
judgment_artifact_digest
normalized_facts_digest
disposition_digest
action_constraint_digest
adapter_id
adapter_version
adapter_profile_digest
repository
source_revision
target_branch
acceptance_condition_digests[]
excluded_scope_digests[]
required_artifact_digests[]
valid_from
expires_at
created_at
nonce
signer_key_id
signature_alg
signature
digest
```

不变量：

1. Acceptor key 必须属于 WorkOrder 指定的客户 Acceptor 权威域。
2. `commitment_id`、`digest` 与签名使用 RFC 8785 JCS、SHA-256 和独立 domain。
3. `valid_from < expires_at`，执行请求必须位于有效期内。
4. 条件、排除项和工件摘要必须排序、去重、非空且受数量/字节上限约束。
5. `action_constraint_digest` 必须由规范化 adapter profile 重算。
6. raw Issue 文本可以进入私有证据包，但协议判断依赖规范化摘要。
7. 普通 metadata 中的同名字段不具有任何绑定权威。

Commitment 可以先于 WorkOrder 签署，因此自身不引用 WorkOrder digest。后续提交
ActionBindingManifest 时，事务必须证明 Commitment signer 正是该 WorkOrder
绑定的 Acceptor；不匹配时零执行拒绝。`expires_at` 限制新行动的授权窗口，
不会抹除在有效期内发生的历史行动。离线验证应按 ActionReceipt 的
`occurred_at` 判断当时是否有效，而不是要求 Commitment 在复核当天仍未过期。

### 6.2 `ActionBindingManifest`

`ActionBindingManifest` 是 Manager 签名的、执行前提交的 Manifest。它避免修改
历史 WorkOrder 模型，并为 v0.4 事务提供显式激活边界。

建议字段：

```text
schema_version = openworkproof-action-binding-manifest/0.4
binding_manifest_id
work_order_digest
judgment_commitment_id
judgment_commitment_digest
evaluation_scope_id
evaluation_scope_digest
adapter_id
adapter_version
adapter_profile_digest
allowed_tool_names[]
allowed_action_kinds[]
allowed_path_roots[]
required_test_profile_digests[]
source_revision
supersedes_binding_manifest_id?
supersedes_binding_manifest_digest?
causal_parent_manifest_ids[]
created_at
expires_at
nonce
signer_key_id
signature_alg
signature
digest
```

不变量：

1. WorkOrder、JudgmentCommitment、EvaluationScope 和 adapter profile 必须完整存在。
2. Manifest 的有效期不得超过 JudgmentCommitment 或 WorkOrder。
3. allowed paths/tools 不能扩大 WorkOrder 和 Judgment 的交集。
4. 一个 WorkOrder 同时只能有一个当前 active Manifest；替换必须精确引用当前
   Manifest 的 id/digest，并追加不可变历史关系。
5. v0.4 AgentRequest 必须显式携带 Manifest id/digest；缺失时在执行前拒绝。
6. ActionReceipt 通过嵌套请求摘要绑定同一 Manifest，不接受后补 metadata。

### 6.3 v0.4 AgentRequest 绑定字段

不静默改变历史 `AgentRequest`。新增 v0.4 sibling model 或显式 versioned payload：

```text
judgment_commitment_id
judgment_commitment_digest
action_binding_manifest_id
action_binding_manifest_digest
```

Policy gateway 在任何工具执行前验证：

- 请求、Manifest、Commitment 和 WorkOrder 的完整摘要链；
- 当前有效期和 nonce；
- tool、path、action kind 与三方约束交集；
- 当前 checkpoint 要求；
- active Manifest 唯一性。

拒绝请求必须零执行、零配额扣减、零业务输出，只能追加拒绝审计回执。

### 6.4 `BindingDecision`

`BindingDecision` 由 Profile-bound 独立 Verifier 签署。

```text
schema_version = openworkproof-binding-decision/0.4
binding_decision_id
work_order_digest
judgment_commitment_digest
action_binding_manifest_digest
verification_decision_id
verification_decision_digest
action_receipt_ids[]
action_receipt_digests[]
adapter_replay_digest
authority_checkpoint_digest?
decision = BOUND | UNBOUND | INDETERMINATE
reason_codes[]
authority_status
causal_parent_decision_ids[]
supersedes_binding_decision_id?
supersedes_binding_decision_digest?
decided_at
nonce
verifier_signatures[]
digest
```

决定规则：

- `BOUND`：所有必需输入存在、签名有效、适配器重算一致、行动满足约束、所需
  checkpoint 当前且无分叉、现有 VerificationDecision 为 `VERIFIED`。
- `UNBOUND`：存在明确反证，例如行动参数、判断工件、Disposition 或映射结果
  不一致。
- `INDETERMINATE`：缺失证据、重放器不可用、依赖漂移、外部权威不可确认或
  其他无法得出结论的情况。

不存在“未发现错误即 BOUND”的默认路径。

### 6.5 `AuthorityCheckpoint`

`AuthorityCheckpoint` 是可选的外部签名输入，高风险 Profile 必须提供：

```text
schema_version = openworkproof-authority-checkpoint/0.4
checkpoint_id
authority_namespace
subject_id
monotonic_revision
current_judgment_commitment_digest
predecessor_checkpoint_digest?
effective_at
expires_at
authority_key_id
signature_alg
signature
digest
```

规则：

1. revision 必须单调递增；新 checkpoint 必须引用前一 checkpoint 摘要。
2. 同一 namespace、subject 和 revision 的多个不同摘要构成 fork。
3. rollback、fork、过期或签名错误不能产生 `BOUND`。
4. 外部 resolver 不可用时，高风险决定为 `INDETERMINATE`。
5. OWP 只验证 checkpoint 格式、签名、链和绑定，不拥有外部治理与信任根。

## 7. AI 代码交付适配器

### 7.1 适配器范围

首版 `openworkproof/code-delivery-github/0.1` 只支持：

- GitHub Issue 内容快照；
- Git repository 与 immutable source revision；
- path allow/exclude roots；
- 明确 acceptance condition ids；
- pytest fixed/selected test profiles；
- patch、candidate commit 和 delivery artifacts；
- 确定性规则，不执行任意客户代码作为受信映射器。

### 7.2 规范化输入

适配器将客户输入规范化为：

```text
issue_snapshot_digest
repository_identity
source_revision
target_branch
acceptance_conditions[]
allowed_path_roots[]
excluded_path_roots[]
required_artifacts[]
required_test_profiles[]
allowed_action_kinds[]
```

Issue 后续编辑不会改写历史快照。任何新版本必须产生新的 Commitment 并追加
supersession。

### 7.3 判断—行动映射

适配器检查：

1. ActionReceipt 使用允许的工具和 action kind；
2. 所有实际路径位于 allowed roots 且不命中 excluded roots；
3. patch、candidate commit 和 workspace digest 对应同一执行链；
4. required artifacts 全部存在且摘要匹配；
5. VerificationDecision 绑定同一 EvaluationScope；
6. acceptance condition 到 required target 的映射完整；
7. 结果不存在未声明的额外副作用记录。

它不判断自然语言 Issue 是否“合理”，也不使用 LLM 推测客户未编码意图。

## 8. 状态机与验收门

### 8.1 Binding 状态生命周期

```text
UNDECIDED
   ├─ complete positive evidence + exact mapping + authority current → BOUND
   ├─ explicit mismatch or replay divergence                     → UNBOUND
   └─ missing evidence, drift, timeout, authority unavailable     → INDETERMINATE

BOUND / UNBOUND / INDETERMINATE
   └─ new evidence or superseding Judgment → append-only superseding decision
```

历史决定不可修改或删除。

### 8.2 Acceptance gate

v0.4 的 Acceptance 请求必须引用：

- 当前 `VerificationDecisionV03 = VERIFIED`；
- 当前 `BindingDecision = BOUND`；
- 同一 WorkOrder、SubjectClaim、Scope、Commitment 和 Manifest；
- 未过期且未被 supersede 的 AuthorityCheckpoint（如 Profile 要求）。

`REFUTED`、`UNKNOWN`、`UNBOUND` 或 `INDETERMINATE` 均不得打开验收门。

### 8.3 SettlementReadiness

```text
VerificationDecision == VERIFIED
and BindingDecision == BOUND
and EffectiveAcceptance == ACTIVE
and required commercial evidence references are present
```

该结果只叫 `READY_FOR_SETTLEMENT_REVIEW`，不得叫“已付款”或“自动结算”。付款
凭证仍是外部商业证据。

## 9. Reason Codes

首版固定枚举：

```text
JUDGMENT_SIGNATURE_INVALID
JUDGMENT_EXPIRED
JUDGMENT_ARTIFACT_MISSING
JUDGMENT_DIGEST_MISMATCH
JUDGMENT_FACTS_DIGEST_MISMATCH
JUDGMENT_DISPOSITION_DIGEST_MISMATCH
JUDGMENT_SUPERSEDED

ADAPTER_PROFILE_DIGEST_MISMATCH

ACTION_DIGEST_MISMATCH
ACTION_ARGUMENTS_MISMATCH
ACTION_MAPPING_REJECTED
ACTION_OUTSIDE_APPROVED_SCOPE
ACTION_SIDE_EFFECT_UNDECLARED

REPLAY_UNAVAILABLE
REPLAY_DIVERGED
EVALUATOR_VERSION_DRIFT

AUTHORITY_CHECKPOINT_MISSING
AUTHORITY_CHECKPOINT_STALE
AUTHORITY_CHECKPOINT_SIGNATURE_INVALID
AUTHORITY_FORK_DETECTED
AUTHORITY_ROLLBACK_DETECTED
ALTERNATIVE_WORK_ORDER_DETECTED

UNSIGNED_METADATA_REFERENCE
EVIDENCE_INCOMPLETE
VERIFICATION_NOT_CURRENT
INDEPENDENCE_UNPROVEN
```

分类规则：

- gateway 在执行前发现签名错误、过期、空判断或缺少必需绑定时，只追加拒绝
  审计回执，不执行行动，也不构造 BindingDecision；
- 离线包的 OWP 结构或签名无效时，先判定 package/chain verification failed，
  不用 `UNBOUND` 掩盖 Layer 1 失败；
- 在链和签名有效的前提下，明确的 facts、Disposition、参数或映射反证 →
  `UNBOUND`；
- 缺失、不可用、超时、版本漂移、无法确认当前权威 → `INDETERMINATE`；
- reason codes 必须排序、去重，并与结果允许集合匹配。

## 10. 外部权威与攻击者能力

### 10.1 首版攻击者能力

必须测试：

- 普通攻击者修改字节但没有签名密钥；
- 内部攻击者控制 Manager、Agent 和 Sidecar 合法密钥；
- 内部攻击者能重签整条 OWP 内部链，但不能使用客户 Acceptor 密钥；
- 高风险场景中，攻击者不能使用外部 checkpoint authority key；
- 攻击者能创建另一条内部自洽 WorkOrder；
- 攻击者能替换判断工件、事实、Disposition、行动和适配器输出；
- 攻击者能使外部服务不可用，但不能因此获得 `BOUND`。

### 10.2 明确不解决的攻击

- 客户 Acceptor、Manager、Verifier 与外部 checkpoint authority 全部串谋；
- 私钥端点被完全攻陷且没有独立外部信任根；
- 物理世界行动未被任何传感器或执行系统记录；
- 客户故意签署虚假判断或提供虚假事实；
- 未编码的业务意图。

这些边界必须进入公开威胁模型，不能以更多测试数掩盖。

## 11. 敌对验证矩阵

### 11.1 注册案例

| 类别 | 攻击 | 责任层 | 预期 |
|---|---|---|---|
| C0 | 完整正常交付 | 全链 | `BOUND` |
| A1 | 修改 Action，不重签 | OWP Layer 1 | 结构/签名拒绝 |
| A2 | 修改 Action，内部合法密钥重签 | Binding Adapter | `UNBOUND` |
| A3 | 替换 Issue 快照 | Binding Adapter | `UNBOUND` |
| A4 | 替换规范化事实 | Binding Adapter | `UNBOUND` |
| A5 | 替换验收条件 | Binding Adapter | `UNBOUND` |
| A6 | 修改 path/tool 参数 | Gateway/Binding | 拒绝或 `UNBOUND` |
| A7 | Commitment 与 Receipt 自洽但违反映射 | Binding Adapter | `UNBOUND` |
| A8 | 伪造 Disposition | Deterministic replay | `UNBOUND` |
| A9 | 更换判断器/适配器版本 | Replay | `INDETERMINATE` |
| A10 | 使用过期 Commitment 发起新行动 | Gateway | 预执行拒绝 |
| A11 | 使用旧 checkpoint | External Authority | `UNBOUND` |
| A12 | checkpoint resolver 不可用 | External Authority | `INDETERMINATE` |
| A13 | 高风险模式构造替代 WorkOrder | External Authority | `UNBOUND` |
| A14 | 低风险模式出现无法外部裁决的替代 WorkOrder | Binding | `INDETERMINATE` |
| A15 | 判断引用只在 metadata | Binding transaction | `INDETERMINATE` |
| A16 | 判断或验收条件为空 | Model/Gateway | 预执行拒绝 |
| A17 | 必选范围遗漏 | Scope v0.3 | `INDETERMINATE` |
| A18 | Manager 重签但缺 Acceptor 签名 | Authority | 预执行拒绝 |

### 11.2 Holdout

由未参与实现的审查者预注册至少 4 个 holdout：

- 首次执行发生在用例冻结后；
- 输入、期望、攻击能力和责任层在执行前提交；
- 不允许执行后修改期望；
- 结果报告区分 adjudicated、divergent 和 pipeline-invalid；
- holdout 全通过也不叫安全证明。

### 11.3 负控

必须存在：

- 一个干净正向控制；
- 至少一个只破坏 OWP 链的负控；
- 至少一个链内自洽但 Binding 错误的负控；
- 至少一个仅 Replay 能发现的负控；
- 至少一个只能由 External Authority 发现或保持未知的边界案例。

## 12. 事务、并发与恢复

每个新对象采用现有 stage → commit → readback 模式：

1. 输入模型完整重建，不接受 `model_copy` 绕过验证；
2. 目标锁和 `BEGIN IMMEDIATE` 保护写入区间；
3. pre-COMMIT 故障必须全表零写入；
4. COMMIT-ACK 丢失必须通过 exact readback 判断已提交或不确定；
5. 同一 id 的不同 payload 拒绝；完全相同提交返回 committed truth；
6. 同一 WorkOrder 的并发 BindingDecision 只有一个当前赢家；
7. superseding decision 必须绑定当前父决定 id/digest；
8. cleanup 故障不能删除已提交真相或重复写入。

## 13. 离线包与隐私视图

### 13.1 客户私有包

必须包含：

- JudgmentCommitment；
- ActionBindingManifest；
- 当前 BindingDecision 与完整历史；
- 所有绑定 ActionReceipt；
- adapter profile、版本和确定性重放输入；
- AuthorityCheckpoint 链（若要求）；
- VerificationDecision、Scope 和 Acceptance 历史；
- 可离线运行的 replay 命令。

### 13.2 Diagnostic 包

可以包含摘要、原因码和去敏定位信息，但若缺少完整私有判断工件，必须显示：

```text
binding_replay = unavailable_in_this_view
```

### 13.3 Public 包

只提供聚合结论、协议版本和公开摘要，不泄露 Issue 私有内容、路径、测试名称、
客户密钥或商业凭证。Public 包不能宣称可完成完整判断重放。

### 13.4 metadata 规则

协议文档和验证器错误消息必须明确：

> 包中包含一个字段，不代表该字段已与授权行动形成签名语义绑定。

任何只存在于普通 metadata 的判断引用都不能满足 v0.4 Profile。

## 14. 兼容与迁移

1. v0.1—v0.3 对象、Schema 和冻结包保持可读。
2. 历史对象没有 JudgmentCommitment 时，Binding 状态为 `UNDECIDED` 或
   `INDETERMINATE`，绝不静默升级为 `BOUND`。
3. v0.4 新对象使用独立 Schema、domain 和数据库表。
4. 现有 VerificationDecision 不改名、不改历史语义。
5. v0.4 Acceptance gate 只对显式采用 v0.4 Binding Profile 的工作生效。
6. 不重签或改写 Rich/Dify 历史冻结包；新增独立 v0.4 演示包。

## 15. API、CLI 与 MCP 最小接口

首版仅要求：

```text
owp judgment validate
owp binding-manifest validate
owp binding compose
owp binding verify
owp binding history
owp package replay --binding
```

MCP 首版只增加结构化查询与验证接口，不允许 MCP 客户持有 Acceptor 私钥：

```text
owp_validate_judgment_commitment
owp_validate_action_binding_manifest
owp_get_binding_status
owp_explain_binding_decision
```

签名继续通过外部 Acceptor/Verifier 服务或离线签名导入完成。

## 16. 稳定性前置切片

进入 v0.4 产品实现前，先关闭当前工程噪音：

1. 修复 `team_network_client` 服务关闭时 Socket 置空与 `accept()` 的竞态；
2. 为该竞态增加可重复的并发回归测试；
3. 分类 pytest 临时目录 `Directory not empty` warnings，能由项目修复的必须修复；
4. required-live 发布门不得出现未分类线程异常；
5. warnings 数量必须在 release ledger 中如实记录，不得改写成零。

该切片不改变协议语义，但属于 v0.4 发布前 P0。

## 17. 21 天付费试点

### 17.1 用户、付费方与验收方

- User：Agent 方案商的交付负责人、质量负责人或项目经理；
- Payer hypothesis：直接承担返工、验收争议和回款不确定性的方案商负责人；
- Customer Acceptor：客户书面指定、密钥独立于交付团队的验收负责人；
- 首个场景：一个真实 Issue、一个仓库、一个基线 revision 和一次 Agent 修改。

以上均为待验证假设，未取得外部材料前保持 `not evidenced`。

### 17.2 交付节奏

| 时间 | 工作 | 通过证据 |
|---|---|---|
| Day 1—3 | SOW、报价、定金、Issue 快照、Acceptor 和 Commitment | 已签 SOW、定金引用、Acceptor 签名 |
| Day 4—7 | Scope、adapter profile、正负控和 Manifest | 可重算、约束不扩权、攻击预注册 |
| Day 8—12 | Agent 执行并形成完整 ActionReceipt 链 | 真实补丁、候选提交、证据包 |
| Day 13—15 | 独立重放并生成 BindingDecision | 正常 BOUND、攻击正确分类 |
| Day 16—18 | Customer Acceptor 独立复核 | 接受、拒绝或补证决定 |
| Day 19—21 | 商业与技术分开复盘 | 回款、验收周期、补证和下一单证据 |

### 17.3 价格假设

- 首个 21 天试点含税报价：人民币 3—5 万元；
- 启动定金：50%；
- 余款触发：约定材料提交 Customer Acceptor，不承诺客户必须接受；
- 多工作流、CI/Agent 平台接入进入 20—50 万元 PoC/改造包。

价格是商业验证假设，不代表已有报价、合同、订单或收入。

### 17.4 成功与停止规则

技术成功：

- 正常链得到 `BOUND`；
- 注册攻击得到预期拒绝、`UNBOUND` 或 `INDETERMINATE`；
- 第三方从客户私有包重放得到相同决定；
- 缺失权威或证据时不产生绿色结论。

商业成功：

- 至少一家目标方案商签署 SOW 并支付可定位定金；
- 客户指定独立 Acceptor；
- 完成一次真实接受、拒绝或补证决定；
- 获得下一项目书面意向，或形成可复用的明确拒绝原因。

停止/重构：

- 21 天内无人支付定金；
- 无法获得独立 Customer Acceptor；
- Issue 无法转写为确定性验收条件；
- 试点超过 8 人日或人民币 2,000 元实验资源上限；
- 五家目标方案商共同认为该问题不值得采购。

## 18. 实施切片边界

后续实施计划应拆为：

1. P0 稳定性 warning 清理；
2. JudgmentCommitment 模型、Schema、签名与纯验证；
3. ActionBindingManifest 与预执行授权门；
4. GitHub code-delivery adapter；
5. BindingDecision 组合、签名、事务和并发；
6. AuthorityCheckpoint 与 as-of 验证；
7. Acceptance/SettlementReadiness 双门；
8. 离线包、CLI/MCP 与隐私视图；
9. 注册攻击、holdout 和 required-live 门；
10. 21 天付费试点材料。

每个切片必须先写失败测试，再写最小实现；不得把 Dashboard、计费、通用规则
语言或第二领域适配器夹带进首版。

## 19. 发布门

v0.4 技术发布候选必须满足：

- 新模型和 Schema canonical/digest/signature 测试；
- 所有新事务 pre-COMMIT、ACK-loss、并发和回读测试；
- 文章核心 `250 → 2500` 连贯重签攻击的等价代码交付案例；
- 至少 16 个注册矩阵案例和 4 个预注册 holdout；
- v0.1—v0.3 兼容回归；
- 便携全量、candidate supply-chain 和 required-live 全量零失败；
- required-live 零 skip，线程异常 warning 为零；
- 新不可变 candidate inventory，不覆盖历史库存；
- 新 v0.4 自有离线包及单字节篡改反例；
- README 中英文、offline verification 和试点文档同步；
- 独立只读规格审查和代码审查。

即使全部通过，也只能声称“v0.4 本地/发布候选技术闭环”。不得据此声称：

- 外部客户采用；
- 已签付费 SOW 或已收定金；
- 客户已验收；
- 上游项目认可；
- 已执行付款、资金释放或自动结算；
- 协议能够抵抗任意攻击者。

## 20. 设计验收标准

本规格进入实施计划前必须确认：

1. `BOUND` 与业务真理、Acceptance、付款严格分离；
2. Acceptor 在执行前签 JudgmentCommitment，Manager 不得代签；
3. ActionBindingManifest 解决 WorkOrder 历史兼容与显式激活问题；
4. AgentRequest/ActionReceipt 原生绑定 Manifest，不依赖普通 metadata；
5. 明确重签攻击、Replay 与 External Authority 的检测责任；
6. AuthorityCheckpoint 采用 as-of 语义，不宣称永久当前；
7. v0.1—v0.3 不静默升级、不重写历史；
8. 首个场景只限 AI 代码交付；
9. 21 天试点的付款方、定金、Acceptor 和停止条件可证伪；
10. 没有占位字段、隐式 TODO 或无法测试的成功标准。
