# OpenWorkProof 可验证交付试点研发设计规格

Date: 2026-08-11

Status: User-approved design; implementation plan not yet approved

Depends on:

- `docs/superpowers/specs/2026-08-09-openworkproof-evidence-lifecycle-v0.2-design.md`
- commit `29c6a84` (`docs: design evidence lifecycle v0.2`)

## 1. 设计目的

本规格将 Evidence Lifecycle v0.2 从协议可信度闭环收敛为一个可以收费、
交付和由客户验收的首个商业产品：

> Agent 可验证交付试点：把一次代码型 Agent 项目交付，转化为客户能够
> 独立复核、签署验收并进入外部结算流程的证据包。

产品的技术内核是 Semantic Safety Overlay：它不只证明某个身份签署了某些
字节，还要求主张、授权、执行、正向验证、负向控制、独立验证和客户验收
绑定到同一个交付对象。

产品的商业外层是 Agent Delivery Proof Package：方案商用它降低客户验收
成本、补证成本和尾款争议，企业客户用它理解并复核一次 Agent 交付。

本规格不授权产品代码实现。下一步必须先由用户审核本文件，再编写独立的
实施计划。

## 2. 核心商业判断

### 2.1 第一付费方假设

首要付费方是交付代码、数据或流程 Agent 的：

- Agent 方案商；
- AI 解决方案商；
- 系统集成商。

其购买的不是密码学、签名数量或协议对象，而是：

- 在执行前冻结验收依据；
- 把交付过程转化为可复核证据；
- 缩短从交付到客户决定的周期；
- 减少反复截图、录屏、解释和补材料；
- 降低尾款争议；
- 把一次性交付方法沉淀为可复制标准。

### 2.2 直接受益方

企业客户的业务负责人、IT 负责人、审计人员和项目 Acceptor 获得：

- 客户可读的交付主张；
- 精确到版本、命令和环境的执行事实；
- `VERIFIED | REFUTED | UNKNOWN` 三态验证结论；
- 负向控制是否真实有效的解释；
- 接受、拒绝、撤回或要求补证的签署依据。

审计机构、保险机构、监理方、采购和法务属于潜在受益方，不作为首个试点的
默认付费方。

### 2.3 第一商业产品

第一产品为 21 天“Agent 可验证交付试点”，采用服务带产品的方式，不建设
多租户 SaaS：

1. 第 1–3 天：冻结交付主张、验收条件、正向验证、负向控制和角色绑定；
2. 第 4–7 天：接入 Agent、Git/CI、Evidence Collector 和 Verifier；
3. 第 8–14 天：完成真实执行、双臂验证和独立重放；
4. 第 15–18 天：向客户交付 Delivery Room，由 Acceptor 决定接受或拒绝；
5. 第 19–21 天：复盘验收周期、补证轮数、争议成本和复购意愿。

试点成功的市场证据是：真实项目、真实验收标准、客户 Acceptor 参与和方案商
支付定金。测试通过、GitHub Star、社区评论或目录上架都不能替代付款证据。

### 2.4 “AI Agent 的支付宝”边界

允许使用以下商业类比：

> 电商交易需要担保和交易凭证；Agent 协作需要授权证明、执行凭证和验收
> 依据。OpenWorkProof 希望成为 Agent 交付中的可信凭证层。

当前产品提供：

- 授权证明；
- 执行证据；
- 独立验证；
- 客户验收状态；
- 外部结算准备状态。

当前产品不提供：

- 资金托管；
- 自动扣款；
- 清分清算；
- 法律争议仲裁；
- 付款成功证明。

`ACCEPTED_FOR_SETTLEMENT` 只能表示具备进入外部结算流程的条件，绝不表示
已经付款或资金已经释放。

## 3. 设计信号与反要求

社区讨论形成了以下可实施信号：

1. 签名证明字节来源，不证明主张正确；
2. 不可变证据不等于不可变真相，需要追加式结论撤回和 supersession；
3. reproducibility 不等于 falsifiability，`VERIFIED` 必须包含真实负控；
4. `mutant not applied` 与 `mutant survived` 必须是不同结果；
5. 验证器崩溃不能冒充主张被反驳；
6. 高风险交付需要不同密钥、不同控制域和不同执行上下文的独立 Verifier；
7. 授权权威与实质判断必须分离；
8. Evidence Bundle 与 Execution Ledger 必须分离；
9. Policy Registry 应由外部系统维护，OWP 只绑定 PolicyAnchor；
10. 负控需要 fast、continuous、periodic 三层，以检测 guard rot；
11. 密码学开销只放在真实信任边界，不替代普通内部 CI；
12. 产品必须解释验证成本和第一付费方，而不是只宣传测试数。

这些信号是研发输入，不代表社区共识、标准组织采纳或客户购买。

## 4. 当前事实与发布前提

### 4.1 已有能力

当前仓库已经具备：

- 六角色密钥和角色隔离；
- Ed25519 签名与 canonical JCS digest；
- ActionReceipt 因果链；
- SQLite 权威账本；
- evidence stage、commit、publish 和 COMMIT-ACK 回读；
- 独立 Verifier rerun 与 proof recomposition；
- AcceptanceReceipt 和拒绝路径；
- Rich #4196 与 Dify #33013 Evidence Bundle；
- CLI、MCP 和离线验证基础。

### 4.2 最近一次核验基线

最近一次完整测试核验结果是：

```text
2282 passed, 3 failed, 7 skipped
```

三个失败为：

1. execution-runner candidate inventory 对当前 revision 匹配数为零；
2. fixed-test-source candidate inventory 对当前 revision 匹配数为零；
3. 安装 distribution metadata 报告 `0.1.0`，模块和协议包报告 `1.1.1`。

因此在 M0 完成前，不得对外声称“2,283 项测试全部通过”。允许的准确表达是：

> 最近一次核验有 2,282 项通过、3 项失败、7 项跳过；失败属于发布真值绑定
> 和版本一致性问题，尚待闭环。

### 4.3 既有 v0.2 规格的权威性

本规格扩展而不替代 2026-08-09 Evidence Lifecycle v0.2 设计。发生冲突时：

1. 已签名协议对象和当前源代码定义优先；
2. Evidence Lifecycle v0.2 的协议不变量优先；
3. 本规格负责商业产品边界、SubjectClaim、arm-result 细分、
   SettlementReadiness、Delivery Package 和试点验收；
4. 路演材料和社区帖子不作为实现权威。

## 5. 范围

### 5.1 本轮范围

- 一个代码型 Agent 交付主张；
- `SubjectClaim` 和 `VerificationProfileV02`；
- 一个 positive arm 和至少一个 Manager-pinned negative arm；
- `VerificationArmResult` 的 mutation、execution、expectation 三维状态；
- standard 和 high-risk assurance；
- `VerificationDecision` 三态与 supersession；
- AcceptanceReceipt、AcceptanceRejectionReceipt 和
  AcceptanceTransitionReceipt；
- `EffectiveAcceptance` 与 `SettlementReadiness` 派生视图；
- JSON 真值包和客户可读 HTML，可选 PDF；
- Provider、Verifier、Auditor CLI；
- 最小 MCP 接口；
- 本地静态 Delivery Room；
- Rich #4196、Dify #33013 和一个真实付费项目。

### 5.2 明确不做

- 资金托管和支付网络；
- 全局身份机构；
- OWP 自有 Policy Registry；
- 区块链或公链依赖；
- LLM-as-judge；
- 任意语义主张和任意用户代码在 trusted verifier 中执行；
- 多租户 SaaS；
- Verifier Marketplace；
- 多 Agent 框架大规模适配；
- 通用信誉评分；
- 没有付费试点前的渠道平台和自动结算。

## 6. 参与方与权威分离

### 6.1 Provider

Provider 是 Agent 方案商或系统集成商，负责提供交付对象、执行 Agent 和证据。
它可以是付费方，但不能代替客户 Acceptor。

### 6.2 Manager

Manager 冻结 WorkOrder、SubjectClaim、VerificationProfile 和必要的独立
Verifier binding。Manager 不能用签名把错误事实变成正确事实。

### 6.3 Verifier

Verifier 只判断证据是否支持、反驳或不足以判断精确主张。Verifier 不拥有
商业验收和付款权。

### 6.4 Customer Acceptor

Customer Acceptor 由 WorkOrder 绑定，必须属于与 Provider 不同的客户权威域。
首个切片不实现多人 quorum，但严格禁止 Provider、Manager 或 Verifier 冒充
客户 Acceptor。

### 6.5 Auditor

Auditor 不需要接入 Provider 的服务器，可以完全离线重放 Delivery Package，
重新计算 VerificationDecision、EffectiveAcceptance 和 SettlementReadiness。

## 7. 总体架构

```text
商业协议与验收标准
        |
        v
L0  Release Truth Gate
        |
        v
L1  Contract Layer
    WorkOrder + SubjectClaim + VerificationProfileV02
        |
        v
L2  Execution Layer
    CapabilityGrant + PolicyDecision + ActionReceipt
        |
        v
L3  Semantic Safety Layer
    positive arm + negative arm + independent verification
        |
        v
L4  Acceptance Layer
    VerificationDecision + Acceptance lifecycle
        |
        v
L5  Delivery Product Layer
    Delivery Proof Package + Delivery Room + offline replay
```

第一阶段保持单仓库、单进程应用服务和 SQLite 事务模型，不引入微服务。

## 8. 核心对象

### 8.1 复用对象

- `WorkOrder`；
- `CapabilityGrant`；
- `PolicyDecision`；
- `ActionReceipt`；
- `CompositionReport`；
- `AcceptanceReceipt`；
- `AcceptanceRejectionReceipt`。

### 8.2 SubjectClaim

`SubjectClaim` 在执行前冻结客户真正要验收的技术主张：

```yaml
schema_version: openworkproof-subject-claim/0.1
claim_id:
work_order_digest:
claim_statement:
delivery_target:
source_revision:
acceptance_conditions: []
excluded_scope: []
required_artifacts: []
customer_acceptor_binding:
created_at:
nonce:
manager_signature:
```

约束：

- `subject_claim_digest` 必须进入 VerificationProfileV02；
- 执行开始后不能原地修改；
- 合同金额、发票、法律条款和支付状态不进入该对象；
- 只绑定可技术验证的交付主张和验收条件；
- 新主张必须创建新对象和新摘要；
- Level 2 和 Level 3 交付必须通过 CommitmentAnchor 绑定一个来自客户权威域的
  执行前确认，例如客户签署的验收标准摘要或客户控制的 Git reference。

### 8.3 VerificationProfileV02

沿用已批准规格，包含：

- profile、WorkOrder 和 SubjectClaim digest；
- `delivery_trust_level = 1 | 2 | 3`；
- 可选 `policy_anchor_digest`；
- `commitment_anchor_digest`：Level 2/3 必填；对应 anchor 必须反向绑定
  同一个 WorkOrder 和 SubjectClaim digest；
- `subject_kind = tests_passed`；
- assurance level；
- verifier bindings；
- positive arm；
- 一个或多个 negative arms；
- evidence 和 output 上限；
- 创建、过期、nonce 和 Manager 签名。

首版不扩展到任意 artifact semantic predicate。

### 8.4 VerificationArmResult

新增 arm 结果对象，避免把不同失败压成单一 exit code：

```yaml
schema_version: openworkproof-verification-arm-result/0.2
arm_result_id:
profile_digest:
arm_id:
arm_kind: positive | negative
mutation_status: not_applicable | applied | not_applied
execution_status: completed | timed_out | crashed | resource_exhausted | evidence_unavailable
expectation_status: satisfied | contradicted | indeterminate
reason_codes: []
action_receipt_ids: []
evidence_refs: []
verifier_subject_id:
verifier_key_id:
verifier_build_digest:
dependency_lock_digest:
controller_factors: []
execution_context_factors: []
created_at:
signature:
```

规则：

- positive arm 的 `mutation_status` 必须为 `not_applicable`；
- negative arm 必须报告 `applied` 或 `not_applied`；
- non-zero exit code 不自动表示负控成功；
- 固定 classifier 必须区分预期测试失败和 verifier crash；
- `not_applied` 必须产生 `indeterminate`；
- 关键 evidence 缺失必须产生 `evidence_unavailable` 或
  `indeterminate`，不能产生 `satisfied`。

### 8.5 VerificationDecision

沿用已批准三态对象：

```text
VERIFIED | REFUTED | UNKNOWN
```

它必须绑定：

- SubjectClaim digest；
- VerificationProfile digest；
- 精确的 ordered arm result references；
- IndependenceAssessment；
- reason codes；
- supersedes；
- 所需 Verifier signatures。

### 8.6 AcceptanceTransitionReceipt

由 Customer Acceptor 签署，只表达：

- `withdrawn`；
- `superseded`。

它不能删除 AcceptanceReceipt，也不能改写 VerificationDecision。

### 8.7 派生视图

`EffectiveAcceptance`：

```text
NONE | ACTIVE | SUSPENDED | WITHDRAWN | SUPERSEDED
```

`SettlementReadiness`：

```text
NOT_READY
READY_FOR_ACCEPTANCE
ACCEPTED_FOR_SETTLEMENT
SUSPENDED
WITHDRAWN
SUPERSEDED
```

这两个对象都是从 append-only 账本确定性计算的 read model，不是新的签名事实。

## 9. 验证决策规则

### 9.1 VERIFIED

仅当全部条件成立：

- positive arm 满足预期；
- 至少一个 Manager-pinned negative arm 被真实施加；
- negative arm 被固定测试正确抓住；
- 关键 evidence 完整且摘要匹配；
- ActionReceipt 因果链完整；
- 所需 Verifier 签名有效；
- assurance level 的独立性条件满足；
- 没有更新的有效 VerificationDecision 取代它。

### 9.2 REFUTED

出现有效反证：

- positive arm 明确违背主张；或
- mutant 已施加但测试仍然通过；或
- 所需独立 Verifier 形成有效否定结论。

### 9.3 UNKNOWN

无法充分判断：

- mutant 未成功施加；
- verifier 超时、崩溃或资源耗尽；
- evidence 不完整；
- 环境或依赖无法重建；
- 独立性不足；
- PolicyAnchor 无法解析；
- 多个有效结果互相冲突。

`UNKNOWN` 在商业上意味着暂不具备客户验收和外部结算准备条件。

### 9.4 非法输入不等于 UNKNOWN

`UNKNOWN` 只用于格式正确、签名有效、权威成立，但证据无法充分支持或反驳
主张的情况。

以下输入必须在事务写入前被拒绝，且不得生成签名的 UNKNOWN 决策：

- Schema 非法；
- 签名无效；
- 角色或能力未授权；
- causal parent 缺失；
- digest、slot 或 SubjectClaim 不匹配；
- nonce 重用；
- 非法 supersession；
- 超出 evidence 或 output 上限。

这一区分防止攻击者通过提交畸形对象，把明确的协议违规包装成“暂时不知道”。

## 10. 状态机

### 10.1 执行与证据状态

```text
running
  -> locally_verified
  -> evidence_incomplete
  -> proof_ready
  -> awaiting_human
  -> accepted | rejected
```

约束：

- 只有当前 VerificationDecision 为 `VERIFIED` 才能进入 `proof_ready`；
- `REFUTED` 或 `UNKNOWN` 保持 `evidence_incomplete`；
- `accepted` 或 `rejected` 是 terminal；
- 失败交付不能原地重开；
- 新一次交付必须创建新 WorkOrder，并引用旧 WorkOrder digest。

### 10.2 VerificationDecision 生命周期

VerificationDecision append-only：

```text
D1 VERIFIED
  -> D2 REFUTED supersedes D1
  -> D3 VERIFIED supersedes D2
```

历史决策保留，但只有最新有效、可重放的决策驱动当前 read model。

### 10.3 Acceptance 生命周期

```text
NONE
  -> ACTIVE
  -> WITHDRAWN

ACTIVE
  -> SUPERSEDED

ACTIVE
  -> SUSPENDED
```

当最新 VerificationDecision 不再为 `VERIFIED` 时，既有 AcceptanceReceipt 不被
删除，但 EffectiveAcceptance 必须转为 `SUSPENDED`。

### 10.4 SettlementReadiness 确定性映射

映射按以下优先级从上到下执行：

| 条件 | SettlementReadiness |
|---|---|
| 当前验收存在有效 withdrawal | `WITHDRAWN` |
| 当前验收被有效新验收取代 | `SUPERSEDED` |
| 已有 AcceptanceReceipt，但当前决策为 `REFUTED`、`UNKNOWN` 或缺失 | `SUSPENDED` |
| 当前决策为 `VERIFIED`，当前验收为 `ACTIVE` | `ACCEPTED_FOR_SETTLEMENT` |
| 当前决策为 `VERIFIED`，尚无接受或拒绝 | `READY_FOR_ACCEPTANCE` |
| 当前存在 AcceptanceRejectionReceipt | `NOT_READY` |
| 其他所有情况 | `NOT_READY` |

同一 validated ledger prefix 必须在 CLI、MCP、Delivery Room 和 offline replay
中计算出完全相同的结果。

## 11. 端到端流程

### Phase A：冻结主张

Provider、客户和 Manager 确认 SubjectClaim、验收条件、positive arm、negative
arm、Verifier 和 Customer Acceptor。所有对象在执行前签名和摘要绑定。

### Phase B：Agent 执行

Agent 在有效 CapabilityGrant 和 PolicyDecision 下执行，对授权、工具调用、
输入、输出、环境和失败生成 ActionReceipt。

### Phase C：Positive Arm

Verifier 对精确 source revision、candidate revision、command、container、fixed
tests 和 dependency lock 执行正常验证。

### Phase D：Negative Arm

Verifier 执行 Manager-pinned mutant，并分别记录：

- mutant applied and caught；
- mutant applied and survived；
- mutant not applied；
- verifier crashed or timed out。

### Phase E：独立验证

standard 模式需要一个独立于执行 Agent 的 Verifier。high-risk 模式需要两个
满足身份、密钥、控制域和执行上下文独立性规则的 Verifier。

### Phase F：组合决策

确定性 composer 只根据签名输入和闭合规则生成 VerificationDecision，不调用
LLM，不依赖自由文本判断。

### Phase G：客户验收

Customer Acceptor 对同一个 delivery digest 作出：

- accept；
- reject；
- no decision，等待补证。

### Phase H：后续重验与争议

出现新证据时创建新的 VerificationDecision，并通过 `supersedes` 建立链路。
Customer Acceptor 可以签署 withdrawal 或 supersession，但不能改写历史。

## 12. 事务与原子性

### 12.1 T1 Profile Commit

原子提交 SubjectClaim 和 VerificationProfile，要求 WorkOrder、角色、签名、
摘要、有效期、nonce 和所有 arm 定义在写入前通过。

### 12.2 T2 Arm Result Commit

原子提交 VerificationArmResult、ActionReceipt parents 和 EvidenceRef。任何
摘要、签名、slot 或 causal predecessor 错误均零写入。

### 12.3 T3 Decision Commit

原子提交 VerificationDecision、ordered arm-result references、独立性评估和
supersedes edge。

### 12.4 T4 Acceptance Commit

原子提交 AcceptanceReceipt 或 AcceptanceRejectionReceipt，要求 Customer
Acceptor 权威和 delivery digest 精确匹配。

### 12.5 T5 Acceptance Transition Commit

原子提交 withdrawal 或 supersession，要求 predecessor 为当前有效验收记录。

### 12.6 共同事务规则

每个事务都必须：

1. 获取 target lock；
2. `BEGIN IMMEDIATE`；
3. stage；
4. 在权威事务上下文中重验；
5. commit；
6. 用 canonical readback 确认 committed truth；
7. 释放锁。

COMMIT ACK 丢失时：

- 已提交且 readback 精确匹配：返回 committed result；
- 明确未提交：返回 not committed；
- 无法确定：返回 transaction indeterminate，禁止静默重试。

并发提交同一 predecessor 时必须恰好一个赢家。

### 12.7 Delivery Package Export

导出是只读操作：

1. 创建同目录临时目录；
2. 写入全部文件；
3. 重算 manifest；
4. 执行一次离线验证；
5. 原子 rename 为最终目录；
6. 失败时清理临时目录。

导出失败不得改变协议账本。

## 13. 失败语义与 ReasonCode Registry

所有决定状态的失败必须使用闭合 reason code，自由文本只能作为解释。

### 13.1 AUTH

- `AUTH_SIGNATURE_INVALID`；
- `AUTH_GRANT_EXPIRED`；
- `AUTH_GRANT_REVOKED`；
- `AUTH_ROLE_MISMATCH`；
- `AUTH_CAPABILITY_MISSING`；
- `AUTH_NONCE_REUSED`；
- `AUTH_SUBJECT_MISMATCH`；
- `AUTH_POLICY_ANCHOR_UNAVAILABLE`。

授权失败不得开始执行，不生成工作完成回执，SettlementReadiness 为
`NOT_READY`。

### 13.2 EXEC

- `EXEC_COMMAND_FAILED`；
- `EXEC_TIMEOUT`；
- `EXEC_CRASHED`；
- `EXEC_RESOURCE_EXHAUSTED`；
- `EXEC_OUTPUT_LIMIT`；
- `EXEC_WORKSPACE_DRIFT`；
- `EXEC_DEPENDENCY_DRIFT`。

执行基础设施失败不自动等于业务主张被反驳。

### 13.3 MUTATION

- `MUTATION_APPLIED`；
- `MUTATION_NOT_APPLIED`；
- `MUTATION_SURVIVED`；
- `MUTATION_CAUGHT`；
- `MUTATION_TARGET_MISMATCH`；
- `MUTATION_CLASSIFIER_UNAVAILABLE`。

### 13.4 EVIDENCE

- `EVIDENCE_MISSING`；
- `EVIDENCE_DIGEST_MISMATCH`；
- `EVIDENCE_SIGNATURE_INVALID`；
- `EVIDENCE_CAUSAL_PARENT_MISSING`；
- `EVIDENCE_SIZE_LIMIT_EXCEEDED`；
- `EVIDENCE_PUBLICATION_INCOMPLETE`；
- `EVIDENCE_BUNDLE_REPLAY_FAILED`。

关键 evidence 错误时，不得 `VERIFIED`、不得 `proof_ready`、不得
`READY_FOR_ACCEPTANCE`。

### 13.5 INDEPENDENCE

- `INDEPENDENCE_KEY_REUSED`；
- `INDEPENDENCE_DOMAIN_OVERLAP`；
- `INDEPENDENCE_BUILD_NOT_DISTINCT`；
- `INDEPENDENCE_CONTEXT_REUSED`；
- `INDEPENDENCE_INSUFFICIENT`；
- `INDEPENDENCE_UNPROVEN`。

### 13.6 ACCEPTANCE

- `ACCEPTANCE_DIGEST_MISMATCH`；
- `ACCEPTANCE_ACTOR_UNAUTHORIZED`；
- `ACCEPTANCE_ALREADY_TERMINAL`；
- `ACCEPTANCE_PREDECESSOR_STALE`；
- `ACCEPTANCE_WITHDRAWN`；
- `ACCEPTANCE_SUPERSEDED`；
- `ACCEPTANCE_TRANSITION_INVALID`。

## 14. 可信边界和外部锚点

### 14.1 OWP 能证明

- 谁授权了哪个 Agent；
- 允许执行什么；
- 对哪个版本、输入和环境执行；
- 产生了哪些签名证据；
- 哪些 Verifier 在什么上下文形成结论；
- Customer Acceptor 对哪个摘要作出验收；
- 是否发生撤回和 supersession。

### 14.2 OWP 不能单独证明

- 商业合同是否合法；
- 付款是否发生；
- 发票是否开具；
- 客户是否真实使用交付物；
- 原始需求是否符合现实业务意图；
- 恶意 Manager 重签整套虚假对象；
- 外部 Policy Registry 的政策内容本身正确。

### 14.3 PolicyAnchor

OWP 只引用外部政策状态：

```yaml
policy_registry_uri:
policy_version:
policy_digest:
effective_at:
resolved_at:
resolver_identity:
```

OWP 不维护全局 Policy Registry。

### 14.4 CommitmentAnchor

用于固定执行前承诺：

```yaml
work_order_digest:
subject_claim_digest:
anchored_at:
anchor_provider:
anchor_reference:
```

首版允许 Git commit/tag、GitHub Release、客户签署文件摘要或企业内部时间戳
服务，不自建区块链。

## 15. 验证成本分级

### Level 0：内部开发

普通 CI，不要求双 Verifier，不生成客户验收包。

### Level 1：跨团队交付

签名 WorkOrder、正向验证、固定负控、单独 Verifier 和可离线 Evidence
Bundle。

### Level 2：客户验收

独立 Verifier、客户权威域 CommitmentAnchor、Customer Acceptor、
AcceptanceReceipt、SettlementReadiness 和 Delivery Package。

### Level 3：高风险交付

两个独立 Verifier、更严格资源和证据保留规则、支持撤回与重新验证。

## 16. 产品接口

### 16.1 内部应用服务

所有接口复用一个应用服务层：

```text
ProfileService
ExecutionEvidenceService
VerificationService
AcceptanceService
DeliveryPackageService
ReplayService
```

接口层只解析输入、调用服务、格式化输出；不得自己生成协议决策、绕过事务、
修改签名对象或推断 SettlementReadiness。

### 16.2 Provider CLI

```bash
owp project init
owp profile validate
owp execute run
owp evidence collect
owp delivery build
owp status
```

### 16.3 Verifier CLI

```bash
owp verify positive
owp verify negative
owp verify compose
owp verify bundle
```

### 16.4 Auditor CLI

```bash
owp audit replay delivery-package/
owp audit explain delivery-package/
owp audit compare old-package/ new-package/
```

### 16.5 最小 MCP 工具

```text
owp_create_work_order
owp_validate_profile
owp_request_authorization
owp_record_action
owp_stage_evidence
owp_commit_evidence
owp_run_verification
owp_get_decision
owp_build_delivery_package
owp_get_settlement_readiness
```

MCP 响应不是 committed truth；commit 后必须回读账本。MCP Server 不托管
Customer Acceptor 私钥。

### 16.6 Delivery Room

首版是可离线打开的静态 HTML。首屏回答：

1. Agent 是否被授权；
2. 对哪个版本做了什么；
3. 结果是否满足约定；
4. 测试是否能发现错误；
5. 客户现在是否具备验收条件。

协议对象放在“查看证据详情”，浏览器不持有客户私钥。

## 17. Delivery Proof Package

固定目录：

```text
delivery-package/
  manifest.json
  subject-claim.json
  work-order.json
  verification-profile.json
  execution-ledger/
  evidence/
    positive/
    negative/
  verification-decision.json
  acceptance/
  public-keys/
  settlement-readiness.json
  summary.html
  summary.pdf              # optional
  verify.sh                # portable entrypoint
```

`manifest.json` 必须绑定每个文件的路径、大小、摘要、media type、公开/私有级别
和必需性。

一次可验证交付流程只有在以下条件全部成立时才称为闭环：

- package 成功导出；
- offline replay 通过；
- Customer Acceptor 对相同 digest 接受或拒绝；
- 当前结论和状态可以由包内签名对象重新计算。

闭环不等于验收成功：收到拒绝表示流程已经形成可验证结果，但商业交付没有
通过。只有本地 HTML/PDF 或 Provider 自签报告，不能称为客户验收。

## 18. 隐私和数据最小化

默认包不得包含：

- 私钥和 access token；
- 环境变量全文；
- 不需要的客户源代码；
- 无关 stdout/stderr；
- 用户个人信息；
- 未授权第三方数据。

必须实现：

- Evidence 路径 allowlist；
- 单文件和总包大小上限；
- stdout/stderr 脱敏；
- 敏感字段拒绝；
- 仅摘要的客户内部 evidence；
- public 和 private package 分离。

## 19. 测试与发布门

### 19.1 Release Truth Record

每次正式发布记录：

```yaml
source_revision:
package_version:
protocol_schema_versions: []
test_environment:
total_passed:
total_failed:
total_skipped:
candidate_inventory:
evidence_bundle_replay:
built_at:
```

正式发布要求零失败、版本一致、candidate inventory 唯一命中、两个标准
Evidence Bundle 离线重放通过、wheel/sdist/container 摘要绑定当前 revision。

### 19.2 六层测试

1. 模型和 Schema；
2. 状态机；
3. 事务和故障注入；
4. 对象、因果链、证据和身份篡改；
5. 语义对抗；
6. 离线、兼容性、供应链和发布真值。

### 19.3 必测语义矩阵

| 场景 | Positive | Negative | 决策 |
|---|---|---|---|
| 修复正确且 mutant 被抓住 | 满足 | caught | VERIFIED |
| 修复错误 | 违背 | 任意 | REFUTED |
| mutant 生效但测试通过 | 满足 | survived | REFUTED |
| mutant 未施加 | 满足 | not applied | UNKNOWN |
| verifier 超时 | 未完成 | 未完成 | UNKNOWN |
| evidence 缺失 | 满足 | caught | UNKNOWN |
| 两个 verifier 重用密钥 | 满足 | caught | UNKNOWN |
| 报告顺序或绑定被篡改 | 任意 | 任意 | replay reject |
| 客户撤回验收 | 历史有效 | 历史有效 | WITHDRAWN |

### 19.4 故障注入

每个写事务至少覆盖：

- START 前失败；
- STAGE 后失败；
- COMMIT 前失败；
- COMMIT 成功但 ACK 丢失；
- commit 状态不确定；
- cleanup 失败；
- readback 失败；
- 双线程并发；
- 中断恢复；
- 重试幂等。

测试必须断言表级零写入、精确已提交事实、无重复回执、无孤儿父节点和 read
model 可重建。

### 19.5 三层负控

- Fast Guard：每次交付执行一个低成本固定 mutant；
- Continuous Guard：关键发布执行多组注册 mutant；
- Periodic Challenge：高风险或季度由独立人员设计 holdout mutant。

首个试点只强制 Fast Guard。Continuous Guard 属于 P1；Periodic Challenge
不进入 MVP。

### 19.6 Registered Adversarial Study

公开研究必须预先登记 source revision、protocol version、cases、mutation
classes、expected results、verifier bindings、exclusion rules、holdout cases 和
analysis method。结论只能覆盖登记案例，不能扩张为所有 Agent 交付可信。

## 20. 试点验收

### 20.1 技术成功条件

- WorkOrder 和 SubjectClaim 在执行前冻结；
- 关键执行步骤产生签名回执；
- positive arm 完成；
- 至少一个固定 negative arm 完成；
- Delivery Package 可断网重放；
- 第三方在全新环境得到相同 VerificationDecision；
- Customer Acceptor 对相同 digest 接受或拒绝；
- 没有 critical evidence 缺口；
- 报告和签名 JSON 一致。

### 20.2 商业成功条件

- 方案商支付试点定金；
- 使用真实项目和真实验收标准；
- Customer Acceptor 实际参与；
- 验收时间、补证轮数或争议定位成本改善；
- 客户或方案商愿意用于第二个项目。

### 20.3 21 天验证门

继续投入至少满足三项：

- 一个真实付费试点；
- 客户提供真实项目和验收标准；
- Customer Acceptor 实际参与；
- 验收周期或补证轮数下降；
- 方案商提出第二个项目；
- 客户愿意把交付包作为尾款依据之一。

停止扩建条件：

- 10 次合格访谈后无人提供真实项目；
- 无人支付定金；
- 客户不愿绑定 Acceptor；
- Delivery Package 不影响验收行为；
- 只有技术称赞，没有采购动作。

停止扩建 SaaS 不等于停止维护开源协议。

## 21. 版本和迁移

### 21.1 三类版本

- software release：Python 包、CLI、MCP Server；
- protocol schema：签名对象结构；
- commercial template：试点和客户报告模板。

三者必须单独披露，不得混成一个版本号。

### 21.2 追加式升级

v0.1 对象保持原始字节和摘要。v0.2 只通过新对象引用旧对象，不自动重签，
不自动补造负控和独立证据。

缺少 v0.2 Profile、negative evidence、SubjectClaim 或 acceptance digest binding
的旧包只能标为历史证据可读取，不能升级成 `VERIFIED`。

## 22. 数据存储

新增建议表：

```text
subject_claims
verification_profiles_v02
verification_arm_results
verification_decisions
verification_decision_parents
acceptance_transitions
external_anchors
delivery_package_records
```

规则：

- canonical signed bytes 单独保存；
- read model 可删除重建；
- 签名事实不得 update 覆盖；
- supersession 用新记录表达；
- HTML/PDF 不是事实源；
- Evidence 大文件只保存摘要和受控路径引用。

## 23. 研发切片

### M0：恢复发布真值

- 修复两个 candidate inventory 绑定失败；
- 统一 package/module/release 版本；
- 重跑 full required-live；
- 生成不可变 Release Truth Record；
- 更新文档。

Gate：零失败、版本一致、库存唯一命中、标准包重放通过。

### M1：SubjectClaim 与 Profile

- SubjectClaim 模型和 canonical serialization；
- Manager 签名；
- VerificationProfileV02 绑定；
- 执行前冻结；
- CLI 客户预览。

Gate：修改任何验收条件都改变 digest，执行后不可原地修改。

### M2：VerificationArmResult

- 三维状态；
- ReasonCode Registry；
- EvidenceRef 和执行上下文；
- Verifier 签名；
- fixed classifier。

Gate：not-applied、survived 和 verifier crash 不可混淆。

### M3：VerificationDecision

- 确定性 composer；
- standard/high-risk assurance；
- independence checking；
- supersession；
- T3 和 COMMIT-ACK readback。

Gate：无真实负控不能 VERIFIED，证据不足只能 UNKNOWN，并发一个赢家。

### M4：验收生命周期

- AcceptanceTransitionReceipt；
- EffectiveAcceptance；
- SettlementReadiness；
- Customer Acceptor 域隔离；
- T4/T5。

Gate：Provider 不能验收，撤回不删除历史，状态可离线重算。

### M5：Delivery Proof Package

- manifest；
- JSON/HTML/optional PDF；
- atomic export；
- offline verifier；
- privacy filters。

Gate：全新断网环境一条命令重放，任何关键文件篡改都被发现。

### M6：CLI、MCP 与 Delivery Room

- Provider/Verifier/Auditor CLI；
- MCP service mapping；
- static Delivery Room；
- Acceptor signing import/export。

Gate：不同接口产生同一协议结果，浏览器不持有 Acceptor 私钥。

### M7：对抗研究和双基准

- Rich #4196；
- Dify #33013；
- registered adversarial matrix；
- holdout cases；
- 机器可读分类报告。

Gate：双案例均含正负臂并离线通过，不把演示称为客户采用。

### M8：首个付费试点

- 10 个合格方案商触达；
- 一个真实项目；
- 收取定金；
- 21 天交付；
- Customer Acceptor 实际签署；
- 商业复盘。

Gate：真实付款、真实验收行为和复购或明确拒绝原因。

## 24. Definition of Done

任何切片只有同时满足以下条件才完成：

1. 模型、不变量和拒绝语义已写入规格；
2. 先有失败测试，再实现；
3. success、reject、UNKNOWN、tamper 和 failure injection 均覆盖；
4. focused tests 通过；
5. full required-live tests 通过；
6. Candidate Inventory 绑定当前 revision；
7. offline replay 通过；
8. 文档与行为一致；
9. 没有夸大外部采用和商业状态；
10. 独立代码审核通过；
11. 合并、推送、发布和外部验收分别报告；
12. 客户试点的外部验收只能由 Customer Acceptor 确认。

## 25. 总体完成定义

可进入商业试点版本必须真实形成：

```text
冻结客户验收主张
  -> Agent 获得有效授权
  -> 产生因果完整执行证据
  -> positive arm 完成
  -> fixed negative arm 完成
  -> independent Verifier 形成三态决策
  -> 生成可离线复核 Delivery Package
  -> Customer Acceptor 接受或拒绝
  -> 计算 SettlementReadiness
```

OpenWorkProof 最终证明的是：

> 谁基于什么授权、证据和验证结果，接受了哪一次 Agent 交付。

它不证明资金已经支付，也不证明现实世界中的全部事实绝对正确。

## 26. 实施前审批门

在触碰产品代码前必须依次完成：

1. 用户审核本规格；
2. 根据本规格编写详细实施计划；
3. 用户审核实施计划；
4. 创建隔离开发分支或 worktree；
5. 从 M0 开始按测试驱动方式实施；
6. 每个切片经过独立规格审核和质量审核；
7. 未经用户指示，不合并、不推送、不发布。
