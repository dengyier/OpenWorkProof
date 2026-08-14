# OpenWorkProof Verification Integrity v0.5 研发设计规格

**日期：** 2026-08-15

**状态：** 用户已复核并批准；可进入 TDD 实施计划

**目标基线：** `main@e285d2c74e7ddde41dcdb9c1d9e2b9e45514b4cc`

**首个适配场景：** AI Agent 代码交付中的 pytest / Git 范围验证

**兼容基线：** Evidence Lifecycle v0.2、Scope-Bound Verification v0.3、
Judgment-to-Action Binding v0.4

## 1. 决策摘要

OpenWorkProof v0.5 第一阶段增加 **Verification Integrity（验证完整性）**。

v0.3 已证明验证器检查的成员集合与预先声明的静态范围一致；v0.4 已证明
Agent 的实际行动仍对应客户批准的判断。但当前协议尚不能稳定回答两个更深的
问题：

1. 验证器在执行选择规则前究竟看到了多少合格对象；零结果是合法空总体，
   还是采集器失明？
2. 负控虽然失败了，但是否因预期的目标错误而失败；还是因为格式、依赖或
   Schema 漂移而产生了无关失败？

本规格在现有 v0.3 Profile / Arm Result / Decision 链上增加两组闭合结构：

- 每条 selector 对应的 `PopulationContractV05` 与
  `PopulationObservationV05`，冻结选择规则、选择前总体、选择后总体与
  捕获率；
- `ControlContractV05` 与 `ControlObservationV05`，冻结负控目标、已知坏样本、
  预期失败签名与实际失败签名。

v0.5 不新增第四种验证结论。最终决定仍为
`VERIFIED / REFUTED / UNKNOWN`：

- 只有总体完整且负控按目标失败时，才允许 `VERIFIED`；
- 主张或修复被充分反例推翻时形成 `REFUTED`；
- 空总体、采集失败、规则漂移、负控失配或证据不足形成 `UNKNOWN`。

## 2. 设计依据与证据边界

### 2.1 社区输入

本规格综合 2026-08-12 至 2026-08-15 的 DEV Community 讨论：

1. 采样器每天可看到数百个合格事件，却连续多日选择零行；命令成功、退出码
   为零、签名有效，但采集器已经失明。
2. `selected_count` 只适合人类阅读；机器验证还需要绑定产生该数量的规则摘要
   和总体摘要。规则或集合变化时，旧结论应显式失效，不能继续静默绿色。
3. 已知坏样本可能继续失败，但失败原因已因 Schema 或依赖迁移改变；这类
   control rot 会让验证器错误地保持 `proven`。
4. 干净重跑只能证明检查执行，不能证明检查边界正确。每个批准应绑定精确证据
   集合，修复后必须生成新检查，不能复用旧结论。
5. 本地、单机、低风险场景可先使用可重放执行记录；签名与独立验证只在证据
   跨组织边界或风险提高时启用。

这些反馈是问题证据和协议输入，不等于客户采用、付费、上游采纳、行业共识或
正式安全认证。

### 2.2 当前协议已覆盖

本轮不重复建设：

- v0.3 `EvaluationScopeManifest` 的 selector、成员、成员数量、总体摘要、
  必含目标、排除项和跨臂 exact-match；
- 正臂与至少一个 Manager-pinned 负臂；
- mutant digest、mutation applied / caught / survived；
- `VERIFIED / REFUTED / UNKNOWN`；
- EvidenceRef、证据快照摘要、独立 Verifier 与高风险双 Verifier；
- Decision supersession、Acceptance withdraw / supersede；
- v0.4 Judgment、ActionBindingManifest、ActionReceipt 与 BindingDecision；
- Delivery Package 与离线重放。

### 2.3 当前缺口

v0.3 的总体是针对冻结 Git revision 的静态声明范围，当前仍缺：

- 选择前合格对象数量与摘要；
- 每条选择规则摘要与对应执行器摘要的显式观测；
- 选择前后数量关系和 capture rate；
- 空总体与采集器失明的区别；
- 负控所证明的目标属性；
- 负控的预期失败签名；
- 负控因错误原因失败时的关闭规则；
- control fixture、规则或执行器变化后的 stale 处理。

## 3. 方案选择

### 3.1 方案 A：原地扩展 v0.3 对象

直接给 v0.3 Schema 增加字段最省代码，但会改变已发布 Schema、签名字节和
历史包解释，违反版本冻结原则，因此拒绝。

### 3.2 方案 B：新增 v0.5 sibling 对象并复用 v0.3 流程

新增 v0.5 Profile / Arm Result / Decision 版本；v0.3 对象和签名字节完全冻结。
新字段采用嵌套闭合结构，事务、离线包与版本路由沿用既有模式。

**采用本方案。** 它能提供机器可验证语义，又不会让 v0.1—v0.4 历史对象被
静默解释为具备新能力。

### 3.3 方案 C：只在 Delivery Package 中增加说明性 metadata

该方案不改变协议对象，但 metadata 不受 Profile、Arm Result 和 Decision 的
完整签名链约束，独立验证器不能把它作为信任输入，因此拒绝。

## 4. 目标与非目标

### 4.1 目标

1. 每个 v0.5 Profile 必须为每条 v0.3 selector rule 冻结一个总体契约，并
   冻结至少一个负控契约。
2. 每个正臂和负臂结果必须报告选择前、选择后总体及规则摘要。
3. 第三方能离线区分合法空总体、采集器失明、规则漂移和集合漂移。
4. 每个负臂必须证明它因声明的目标失败，而不是因无关错误失败。
5. fixture、规则、执行器或失败签名变化时，旧 `proven` 不得继续生效。
6. v0.5 结论必须保持三态并提供闭合 reason codes。
7. v0.1—v0.4 Schema、签名字节、账本和历史包保持可读且不可变。
8. 首版 Python/pytest 适配器形成可重复、可离线重放的演示闭环。

### 4.2 非目标

本轮不实现：

- 动态消息流、监控线程、数据库记录或跨 SaaS 事件采样适配器；
- Merkle membership proof、透明日志、区块链或见证人网络；
- 任意领域 `control_target` 或可编程 policy language；
- LLM-as-judge、业务真理判断或自然语言验收条件自动解释；
- Evidence Requirement Binding、权威来源冲突治理或修复审批工作流；
- Verification Maturity CLI、Dashboard、托管控制面或计费系统；
- 支付、托管、自动结算、法律责任判断或客户验收证明；
- 把 GitHub Star、评论、测试通过或本地演示写成商业采用。

Evidence Requirement Binding 与成熟度产品属于独立后续规格，必须在本阶段
完成并取得外部复现证据后再启动。

## 5. 核心术语

- **Eligible population：** 在选择规则应用前，适配器实际看见的全部合格对象。
- **Selected population：** 选择规则应用后，验证器真正检查的对象集合。
- **Selection rule digest：** 对规范化规则集合和规则版本进行 JCS 编码后得到的
  SHA-256 摘要。
- **Eligible population digest：** 对排序后的合格成员身份集合计算的摘要。
- **Selected population digest：** 与 v0.3 `population_digest` 相同的成员身份
  摘要；不得用数量替代。
- **Capture rate：** `selected_count / eligible_seen` 的规范化有理数表示；协议
  不使用浮点数。
- **Control target：** 负控被设计用于证明的闭合目标属性。
- **Failure signature：** 能区分“按目标失败”和“因无关问题失败”的结构化结果。
- **Control rot：** control 仍失败，但 fixture、目标或失败原因已变化，旧的
  `proven` 状态不再成立。

## 6. 协议对象

### 6.1 `PopulationContractV05`

该对象嵌入 Manager 签名的 `VerificationProfileV05`，本身不另设签名：

```yaml
contract_id: <sha256>
selector_rule_id: <sha256>
member_kind: source_file | test_case
selector_spec_digest: <sha256>
selector_engine_digest: <sha256>
declared_selected_member_ids: [<sha256>, ...]
minimum_eligible_count: 1
minimum_selected_count: 1
maximum_eligible_count: 4096
maximum_selected_count: 4096
minimum_capture_numerator: 1
minimum_capture_denominator: 100
empty_population_policy: unknown
required_population_evidence_purposes:
  - eligible-population
  - selected-population
```

约束：

1. 首版 `empty_population_policy` 固定为 `unknown`；零总体不能产生
   `VERIFIED`，也不被误报为采集失败。
2. capture rate 使用整数分子和分母，必须满足
   `0 <= numerator <= denominator`；`0/1` 只表示未设比例下限，不能绕过
   `minimum_selected_count`。
3. 上限不得超过 4096，且 selected 上限不得大于 eligible 上限。
4. 每个 v0.3 selector rule 必须恰好对应一个 contract；`selector_rule_id`、
   selector spec digest 和 engine digest 必须与该 rule 完全一致。
5. `declared_selected_member_ids` 必须是该 rule 产出的 v0.3 Scope member 子集，
   非空、排序、唯一，且所有成员的 kind 等于 `member_kind`。Profile 中所有
   contract 的该字段并集必须恰好覆盖 Scope Manifest 的 source/test 成员；
   不允许一个成员由多个 rule 重复声明。
6. `contract_id` 使用 domain
   `openworkproof/population-contract/v0.5` 重算。

### 6.2 `PopulationObservationV05`

该对象嵌入 Verifier 签名的 `VerificationArmResultV05`：

```yaml
contract_id: <sha256>
selector_rule_id: <sha256>
selector_spec_digest: <sha256>
selector_engine_digest: <sha256>
eligible_seen: <non-negative integer>
eligible_population_digest: <sha256>
selected_count: <non-negative integer>
selected_population_digest: <sha256>
capture_numerator: <non-negative integer>
capture_denominator: <positive integer>
observed_at: <canonical UTC time>
evidence_refs: [EvidenceRef, ...]
```

约束：

1. `eligible_seen == 0` 时 selected_count 必须为零，capture 固定为 `0/1`，
   两个总体摘要使用规范空集合摘要。
2. `eligible_seen > 0` 时 capture 必须化为最简分数，并精确等于
   `selected_count / eligible_seen`。
3. `selected_count <= eligible_seen`。
4. 两个总体摘要都必须从规范排序、唯一的成员身份列表重算。
5. observation 的规则和执行器摘要必须与 contract 完全一致。
6. 结论性 observation 必须提供 contract 要求的两类 EvidenceRef。
7. Observation 的 `selector_rule_id` 必须等于 contract；selected 成员必须
   精确等于 contract 的 `declared_selected_member_ids`。
8. 正臂与所有负臂必须按 contract id 报告相同 eligible / selected 集合；
   任一缺失、重复或不一致形成
   `UNKNOWN / POPULATION_CROSS_ARM_MISMATCH`。

### 6.3 `FailureSignatureV05`

```yaml
execution_status: completed
exit_codes: [1]
reason_codes: [MUTATION_CAUGHT]
predicate_ids: [tests_passed]
required_evidence_purposes: [test-result]
```

约束：

1. 所有数组非空、排序、唯一并有数量上限。
2. `execution_status` 使用现有闭合执行状态；首版预期签名必须是
   `completed`，基础设施失败不能证明 control target。
3. failure signature 摘要使用 domain
   `openworkproof/failure-signature/v0.5`。
4. 不绑定完整 stderr 文本，避免平台噪声；只绑定结构化错误码、谓词和证据
   用途。

### 6.4 `ControlContractV05`

该对象嵌入 Manager 签名的 `VerificationProfileV05`：

```yaml
control_id: <sha256>
arm_id: <sha256>
control_target: semantic_regression | required_target_coverage
fixture_digest: <sha256>
provocation_digest: <sha256>
expected_failure_signature: FailureSignatureV05
expected_failure_signature_digest: <sha256>
valid_from: <canonical UTC time>
expires_at: <canonical UTC time>
```

首版只允许两个 target：

- `semantic_regression`：已知补丁重新引入目标缺陷，测试必须以注册签名失败；
- `required_target_coverage`：移除或绕过一个必含目标，Scope gate 必须以注册
  签名失败。

约束：

1. 每个 v0.5 negative arm 恰好对应一个 control contract。
2. `fixture_digest` 必须等于该 arm 的 `mutant_patch_digest`。
3. `provocation_digest` 绑定应用 fixture 的规范化步骤，不绑定自由文本说明。
4. `valid_from < expires_at`，Arm Result 的 `created_at` 必须位于窗口内。
5. failure signature digest 必须由嵌套对象重算。
6. `control_id` 使用 domain `openworkproof/control-contract/v0.5` 重算。

### 6.5 `ControlObservationV05`

该对象嵌入 Verifier 签名的 `VerificationArmResultV05`：

```yaml
control_id: <sha256>
fixture_digest: <sha256>
provocation_digest: <sha256>
observed_failure_signature: FailureSignatureV05
observed_failure_signature_digest: <sha256>
control_status: proven | survived | mismatched | unavailable
evidence_refs: [EvidenceRef, ...]
```

状态闭合映射：

- `proven`：fixture 和 provocation 精确匹配，实际失败签名与预期签名精确相同；
- `survived`：fixture 已应用且执行完成，但目标检查没有失败；
- `mismatched`：发生失败，但失败签名与预期不一致；
- `unavailable`：fixture 未应用、执行未完成或证据不可用。

`survived` 提供主张反例，可参与形成 `REFUTED`；`mismatched` 和
`unavailable` 只能形成 `UNKNOWN`。

### 6.6 v0.5 Profile / Arm Result / Decision

新增 sibling 版本：

```text
VerificationProfileV05(VerificationProfileV03)
  population_contracts: tuple[PopulationContractV05, ...]
  control_contracts: tuple[ControlContractV05, ...]

VerificationArmResultV05(VerificationArmResultV03)
  population_observations: tuple[PopulationObservationV05, ...]
  control_observation: ControlObservationV05 | None

VerificationDecisionV05(VerificationDecisionV03)
  integrity_assessment: VerificationIntegrityAssessmentV05
```

每个 Arm Result 必须按 contract id 排序、唯一地覆盖全部 population
contracts。正臂的 `control_observation` 必须为空；每个负臂必须提供与自身 arm
id 对应的 control observation。Profile 和 Result 使用独立 `0.5` signing
domain，不能复用 v0.3 签名字节。

## 7. `VerificationIntegrityAssessmentV05`

```yaml
population_status: matched | empty | capture_failed | drifted | unavailable
control_status: proven | survived | mismatched | unavailable
reason_codes: [<closed code>, ...]
```

### 7.1 总体状态

- `matched`：规则、执行器、集合、数量、capture rate 和证据全部满足 contract；
- `empty`：eligible 和 selected 都为零；
- `capture_failed`：eligible 非零但 selected 为零或低于最小 capture；
- `drifted`：规则、执行器、集合摘要或跨臂结果不一致；
- `unavailable`：无法取得或重放总体证据。

### 7.2 控制状态

聚合所有负臂：

- 全部 `proven` 才是 `proven`；
- 任一 `survived` 为 `survived`；
- 无 survived 且任一 mismatched 为 `mismatched`；
- 其余不完整情况为 `unavailable`。

### 7.3 决策映射

1. `population_status != matched` 时必须 `UNKNOWN`。
2. `control_status == survived` 且总体完整时必须 `REFUTED`。
3. `control_status in {mismatched, unavailable}` 时必须 `UNKNOWN`。
4. 只有总体 matched、全部 control proven、正臂 satisfied、独立性充分且 v0.3
   条件全部满足时才允许 `VERIFIED`。
5. 已提交决定不可原地变成 stale。规则、fixture、执行器或新证据发生变化时，
   必须提交引用前决定的 superseding Decision；历史决定保持当时真相。

## 8. 闭合 reason codes

v0.5 新增：

```text
NO_ELIGIBLE_POPULATION
POPULATION_CAPTURE_FAILED
POPULATION_RULE_DRIFT
POPULATION_ENGINE_DRIFT
POPULATION_DIGEST_MISMATCH
POPULATION_CROSS_ARM_MISMATCH
POPULATION_EVIDENCE_MISSING
CONTROL_CONTRACT_EXPIRED
CONTROL_FIXTURE_DRIFT
CONTROL_PROVOCATION_DRIFT
CONTROL_FAILURE_SIGNATURE_MISMATCH
CONTROL_SURVIVED
CONTROL_EVIDENCE_MISSING
```

reason codes 必须排序、唯一，并与 assessment 状态相容。解析失败、未知字段、
非规范 JSON、错误签名或错误角色属于 invalid protocol input，不允许包装为
签名 `UNKNOWN`。

## 9. 数据流

1. Manager 为 v0.3 Scope 的每条 selector rule 生成一个 population contract。
2. Manager 为每个 negative arm 生成 control contract，并签署 v0.5 Profile。
3. Verifier 在冻结容器中先枚举 eligible population，再应用 selector，记录两个
   集合和证据。
4. Verifier 应用固定 fixture 和 provocation，执行检查并生成结构化 failure
   signature。
5. Verifier 签署 v0.5 Arm Result；Sidecar 只记录，不替 Verifier 决策。
6. Decision composer 加载完整 v0.3 与 v0.5 历史，计算 integrity assessment。
7. Decision 事务以 append-only、target lock、`BEGIN IMMEDIATE`、pre-COMMIT
   零写入和 COMMIT-ACK exact readback 提交。
8. Delivery Package 包含 Profile、Arm Result、Decision、规则证据、eligible 与
   selected population 证据、control fixture 与 failure signature。
9. 离线 verifier 从包内字节重算所有摘要和状态，不访问网络，也不信任
   README、日志摘要或调用方 metadata。

## 10. 存储与不可变性

v0.5 使用与现有 verification 事务平行的 append-only 表，不修改 v0.3 行：

- v0.5 Profile、Arm Result、Decision 使用新 schema discriminator；
- 表内保存 canonical JSON、digest、签名、`committed_at`；
- digest / canonical JSON、业务 id、signer nonce 使用唯一约束；
- UPDATE / DELETE trigger 物理拒绝；
- 所有外键指向已提交 WorkOrder、Scope 和前序 Decision；
- exact replay 返回 committed truth；同 id 不同 payload、不同 profile 或不同
  relation 失败关闭；
- 完整历史重放必须检测 root、fork、cycle、dangling parent 与时间逆序。

## 11. Python / pytest 首版适配器

### 11.1 Eligible population

`pytest --collect-only` 在应用 marker、path 或 node-id selector 前收集的完整 node
集合。每个 node 使用规范 node id 作为稳定身份。

### 11.2 Selected population

按 v0.3 `ScopeSelectorRule` 应用 selector 后的 node 集合。选后成员必须等于
EvaluationScopeManifest 的 test-case 成员子集。

### 11.3 Git 范围

Git 适配器把 source revision 与 candidate commit 的规范 diff closure 作为
eligible 集合，把 allowlist、排除项和必含规则应用后的集合记录为 selected。

### 11.4 负控失败签名

首版从以下结构生成：

- 容器执行状态；
- 规范化退出码；
- OWP reason codes；
- 产生决定的 predicate ids；
- 注册 EvidenceRef purposes。

不得把未清洗 stderr、绝对路径、主机名、随机临时目录或 wall-clock duration
写入 failure signature。

## 12. 威胁模型与失败关闭

必须拒绝或关闭：

1. `eligible_seen=400`、`selected_count=0` 仍报告绿色。
2. eligible 为零却伪造非空 selected。
3. 数量不变但规则摘要变化。
4. 数量不变但成员摘要变化。
5. 正负臂使用不同 eligible 或 selected 集合。
6. fixture 已替换但复用旧 control id。
7. fixture 仍失败，但错误码或 predicate 与注册签名不同。
8. provocation 没有实际应用。
9. 负控只因依赖安装、Schema 或基础设施错误失败。
10. Profile 已过期后产生新 Result。
11. Result 引用未知、过期或错误角色签署的 Profile。
12. 修复后复用旧 Result 或旧 Decision。
13. 人工修改账本 relation、canonical JSON、committed_at 或签名。
14. COMMIT 已发生但 ACK 丢失时重复提交。
15. public Delivery Package 泄露私有 locator、fixture 内容或绝对路径。

## 13. 测试与验收标准

### 13.1 模型与 Schema

- v0.5 四个嵌套对象与三个 sibling 对象均有 closed-schema JSON；
- 未知字段、非规范顺序、重复数组、越界数量、错误摘要、错误时间全部拒绝；
- runtime schema 与 `spec/protocol/schema/v0.5`、包内 schema 三份逐字节一致；
- v0.1—v0.4 已冻结 Schema SHA 与 golden signing bytes 不变。

### 13.2 决策矩阵

- matched + proven + positive satisfied => VERIFIED；
- matched + survived => REFUTED；
- empty、capture_failed、drifted、unavailable => UNKNOWN；
- matched + mismatched/unavailable control => UNKNOWN；
- invalid input 在签名 Decision 之前拒绝。

### 13.3 敌对矩阵

至少覆盖第 12 节全部 15 类攻击，并使用 `model_dump -> mutate ->
model_validate` 完整重建；需要测试语义校验的案例必须重新签名，避免被坏签名
提前短路。

### 13.4 事务与并发

- pre-COMMIT fault 对所有表零写入；
- COMMIT-then-raise 回读 exact committed truth；
- identical 并发恰好一个 committed、一个 already_committed；
- 同 id 不同 payload 恰好一个成功；
- cleanup 失败不改变 committed truth；
- UPDATE / DELETE 均物理拒绝。

### 13.5 离线包

- 在无仓库、无网络、无原始账本的独立临时目录得到相同 Decision；
- 篡改任一 contract、observation、证据、签名、关系或 schema 必须失败关闭；
- public/customer_private/verifier_private 三种视图均通过隐私矩阵。

### 13.6 全量门

- v0.5 focused 套件零失败；
- v0.1—v0.4 frozen compatibility 零失败；
- candidate supply-chain 两套件零失败；
- required-live 全量零失败、零 skip，并启用
  `-W 'error::pytest.PytestUnhandledThreadExceptionWarning'`；
- Docker 容器、卷、临时锁和构建残留为零。

## 14. 商业与产品边界

本阶段产生的是协议能力和自有演示，不是客户案例。它可以支持后续
“AI Agent 验证成熟度诊断”的技术底座，但不得声称：

- 客户愿意付费；
- 已减少验收争议或回款周期；
- 已获得第三方安全认证；
- 已被 MCP、A2A 或其他上游项目采纳；
- 可自动付款、托管、结算或仲裁。

商业验证必须另行取得真实 SOW、定金、客户控制的 Acceptor、外部复现和客户
验收决定。没有这些材料时继续标记为 `not_evidenced`。

## 15. 后续规格边界

完成本规格并取得一项外部复现后，才进入：

1. `EvidenceRequirementBinding`：需求—权威来源—证据—新鲜度—矛盾规则；
2. Verification Currentness：跨规则、总体、控制和证据的当前有效性视图；
3. Verification Maturity Report：面向 Agent 方案商的可售诊断工具；
4. 动态事件流适配器：消息、监控、数据库和跨 SaaS population。

每一项必须有独立设计规格和实施计划，不在 v0.5 第一阶段预埋通用平台。
