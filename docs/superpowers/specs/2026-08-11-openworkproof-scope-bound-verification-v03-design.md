# OpenWorkProof Scope-Bound Verification v0.3 设计规格

**日期：** 2026-08-11

**状态：** 用户已书面批准，进入实施计划阶段

**目标基线：** `main@fe719e95fd5b34a9a5c00bb137c56db22c430fd3`

**规格范围：** Agent 代码交付验收

**兼容基线：** Evidence Lifecycle v0.2

## 1. 决策摘要

OpenWorkProof v0.3 增加 **Scope-Bound Verification（范围绑定验证）**：
验证结论不仅要证明检查真实执行、正负臂满足预期，还必须证明检查覆盖了
正确的、预先承诺的对象集合。

本规格回答一个 v0.2 尚未回答的问题：

> 当验证器报告绿色结果时，它究竟检查了哪些源文件、测试和交付工件；客户
> 要求的关键目标是否真的进入了被检查集合？

v0.3 的核心新增对象是 `EvaluationScopeManifest`。它冻结选择规则、不可变
源码 revision、被检查成员集合、客户要求的必含目标和明确排除项。新的
Verification Profile、Arm Result 与 Verification Decision 均绑定该 Manifest。

## 2. 设计依据与证据边界

### 2.1 社区输入

本规格综合以下外部工程反馈：

1. 检查逻辑和负控都可能正确，但正确目标从未进入输入集合；空集合与真实
   “全部通过”可能产生相同绿色输出。
2. 文件存在、命令成功和签名有效，仍可能形成内容空洞但密码学完整的交付。
3. 今天有效的 guard 会因依赖重构而退化，单次负控不能证明长期有效。
4. 测试总数不能替代敌对案例、负控覆盖和已证明 guard 的披露。
5. 外部 PolicyAnchor 的信任根与历史应由外部系统负责，OWP 不应膨胀为
   全球政策注册表。

这些反馈是问题证据和研发输入，不代表客户付款、产品采用、行业共识或标准
组织认可。

### 2.2 当前 v0.2 已覆盖能力

v0.2 已实现且 v0.3 不重复建设：

- 正臂与至少一个真实负臂；
- `VERIFIED / REFUTED / UNKNOWN`；
- 独立 Verifier 与高风险双 Verifier；
- mutation applied / caught / survived 区分；
- `PolicyAnchor`、`CommitmentAnchor`；
- Acceptance withdraw / supersede；
- Delivery Package、离线重放与结算就绪度。

### 2.3 证据纠偏

历史社区笔记中的以下表述不得作为本规格的证据：

- “Study 014 包含 47 次攻击”；准确边界是 47 个测试单元/cells；
- “Policy-State Registry 参与了 Study 014”；该 Registry 并非实验组成部分；
- “零分歧验证了 Policy Registry 架构”；实验不能支持该结论。

Study 014 可支持的较窄结论是：存在对链内检查不可见的边界案例，外部权威
状态和范围完整性需要独立处理。

## 3. 目标与非目标

### 3.1 目标

1. 每个 v0.3 Verification Profile 必须绑定一个不可变范围 Manifest。
2. 第三方能够离线重算“声明范围”和“实际观察范围”是否一致。
3. 空集合、必含目标遗漏、选择器漂移和跨臂范围不一致不得产生 `VERIFIED`。
4. 正臂和所有负臂必须使用同一个成员身份集合和源码 revision。
5. 客户能够看到可读的 Scope Coverage Report，而不必理解协议对象。
6. v0.2 已签对象保持有效，不做静默升级或历史重写。

### 3.2 非目标

本轮不实现：

- 通用“语义真理”或 LLM-as-judge；
- Policy Registry、透明日志网络、见证人网络或区块链；
- Guard Health Dashboard 和持续调度服务；
- 资金托管、支付、清分、仲裁或付款证明；
- 非代码型动态数据源；
- 任意语言的通用测试发现器；首版只定义 Python/pytest 参考适配器；
- 将所有内部 CI 调用加密化；协议只用于真实信任边界。

## 4. 核心术语

- **Declared scope：** `EvaluationScopeManifest` 中预先承诺的成员集合。
- **Observed scope：** Verifier 在冻结环境执行选择器后实际得到的成员集合。
- **Scope member：** 一个源文件、测试节点或交付工件的稳定身份记录。
- **Required target：** 由 SubjectClaim/验收条件要求必须进入范围的成员。
- **Selector rule：** 从冻结源码 revision 中确定成员集合的规范化规则。
- **Population digest：** 对排序后的成员身份元组
  `(member_id, member_kind, locator_digest)` 做 JCS 编码后得到的 SHA-256
  摘要；它证明“检查了哪些对象”，不把 mutation 后的内容变化误判为成员
  集合变化。
- **Scope drift：** Declared scope 与 Observed scope 在成员身份、revision、
  选择器或摘要上的不一致。

## 5. 威胁模型

v0.3 必须检测或关闭以下失败：

1. 选择器返回空集合，验证器仍报告绿色。
2. Manager 省略一个客户要求的测试或文件。
3. 正臂检查完整集合，负臂只检查更小集合。
4. Manifest 声明 N 个成员，Evidence 实际只覆盖 N-1 个。
5. Manifest 绑定 revision A，执行发生在 revision B。
6. 选择器规范未变，但选择器执行器或依赖版本发生变化。
7. 成员路径、测试 node id 或内容摘要被篡改。
8. 通过符号链接、路径逃逸或重复规范化让一个成员冒充另一个成员。
9. 通过超大 Manifest 消耗离线验证器资源。
10. Public Delivery Package 泄露私有路径或测试名称。

v0.3 不宣称检测：

- 被检查代码是否满足未编码的业务意图；
- 恶意客户或 Manager 共同签署虚假目标；
- 外部政策内容本身是否正确；
- 测试断言是否在语义上充分；该问题属于后续语义适配器和 guard 健康层。

## 6. 协议不变量

Scope 相关摘要使用 RFC 8785 JCS 与 SHA-256，并采用以下固定 domain：

- member id：`openworkproof/scope-member/v0.3`；
- requirement digest：`openworkproof/scope-requirement/v0.3`；
- population digest：`openworkproof/scope-population/v0.3`；
- signed manifest：`openworkproof/evaluation-scope/v0.3`。

以下不变量全部满足时，Scope 才可被判断为充分：

1. Manifest 的签名、角色、授权、有效期和 nonce 有效。
2. Manifest 的 `work_order_digest`、`subject_claim_digest` 与 Profile 一致。
3. Manifest 的 `source_revision` 与所有 Verification Arm 一致。
4. `member_count == len(members)`。
5. `population_digest` 可由规范排序后的完整成员列表重算。
6. `required_target_ids` 是成员 id 集合的子集。
7. `excluded_locator_digests` 与成员 locator digest 集合不相交。
8. `required_target_ids` 指向的成员不得命中任何 excluded locator digest。
9. Profile、正臂结果和所有负臂结果绑定同一 `scope_manifest_digest`。
10. 每个 Arm Result 的 Observed scope 可重算并等于 Declared scope。
11. 空集合只允许形成 `UNKNOWN`；首版不提供“空集合视为通过”的配置。
12. Scope 证据缺失或无法重放只能形成 `UNKNOWN`，不能形成 `VERIFIED`。
13. `REFUTED` 仍只用于有充分证据支持的主张反例，例如负控存活；范围不足
    不等于主张被反驳。
14. v0.2 对象不得被 v0.3 Verifier 默认为已具备范围证明。

## 7. 新协议对象

### 7.1 `ScopeMember`

```yaml
member_id: <sha256>
member_kind: source_file | test_case | delivery_artifact
locator: <canonical logical locator>
locator_digest: <sha256>
content_digest: <sha256>
source_revision: <git object id>
```

约束：

- `member_id` 必须由 domain-separated 的 `(member_kind, locator)` canonical
  payload 重算，不能包含 `content_digest`，从而使同一逻辑对象在正负臂中
  保持稳定身份；
- `locator` 对源文件使用仓库相对 POSIX 路径，对 pytest 使用完整 node id，
  对交付工件使用 Delivery Package 内规范路径；
- 路径禁止绝对路径、`..`、NUL、反斜杠和未解析符号链接；
- 成员按 `(member_kind, locator_digest, member_id)` 严格排序且唯一；
- `content_digest` 对 source/test member 绑定冻结 revision 中的内容；对
  delivery artifact 绑定 SubjectClaim 中的预期工件描述，不绑定尚未产生的
  执行结果字节；结果字节继续由现有 EvidenceRef 证明；
- `population_digest` 只使用成员身份元组；成员内容完整性由签名 Manifest、
  revision、`workspace_manifest_digest` 和各 Arm 的 EvidenceRef 共同验证。

### 7.2 `ScopeSelectorRule`

首版允许三种规则：

```yaml
rule_id: <sha256>
selector_kind: explicit | git_diff_closure | pytest_collection
selector_spec_digest: <sha256>
selector_engine_digest: <sha256>
required_evidence_paths: [<canonical package path>, ...]
```

- `explicit`：显式列出成员；
- `git_diff_closure`：从 source/candidate revision 的变更闭包生成源文件成员；
- `pytest_collection`：从冻结 pytest 版本、配置和命令收集测试 node id；
- 规则规范作为 EvidenceRef 进入完整 Delivery Package，Manifest 只绑定摘要；
- 任意自定义脚本不属于 v0.3 首版。

### 7.3 `ScopeRequirementBinding`

`SubjectClaim.acceptance_conditions` 和 `SubjectClaim.required_artifacts` 不能只靠
自然语言与成员集合建立关系。Manifest 必须显式提供覆盖映射：

```yaml
requirement_kind: acceptance_condition | required_artifact
requirement_digest: <domain-separated sha256 of the canonical claim value>
member_ids: [<member_id>, ...]
```

约束：

- SubjectClaim 中每一个 acceptance condition 和 required artifact 都必须恰好
  出现一个 binding；
- 每个 binding 至少引用一个 Manifest member；
- 所有 `member_ids` 必须属于 Manifest，且严格排序、唯一；
- required artifact 只能绑定 `source_file` 或 `delivery_artifact`；
- acceptance condition 可以绑定 `source_file`、`test_case` 或
  `delivery_artifact`；
- 同一个 member 可以支持多个 requirement，但报告必须逐项披露；
- binding 只证明“该检查被指定用于覆盖该要求”，不证明检查语义充分。

### 7.4 `EvaluationScopeManifest`

`EvaluationScopeManifest` 是 Manager 签名的 `SignedProtocolModel`：

```yaml
schema_version: openworkproof-evaluation-scope/0.3
scope_id: <sha256>
work_order_digest: <sha256>
subject_claim_digest: <sha256>
source_revision: <git object id>
candidate_commit: <git object id>
selector_rules: [ScopeSelectorRule, ...]
members: [ScopeMember, ...]
member_count: <integer>
population_digest: <sha256>
requirement_bindings: [ScopeRequirementBinding, ...]
required_target_ids: [<member_id>, ...]
excluded_locator_digests: [<locator digest>, ...]
workspace_manifest_digest: <sha256>
freshness_mode: immutable_git_revision
created_at: <UTC timestamp>
expires_at: <UTC timestamp>
nonce: <sha256>
signer_key_id: <manager key id>
signature_alg: Ed25519
signature: <base64url>
```

约束：

- 首版 `freshness_mode` 只允许 `immutable_git_revision`；动态 API、收件箱和
  数据库水位留到后续规格；
- Manifest 不能为空，`member_count` 范围为 1..4096；
- canonical JSON 不得超过 8 MiB；
- 至少包含一个 `source_file` 或 `test_case`；
- 至少一个 `required_target_id`；
- `required_target_ids` 必须等于所有 requirement binding 引用成员的并集；
- `requirement_bindings` 必须完整覆盖 SubjectClaim 中的 acceptance conditions
  和 required artifacts，不能多出一个 Claim 中不存在的 requirement；
- `excluded_locator_digests` 必须严格排序且唯一；它只表达代码定位器级别的
  操作排除，不替代 SubjectClaim 中无法映射为路径的语义排除；语义排除继续
  由既有 predicate 和 Acceptance 条件执行；
- Manifest 的 `workspace_manifest_digest` 必须与 Profile 正臂和所有负臂的
  pinned workspace manifest 一致；
- Manifest 的 `source_revision`、`candidate_commit` 必须分别等于 Profile
  所有 Arm 的 `source_commit`、`candidate_commit`；
- `expires_at` 不得晚于 WorkOrder/Profile 的有效期；
- Level 2/3 必须由客户控制的现有 `CommitmentAnchor` 先绑定 SubjectClaim，
  Verifier 再通过 `requirement_bindings` 证明 Manifest 的必含目标覆盖该 Claim
  的 required artifacts 与 acceptance conditions；OWP 不把 Manager 签名
  冒充客户批准。

## 8. v0.3 Profile 与结果绑定

### 8.1 `VerificationProfileV03`

v0.3 新建 schema，不修改 v0.2 已签 payload：

```yaml
schema_version: openworkproof-verification-profile/0.3
evaluation_scope_id: <scope_id>
evaluation_scope_digest: <manifest digest>
scope_requirement: exact_match
...all v0.2 profile fields...
```

首版 `scope_requirement` 只允许 `exact_match`。子集、超集和近似匹配不在
本轮范围内。

Profile 校验必须加载完整 Manifest，并验证第 6 节全部静态不变量。仅有摘要
但无法取得 Manifest 时，Profile 不可进入执行。

### 8.2 `VerificationArmResultV03`

每个 v0.3 Arm Result 增加：

```yaml
scope_manifest_digest: <sha256>
observed_member_count: <integer>
observed_population_digest: <sha256>
observed_required_target_ids: [<member_id>, ...]
scope_expectation_status: satisfied | contradicted | indeterminate
scope_evidence_refs: [EvidenceRef, ...]
...all v0.2 arm result fields...
```

约束：

- `satisfied` 要求 count、population digest、required targets 和 revision
  全部精确一致；
- Manifest、选择器证据或成员证据缺失时必须为 `indeterminate`；
- 有完整证据证明成员集合不同则为 `contradicted`；
- `scope_expectation_status != satisfied` 时 Arm Result 不能参与
  `VERIFIED` 决定；
- 正臂与负臂必须分别重新执行选择器，但结果要收敛到同一 population digest。

### 8.3 `VerificationDecisionV03`

v0.3 Decision 使用新 schema，并在 v0.2 字段基础上增加一个可重算的 Scope
Assessment：

```yaml
schema_version: openworkproof-verification-decision/0.3
scope_manifest_digest: <sha256>
scope_assessment:
  declared_member_count: <integer>
  observed_member_counts: [<integer>, ...]
  population_digest: <sha256>
  required_target_count: <integer>
  missing_required_target_ids: [<member_id>, ...]
  scope_status: satisfied | contradicted | indeterminate
...all v0.2 decision fields...
```

- `observed_member_counts` 按 Arm id 顺序与 Decision 的 arm references 一一对应；
- `satisfied` 要求所有 Arm 的 scope status 均 satisfied、observed count 与
  population digest 全部一致，且 missing required targets 为空；
- Scope Assessment 必须从 Profile、Manifest 和 Arm Results 重算，调用者
  不能直接提交任意摘要；
- v0.3 AcceptanceTransition 只能引用同一 WorkOrder/SubjectClaim 下已经提交的
  v0.3 Decision digest；不新增验收状态。

## 9. 新增 Reason Codes 与决策语义

新增：

- `SCOPE_MANIFEST_INVALID`
- `SCOPE_MANIFEST_UNAVAILABLE`
- `SCOPE_EMPTY`
- `SCOPE_SELECTOR_MISMATCH`
- `SCOPE_REQUIRED_TARGET_MISSING`
- `SCOPE_WORKSPACE_DRIFT`
- `SCOPE_POPULATION_DRIFT`
- `SCOPE_EVIDENCE_MISSING`
- `SCOPE_CROSS_ARM_MISMATCH`
- `SCOPE_UNPROVEN`

决策表：

| 条件 | Decision | 说明 |
|---|---|---|
| Scope 全部满足，正臂通过，所有负臂被捕获，独立性满足 | `VERIFIED` | 仍然是有范围、有条件的结论 |
| 有效负臂 mutation 存活 | `REFUTED` | 有证据证明验证主张不成立 |
| Scope 为空、缺目标、漂移、证据不足或跨臂不一致 | `UNKNOWN` | 未证明主张错误，只证明当前验证不足 |
| Manifest 或 Scope Evidence 字节被篡改 | fail closed | 不形成有效 Decision |
| v0.2 Profile 被要求按 v0.3 规则验证 | `UNKNOWN` | 原对象无范围承诺，不做追溯性伪造 |

`VERIFIED` 的客户可见文案必须包含：

> 在 Scope Manifest `<digest>` 所列的 `<N>` 个对象、source revision
> `<revision>`、固定正负臂和已披露独立性条件下，当前主张获得 VERIFIED。

不得缩写为“Agent 输出可信”或“结果绝对正确”。

## 10. 数据流与事务

### 10.1 准备阶段

1. 从已签 SubjectClaim 读取 required artifacts、acceptance conditions 和
   excluded scope。
2. 在固定 source/candidate revision 运行允许的 Selector Rules。
3. 生成规范排序的成员列表和 population digest。
4. 校验必含目标、排除项、路径和大小限制。
5. 生成 Manager 待签的 Manifest draft，不写入权威账本。

### 10.2 提交阶段

1. 校验 Manager 授权、签名、nonce、期限和 WorkOrder 绑定。
2. 在同一 SQLite 事务写入 Manifest canonical bytes、digest 和对象索引。
3. Profile 提交只能引用已提交且 exact-match 的 Manifest。
4. COMMIT 应答丢失时，沿用 v0.2 canonical readback 语义确认提交真相。

### 10.3 执行阶段

1. 每个 Verifier 在自己的冻结执行上下文重新运行 Selector Rules。
2. 将完整 observed member evidence 写入受限 EvidenceRef。
3. 计算 observed population digest 和 required target coverage。
4. 形成签名 Arm Result；不允许 Executor 自报 Scope 代替 Verifier 重算。

### 10.4 决策与交付阶段

1. Decision composer 验证所有 Arm Result 绑定相同 Manifest。
2. Decision 根据第 9 节生成结论和 reason codes。
3. Delivery Package 收录 Manifest、selector specs、scope evidence、Profile、
   Arm Results、Decision 和 Acceptance。
4. `audit-replay` 离线重算 Manifest、observed scope 和 Decision。

## 11. Python API、CLI 与 MCP 边界

### 11.1 Python API

首版公开最小接口：

```python
build_evaluation_scope(...)
validate_evaluation_scope(...)
compare_observed_scope(...)
commit_evaluation_scope(...)
load_evaluation_scope(...)
```

每个函数只负责一个边界；不新增通用 Selector 插件框架。

### 11.2 CLI

```bash
owp scope-build --claim claim.json --source-revision <sha> --rules rules.json
owp scope-validate scope.json
owp scope-commit pilot.sqlite3 signed-scope.json
owp scope-compare scope.json observed-scope.json
```

- `scope-build` 默认只输出 draft 文件，不持有 Manager 私钥；
- 签名由现有安全边界或 Python API 完成；
- `scope-compare` 输出机器 JSON 和人类摘要；
- 非零退出码区分 invalid、unknown 和 contradicted，不把 UNKNOWN 写成成功。

### 11.3 MCP

本轮只增加只读/校验工具：

- `owp_scope_validate`
- `owp_scope_compare`

不通过 MCP 接收私钥，不提供自动签名或自动客户验收。

## 12. Scope Coverage Report

客户可读报告必须展示：

1. 工作主张和 source/candidate revision；
2. 选择规则及其固定版本；
3. 声明对象数与实际观察对象数；
4. 必含目标：已覆盖 / 缺失；
5. 排除项；
6. 正臂和负臂是否使用同一范围；
7. 当前 Decision 和 reason codes；
8. 结论适用边界；
9. 签名摘要和离线复核命令。

Level 1 报告必须注明“方案商内部主张，未绑定客户控制锚点”；只有 Level 2/3
同时存在客户控制的 CommitmentAnchor 和绑定 Acceptor 时，才能写“客户可
验收”。二者都不表示客户已经接受或付款。

报告不展示：

- “100% 正确”；
- “客户已付款”；
- “可以自动结算”；
- “符合所有监管要求”；
- 未经授权的私有路径、源码内容或客户身份。

## 13. 隐私视图

Delivery Package 延续现有 `private / diagnostic / public` 视图：

- `private`：包含完整 locator、selector spec 与成员证据，供客户审计；
- `diagnostic`：保留 locator 和 reason code，移除源码内容；
- `public`：只保留成员数量、population digest、必含目标数量和结论边界，
  不暴露私有路径或测试名称；该视图不提供成员级独立证明。

任何裁剪后的 public 包都必须保留原始 Manifest digest，且明确说明它不是
完整离线重放包。

## 14. 错误处理与恢复

- PREPARE 失败：权威表零写入；
- COMMIT 前故障：全表快照不变；
- COMMIT-ACK 丢失：canonical readback 能确认时报告 committed truth；
- readback 不确定：返回 indeterminate，不重试签署新对象；
- Selector 崩溃或超限：Arm Result 为 `indeterminate` +
  `SCOPE_UNPROVEN`；
- cleanup 失败：不得改写已确认的提交真相；
- 并发提交同一 `scope_id`：exact canonical bytes 幂等，不同 bytes 冲突；
- superseding scope：必须创建新 scope id 和新 Profile，不覆盖旧对象。

## 15. 测试与验收矩阵

### 15.1 模型与 Schema

- 所有字段、上限、排序、唯一性和 digest 重算；
- 无效 signer、角色、nonce、期限和 WorkOrder 绑定；
- 空成员、超过 4096 成员和超过 8 MiB；
- 路径逃逸、符号链接、大小写/Unicode 规范化冲突；
- v0.2 与 v0.3 schema registry 并存。

### 15.2 选择器

- explicit、git diff closure、pytest collection 的确定性；
- 选择器执行器 digest 漂移；
- source/candidate revision 漂移；
- 同一输入重复执行 population digest 一致；
- pytest node id 被遗漏时必然产生 UNKNOWN。

### 15.3 敌对案例

- 空集合伪装绿色；
- 必含文件缺失；
- 必含测试缺失；
- Manifest 声明 N、Evidence 只有 N-1；
- 正臂完整、负臂缩小；
- 重签合法但语义错误的 observed count；
- Manifest、selector spec、scope evidence 和账本行逐类篡改；
- public view 冒充完整包；
- 旧 v0.2 Decision 冒充 v0.3 Scope proof。

### 15.4 事务

- PREPARE 零写入；
- insert/state/COMMIT/COMMIT-ACK/readback/cleanup 故障注入；
- 并发提交恰一真相；
- committed truth 防重复写入。

### 15.5 真实演示

首个演示必须使用真实开源代码 Issue，但在 OpenWorkProof 仓库内准备自有
演示任务。演示至少包含：

1. 一个旧式检查得到绿色但遗漏必含测试的反例；
2. 同一任务在 v0.3 返回 `SCOPE_REQUIRED_TARGET_MISSING / UNKNOWN`；
3. 修复范围后，正臂通过且负臂被捕获；
4. 第三方离线重放得到同一 Scope 与 Decision；
5. 篡改任一成员或 scope evidence 后 fail closed。

不得把自有演示写成上游项目采用或客户案例。

## 16. 兼容与迁移

1. v0.2 schema、对象、历史账本和 Delivery Package 保持只读有效。
2. v0.3 使用新 schema version 和新 domain separation，不在 v0.2 payload
   追加字段。
3. v0.2 Profile 不能无证据升级；迁移必须重新生成 Scope、Profile、Arm
   Results 和 Decision。
4. Acceptance 可引用新的 v0.3 Decision，但不得把旧 Acceptance 静默重绑。
5. Rich #4196 与 Dify #33013 可在后续作为迁移示例，但不是首版发布硬门。

## 17. 分阶段交付

### Phase A：协议最小闭环

- Scope 模型、schema registry 和签名域；
- Profile/Arm Result/Decision v0.3 绑定；
- explicit selector；
- SQLite 原子提交与离线重放；
- 敌对案例：空集合、必含目标遗漏、跨臂不一致。

### Phase B：代码交付参考适配器

- git diff closure；
- pytest collection；
- Scope Coverage Report；
- CLI 和只读 MCP；
- 自有真实 Issue 演示。

### Phase C：21 天商业试点

- 真实 SOW 与客户验收条件；
- 客户控制的 CommitmentAnchor 和 Acceptor；
- 付费报价与定金证据；
- 补证轮次、验收周期、范围遗漏和验证成本记录。

Phase C 的客户、付款、定金和验收均默认为 `not evidenced`，只有外部材料
存在后才能更新。

## 18. 商业验证设计

### 18.1 User、payer 与购买结果

- User：Agent 方案商的交付负责人、QA 和项目经理；
- Payer 假设：Agent 方案商、AI 解决方案商或系统集成商；
- Customer Acceptor：最终客户的技术验收负责人；
- 购买结果：减少范围遗漏、反复补证、验收争议和回款不确定性；
- 当前替代：CI 日志、截图、人工代码审查、聊天确认和供应商信用。

### 18.2 最小现实实验

- Offer：21 天 Scope-Bound Agent 代码交付试点，交付 Scope Coverage
  Report、正负验证结果、客户验收包和离线复核命令；必须给出含金额与定金
  条款的正式报价，不做无边界免费试点；
- Target：5 家正在向企业交付 Agent/AI 软件项目的方案商或集成商；
- Real behavior：提供真实任务、指定真实 Acceptor、确认验收条件、签署 SOW
  并支付对应定金；
- Success threshold：至少 1 家签署付费 SOW 并支付定金，且至少发现或阻止
  1 个真实范围遗漏、补证问题或验收争议；
- Failure learning：若认可问题但不付费，修正付费方、报价或交付结果假设；
  若不提供真实任务，修正目标客户或信任机制假设；
- Money/labor cap：一个协议切片、一个真实项目、不超过 8 人日和 2,000 元
  外部成本；
- Deadline：正式报价发出后 21 天；
- Stop：5 家均拒绝真实任务，或只接受免费试用且不承担验收责任；
- Increase condition：付费 SOW、定金和真实客户验收三项同时出现后，才投入
  Guard Health Dashboard 或 PolicyAnchor 历史服务。

当前阶段保持 `需求验证`，裁决保持 `小额验证`。

## 19. 后续但不进入 v0.3 首版的需求

### 19.1 Semantic Safety Adapter

用于验证“文件内容是否满足任务”，但必须是显式领域适配器，不得把模型判断
伪装成协议真理。适配器输出进入 Evidence，不改变 OWP 对真理边界的声明。

### 19.2 Continuous Guard Health

记录 guard 的 `last_proven_at`、known-bad fixture、过期策略与连续负控结果。
只有真实试点证明客户愿为此付费后才产品化 Dashboard。

### 19.3 External Policy History

OWP 只保留 `PolicyAnchor` 消费接口。外部组件可以提供签名检查点、单调 revision
和分叉视图检测；OWP 不拥有其信任根或治理。

## 20. 发布与事实边界

发布 v0.3 前必须有：

- 新模型、Schema、事务和敌对测试全部通过；
- 便携与 required-live 门的 fresh 结果；
- 不覆盖历史库存的新 candidate inventory；
- 自有演示的完整离线包和篡改反例；
- README 中英文同步；
- 明确的 v0.2/v0.3 兼容说明。

即使全部技术门通过，也只能声称“本地/发布候选技术闭环”。不得据此声称：

- 客户采用；
- 真实付费；
- 客户验收；
- 付款或资金释放；
- 上游开源项目认可；
- MCP/A2A 官方采纳；
- 行业标准成立。

## 21. 规格验收标准

本规格进入实施计划的前提：

1. 用户书面确认本规格；
2. `EvaluationScopeManifest` 的 authority、成员模型和 exact-match 语义无歧义；
3. `UNKNOWN` 与 `REFUTED` 的 Scope 分界明确；
4. v0.2 兼容与迁移边界明确；
5. Phase A/B/C 不混合技术完成和商业完成；
6. 不存在未决占位标记或尚未裁决的产品范围。

用户确认后，下一步仅编写详细实施计划；实施计划获批以前不修改产品代码。
