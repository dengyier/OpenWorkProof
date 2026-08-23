# OpenWorkProof HumanAgencyProfile v0.1 设计规格

> 日期：2026-08-24
> 状态：待用户书面复核
> 工程基线：`main@5b7d9b5`
> 实施分支：`codex/human-agency-profile-v01`
> 产品边界：本切片是协议能力，不是 Agent OS、SaaS 控制台、交易平台、
> 资金托管、法律仲裁或空间智能系统

## 1. 决策摘要

OpenWorkProof 下一切片增加 **HumanAgencyProfile v0.1**，把一次 Agent 委托中
“人交出了什么执行权、保留了什么决定权、何时必须升级给人、如何撤销或申诉”
从隐含约定提升为机器可验证的签名协议对象。

当前 OWP 已能证明 WorkOrder、CapabilityGrant、PolicyDecision、ActionReceipt、
VerificationDecision 与 AcceptanceDecision 的授权、执行、验证和验收关系；但
WorkOrder 只冻结目标、范围、工具和验收条件，没有一个独立对象明确表达：

1. 哪些工具可以由 Agent 在授权范围内自主执行；
2. 哪些行动即使出现在 WorkOrder/Grant 中，仍保留给人作最终决定；
3. 出现何种条件时必须停止自主执行并升级；
4. 人如何撤销该委托，以及 Agent/Manager/Verifier 如何提出不产生自动授权的申诉。

本切片选择“**独立 Acceptor 签名的 sibling profile**”而不是修改冻结 WorkOrder：

```text
WorkOrder v0.1 (保持不变)
      ↓ exact digest binding
HumanAgencyProfileV01 (Acceptor 签名)
      ↓ policy intersection
CapabilityGrant ∩ WorkOrder ∩ Active Agency Profile
      ↓
AgentRequest → PolicyDecision → ActionReceipt
```

核心语义是：

> CapabilityGrant 表达“系统授予了什么能力”；HumanAgencyProfile 表达“人目前
> 愿意让 Agent 自主使用其中哪些能力”。有效权限取二者与 WorkOrder 的交集，
> 任一层不允许都必须 fail closed。

## 2. 设计依据

### 2.1 技术依据

1. `WorkOrder`、v0.1 schema 与 golden digest 已冻结，直接增字段会破坏兼容。
2. `CapabilityGrant` 已支持工具、读写路径、配额、有效期、衰减授权和撤销，但
   它表达的是能力边界，不表达人的保留决定权。
3. `ApprovalHumanDecision` 只覆盖既有高风险 PR proposal gate，不能被泛化为
   所有自主委托的默认真理源。
4. `AcceptanceTransitionReceipt` 与 `RetractionReceiptV05` 已证明“追加式、不可变、
   用新签名对象改变当前有效状态”的模式可行，应复用而非创建可变 profile。
5. OWP 现有 policy 是纯函数并采用 fail-closed，应在授权前增加 profile 交集，
   不能在执行后仅生成 advisory 报告。

### 2.2 商业依据

企业不会为“多一个签名模型”付费；可销售结果是：

- 在不逐步审批的前提下扩大 Agent 可自主完成的工作；
- 对发布、付款、最终验收、范围/标准变化等关键决定保持人类控制；
- 越界请求在执行前被阻止，并留下可复核拒绝原因；
- 委托关系可撤销、可申诉、可重新签署，而历史不被抹除。

对外产品仍是 Verified Agent Delivery。HumanAgencyProfile 是其底层协议能力，
不是新的独立 SaaS 产品。

## 3. 比较过的方案

### 方案 A：直接扩展 WorkOrder v0.1

优点：单对象、读取简单。

拒绝原因：破坏冻结 schema、签名字节和历史兼容；把“业务任务合同”和“当前自主
委托策略”锁成同一生命周期，任何人类授权变化都迫使重建 WorkOrder。

### 方案 B：Acceptor 签名的 sibling profile（选定）

优点：不修改历史对象；可独立撤销或替换；能与 Grant 做权限交集；可由离线验证器
单独重放；符合现有追加式协议模式。

代价：增加一个当前 profile 选择问题，必须用确定性 transition 链解决，不能信任
调用方传入的“active=true”。

### 方案 C：仅在交付目录或 Dashboard 中保存配置

优点：实现最快。

拒绝原因：配置不受签名与账本约束，只是 advisory；攻击者可删除或替换配置，
无法证明执行时生效的是哪一版委托边界。

## 4. 目标与非目标

### 4.1 必须实现

1. `HumanAgencyProfileV01`：四类已确认内容——`delegated_actions`、
   `reserved_decisions`、`escalation_conditions`、`revocation_and_appeal`。
2. `AgencyProfileTransitionV01`：Acceptor 对 profile 作 `revoked` 或 `superseded`
   追加式转换，不删除原 profile。
3. `AgencyAppealV01`：Manager、Developer 或 Verifier 可签署申诉；申诉只请求人类
   复核，不自动授予权限。
4. profile 必须由 WorkOrder 绑定的 Acceptor 签名；transition 也必须由同一
   Acceptor 权威域签名。
5. 自主工具调用的有效权限为 `WorkOrder ∩ Grant ∩ active profile`。
6. profile 保留的工具请求在执行前返回稳定拒绝码
   `AGENCY_HUMAN_DECISION_REQUIRED`，零 handler 调用、零 receipt 写入。
7. profile 被撤销、过期、不存在、分叉或无法确定当前版本时 fail closed。
8. 离线证据包能验证 profile、transition、appeal 与受约束 ActionReceipt 的绑定。
9. v0.1—v0.5 冻结 schema、签名字节和历史 fixture 不变。

### 4.2 明确不做

- 不实现通用策略语言、自然语言政策执行器或 LLM-as-policy；
- 不建设人工审批 Inbox、Web Dashboard 或 hosted control plane；
- 不新增支付、发布、邮件等外部副作用工具；
- 不证明人类判断正确，也不把 Acceptor 签名解释为法律同意；
- 不实现员工能动性评分、生产率排名或行为监控；
- 不实现机器人、传感器、视频、位置或物理世界证据；
- 不实现 Agent 商城、信誉市场、资金托管或自动结算；
- 不允许 appeal 自动覆盖 profile；只有 Acceptor 签署 transition 或新 profile
  才能改变有效授权。

## 5. 协议对象

### 5.1 `DelegatedActionV01`

```yaml
action_id: <sha256>
tool_name: owp.repo_read
autonomy: delegated
```

约束：

1. `tool_name` 必须存在于 WorkOrder `allowed_tools`；
2. `action_id` 使用 domain `openworkproof/delegated-action/v0.1` 对规范化内容重算；
3. 数组按 `tool_name` UTF-8 排序、唯一；
4. 本版只允许 exact tool name，不允许 glob、正则或自由文本谓词。

### 5.2 `ReservedDecisionV01`

```yaml
decision_id: <sha256>
decision_kind: scope_or_criteria_change
blocked_tools:
  - owp.apply_patch
required_role: Acceptor
```

`decision_kind` 为闭合枚举：

- `scope_or_criteria_change`
- `external_publication`
- `external_communication`
- `acceptance`
- `payment_or_settlement`

`decision_id` 使用 domain `openworkproof/reserved-decision/v0.1` 对
`decision_kind`、`blocked_tools` 与 `required_role` 的规范化 closed JSON 重算。

本版只有映射到当前 WorkOrder `allowed_tools` 的 `blocked_tools` 才参与运行时强制。
没有对应工具的决定（如外部付款）可以被 profile 声明并离线展示，但不得被宣传为
OWP 已拦截现实支付。`blocked_tools` 可以为空；非空时必须排序、唯一并且全部属于
WorkOrder `allowed_tools`。同一工具不得同时出现在 `delegated_actions` 和任何
`blocked_tools` 中。

### 5.3 `EscalationConditionV01`

```yaml
condition_code: reserved_decision_requested
```

闭合枚举：

- `reserved_decision_requested`
- `scope_change_requested`
- `evidence_incomplete`
- `verifier_conflict`
- `authorization_revoked`
- `deadline_or_quota_exceeded`

v0.1 只强制 `reserved_decision_requested` 与 `authorization_revoked`。其余条件进入
离线 profile 与后续集成接口，但在没有确定性观测输入前不得伪造自动升级。

### 5.4 `RevocationAndAppealPolicyV01`

```yaml
revocation_mode: acceptor_signed_transition
appeal_mode: signed_request_then_acceptor_decision
appeal_roles:
  - Developer
  - Manager
  - Verifier
```

字段值固定；`appeal_roles` 按上述顺序固定，防止调用方通过配置扩大申诉签名角色。

### 5.5 `HumanAgencyProfileV01`

```yaml
schema_version: openworkproof-human-agency-profile/0.1
profile_id: <sha256>
work_order_digest: <sha256>
delegated_actions: [DelegatedActionV01, ...]
reserved_decisions: [ReservedDecisionV01, ...]
escalation_conditions: [EscalationConditionV01, ...]
revocation_and_appeal: RevocationAndAppealPolicyV01
valid_from: 2026-08-24T00:00:00Z
expires_at: 2026-08-25T00:00:00Z
issued_at: 2026-08-24T00:00:00Z
nonce: <sha256>
signer_key_id: ed25519:<...>
signature_alg: Ed25519
signature: <base64url>
digest: <sha256>
```

不变量：

1. `profile_id` 使用 domain `openworkproof/human-agency-profile-id/v0.1`；
2. 签名 domain 为 `human-agency-profile`；
3. signer 必须唯一匹配 WorkOrder 中 `role=Acceptor` 的 key binding；
4. `issued_at <= valid_from < expires_at <= WorkOrder.deadline`；
5. 至少一个 delegated action 或 reserved decision；两者不能同时为空；
6. profile 只能收紧 WorkOrder，不得引入额外工具或扩权；
7. 规范字节、digest、签名、WorkOrder 绑定任一不匹配即拒绝。

### 5.6 `AgencyProfileTransitionV01`

```yaml
schema_version: openworkproof-agency-profile-transition/0.1
transition_id: <sha256>
work_order_digest: <sha256>
target_profile_id: <sha256>
target_profile_digest: <sha256>
transition: revoked | superseded
replacement_profile_id: <sha256> | null
replacement_profile_digest: <sha256> | null
reason_code: human_withdrawal | scope_changed | risk_changed | correction
transitioned_at: 2026-08-24T01:00:00Z
nonce: <sha256>
signer_key_id: ed25519:<...>
signature_alg: Ed25519
signature: <base64url>
digest: <sha256>
```

`superseded` 必须同时绑定 replacement id/digest；`revoked` 必须二者均为空。
transition signer 必须属于同一 WorkOrder 的 Acceptor 权威域。原 profile 永不修改。
`transition_id` 使用 domain `openworkproof/agency-profile-transition-id/v0.1`
重算，签名 domain 为 `agency-profile-transition`；`digest` 绑定除签名字段外的
完整规范载荷。

### 5.7 `AgencyAppealV01`

```yaml
schema_version: openworkproof-agency-appeal/0.1
appeal_id: <sha256>
work_order_digest: <sha256>
profile_id: <sha256>
profile_digest: <sha256>
appellant_role: Developer | Manager | Verifier
appellant_subject_id: <identifier>
requested_change_digest: <sha256>
reason_code: task_blocked | scope_mismatch | evidence_available | verifier_disagreement
created_at: 2026-08-24T01:05:00Z
nonce: <sha256>
signer_key_id: ed25519:<...>
signature_alg: Ed25519
signature: <base64url>
digest: <sha256>
```

Appeal 只证明“某角色提出了这一请求”。它不会改变 profile 状态，也不会让原本
被拒绝的工具调用变成允许。只有后续 Acceptor 签署新 profile 并以 transition
supersede 旧 profile，权限才发生变化。

`requested_change_digest` 是 appellant 提议的新 `delegated_actions`、
`reserved_decisions` 与理由说明组成的 closed JSON 的 JCS SHA-256；原始说明只进入
私有证据包，不进入协议真理。`appeal_id` 使用 domain
`openworkproof/agency-appeal-id/v0.1`，签名 domain 为 `agency-appeal`。
appellant key 必须唯一匹配 WorkOrder 中声明的 appellant role 与 subject。

## 6. 当前 profile 的确定性选择

对同一 WorkOrder：

1. 没有 profile：受保护的新入口返回 `AGENCY_PROFILE_REQUIRED`；旧 v0.1—v0.5
   API 保持原行为，避免静默改变兼容面；
2. 恰好一个有效、未过期、无 transition 的 genesis profile：它是 active；
3. revoked：无 active profile；受保护入口 fail closed；
4. superseded：沿 replacement 链找到唯一终点；
5. replacement 不存在、digest 不符、环、分叉、多个终点或时间倒置：
   `AGENCY_PROFILE_HISTORY_INVALID`；
6. profile 过期：`AGENCY_PROFILE_EXPIRED`；
7. active profile 与 request 的 WorkOrder 不同：`AGENCY_PROFILE_BINDING_INVALID`。

若同一 WorkOrder 出现两个未通过 transition 连接的 genesis profile，视为分叉并
返回 `AGENCY_PROFILE_HISTORY_INVALID`，不得按提交时间选择“最新”一份。

本版不根据文件名、提交顺序或调用方传入的布尔值选择当前 profile。

## 7. 授权与执行语义

新增 opt-in 授权入口：

```python
authorize_tool_call_with_agency_profile(
    context,
    profile_history,
    request,
    request_arguments,
    execution_facts=None,
) -> PolicyDecision
```

`profile_history` 是包含全部候选 profiles 与 transitions 的只读输入；调用方不得
直接指定某个 profile 为“当前版本”。该入口必须调用 §6 的确定性 resolver，只有
唯一 active profile 才能继续授权。

执行顺序固定：

1. 验证 WorkOrder、Grant、request、签名、freshness 与现有 policy；
2. 解析唯一 active profile；
3. 验证 profile 的 Acceptor 签名、有效期和 WorkOrder 绑定；
4. 若 tool 出现在 reserved `blocked_tools`，返回
   `AGENCY_HUMAN_DECISION_REQUIRED`；
5. 若 tool 不在 `delegated_actions`，返回 `AGENCY_ACTION_NOT_DELEGATED`；
6. 仅当三层均允许时返回 allow。

拒绝优先级必须稳定：坏签名/坏 WorkOrder/坏 Grant 等既有安全错误优先于 agency
策略错误，避免 profile 掩盖底层攻击；底层授权通过后才返回 agency-specific code。

首个执行适配只覆盖 `owp.repo_read`、`owp.apply_patch`、`owp.run_tests` 和
`owp.rollback_patch`。Manager direct tools、acceptance 事务和外部副作用工具不在
本切片中被重新实现。

## 8. 账本与离线验证

新增三组 append-only 表：

```text
human_agency_profiles_v01
agency_profile_transitions_v01
agency_appeals_v01
```

每组保存 id、digest、work_order_digest、规范 JSON、committed_at；transition 另存
target/replacement id，appeal 另存 profile id。全部表具备 BEFORE UPDATE/DELETE
不可变触发器。

提交事务遵循现有模式：

- pre-COMMIT 故障零写入；
- COMMIT-ACK 丢失后回读 committed truth；
- 同 id/digest 幂等；同 id 不同字节拒绝；
- 并发 profile/transition 提交不产生两个 active 终点；
- cleanup 失败不改变已提交事实。

离线 bundle 必须包含：WorkOrder、公钥绑定、profile、全部 transition、相关 appeal、
受 profile 约束的 request/decision/receipt。验证器重新计算当前 profile，不信任导出
时预写状态。

## 9. 首个端到端场景

固定同一 WorkOrder 与 Grant，使它们同时允许：

- `owp.repo_read`
- `owp.apply_patch`

Acceptor 签署 profile：

- `repo_read` 在 `delegated_actions`；
- `apply_patch` 位于 `scope_or_criteria_change.blocked_tools`；
- escalation 包含 `reserved_decision_requested`；
- revocation/appeal 使用固定模式。

必须证明：

1. Developer 调用 `repo_read`：三层授权全部允许，handler 执行并产生正常收据；
2. Developer 调用 `apply_patch`：底层 WorkOrder/Grant 本可允许，但 agency profile
   返回 `AGENCY_HUMAN_DECISION_REQUIRED`，handler 调用次数为 0，所有账本表快照
   不变；
3. Developer 可以签署 appeal，但重试 `apply_patch` 仍被拒绝；
4. Acceptor 签署 replacement profile 并 supersede 旧 profile 后，`apply_patch`
   才可进入既有执行路径；
5. Acceptor revoke replacement 后，受保护入口全部 fail closed。

## 10. 测试与验收标准

### 10.1 模型与签名

- closed JSON；未知字段、错误类型、超限数组、非规范时间拒绝；
- id/digest/domain/signature 逐项重算；
- Acceptor、Manager、Developer、Verifier 的角色绑定正负矩阵；
- delegated/reserved 重叠、WorkOrder 外工具、乱序/重复全部拒绝；
- `model_dump → mutate → model_validate` 敌对重建，不用 `model_copy` 绕过校验。

### 10.2 当前版本与 transition

- active/revoked/superseded 正常链；
- replacement 缺失、digest 替换、分叉、环、时间倒置、跨 WorkOrder 全部 fail closed；
- appeal 不改变 active profile；
- 非 Acceptor transition 零写入。

### 10.3 policy 与执行

- delegated allow；reserved deny；not-delegated deny；expired/revoked deny；
- 底层签名、Grant、freshness、quota 错误优先；
- 拒绝路径 handler 0 调用、receipt/evidence/publication 全表快照零写入；
- replacement 后才允许，revoke 后重新拒绝。

### 10.4 事务与离线包

- pre-COMMIT、COMMIT-ACK、并发、cleanup、不可变触发器；
- 独立临时目录、无网络、无活账本验证；
- 篡改 profile、transition、appeal、WorkOrder、公钥、关系任一项失败关闭。

### 10.5 兼容门

- v0.1—v0.5 frozen schema/golden bytes 不变；
- agency focused 套件零失败；
- 相关 policy/MCP/acceptance/retraction 回归零失败；
- candidate 两套件零失败；
- required-live 全量零失败、零 skip、严格 warning 门通过。

测试计数只在实际运行后写入 README/status，不在规格中预填。

## 11. 文件边界建议

为避免继续扩大 `models.py`、`policy.py` 和 `evidence.py`，本切片优先建立独立模块：

```text
src/openworkproof/agency.py
    # v0.1 models、id/digest、签名绑定、profile history resolver
src/openworkproof/agency_policy.py
    # WorkOrder ∩ Grant ∩ active profile 的 opt-in 纯授权入口
src/openworkproof/agency_ledger.py
    # 三类对象的 schema、append-only 提交与查询
src/openworkproof/agency_bundle.py
    # 离线导出/验证
src/openworkproof/schemas/agency-v0.1/
    # 三个 JSON Schema 与 registry
tests/test_agency_models_v01.py
tests/test_agency_policy_v01.py
tests/test_agency_ledger_v01.py
tests/test_agency_bundle_v01.py
tests/test_agency_end_to_end_v01.py
```

只在 `src/openworkproof/__init__.py`、必要的 MCP/CLI opt-in 入口、README 与
status 中做最小接线。不得借机重构历史协议模块。

## 12. 产品与商业影响边界

HumanAgencyProfile 让 OWP 从“证明 Agent 做过什么”进一步变成“证明人在委托后
仍保留了哪些决定权”。它支持的商业语言是：

> 放权不失控；Agent 在边界内自主执行，触碰保留决定时停止并升级给人。

但本次实现只证明协议可以表达并强制这一边界，不证明：

- 客户愿意付费；
- 企业扩大了委托比例；
- 人工复核时间下降；
- 真实外部发布或付款被拦截；
- 形成行业标准、Agent 市场或结算网络。

上述商业状态继续保持 `not_evidenced`，直到出现真实付款方、SOW、交付、客户
Acceptor 决定和外部结果证据。

## 13. 后续版本候选（不进入本计划）

1. `ClaimProvenance`：来源—说话人—主张—解释的语义归因；
2. 一次性 human override，而不是只能 supersede 整个 profile；
3. Dashboard/审批 Inbox 与可视化委托边界；
4. 多模态/传感器 `PhysicalEvidenceProfile`；
5. 跨平台 conformance 与认证；
6. WorkOrder 交易、争议和外部结算伙伴集成。

进入任何后续版本前，先验证 HumanAgencyProfile 是否减少人工逐项审批、扩大安全
委托范围或降低交付争议；不能仅因技术可行而自动扩展。
