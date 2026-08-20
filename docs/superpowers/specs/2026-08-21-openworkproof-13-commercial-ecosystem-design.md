# OpenWorkProof 1.3 商业入口与生态演示双层设计规格

> 日期：2026-08-21
> 状态：待用户书面审查
> 产品基线：OpenWorkProof 1.2.0
> 协议基线：v0.5（已冻结）；v0.6 divergence ledger 另案设计

## 1. 决策摘要

OpenWorkProof 1.3 采用“一套协议核心、两个产品表面”的路线：

1. **A｜商业入口**：GitHub Action、PR Check、HTML/JSON 验证报告，面向正在
   使用 Coding Agent 的研发团队，解决“这次 Agent 交付能否被复核和验收”。
2. **C｜生态演示**：AgentTeams + MCP 三 Agent 真实调度，展示 Manager、
   Developer、Verifier 在同一工作契约和证据包上的协作闭环。
3. 两者必须调用同一 OpenWorkProof Core、生成同一种可离线验证证据包；不得
   发展成两套协议、两套状态机或两套真相来源。

商业排序为 **A 先、C 后**：A 负责形成首个可付费试点入口，C 负责比赛演示、
开发者传播与生态扩展。C 不能反向拖延 A 的交付。

## 2. 问题与用户价值

MCP 解决 Agent 与工具的互操作，A2A 解决 Agent 与 Agent 的互操作；GitHub
Agent 工作流解决 Agent 如何进入仓库、Issue 与 PR。但这些基础设施并不自动
回答以下交付问题：

- 谁授权 Agent 执行这项工作；
- Agent 实际调用了什么工具、修改了什么对象；
- 测试是否在声明的环境中真实执行；
- 两个独立验证者是否得到一致结果；
- 验收人能否在不信任运行平台的情况下离线复核证据。

OpenWorkProof 1.3 的产品承诺限定为：**把一次 Coding Agent 交付转换成可离线
复核的授权、执行、验证与验收证据包，并把结果直接呈现在 PR/CI 工作流中。**

本版本不承诺证明 Agent 的所有语义判断正确，也不承诺替代合同、付款、保险、
法律审计或人工验收。

## 3. 目标与验收结果

### 3.1 产品目标

1. 仓库维护者可通过一个 GitHub Action 对 Agent PR 运行 OpenWorkProof 验证。
2. PR 页面可见明确的 `VERIFIED`、`REFUTED` 或 `UNKNOWN`，且不得把
   `UNKNOWN` 显示为成功。
3. 每次运行产出机器可读 JSON、面向人的 HTML 报告和可下载证据包。
4. 第三方仅凭证据包与公开密钥即可离线重放，不依赖 GitHub、AgentTeams 或
   OpenWorkProof 托管服务。
5. AgentTeams 演示至少包含 Manager、Developer、Verifier 三个 Agent，并与
   GitHub 入口复用同一证据结构和离线验证器。

### 3.2 商业验证目标

本版本服务于需求验证阶段，不以平台收入叙事替代事实：

- 目标用户：5–50 人、已在真实仓库使用 Coding Agent 的研发团队；
- 首个产品化服务：21 天“Agent PR 可验证交付”付费试点；
- 30 天验证门：3 个真实仓库安装、1 个付费试点；
- 未取得真实订单前，付费主体、价格和续费均标记为假设，不写成已验证收入。

### 3.3 工程验收目标

- 既有 v0.1–v0.5 schema、golden bytes 和历史证据包不变；
- GitHub 与 AgentTeams 入口对同一规范化输入产生相同核心摘要；
- 所有拒绝路径有闭合 reason code，并生成可审计结果；
- 发布门包含单元、集成、离线重放、GitHub fixture 和三 Agent 端到端测试；
- README、状态文档、PyPI、GitHub Release 与 MCP Registry 的版本事实一致。

## 4. 非目标

OpenWorkProof 1.3 明确不实现：

- 正式 A2A 协议适配；
- 多租户托管平台、企业仪表盘或计费系统；
- 支付、托管交易或自动结算；
- GitLab、Bitbucket 等第二代码托管平台；
- 区块链锚定；
- 动态第三验证者仲裁；
- v0.6 `DUAL_VERIFIER_DIVERGENCE` 正式入账；
- 对任意 Agent 框架的全量兼容。

## 5. 设计原则

1. **协议中立**：核心对象不得以 GitHub PR number、GitHub run id、Matrix
   event id 等平台字段作为必填协议语义。
2. **一个真相源**：HTML、PR Check 和聊天消息都是离线重放结果的视图，不得
   自行创造新结论。
3. **失败闭合**：缺证据、环境不完整、签名错误和验证者分歧必须 fail closed。
4. **可移植证据**：证据包离开 GitHub/AgentTeams 后仍可验证。
5. **采集不等于证明**：环境指纹证明“签名采集者对这些字段作出声明”；只有
   接入平台证明或硬件证明时，才能提升字段的证据等级。
6. **先验证付费，再平台化**：不为假想客户提前建设控制台、账户和计费系统。

## 6. 总体架构

```text
                     OpenWorkProof Core
      WorkOrder / PolicyDecision / ActionReceipt / Scope
       Environment Evidence / Verification / Acceptance
             Evidence Bundle / Offline Replay / CLI
                      /                 \
                     /                   \
      A. GitHub Commercial Surface      C. Ecosystem Demo Surface
      Action / PR Check / Report        AgentTeams / MCP / 3 Agents
                     \                   /
                      \                 /
                 Same canonical evidence bundle
```

Core 负责规范化、摘要、签名、状态机、事务提交和离线重放。适配层只负责：

- 把平台输入投影为核心可验证输入；
- 调用核心 API；
- 把核心结果渲染回平台；
- 保存平台来源信息，但不改变核心判定。

## 7. 核心数据设计

### 7.1 冻结面与新增文档域

1. v0.1–v0.5 的 schema、签名字节和历史模型保持冻结。
2. 1.3 新增两个伴随证据文档域，不伪装为 v0.6 决策模型：
   - `openworkproof-execution-environment/0.1`
   - `openworkproof-verification-report/0.1`
3. 文档域分别独立注册 schema 与 canonical digest；不得修改既有 v0.5
   registry 条目的摘要。
4. 产品版本发布为 `1.3.0`；协议对象版本与产品包版本分别展示。

### 7.2 `ExecutionEnvironmentFingerprintV01`

环境指纹是 canonical evidence document，核心字段为：

```text
protocol_version
source_revision
runner_os
runner_arch
runner_image_digest
container_image_digest
toolchain_lock_digest
command_digest
arguments_digest
environment_allowlist_digest
sandbox_policy_digest
workflow_identity_digest
collection_status
missing_reason_codes
collected_at
collector_actor_id
collector_key_id
signature
```

约束：

- 摘要字段必须为闭合格式，禁止任意字符串替代；
- `collection_status` 仅允许 `complete`、`partial`、`unavailable`；
- `partial`/`unavailable` 必须带闭合 `missing_reason_codes`；
- 环境变量不得原样写入，只能对显式 allowlist 的规范化投影求摘要；
- secret、token、完整系统环境和未授权路径不得进入报告或证据包；
- GitHub/AgentTeams 平台字段放在各自 adapter source document 中，再投影到
  上述中立字段；核心对象不直接依赖平台字段。

签名字节只覆盖不含 `signature` 的 canonical payload，避免自引用；验证时必须
按该文档域的固定签名版本重建字节，不能使用调用方提供的任意序列化结果。

默认决策规则：high-risk 验证要求两个独立 Verifier 分别提交 `complete` 环境
指纹；standard 验证若出现 `partial`/`unavailable`，除非已签 Scope 明确允许
对应缺失原因，否则结果只能是 `UNKNOWN`，不得降级为 `VERIFIED`。

Verifier 的信任链为 WorkOrder → WorkOrder Manager 签署的 VerificationProfile
→ Profile 中的 Verifier binding。WorkOrder 保持固定六角色与单 Verifier 角色，
high-risk 所需的第二个独立 Verifier 由同一 WorkOrder 下已签 Profile 显式委托，
不得由调用方元数据或未签配置补充。环境指纹的 `collector_key_id` 与
`collector_actor_id` 必须同时匹配该 Profile binding，不能只验证公钥而忽略主体。

首版缺失原因至少覆盖：runner image 不可得、container digest 不可得、toolchain
lock 不可得、sandbox policy 不可得、workflow identity 不可验证。未知原因不得
落成 `complete`。

### 7.3 `VerificationReportV01`

报告是离线重放的确定性派生视图，不是新的授权或验收真相。核心字段为：

```text
bundle_digest
replay_result_digest
decision_status          # VERIFIED / REFUTED / UNKNOWN
reason_codes
work_order_digest
source_revision
environment_fingerprint_digests
verification_decision_digests
acceptance_receipt_digest
evidence_closed_at
renderer_version
```

同一证据包、同一 renderer 版本必须得到同一 `replay_result_digest` 和业务内容；
`evidence_closed_at` 来自包内已提交终态而非渲染墙钟，因此重渲染不引入随机
字段。HTML 的样式差异不得改变协议判定。若报告与离线重放不一致，报告验证
失败。

### 7.4 退出码

CLI 与 GitHub Action 统一使用：

| 退出码 | 含义 | GitHub Check |
|---:|---|---|
| 0 | `VERIFIED` | success |
| 2 | `REFUTED` | failure |
| 3 | `UNKNOWN` | failure，显示证据不足或分歧 |
| 4 | 输入无效、包损坏或运行故障 | failure，显示 operational error |

任何非零结果都不得被 wrapper 吞掉或改写为成功。

## 8. A：GitHub 商业入口

### 8.1 用户入口

首版提供：

1. 可复用 GitHub Action；
2. PR Check 与 Job Summary；
3. `openworkproof-report.html`；
4. `openworkproof-report.json`；
5. `openworkproof-evidence-bundle.tar.gz`；
6. 可复制的本地离线验证命令。

### 8.2 输入

- repository 与 source revision；
- WorkOrder/Scope/Policy inputs；
- 被允许的测试命令和资源约束；
- 验证者公钥或受支持的 key binding；
- GitHub workflow identity 的规范化投影；
- 可选第二验证环境配置。

Action 不接受任意 shell 文本作为未审查的协议字段。命令必须来自已签工作契约
或受支持配置，并在现有限界执行器中运行。

### 8.3 输出页面的非技术表达

PR Check 首屏只回答四个问题：

1. 谁授权；
2. Agent 做了什么；
3. 谁验证、是否独立收敛；
4. 当前能否验收。

底层 digest、签名和 schema 进入“技术证据”折叠区。报告不得用“绝对安全”、
“保证正确”或“完成结算”等越界措辞。

## 9. C：AgentTeams/MCP 生态演示

### 9.1 最小角色

- Manager Agent：签发/选择 WorkOrder，派发任务；
- Developer Agent：通过受限 MCP 工具读仓库、修改、运行测试；
- Verifier Agent：在独立上下文验证执行与结果；
- 人类 Acceptor：查看同一报告并作最终验收。

比赛演示至少出现三个 Agent 的真实身份、消息和因果链接，不用同一 Agent
换名字模拟多角色。

### 9.2 演示闭环

```text
真实 Issue/任务
  -> Manager 授权并派发
  -> Developer 执行并产生 ActionReceipts
  -> Verifier 独立重跑
  -> 若 REFUTED/UNKNOWN：返回 Developer 返工
  -> 再验证
  -> 生成与 GitHub 入口相同格式的证据包和报告
  -> 人类 Acceptor 验收
  -> 第三方离线重放
```

AgentTeams room event id、Matrix sender 等仅作为 adapter provenance；证据链仍以
OpenWorkProof canonical ids、签名和 digest 为权威。

## 10. A 与 C 的复用边界

必须复用：

- Core models、schema registry、canonicalization 与 signing；
- WorkOrder/Policy/Receipt/Verification/Acceptance 状态机；
- 环境指纹文档与报告 renderer；
- 证据包格式、离线验证器、退出码与 reason codes；
- conformance fixtures 与攻击测试。

允许不同：

- 平台事件采集器；
- UI 展示；
- 身份来源到 OpenWorkProof key binding 的映射；
- workflow/room provenance 文档；
- 启动命令和部署方式。

禁止：GitHub adapter 和 AgentTeams adapter 各自实现一套验收逻辑，或在平台
消息中声明与核心离线重放不同的结果。

## 11. 安全与失败处理

### 11.1 信任边界

- GitHub OIDC、workflow metadata 或 AgentTeams sender 只在经过显式验证与
  key binding 后成为身份证据；用户名本身不是授权。
- 环境指纹的签名只证明采集者声明，除非字段绑定平台 attestation，否则不得
  称为硬件级证明。
- HTML 不作为验证输入；验证器只读取 canonical JSON 与签名对象。
- 所有 artifact 路径、archive entry、URL 和 ref 必须做 traversal、大小和数量
  上限校验。

### 11.2 失败矩阵

至少覆盖：

- 签名错误、key binding 错误、授权过期、nonce 重放；
- source revision 与 PR head 漂移；
- 环境指纹缺失、部分缺失、伪造或与报告引用不一致；
- 双验证者结果分歧；
- 证据包字段、父链、报告或 artifact 被篡改；
- COMMIT 已发生但 ACK 丢失；
- 并发重复执行与 supersession；
- GitHub API 不可用但本地证据已提交；
- AgentTeams 消息成功但核心提交失败，或核心提交成功但消息 ACK 丢失。

原则是先确定核心账本真相，再决定平台重试；平台显示不得覆盖已提交真相。

## 12. 测试策略

### 12.1 Core

- 新文档模型的边界、canonical bytes、签名与 schema parity；
- v0.1–v0.5 frozen hash/golden bytes 不变；
- 环境指纹 complete/partial/unavailable 的闭合组合；
- 报告由离线重放确定性生成；
- 三态退出码和 reason code 映射。

### 12.2 GitHub

- 使用固定 GitHub event/workflow fixture，不依赖真实 PR 才能测试；
- source revision 漂移、fork PR、权限不足、artifact 上传失败；
- PR Check、JSON、HTML、证据包引用同一 bundle digest；
- 本地 runner 与 GitHub-hosted runner 至少各一个集成路径。

### 12.3 AgentTeams/MCP

- 三个真实身份与不同 key binding；
- Manager -> Developer -> Verifier 的因果父链；
- 失败 -> 返工 -> 再验证 -> 验收；
- room 消息丢失/重复不改变核心账本；
- 与 GitHub surface 的 shared-bundle conformance test。

### 12.4 发布门

发布前必须运行 focused、frozen compatibility、schema generation/parity、portable
full suite、candidate supply-chain 和 required-live 门；计划中记录实际命令、
退出码、passed/failed/skipped/warnings，禁止只写历史计数。

## 13. 实施切片与依赖顺序

### P0｜事实与发布卫生

- 同步 README、README_en、docs/status 的 1.2.0 当前事实；
- 修正 MCP Registry 与当前发布版本差异；
- 增加基础 CI；
- 清理或更新已被实现覆盖的公开 issue。

### P1｜共享 Core

- 环境指纹 canonical evidence document；
- 确定性 VerificationReport renderer；
- 三态 CLI 退出码；
- conformance fixtures 与攻击测试。

### P2｜GitHub 商业入口

- GitHub Action、PR Check、artifact bundle、HTML/JSON 报告；
- 示例仓库和安装文档；
- 21 天试点交付清单与人工 Acceptor SOP。

### P3｜AgentTeams/MCP 生态演示

- 三 Agent adapter 与真实调度脚本；
- 失败/返工/复验/验收演示；
- 录屏脚本与证据包离线复核演示。

P3 不得阻塞 P2。只有 P1 的 shared conformance contract 稳定后，P2/P3 才能
分别接入。

## 14. 开源与商业边界

### 14.1 开源层

- 协议 schema、SDK/CLI、离线验证器；
- 基础 GitHub Action、MCP Server、AgentTeams adapter；
- 示例、conformance kit 和验证报告基础 renderer；
- 本地单组织部署能力。

### 14.2 待验证的商业层

以下仅为产品假设，未获订单前不得称为已有能力或收入：

- 托管验证运行与长期证据保留；
- 企业策略包、SSO/RBAC/KMS；
- 私有部署、审计报告模板和合规导出；
- 自定义 Verifier、企业连接器、SLA 与支持。

付费主体假设优先级：AI/Coding Agent 方案商，其次为使用 Agent 的研发团队和
系统集成商。购买理由假设是降低验收成本、责任不清和企业准入风险；必须通过
真实访谈、安装和付费试点验证。

## 15. 完成定义

OpenWorkProof 1.3 只有同时满足以下条件才可宣称工程完成：

1. GitHub Action 对 fixture PR 生成三态 Check、HTML/JSON 与证据包；
2. 证据包在隔离环境中离线验证通过，篡改后 fail closed；
3. AgentTeams 三 Agent 使用同一 Core 完成至少一次真实失败返工闭环；
4. 两个 surface 通过 shared-bundle conformance test；
5. 既有冻结协议与历史包兼容门全绿；
6. required-live 全量门取得新鲜的零失败结果；
7. 文档和所有公开分发版本事实一致。

商业完成另设证据门：真实安装、客户访谈、付费 SOW、付款与续费不能由工程
完成推导。未发生时继续标记 `not_evidenced`。

## 16. 后续但不进入 1.3

- v0.6 正式 divergence ledger，使双验证者不一致以 `UNKNOWN` 可审计入账；
- 正式 A2A adapter；
- GitLab/Bitbucket surface；
- hosted multi-tenant control plane；
- 计费、结算与风险定价；
- 第三验证者仲裁和跨组织治理。
