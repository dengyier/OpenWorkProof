OpenWorkProof
=============

Agent 工作契约与可验证执行协议
Agent Work Contracts and Verifiable Execution Protocol

项目地址：https://github.com/dengyier/OpenWorkProof
当前版本：0.1.0（开发中）


一、项目是什么
------------

OpenWorkProof 是面向多 Agent 协作的开放工作契约与可验证执行协议。

它不试图让 Agent 变得更聪明，而是补足 Agent 进入真实社会协作所需要的
责任基础设施：

- 开始工作前，明确谁授权、允许做什么、可以访问哪些资源；
- 执行过程中，把权限、配额、状态变化和证据绑定到同一条可验证历史；
- 工作结束后，用预先约定的验收条件判断结果能否交付；
- 跨组织协作时，让第三方能够离线复核授权、执行和验收事实。

反共识判断：

未来多 Agent 系统的主要瓶颈，不只是模型能力，而是责任、授权、证据和
验收机制。没有这些机制，Agent 可以生成结果，却很难成为可委托、
可追责、可结算的生产主体。


二、OpenWorkProof 解决的断层
--------------------------

现有 Agent 框架通常擅长任务分解、消息传递和工具调用，但仍难以统一回答：

1. 这项工作依据什么授权？
2. 子 Agent 获得的能力是否只能缩减，不能自行扩权？
3. 一次工具调用是否真的在授权范围和配额之内？
4. 测试、补丁和报告之间是否形成完整因果链？
5. 哪些证据足以证明工作已经完成？
6. 谁能够作出最终接受或拒绝决定？

MCP 连接 Agent 与工具，A2A 连接 Agent 与 Agent，AgentTeams 组织 Agent
协作；OpenWorkProof 补充“依据什么授权工作，以及凭什么接受结果”。


三、四类核心协议对象
------------------

1. WorkOrder

   工作契约。冻结目标、代码来源、允许路径、工具、配额、测试方式、
   证据要求、截止时间、验收条件和参与者身份。

2. CapabilityGrant

   能力授权。把 Agent 可以执行的工具、读写根目录、配额、有效期和
   是否允许继续委托，约束为可签名、可衰减的授权对象。

3. ActionReceipt

   行动凭证。记录一次授权判断、执行结果、配额变化、状态迁移、
   因果父节点和证据引用，并由 Sidecar 绑定到不可重排的历史。

4. AcceptanceReceipt

   验收凭证。把最终结果、证据覆盖、独立性披露、全局后置条件和
   人类接受决定绑定在一起。


四、技术原则
------------

- Proof-Carrying Work：
  动作必须携带机器可检查的授权和结果证据。

- No-Cloning Authority：
  子授权只能衰减或消费，不能复制出等价或更大的权限。

- Multi-Scale Proof Composition：
  局部凭证只有在因果完整、证据维度覆盖、相关性披露和全局条件同时
  满足时，才能组合成可接受的整体证明。

- Fail Closed：
  无法验证的权限、签名、历史、状态或证据一律不能被解释为成功。


五、当前已经实现的能力
--------------------

当前公开 main 分支已经实现并验证：

- WorkOrder、CapabilityGrant、ActionReceipt 和 AcceptanceReceipt 模型；
- RFC 8785 JCS 规范化、Ed25519 签名和域分离摘要；
- 五角色身份绑定、Agent/Human 嵌套签名和 Sidecar 回执；
- 状态机、谓词注册表和严格 JSON/字节边界；
- 四类协议对象的 JSON Schema 和注册表；
- 确定性源码工件、受限补丁、WorkspaceManifest 和离线重放；
- SQLite 权威账本初始化和唯一 Root Grant 激活；
- child Grant 原子签发、永久 ID 预留、policy-deny 审计历史；
- child Grant 原子撤销、签名历史回放和 duplicate nonce 防重；
- Receipt、Grant、attempt、reservation、event、state 和 version 闭包；
- 300 秒历史时钟重放、61 条常规 Receipt 容量门；
- 并发确认快照、提交事实分类、成功发行唯一性和并发撤销单胜。
- 从签名 Receipt 重放 Grant 余额、single-use 次数和撤销状态；
- parent 直接计费与 child 额度预留合并计算，child 消费不重复扣减
  parent；
- deny 零计费、失败但已启动的工具/回滚计费，以及 direct-call
  角色交集。
- Manager-only `owp.start_retry` 原子消费固定 `repair_rounds=1`，
  并完成 `needs_rework → retrying`；
- 从已提交的 PatchResultEvidence、Verifier 失败和成功回滚重建当前
  rework episode，拒绝错误槽位、篡改字节和证据命名空间置换；
- `STATE_DENIED`、`ROLE_DENIED`、`CAPABILITY_DENIED` 和
  `QUOTA_EXHAUSTED` 的 start-retry 闭合顺序、零计费审计及并发单胜。
- group-aware 证据 staging、POSIX no-replace 发布、整组提交标记、
  崩溃恢复和已提交证据读取门；
- 证据 authority/journal 精确覆盖、固定 publication ID、锚定目录
  描述符和提交前后命名根身份校验；
- SQLite 提交事实三态、COMMIT-ACK 不确定性分类，以及锁、连接和
  文件描述符的独立清理故障上报。
- `commit_receipt_with_publications` Phase 2 原子提交原语：在同一
  `BEGIN IMMEDIATE` 中写入 signed ToolCall Receipt、父边、配额事件、
  `COMMITTING` publication journal、状态版本和全局序号；
- 从当前 ledger、Grant、请求参数、pending evidence 和 Sidecar 提供的
  trusted ResolutionManifest 重算谓词事实；支持成功与已启动但失败的
  `apply_patch` 收据，并对成功结果追加 PatchResult 交叉校验；
- pending 文件名/打开 inode、evidence root 和 ledger 命名身份的
  多阶段锚定，以及 SQLite 清理后的最终文件门和权威账本复核。
- `complete_receipt_publication` Phase 1→4 协调器：在同一目标锁下依次
  完成 pending staging、Receipt/journal 原子提交、no-replace 发布和
  整组 `COMMITTED` 标记；返回前再次重放完整账本、核对配额事件并
  重哈希最终证据；
- Phase 2 提交真值未知时停止后续发布；Receipt 已提交后的发布、
  标记、最终读取门或锁清理故障统一保留为需恢复的 committed truth。
- `validate_grant_chain` 五输入离线验证器：对 Grant、拒绝尝试、
  ActionReceipt 和五个 WorkOrder 绑定公钥执行有界单次快照，重建
  确定性索引，并验证完整签名授权历史；
- 独立的因果回放层：重建每条 Receipt 当时可见的不可变因果快照，
  校验唯一 genesis、精确父集、active patch、rework/rollback、
  approval、composition/recomposition 和 independent-result episode；
- 独立的策略回放层：重算 Grant 衰减、余额、撤销、single-use、
  角色/能力/审批/谓词/配额拒绝优先级，以及 Sidecar 签名的
  ResolutionManifest 解析断言；
- evidence-incomplete 独立验证的新执行上下文、失败封存、
  compose previous-report 绑定、审批有效期上限和 proactive rollback
  拒绝审计均已进入真实签名回归。
- Task 8A `derive_authorization_context` 纯函数：冻结 WorkOrder、规范化
  Grant/Receipt 前缀、可信 UTC 事务秒、逐字节 committed evidence 与
  ReplayCheckpoint，复用既有因果/策略 reducer 推导一次实时决策所需的
  不可变上下文；它不执行工具，也不写入账本。
- Task 8B1 `authorize_tool_call` 纯函数：对签名 AgentRequest、
  精确类型化参数和 Sidecar 分配的测试执行事实进行事前授权；
  按固定顺序检查状态、角色、Grant 能力、人工批准、静态谓词和
  配额，仅返回 `PolicyDecision`，不启动 handler、不扣减配额、
  不签发 Receipt，也不写入账本。
- Task 8B2 `validate_human_decision` 纯函数：验证 HumanDecision 的
  WorkOrder、签名人与角色、300 秒摄入窗口；审批必须精确绑定一张
  尚未决策的高风险请求及其 scope、digest 和 expiry，终止决策无需
  预先请求；仅返回 `PolicyDecision`，不签发 Receipt、不改变状态。
- Task 8B3 `validate_rollback` 纯函数：验证 Developer rollback 请求的
  WorkOrder、Grant、签名和 300 秒新鲜度，绑定当前 active patch 的
  receipt/digest 与 ReplayCheckpoint HEAD；仅开放尚未完成 rollback 的
  needs-rework failure episode，并执行角色、能力和 tool_calls 配额判定。
- Task 13 首个 `owp.run_tests` 可信协调切片：在同一目标锁下
  重放当前授权上下文，事前检查证据槽位与成功/失败 Receipt
  形态，通过内部 `handler_executions` journal 持久化
  `RESERVED → STARTED_UNCONFIRMED` 启动边界，然后仅启动一次
  可信 handler；正常结果进入
  stage→commit→publish→mark committed，handler 异常则提交
  已扣费、无证据附件的 `allow/failed + HANDLER_ERROR` Receipt。

当前验证快照：

- Policy 专项：101 passed；
- Policy、Composition 与 Receipt-chain 专项：540 passed；
- Receipt-chain 专项：407 passed；
- 全量测试：1247 passed；
- 独立规格复核：7B4_SPEC_PASS；
- 独立质量复核：7B4_QUALITY_PASS；
- pip check、compileall 和 git diff check：通过。

重要边界：

上述 Task 7B3a、7B3b Phase 2、7B3c 协调器和 Task 7B4 离线授权链
验证稳定切片已经完成本地实现与独立复核。Task 8A 已新增实时授权
上下文的纯推导与证据/检查点绑定；Task 8B1 已新增纯事前
工具授权；Task 8B2 已新增纯 HumanDecision 授权；Task 8B3 已新增
纯 rollback 事前授权。Task 8A/8B1/8B2/8B3 均尚未进行独立
Acceptor 复核。
当前实现包含
`stage_pending_evidence_group`、`publish_group_no_replace`、
`mark_publication_group_committed`、`recover_evidence_publications`
和 `require_all_publications_committed` 五个 group-aware 基础原语，
`commit_receipt_with_publications` 的 Phase 2 提交原语，以及串联
Phase 1→4 和最终权威读取门的 `complete_receipt_publication`。
`validate_grant_chain` 可以验证签名授权链和 Sidecar 签名的
ResolutionManifest 解析断言，但五输入 API 没有独立读取并重哈希
ResolutionManifest 原始字节。
当前只接入了 `owp.run_tests(test_mode=verifier)` 的首个可调用
handler 协调切片，还没有 MCP 传输服务器、Docker 测试执行器或
Developer mode 生产入口。当前目标锁与内部 journal 能区分：
只有 `RESERVED` 的崩溃可清理并安全重试；Receipt 已提交但 journal
未清理时可按已提交事实收敛；`STARTED_UNCONFIRMED` 且无 Receipt
时只返回 `RECOVERY_REQUIRED`，不重跑、不补造 Receipt 或扣费事实。
从旧开发快照打开的 ledger 会在目标锁内仅新增这张内部表，
不改变 Receipt、sequence、配额、协议状态或状态版本。
要自动收敛该不确定分支，仍需真实无网执行器提供稳定
execution ID 和可验证启动/结果回执。deny Receipt、rollback 和 Acceptance
生产事务也尚未完成。Task 7 与完整 Task 9 仍未完成，Day 0
执行门仍为 FAIL。


六、快速开始
------------

环境要求：

- Python 3.12；
- Git；
- macOS 或 Linux。

获取代码：

    git clone https://github.com/dengyier/OpenWorkProof.git
    cd OpenWorkProof

创建环境并安装锁定依赖：

    python3.12 -m venv .venv
    ./.venv/bin/python -m pip install -r requirements-lock.txt

运行当前公开快照的测试：

    ./.venv/bin/python -m pytest -q

说明：

- 当前开发快照包含 Task 8A 实时授权上下文、Task 8B1 纯事前
  工具授权、Task 8B2 纯 HumanDecision 授权、Task 8B3 纯 rollback
  事前授权和 Task 13 首个 Verifier `run_tests` 协调切片，fresh
  全量验证为 1247 passed；
- pyproject.toml 已预留 owp 命令入口，但 CLI 模块尚未完成，因此本文件
  暂不提供 CLI 使用命令；
- 不应把测试通过理解为 Day 0、独立验收或赛事提交已经完成。


七、真实开源 Issue 演示方向
------------------------

首个规划演示使用 Textualize/Rich 的真实 GitHub Issue #4196，并固定到
上游提交：

    9d8f9a372cc5916fd4781fec207ced7ddac2f08f

演示目标是在 OpenWorkProof 仓库内准备自有任务封装，使用固定的真实
上游源码、测试和许可证信息，展示：

- Manager 如何签发最小权限；
- Developer 如何在受限工作区修改代码；
- 越权路径如何在执行前被拒绝；
- Verifier 如何运行固定测试并形成独立证据；
- 局部测试通过为何不自动等于最终接受；
- Acceptor 如何基于完整证据作出人工验收。

该演示目前是冻结设计目标，尚未完成，不应描述为已经可运行的 Demo。
Rich 及其源码仍归属于原权利人；OpenWorkProof 只拥有自有协议和任务封装。


八、当前状态与边界
----------------

已完成：

- 项目方向与初赛方案设计；
- 协议模型、签名、状态、谓词和 Schema；
- Task 6A 确定性源码、补丁和重放原语；
- Task 7B2a 账本初始化、Root/child Grant 签发与 child Grant 撤销切片；
- Task 7B2b 签名历史额度、single-use、撤销和角色语义回放切片；
- Task 7B2c Manager `start_retry` 原子消费、rework episode 与 committed
  evidence 读取门；
- Task 7B3a group-aware staging、no-replace publication、整组提交、
  崩溃恢复和 committed publication gate；
- Task 7B3a 独立规格和质量复核。
- Task 7B3b Phase 2 Receipt/quota/state/sequence 与 COMMITTING journal
  原子提交，以及权威谓词、文件身份和 commit-truth 复核；
- Task 7B3b 独立规格和质量复核。
- Task 7B3c 单锁串联 stage、commit、publish、mark committed 和最终
  权威读取门，并保留各故障阶段的 receipt/publication 真值；
- Task 7B3c 独立规格和质量复核。
- Task 7B4 将授权因果回放与策略回放拆为单一职责模块，使
  `validate_grant_chain` 成为有界五输入编排器，并完成合法重组链、
  拒绝审计、独立验证新鲜性与失败封存的离线验证；
- Task 7B4 独立规格和质量复核。
- Task 8A 不可变实时授权上下文：规范化有界 Grant/Receipt 前缀，重放
  既有因果与策略，逐字节验证 committed evidence，并将 active patch
  结果绑定到 ReplayCheckpoint 的 candidate commit 与 manifest digest。
- Task 8B1 纯事前工具授权：校验请求签名、参数摘要、300 秒新鲜度、
  角色/工具矩阵、Grant 能力与配额、路径根、人工批准、测试 Profile、
  ReplayCheckpoint、独立执行标识和组合版本；只判定 handler 资格。
- Task 8B2 纯 HumanDecision 授权：验证签名、WorkOrder 与 Maintainer
  身份，精确绑定审批请求、范围、有效期和唯一决策，并允许无需预先
  请求的 Maintainer 终止；只判定决策资格，不落账、不改变状态。
- Task 8B3 纯 rollback 事前授权：验证 Developer 请求签名、Grant、
  300 秒新鲜度、唯一 active patch 目标、ReplayCheckpoint HEAD、
  needs-rework failure episode、角色、能力与配额；不执行 workspace
  回滚、不签 Receipt、不扣减配额。
- Task 13 首个 Verifier `run_tests` 协调切片：锁内复核账本/证据
  快照、事前预留证据槽位、启动单次 handler、Sidecar 签署 Receipt，
  并对正常结果完成四阶段证据发布；已启动的 handler 异常会
  扣减 `tool_calls` 并提交无附件失败 Receipt，事前策略拒绝不启动
  handler；内部执行 journal 已用真实子进程崩溃注入验证
  RESERVED 安全重试、未确认启动阻断与已提交 Receipt 自动收敛；
  旧 ledger 可受锁迁移内部 journal schema，不伪造协议版本步。

尚未完成：

- `run_tests` 的真实无网执行器、稳定 execution ID、启动/结果
  回执与 `STARTED_UNCONFIRMED` 自动恢复，以及 Developer mode 与 MCP 入口；
- deny/rollback 生产事务和剩余入口的全局 nonce 处理；
- 其他 ToolCall handler 与 evidence publication 的调用闭包，
  rollback handler 及其结果/Receipt 闭包，以及 acceptance 事务闭包；
- ResolutionManifest 原始字节的独立读取与重哈希、完整 Task 9
  composition 和 Acceptance；
- CLI、MCP Sidecar 和 AgentTeams 接线；
- Rich #4196 完整演示；
- Acceptor 独立环境复现；
- Day 0 人类签署和完整执行门；
- 正式赛事提交、入围或获奖。

许可证状态：

当前仓库没有 LICENSE 文件。版权与公开许可尚未完成正式批准。
公开可访问不等于已经授予复制、修改或再分发许可。


九、路线图
----------

1. 接入真实无网执行器的稳定 execution ID 与启动/结果回执，
   闭合 `STARTED_UNCONFIRMED` 恢复后再接入 MCP 传输层；
2. 完成人工决策、回滚和终止策略 API；
3. 完成多尺度证据合成与 AcceptanceReceipt 成功路径；
4. 完成 CLI、MCP Sidecar 和 AgentTeams 集成；
5. 完成 Rich #4196 自包含演示及独立验收；
6. 完成许可证、Day 0 和赛事交付材料。


十、参与方式
------------

项目仍处于协议和 MVP 开发阶段。当前适合参与的方向包括：

- 协议对象与一致性测试；
- 授权衰减和配额重放；
- 可验证构建与证据包；
- MCP/Agent 框架适配；
- 真实开源 Issue 的任务封装；
- 安全、隐私和数据治理审查。

在贡献流程、贡献者协议和许可证正式确定前，请先通过 GitHub Issue
提出建议，不要把代码公开可见解释为已经获得许可授权。


十一、项目主体
--------------

技术 Owner：dengyier
独立 Acceptor：龙胜海
版权主体：成都星火领航科技有限公司

说明：

以上角色已经作为项目责任角色记录，但不能据此推断 Day 0 人类签署、
独立验收或许可证批准已经完成。


十二、项目愿景
--------------

OpenWorkProof 希望让 Agent 工作从“可以生成结果”，迈向：

    可以被授权，
    可以被约束，
    可以被验证，
    可以被接受，
    也可以在证据不足时被拒绝。

OpenWorkProof 不提高 Agent 的智力，而是为 Agent 增加进入社会协作所需的
责任结构。
