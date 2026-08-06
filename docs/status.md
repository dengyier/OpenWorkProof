# OpenWorkProof 当前状态与边界

> 本文档是项目实现状态的权威记录。README 只保留概览，
> 「已经完成什么」和「尚未完成什么」的完整清单以本文为准。

当前版本：0.1.0（开发中）

## 当前已经实现的能力

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
- Task 14 独立 Acceptor 权威：WorkOrder 扩为六角色身份绑定
  （Acceptor 密钥独立于 Maintainer），AcceptanceReceipt 仅接受
  WorkOrder 绑定的 Acceptor 签名，final-acceptance 请求必须声明
  `required_role = Acceptor`，v0.1 schema 与注册表锚点已随模型
  权威重生成。
- Task 15 确定性 proof composition：`CompositionReport` 作为
  可重哈希的权威账本工件，`owp.compose_proof` 在单目标锁与一个
  `BEGIN IMMEDIATE` 内原子提交 Manager 发起收据、报告行、
  proof_composed 收据、配额事件、状态与版本；局部缺失证据的
  首次合成收敛为 `evidence_incomplete`。
- Task 16 final-acceptance 事务链：`request_acceptance_transaction`
  从 proof_ready 原子进入 awaiting_human（1 小时 + WorkOrder 期限
  约束），`prepare_acceptance` 在无私钥输入下返回唯一可外部签名的
  规范草稿，`commit_acceptance` 仅接受 WorkOrder 绑定 Acceptor 的
  签名并原子提交 `accepted` 状态；compose 收据引发的状态转换与
  Acceptor 验收转换已在状态机中由收据级校验授权。

## 当前验证快照

- Acceptance 事务专项：40 passed；
- Acceptance、Contract、Signing、State、Composition、Policy、
  Receipt-chain、MCP 与 Schema focused 门：1058 passed；
- candidate-inventory 供应链专项（required-live Docker）：144 passed
  （image supply-chain 62 + candidate integration 83）；
- 全量测试（required-live Docker，0 skip）：2226 passed、0 failed，
  退出码 0；固定 execution RepoDigest 与外部 artifact root 均按冻结计划提供；
- 本轮精确验收修复提交：`cac4b51739d1bd1f18069fc957fe116bb8bb2d42`；
- 独立结果与 recomposition 专项：test_independent_recomposition
  34 passed（独立 episode 推导、槽位一对一映射、前置闸门七项拒绝、
  独立基础设施失败精确回放与新签名重试、失败零 EvidenceRef、
  recomposition 五维 proof_ready、COMMIT-ACK 回读、并发一个赢家、
  非通过封印、双报告离线验签与一一对应绑定、语义层重签篡改拒绝、
  报告/收据/关联因子/公钥/四类账本表篡改拒绝、STARTED_UNCONFIRMED
  恢复、pre-COMMIT/cleanup/锁释放故障保持提交）；
- 独立规格复核：7B4_SPEC_PASS；
- 独立质量复核：7B4_QUALITY_PASS；
- pip check、compileall 和 git diff check：通过；
- OpenWorkProof Docker 容器与卷残留：0。

同一验证窗口的前两轮全量测试分别暴露一个未修改测试夹具的进程竞态：
schema registry 交叉进程写入用例，以及 detached-survivor pidfile 就绪用例。
两项均在不改代码的情况下独立重复 5 次并全部通过；最终完整 required-live
门取得上述 2197/2197 结果（第四轮审核修复后复验，0 failed、0 skip）。
该记录保留失败历史，不把一次最终绿灯改写成“从未出现过不稳定性”。

## 重要边界

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
handler 协调切片；真实无网 Docker 测试执行器生产 driver 与
MCP 传输服务器、Developer mode 生产入口尚未接入（当前以确定性
fake driver 完成全部协调与恢复切片验证）。当前目标锁与内部 journal 能区分：
只有 `RESERVED` 的崩溃可清理并安全重试；Receipt 已提交但 journal
未清理时可按已提交事实收敛；`STARTED_UNCONFIRMED` 且无 Receipt
时只返回 `RECOVERY_REQUIRED`，不重跑、不补造 Receipt 或扣费事实。
从旧开发快照打开的 ledger 会在目标锁内仅新增这张内部表，
不改变 Receipt、sequence、配额、协议状态或状态版本。
要自动收敛该不确定分支，仍需真实无网执行器提供稳定
execution ID 和可验证启动/结果回执。deny Receipt 与 rollback
生产事务尚未完成；acceptance 生产事务（compose/request/prepare/
commit）已实现并验证。独立结果执行 episode 与五维 recomposition
链已实现并验证（含独立失败收据精确回放与失败后新签名重试），
Day 0 执行门仍为 FAIL；deny/rollback 生产事务、真实无网执行器
生产 driver、MCP 传输服务器与 Acceptor 拒绝路径仍为边界。

## 已完成（按任务切片）

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
- Task 14 六角色信任模型：Acceptor 独立密钥绑定、AcceptanceReceipt
  签名权威迁移、final-acceptance 角色矩阵与 v0.1 schema 重生成。
- Task 15 确定性 CompositionReport 与 `owp.compose_proof` 原子合成。
- Task 16 独立验收事务链：原子 final-acceptance 请求、无密钥
  prepare 草稿与 Acceptor 签名 commit（awaiting_human → accepted）。

## 尚未完成

- `run_tests` 真实无网执行器已接入生产路径：DockerRunTestsExecutor
  驱动 execute_run_tests_production（稳定 execution ID、启动/结果回执、
  STARTED_UNCONFIRMED 恢复，required-live 真实 Docker 执行已验证）；
  剩余为 Developer mode 生产入口与 MCP 传输层；
- 独立结果（independent-result）执行 episode 与五维证据 recomposition
  → proof_ready 链已实现并验证（本切片测试使用五维 WorkOrder 变体：
  独立结果占 verifier_independent_result 专属槽位，recomposition 在
  五维闭合后到达 proof_ready，双报告离线验签证明两段 signed
  report-to-trigger 绑定）；剩余为真实外部 Acceptor 复核与赛事交付；
- deny/rollback 生产事务和剩余入口的全局 nonce 处理；
- Acceptor 拒绝（rejection）收据与拒绝终态事务已实现并验证
  （AcceptanceRejectionReceipt 独立签名对象、awaiting_human → rejected
  原子事务、与 accepted 互斥、COMMIT-ACK 回读、离线 bundle 验签与
  篡改拒绝）；真实外部 Acceptor 签署与复核仍为边界；
- 其他 ToolCall handler 与 evidence publication 的调用闭包，
  rollback handler 及其结果/Receipt 闭包；
- ResolutionManifest 原始字节的独立读取与重哈希、完整 Task 9
  composition 和外部真实 Acceptor 独立环境复现；
- CLI、MCP Sidecar 和 AgentTeams 接线；
- Rich #4196 完整演示；
- Acceptor 独立环境复现；
- Day 0 人类签署和完整执行门；
- 正式赛事提交、入围或获奖。

## 许可证状态

仓库已采用 Apache License 2.0（见根目录 LICENSE 文件），
版权主体为成都星火领航科技有限公司。

## 项目主体说明

技术 Owner：dengyier
独立 Acceptor：待定（当前不绑定真实个人）
版权主体：成都星火领航科技有限公司

以上角色已经作为项目责任角色记录，但不能据此推断 Day 0 人类签署、
独立验收已经完成。
