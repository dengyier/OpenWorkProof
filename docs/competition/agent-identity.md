# OpenWorkProof Agent Identity 清单(参赛附录 A)

> 对应赛事 Agent Infra 赛道「1.2 Agent Identity 清单」要求。
> 项目:OpenWorkProof — Agent 工作契约与可验证执行协议。
> 版本:0.1.0(2026-08-07 冻结 HEAD `10619d3`)。

## 一、系统概览

OpenWorkProof 是一个面向企业级多 Agent 协作的**工作契约与可验证执行
协议层**:为「Agent 完成任务」这件事本身建立授权、执行、验证、审计的
机器可检查闭环。系统由六个职能 Agent 组成,协作处理一个端到端任务:

```
任务输入 → 任务拆解 → 上下文传递 → 工具调用 → 结果验证
        → 执行证据沉淀 → 审批/回滚 → 经验沉淀
```

六角色统一以 **AgentTeams 为协同设计基点**:角色编排与状态追踪由
`execution_adapter` 的 TeamTask 生命周期(PENDING→RUNNING→SUCCEEDED/FAILED)
承载,任务派发/上下文传递经 `team_network_client` 的真实 TCP 网络协议
实现,协议执行侧由 OpenWorkProof 协调器完成。

## 二、Agent Identity 清单

### A1. Maintainer(维护者)

| 属性 | 说明 |
|---|---|
| 身份定位 | 系统与 WorkOrder 的所有者,定义任务目标与验收条件 |
| 能力边界 | 签发/撤销 WorkOrder;绑定六角色公钥;定义验收条件与配额 |
| 不可为 | 不直接执行工具;不决定验收结论(验收归 Acceptor) |
| 关键工具 | `owp.status`(账本查询)、Grant 签发原语 |
| 协同关系 | 向 Manager 授权签发子 Grant;向 Acceptor 提供验收依据 |

### A2. Manager(调度者)

| 属性 | 说明 |
|---|---|
| 身份定位 | 任务拆解与编排者,在授权范围内发起工作请求 |
| 能力边界 | 签发 child Grant(仅可衰减);发起 compose/recompose;请求验收 |
| 不可为 | 不可扩权(No-Cloning Authority);不可伪造 Developer 执行 |
| 关键工具 | `owp.compose_proof`、`request_acceptance_transaction` |
| 协同关系 | 承接 Maintainer 授权 → 拆解任务 → 协调 Developer/Verifier → 汇总证据 |

### A3. Developer(执行者)

| 属性 | 说明 |
|---|---|
| 身份定位 | 实际执行任务的 Agent(写代码、改配置、执行工具调用) |
| 能力边界 | 在 Grant 能力/配额内执行 `repo_read`/`apply_patch`/`run_tests(developer)` |
| 不可为 | 越权路径在执行前被策略拒绝(STATE_DENIED/ROLE_DENIED/CAPABILITY_DENIED) |
| 关键工具 | `owp.repo-read`、`apply_patch`、`owp.run-tests`(developer 模式) |
| 协同关系 | 接收 Manager 拆解的子任务;产出 ActionReceipt 供 Verifier 验证 |

### A4. Verifier(验证者)

| 属性 | 说明 |
|---|---|
| 身份定位 | 独立验证执行结果与证据完整性的 Agent |
| 能力边界 | 在隔离上下文运行 `run_tests`;生成不可变 CompositionReport;判断证据维度 |
| 不可为 | 不修改代码/工作区;不替代 Acceptor 作最终验收 |
| 关键工具 | `execute_run_tests_production`、五输入离线验证器 `validate_grant_chain` |
| 协同关系 | 对 Developer 结果独立复现;产出独立报告供 Manager recompose |

### A5. Sidecar(旁路代理)

| 属性 | 说明 |
|---|---|
| 身份定位 | 协议执行侧的签名与传输代理(Agent 侧 AgentTeam 的协议网关) |
| 能力边界 | 代表 Agent 签署收据;承载 JSON 协议消息转发(MCP stdio/CLI/TCP) |
| 不可为 | 不持有业务密钥;不生成业务证据 |
| 关键工具 | MCP stdio 服务器(`owp_status`/`owp_run_tests`/`owp_repo_read`)、CLI 传输 |
| 协同关系 | 连接 AgentTeams 与协议协调器,完成上下文与结果的双向传递 |

### A6. Acceptor(验收者)

| 属性 | 说明 |
|---|---|
| 身份定位 | 最终验收决策者,基于完整证据链作出 accepted/rejected 决定 |
| 能力边界 | 用独立密钥签署 AcceptanceReceipt / AcceptanceRejectionReceipt;四类闭式拒绝理由 |
| 不可为 | 不参与执行;验收必须基于完整因果证据(evidence-incomplete 不可验收) |
| 关键工具 | `verify_acceptance_bundle`(离线验签)、`commit_acceptance` |
| 协同关系 | 复核 Manager 汇总的证据链 → 作出终态 → 证据包离线可复核 |

## 三、协同关系总览

```text
Maintainer ──定义 WorkOrder──▶ Manager ──拆解授权──▶ Developer
    ▲                            │   ▲                  │
    │                            │   └──证据汇总─────────▼
    │                            │               Verifier(独立复现)
    │                            │   ▲                  │
    └──────验收依据──────────────┼───┴──CompositionReport┤
                         Acceptor ◀──证明链完整── Manager recompose
                              │
                              └─ accepted/rejected(离线可复核)
        Sidecar:贯穿全程的签名与协议传输代理
```

## 四、闭环映射(对应 1.3 要求)

| 闭环环节 | 承担角色 | 实现机制 |
|---|---|---|
| 任务输入 | Maintainer | WorkOrder(冻结目标/路径/工具/配额/验收条件) |
| 任务拆解 | Manager | child Grant 签发(仅衰减、不可扩权) |
| 上下文传递 | Manager/Sidecar | Grant/Receipt 前缀 + 协议 JSON 消息(TCP/MCP) |
| 工具调用 | Developer/Verifier | `repo_read`/`apply_patch`/`run_tests` |
| 结果验证 | Verifier | 独立上下文复现 + 五维证据闭合判断 |
| 执行证据沉淀 | 全体 | 不可变 ActionReceipt 链 + SQLite 账本 + CompositionReport |
| 审批与回滚 | Acceptor/Manager | 人工决策、acceptance/rejection 双终态、rollback 事务 |
| 经验沉淀 | 全体 | 证据包 + 离线验签,形成可复用审计资产 |
