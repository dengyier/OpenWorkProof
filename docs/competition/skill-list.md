# OpenWorkProof Skill 清单

> 对应赛事 Agent Infra 赛道「2.1 Skill 要求」(Skill 为本赛题必选项)。
> 设计原则:每个 Skill 都是**任务能力抽象层**,而非一次性 Agent 行为;
> 可被多个 Agent/多个场景复用,并支持版本、发布、回滚与质量评估。
> 版本:0.1.0(2026-08-07)。

## 一、Skill 清单总览

| # | Skill 名称 | 承担角色 | 关键能力 |
|---|---|---|---|
| S1 | `owp.authorize` | Manager | 任务拆解与最小权限授权 |
| S2 | `owp.repo_read` | Developer | 受限仓库读取与分析 |
| S3 | `owp.apply_patch` | Developer | 受限补丁应用(active patch) |
| S4 | `owp.run_tests` | Developer/Verifier | 可信测试执行(两种模式) |
| S5 | `owp.compose_proof` | Manager | 证据合成与证明链闭合 |
| S6 | `owp.acceptance` | Acceptor | 终态验收/拒绝与离线验签 |
| S7 | `owp.rollback` | Manager | 高风险动作回滚 |
| S8 | `owp.audit` | 任意/第三方 | 全链审计与离线复核 |

## 二、Skill 明细

### S1 `owp.authorize` — 任务拆解与授权

| 维度 | 说明 |
|---|---|
| Skill 用途 | 将 WorkOrder 拆解为可执行子任务,签发仅衰减的 child Grant,完成角色与配额绑定 |
| 输入 | WorkOrder、父 Grant、目标工具集、配额 |
| 输出 | child Grant(签名收据)、授权上下文 |
| 调用条件 | Manager 角色、父 Grant 有效、能力/配额足够 |
| 依赖工具 | SQLite 账本、Ed25519 签名 |
| 失败处理 | policy-deny 审计历史记录;ROLE_DENIED/CAPABILITY_DENIED 明确报错 |
| 安全边界 | No-Cloning Authority:子授权只能衰减或消费,不可复制等价或更大权限 |
| 复用价值 | 任何需要「按最小权限拆解任务」的多 Agent 场景均可复用 |
| 协同关系 | 作为任务拆解入口,串联 Developer/Verifier 的执行与验证 |

### S2 `owp.repo_read` — 受限仓库读取

| 维度 | 说明 |
|---|---|
| Skill 用途 | 在受限工作区读取目标仓库代码/文件,产出可哈希的输出摘要 |
| 输入 | 仓库路径/URL、读取范围、WorkOrder 绑定 |
| 输出 | 读取结果 + `output_digest`(精确重算可验证) |
| 调用条件 | Developer 角色、路径在授权白名单内 |
| 依赖工具 | repo_pipeline(递归遍历+过滤+语言识别)、MCP/CLI 传输 |
| 失败处理 | 越权路径前置拒绝;结构化错误码 |
| 安全边界 | 只读、路径根约束、无任意命令字符串 |
| 复用价值 | 代码缺陷定位、影响面分析等研发场景的通用读取能力 |
| 协同关系 | 为 apply_patch/run_tests 提供上下文与证据基础 |

### S3 `owp.apply_patch` — 受限补丁应用

| 维度 | 说明 |
|---|---|
| Skill 用途 | 将修复补丁应用到候选工作区,形成 active patch 并绑定证据 |
| 输入 | 补丁内容、目标文件、父 repo_read 收据 |
| 输出 | patch 收据 + active patch 绑定 |
| 调用条件 | Developer 角色、补丁在授权路径/范围内 |
| 依赖工具 | WorkspaceManifest、证据 staging |
| 失败处理 | 补丁语义父规则校验;失败回滚 |
| 安全边界 | 路径根约束、只允许授权文件改动 |
| 复用价值 | 缺陷修复、配置变更等「受限写操作」的通用封装 |
| 协同关系 | 承接 repo_read 上下文,产出待验证补丁 |

### S4 `owp.run_tests` — 可信测试执行

| 维度 | 说明 |
|---|---|
| Skill 用途 | 运行固定测试并产出签名验证报告(两种模式:Developer 执行 / Verifier 独立复现) |
| 输入 | 测试 Profile、执行上下文、freshness 约束 |
| 输出 | 测试收据 + 独立结果报告(TIMEOUT/OUTPUT_LIMIT/DISK_LIMIT 精确回放) |
| 调用条件 | Developer 或 Verifier 角色;300 秒新鲜度 |
| 依赖工具 | Docker 生产执行器、candidate 镜像供应链、Landlock 隔离 |
| 失败处理 | 基础设施失败可新签名重试;失败收据零 EvidenceRef |
| 安全边界 | Linux 容器私有 PID namespace、UID/GID 65532、无网络 |
| 复用价值 | 「可验证测试执行」跨任何语言/仓库场景通用 |
| 协同关系 | Verifier 独立复现 Developer 结果,形成双报告链 |

### S5 `owp.compose_proof` — 证据合成

| 维度 | 说明 |
|---|---|
| Skill 用途 | 将多份收据/报告合成为 CompositionReport,五维证据闭合后到达 proof_ready |
| 输入 | 收据序列、独立报告、关联因子 |
| 输出 | 不可变 CompositionReport + proof_composed 收据(原子提交) |
| 调用条件 | Manager 角色、证据维度覆盖 |
| 依赖工具 | 原子提交原语、五输入验证器 |
| 失败处理 | evidence-incomplete 收敛为首份报告;篡改拒绝 |
| 安全边界 | 单目标锁、无 replace 发布、崩溃恢复 |
| 复用价值 | 「多来源证据组合为可验收证明」的通用机制 |
| 协同关系 | 汇总 Developer+Verifier 证据,为 Acceptor 提供完整依据 |

### S6 `owp.acceptance` — 终态验收/拒绝

| 维度 | 说明 |
|---|---|
| Skill 用途 | 基于完整证据链作出 accepted/rejected 终态决策并签名 |
| 输入 | 完整证据包、Acceptor 独立密钥 |
| 输出 | AcceptanceReceipt 或 AcceptanceRejectionReceipt(离线可验签) |
| 调用条件 | Acceptor 角色;证据因果完整(evidence-incomplete 不可验收) |
| 依赖工具 | `verify_acceptance_bundle`、外部 Acceptor 子进程 |
| 失败处理 | 四类闭式拒绝理由;与 accepted 互斥终态 |
| 安全边界 | Acceptor 密钥独立于 Maintainer;离线双路径验签 |
| 复用价值 | 任何「需要独立人类/权威验收」的交付场景 |
| 协同关系 | 验收 Manager 汇总的证明链,产出终态与可审计证据包 |

### S7 `owp.rollback` — 高风险动作回滚

| 维度 | 说明 |
|---|---|
| Skill 用途 | 对失败的 needs-rework episode 执行工作区回滚并记录回滚收据 |
| 输入 | 失败补丁收据、目标工作区、回滚目标 commit |
| 输出 | RollbackReceipt(成功/验证失败) |
| 调用条件 | Manager 角色;唯一 active patch 目标 |
| 依赖工具 | 回滚协调器、handler journal |
| 失败处理 | RECOVERY_REQUIRED 保留已提交真值;锁释放故障保持提交 |
| 安全边界 | 事前授权校验;拒绝不启动 handler |
| 复用价值 | 高风险自动化动作的标准回滚与审计封装 |
| 协同关系 | 与 acceptance 的 rejected 路径联动,形成闭环容错 |

### S8 `owp.audit` — 全链审计与离线复核

| 维度 | 说明 |
|---|---|
| Skill 用途 | 不接入任何一方系统,离线验证完整签名授权历史与证据链 |
| 输入 | 证据包(Grant/Receipt/Report/公钥) |
| 输出 | 验证结论(全链通过或篡改定位) |
| 调用条件 | 任意第三方;证据包字节完整 |
| 依赖工具 | `validate_grant_chain`、`verify_acceptance_bundle` |
| 失败处理 | 任一字节篡改即拒绝,定位失败点 |
| 安全边界 | 只读、无网络、无状态修改 |
| 复用价值 | 纠纷复核、交付审计、赛事评审的通用离线核验 |
| 协同关系 | 独立于执行链,可由外部第三方直接调用 |

## 三、Skill 与多 Agent 协同流程的关系

```text
S1 authorize ─▶ S2 repo_read ─▶ S3 apply_patch ─▶ S4 run_tests
      │              │               │                │
      │              └──上下文/证据──┴──证据───────────┘
      ▼                          ▼
S5 compose_proof ◀──── S4 独立 Verifier 复现(双报告)
      │
      ▼
S6 acceptance(accepted/rejected) ── S7 rollback(失败路径)
      │
      ▼
S8 audit(第三方离线复核,闭环)
```

- **S1/S5/S6/S7** 属编排与决策面(Manager/Acceptor);
- **S2/S3/S4** 属执行与验证面(Developer/Verifier);
- **S8** 属审计面(任意第三方),是项目「执行证据沉淀与安全审计」
  差异化价值的直接体现。

## 四、版本、发布与质量评估

- 每个 Skill 以协议对象(schema 注册表)绑定,JSON Schema 版本化;
- 发布走证据 staging 原子提交,崩溃可恢复,支持版本回退;
- 质量评估:全量测试 2281 passed(required-live Docker)、候选镜像
  供应链门、离线验签通过——Skill 行为由测试契约锁定。
