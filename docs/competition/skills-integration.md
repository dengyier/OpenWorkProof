# OpenWorkProof Skill 工程体系在 AgentTeams 的实证（25% 评审权重补强）

> 评审维度 3「Skill 工程体系与生态复用」（25%）原文：
> Skill 覆盖关键任务能力；输入输出/调用条件/失败处理清晰；可被多个 Agent 或多个场景复用；
> 考虑版本、发布、回滚、质量评估；以 AgentTeams 为协同基点，并合理使用阿里云官方用云 Skills。

OWP 八个 Skill（S1–S8）在协议层是**任务能力抽象层**，不是一次性 Agent 行为；
每个 Skill 有明确的输入输出/调用条件/失败处理/安全边界/复用价值（详见
`docs/competition/skill-list.md`）。本文件说明 Skill 在 AgentTeams 内如何被
Worker 实际调用（设计基点 = AgentTeams，符合赛道必选要求）。

## 一、S1–S8 → OWP 能力与 MCP 工具映射

> OWP 已在 `src/openworkproof/mcp_transport.py` 暴露 25 个 MCP 工具
> （`@mcp.tool()` 装饰），可直接挂在 AgentTeams Worker 的 `spec.mcpServers`
> 上被任意 Agent 调用。

| Skill | 名称 | OWP 能力/CLI | 已暴露 MCP 工具（`mcp_transport.py`） |
|---|---|---|---|
| **S1** | owp.authorize（任务拆解与最小权限授权） | `cli_profile_validate` + `cli_scope_validate` + `cli_scope_compare` + `work_order` 验证 | `owp_validate_profile`, `owp_scope_validate`, `owp_scope_compare`, `owp_verify_work_order` |
| **S2** | owp.repo_read（受限仓库读取） | `cli_repo_read` | `owp_repo_read` ✓ |
| **S3** | owp.apply_patch（受限补丁应用） | `cli_delivery_build`（apply_patch 阶段）+ `repo_pipeline` 依赖分析 | `owp_build_delivery_package`, `owp_analyze_repo` |
| **S4** | owp.run_tests（可信测试执行，两种模式：离线/Docker） | `cli_run_tests`（两种后端）+ `owp_run_verification`（独立验证） | `owp_run_tests`, `owp_run_verification` |
| **S5** | owp.compose_proof（证据合成与证明链闭合） | `cli_verify_compose` + `decision` 组合 | `owp_validate_action_binding_manifest`, `owp_get_decision`, `owp_validate_judgment_commitment` |
| **S6** | owp.acceptance（终态验收/拒绝与离线验签） | `cli_verify_arm` + `settlement_readiness` | `owp_get_decision`, `owp_get_settlement_readiness`, `owp_build_delivery_package` |
| **S7** | owp.rollback（高风险动作回滚） | ⚠️ **空白**（OWP 通过 `superseded_by` 账本前作覆盖语义实现，但未独立 Skill 化） | — |
| **S8** | owp.audit（全链审计与离线复核） | `cli_audit_replay` + `delivery_package` | `owp_audit_replay`（包装为 verifier）+ 整套 `owp_*` 工具组合 |

**S7 rollback 是诚实缺口**：OWP 当前未提供独立 Skill 化的回滚工具——回滚是通过账本
`superseded_by` 关系实现的（BindingDecision 前作覆盖），但没有用户面向的
`owp_rollback` MCP 工具。**复赛前会补齐**（任务清单中标记）。该缺口**不影响
其余 7 个 Skill 在 AgentTeams 的实证**。

## 二、AgentTeams Worker 接入 Skill 的方式

OWP Skill 接入 AgentTeams Worker 采用两种互补路径，对应赛道「2.2 MCP 与工具集成要求」：
**MCP（推荐）+ 等价 CLI 契约**。

### 路径 A：MCP Server 挂载（推荐）
Worker spec.mcpServers 指向 OWP MCP Server，Agent 在 AgentTeams Matrix 房间里
直接以 `tool_call` 形式调用 OWP Skill（与赛题推荐一致）。

`agentteams/workers.yaml` 增补如下：

```yaml
apiVersion: agentteams.io/v1beta1
kind: Worker
metadata:
  name: dev-worker
spec:
  model: deepseek-v4-pro
  runtime: openclaw
  # —— OWP Skill 接入 ——
  skills:
    - owp.repo_read          # S2
    - owp.apply_patch        # S3
    - owp.run_tests          # S4
    - owp.compose_proof      # S5
    - owp.acceptance         # S6
  mcpServers:
    - name: owp
      # OWP MCP HTTP 端点（复赛工程目标：MCP HTTP transport；
      # 当前 stdio 见下文演示方案，端口规划见 README）
      url: http://host.docker.internal:8765/mcp
      transport: streamable-http
  # —— OWP Skill 接入 ——
  # —— 原有 identity / soul / agents 不变 ——
```

```yaml
apiVersion: agentteams.io/v1beta1
kind: Worker
metadata:
  name: verifier-worker
spec:
  model: deepseek-v4-pro
  runtime: openclaw
  skills:
    - owp.run_tests            # S4（独立模式）
    - owp.compose_proof       # S5
    - owp.acceptance          # S6
    - owp.audit               # S8
  mcpServers:
    - name: owp
      url: http://host.docker.internal:8765/mcp
      transport: streamable-http
```

### 路径 B：等价 CLI 契约（stdio MCP + 等价 fallback，赛道「如方案未使用 MCP…」允许）

复赛前若 Worker 环境不便引入 HTTP MCP（如 Docker 网络隔离或依赖评审约束），采用
**OWP stdio MCP + 等价 CLI 调用**作为降级路径：

- OWP MCP 当前以 stdio transport 运行（`python -m openworkproof.mcp_transport`）
- Worker 可通过本地子进程调用 OWP CLI（`python -m openworkproof.cli`），CLI 已提供
  等价 `cli_repo_read` / `cli_run_tests` / `cli_verify_compose` / `cli_audit_replay` 等
  11 个工具（见 `src/openworkproof/cli.py`）
- 输入输出 Schema 与 MCP 工具完全一致；调用接口从 `tool_call` 降级为
  `subprocess.run` —— 不需重新设计工具调用链

无论路径 A 还是 B，**调用的 Skill 集合与工具契约不变**，评审可验证。

## 三、Skill 调用的现场证据（demo 脚本）

`agentteams/scripts/run_skills_demo.sh` 调用 7 个已落地的 Skill（缺 S7），生成
运行证据文件 `evidence/skill-execution.log`，证明 OWP Skill 在 AgentTeams 任务
流中真实可用。

```bash
# 一键运行：调用 7 个 MCP/CLI 工具并捕获输出
bash agentteams/scripts/run_skills_demo.sh
# 输出：agentteams/evidence/skill-execution.log（每 Skill 真实返回）
```

## 四、Skill 评审的四个检查点（对齐赛道「1.2 赛题个性化评审补充」）

- **输入输出**：`skill-list.md` 第 8 列详细定义；MCP 工具返回结构化 dict
- **调用条件/依赖工具/失败处理/安全边界**：`skill-list.md` 每 Skill 第 4–7 列
- **复用价值**：同协议适用于 3 个企业场景（场景叙事文档）；同一 Skill 在
  AgentTeams 多个 Worker 之间共享（dev/verifier 都有 owp.run_tests/composition_proof）
- **版本演进**：OWP schema 已版本化（`owp_get_schema(object_type, version="0.1")`）；
  Skill 升级走 schema 版本号（无 breaking change 即可向前兼容）

## 五、诚实边界

- S7 rollback Skill 未独立工具化（账本 superseded_by 是兜底语义）—— **复赛前补齐**
- 当前演示通过 stdio MCP + 等价 CLI（不需引入新依赖）；复赛目标是用 MCP HTTP
  挂载到 Worker spec.mcpServers（`host.docker.internal:8765/mcp`）——需评估
  `mcp[streamable-http]` 依赖对供应链 allowlist 的影响
- Worker spec.skills 中的 5 个 Skill（dev）/4 个 Skill（verifier）是**声明式能力列表**
  （Manager 可分配或对话挂载）；实际是否被 Agent 调用取决于 Worker 实现的 agent
  loop + 工具调用逻辑——我们的 M4 demo 已在 `tests/test_delivery_m4_agentscope.py`
  层面验证了 Skill 链路，端到端 AgentTeams 房间内调用待复赛前在完整环境验证
