# OpenWorkProof × AgentTeams 复赛代码包

> 赛事：世界人工智能开源大赛 · Agent Infra（新智基座）赛道
> 场景：AgentScope #2239（DictMixin 属性协议 bug）多 Agent 修复闭环
> 版本：0.2.0（2026-08-13）
> 仓库：github.com/dengyier/OpenWorkProof

## 这是什么

OpenWorkProof 是 **Agent 工作的契约、授权、证据与验收协议层**。本代码包
演示它与 **AgentTeams（hiclaw，赛道必选协同框架）** 的真实集成：多 Agent
协同编排走 AgentTeams（Matrix 房间，全量可见、人类可介入），而**结果验证、
执行证据沉淀、审批/回滚、审计**由 OpenWorkProof 协议栈承担（机器可检查，
不依赖 Agent 自证）。

Demo 场景：修复 AgentScope（AgentTeams 母生态框架）真实 issue
[#2239](https://github.com/agentscope-ai/agentscope/issues/2239)——
`DictMixin.__getattr__` 抛 `KeyError` 而非 `AttributeError`，导致
`copy.deepcopy()` 崩溃，`hasattr` / `getattr(..., default)` 全部异常。

## 目录结构

```text
agentteams/
├── README.md                    # 本文件
├── workers.yaml                 # dev-worker（修复）+ verifier-worker（独立复核）
├── team.yaml                    # owp-team（leader=dev-worker）
├── evidence/                    # 运行证据（Matrix 任务分派记录）
└── ../../src/openworkproof/
    ├── agentteams_controller_client.py   # 管理面：docker exec agt（REST :8090 等效）
    ├── agentteams_matrix_client.py       # 执行面：Matrix client-server API
    ├── mcp_transport.py                  # OWP MCP Server（stdio；HTTP 挂载为复赛工程）
    └── ../../tests/test_delivery_m4_agentscope.py  # 修复真值基准（3 测试，离线）
```

## 部署（评审可复现）

1. 安装 AgentTeams（官方一键脚本，Docker）：

```bash
bash <(curl -sSL https://raw.githubusercontent.com/agentscope-ai/AgentTeams/main/install/agentteams-install.sh)
```

2. 配置 LLM：本包使用 `openai-compat` 接 DeepSeek v4-pro：

```bash
AGENTTEAMS_LLM_PROVIDER=openai-compat
AGENTTEAMS_OPENAI_BASE_URL=https://api.deepseek.com/v1
AGENTTEAMS_LLM_API_KEY=<key>
AGENTTEAMS_DEFAULT_MODEL=deepseek-v4-pro
AGENTTEAMS_EMBEDDING_MODEL=          # DeepSeek 无 embedding，必须留空
AGENTTEAMS_MODEL_CONTEXT_WINDOW=150000
AGENTTEAMS_MODEL_MAX_TOKENS=65536
AGENTTEAMS_MODEL_REASONING=true
AGENTTEAMS_MODEL_VISION=false
```

3. 应用资源（官方 apply 脚本）：

```bash
bash install/agentteams-apply.sh -f agentteams/workers.yaml
bash install/agentteams-apply.sh -f agentteams/team.yaml
```

4. 程序化接入（OWP 适配器，纯标准库零新依赖）：

```python
from openworkproof.agentteams_controller_client import AgentTeamsControllerClient
from openworkproof.agentteams_matrix_client import AgentTeamsMatrixClient

ctrl = AgentTeamsControllerClient()
print([(w["name"], w["phase"]) for w in ctrl.get_workers()])   # 管理面

matrix = AgentTeamsMatrixClient()
matrix.login("admin", "<password>")
room = matrix.find_room("Worker: dev-worker")                   # 执行面
matrix.send_text(room, "<修复任务描述>")
```

5. 修复真值基准（离线，不依赖 Agent）：

```bash
./.venv/bin/python -m pytest tests/test_delivery_m4_agentscope.py -q
# 3 passed —— bug 复现（deepcopy/hasattr/getattr 全 KeyError）+ 修复应用 + 回归矩阵
```

## 运行证据（2026-08-13）

- AgentTeams 真实部署：controller / manager / dashboard / 2×worker 容器全 Up
- Manager `default`：Running · deepseek-v4-pro
- Matrix 任务链路：admin → Worker 房间 → **Manager 自动分派**
  （`task-20260813-013945`，分派消息含正确 bug 分析）→ 见
  `agentteams/evidence/2026-08-13-manager-dispatch.md`
- 管理面/执行面双适配器：14 个单元测试通过（mock，离线）

## 诚实边界

- Worker 实时执行（openclaw 运行时对任务的实际响应）在本机环境存在兼容
  限制（Worker 容器仅 gateway 进程、agent 未 spawn），**复赛前需在完整
  环境修复**；已跑通的是「任务提交 → Manager 分派」链路与确定性的
  OWP 真值验证，不声称 Worker 端到端实时执行完成。
- Demo 不证明：AgentScope 上游合入、客户采用、付款或结算。
- AgentScope / AgentTeams 均为第三方开源项目，OWP 只做集成。
