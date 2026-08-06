# Team Network Client — 使用说明

Date: 2026-08-07

Module: `src/openworkproof/team_network_client.py`

## 1. 背景与诚实说明

「AgentTeams」存在真实 SDK（阿里云 `@alicloud/agentteams20260605`），但：
- 当前仅提供 TypeScript/Java/Swift/PHP 版本，**无 Python SDK**；
- 其 API 属**治理/管理面**（workspace、身份、策略），与本项目「任务派发 →
  执行 → 结果回收」的执行面语义不匹配。

因此本模块用**真实 TCP 网络协议**实现任务生命周期的网络传输（连接真实、
认证真实、收发真实），遵循 `execution_adapter.py` 的 `AgentTeamClient`
契约；未来若官方发布 Python 执行面 SDK，可在适配器边界接入，业务层不变。

## 2. 文件清单与调用关系

```
execution_adapter.py       业务层：AgentTeamClient 协议 + TeamExecutionAdapter
        ▲ 实现契约
team_network_client.py     网络层：TeamNetworkClient（TCP 客户端）
   ├── TeamNetworkService   参考服务端（远程团队服务）
   └── TeamNetworkConfig    配置（环境变量）
        ▼
远程团队服务（跨进程/主机，真实 TCP）
```

数据流：`TeamNetworkClient.dispatch(TeamTask)` → TCP → 服务端入队 →
`TeamExecutionAdapter.run_pending_tasks()` 经 `list_pending` 取任务 →
协调器执行 → `store_result` 回写 → `collect` 回收 `TeamTaskResult`。

## 3. 依赖与安装

- 仅标准库（socket/threading/json），无第三方依赖；
- 依赖本仓库既有模块（`execution_adapter`、`openworkproof` 包）。

## 4. 配置（环境变量）

| 变量 | 说明 | 默认 |
|---|---|---|
| `OWP_TEAM_ENDPOINT` | 团队服务 `host:port` | `127.0.0.1:18742` |
| `OWP_TEAM_TOKEN` | 共享认证 token（空=不鉴权） | 空 |
| `OWP_TEAM_TIMEOUT` | socket 超时（秒） | 5.0 |
| `OWP_TEAM_MAX_RETRIES` | 请求重试次数 | 3 |
| `OWP_TEAM_BACKOFF` | 指数退避基值（秒） | 0.2 |

## 5. 使用示例

```python
# 远程团队服务端（可部署到独立主机）
# OWP_TEAM_ENDPOINT=team.example.com:18742 OWP_TEAM_TOKEN=s3cret \
#   python -m openworkproof.team_network_client

# 客户端（应用侧）
from openworkproof.execution_adapter import TeamExecutionAdapter, TeamTask
from openworkproof.team_network_client import TeamNetworkClient

client = TeamNetworkClient()          # 配置来自环境变量
client.connect()                      # TCP + auth 握手
adapter = TeamExecutionAdapter(client)

client.dispatch(TeamTask(
    task_id="t-1", kind="repo_read",
    ledger="/data/work.sqlite3", payload={...},
))
outcomes = adapter.run_pending_tasks()
for result in client.collect():
    print(result.task_id, result.status, result.result)
client.disconnect()
```

## 6. 错误处理与重试

- 连接失败/超时：指数退避重试（`max_retries` 次）后抛 `TeamNetworkError`；
- 认证失败：`TeamAuthenticationError`/`TeamProtocolError`（服务端拒绝）；
- 断连：自动失效会话，重连后恢复；结构化日志
  （`openworkproof.team_network_client`）记录每次连接与重试。

## 7. 验证

`tests/test_team_network_client.py`（6 项）：真实 TCP 派发/回收往返、
token 鉴权（对/错）、不可达端口重试耗尽、服务重启后重连、配置校验、
**网络客户端 + 适配器 + Developer 协调器端到端闭环**（repo_read 全链路）。
