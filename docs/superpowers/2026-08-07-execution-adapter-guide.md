# Execution Adapter Layer — Usage Guide

Date: 2026-08-07

Module: `src/openworkproof/execution_adapter.py`

## 1. 目的

在 **AgentTeams（团队协作侧）** 与 **Developer mode（协议执行侧）** 之间建立
统一的执行接入层，形成完整闭环：

```
AgentTeams（团队）                     OpenWorkProof（Developer mode）
    │  派发 TeamTask                          │
    ├─────────────────────────────────────────▶
    │   (task_id / kind / ledger / payload)   │
    │                                         │ 协调器执行
    │  TeamExecutionAdapter                   │  - repo_read（管道 handler）
    │  - 数据转换 payload → 协议输入           │  - run_tests（developer mode）
    │  - 协议适配 结果 → TeamTaskResult        │  - status（账本 replay）
    │  - 状态同步 PENDING→RUNNING→SUCCEEDED/FAILED
    │  - 错误隔离 → 稳定错误码
    │  - 分级日志
    │                                         │
    ◀─────────────────────────────────────────┤
    │  回收 TeamTaskResult                     │
```

## 2. 核心接口

### 2.1 任务模型（`TeamTask`）

| 字段 | 说明 |
|---|---|
| `task_id` | 团队任务唯一 ID |
| `kind` | `repo_read` / `run_tests` / `status` |
| `ledger` | 账本文件路径 |
| `payload` | 协议 JSON 消息（request/arguments/checkpoint/facts/密钥引用等，见 CLI 传输文档） |
| `state` | PENDING → RUNNING → SUCCEEDED / FAILED |

### 2.2 团队客户端协议（`AgentTeamClient`）

```python
class AgentTeamClient(Protocol):
    def dispatch(self, task: TeamTask) -> None: ...        # 派发任务
    def list_pending(self) -> tuple[TeamTask, ...]: ...    # 待办队列
    def store_result(self, result: TeamTaskResult) -> None: ...  # 回写结果
    def collect(self) -> tuple[TeamTaskResult, ...]: ...   # 回收结果
```

内置参考实现 `LocalTeamClient`（进程内 FIFO 队列）；接入真实 AgentTeams SDK
时实现同一协议即可，适配器无需改动。

### 2.3 适配器（`TeamExecutionAdapter`）

- `execute_task(task) -> TeamTaskResult`：单任务执行（含状态追踪与错误隔离）
- `run_pending_tasks(max_tasks=None) -> tuple[TeamTaskResult, ...]`：排空团队队列并回写结果

## 3. 接线方式与调用示例

```python
from openworkproof.execution_adapter import (
    LocalTeamClient,
    TeamExecutionAdapter,
    TeamTask,
)

# 1) 团队侧：建客户端、派发任务
client = LocalTeamClient()
client.dispatch(TeamTask(
    task_id="task-42",
    kind="repo_read",
    ledger="/data/work.sqlite3",
    payload={...},  # 协议 JSON 消息（同 CLI/MCP 传输 payload）
))

# 2) 接入层：统一执行
adapter = TeamExecutionAdapter(client)
outcomes = adapter.run_pending_tasks()

# 3) 团队侧：回收结果
for result in client.collect():
    print(result.task_id, result.status, result.result)
```

`run_tests` 任务的 payload 使用 `test_mode="developer"` 的 RunTestsArguments，
即 Developer mode 执行（与 Verifier 测试共用 `execute_run_tests_production`
协调器，授权矩阵按 Developer 角色判定）。

## 4. 错误处理与状态

| 场景 | 行为 |
|---|---|
| 未知 `kind` | `UnknownTaskKindError` |
| payload 缺失字段 / 账本缺失 | 任务 FAILED，`error="CLI_TRANSPORT_ERROR"` |
| 协调器拒绝（授权/路径等） | 任务 FAILED，`error="HANDLER_COORDINATION_ERROR"` |
| 客户端不满足协议 | `ExecutionAdapterError`（构造期） |
| 结果回写失败 | `TaskDispatchError` |

每次任务转换（PENDING→RUNNING→SUCCEEDED/FAILED）均写入分级日志
（`openworkproof.execution_adapter`）。

## 5. 扩展：新增任务种类

1. 在 `SUPPORTED_KINDS` 中加入新 kind；
2. 在 `TeamExecutionAdapter` 增加 `_run_<kind>` 方法（复用 CLI 传输的
   `cli_*` 转发函数或直接调协调器）；
3. 补充测试（成功路径 + 失败错误码）。

## 6. 验证

`tests/test_execution_adapter.py`（6 项）：团队→开发者闭环、status 往返、
失败稳定错误码、未知 kind、坏客户端契约、RUNNING 状态追踪。
