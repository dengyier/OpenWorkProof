# OpenWorkProof

> Agent 可以生成结果，但凭什么交付？
> Agent Work Contracts and Verifiable Execution Protocol

项目地址：https://github.com/dengyier/OpenWorkProof
当前版本：1.0.0
许可证：Apache-2.0

---

## 30 秒理解 OpenWorkProof

MCP 连接 Agent 与工具，A2A 连接 Agent 与 Agent，AgentTeams 组织 Agent 协作。

但当 Agent 说「我完成了」，没有任何一层能回答：

- 这项工作依据什么授权？
- 它做的每一步是否在授权范围和配额之内？
- 测试、补丁和报告之间是否形成完整因果链？
- 谁有权作出最终接受或拒绝的决定？
- 出了纠纷，第三方能否不接入任何一方系统、离线复核全部事实？

**OpenWorkProof 补足这一层：Agent 工作的契约、授权、证据与验收协议。**

它不试图让 Agent 变得更聪明，而是让 Agent 的工作可以被授权、被约束、
被验证、被接受——也可以在证据不足时被拒绝。

反共识判断：未来多 Agent 系统的主要瓶颈，不只是模型能力，而是责任、
授权、证据和验收机制。没有这些机制，Agent 可以生成结果，却很难成为
可委托、可追责、可结算的生产主体。

---

## 为什么使用 OpenWorkProof

### 谁需要它

| 角色 | 痛点 | OpenWorkProof 提供的 |
|------|------|----------------------|
| **Agent 平台/框架开发者** | Agent 能调工具，但无法证明「这次调用被授权了」 | 签名 AgentRequest + PolicyDecision 事前授权，每次调用携带机器可检查的授权证据 |
| **企业 IT / 合规团队** | EU AI Act 高风险条款要求证明「Agent 被授权、被约束、可问责」 | 完整签名授权链、配额追踪、离线第三方复核，满足审计需求 |
| **多 Agent 协作编排者** | Agent 之间委托权限后无法控制衰减、无法追责 | CapabilityGrant 原子衰减签发，子授权只能收缩不能扩张 |
| **交付验收方** | Agent 声称完成，但测试、补丁、报告之间的因果关系不可查 | 因果回放层 + 策略回放层 + 五输入离线验证器，完整证据链可复现 |
| **纠纷仲裁方** | 需要不接入任何一方系统来复核事实 | `validate_grant_chain` 纯离线验签，只需证据包 + 公钥即可复核全部签名历史 |

### 为什么是现在

**市场拐点已至。** Gartner 预测 2026 年底 40% 的企业软件将嵌入 AI Agent
（2025 年不足 5%）；EU AI Act 高风险条款已经生效，无法证明「Agent 被授权、
被约束、可问责」的企业面临实际法律风险。

**赛道已被资本验证。** 2026 年上半年，Agent 信任基础设施赛道公开融资超过
6500 万美元：

| 项目 | 融资 | 覆盖层 |
|------|------|--------|
| Catena Labs | $48M（a16z 领投） | Agent 身份 + 支付协议 |
| GenLayer | $7.5M | 可验证判断 + 链上身份 |
| OpenBox AI | $5M | 执行时治理（身份/授权） |
| t54 Labs | $5M（Franklin Templeton / Ripple） | Agent 金融信任层 |

这些项目解决「谁在行动、钱怎么动」——身份层与支付层。

**OpenWorkProof 解决它们都没覆盖的一层：这项工作凭什么被授权、过程凭什么
可信、结果凭什么被验收——工作契约层。** 二者互补而非竞争。

一个类比：OAuth 定义了「人如何授权应用」，催生了 Okta/Auth0 的百亿美元
市场。OpenWorkProof 定义「人如何授权 Agent 工作并验收结果」。

### 核心原则

- **Proof-Carrying Work**：动作必须携带机器可检查的授权与结果证据
- **No-Cloning Authority**：子授权只能衰减或消费，不能复制出等价或更大的权限
- **Multi-Scale Proof Composition**：局部凭证只有在因果完整、证据维度覆盖、
  相关性披露和全局条件同时满足时，才能组合成可接受的整体证明
- **Fail Closed**：无法验证的权限、签名、历史、状态或证据一律不得解释为成功
- **离线第三方复核**：`validate_grant_chain` 支持第三方在不接入任何一方
  系统的情况下，验证完整签名授权历史

---

## 工作原理

四类协议对象构成完整的工作级证明链：

```
WorkOrder            CapabilityGrant        ActionReceipt          AcceptanceReceipt
工作契约              能力授权               行动凭证               验收凭证
冻结目标/路径/工具/   可签名、可衰减、        每次执行绑定授权判断、   证据覆盖 + 因果完整 +
配额/验收条件    →    不可扩权的授权    →    配额变化与证据引用  →   独立性披露 + 人工决定
```

六角色身份绑定：

| 角色 | 职责 | 密钥 |
|------|------|------|
| Maintainer | 初始化 WorkOrder、签发 Root Grant | Ed25519 |
| Manager | 签发 child Grant、发起 compose_proof | Ed25519 |
| Developer | 执行 repo_read / apply_patch / run_tests | Ed25519 |
| Verifier | 独立运行测试、形成独立证据 | Ed25519 |
| Sidecar | 分配可信执行事实（ReplayCheckpoint） | Ed25519 |
| Acceptor | 人工验收（accept / reject），独立密钥 | Ed25519（独立于系统） |

状态流转：

```
running → locally_verified → proof_ready → awaiting_human → accepted
                                                        ↘ rejected
```

详细协议 Schema 见 [specs/v0.1](specs/v0.1/)。

---

## 快速开始

### 环境要求

- Python 3.12（`>=3.12, <3.13`）
- Git
- macOS 或 Linux

### 安装

```bash
git clone https://github.com/dengyier/OpenWorkProof.git
cd OpenWorkProof
python3.12 -m venv .venv
./.venv/bin/python -m pip install -r requirements-lock.txt
./.venv/bin/python -m pip install -e .          # 安装 owp CLI 入口
```

### 验证安装

```bash
# 运行全量测试（约 5 分钟）
./.venv/bin/python -m pytest -q

# 预期结果：2283 passed, 7 skipped, 0 failed
```

### 运行端到端演示

OpenWorkProof 提供两个独立的端到端验证演示，覆盖不同的项目类型和协议场景：

#### M2 — Rich #4196（开发者工具类）

基于真实开源 Issue [Textualize/Rich #4196](https://github.com/Textualize/rich/issues/4196)
的完整五角色工作流演示（约 9 秒）：

```bash
./.venv/bin/python -m pytest tests/test_delivery_m2.py -q

# 预期结果：5 passed
```

该演示完整覆盖 9 步证据链：

```
1. 初始化 WorkOrder（五角色 + root grant）        → running
2. Developer repo_read（管道读取候选文件）          → 收据 + output_digest
3. Developer apply_patch（发布补丁修复 #4196）      → active patch 绑定
4. Developer run_tests（开发者模式自检）            → 测试收据
5. Manager compose_proof（首份报告）               → evidence_incomplete
6. 独立 Verifier run_tests（新鲜上下文）           → 独立结果收据
7. Manager recompose_proof（五维证据闭合）          → proof_ready
8. request_acceptance + 外部 Acceptor 签名         → accepted
9. 导出证据包 + 离线验签                           → verify_acceptance_bundle 通过
```

完整记录见 [docs/superpowers/2026-08-07-rich-4196-demo-log.md](docs/superpowers/2026-08-07-rich-4196-demo-log.md)。

#### M3 — Dify #33013（AI 应用平台类）

基于真实开源 Issue [langgenius/dify #33013](https://github.com/langgenius/dify/issues/33013)
的完整五角色工作流演示（约 6 秒）：

```bash
./.venv/bin/python -m pytest tests/test_delivery_m3_dify.py -q

# 预期结果：7 passed
```

该 Bug 发生在 Dify 的 QuestionClassifierNode 节点中——用户在工作流中
添加问题分类器节点后执行时直接抛出 `TypeError`，因为 `invoke_llm()` 调用
传入了 `structured_output_schema` 参数，但底层 LLM SDK 意外地将它转换为
字典而非预期对象。上游修复将参数名更新为 `json_schema`，一行修改解决。

Dify 是 AI 工作流平台，终端用户直接编排 Agent 工作流——这是与 Rich（开发
者工具）完全不同的应用场景，证明 OpenWorkProof 协议跨项目类型通用。

该演示覆盖与 M2 相同的九步证据链：

```
1. 初始化 WorkOrder（五角色 + root grant）        → running
2. Developer repo_read（裁剪真实的 pre-fix 源码）  → 收据 + output_digest
3. Developer apply_patch（一行精确修复）           → active patch 绑定
4. Developer run_tests（开发者模式自检）            → 测试收据
5. Manager compose_proof（首份报告）               → evidence_incomplete
6. 独立 Verifier run_tests（新鲜上下文）           → 独立结果收据
7. Manager recompose_proof（五维证据闭合）          → proof_ready
8. request_acceptance + 外部 Acceptor 签名         → accepted
9. 导出证据包 + 离线验签                           → verify_acceptance_bundle 通过
```

另外验证了两个功能层断言：
- 裁剪代码中的 `invoke_llm` 调用确认复现了 TypeError（`structured_output_schema` 参数）
- upstream fix 行级精确替换为 `json_schema`，验证修复有效

完整记录见 [docs/superpowers/2026-08-07-dify-33013-demo-log.md](docs/superpowers/2026-08-07-dify-33013-demo-log.md)。

---

## 使用方式

OpenWorkProof 提供三种使用入口：CLI、MCP 传输层和 Python API。

### 1. CLI（命令行）

```bash
# 查看账本状态（回放全部收据，输出当前状态）
owp status path/to/ledger.db

# 输出示例：
# {
#   "schema_version": "openworkproof/cli-status/0.1",
#   "work_order_digest": "sha256:...",
#   "current_state": "accepted",
#   "version": 42,
#   "receipt_count": 15
# }

# 转发一个 run-tests 执行请求
owp run-tests path/to/ledger.db payload.json

# 转发一个 repo-read 执行请求
owp repo-read path/to/ledger.db payload.json

# 文本输出模式
owp --output text status path/to/ledger.db
# state=accepted version=42 receipts=15
```

payload.json 示例（run-tests）：

```json
{
  "request": {
    "schema_version": "openworkproof/agent-request/0.1",
    "work_order_digest": "sha256:abc123...",
    "grant_id": "grant-uuid-here",
    "role": "verifier",
    "tool_name": "owp.run_tests",
    "nonce": "unique-nonce-string",
    "arguments": { "mode": "verifier", "test_filter": "test_basic" },
    "signature": { "key_id": "verifier-key-1", "sig": "..." }
  },
  "arguments": { "mode": "verifier", "test_filter": "test_basic" },
  "execution_facts": { ... },
  "replay_checkpoint": { ... }
}
```

### 2. MCP 传输层（stdio）

OpenWorkProof 协调器已封装为 MCP 工具，可被任何 MCP 客户端（如 Claude Desktop、
Cursor 等）直接调用：

```bash
# 启动 stdio MCP 服务器
./.venv/bin/python -m openworkproof.mcp_transport
```

提供的 MCP 工具：

| 工具 | 功能 |
|------|------|
| `owp_status(ledger)` | 回放账本并返回权威状态 |
| `owp_run_tests(ledger, payload)` | 转发 run-tests 执行 |
| `owp_repo_read(ledger, payload)` | 转发 repo-read 执行 |

在 MCP 客户端配置中添加：

```json
{
  "mcpServers": {
    "openworkproof": {
      "command": "/path/to/.venv/bin/python",
      "args": ["-m", "openworkproof.mcp_transport"]
    }
  }
}
```

### 3. Python API

```python
from openworkproof import evidence, mcp_server, policy
from openworkproof.models import WorkOrder, CapabilityGrant, AgentRequest
from openworkproof.signing import sign_payload, verify_payload
from openworkproof.acceptance import verify_acceptance_bundle

# 1. 初始化账本（创建 WorkOrder + Root Grant）
evidence.init_ledger("ledger.db", work_order, root_grant)

# 2. 事前授权检查（纯函数，不执行工具、不写账本）
auth_ctx = policy.derive_authorization_context(
    work_order=work_order,
    grants=grant_prefix,
    receipts=receipts,
    request=signed_request,
    arguments=typed_args,
    execution_facts=facts,
    checkpoint=checkpoint,
)
decision = policy.authorize_tool_call(auth_ctx)
if not decision.allowed:
    # deny 路径：审计记录但不执行
    mcp_server.produce_deny_receipt("ledger.db", request, decision)
    return

# 3. 执行工具并提交收据
receipt = mcp_server.complete_receipt_publication(
    "ledger.db", request, decision, execution_result, evidence_list
)

# 4. 离线验签（第三方，不需要活账本）
result = verify_acceptance_bundle(
    work_order=work_order,
    report=report,
    effective_grants=grants,
    grant_attempts=attempts,
    receipts=receipts,
    committed_evidence=evidence,
    acceptance_receipt=signed_receipt,
    public_keys=public_keys,
    reports=all_reports,
)
```

### 4. 外部 Acceptor 服务

Acceptor 作为独立进程运行，仅持有 Acceptor 私钥，通过 TCP 接收签名请求：

```bash
# 启动外部 Acceptor（默认 127.0.0.1:18741）
./.venv/bin/python -c "
from openworkproof.external_acceptor import ExternalAcceptorService
svc = ExternalAcceptorService(host='127.0.0.1', port=18741, key_hex='...')
svc.serve()
"

# 客户端发送签名请求
./.venv/bin/python -c "
from openworkproof.external_acceptor import ExternalAcceptorClient
client = ExternalAcceptorClient(host='127.0.0.1', port=18741)
result = client.sign_acceptance(draft_receipt)
print(result)
"
```

### 5. AgentTeams 网络传输

通过 TCP 网络客户端连接 AgentTeams 执行层：

```bash
# 环境变量配置
export OWP_TEAM_ENDPOINT=127.0.0.1:18742
export OWP_TEAM_TOKEN=shared-secret
export OWP_TEAM_TIMEOUT=5.0
```

---

## 离线验签

OpenWorkProof 的核心设计目标之一：第三方不接入任何一方系统，仅凭证据包
离线复核全部事实。

```python
from openworkproof.acceptance import verify_acceptance_bundle

# 只需要证据包 + 公钥，不需要活账本
result = verify_acceptance_bundle(
    work_order=work_order,           # WorkOrder（含六角色绑定公钥）
    report=report,                   # CompositionReport（权威账本工件）
    effective_grants=grants,         # 规范化 Grant 前缀
    grant_attempts=attempts,          # 签发尝试
    receipts=receipts,               # ActionReceipt 信封序列
    committed_evidence=evidence,      # (CommittedEvidence, ...)
    acceptance_receipt=signed,       # 终态验收收据
    public_keys=public_keys,         # {key_id: Ed25519PublicKey}
    reports=reports,                 # 全部 CompositionReport
)
```

验签器验证内容：
1. **签名授权历史**：重建确定性索引，验证每条收据的 Ed25519 签名
2. **策略回放**：重算 Grant 衰减、余额、撤销、single-use、配额与拒绝优先级
3. **证据引用**：验证 EvidenceRef 的路径、sha256 和 publication 闭包
4. **因果完整性**：精确父集、genesis 唯一、active patch/rework/approval 语义
5. **终态决策**：acceptance 或 rejection 二选一绑定请求 tip

详见 [docs/offline-verification.md](docs/offline-verification.md)。

---

## 项目结构

```
OpenWorkProof/
├── src/openworkproof/
│   ├── models.py              # 四类协议对象模型（WorkOrder/Grant/Receipt/Acceptance）
│   ├── policy.py              # 事前授权：authorize_tool_call / validate_human_decision / validate_rollback
│   ├── evidence.py           # SQLite 权威账本、原子提交、证据 staging 与发布
│   ├── composition.py         # 因果回放层 + 确定性 CompositionReport
│   ├── acceptance.py         # 终态验收 + 离线验签器（verify_acceptance_bundle）
│   ├── mcp_server.py         # 协调器：complete_receipt_publication / compose_proof 等
│   ├── mcp_transport.py       # MCP stdio 传输层
│   ├── cli.py                 # CLI 传输层（owp 命令）
│   ├── execution_adapter.py  # AgentTeams 执行适配层
│   ├── team_network_client.py # TCP 网络客户端
│   ├── external_acceptor.py  # 独立 Acceptor 服务
│   ├── signing.py            # Ed25519 签名 + RFC 8785 JCS 规范化
│   ├── schema_registry.py    # JSON Schema 注册表
│   ├── predicates.py         # 谓词注册表
│   ├── repo_tools.py         # 仓库管道工具
│   ├── runtime_context.py   # 运行时上下文
│   ├── trusted_helper.py    # 可信助手请求分发
│   └── schemas/v0.1/         # JSON Schema 文件
├── specs/v0.1/               # 协议 Schema（WorkOrder/Grant/Receipt/Acceptance）
├── tests/                    # 2283 项一致性测试
├── docs/                     # 文档（状态、演示日志、离线验签说明）
├── supply-chain/             # 可信构建镜像 + 候选清单
├── pyproject.toml            # 打包元数据
└── requirements-lock.txt     # 锁定依赖
```

---

## 当前状态

**已实现并验证（公开快照）：**

- 四类协议对象模型、RFC 8785 JCS + Ed25519 签名、六角色身份绑定
- SQLite 权威账本、Root/child Grant 原子签发与撤销、配额回放
- 纯事前授权：工具调用 / 人工决策 / 回滚三类 PolicyDecision
- 因果回放层 + 策略回放层 + 五输入离线验证器
- group-aware 证据 staging、原子提交、no-replace 发布、崩溃恢复
- 首个 Verifier `run_tests` 可信协调切片（含真实子进程崩溃注入验证）
- 确定性 CompositionReport 与 `owp.compose_proof` 原子合成事务
- 原子 final-acceptance 请求、无密钥外部签名草稿与 Acceptor 签名验收提交
- Acceptor 拒绝路径：同权威 Acceptor 签名的 AcceptanceRejectionReceipt
- 独立 Verifier 结果与确定性 recomposition
- deny 收据生产入口（`produce_deny_receipt`）
- CLI（`owp status` / `owp run-tests` / `owp repo-read`）
- MCP stdio 传输层
- AgentTeams TCP 网络客户端 + 执行适配层
- Docker 生产执行器（STARTED_UNCONFIRMED 恢复）
- Rich #4196 完整五角色端到端演示（Acceptor TCP 签名 + 离线验签）
- Dify #33013 完整五角色端到端演示（AI 应用平台类，跨项目类型通用性验证）
- **全量测试：2283 passed、0 failed、7 skipped**

**尚未完成：** 其他 ToolCall handler 与 evidence publication 的调用闭包、
正式赛事提交。

> 我们把「尚未完成什么」写得和「已经完成什么」一样清楚。
> 这不是谦虚，这是协议项目应有的证据标准。

详细实现清单与边界声明见 [docs/status.md](docs/status.md)。

---

## 演示

### M2：Rich #4196（开发者工具类）

基于真实开源 Issue [Textualize/Rich #4196](https://github.com/Textualize/rich/issues/4196)，
并固定到上游提交 `9d8f9a372cc5916fd4781fec207ced7ddac2f08f`，展示完整
五角色工作流：

Manager 签发最小权限 → Developer 在受限工作区修改代码（repo_read + apply_patch）→
越权路径在执行前被拒绝 → Verifier 运行固定测试并形成独立证据 → 局部测试通过
为何不自动等于最终接受 → 独立 Verifier 结果与 recomposition → Acceptor 基于
完整证据链作出人工验收（Acceptor 子进程 TCP 签名模拟）→ 离线 bundle 验签。

Rich 及其源码仍归属于原权利人；OpenWorkProof 只拥有自有协议和任务封装。

### M3：Dify #33013（AI 应用平台类）

基于真实开源 Issue [langgenius/dify #33013](https://github.com/langgenius/dify/issues/33013)，
固定到上游提交 `9f7bea37e`。Bug 发生在 Dify 的 QuestionClassifierNode 节点中：
用户在工作流中加问题分类器节点后执行时直接 `TypeError` 崩溃——一行修复将参数从
`structured_output_schema` 更新为 `json_schema`。

Dify 是面向终端用户的 AI 工作流平台，与 Rich 的开发者工具属性完全不同。
该验证证明了 OpenWorkProof 协议的**跨项目类型通用性**：同样的九步五角色证据链
同样适用于用户产品层的修复，且功能层额外验证了 bug 的真实复现和上游修复的有效性。

---

## 路线图

1. ~~接入真实无网执行器的稳定 execution ID 与启动/结果回执~~（已完成）
2. ~~完成人工决策、回滚和终止策略 API~~（已完成）
3. ~~独立结果执行 episode 与五维 recomposition → proof_ready~~（已完成）
4. ~~完成 CLI、MCP Sidecar 和 AgentTeams 集成~~（已完成）
5. ~~完成 Rich #4196 自包含演示及外部独立验收~~（已完成）
6. ~~完成 Acceptor 拒绝路径、真实外部 Acceptor 复现~~（已完成）
7. ~~完成 deny 收据生产入口~~（已完成）
8. ~~完成 Dify #33013 自包含演示及跨项目类型通用性验证~~（已完成）
9. 剩余：其他 ToolCall handler 与 evidence publication 的调用闭包、正式赛事提交。

---

## 参与方式

项目仍处于协议和 MVP 开发阶段。当前适合参与的方向包括：

- 协议对象与一致性测试
- 授权衰减和配额重放
- 可验证构建与证据包
- MCP/Agent 框架适配
- 真实开源 Issue 的任务封装
- 安全、隐私和数据治理审查

仓库采用 Apache-2.0 许可证。贡献流程与贡献者协议仍在制定中，
欢迎先通过 GitHub Issue 提出建议。

## 项目主体

- 技术 Owner：dengyier（当前兼任 Maintainer、Manager、Acceptor）
- 版权主体：成都星火领航科技有限公司

---

## 愿景

OpenWorkProof 希望让 Agent 工作从「可以生成结果」，迈向：

> 可以被授权，可以被约束，可以被验证，可以被接受，
> 也可以在证据不足时被拒绝。

OpenWorkProof 不提高 Agent 的智力，而是为 Agent 增加进入社会协作所需的
责任结构。
