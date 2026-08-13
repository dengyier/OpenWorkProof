# OpenWorkProof × AgentTeams(hiclaw) 真实接入规划

> 赛事:世界人工智能开源大赛 · Agent Infra(新智基座)赛道
> 目标:复赛(8.25–9.3)交付「可执行 AgentTeams 代码包 + 可运行 Demo」
> 版本:0.2.0(2026-08-13)
> 调研基准:agentscope-ai/AgentTeams main 分支(2026-08-11 docs 重构后)

---

## 1. 现状盘点:初赛假设 vs 复赛硬要求

初赛材料(docs/competition/)已将 AgentTeams 设为协同设计基点,但当前
工程假设的「AgentTeams 执行层」是**自研 TCP JSON-lines 协议**
(`team_network_client.py` 的 TeamNetworkClient/TeamNetworkService),并非
真实 AgentTeams。`team_network_client.py` 模块注释也明确承认:官方 SDK
`@alicloud/agentteams20260605` 仅提供 TS/Java/Swift/PHP 且为管理面,
Python 无执行面 SDK,故以自研协议过渡。

| 维度 | 初赛材料假设 | 真实 AgentTeams(复赛要求) |
|---|---|---|
| 部署 | 进程内/TCP 服务 | Docker 容器集群(controller/manager/worker) |
| 通信 | JSON-lines TCP | Matrix 协议(房间内 @mention) |
| 任务提交 | `dispatch` action | Matrix 房间发消息(无任务 REST API) |
| 资源管理 | 无 | REST API `:8090` + `agt` CLI + YAML |
| 凭证 | `OWP_TEAM_TOKEN` | Higress 网关 consumer token(Worker 不持真实密钥) |
| 可观测 | 无 | Matrix 房间全量可见 + 人类可随时介入 |

结论:**复赛必须把「自研 TCP 占位」替换为「真实 AgentTeams 接入」**,
否则代码包无法在评审侧运行。

---

## 2. 真实 AgentTeams(hiclaw)接入模型(调研事实)

来源:hiclaw.io + github.com/agentscope-ai/AgentTeams docs
(overview/quickstart/resource-management/usage)。

### 2.1 部署与形态

- 一键安装:`bash <(curl -sSL .../agentteams-install.sh)`,Docker Desktop/Engine,
  至少 2 CPU / 4 GB(多 Worker 建议 4 CPU / 8 GB)
- 核心容器:`agentteams-controller`(REST :8090)、`agentteams-manager`、
  `agentteams-worker`;管理界面 Element Web `http://127.0.0.1:18088/#/login`
- 依赖:LLM API key(Qwen / OpenAI-compatible,Manual Setup 可配 Base URL)

### 2.2 资源模型(YAML,`agentteams-apply.sh -f`)

- **Worker**:`model` / `runtime`(openclaw 默认) / `identity`/`soul`/`agents`
  / `skills[]` / `mcpServers[]` / `expose` / `channelPolicy` / `resources`
- **Team**:`workerMembers` + `role`(team_leader 恰一个 / worker)
- **Manager / Human**:角色与权限(permissionLevel/accessibleTeams)
- 管理面 REST:`GET/POST/PUT/DELETE /api/v1/{workers,teams,managers,humans}`

### 2.3 执行面(关键约束)

- **任务只能通过 Matrix 聊天提交**(管理员→Manager→Leader→Worker @mention),
  **没有任务提交/进度查询 REST API**
- 资源状态可查:`agt get worker <name>`(Running/Sleeping/Failed)
- Worker 技能:`spec.skills` 声明式或 Manager 对话分配;MCP Server 挂载于
  `spec.mcpServers`

---

## 3. 目标架构:AgentTeams 编排层 × OWP 验证/审计层

```
                    ┌─────────────────────────────────────────────┐
                    │             AgentTeams(hiclaw)              │
                    │  Matrix 房间(全量可见、人类可介入)            │
                    │  Manager ──拆解/授权──▶ Team Leader ──▶ Workers │
                    │                                            │
                    │  Worker A: dev-worker   (修复执行, 持 OWP 库)  │
                    │  Worker B: verifier-worker(独立复现, OWP 验证) │
                    └──────┬──────────────────────────────┬───────┘
                           │ REST :8090(资源)              │ Matrix(任务/事件)
                   ┌───────▼──────────────────────────────▼───────┐
                   │          OWP 接入层(新增, 替代自研 TCP)        │
                   │  AgentTeamsControllerClient  AgentTeamsMatrixClient │
                   └───────┬──────────────────────────────┬───────┘
                           │ 验证/绑定/审计                  │ 证据提取
                   ┌───────▼──────────────────────────────▼───────┐
                   │      OpenWorkProof 协议栈(全部复用, 零改动)    │
                   │  VerificationDecision / BindingDecision       │
                   │  证据账本(append-only) / AuthorityCheckpoint  │
                   │  离线包(隐私视图) / MCP Server(验证工具)        │
                   └──────────────────────────────────────────────┘
```

分工:AgentTeams 负责**任务拆解、上下文传递、协同执行、状态流转**(Matrix
透明可见);OWP 负责**结果验证、执行证据沉淀、审批/回滚门、审计与离线复核**
——恰好补全赛道闭环八步中 AgentTeams 不提供的部分,形成差异化。

---

## 4. 接入点映射(现有代码 ↔ 真实 AgentTeams)

| 现有组件 | 角色 | 变更 |
|---|---|---|
| `AgentTeamClient` Protocol | 传输无关契约 | **保留**;真实语义下重定义为两个适配器的共同接口 |
| `LocalTeamClient` | 参考实现 | 保留(单测/离线) |
| `TeamNetworkClient`(自研 TCP) | 过渡占位 | **弃用或降级为 dev-only**;由真实适配器替换 |
| `TeamNetworkService`(自研 TCP 服务) | 过渡占位 | 保留仅用于离线测试,不进复赛代码包 |
| `TeamExecutionAdapter` | kind→协调器 | 保留 repo_read/run_tests/status;新增 `verify` kind(OWP 验证) |
| `TeamTask` | 任务单元 | 保留字段;payload 扩展 Matrix 消息/执行结果 |

### 4.1 新增适配器 A:`AgentTeamsControllerClient`(管理面,REST :8090)

- 职责:资源 CRUD + 状态查询(YAML 应用/`agt` 等价)
- 接口:get/create/delete worker/team/human;get status;apply YAML
- 复用 `TeamNetworkConfig` 的 env 配置模式(新增 `OWP_AGENTTEAMS_API_URL`)

### 4.2 新增适配器 B:`AgentTeamsMatrixClient`(执行面,Matrix)

- 职责:登录(installer 输出的账号)→ 加入房间 → 发消息(@mention Manager/
  Worker)→ 订阅房间 timeline(任务流、结果、证据引用)
- 协议:Matrix client-server API(sync / rooms/{id}/send/…),Python 无官方
  执行面 SDK → 基于 `matrix-nio`(开源 Python SDK)或裸 REST 封装
- 证据提取:Worker 在房间回传的文件/链接/结果 → OWP 证据提取器 → 账本

### 4.3 OWP 嵌入形态(组合推荐)

1. **Verifier/Auditor Worker**:在 AgentTeams 中注册 `owp-verifier` Worker
   (runtime openclaw),identity 定义为独立验证者,skills 挂 OWP 验证能力;
   结果用 OWP 库(VerificationDecision)复现 → 满足「Verifier 不能自证」
2. **OWP 审计 bot**:OWP 程序以 Matrix client 身份常驻任务房间,独立复核
   Worker 输出(与 Worker 内验证**双通道**),BindingDecision + 账本沉淀 +
   审计报告回写房间 → 人类可随时介入审批(对应赛道「审批/回滚/审计」)
3. **MCP Server**:OWP 验证工具(复用 mcp_transport 的 `owp_validate_*` /
   `owp_explain_binding_decision`)挂到各 Worker `spec.mcpServers` → 满足
   赛道 MCP 推荐项,任意 Agent 可调用 OWP 验证能力

---

## 5. 分阶段实施

### Phase 0(8.13–8.16 初赛提交)——不变更材料

- 现有 500 字 + PPT + Identity + Skill 清单直接提交(初赛以设计为主)
- 可选:在材料中把「自研 TCP 协议」一句话改为「AgentTeams 真实接入于复赛
  交付可执行代码包」,避免评审对自研协议产生疑问

### Phase 1(8.17–8.24 初赛评审期)——接入基座(可运行,可演示)

> 状态:全部完成(2026-08-13)。DeepSeek v4-pro 部署、2 Worker + Team Running、
> 双适配器 14 测试通过、Matrix 程序化闭环(pong 往返)已验证。

| 步骤 | 交付物 | 验收 |
|---|---|---|
| 1. 部署 AgentTeams | Docker 容器 + Element 登录 + agt 可达 | `agt get managers` 返回 default(deepseek-v4-pro) |
| 2. YAML 资源定义 | `agentteams/team.yaml`(dev-worker/verifier-worker + Team) | `agt get workers` 全部 Running |
| 3. 管理面适配器 | `AgentTeamsControllerClient` + 测试 | `agt -o json` 解析 + 状态查询测试通过 |
| 4. 执行面适配器 | `AgentTeamsMatrixClient` + 测试 | 登录/房间发现/发消息/读 timeline 测试通过 |
| 5. 最小闭环 | Manager 建 Worker → Matrix 任务 → 结果回传 | 程序化闭环验证:pong 精确回复 |

### Phase 2(8.25–9.3 复赛提交)——端到端 Demo

| 步骤 | 交付物 | 验收 |
|---|---|---|
| 6. 场景升级 | AgentScope #2239 缺陷修复升级为多 Agent(方向三:研发全流程协同) | Manager 拆解→dev-worker 修复→verifier-worker 复现→OWP 验证+账本+审批→审计报告 |
| 7. OWP MCP Server 接入 | Worker `spec.mcpServers` 指向 OWP | 任意 Worker 可调用 `owp_validate_*` |
| 8. 审计 bot | Matrix 常驻 bot 独立复核 + 回写报告 | 双通道验证一致;篡改被抓 |
| 9. 代码包 | `agentteams/`(YAML+适配器+README+运行证据)+ Demo 视频 | 评审可复现:单命令部署+跑通场景 |

---

## 6. 复赛 Demo 场景(推荐:方向三 软件研发全流程协同)

> 2026-08-13 更新:场景项目定为 **AgentScope #2239**(agentscope-ai/agentscope,
> 阿里通义生产级 Agent 框架, 28.9K stars)。
> 理由:
> 1. **同源生态叙事**:AgentScope 是 AgentTeams(HiClaw)的母生态(赛道必选
>    框架),「用 OWP 验证协议修复 Agent 框架自身 bug,再用同源 AgentTeams
>    多 Agent 演示修复闭环」形成闭环叙事;
> 2. **真实未修复**:issue #2239(DictMixin.__getattr__ 抛 KeyError 而非
>    AttributeError → deepcopy/hasattr/getattr default 全崩)仍 open,
>    两条修复 PR(#2241/#2281)均未合并,可 pinned 当前 main(8f24009)复现;
> 3. **教科书级可复现**:源码仅 6 行(_utils/_mixin.py),`deepcopy()` 空
>    ChatResponse 即崩,4 行修复,回归矩阵(deepcopy/hasattr/getattr default/
>    mapping KeyError 保留)清晰;
> 4. **证据叙事钩子**:「Agent 响应无法被安全深拷贝用于日志/证据存证」——
>    正是 OWP 执行证据领域的核心问题。
> 备选:Dify #33013(已有 M3 材料, test_delivery_m3_dify.py 7 passed)。

```
缺陷聚合(Manager) → 根因定位(dev-worker, OWP repo_read)
  → 修复生成与执行(dev-worker, OWP apply_patch: DictMixin.__getattr__)
  → 测试验证(verifier-worker, OWP run_tests 独立复现: deepcopy/hasattr/getattr)
  → 发布确认(OWP VerificationDecision + BindingDecision + 人类审批门)
  → 复盘与知识沉淀(OWP 账本 + 审计报告,离线可复核)
```

差异化叙事:AgentTeams 提供**透明可介入的协同**,OWP 提供**机器可检查的
执行凭证**(授权链/证据链/验收终态/离线复核)——评审关注的 25% 协同 +
25% Skill + 20% 工程验证权重均有现成材料支撑。

---

## 7. 风险与诚实边界

| 风险 | 缓解 |
|---|---|
| LLM API key 依赖(Qwen/OpenAI-compatible) | 需用户提供;Manual Setup 支持自定义 endpoint |
| Docker 资源(≥4C/8G 多 Worker) | 本机 Docker Desktop 已可用;可先 2 Worker 起步 |
| 任务无 REST API(仅 Matrix) | Matrix 事件订阅;agt 查资源状态互补(等价契约,赛道允许) |
| Matrix 外部 client 兼容性 | Element Web 即外部 client,可行性已由官方 quickstart 证明 |
| 官方 SDK 无 Python 执行面 | 自研 Matrix/REST 客户端(等价集成契约,非重新设计工具链) |
| 任务状态查询受限 | 房间 timeline + 资源状态组合;演示叙事不夸大 |

诚实边界(不变):Demo 是工程演示,不声称生产就绪、客户采用、付款或结算;
AgentTeams 为第三方开源框架(Apache 2.0),OWP 仅做集成,不拥有其信任根;
执行凭证只证明「Agent 实际做的与记录判断一致」,不证明判断正确。

---

## 8. 待办(下一步)

1. [ ] 用户确认 LLM API key 提供方式(Qwen 或 OpenAI-compatible)
2. [ ] Phase 1 步骤 1–2:本地部署 AgentTeams + YAML 资源(需 Docker 4C/8G)
3. [ ] Phase 1 步骤 3–5:两个真实适配器 + 最小闭环
4. [ ] 可选:初赛材料中一句话更新接入表述
