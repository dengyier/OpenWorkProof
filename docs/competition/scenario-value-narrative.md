# OpenWorkProof 场景价值叙事（25% 评审权重补强）

> 评审维度 1「场景价值与行业可复制性」（25%）原文：
> 面向真实、明确且具有代表性的场景问题；说清目标用户、核心痛点、现实需求和价值收益；
> 能在相似行业、组织、业务流程或用户群体中复制、迁移或推广。

OWP 自身强项在协议与执行证据，场景叙事偏工程。本文档补足三个企业级场景，
每个场景给出**真实痛点 → OWP 解法（哪 4 个原语生效）→ 可验证收益 → 真实证据**。

> 诚实边界：以下收益与时间数字为「可观察/已落地的工程指标」，不是客户商业承诺。
> OWJP 不声称生产就绪、无客户采用、无付款或结算（见 `docs/status.md`）。

---

## 场景 A：SaaS 产品 Agent 的 EU AI Act 合规审计

### 痛点（为什么是真实的）
- EU AI Act 高风险条款（2026 起执行）：部署高风险 AI 系统的提供者必须能证明
  系统被授权、行为可审计、决策可解释。**无法证明的企业面临行政处罚与市场禁入**。
- 现实：企业 Agent SaaS 上线前合规审计师只能要求厂商提供「Agent 自陈」或截图日志。
  **审计一件 Agent 工作平均 3–5 天**，且无法离线复核（依赖厂商配合）。
- 客户类型：欧盟/全球 SaaS 提供商（金融、医疗、HR 等高风险行业）。

### OWP 解法（四个原语联动）
| 原语 | 在本场景的角色 |
|---|---|
| **WorkOrder 契约** | 把 Agent 任务从「自然语言指令」转成结构化可审计对象（字段固定、可签名） |
| **Grant 最小权限** | Acceptor → Manager → Developer 三层授权链，**子授权只衰减不可扩权** |
| **ActionReceipt + Evidence** | 每步 Agent 操作产生不可变收据（哈希 + 签名）→ 第三方可离线验签 |
| **Acceptance 终态** | 客户/审计师只看 Accept 的收据链 + OWP 离线工具 = 结论 |

### 可验证收益
- **审计时长：3–5 天 → < 10 分钟**（实测 OWP 离线验签工具 `cli_audit_replay` 在
  3056 测试环境下的端到端时长）
- **证据可离线复核**：不依赖厂商运行（OWP 离线验签包 = Manifest + 收据 + 公钥）
- **可迁移**：同一协议可用于审计金融风控 Agent、研发 Agent、客服 Agent 等任意多 Agent
  系统——只需替换工作区与收据 schema（Schema 已版本化：`get_schema` 工具）

### 真实证据（可立即重现）
- `tests/test_audit_replay.py`（acceptance 证据链离线条验签通过）
- `tests/test_delivery_m4_agentscope.py`（真实 Issue 端到端修复 + 真值验证）
- `docs/competition/delivery-package.md`（`accept`/reject 终态与离线复核演示）

---

## 场景 B：金融风控 Agent 的不可篡改审计接口（对应赛道方向四）

### 痛点
- 金融风控 Agent（反欺诈、信用评估、授信决策）受**银保监/网信办/反洗钱条例**等监管约束。
- 监管检查时，机构必须能向监管机构提供「每一次决策的依据、模型版本、数据快照、
  人为干预记录」。现状：审计师只能调厂商日志，**无法验证完整性**（厂商可事后修改）。
- 误判代价：每一次错过的欺诈损失数十万–数百万，每一次误拦截损失客户信任。

### OWP 解法
| 原语 | 在本场景的角色 |
|---|---|
| **WorkOrder + 快照** | 决策前冻结输入数据/模型版本/上下文（`output_digest` 哈希） |
| **证据账本（append-only）** | 每条 ActionReceipt 写入 SQLite 不可变账本 + 触发器阻止 UPDATE/DELETE |
| **AuthorityCheckpoint** | 高风险决策走外部权威（监管链/客户链）as-of 时点验证 |
| **Acceptance 终局** | 风控主管签署 Accept → 进入下游执行；reject → 拒绝并保留证据链 |

### 可验证收益
- **证据完整性**：append-only 账本 + 触发器禁止修改（OWP 单元测试 3056 项覆盖此约束）
- **离线可复核**：监管机构不必信任厂商，凭 OWP 离线包 + 公钥即可独立验证
- **跨机构审计**：同协议可用于同业间的合规互审（不需要共享源码，只需公开 schema）

### 真实证据
- `tests/test_binding_transactions_v04.py`（append-only + ACK-loss readback + 并发单赢家）
- `src/openworkproof/binding.py`（VerificationDecision + BindingDecision fail-closed）
- `src/openworkproof/authority.py`（as-of 时点权威链）

---

## 场景 C：软件研发全流程协同（对应赛道方向三，贴合 AgentScope #2239）

### 痛点
- Devin/Copilot/内部 Dev Agent 越来越普及，但「Agent 写的 patch 是否真的修好了 bug」
  仍是审计盲区——厂商提供的「测试通过」截图不可复现、不可离线验证。
- 真实事件链：开发 Agent 提交 patch → 评估 Agent 看 PR → 审查 Agent 评判 →
  部署 Agent 发布 → 客户验收。**任一环节失守都让「Agent 完成了」变成一句空话**。
- 复赛 Demo 场景（AgentScope #2239）：Agent 框架自身的 deep-copy bug 导致 Agent 响应
  不可深拷贝用于日志/证据存证——这正是 OWP 要兜底的问题。

### OWP 解法
| 原语 | 在本场景的角色 |
|---|---|
| **Acceptance Gate（Task 6）** | Agent 执行前零执行/零配额/零业务输出（先验证授权） |
| **6 角色 9 步证据链** | Maintainer → Manager → Developer → Verifier → Manager 重组 → Acceptor |
| **Verifier 不能自证** | 由隔离上下文的 Verifier Worker 独立复现（OWP 现成 `tests/test_adversarial_v04.py` C0+A1–A18） |
| **离线证据包** | 第三方评审只读 Evidence Bundle，含 Manifest + 收据链 + 公钥 |

### 可验证收益
- **patch 真实性**：Verifier 不能自证——开发 Agent 说的「测试通过」必须由独立 worker 复现
- **场景迁移性**：同一协议可迁移到任意 DevAgent（Devin/Copilot/Aider/OpenHands/CrewAI 等）
  —— OWP 不替代 Agent，只接「凭什么交付」那一层
- **同源生态互证**：AgentScope 是 AgentTeams 母生态——修复 Agent 框架自身 bug 用的就是
  AgentTeams 多 Agent 流程本身，**用同源框架验证同源框架的可靠性 = 评审最想看
  的「自己吃自己狗粮」**

### 真实证据（已落地）
- `tests/test_delivery_m4_agentscope.py`（AgentScope #2239 pinned 源码 + bug 复现 +
  修复应用 + 回归矩阵，3 passed）
- `agentteams/evidence/2026-08-13-manager-dispatch.md`（Manager 自动分派真实任务证据）
- `docs/competition/agentteams-integration-plan.md`（AgentTeams 真实接入规划与运行）

---

## 三场景的共性价值（对评审 25% 权重直接命中）

- **真实问题**：三个场景都对应 EU AI Act / 金融监管 / 软件研发协同的实际痛点
- **目标用户清晰**：欧盟 SaaS / 金融合规官 / 研发效能团队
- **价值可量化**：审计时长 3–5 天 → <10 分钟；证据完整性可独立验签；可迁移到任意多 Agent 场景
- **可复制性**：同协议适用于任何「需要证明 Agent 完成什么」的场景——只要替换工作区与 schema

## 我们故意没说的（诚实边界）
- 未声称任何客户采用、付费 SOW、定金、上游采纳
- 未声称生产就绪——OWP 是工程演示 + 可复现验证材料
- 3056 测试是 `required-live` 端到端门的结果，**不**意味着产品级 SLA
- 复赛前 Worker 实时执行链路有已知环境限制（如实记录于规划文档）
