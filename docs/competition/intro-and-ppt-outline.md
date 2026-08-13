# OpenWorkProof — 参赛作品简介与方案大纲

> 赛事:世界人工智能开源大赛 · Agent Infra(新智基座)赛道
> 初赛提交:作品简介(500 字)+ 方案 PPT

---

## 一、作品简介(约 500 字)

**项目名称:OpenWorkProof —— Agent 工作契约与可验证执行协议**

**问题与场景。** 多 Agent 走向生产,最大瓶颈是责任、授权、证据与验收:
Agent 说「我完成了」,却没有一层能回答——工作依据什么授权?每步是否在
授权和配额内?测试、补丁、报告是否形成完整因果链?谁有权作最终接受或
拒绝?纠纷时第三方能否离线复核全部事实?Gartner 预测 2026 年底 40%
企业软件嵌入 AI Agent,EU AI Act 高风险条款已生效,无法证明「Agent 被
授权、被约束、可问责」的企业面临法律风险。

**核心方案。** OpenWorkProof 是 Agent 工作的契约、授权、证据与验收协议层,
以 AgentTeams 为协同设计基点,六个职能 Agent(Maintainer/Manager/
Developer/Verifier/Sidecar/Acceptor)构成端到端闭环:Manager 按最小权限
拆解任务并签发仅衰减的 child Grant;Developer 在受限工作区执行
repo_read/apply_patch/run_tests;Verifier 在隔离上下文独立复现;证据
五维闭合后由 Acceptor 作出 accepted/rejected 终态;不可变收据链写入
SQLite 账本,第三方可凭证据包离线验签,高风险动作支持人工确认与回滚。

**创新与差异化。** 现有 Agent 信任基础设施聚焦身份层与支付层;OpenWorkProof
补足「工作凭什么被授权、过程凭什么可信、结果凭什么被验收」的契约层。
核心机制:No-Cloning Authority(子授权只衰减不可扩权)、Proof-Carrying
Work、Fail Closed、离线第三方复核。

**复用价值与进展。** 8 个可复用 Skill;required-live 全量测试 3056
passed、0 failed、0 skipped;AgentTeams(hiclaw)真实接入已跑通——Docker
部署 + Matrix 房间协同 + 双适配器(agt 管理面 / Matrix 执行面)程序化
闭环,Manager 已自动分派真实修复任务(证据存档);基于 AgentScope
(AgentTeams 母生态框架)真实 Issue #2239 的可复现修复演示(离线测试
3 passed,含 deepcopy 崩溃复现与回归矩阵);MCP/CLI 接入层与候选镜像
供应链门全部实现;交付物冻结签署并离线可验签,材料齐备。

---

## 二、方案 PPT 大纲(初赛)

### 封面
OpenWorkProof —— Agent 工作契约与可验证执行协议
(副题:授权 / 执行 / 验证 / 审计 的端到端闭环)

### 01 场景与价值
- 多 Agent 生产化的核心痛点:授权不明、证据缺失、验收无据
- 市场拐点:Gartner 40% 企业软件嵌入 Agent;EU AI Act 合规压力
- 目标用户:企业 IT、DevOps、FinOps、安全审计、研发效能团队

### 02 方案设计
- 六职能 Agent 角色编排(Identity 清单见附录)
- 四对象协议:WorkOrder → CapabilityGrant → ActionReceipt → AcceptanceReceipt
- AgentTeams(hiclaw)真实接入:Matrix 房间协同 + 双适配器
  (agt 管理面 / Matrix 执行面),任务经 Matrix 提交、Manager 自动分派
- 端到端闭环:任务输入 → 拆解 → 执行 → 验证 → 证据 → 审批/回滚

### 03 Skill 与工具集成
- 8 个 Skill 清单(S1–S8,输入输出/失败处理/安全边界/复用价值)
- MCP 工具集成(owp_status / owp_run_tests / owp_repo_read)
- 上下文增强:共享状态(SQLite 账本)+ 轨迹(收据链)≥2 项
- 可观测:结构化日志 + 执行证据 + 离线验签

### 04 可行性与落地计划
- 工程证据:3056 passed、0 failed、0 skipped(required-live);
  AgentScope #2239 真实 Issue 多 Agent 演示(分派证据 + 离线真值验证)
- 真实场景链路:9 步证据链 + 离线 bundle 验签
- 落地路径:运维闭环、研发协同、风控审计三个行业场景
- 开放/开源:Apache-2.0、协议 Schema 公开、候选镜像供应链可复现

### 附:支撑材料索引
- Agent Identity 清单:docs/competition/agent-identity.md
- Skill 清单:docs/competition/skill-list.md
- 交付验证计划与材料清单:docs/superpowers/plans/2026-08-07-openworkproof-delivery-validation-plan.md
- 演示记录:docs/superpowers/2026-08-07-rich-4196-demo-log.md
- AgentTeams 接入规划:docs/competition/agentteams-integration-plan.md
- AgentScope #2239 修复真值基准:tests/test_delivery_m4_agentscope.py
- 复赛代码包:agentteams/(YAML 资源 + 双适配器 + 分派证据 + README)
