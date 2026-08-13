# STORY — OpenWorkProof 参赛方案（GOAI Agent Infra 赛道）

## 叙事主线
**问题**（Agent 生产化缺"凭什么交付"）→ **方案**（契约/授权/证据/验收协议层）→
**验证**（真实接入 AgentTeams + 真实 Issue 修复 + 3056 测试）→ **诚实边界**。

## 受众
大赛评审（技术 + 商业视角）：看场景价值（25%）、多 Agent 协同（25%）、
Skill 工程（25%）、工程落地（20%）、开源（5%）。

## 页面叙事（9 页）

| # | 页 | 叙事任务 | 关键内容 | 角色 |
|---|---|---|---|---|
| 01 | 封面 | 定调：Agent 交付凭什么可信 | 项目名 + 赛道 + 副题 | hero |
| 02 | 问题与场景 | 痛点 + 市场拐点 | 授权不明/证据缺失/验收无据；Gartner 40%；EU AI Act | supporting |
| 03 | 核心方案 | 定位：协议层（非框架/非工具） | 六职能 Agent + 四对象协议 + Proof-Carrying Work | supporting |
| 04 | 协议设计 | 机器可检查的闭环 | WorkOrder→Grant→Receipt→Acceptance；状态流转图（SVG） | supporting |
| 05 | AgentTeams 真实接入 | 赛道必选框架的真实落地 | 3 Agent 分工 + Matrix 房间 + 双适配器 + 分派证据 | hero |
| 06 | 真实案例：AgentScope #2239 | 用真实 bug 证明协议 | bug 复现→修复→真值验证（离线 3 测试） | supporting |
| 07 | Skill 与工具集成 | Skill 必选项 | 8 Skills + MCP + 可观测 | supporting |
| 08 | 工程证据与可行性 | 数字说服 | 3056 passed/0 failed/0 skipped；供应链门；离线验签 | supporting |
| 09 | 诚实边界与开放计划 | 可信收尾 | 不声称付款/结算；Apache-2.0；复赛规划 | transition/end |

## 关键数字锚点
- **3**（职能 Agent：Manager/Developer/Verifier）
- **3056**（required-live 全量测试 passed）
- **0**（failed / skipped）
- **8**（可复用 Skill）
- **3**（M4 真值测试 passed，离线）
