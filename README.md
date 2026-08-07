# OpenWorkProof

> Agent 可以生成结果，但凭什么交付？
> Agent Work Contracts and Verifiable Execution Protocol

项目地址：https://github.com/dengyier/OpenWorkProof
当前版本：0.1.0（开发中）
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

## 为什么是现在

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

---

## 工作原理

四类协议对象构成完整的工作级证明链：

```
WorkOrder            CapabilityGrant        ActionReceipt          AcceptanceReceipt
工作契约              能力授权               行动凭证               验收凭证
冻结目标/路径/工具/   可签名、可衰减、        每次执行绑定授权判断、   证据覆盖 + 因果完整 +
配额/验收条件    →    不可扩权的授权    →    配额变化与证据引用  →   独立性披露 + 人工决定
```

技术原则：

- **Proof-Carrying Work**：动作必须携带机器可检查的授权与结果证据
- **No-Cloning Authority**：子授权只能衰减或消费，不能复制出等价或更大的权限
- **Multi-Scale Proof Composition**：局部凭证只有在因果完整、证据维度覆盖、
  相关性披露和全局条件同时满足时，才能组合成可接受的整体证明
- **Fail Closed**：无法验证的权限、签名、历史、状态或证据一律不得解释为成功
- **离线第三方复核**：`validate_grant_chain` 支持第三方在不接入任何一方
  系统的情况下，验证完整签名授权历史

---

## 当前状态

**已实现并验证（公开快照）：**

- 四类协议对象模型、RFC 8785 JCS + Ed25519 签名、六角色身份绑定
  （Maintainer/Manager/Developer/Verifier/Sidecar/Acceptor，Acceptor 独立密钥）
- SQLite 权威账本、Root/child Grant 原子签发与撤销、配额回放
- 纯事前授权：工具调用 / 人工决策 / 回滚三类 PolicyDecision
- 因果回放层 + 策略回放层 + 五输入离线验证器
- group-aware 证据 staging、原子提交、no-replace 发布、崩溃恢复
- 首个 Verifier `run_tests` 可信协调切片（含真实子进程崩溃注入验证）
- 确定性 CompositionReport 与 `owp.compose_proof` 原子合成事务
  （Manager 发起收据 + 报告 + proof_composed 收据一次提交）
- 原子 final-acceptance 请求、无密钥外部签名草稿与 Acceptor 签名验收提交
  （proof_ready → awaiting_human → accepted，本地合成 Acceptor 验证）
- Acceptor 拒绝路径：同权威 Acceptor 签名的 AcceptanceRejectionReceipt
  原子提交 awaiting_human → rejected（四种闭式拒绝理由、与 accepted
  互斥终态、COMMIT-ACK 回读、离线双路径验签与篡改拒绝）
- 独立 Verifier 结果与确定性 recomposition：证据不完整的首份报告保持
  不可变，独立执行的结果占专属证据槽位（槽位与状态一对一映射；
  TIMEOUT/OUTPUT_LIMIT/DISK_LIMIT 失败收据精确回放且可新签名重试，
  失败收据零 EvidenceRef），Manager 显式 recomposition
  在五维证据链闭合后到达 `proof_ready`（双报告离线验签、一一对应
  绑定与报告/收据/关联因子/公钥/账本表篡改拒绝、STARTED_UNCONFIRMED
  恢复与锁释放故障保持提交均已覆盖）
- **全量测试：2271 passed、7 skipped、2 既有失败**（非 required-live 本地模式；
  required-live Docker 模式含 candidate-inventory 供应链门，历史计数
  2226 passed、0 failed、0 skip，需候选库存对齐 HEAD 后重跑确认最终数）

**尚未完成：** deny/rollback 生产事务、真实外部 Acceptor 的人类签署
（本地子进程/TCP 验证已完成，外部个人复核属线下事件）、正式赛事提交。
CLI、MCP 传输层、Docker 生产执行器、Acceptor 拒绝路径、独立结果
（independent-result）episode 与五维 recomposition 链均已实现并验证
（见上方能力清单与 docs/status.md 的验证记录）。

> 我们把「尚未完成什么」写得和「已经完成什么」一样清楚。
> 这不是谦虚，这是协议项目应有的证据标准。

详细实现清单与边界声明见 [docs/status.md](docs/status.md)。
协议 Schema 见 [specs/v0.1](specs/v0.1/)。

---

## 演示（已完成，可复现）

首个演示基于真实开源 Issue [Textualize/Rich #4196](https://github.com/Textualize/rich/issues/4196)，
并固定到上游提交 `9d8f9a372cc5916fd4781fec207ced7ddac2f08f`，展示完整
五角色工作流：

Manager 签发最小权限 → Developer 在受限工作区修改代码（repo_read + apply_patch）→
越权路径在执行前被拒绝 → Verifier 运行固定测试并形成独立证据 → 局部测试通过
为何不自动等于最终接受 → 独立 Verifier 结果与 recomposition → Acceptor 基于
完整证据链作出人工验收（真实外部 Acceptor 子进程 TCP 签名）→ 离线 bundle 验签。

该演示端到端可复现（test_delivery_m2，5 测试），完整记录见
[docs/superpowers/2026-08-07-rich-4196-demo-log.md](docs/superpowers/2026-08-07-rich-4196-demo-log.md)。
Rich 及其源码仍归属于原权利人；OpenWorkProof 只拥有自有协议和任务封装。

---

## 快速开始

环境要求：Python 3.12 · Git · macOS 或 Linux

```bash
git clone https://github.com/dengyier/OpenWorkProof.git
cd OpenWorkProof
python3.12 -m venv .venv
./.venv/bin/python -m pip install -r requirements-lock.txt
./.venv/bin/python -m pytest -q
```

说明：CLI（`owp status` / `owp run-tests` / `owp repo-read`）与 MCP stdio
传输层已实现；不应把测试通过理解为交付验证签署、独立验收或赛事提交
已经完成。赛事交付材料见 [docs/superpowers/plans/2026-08-07-openworkproof-delivery-validation-plan.md](docs/superpowers/plans/2026-08-07-openworkproof-delivery-validation-plan.md)。

---

## 路线图

1. ~~接入真实无网执行器的稳定 execution ID 与启动/结果回执~~（已完成：
   DockerRunTestsExecutor 生产入口 + STARTED_UNCONFIRMED 恢复）；
2. ~~完成人工决策、回滚和终止策略 API~~（已完成：Task 8B2/8B3 事前授权）；
3. ~~独立结果执行 episode 与五维 recomposition → proof_ready~~（已完成并验证，
   双报告离线验签与篡改拒绝已覆盖）；
4. ~~完成 CLI、MCP Sidecar 和 AgentTeams 集成~~（已完成：CLI、MCP stdio、
   execution_adapter、真实 TCP 团队网络客户端）；
5. ~~完成 Rich #4196 自包含演示及外部独立验收~~（已完成：M2 五角色 9 步
   证据链，外部 Acceptor 子进程签名 + 离线验签）；
6. ~~完成 Acceptor 拒绝路径、真实外部 Acceptor 复现~~（已完成：拒绝终态
   事务 + M1 外部 Acceptor 端到端）；
7. 剩余：deny/rollback 生产事务、真实外部 Acceptor 人类签署（线下事件）、
   正式赛事提交。

---

## 参与方式

项目仍处于协议和 MVP 开发阶段。当前适合参与的方向包括：

- 协议对象与一致性测试；
- 授权衰减和配额重放；
- 可验证构建与证据包；
- MCP/Agent 框架适配；
- 真实开源 Issue 的任务封装；
- 安全、隐私和数据治理审查。

仓库采用 Apache-2.0 许可证。贡献流程与贡献者协议仍在制定中，
欢迎先通过 GitHub Issue 提出建议。

## 项目主体

- 技术 Owner：dengyier
- 独立 Acceptor：待定（当前不绑定真实个人）
- 版权主体：成都星火领航科技有限公司

---

## 愿景

OpenWorkProof 希望让 Agent 工作从「可以生成结果」，迈向：

> 可以被授权，可以被约束，可以被验证，可以被接受，
> 也可以在证据不足时被拒绝。

OpenWorkProof 不提高 Agent 的智力，而是为 Agent 增加进入社会协作所需的
责任结构。
