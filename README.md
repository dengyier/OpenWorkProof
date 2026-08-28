# OpenWorkProof

<!-- mcp-name: io.github.dengyier/OpenWorkProof -->

<div align="center">
  <strong>中文</strong> | <a href="README_en.md">English</a>
</div>

> 让智能依人的目的而行动，让每一次行动经得起人的判断。

OpenWorkProof 是 AI Agent 工作契约与可验证执行协议。

它记录谁授权了任务、Agent 实际执行了什么、是否超出约定范围、验证者得出了什么结论，
以及验收者最终接受还是拒绝。每次工作都可以导出为一套签名证据包。第三方不需要接入
原系统，只凭证据包和公钥，就能独立验证整条工作链。

OpenWorkProof 不保证 Agent 的结果一定正确，也不替客户作出验收决定。它确保授权有来源、
执行有证据、验证与验收不会被混为一谈，并把接受、拒绝、撤销和申诉的权利留给人。

[安装](#五分钟开始) · [工作原理](#工作原理) ·
[Human Agency](#human-agency能力越强人的决定权越不能消失) ·
[DeepSeek Harness](docs/integrations/deepseek-harness.md) ·
[协议文档](docs/protocol/human-agency-profile-v0.1.md) ·
[English](README_en.md)

```text
本地候选版本: 1.4.0, 尚未发布
core focused: 77 passed / 0 failed / 0 skipped
plugin: 56 passed / 0 failed / 0 skipped
candidate: 186 passed / 0 failed / 0 skipped
required-live: 4333 passed / 0 failed / 0 skipped
许可证: Apache-2.0
```

公开发布状态请直接回读 [PyPI](https://pypi.org/project/openworkproof/) 与
[MCP Registry](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.dengyier%2FOpenWorkProof/versions/1.2.0)。
本地候选版本与公开版本是两件事。

## Agent 说 `完成了`，还缺什么

MCP 连接 Agent 与工具，A2A 连接 Agent 与 Agent。它们解决如何连接和通信，不能单独
证明一次工作是否获得授权、是否按约执行，以及最终由谁验收。

设想一家 AI 服务商让 Agent 修改客户的代码仓库。Agent 提交了补丁，也说测试已经通过。
客户仍然需要回答：

1. 谁授权 Agent 修改这个仓库？
2. 它是否只使用了允许的工具、路径、配额和期限？
3. 补丁、测试和报告是否来自同一次执行？
4. 验证通过是否被错误地写成客户已经接受？
5. 发生争议时，第三方能否在不接入双方系统的情况下复核事实？

日志能告诉人系统输出了什么，却很难独立证明授权、因果关系和最终验收。平台也不能只用
自己的数据库证明自己可信。

OpenWorkProof 把一次 Agent 工作变成一条可以带走、保存和复核的证据链：

```text
客户冻结任务与验收条件
        ↓
有权主体签署授权
        ↓
Agent 执行，每个重要动作留下签名凭证
        ↓
Verifier 独立验证证据与因果链
        ↓
Acceptor 独立接受或拒绝
        ↓
第三方离线复核完整结果
```

OpenWorkProof 不让 Agent 变得更聪明。它让 Agent 的工作更值得委托。

## OpenWorkProof 是什么

OpenWorkProof 是可以嵌入现有 Agent、CI、MCP 和多 Agent 编排器的开放协议层。
它把六类事实连接起来：

| 事实 | 回答的问题 |
|---|---|
| 工作目的与范围 | Agent 被要求完成什么 |
| 签名授权 | 谁允许它做这件事 |
| 事前决策 | 这个动作现在是否可以执行 |
| 行动凭证 | Agent 实际做了什么 |
| 独立验证 | 证据是否完整，结论是否成立 |
| 人工验收 | 谁最终接受或拒绝 |

最终交付的不是一份只能在原平台查看的日志，而是一套可离线验证的签名证据包。持有证据包
和公钥的第三方，可以独立复核授权来源、执行范围、证据摘要、验证结论和验收结果。

### 它不是什么

OpenWorkProof 不是 Agent OS，也不是新的模型或编排框架。它不负责替 Agent 规划任务，
也不声称能够判断所有业务结果是否正确。

Human Agency Profile 是授权边界，不是员工评分、绩效监控、法律责任转移、自动担责、资金托管或合规认证。

OpenWorkProof 也不托管资金，不执行付款，不代替法律仲裁。协议状态可以证明证据达到某个
阶段，但不能制造外部商业事实。

## 工作原理

一条完整工作链由以下对象组成：

```text
WorkOrder -> CapabilityGrant -> PolicyDecision -> ActionReceipt
          -> VerificationDecision -> AcceptanceDecision
```

| 对象 | 作用 |
|---|---|
| `WorkOrder` | 冻结目标、源版本、路径、工具、期限和验收条件 |
| `CapabilityGrant` | 由有权主体签署，只能缩小或消费，不能扩权 |
| `PolicyDecision` | 在工具执行前作出允许或拒绝决定 |
| `ActionReceipt` | 绑定请求、授权决定、执行结果和证据摘要 |
| `VerificationDecision` | 由独立 Verifier 对冻结范围和证据作出判断 |
| `AcceptanceDecision` | 由 WorkOrder 绑定的 Acceptor 接受或拒绝交付 |

协议使用 Ed25519 签名、规范化 JSON、追加式账本和内容摘要。修改 WorkOrder、授权、
receipt、证据、公钥或因果父集，离线回放都会失败并关闭流程。

详细 Schema 位于 [specs](specs/)，当前实现与历史快照位于
[docs/status.md](docs/status.md)。

## 六个角色，各自保留边界

| 角色 | 职责 |
|---|---|
| Maintainer | 初始化 WorkOrder，签发根授权 |
| Manager | 委派受限权限，发起工作与证明组合 |
| Developer | 在授权范围内读取、修改和运行测试 |
| Verifier | 使用独立密钥验证结果和证据 |
| Sidecar | 提供受信任的执行事实与 checkpoint |
| Acceptor | 独立签署接受、拒绝或权限 profile 变更 |

角色分离的目的不是增加组织层级，而是防止同一个 Agent 同时充当执行者、验证者和最终
验收者。系统可以自动化流程，但不能让权力边界在自动化中消失。

## Human Agency：能力越强，人的决定权越不能消失

`CapabilityGrant` 表示系统允许 Agent 使用哪些能力。`Human Agency Profile` 表示人愿意
让 Agent 自主使用这些能力中的哪一部分。真正有效的权限取以下三者的交集：

```text
WorkOrder 允许的范围
∩ CapabilityGrant 授予的能力
∩ active HumanAgencyProfile 中人的选择
```

Human Agency Profile 具有三个工程特征：

- **WorkOrder 绑定**：profile 不能被挪到另一项任务使用；
- **Acceptor 签名**：只有被指定的人类权威可以改变 active profile；
- **机器可验证**：执行前可以确定某个动作是 allowed、reserved 还是 denied。

`reserved` 动作不会先执行再提醒，而是在执行前返回
`AGENCY_HUMAN_DECISION_REQUIRED`。appeal 是签名复核请求，只记录异议，
不恢复或扩大权限。只有 Acceptor 签名的 transition 才能撤销当前 profile 或将其替换为另一个 Acceptor 签名的 profile。

完整定义见 [Human Agency Profile v0.1](docs/protocol/human-agency-profile-v0.1.md)，
可运行示例见 [examples/human_agency_profile_v01.py](examples/human_agency_profile_v01.py)。

## 验证与验收必须分开

`VERIFIED` 只说明 Verifier 按冻结范围和证据得出了验证结论。客户是否接受交付，必须由
WorkOrder 绑定的 Acceptor 独立决定。

OpenWorkProof 使用双签：Verifier 签署验证结果，Acceptor 再签署
`AcceptanceDecisionBindingV01`。该 binding 把 WorkOrder、Decision、
CompositionReport、验收请求和最终 receipt 精确连接起来。缺失 binding 时，系统拒绝
把两份彼此无关的有效签名拼成一次交付。

Acceptor 私钥不进入 AgentTeams 或 exporter。外部人工验收使用
`prepare → sign → commit`：

1. 系统生成不包含私钥的草稿；
2. 外部 Acceptor 独立签名；
3. 追加式事务提交签名对象；
4. 导出 Acceptance Bundle；
5. 第三方离线验证。

```bash
owp acceptance-bundle-build LEDGER SURFACE \
  --evidence-root PATH --output DIRECTORY

owp acceptance-bundle-verify DIRECTORY
```

退出码是闭合的：`ACCEPTED=0`、`REJECTED=2`、`operational=4`。
AgentTeams 的外部人工验收入口使用 `--acceptance-bundle DIRECTORY`，只读取外部目录并
调用同一个 verifier，不生成密钥、receipt 或 binding。

```text
VERIFIED != ACCEPTED != PAID/SETTLED/LEGAL AUDIT/ADOPTION
```

`REJECTED` 是可验证终态，不是系统错误，也不能写成交付成功。

## 验证完整性：验证结果本身也要经得起检查

“测试通过”不等于“该验证可信”。如果测试选择器漏掉了本应检查的对象，或者负向控制虽然
失败、却不是按预期原因失败，结论仍然不应进入 `VERIFIED`。

Verification Integrity v0.5 会冻结合格对象集合和负向控制的预期失败特征：

- `POPULATION_CAPTURE_FAILED`：实际选择没有覆盖约定的合格对象，结论关闭为 `UNKNOWN`；
- `CONTROL_FAILURE_SIGNATURE_MISMATCH`：负向控制的失败原因与登记特征不符，不能把这次失败当作有效证明；
- 只有人口覆盖和控制证据都成立时，系统才会根据证据给出 `VERIFIED`、`REFUTED` 或 `UNKNOWN`。

这套机制证明“结论由约定范围内的证据支持”，不证明业务结果永远正确。客户采用、付款、
法律效力和上游采纳仍是独立外部事实；没有相应证据时，状态就是 `not evidenced`。

## 五分钟开始

### 1. 从公开包安装

公开 PyPI 页面当前状态应以页面回读为准：

```bash
python -m pip install openworkproof
owp --help
```

### 2. 运行本地候选

本仓库中的 `1.4.0` 是尚未发布的本地候选。开发者可以从源码安装：

```bash
git clone https://github.com/dengyier/OpenWorkProof.git
cd OpenWorkProof
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
owp --help
```

### 3. 运行 Human Agency 最小示例

```bash
python examples/human_agency_profile_v01.py
```

预期输出包含：

```text
profile verified  : True
resolved status   : active
owp.repo_read     : delegated -> allowed
owp.apply_patch   : reserved -> AGENCY_HUMAN_DECISION_REQUIRED
```

该示例不写应用层文件或账本，也不输出私钥。

### 4. 验证离线包

已有 Surface Bundle 时：

```bash
owp surface-verify PATH
```

已有 Acceptance Bundle 时：

```bash
owp acceptance-bundle-verify DIRECTORY
```

完整离线验证说明见 [docs/offline-verification.md](docs/offline-verification.md)。

## 接入方式

| 入口 | 适合谁 | 从哪里开始 |
|---|---|---|
| GitHub Action | 已有 PR 交付流程的团队 | [integrations/github/action.yml](integrations/github/action.yml) |
| CLI | 本地验证、CI 和自动化脚本 | `owp --help` |
| MCP | 需要把 OWP 暴露为 Agent 工具的团队 | [MCP_SERVER.md](MCP_SERVER.md) |
| AgentTeams | Manager、Developer、Verifier 多角色协作 | [agentteams/README.md](agentteams/README.md) |
| DeepSeek Harness | 需要事前授权、独立复核与外部验收的代码变更 | [集成说明](docs/integrations/deepseek-harness.md) |
| Python API | 需要嵌入已有平台或服务 | [src/openworkproof](src/openworkproof/) |

GitHub Action 的 four-question 对应中文四问报告：

1. 验证了什么主张；
2. 看到了什么证据；
3. 执行受到什么约束；
4. 现在可以得出什么结论。

报告结论是 `VERIFIED`、`REFUTED` 或 `UNKNOWN`，并说明是否只达到
`READY_FOR_ACCEPTANCE`。它不会把协议结论写成客户已经接受或已经付款。

DeepSeek Harness 适配器当前是外部发布 READY 的本地候选，锁定
`DeepSeek Harness 0.1.1-rc.2`。Audit 只记录观察事实；Enforce 在工具执行前授权，并阻断
原生 `write`、`edit`、`bash`、`pwsh`、`str_replace_editor`、`cordis_define` 与
`cordis_run` 修改面。`/owp-verify` 只消费因果关联后的精确补丁
回执；真实 CLI 进程已完成账本回读、独立验证、无私钥验收草稿与离线导出，并在进程重启
后恢复同一已提交 receipt。上述本地预检不等于 npm 发布、外部复现、客户采用或
DeepSeek 官方背书。

## 当前可以复核的证据

以下是本地候选的工程证据，不是客户采用证明：

| 验证门 | 当前结果 |
|---|---|
| core focused | `77 passed / 0 failed / 0 skipped` |
| plugin | `56 passed / 0 failed / 0 skipped` |
| candidate | `186 passed / 0 failed / 0 skipped` |
| required-live | `4333 passed / 0 failed / 0 skipped` |
| AgentTeams | Manager、Developer、Verifier 三角色 live preflight 已通过（`http://127.0.0.1:18080`） |
| 离线验证 | Surface、Acceptance 与 Human Agency bundle 可独立回放 |
| 供应链 | candidate inventory、OCI/Docker 工件和哈希绑定已过门 |

required-live 全量门在 `OPENWORKPROOF_AGENTTEAMS_REQUIRED=1` 与
`AGENTTEAMS_HOMESERVER=http://127.0.0.1:18080` 下以 `0 failed / 0 skipped` 通过；
`AGENTTEAMS_MATRIX_TOKEN` 仅从本机 `agentteams-manager` 容器只读取得，不打印、不落盘。

Rich #4196、Dify #33013 和 AgentScope #2239 是自有演示与复现实验，用于验证不同项目
类型下的协议路径。它们不是客户案例，也不代表上游项目已经采用 OpenWorkProof。

```text
agentteams_live_environment: evidenced
agentteams_three_role_preflight: evidenced
agentteams_end_to_end_business_execution: not_evidenced
human_acceptance: not_evidenced
customer_adoption: not_evidenced
paid_sow: not_evidenced
deposit: not_evidenced
upstream_adoption: not_evidenced
```

## Verified Agent Delivery

`OpenWorkProof Verified Agent Delivery` 是协议之上的首个应用切片。它把一次 Agent 工作
组织成可独立验证、可由客户验收的交付事实。

```bash
owp delivery-case init CASE_DIR
owp delivery-case inspect CASE_DIR
owp delivery-case verify CASE_DIR
owp delivery-case export CASE_DIR --output-directory OUTPUT_DIR
```

`inspect` 从真实 Surface、Acceptance 和 Settlement 证据重新派生状态，不信任磁盘中
预写的结论。`export` 生成带确定性摘要和完整性 manifest 的第三方复核包。

`READY_FOR_SETTLEMENT_REVIEW` 只表示证据已经可以交给外部付款方复核，不表示付款或
结算已经发生。`BOUND` 表示协议对象已经形成确定绑定，也不表示付款、客户采用或法律
认可。

商业材料与准入边界见
[docs/commercial/verified-agent-delivery](docs/commercial/verified-agent-delivery/)。

## 开放协议与长期方向

OpenWorkProof 当前先解决一件小而具体的事：让一次 Agent 工作可以被独立验证和验收。
当不同组织之间积累了足够多可携带的履约事实，才可能进一步支持 Agent 服务的比较、
交易、争议处理和结算。

```text
单次工作可验证
        ↓
跨组织交付可验收
        ↓
履约事实可携带
        ↓
Agent 服务可以被比较、交易和结算
```

最后一步是长期方向，不是当前能力。OpenWorkProof 当前不建设商城、钱包、支付通道、
资金托管、保险、公证或法定仲裁。

下一阶段重点：

- 让更多 Agent 框架和编排器复现协议；
- 完善 Human Agency 的权限 profile、transition 与 appeal 生态；
- 增加跨组织真实执行和外部 Acceptor 复现；
- 用公开、可复核的事实推进协议互操作，而不是用平台锁定换取采用。

## 参与项目

你可以从以下任何一步开始：

- 运行最小示例并报告无法复现的地方；
- 把协议接入一个现有 Agent、CI 或 MCP 工具；
- 审阅 Schema、威胁模型和真值边界；
- 提交适配器、测试或文档；
- 带着一个真实但可脱敏的 Agent 交付问题参与讨论。

贡献说明见 [CONTRIBUTING.md](CONTRIBUTING.md)。安全问题请使用
[GitHub Security Advisories](https://github.com/dengyier/OpenWorkProof/security/advisories/new)
私下报告。项目使用 [Apache-2.0](LICENSE) 许可证。

## 为什么继续做这件事

能力回答 Agent 能做什么，工作契约回答它为什么被允许这样做，证据让行动接受复核。
机器可以执行验证规则，但最终接受、拒绝和承担后果的判断仍然属于人。

我们希望未来的 Agent 可以承担越来越多的工作。能力越强，越应该忠于人明确表达的目的；
系统越自动，授权、证据和申诉越不能消失。

OpenWorkProof 想做的事情很朴素：当人把工作交给 AI，仍然知道自己交出了什么、发生了
什么，以及何时可以说不。

**让智能依人的目的而行动，让每一次行动经得起人的最终判断。**
