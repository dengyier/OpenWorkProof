# OpenWorkProof

<!-- mcp-name: io.github.dengyier/OpenWorkProof -->

> Agent 可以生成结果，但凭什么交付？
> Agent Work Contracts and Verifiable Execution Protocol

<div align="center">
  <a href="README_en.md">English</a> | <strong>中文</strong>
</div>

---

项目地址：https://github.com/dengyier/OpenWorkProof
本地候选版本：1.3.0（尚未发布；公开 PyPI / MCP Registry 仍以各自页面回读为准）
许可证：Apache-2.0
PyPI：[openworkproof](https://pypi.org/project/openworkproof/)
MCP Registry：[io.github.dengyier/OpenWorkProof](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.dengyier%2FOpenWorkProof/versions/1.2.0)

支持本协议的研究与维护：[GitHub Sponsors](https://github.com/sponsors/dengyier)（早期采用者可获 README 署名）

---

## 1.3 双入口：先卖结果，再建设生态

OpenWorkProof 1.3 把同一套可验证证据核心做成两个入口：

- **商业入口｜GitHub Action**：让 Agent 方案商、AI 解决方案商和系统集成商
  在现有 PR 流程中生成可离线复核的 Surface Bundle，并把结果交给客户验收；
- **生态入口｜AgentTeams / MCP**：让 Manager、Developer、Verifier 三个角色
  共享同一任务但保持角色、密钥、事件和证据边界，为更多编排器提供协议适配面。

发布 1.3.0 后的最短接入路径（需要现成的 Delivery Package、Verifier 私钥文件、
工具链锁和沙箱策略；私钥不进入仓库）：

```yaml
- name: Verify Agent delivery
  uses: dengyier/OpenWorkProof/integrations/github@v1.3.0
  with:
    delivery-package: delivery-package
    collector-private-key-file: ${{ runner.temp }}/verifier.key
    collector-actor-id: customer-verifier
    toolchain-lock-file: toolchain.lock
    sandbox-policy-file: sandbox-policy.json
```

报告首先回答四问，而不是展示协议术语：

1. **验证了什么主张？** —— 交付对象、源 revision 与验收范围；
2. **看到了什么证据？** —— 测试人口、选择结果、负控与环境指纹；
3. **受到什么约束？** —— 授权、工具、路径、容器、工具链和沙箱边界；
4. **现在能得出什么结论？** —— `VERIFIED`、`REFUTED` 或 `UNKNOWN`，以及
   是否仅达到 `READY_FOR_ACCEPTANCE`。

`owp surface-verify PATH` 可在不接入原账本、不访问执行环境的情况下离线复核
签名 Surface Bundle。三态结论不等于客户验收、付款、结算或法律判断。

AgentTeams 真实环境前置检查已在本地候选上通过：Manager、Developer、Verifier
均处于运行状态，且分别绑定不同的 Matrix 身份与 OpenWorkProof key id。该结果证明
真实三角色环境和 live preflight 可用，不证明一次新的 Manager → Developer →
Verifier 业务执行已经完成，也不证明外部人工验收：

```text
agentteams_live_environment: evidenced
agentteams_three_role_preflight: evidenced
agentteams_end_to_end_business_execution: not_evidenced
human_acceptance: not_evidenced
```

### 离线人工验收：验证结论与客户决定分别签名

`VERIFIED` 只说明 Verifier 按冻结范围和证据得出了验证结论；是否接受交付，必须
由 WorkOrder 绑定的 Acceptor 独立决定。OpenWorkProof 因此采用双签：Verifier
签署 `VerificationDecisionV05`，Acceptor 再签署
`AcceptanceDecisionBindingV01`，把 WorkOrder、Decision、CompositionReport、
验收请求和最终 ACCEPTED/REJECTED receipt 精确绑定。这样可阻止把两份各自有效、
但彼此无关的验证与验收结果拼成一次交付；缺失 binding 一律拒绝。

Acceptor 私钥不进入 AgentTeams 或 exporter。签署流程是
`prepare → sign → commit`：系统先生成无密钥草稿，外部 Acceptor 签名，再由追加式
事务提交。随后导出并离线复核：

```bash
owp acceptance-bundle-build LEDGER SURFACE \
  --evidence-root PATH --output DIRECTORY
owp acceptance-bundle-verify DIRECTORY
```

验证退出码闭合为 `ACCEPTED=0`、`REJECTED=2`、`operational=4`。AgentTeams 的
外部人工验收入口使用 `--acceptance-bundle DIRECTORY`：只轮询外部目录并调用同一
核心 verifier，不生成 key、receipt 或 binding。合法 REJECTED 是可验证终态，
不能写成“交付成功”；通知失败也不会抹掉已经验证的终态事实。

**VERIFIED != ACCEPTED != PAID/SETTLED/LEGAL AUDIT/ADOPTION**

---

## 1.4 首个商业产品：Verified Agent Delivery

`OpenWorkProof Verified Agent Delivery`（Agent 可验证交付见证）是 1.3 之上的首个
商业产品切片：把一次跨组织 Agent 工作转换成可签约、可执行、可独立验证、可由
客户验收、可交给外部支付方处理的交付事实。它只是现有 Surface Bundle、
Acceptance Bundle 与 settlement readiness 上方的薄编排层，不建设商城、SaaS、
登录、钱包、托管或自动付款。

```bash
owp delivery-case init CASE_DIR
owp delivery-case inspect CASE_DIR
owp delivery-case verify CASE_DIR
owp delivery-case export CASE_DIR --output-directory OUTPUT_DIR
```

- `init` 生成订单目录、清单和模板；
- `inspect` 从真实 Surface / Acceptance / Settlement 证据重新派生状态，不信任
  磁盘预写状态；
- `verify` 复核导出的交付包并返回闭合退出码
  （`READY_FOR_SETTLEMENT_REVIEW=0`、`REFUTED=2`、`REJECTED=2`、
  `UNKNOWN=3`、`operational=4`）；
- `export` 以确定性摘要 + 完整性 manifest 原子导出第三方可复核的交付包。

`READY_FOR_SETTLEMENT_REVIEW` 不等于付款或完成结算。完整商业模板、准入清单与
Acceptor 清单见 `docs/commercial/verified-agent-delivery/`。

```text
customer_adoption: not_evidenced
paid_sow: not_evidenced
deposit: not_evidenced
external_payment: not_evidenced
```

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

详细协议 Schema 见 [specs](specs/)（当前覆盖 v0.1–v0.5）。

---

## 快速开始

### 环境要求

- Python ≥ 3.10（支持 3.10 / 3.11 / 3.12 / 3.13）
- Git
- macOS 或 Linux

### 安装

**直接使用（推荐）：**

```bash
pip install openworkproof
```

安装后即获得 `owp` CLI 命令、`owp-mcp` MCP Server 命令和完整的 Python API。

**本地开发环境：**

```bash
git clone https://github.com/dengyier/OpenWorkProof.git
cd OpenWorkProof
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements-lock.txt
./.venv/bin/python -m pip install -e .          # 可编辑安装，同步代码修改
```

### 验证安装

```bash
# 检查 CLI 是否可用
owp status

# 运行全量测试（约 5 分钟，需本地开发环境）
./.venv/bin/python -m pytest -q

# 精确数量以当前命令输出为准；下方记录最终发布候选的 fresh 验证快照
```

### Scope-Bound Verification v0.3 与 21 天付费试点

v0.3 把“到底验证了哪些文件、测试与交付对象”纳入签名协议。Manager 冻结
`EvaluationScopeManifest`，Verifier 分别提交正臂和负臂的 Observed Scope，
Decision composer 只有在两臂人口一致、必选目标完整、注册负控被捕获时，
才会形成限定范围的 `VERIFIED`。范围遗漏、选择器漂移或证据不足只能得到
`UNKNOWN`，不能用局部绿灯冒充完整交付。

```bash
owp scope-build --claim claim.json --source-revision COMMIT_SHA --rules rules.json
owp scope-validate scope.json
owp scope-commit pilot.sqlite3 signed-scope-envelope.json
owp scope-compare scope.json observed-scope.json
owp delivery-build --privacy-view customer_private pilot.sqlite3 delivery-package/
owp audit-replay delivery-package/
```

v0.3 证明的是代码交付中“声明范围与观察范围精确一致”。它不证明未编码的
业务意图、客户已经接受、已经付款、资金已释放、自动结算、普遍正确性或
法规合规。MCP/A2A 继续负责互操作、身份、安全、任务和消息能力；
OpenWorkProof 作为补充层，把一次工作的授权、范围证据和验收依据冻结下来。

商业验证材料见 [21 天范围可验证交付试点](docs/pilot/scope-bound-verification-offer.md)，
买方交付样例见 [Scope Coverage Report](docs/pilot/scope-coverage-report.example.md)。
当前外部付费、客户验收、上游采用与正式部署均为 `not evidenced`。

### 验证完整性 Verification Integrity v0.5

v0.5 在 v0.3 的“声明范围与观察范围一致”之上，把**选择前的合格人口**与
**负控失败原因**一并冻结进签名协议。v0.3 只能证明“被选中的部分被验证了”；
v0.5 额外证明“选择之前存在哪些合格人口、选择器实际选中了什么，以及负向
控制失败是否来自注册的原因”，从而堵住两类此前测不到的盲区：

- **人口盲区**：执行引擎能看到多个合格测试，但选择器选出了零个。运行本身
  正常结束，v0.5 得出 `UNKNOWN / POPULATION_CAPTURE_FAILED`，不会把局部
  绿灯当成完整交付。
- **负控腐化**：注册的变异体仍然失败，但失败原因（错误码 / predicate 签名）
  与注册签名不一致。v0.5 得出 `UNKNOWN / CONTROL_FAILURE_SIGNATURE_MISMATCH`，
  不会把“碰巧失败”当成“按预期失败”。

三态边界保持单调：`VERIFIED`（人口 matched + 负控 proven + 正臂满足）、
`REFUTED`（负控 survived）、`UNKNOWN`（人口 empty/capture_failed/drifted/
unavailable 或负控 mismatched/unavailable）。`UNKNOWN` 是安全结论，不是系统
崩溃，也不是失败。

```bash
owp integrity-observation validate population.json
owp control-observation validate control.json
owp delivery-build --privacy-view customer_private pilot.sqlite3 delivery-package/
owp audit-replay delivery-package/
```

退出码：人口 `matched` 为 `0`，其余人口状态为 `3`；负控 `proven` 为 `0`、
`survived` 为 `4`、`mismatched/unavailable` 为 `3`；输入不合法为 `1`。

离线验证、原因码表与恢复边界见
[离线验签说明](docs/offline-verification.md)。真实 Issue 演示见
`tests/integrity-demo/rich-4196/README.md`（Rich #4196）。该演示由
OpenWorkProof 自建，`upstream_adoption`、`customer_case`、
`commercial_validation` 均为 `not_evidenced`；它不证明任何客户采用、已经
付款、资金已释放、自动结算、普遍正确性或法规合规。

### Human Agency Profile v0.1（实验能力入口）

`HumanAgencyProfileV01` 是 WorkOrder 绑定、Acceptor 签名的机器可验证授权/保留
决策边界：把「哪些工具委托给 Agent、哪些决定保留给人」冻结为可离线验签的协议
对象。三条事实：

1. profile 只收紧、不扩大：有效权限 = WorkOrder ∩ Grant ∩ active profile；
2. appeal 只记录请求，不恢复或扩大权限；只有 Acceptor 签名的 transition 才能撤销当前 profile 或将其替换为另一个 Acceptor 签名的 profile；
3. 它不是员工评分、绩效监控、法律责任转移、自动担责、资金托管或合规认证。

协议说明见 [docs/protocol/human-agency-profile-v0.1.md](docs/protocol/human-agency-profile-v0.1.md)，
最小可运行样例见 [examples/human_agency_profile_v01.py](examples/human_agency_profile_v01.py)。
`customer_adoption` / `payment` / `upstream_adoption` 仍为 `not_evidenced`。

### Evidence Lifecycle v0.2 兼容入口

当前 1.3.0 本地候选保留 v0.2 的 Profile 校验、正负证据提交、验证决定、Delivery
Package、离线审计和结算就绪度接口：

```bash
owp profile-validate signed-profile.json
owp verify-positive pilot.sqlite3 signed-positive-result.json
owp verify-negative pilot.sqlite3 signed-negative-result.json
owp verify-compose --mode prepare pilot.sqlite3 decision-request.json
owp verify-compose --mode commit pilot.sqlite3 signed-decision.json
owp delivery-build --privacy-view public pilot.sqlite3 delivery-package/
owp audit-replay delivery-package/
owp settlement-status pilot.sqlite3
```

既有运营步骤、信任等级成本和商业证据计分卡见
[v0.2 可验证交付试点](docs/pilot/README.md)。示例对象只用于本地解析和
接入演练，不代表真实客户、客户验收、付款、资金释放或正式部署。

以下是 1.2.0 的历史发布门快照：其候选曾在 source revision
`d0bec9d2f2c3cf12568fa866d16be1a56de4aa9c` 上完成发布门，并新增不可变
[候选库存](supply-chain/images/candidates/d0bec9d2f2c3cf12568fa866d16be1a56de4aa9c.json)：

- v0.5 focused：`401 passed、0 failed`；
- candidate live：`176 passed、0 failed`；
- required-live 全量：`3494 passed、0 failed、0 skipped`；
- 冻结执行镜像：
  `docker.io/openworkproof/execution-test@sha256:6d0dadec750eb498ed4d2260b4de65f33ed1c146adda6e64ec8ba588f7a88097`；
- Rich #4196 v0.5 交付包离线重放为
  `VERIFICATION PASSED / VERIFIED / READY_FOR_ACCEPTANCE`。

`READY_FOR_ACCEPTANCE` 表示证据包满足进入验收的协议条件，不等于客户已经
验收、付款或部署。详细环境、耗时与边界见 [docs/status.md](docs/status.md)。

### 运行端到端演示

OpenWorkProof 提供两个独立的端到端验证演示，覆盖不同的项目类型和协议场景：

#### M2 — Rich #4196（开发者工具类）

基于真实开源 Issue [Textualize/Rich #4196](https://github.com/Textualize/rich/issues/4196)
的完整五角色工作流演示（约 9 秒）：

```bash
./.venv/bin/python -m pytest tests/test_delivery_m2.py -q

# 预期：退出码 0；精确数量以当前命令输出为准
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

# 预期：退出码 0；精确数量以当前命令输出为准
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

### 2. MCP Server（stdio）

OpenWorkProof 已注册到官方 MCP Registry（`io.github.dengyier/OpenWorkProof`），
提供 21 个 MCP 工具，可被任何 MCP 客户端（Claude Desktop、Cursor、VS Code 等）直接调用：

```bash
# 启动 MCP Server（pip install 后直接可用）
owp-mcp

# 或通过 Python 模块启动
python -m openworkproof.mcp_transport
```

提供的 MCP 工具（21 个）：

**独立验证工具（无需 ledger）：**

| 工具 | 功能 |
|------|------|
| `owp_generate_keypair` | 生成 Ed25519 密钥对 |
| `owp_compute_key_id` | 从公钥派生 key_id |
| `owp_sign_payload` | 对规范化载荷签名 |
| `owp_verify_signature` | 验证已签名载荷 |
| `owp_compute_digest` | 计算 JCS 规范化 SHA-256 摘要 |
| `owp_verify_work_order` | 验证 WorkOrder 身份绑定 |
| `owp_verify_nested_claim` | 验证 AgentRequest / HumanDecision 嵌套声明 |
| `owp_list_domains` | 列出所有规范域名 |

**Ledger 协调工具：**

| 工具 | 功能 |
|------|------|
| `owp_status(ledger)` | 回放账本并返回权威状态 |
| `owp_run_tests(ledger, payload)` | 转发 run-tests 执行 |
| `owp_repo_read(ledger, payload)` | 转发 repo-read 执行 |

**实用工具：**

| 工具 | 功能 |
|------|------|
| `owp_get_schema` | 获取权威 JSON Schema |
| `owp_get_schema_digest` | 获取 Schema 冻结摘要 |
| `owp_analyze_repo` | 分析仓库结构 |

在 MCP 客户端配置中添加：

**Claude Desktop**（`~/Library/Application Support/Claude/claude_desktop_config.json`）：

```json
{
  "mcpServers": {
    "openworkproof": {
      "command": "owp-mcp"
    }
  }
}
```

**Cursor / VS Code**（`.cursor/mcp.json`）：

```json
{
  "mcpServers": {
    "openworkproof": {
      "command": "uvx",
      "args": ["--from", "openworkproof", "owp-mcp"]
    }
  }
}
```

更多配置方式见 [MCP_SERVER.md](MCP_SERVER.md)。

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
│   ├── mcp_transport.py       # MCP Server（既有工具 + v0.2/v0.3 接口）
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
│   └── schemas/v0.1..v0.5/   # 多版本 JSON Schema 文件
├── specs/v0.1..v0.5/         # 公开协议 Schema
├── tests/                    # 协议、故障注入与端到端测试
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
- CLI（既有执行入口 + v0.2/v0.3 范围验证、交付包、审计和就绪度入口）
- MCP Server（既有工具 + 生命周期聚合接口 + 两个只读 Scope 工具；已注册到 MCP Registry
  `io.github.dengyier/OpenWorkProof`）
- AgentTeams TCP 网络客户端 + 执行适配层
- Docker 生产执行器（STARTED_UNCONFIRMED 恢复）
- Rich #4196 完整五角色端到端演示（Acceptor TCP 签名 + 离线验签）
- Dify #33013 完整五角色端到端演示（AI 应用平台类，跨项目类型通用性验证）
- Verified Agent Delivery：交付案件模型、CLI、确定性导出、GitHub Action、商业
  准入模板，以及从 Surface / Acceptance / Settlement 证据 fail-closed 派生状态；
  `READY_FOR_SETTLEMENT_REVIEW` 不等于付款或完成结算
- **1.2.0 历史发布门快照**：v0.5 focused 401 passed；candidate live 176 passed；required-live 3494 passed、0 failed、0 skipped
- **1.3.0 本地候选 fresh required-live 门**：同时启用 live Docker、当前
  candidate inventory 与 `OPENWORKPROOF_AGENTTEAMS_REQUIRED=1`，全量
  **4265 passed、0 failed、0 skipped**；真实三角色 preflight 在严格门内通过。

**尚未完成或尚无外部证据：** 新的 Manager → Developer → Verifier 真实业务执行、
外部人工 Acceptor 终态、客户采用/付费/结算、其他 ToolCall handler 与 evidence
publication 的调用闭包，以及正式赛事提交。

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
9. ~~MCP Server 注册到官方 MCP Registry~~（`io.github.dengyier/OpenWorkProof` v1.2.0 元数据已就绪；远端发布以 Registry 回读为准）
10. 剩余：其他 ToolCall handler 与 evidence publication 的调用闭包、正式赛事提交。

---

## 参与方式

项目仍处于协议和 MVP 开发阶段。当前适合参与的方向包括：

- 协议对象与一致性测试
- 授权衰减和配额重放
- 可验证构建与证据包
- MCP/Agent 框架适配
- 真实开源 Issue 的任务封装
- 安全、隐私和数据治理审查

仓库采用 Apache-2.0 许可证。PyPI 包已发布至 [pypi.org/project/openworkproof](https://pypi.org/project/openworkproof/)，
MCP Server 已注册至 [MCP Registry](https://registry.modelcontextprotocol.io/)。
贡献流程与贡献者协议仍在制定中，欢迎先通过 GitHub Issue 提出建议。

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

---

## Judgment-to-Action Binding v0.4

v0.4 为 Agent 交付增加**判断—行动绑定**：用可验证的执行凭证回答
「Agent 实际做的，是否仍然对应客户原先批准的业务判断」。

### 业务语言（Business-First）

OpenWorkProof 提供的是**可验证的 Agent 执行凭证**。它：

- ✅ 证明「这次执行依据什么授权、做了什么、验证器是否真的能抓到谎言」；
- ❌ 不成为支付机构、不充当真理预言机、不做法律裁决、不替代客户验收。

### v0.4 状态链与门

```text
Customer Acceptor 签署 JudgmentCommitment（执行前）
      ↓
Manager 提交 ActionBindingManifest（判断↔执行约束绑定）
      ↓
Agent v0.4 请求 + ActionReceipt（原生绑定同一 Manifest）
      ↓
独立 Verifier 组合 BindingDecision（BOUND / UNBOUND / INDETERMINATE）
      ↓
双门：VerificationDecision=VERIFIED ∧ BindingDecision=BOUND ∧ Acceptance=ACTIVE
      ↓
READY_FOR_SETTLEMENT_REVIEW（不证明付款或结算）
```

### 外部权威边界

高风险场景可接入外部 **AuthorityCheckpoint**（客户控制域的独立密钥）。
OWP 只验证 checkpoint 的格式、签名、链与绑定，**不拥有外部治理与信任根**；
权威状态只按行动发生时点（as-of）判定，解析器不可用时不伪造 checkpoint。

### 真值边界（Truth Boundaries）

- `BOUND` 只表示「行动与记录判断一致」，**不等于**判断正确、代码无缺陷、
  客户验收、付款或结算。
- 未取得的商业状态一律标记 `not_evidenced`（上游采纳、客户使用、付款）。

### 接口

```text
owp judgment validate
owp binding-manifest validate
owp binding compose
owp binding verify
owp binding history
owp package replay --binding
```

只读 MCP 工具：`owp_validate_judgment_commitment`、
`owp_validate_action_binding_manifest`、`owp_get_binding_status`、
`owp_explain_binding_decision`。MCP 验证**拒绝任何 Acceptor/Verifier 私钥
参数**，只读不签名不提交。

完整实现状态见 [docs/status.md](docs/status.md)，21 天付费试点材料见
[docs/pilot/](docs/pilot/)。
