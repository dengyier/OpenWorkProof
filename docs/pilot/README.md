# OpenWorkProof 21 天可验证交付试点

本目录是一个运营工具包，不是客户案例。它帮助 Agent 方案商、AI
解决方案商和系统集成商，把一项真实交付从“口头说完成”变成可冻结、
可执行、可反证、可验收和可离线复核的工作记录。

## 商业假设与证据边界

- **首要付费方是假设**：优先验证 Agent 方案商、AI 解决方案商和系统
  集成商是否愿意为减少验收争议、补证成本和回款不确定性付费。
- **最小商业验证信号**：客户或方案商依据明确 SOW 支付可核验定金。
  口头兴趣、会议纪要、试用、GitHub Star、技术测试通过都不是付费验证。
- OpenWorkProof 记录工作证据和结算就绪度，不托管资金、不执行付款、
  不判断法律责任，也不把 `READY_FOR_ACCEPTANCE` 写成客户已经接受。
- 所有客户验收、付款、正式部署、重复采购只有在对应外部材料存在后，
  才能从 `not evidenced` 更新为事实。

## 交付信任等级与成本边界

| 等级 | 增量机制 | 交付物与适用边界 |
|---|---|---|
| Level 0 | 普通 CI | 只运行已有测试；不生成 Evidence Bundle，也不生成客户包。适合内部开发基线。 |
| Level 1 | 正臂、真实负臂和签名验证结论 | 生成 Evidence Bundle，但不生成客户 Delivery Package；适合内部质量复核和开源复现。 |
| Level 2 | 客户控制的 `CommitmentAnchor`、客户验收和 Delivery Package | 在真实客户锚点与验收权威存在时形成客户可离线复核的交付包。未发生客户签署时只能报告等待验收。 |
| Level 3 | 第二名独立 Verifier、不同控制与执行环境、更加严格的保留期限 | 面向高风险或高金额工作；两名 Verifier 必须满足协议独立性约束。 |

等级越高，签署、隔离执行、证据保留和人工复核成本越高。试点应选择满足
风险所需的最低等级，不为展示技术而升级。

## 21 天运行节奏

| 阶段 | 运营动作 | 必须形成的证据 | 退出条件 |
|---|---|---|---|
| Day 1–3：冻结主张 | 选择一项真实交付；确认用户、付费方、验收方；冻结 `SubjectClaim`、验收条件、排除项、源 revision 和目标候选；提出定金要求。 | 经授权签名的 SubjectClaim；真实 SOW/任务单引用；若为 Level 2/3，客户控制的 CommitmentAnchor。 | 主张可被明确证伪；验收方和付款方不是团队自行代填。 |
| Day 4–7：接入协议 | 固定测试源、命令、容器、依赖锁、正臂和 Manager-pinned 负臂；签署 `VerificationProfileV02`；校验角色与保留期限。 | 可解析的 Profile；候选与 mutant 不同；正负臂共用固定测试与执行边界。 | `owp profile-validate` 通过；没有私钥进入仓库或交付包。 |
| Day 8–14：真实执行 | 在冻结环境运行正臂和负臂；提交签名 ArmResult；生成 `VerificationDecision`；失败或证据缺失时保持 `REFUTED`/`UNKNOWN`。 | 正负结果、执行收据、证据摘要、VERIFIED/REFUTED/UNKNOWN 决定；可复核 Delivery Package（Level 2/3）。 | 第三方离线重放得到同一结论；篡改失败关闭。 |
| Day 15–18：客户决定 | 向绑定的 Acceptor 展示可读摘要和完整包；记录接受、拒绝、撤回、替换或补证请求。 | 客户独立签名决定，或明确的 `not evidenced`；补证轮次及新增材料。 | 不用团队自签替代客户决定；没有决定时不得进入“已验收”。 |
| Day 19–21：商业复盘 | 对照计分卡复核周期、补证轮次、定金/付款材料、复购或下一任务单；决定继续、调整或停止试点。 | 更新后的 `pilot-scorecard.md`；定金凭证引用；下一项目书面证据或 `not evidenced`。 | 技术结论与商业结论分别记录；没有定金或付款证据时，付费假设仍未验证。 |

## 操作前检查

1. 为真实试点换掉示例中的 `example.invalid`、占位摘要和示例公钥。
2. 私钥留在各角色自己的安全边界，不写入 JSON、Git、日志或 Delivery
   Package；包内只能出现公钥和签名。
3. 固定 source、candidate、测试、命令、容器和依赖锁。
4. 负臂必须是真实 mutant，不能把正向 candidate 改名充当负控。
5. Level 2/3 的 CommitmentAnchor 必须由客户控制，项目团队不能代造。
6. 复制 [计分卡](pilot-scorecard.md)，所有外部结果保持
   `not evidenced`，直到材料可定位。

## v0.2 CLI 操作顺序

```bash
# 1. 校验已签名 Profile
owp profile-validate docs/pilot/verification-profile.example.json

# 2. 在权威 ledger 中分别提交已签名正臂和负臂结果
owp verify-positive pilot.sqlite3 positive-arm-result.json
owp verify-negative pilot.sqlite3 negative-arm-result.json

# 3. 先准备规范化决定草稿，再由绑定 Verifier 签名并提交
owp verify-compose --mode prepare pilot.sqlite3 decision-request.json
owp verify-compose --mode commit pilot.sqlite3 signed-decision.json

# 4. 生成客户包并离线复核
owp delivery-build --privacy-view public pilot.sqlite3 delivery-package/
owp audit-replay delivery-package/
owp audit-explain delivery-package/
owp audit-compare older-package/ delivery-package/

# 5. 读取结算就绪度；输出不是付款或完成结算证明
owp settlement-status pilot.sqlite3
```

机器集成使用五个已注册的 v0.2 MCP 工具：`owp_validate_profile`、
`owp_run_verification`、`owp_get_decision`、
`owp_build_delivery_package` 和 `owp_get_settlement_readiness`。离线
replay/explain/compare 当前使用 CLI。Acceptor 私钥签名仍是外部、本地密钥
操作，不通过 MCP 托管。

## 示例对象

- [SubjectClaim 示例](subject-claim.example.json)
- [VerificationProfileV02 示例](verification-profile.example.json)
- [技术/商业计分卡](pilot-scorecard.md)

两个 JSON 使用不可路由域名、占位摘要和示例公钥，只用于解析与接入演练。
它们不代表真实客户、真实交付、真实验收或真实付款。
