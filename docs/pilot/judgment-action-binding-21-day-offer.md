# Judgment-to-Action Binding — 21 天付费试点 Offer（草案）

> **状态：not_evidenced。** 本文是商业验证假设的书面模板，**不代表已
> 有报价、合同、订单或收入**。任何未填充的外部状态一律标记
> `not_evidenced`，协议状态绝不制造商业证据。

## 1. 参与方（待确认，非证据）

| 角色 | 假设 | 当前状态 |
|---|---|---|
| User | Agent 方案商的交付/质量/项目负责人 | not_evidenced |
| Payer hypothesis | 直接承担返工、验收争议与回款不确定性的方案商负责人 | not_evidenced |
| Customer Acceptor | 客户书面指定、密钥独立于交付团队的验收负责人 | not_evidenced |

## 2. 试点范围（一个真实场景）

- 一个真实 GitHub Issue；
- 一个仓库；
- 一个基线 source revision；
- 一次 Agent 代码修改；
- 一个独立 Customer Acceptor 签署判断承诺与验收决定。

## 3. 价格假设（待验证，非报价）

- 首个 21 天试点含税报价：人民币 **30,000–50,000 元**；
- 启动定金：**50%**（支付动作是外部商业证据，本协议不证明收到定金）；
- 余款触发：约定材料提交 Customer Acceptor，**不承诺客户必须接受**。

## 4. 交付节奏（Day 1–21）

| 时间 | 工作 | 通过证据 |
|---|---|---|
| Day 1–3 | SOW、报价、定金、Issue 快照、Acceptor 与 JudgmentCommitment | 已签 SOW、定金引用、Acceptor 签名（外部） |
| Day 4–7 | Scope、adapter profile、正负控与 ActionBindingManifest | 可重算、约束不扩权、攻击预注册 |
| Day 8–12 | Agent 执行并形成完整 ActionReceipt 链 | 真实补丁、候选提交、证据包 |
| Day 13–15 | 独立重放并生成 BindingDecision | 正常 BOUND、攻击正确分类 |
| Day 16–18 | Customer Acceptor 独立复核 | 接受、拒绝或补证决定 |
| Day 19–21 | 商业与技术分开复盘 | 回款、验收周期、补证与下一单证据 |

## 5. 成功与停止规则

技术成功：正常链 `BOUND`；注册攻击得到预期拒绝/`UNBOUND`/`INDETERMINATE`；
第三方从客户私有包重放得到相同决定；缺失权威或证据时不产生绿色结论。

商业成功：至少一家目标方案商签署 SOW 并支付可定位定金；客户指定独立
Acceptor；完成一次真实接受/拒绝/补证决定；获得下一项目书面意向或可复用
的明确拒绝原因。

停止/重构：21 天内无人支付定金；无法获得独立 Customer Acceptor；Issue
无法转写为确定性验收条件；试点超过 **8 人日或人民币 2,000 元实验资源
上限**；五家目标方案商共同认为该问题不值得采购。

## 6. 外部商业证据字段（协议不制造）

以下字段仅可**引用**外部证据 id，不得由协议状态生成，未填充一律
`not_evidenced`：

```text
sow_signed: not_evidenced
deposit_received: not_evidenced
acceptor_appointed: not_evidenced
acceptance_decision: not_evidenced
next_order_intent: not_evidenced
```
