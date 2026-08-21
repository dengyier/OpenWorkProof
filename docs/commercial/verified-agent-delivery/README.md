# OpenWorkProof Verified Agent Delivery

> 产品名：`OpenWorkProof Verified Agent Delivery`
> 中文工作名：Agent 可验证交付见证
> 一句话：Make agent work verifiable, acceptable, and ready for settlement.

## 目标用户

本切片只服务英语市场里已经在用 Coding Agent 交付真实仓库任务的组织：

- AI 编程外包团队；
- Agent 方案商与系统集成商；
- 采购 Agent 开发服务的小型软件团队；
- 需要独立验收高价值 PR / 自动化任务的平台或项目方。

首轮核心付费方假设是 **Delivery Provider**（承担交付、返工和回款周期的一方），
因为其直接承担补证、争议和回款周期。**Customer Acceptor** 是独立决定接受或
拒绝交付的客户方角色，绝不与 Delivery Provider 混同。

## 准入条件（缺任何一项不得开工）

一次交付只有同时满足以下条件才能进入本流程：

1. 真实仓库或脱敏仓库（必须有代码 revision 与可执行测试）；
2. 可定位的任务单 / SOW 外部引用（含付款主体、金额区间和期限）；
3. 双方冻结的 SubjectClaim 与 WorkOrder；
4. 独立的 Verifier 密钥与执行环境；
5. 客户控制的独立 **Customer Acceptor**；
6. 冻结的验收条件、必选产物、允许工具、测试与排除项。

任何一项缺失都不得开始执行，更不得导出交付包。

## 九项交付物

每笔订单必须形成以下九项材料：

1. 商务任务单 / SOW 的外部引用；
2. 双方冻结的 SubjectClaim 与 WorkOrder；
3. Verification Profile、范围和环境证据；
4. ActionReceipts 与正负验证结果；
5. Surface Bundle；
6. Acceptance Bundle；
7. Settlement Readiness Result；
8. 面向 Buyer 的一页交付摘要；
9. 运营计分卡与复盘记录。

公开包不得包含合同金额、银行流水、支付账号、私钥、访问令牌、客户私有代码或
未经授权的个人信息。商业材料只保存外部引用和证据状态，不把支付凭证写进协议包。

## 21 天 / 8 人日 / 2,000 元内部上限

首轮单笔交付遵循内部运营上限，不放大为公开价目或承诺：

- 周期上限：21 天；
- 交付人日上限：8 人日；
- 内部成本上限：2,000 元（人民币，内部核算口径，不是客户报价）。

超限必须显式复核，不得自动续期、自动追加预算或自动开工。

## 继续 / 停止条件

**继续条件**（全部满足才继续推进）：

- 验收口径在执行前冻结且双方认可；
- 每个关键动作绑定授权、执行者、环境、输入输出与证据；
- Verifier 与交付团队密钥、上下文和执行环境保持独立；
- Acceptor 对同一交付和验证结论作出签名接受或拒绝；
- 争议可定位到具体条件、证据或验证步骤。

**停止条件**（任一满足即停止，不回写历史、不渲染成成功）：

- 缺 WorkOrder、范围或验收权威；
- 缺证据、验证者分歧或环境不完整；
- 验证明确失败（`REFUTED`）；
- 客户合法拒绝（`REJECTED`）；
- 未取得外部付款凭证（只到 `READY_FOR_SETTLEMENT_REVIEW`，不等于付款）。

## 四种收费单元

首轮不发布永久价目表，用固定范围 SOW 验证计费单元：

1. **Delivery Setup**：把模糊需求转写为可执行验收条件，固定一次性费用；
2. **Verified Delivery**：减少补证、争议并加快验收，每笔任务固定费用；
3. **Independent Review**：买方要求额外独立复核，可选附加费用；
4. **Dispute Review**：争议发生后的证据定位与复核，单独报价。

Platform Integration（平台批量接入）不作为首轮计费单元，有三笔以上真实订单后
再单独报价。

## 诚实边界

```text
customer_adoption: not_evidenced
paid_sow: not_evidenced
deposit: not_evidenced
external_payment: not_evidenced
```

本产品**不托管资金**、**不等于付款**、不提供付款担保、不构成法律审计、不保证
任务天然正确、不承诺客户必然接受、不承诺争议必然消失。`READY_FOR_SETTLEMENT_REVIEW`
只表示状态可进入外部结算审核，不代表完成结算或已收到款项；外部付款状态只表示
存在摘要引用，不表示 OpenWorkProof 验证了资金事实。

## 四步操作

```bash
owp delivery-case init CASE_DIR
owp delivery-case inspect CASE_DIR
owp delivery-case verify CASE_DIR
owp delivery-case export CASE_DIR --output-directory OUTPUT_DIR
```

`verify` 退出码闭合为 `READY_FOR_SETTLEMENT_REVIEW=0`、
`EXTERNAL_PAYMENT_EVIDENCED=0`、`REFUTED=2`、`REJECTED=2`、
`UNKNOWN=3`、`SCOPE_DRAFTED=3`、`SOW_REFERENCED=3`、
`READY_FOR_ACCEPTANCE=3`、`ACCEPTED=3`、`operational=4`。
