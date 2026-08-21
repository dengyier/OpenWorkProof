# OpenWorkProof Verified Agent Delivery 0.1 设计规格

> 日期：2026-08-22
> 状态：待用户书面审查
> 产品基线：OpenWorkProof 1.3 开发基线（`main@61accc3`）
> 商业边界：客户采用、付费 SOW、定金、复购与外部平台接入均为
> `not_evidenced`

## 1. 决策摘要

OpenWorkProof 的首个商业产品定义为 **Verified Agent Delivery**：把一次跨组织
Agent 工作转换成可签约、可执行、可独立验证、可由客户验收并可交给外部支付方
处理的交付事实。

本切片不建设 Agent 商城、SaaS 控制台、资金托管或新协议版本。它只把仓库中
已经存在的 WorkOrder、执行凭证、双验证、Surface Bundle、Acceptance Bundle 和
`settlement-status` 组合成一套可重复销售的单笔交付流程。

产品承诺限定为：

> 让 Agent 的一次约定工作产生机器可复核的授权、执行、验证和人工验收材料，
> 并输出是否具备进入外部结算审核的状态。

产品不承诺任务天然正确、客户必然接受、自动付款、法律担保、监管合规或争议
必然消失。

## 2. 第一市场与参与者

### 2.1 第一市场

首批只服务英语市场中已经使用 Coding Agent 交付真实仓库任务的：

- AI 编程外包团队；
- Agent 方案商与系统集成商；
- 采购 Agent 开发服务的小型软件团队；
- 需要独立验收高价值 PR/自动化任务的平台或项目方。

不同时进入通用办公 Agent、营销内容、政企合规和消费级 Agent 市场。第一场景
必须具有代码 revision、可执行测试、明确产物、独立验收人和可定位任务单。

### 2.2 六类参与者

| 参与者 | 商业责任 | 协议对应 |
|---|---|---|
| Buyer | 提出任务并承担采购决策 | WorkOrder 业务发起方 |
| Delivery Provider | 承担交付、返工和回款风险 | Manager / Maintainer |
| Agent Worker | 在授权范围内执行 | Developer / Worker |
| Independent Verifier | 独立执行验证，不替代客户验收 | Verifier |
| Customer Acceptor | 独立决定接受或拒绝 | Acceptor |
| Payment Partner | 根据外部合同和状态处理资金 | 协议外部系统 |

首轮核心付费方假设是 Delivery Provider，因为其直接承担补证、争议和回款周期。
Buyer 购买独立验证以及平台按 API 付费属于第二阶段假设，在有付款证据前不得写成
已验证模式。

## 3. 用户购买的结果

客户购买的不是加密技术或审计报告，而是以下结果组合：

1. **验收口径冻结**：在执行前明确任务、必选产物、允许工具、测试和排除项；
2. **履约过程可复核**：每个关键动作绑定授权、执行者、环境、输入输出和证据；
3. **验证结论独立**：Verifier 与交付团队密钥、上下文和执行环境保持独立；
4. **客户决定可证明**：Acceptor 对同一交付和验证结论作出签名接受或拒绝；
5. **结算状态可传递**：产生供外部合同或支付系统消费的结算审核状态；
6. **争议可定位**：争议落到具体条件、证据或验证步骤，而不是笼统争论“是否做完”。

核心业务结果指标是：从 SubjectClaim 冻结到 Acceptor 决定的时间、补证轮次、
争议项数量和付款周期变化。测试数量、签名数量和哈希数量只能作为技术证据，
不能替代商业结果。

## 4. 产品形态

### 4.1 对外产品名称

- 产品名：`OpenWorkProof Verified Agent Delivery`
- 中文工作名：`Agent 可验证交付见证`
- 类别：`Agent 履约验证与结算就绪服务`
- 一句话：`Make agent work verifiable, acceptable, and ready for settlement.`

避免使用“担保支付”“自动结算”“Agent 支付宝”“法律公证”等可能暗示资金托管或
法定资质的名称。

### 4.2 单笔交付包

每笔订单必须形成以下材料：

1. 商务任务单/SOW 的外部引用；
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

### 4.3 软件入口

首版只增加一个薄编排入口，不复制协议逻辑：

```text
owp delivery-case init CASE_DIR --profile coding-agent
owp delivery-case inspect CASE_DIR
owp delivery-case verify CASE_DIR
owp delivery-case export CASE_DIR --output OUTPUT_DIR
```

职责限定为：

- 生成订单目录、清单和模板；
- 检查必需材料与状态；
- 调用已有 Surface/Acceptance/Settlement 验证器；
- 输出机器可读状态和一页人类摘要；
- 保留协议组件原有退出码与 fail-closed 语义。

该入口不生成客户签名、不代替 Acceptor、不读取支付账户、不自动执行资金指令，
也不通过新数据库制造第二真相源。

## 5. 交付生命周期

```text
LEAD
  -> SCOPE_DRAFTED
  -> SOW_REFERENCED
  -> CLAIM_FROZEN
  -> EXECUTION_IN_PROGRESS
  -> READY_FOR_VERIFICATION
  -> VERIFIED / REFUTED / UNKNOWN
  -> READY_FOR_ACCEPTANCE
  -> ACCEPTED / REJECTED
  -> READY_FOR_SETTLEMENT_REVIEW
  -> EXTERNAL_PAYMENT_EVIDENCED / PAYMENT_NOT_EVIDENCED
```

前五个商业运营状态不得写入冻结的协议状态机。协议权威仍由既有账本和签名对象
构成；交付目录中的运营状态必须由已有可验证材料派生。最后两个支付状态只引用
外部材料，OWP 不声明自己完成结算。

### 5.1 失败语义

- 缺 WorkOrder、范围或验收权威：不得开始执行；
- 缺证据、验证者分歧或环境不完整：`UNKNOWN`；
- 验证明确失败：`REFUTED`；
- 客户合法拒绝：`REJECTED`，不得渲染成项目成功；
- 验收完成但无付款凭证：只到 `READY_FOR_SETTLEMENT_REVIEW`；
- 外部支付失败或未知：不回写或篡改历史验收事实。

## 6. 目录与数据边界

建议订单目录：

```text
case.json
commercial/
  sow-reference.json
  payer-status.json
  scorecard.json
protocol/
  work-order.json
  subject-claim.json
surface/
acceptance/
settlement/
  settlement-status.json
delivery-summary.md
```

`case.json` 只保存：随机 case id、非敏感参与者别名、交付类型、外部引用、创建时间
和组件相对路径。当前状态必须由 `inspect` 从已有材料重新派生，不写入 manifest。
不得保存密码、支付凭证正文、私钥、客户源码快照或任意可执行 shell。

所有路径必须是规范化相对路径。检查器拒绝绝对路径、`..`、symlink、hardlink、
设备文件、重复文件以及超出既有限额的包。导出采用临时目录自验后 no-replace
原子提交。

## 7. 收费结构与验证方式

首轮不发布永久价目表，使用固定范围 SOW 验证五种计费单元：

| 计费单元 | 付费理由 | 首轮验证方式 |
|---|---|---|
| Delivery Setup | 把模糊需求转写为可执行验收条件 | 固定一次性费用 |
| Verified Delivery | 减少补证、争议并加快验收 | 每笔任务固定费用 |
| Independent Review | 买方要求额外独立复核 | 可选附加费用 |
| Dispute Review | 争议发生后的证据定位与复核 | 单独报价 |
| Platform Integration | 平台批量生成和验证凭证 | 有三笔以上订单后再报价 |

不按客户资金余额获利，不保管资金，不承诺赔付。按交易金额比例计费仅作为未来
假设，而且必须有封顶、法律审查和持牌支付伙伴；首轮不实施。

## 8. 首批十单实验

### 8.1 获客与选择

- 最多定向接触 20 个英语市场 Coding Agent 服务商；
- 只选择正在发生、金额和付款路径明确、可取得独立 Acceptor 的任务；
- 首批可以包含 OpenWorkProof 自有开源任务作为技术演练，但不得计入客户采用、
  付费订单或市场验证；
- 没有 SOW/任务单引用和付款主体的任务不得计入十单。

### 8.2 每单必须记录

- 付款方和付费原因；
- 任务金额区间与 OWP 服务费；
- SubjectClaim 冻结时间；
- 首次提交、每次补证和最终验收时间；
- `VERIFIED / REFUTED / UNKNOWN` 及原因；
- `ACCEPTED / REJECTED`；
- 争议项和解决方式；
- 是否存在外部付款证据；
- 交付人日、验证成本与毛利；
- 是否产生下一单或平台接入意向。

### 8.3 进入网络阶段的门

只有同时满足以下条件，才设计 Marketplace 或托管交易网络：

1. 至少 10 笔具有完整任务单的交付；
2. 至少 2 个独立真实付款方；
3. 至少 1 个付款方发生复购；
4. 至少 1 个第三方平台给出责任人、时间和范围明确的接入意向；
5. 验证成本能够压到订单价值的目标比例以内；目标比例在首十单后按数据确定，
   不在当前无数据情况下拍定；
6. 至少 1 个案例证明 OWP 缩短验收、减少补证或解决争议。

## 9. 工程范围

### 9.1 必须实现

- `delivery-case` 目录初始化、检查、验证和导出命令；
- 严格的 case manifest 模型和路径/大小边界；
- 对现有 Surface Bundle、Acceptance Bundle 与 settlement status 的组合验证；
- 一页 Markdown/JSON 交付摘要；
- 正常、拒绝、未知、缺材料、篡改和支付未证实路径的 fixture；
- SOW 引用、客户 intake、Acceptor checklist 和商业计分卡模板；
- GitHub Action 示例，把完成的交付包作为 artifact 输出；
- 中英文 README 的商业入口与诚实边界同步。

### 9.2 明确不实现

- 多租户账号、登录、团队权限和云端控制台；
- Agent 供需撮合、商品列表、搜索与推荐；
- 钱包、余额、充值、提现、托管和自动付款；
- 通用信誉分、链上存证或代币；
- 动态定价、比例抽佣与财务会计；
- 第二代码托管平台；
- 新协议 schema 或修改冻结签名字节；
- 把自有演练包装成真实客户订单。

## 10. 测试与验收

### 10.1 功能验收

1. `init` 在空目录生成确定的最小目录和模板；
2. 完整 fixture 的 `inspect` 输出唯一状态；
3. `verify` 调用真实底层验证器，不相信预写状态；
4. 合法拒绝输出非成功但可验证终态；
5. 缺证据输出 `UNKNOWN` 或 operational error，不降级为成功；
6. `export` 只包含 allowlist 文件，并在提交前完成自验；
7. 同一输入重复验证产生相同业务摘要；
8. 修改任一受保护字节后验证失败关闭；
9. 输出不含私钥、Token、支付正文和绝对本地路径；
10. 既有协议、golden bytes、required-live 和 candidate 门保持通过。

### 10.2 商业验收

软件完成不等于商业完成。商业阶段分别记录：

```text
outreach_sent
buyer_interviewed
sow_signed
deposit_evidenced
delivery_verified
customer_accepted
external_payment_evidenced
repeat_order_evidenced
```

任何状态只有存在可定位材料时才能更新；GitHub Star、社区评论、测试通过、演示
视频、口头兴趣和本地生成的包均不能替代签约、付款或客户验收。

## 11. 发布策略

1. 先在独立开发分支实现，不改变 main 上已冻结协议事实；
2. 先提交模型与攻击测试，再实现 CLI 编排和模板；
3. 聚焦测试通过后执行 candidate 与 required-live 发布门；
4. 文档只写实际完成能力，商业采用继续标记 `not_evidenced`；
5. 第一笔真实交付产生后，单独提交脱敏案例和运营复盘，不重写历史状态。

## 12. 成功标准

### 软件完成

- 一条命令能建立订单目录；
- 一条命令能从现有证据推导交付状态；
- 一条命令能导出客户可读、第三方可复核的交付包；
- 不修改冻结协议、不引入第二真相源、不触碰资金。

### 商业验证

- 至少一份双方主体、金额、范围和期限明确的 SOW；
- 与 SOW 对应的定金或付款证据；
- 客户控制的 Acceptor 对真实交付作出决定；
- 客户原话说明购买原因；
- 下一单、复购或平台接入意向有独立材料。

在上述材料出现前，OpenWorkProof 仍是技术与商业交付准备完成、市场采用尚未
证实的开源项目。
