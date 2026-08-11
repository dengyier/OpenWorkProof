# OpenWorkProof 21 天试点计分卡

> 本文件是空白运营模板。默认状态 `not evidenced` 表示当前没有可定位的
> 证据，不等于“否”，也不得凭口头陈述改成“是”。技术证据与商业证据必须
> 分开更新。

## 试点身份

| 字段 | 当前值 |
|---|---|
| 试点 ID | `not evidenced` |
| 方案商 / 实施方 | `not evidenced` |
| 最终使用组织 | `not evidenced` |
| 付款主体 | `not evidenced` |
| 客户 Acceptor | `not evidenced` |
| 交付信任等级 | `not evidenced` |
| SOW / 任务单引用 | `not evidenced` |
| SubjectClaim digest | `not evidenced` |
| VerificationProfile digest | `not evidenced` |

## A. 技术与协议证据

| 指标 | 定义与口径 | 实际值 | 证据引用 | 状态 |
|---|---|---|---|---|
| 测试计数 | 最终冻结命令的 passed / failed / skipped；必须带时间和 revision | `not evidenced` | `not evidenced` | `not evidenced` |
| 注册敌对案例 | 预先登记且非 holdout 的攻击/故障案例总数与通过数 | `not evidenced` | `not evidenced` | `not evidenced` |
| 开源重放案例 | 第三方可离线重放的真实开源 Issue 数量与结论 | `not evidenced` | `not evidenced` | `not evidenced` |
| 正臂执行 | 冻结候选按 Profile 运行并得到预期 pass | `not evidenced` | `not evidenced` | `not evidenced` |
| 负臂执行 | Manager-pinned mutant 被同一固定测试按预期捕获 | `not evidenced` | `not evidenced` | `not evidenced` |
| 第三方重放执行 | 独立环境执行 `audit-replay`，记录结论、环境和 manifest digest | `not evidenced` | `not evidenced` | `not evidenced` |
| 验证结论 | 当前 `VERIFIED` / `REFUTED` / `UNKNOWN`，不得只报退出码 | `not evidenced` | `not evidenced` | `not evidenced` |
| 证据篡改检查 | 修改包内字节后是否 fail closed | `not evidenced` | `not evidenced` | `not evidenced` |

## B. 客户决策与交付效率

| 指标 | 定义与口径 | 实际值 | 证据引用 | 状态 |
|---|---|---|---|---|
| 客户验收决定 | 绑定 Acceptor 的 accept / reject / withdraw / supersede 签名记录 | `not evidenced` | `not evidenced` | `not evidenced` |
| 交付周期 | SubjectClaim 冻结到客户决定的自然日/小时 | `not evidenced` | `not evidenced` | `not evidenced` |
| 补证轮次 | 客户首次复核后新增证据并再次提交的次数 | `not evidenced` | `not evidenced` | `not evidenced` |
| 争议项数量 | 客户提出且可定位到验收条件的争议项数 | `not evidenced` | `not evidenced` | `not evidenced` |
| 结算就绪度 | 协议推导状态；明确不等于付款或资金释放 | `not evidenced` | `not evidenced` | `not evidenced` |

## C. 商业验证证据

| 指标 | 定义与口径 | 实际值 | 证据引用 | 状态 |
|---|---|---|---|---|
| 付费试点 | 有双方主体、范围、金额和期限的付费 SOW 数量 | `not evidenced` | `not evidenced` | `not evidenced` |
| 定金 / 付款证据 | 与该 SOW 对应的可核验入账或付款材料；意向不计 | `not evidenced` | `not evidenced` | `not evidenced` |
| 付费主体 | 实际付款的方案商、集成商或最终客户主体 | `not evidenced` | `not evidenced` | `not evidenced` |
| 付费原因 | 客户原话归因：减少争议、缩短验收、合规审计或其他 | `not evidenced` | `not evidenced` | `not evidenced` |
| 重复项目证据 | 同一付款方的下一任务单、续费或书面采购承诺 | `not evidenced` | `not evidenced` | `not evidenced` |
| 正式部署 | 有生产环境、责任主体和上线验收材料的部署 | `not evidenced` | `not evidenced` | `not evidenced` |

## 阶段判定

| 判定 | 必须满足 | 当前状态 |
|---|---|---|
| 技术可复核 | 正负臂、签名结论、离线重放和篡改失败关闭都有证据 | `not evidenced` |
| 客户可验收 | 客户控制锚点、绑定 Acceptor 和独立客户决定都有证据 | `not evidenced` |
| 付费假设已验证 | 付费 SOW 与对应定金/付款证据同时存在 | `not evidenced` |
| 可重复销售 | 同一或第二付款方出现下一任务单/续费证据 | `not evidenced` |

## 复盘决定

- 继续 / 调整 / 停止：`not evidenced`
- 下一步最小实验：`not evidenced`
- 负责人和截止时间：`not evidenced`
- 未解决风险：`not evidenced`
