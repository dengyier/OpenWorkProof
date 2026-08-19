# RetractionReceipt v0.5 设计规格（语义可撤销性）

> 日期：2026-08-18
> 状态：待审查（Phase 2 设计，社区协议缺口 #1）
> 协议基线：v0.5（Verification Integrity，已闭环）

## 1. 背景与社区输入

Mikhail 在 LinkedIn 与 DEV 社区指出：**签名只证明非否认，不证明语义正确性**。
"immutable evidence ≠ immutable truth"——一个动作收据可以签名有效、证据防篡改，
但其后得出的**结论**可能是错的（上下文漂移、模型解释错误、下游信息推翻了先前
假设）。收据没撒谎、动作确实发生了，但**结论需要被推翻**。

社区共识（Mikhail 两轮 + Zira + 三项目收敛）：
1. **原始收据保持不可变**：永远证明"此动作以这些输入、此时、由该身份发生"，
   forensic integrity 不被破坏，任何内容都不被重写。
2. **RetractionReceipt 作为独立的签名收据叠加在上**：标记原收据的
   verdict 从 `VERIFIED → REFUTED`（或降级）。不删除、不修改原收据。
3. **生命周期显式可查询**：任何 verifier 都能程序化检查
   "此收据的结论还成立吗，还是已被反驳？"——协议级保证，不是文档实践。
4. **一等协议概念**：如果撤销只活在日志里，它是 advisory；活在收据链里，
   它是 enforceable。
5. **partial refutation 语义**：有时动作正确但解释错误；有时动作本身错误但
   下游依赖仍有效。reason 分类需保持简单，不过度工程化。

## 2. 当前缺口（现状 vs 需求）

现有协议已覆盖的撤销面：

| 机制 | 对象 | 谁能撤销 | 语义 |
|---|---|---|---|
| 决策 supersede（v0.2–v0.5） | `VerificationDecision` | 任何重验 | 新决策取代旧决策；旧决策仍在（`supersedes_decision_id` 链） |
| `AcceptanceTransitionReceipt`（v0.2/v0.5） | `AcceptanceReceipt` | **仅 Acceptor** | withdrawn / superseded + 5 reason codes |

**缺口**：对**已签发的单个 ActionReceipt**（grant / tool_call / approval /
termination / rollback 收据）没有一等语义撤销。当前一个工具收据一旦签发就
永远"有效"——即使其后的证据、上下文或解释推翻了它，也没有协议对象能把它
标记为 REFUTED。`AcceptanceTransitionReceipt` 只能撤销验收决定，不能撤销
动作收据；决策 supersede 只能换新决策，不能把旧收据标记为"已被反驳"。

## 3. 设计目标与非目标

### 3.1 目标

1. 新增 `RetractionReceiptV05`：对已签发 ActionReceipt（及可选 VerificationDecision）
   的一等语义撤销，叠加在原收据上，不重写原收据。
2. 可查询生命周期：`receipt_retraction_status(receipt_id)` 返回
   `standing / refuted / confidence_downgraded`。
3. reason 分类（闭合、简单）：`context_invalidated`、`interpretation_error`、
   `cascading_failure`、`evidence_refuted`。
4. 撤销权限绑定 WorkOrder：Manager 或 Verifier（而非仅 Acceptor）可签发
   retraction——因为撤销的是"结论有效性"，不是"验收决定"。
5. 事务落账：append-only ledger 表 + 不可变触发器 + 崩溃恢复，与 v0.5
   事务模式一致。
6. 三态兼容：被撤销收据进入后续决策时按规则收敛
   （`evidence_refuted` → 决策 UNKNOWN 或 REFUTED，视上下文）。
7. 离线验证：delivery package 离线重放可见 retraction 链。
8. v0.1–v0.5 冻结面完全不动：新增 v0.5 sibling 对象 + 新表，不触碰旧模型、
   签名字节、schema。

### 3.2 非目标

- 不实现自动撤消（不基于时间、不基于依赖图自动触发）；
- 不实现链式传播撤销（撤销 A 不会自动撤销依赖 A 的 B，但可显式逐个签发）；
- 不实现"删除"或"重写"语义——原收据永远不可变；
- 不实现 retraction 的 retraction（本版本不允许撤销一次撤销；二次撤销 = 新
  RetractionReceipt 指向新状态，留给 v0.6）；
- 不做付款/结算/法律仲裁语义。

## 4. 协议对象

### 4.1 `RetractionReceiptV05`（SignedProtocolModel）

```yaml
schema_version: openworkproof-retraction-receipt/0.5
protocol_version: "0.5"
retraction_id: <sha256>
work_order_digest: <sha256>
target_receipt_id: <sha256>          # 被撤销的 ActionReceipt id
target_receipt_digest: <sha256>      # 精确绑定被撤销收据的字节
target_receipt_kind: tool_call | approval_decision | termination_decision |
                     grant_issued | grant_consumed | grant_revoked |
                     rollback | verification_decision
retraction_effect: refuted | confidence_downgrade
retraction_reason: context_invalidated | interpretation_error |
                   cascading_failure | evidence_refuted
refutes_decision_id: <sha256> | null  # 若同时撤销某个决策结论
refutes_decision_digest: <sha256> | null
causal_parent_ids: [<sha256>, ...]    # 必须含 target_receipt_id；可选含 refutes_decision_id
nonce: <sha256>
retracted_at: <canonical UTC time>
```

约束：

1. `retraction_id` 使用 domain `openworkproof/retraction-receipt/v0.5` 重算。
2. `target_receipt_digest` 必须重算自目标收据的规范字节；不匹配即拒。
3. `refutes_decision_id` 与 `refutes_decision_digest` 必须成对出现或同时为空。
4. `causal_parent_ids` 必须非空、排序、唯一，且包含 `target_receipt_id`；
   若 `refutes_decision_id` 非空则必须同时包含它。
5. `retraction_effect == confidence_downgrade` 时 reason 不得为
   `evidence_refuted`（降级不是反驳）。
6. `retracted_at` 必须晚于目标收据的 `occurred_at`（时间因果序）。

### 4.2 签名与权威

- 签名域：`retraction-receipt`（新 domain，不与其他对象共用签名字节）。
- 签发者：WorkOrder 绑定的 **Manager 或 Verifier**（`validate_against_work_order`
  检查签发者 key 在 `{Manager, Verifier}` 角色绑定内）。
- 理由：撤销的是"结论有效性"，不是"验收决定"；Acceptor 撤销验收仍走既有
  `AcceptanceTransitionReceipt`。

### 4.3 账本表

```text
retraction_receipts_v05 (
    retraction_id TEXT PRIMARY KEY,
    retraction_digest TEXT NOT NULL UNIQUE,
    work_order_digest TEXT NOT NULL,
    target_receipt_id TEXT NOT NULL,
    target_receipt_digest TEXT NOT NULL,
    retraction_json BLOB NOT NULL UNIQUE,
    committed_at TEXT NOT NULL
)
retraction_receipt_parents_v05 (
    retraction_id TEXT NOT NULL REFERENCES retraction_receipts_v05(retraction_id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    parent_id TEXT NOT NULL,
    PRIMARY KEY (retraction_id, ordinal),
    UNIQUE (retraction_id, parent_id)
)
```

两表均有 BEFORE UPDATE/DELETE 不可变触发器。`target_receipt_id` 不设 FK——
因为它可能指向 v0.1/v0.4 的 ActionReceipt 或 v0.5 决策，跨表族；用 digest
精确绑定，不靠 FK 关系。

### 4.4 查询 API

- `receipt_retraction_status(ledger, receipt_id)` →
  `standing | refuted | confidence_downgraded`：扫描 `retraction_receipts_v05`
  中 `target_receipt_id == receipt_id` 的最新一行（按 committed_at 因果序，
  二次撤销留给 v0.6，本版取最早一行即可——因为本版不撤销撤销，每个收据
  最多一条有效 retraction）。
- `retraction_chain(ledger, receipt_id)` → 该收据的全部 retraction 记录。

### 4.5 决策兼容

`VerificationDecisionDraftV05` / `VerificationDecisionV05` 不新增字段（冻结面）。
决策合成入口 `prepare_verification_decision_v05` 在检查证据时若发现某
`action_receipt_ids` 指向的收据已被 `evidence_refuted` 撤销，则该决策
reason_codes 追加 `RECEIPT_RETRACTED` 且决策收敛 UNKNOWN（无法依赖被反驳的
证据）——除非正臂 `expectation_status == contradicted`（此时 REFUTED 优先）。

## 5. 威胁模型与失败关闭

1. 伪造 retraction 指向不存在的收据 → digest 校验失败关闭。
2. 伪造 retraction 指向不同收据（id 对 digest 不匹配）→ 拒绝。
3. 非 Manager/Verifier 签发 → 签名/绑定校验失败。
4. retraction 时间早于目标收据 → 拒绝（因果倒置）。
5. 用 retraction 掩盖真实失败（把 REFUTED 收据标回 standing）→ 本版不允许
   撤销撤销；重复 retraction 同一收据且 effect 冲突 → 拒绝或按最早行。
6. `evidence_refuted` + `confidence_downgrade` 组合 → 拒绝（§4.1 约束 5）。
7. 离线包篡改 retraction 链 → 重放失败关闭。
8. 账本物理篡改 retraction 行 → 不可变触发器 + 重放校验失败。

## 6. 测试与验收标准

### 6.1 模型与 Schema

- closed JSON；未知字段、重复数组、错误摘要、错误时间全部拒绝；
- digest 重算、domain 分离、签名角色校验；
- v0.1–v0.5 冻结 schema SHA 与 golden signing bytes 不变（新增对象不影响）。

### 6.2 事务

- pre-COMMIT fault 零写入；COMMIT-ACK 回读；并发单赢家；UPDATE/DELETE
  物理拒绝；cleanup 失败不改变 committed truth。

### 6.3 决策兼容

- 被 `evidence_refuted` 撤销的收据 → 决策 UNKNOWN + `RECEIPT_RETRACTED`；
- 正臂 contradicted 时 REFUTED 优先；
- 被 `confidence_downgrade` 撤销的收据 → 决策不受影响（降级不反驳）。

### 6.4 敌对矩阵

至少覆盖 §5 全部 8 类攻击，`model_dump -> mutate -> model_validate` 重建。

### 6.5 离线包

- 无仓库、无网络、无原始账本的独立临时目录重放，retraction 链可见；
- 篡改任一 retraction 字段、证据、签名、关系必须失败关闭。

### 6.6 全量门

- v0.5 focused 套件零失败（新增 retraction 测试并入）；
- v0.1–v0.5 frozen compatibility 零失败（216 基线）；
- candidate 两套件零失败；
- required-live 全量零失败、零 skip、零 warning。

## 7. 实施边界与诚实声明

- 本规格是协议能力，不是客户案例、付款、上游采纳或商业验证。
- `customer_adoption / paid_sow / deposit / upstream_adoption /
  commercial_validation` 在取得外部证据前保持 `not_evidenced`。
- RetractionReceipt 证明"协议可以表达撤销"，不证明"有人真的撤销过"、
  "撤销正确"或"下游据此行动"。
