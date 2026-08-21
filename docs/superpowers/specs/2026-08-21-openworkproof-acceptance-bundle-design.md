# OpenWorkProof Acceptance Bundle 0.1 设计规格

**状态：** 用户已确认（含 2026-08-21 跨版本绑定修订）
**日期：** 2026-08-21  
**范围：** 为已验证的 Surface Bundle 追加可离线复核的人工验收事实；不修改冻结的 v0.5 Delivery Package，不实现支付、结算或自动验收。

## 1. 问题与目标

OpenWorkProof 1.3 的 Surface Bundle 可以证明机器验证结论，但当前 v0.5 Delivery
Package 没有携带 `verify_acceptance_bundle` 所需的完整 CompositionReport、Grant
历史和 committed evidence。单独读取一个外部 AcceptanceReceipt 只能验证自签名，
不能证明它绑定了正确的 WorkOrder、报告、receipt prefix 和证据快照。

本规格新增 companion `Acceptance Bundle 0.1`。它嵌套一个原样、已验证的 Surface
Bundle，并补齐人工验收离线回放需要的最小证明材料。验收包必须能在无原账本、无
执行环境、无私钥和无网络的情况下返回唯一终态：`ACCEPTED` 或 `REJECTED`。

现有 `AcceptanceReceipt 0.1` 只签名绑定 `CompositionReport`，而 v0.5
`VerificationDecision` 是另一条签名链。两者共享 WorkOrder 只能证明“属于同一工作
契约”，不能证明“Acceptor 接受或拒绝的正是该 v0.5 验证结论”。因此本规格同时新增
Acceptor 签名的 companion `AcceptanceDecisionBindingV01`，禁止依赖未签名的外层
manifest 把两份独立有效的证明拼成同一交付事实。

## 2. 明确非目标

- 不修改 v0.5 Delivery Package schema、签名字节或冻结哈希。
- 不修改或重新解释冻结的 `AcceptanceReceipt 0.1`、
  `AcceptanceRejectionReceipt 0.1` 签名字节。
- 不让 AgentTeams、MCP Server 或 CLI 生成 Acceptor 私钥或替人做决定。
- 不把 `VERIFIED`、`ACCEPTED` 写成已付款、可结算、法律审计通过或客户采用。
- 不处理 AcceptanceTransitionReceipt 的撤回或替换；出现 transition history 时
  0.1 exporter 必须 fail closed，后续另发新版本。
- 不支持 public/diagnostic Delivery Package；嵌套 Surface 必须来自
  `customer_private`、`full_offline_replay=true` 的 v0.5 包。

## 3. 信任边界

1. WorkOrder 中角色为 `Acceptor` 的唯一 KeyBinding 是 Acceptor trust root；外部
   文件不能新增或替换信任公钥，也不得依赖数组位置推断角色。
2. Acceptance Bundle manifest 只提供完整性，不是新的授权或验收信任根。
3. CompositionReport、Grant、receipt 与 committed evidence 必须从同一权威账本
   快照导出，并由既有 `verify_acceptance_bundle` 完整重放。
4. 嵌套 Surface Bundle 必须先通过 `verify_surface_bundle`；验收证明不能覆盖或
   降级机器验证结果。
5. `AcceptanceDecisionBindingV01` 必须由 WorkOrder 的 Acceptor 签名，并精确绑定
   Surface 中的 v0.5 VerificationDecision、CompositionReport、验收请求和终态
   receipt；外层 manifest 不能替代该签名。
6. 仅当嵌套 Surface 的 report 为 `VERIFIED`、旧式验收证明完整且 companion binding
   完整时，验收终态才可输出。

## 4. 目录格式

```text
acceptance-manifest.json
surface/                         # 原样复制的完整 Surface Bundle
acceptance/effective-grants.json
acceptance/grant-attempts.json
acceptance/composition-reports.json
acceptance/committed-evidence-index.json
acceptance/evidence/<safe-relative-path>
acceptance/terminal-receipt.json # AcceptanceReceipt 或 AcceptanceRejectionReceipt
acceptance/decision-binding.json # AcceptanceDecisionBindingV01
verify.sh
```

所有 JSON 都使用 RFC 8785 JCS canonical bytes。文件路径只允许规范化相对 POSIX
路径；拒绝绝对路径、`..`、反斜杠、NUL、symlink、hardlink、FIFO 和设备文件。
上限沿用 Surface Bundle：4096 个文件、单文件 64 MiB、总计 512 MiB。

### 4.1 AcceptanceManifestV01

```python
class AcceptanceManifestV01(ProtocolModel):
    schema_version: Literal["openworkproof-acceptance-bundle/0.1"]
    surface_manifest_digest: Digest64
    delivery_manifest_digest: Digest64
    work_order_digest: Digest64
    verification_decision_digest: Digest64
    composition_report_digest: Digest64
    terminal_decision: Literal["accepted", "rejected"]
    terminal_receipt_digest: Digest64
    acceptance_decision_binding_digest: Digest64
    entries: tuple[AcceptanceManifestEntry, ...]
```

`entries` 覆盖除 `acceptance-manifest.json` 自身外的全部文件，并按 UTF-8 bytes
排序且唯一。摘要定义如下：

- `surface_manifest_digest`：嵌套 `surface/surface-manifest.json` 原始 canonical
  bytes 的 SHA-256；
- `delivery_manifest_digest`：嵌套 Surface report 已绑定的 Delivery Package
  `manifest.json` bytes SHA-256；
- `composition_report_digest`：调用既有 `composition_report_digest(final_report)`；
- `terminal_receipt_digest`：终态 receipt 的既有协议 digest。
- `verification_decision_digest`：嵌套 Surface 完整离线重放得出的当前 v0.5
  VerificationDecision digest；
- `acceptance_decision_binding_digest`：companion binding 的协议 digest。

### 4.2 AcceptanceDecisionBindingV01

```python
class AcceptanceDecisionBindingV01(SignedProtocolModel):
    schema_version: Literal["openworkproof-acceptance-decision-binding/0.1"]
    protocol_version: Literal["0.1"]
    binding_id: Digest64
    work_order_digest: Digest64
    verification_decision_id: Digest64
    verification_decision_digest: Digest64
    composition_report_digest: Digest64
    acceptance_request_receipt_id: Digest64
    acceptance_request_receipt_digest: Digest64
    terminal_kind: Literal["accepted", "rejected"]
    terminal_receipt_id: Digest64
    terminal_receipt_digest: Digest64
    bound_at: CanonicalUTCTime
    nonce: Digest64
```

签名域固定为 `acceptance-decision-binding`。`binding_id` 由上述语义字段（不含
`binding_id`、签名元数据和协议 digest）按固定 domain 做 JCS SHA-256 得出。它必须由
WorkOrder 中唯一 Acceptor key 签名；Maintainer、Verifier、外部自签 key 均不得成为
替代信任根。

绑定对象在终态 receipt 已由 Acceptor 签名后生成，因此 Acceptor 需要第二次显式签名：
第一次签署接受/拒绝事实，第二次确认“该终态对应此 v0.5 VerificationDecision”。实现
不得复用第一次签名、代签或从本地私钥自动生成第二次签名。

新增 append-only ledger 表保存 binding canonical JSON、digest、WorkOrder、Decision 和
terminal 外键关系。提交事务必须重新加载并验证当前 VERIFIED decision、唯一终态
receipt、CompositionReport 和验收请求；精确幂等返回已提交真相，同 ID 不同 payload、
同 terminal 多 binding、UPDATE/DELETE、pre-COMMIT 故障和 COMMIT-ACK 丢失均 fail
closed。若 decision 后续被 supersede，旧 binding 仍是历史事实，但 0.1 exporter 不得
把它输出为当前有效验收包。

## 5. 导出接口

新增纯生产接口：

```python
def export_acceptance_bundle(
    ledger: Path,
    evidence_root: Path,
    surface_bundle: Path,
    output: Path,
) -> AcceptanceManifestV01:
    ...
```

导出顺序：

1. 稳定扫描并验证 `surface_bundle`，要求机器结论为 `VERIFIED`；
2. 获取 ledger target lock，开启只读一致性事务；
3. 用现有权威 validators 加载 WorkOrder、current v0.5 VerificationDecision、
   effective grants、grant attempts、完整 receipts、全部 CompositionReports、
   committed evidence、终态 receipt 和唯一 companion binding；
4. 要求恰好一个当前终态（acceptance XOR rejection）、恰好一个与该终态匹配的
   binding，且不存在 transition history；
5. 调用 `verify_acceptance_bundle` 对旧式验收内存快照完整重放，再验证 binding 的
   Acceptor 签名、确定性 ID 和所有 cross-object 字段；
6. 要求 binding 的 VerificationDecision 与嵌套 Surface 离线重放得到的当前
   decision 精确相等，并要求 WorkOrder digest、内层 Delivery manifest digest 和
   Surface report 的 WorkOrder/source 事实一致；
7. 在同级随机临时目录写入全部文件，调用 `verify_acceptance_bundle_directory`
   自验；
8. 用 no-replace rename 原子提交。目标已存在、提交 ACK 不确定或 cleanup 失败均
   fail closed，不覆盖已有目录。

导出接口不接受 private key，也不签名。人工 Acceptor 必须先通过既有验收事务把
receipt 写入权威账本，再通过独立 prepare/sign/commit 流程提交 companion binding。
缺少 binding 的历史验收记录可以继续按旧协议读取，但不得导出 Acceptance Bundle
0.1，也不得在该格式中降级为“仅凭同一 WorkOrder 推断已绑定”。

## 6. 离线验证接口与顺序

```python
class AcceptanceBundleVerificationResult(ProtocolModel):
    schema_version: Literal["openworkproof-acceptance-bundle-result/0.1"]
    terminal_decision: Literal["ACCEPTED", "REJECTED"]
    work_order_digest: Digest64
    surface_manifest_digest: Digest64
    verification_decision_digest: Digest64
    terminal_receipt_digest: Digest64
    acceptance_decision_binding_digest: Digest64
    boundary: Literal["not payment, settlement, legal audit, or adoption"]

def verify_acceptance_bundle_directory(
    bundle: Path,
) -> AcceptanceBundleVerificationResult:
    ...
```

验证器必须按固定顺序执行：

1. 稳定扫描整棵目录并验证 AcceptanceManifest 的 exact file set、size 和 SHA-256；
2. 验证嵌套 Surface Bundle，并要求 `decision_status == "VERIFIED"`；
3. 从嵌套的已验证 customer-private Delivery Package 读取 WorkOrder 与完整 receipts；
4. 解析 companion grants、attempts、reports、evidence、terminal receipt 和
   decision binding；
5. 只从 WorkOrder KeyBindings 解码公钥；
6. 调用既有 `verify_acceptance_bundle`，重放 CompositionReport 链、receipt prefix、
   evidence snapshot、Acceptor 权威和终态签名；
7. 验证 binding 的 Acceptor 签名和确定性 ID，并逐字段要求：binding WorkOrder =
   Surface WorkOrder、binding Decision = Surface 当前 v0.5 Decision、binding report =
   离线重放 final report、binding request = receipt tip 对应的验收请求、binding terminal =
   已验证终态 receipt；
8. 重算 manifest 的全部 summary digest，并与终态类型精确比较；
9. 返回闭合结果，不信任磁盘中任何预写 status。

任一输入异常返回 operational error，CLI 退出码为 4；成功验收退出 0；合法拒绝
退出 2。0.1 不输出 UNKNOWN，因为缺证据或无法重放属于不可信输入，而不是终态。

## 7. CLI 与 AgentTeams 接入

新增 CLI：

```text
owp acceptance-bundle-build LEDGER SURFACE \
  --evidence-root PATH --output DIRECTORY
owp acceptance-bundle-verify DIRECTORY
```

AgentTeams 演示入口把 `--acceptance-receipt` 替换为
`--acceptance-bundle DIRECTORY`。流程停在 `ready_for_acceptance` 后，只轮询外部
目录出现；不持锁、不生成 receipt。目录出现后调用离线验证器：

- `ACCEPTED`：演示结束并记录 `human_acceptance: evidenced`；
- `REJECTED`：演示以可验证拒绝结束，不宣称交付成功；
- operational error/超时：退出 4，并保持 `human_acceptance: not_evidenced`。

provenance 只记录 bundle/terminal digest、终态和 event-id digest；不保存 token、
私钥、消息全文或绝对路径。

## 8. 失败与攻击矩阵

必须用 TDD 覆盖：

- 用攻击者自签 Acceptor key 重建全部外层摘要；
- Surface、Delivery Package、WorkOrder 或 CompositionReport 交换；
- 将同一 WorkOrder 下各自有效但不相干的 v0.5 Decision、CompositionReport 和终态
  receipt 拼装到同一目录；
- 缺失/重复 binding、攻击者自签 binding、错误 Acceptor key、binding ID 漂移；
- binding 中任一 Decision/report/request/terminal ID 或 digest 被替换后同步外层
  manifest；
- binding 指向已 supersede 的 Decision，或导出后当前 Decision 已变化；
- 省略/重复/乱序 report、grant、attempt、receipt 或 evidence；
- terminal receipt 同 ID 不同 payload、accept/reject 同时出现；
- receipt、report 或 evidence 被篡改后同步外层 manifest；
- path traversal、symlink、hardlink、FIFO、文件数/单文件/总大小超限；
- exporter 的 pre-commit、commit-ACK、cleanup 故障；
- 并发导出同目标和不同内容同目标；
- AgentTeams 超时、合法拒绝、无效目录和 announcement failure；
- 任一输出不得包含 private key、Matrix token、消息全文或绝对本地路径。

## 9. 完成标准

1. 冻结 v0.5 schema/hash/签名字节全部不变；
2. Acceptance Bundle round-trip 在另一临时目录离线通过，且能证明 Surface Decision、
   CompositionReport、验收请求和终态 receipt 的同一交付绑定；
3. 上述攻击矩阵全部 fail closed；
4. AgentTeams 脚本不再接受裸 AcceptanceReceipt，且不会自动做人工决定；
5. portable、focused、candidate 和 required-live 回归无新增失败；
6. 真实三 Agent、人工验收、客户采用、付款和上游采纳仍按各自证据门单独声明。
