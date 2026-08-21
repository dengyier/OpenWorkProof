# OpenWorkProof Acceptance Bundle 0.1 设计规格

**状态：** 待用户书面复核  
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

## 2. 明确非目标

- 不修改 v0.5 Delivery Package schema、签名字节或冻结哈希。
- 不让 AgentTeams、MCP Server 或 CLI 生成 Acceptor 私钥或替人做决定。
- 不把 `VERIFIED`、`ACCEPTED` 写成已付款、可结算、法律审计通过或客户采用。
- 不处理 AcceptanceTransitionReceipt 的撤回或替换；出现 transition history 时
  0.1 exporter 必须 fail closed，后续另发新版本。
- 不支持 public/diagnostic Delivery Package；嵌套 Surface 必须来自
  `customer_private`、`full_offline_replay=true` 的 v0.5 包。

## 3. 信任边界

1. WorkOrder 中第六个 KeyBinding 是唯一 Acceptor trust root；外部文件不能新增或
   替换信任公钥。
2. Acceptance Bundle manifest 只提供完整性，不是新的授权或验收信任根。
3. CompositionReport、Grant、receipt 与 committed evidence 必须从同一权威账本
   快照导出，并由既有 `verify_acceptance_bundle` 完整重放。
4. 嵌套 Surface Bundle 必须先通过 `verify_surface_bundle`；验收证明不能覆盖或
   降级机器验证结果。
5. 仅当嵌套 Surface 的 report 为 `VERIFIED` 且验收证明完整时，验收终态才可输出。

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
    composition_report_digest: Digest64
    terminal_decision: Literal["accepted", "rejected"]
    terminal_receipt_digest: Digest64
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
3. 用现有权威 validators 加载 WorkOrder、effective grants、grant attempts、完整
   receipts、全部 CompositionReports、committed evidence 和终态 receipt；
4. 要求恰好一个当前终态（acceptance XOR rejection），且不存在 transition
   history；
5. 调用 `verify_acceptance_bundle` 对内存快照完整重放；
6. 要求 WorkOrder digest、内层 Delivery manifest digest 和 Surface report
   的 WorkOrder/source 事实一致；
7. 在同级随机临时目录写入全部文件，调用 `verify_acceptance_bundle_directory`
   自验；
8. 用 no-replace rename 原子提交。目标已存在、提交 ACK 不确定或 cleanup 失败均
   fail closed，不覆盖已有目录。

导出接口不接受 private key，也不签名。人工 Acceptor 必须先通过既有验收事务把
receipt 写入权威账本。

## 6. 离线验证接口与顺序

```python
class AcceptanceBundleVerificationResult(ProtocolModel):
    schema_version: Literal["openworkproof-acceptance-bundle-result/0.1"]
    terminal_decision: Literal["ACCEPTED", "REJECTED"]
    work_order_digest: Digest64
    surface_manifest_digest: Digest64
    terminal_receipt_digest: Digest64
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
4. 解析 companion grants、attempts、reports、evidence 和 terminal receipt；
5. 只从 WorkOrder KeyBindings 解码公钥；
6. 调用既有 `verify_acceptance_bundle`，重放 CompositionReport 链、receipt prefix、
   evidence snapshot、Acceptor 权威和终态签名；
7. 重算 manifest 的四个 summary digest，并与终态类型精确比较；
8. 返回闭合结果，不信任磁盘中任何预写 status。

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
2. Acceptance Bundle round-trip 在另一临时目录离线通过；
3. 上述攻击矩阵全部 fail closed；
4. AgentTeams 脚本不再接受裸 AcceptanceReceipt，且不会自动做人工决定；
5. portable、focused、candidate 和 required-live 回归无新增失败；
6. 真实三 Agent、人工验收、客户采用、付款和上游采纳仍按各自证据门单独声明。
