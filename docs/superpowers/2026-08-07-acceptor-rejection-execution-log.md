# Acceptor 拒绝路径切片 — 执行过程记录

Date: 2026-08-07

Branch: `codex/acceptor-rejection`

Status: 实现完成，未合并未推送（等待审核与用户选择）

Spec: `docs/superpowers/specs/2026-08-07-openworkproof-acceptor-rejection-design.md`
Plan: `docs/superpowers/plans/2026-08-07-openworkproof-acceptor-rejection-implementation.md`

## 1. 目标与设计决策

为 final-acceptance 事务补齐 `awaiting_human -> rejected` 终态（状态机早已
允许该转换，但无任何事务/收据/回放规则/schema 实现它）。

关键设计决策（见规格 D1-D7）：

- **D1** 独立 `AcceptanceRejectionReceipt` 协议对象，不拓宽
  `AcceptanceReceipt.decision`（保留 accepted 纯语义与已有 validator）；
- **D2** 同 WorkOrder 绑定的 Acceptor 密钥签名，不加第七角色；
- **D3** 拒绝必须绑定当前 request、当前 CompositionReport、精确证据快照；
- **D4** 拒绝与接受互斥终态：一次 request 恰好产生 accepted 或 rejected 之一；
- **D5** 拒绝理由为闭式码：EVIDENCE_INSUFFICIENT / INDEPENDENCE_UNSATISFIED /
  GLOBAL_POSTCONDITION_FAILED / BUSINESS_DECISION；
- **D6** 复用现有原子事务模式（BEGIN IMMEDIATE / COMMIT / exact readback）；
- **D7** prepare 草稿不在本切片范围（Acceptor 直接签名完整对象，同
  commit_acceptance 的输入方式）。

## 2. Commit 清单（8 个，HEAD `c26acad`）

| # | SHA | 内容 |
|---|-----|------|
| 1 | `ba34c89` | docs: design acceptor rejection transaction（规格） |
| 2 | `e722eff` | docs: plan acceptor rejection implementation（计划） |
| 3 | `888aa1f` | feat: model acceptor rejection receipt and schema（Task 1） |
| 4 | `1215475` | feat: replay and validate acceptor rejection suffix（Task 2） |
| 5 | `f323f2c` | feat: atomic acceptor rejection transaction（Task 3） |
| 6 | `0c2786c` | feat: enforce rejection-acceptance mutual exclusion（Task 4） |
| 7 | `776eba9` | feat: verify rejection bundles offline（Task 5） |
| 8 | `21b2b8b`/`043ce41`/`d39d052`/`c26acad` | 勾选步骤 / signing 域测试 / 新库存 / 验证记录（Task 6） |

## 3. 逐 Task 执行摘要

### Task 1 模型 + schema（`888aa1f`）

- `AcceptanceRejectionReceipt(SignedProtocolModel)`：rejection_id、
  work_order_digest、acceptance_request_receipt_id/digest、
  composition_report_digest、evidence_snapshot_digest、receipt_digests、
  causal_graph_root、reason_code（闭式）、reason_detail（<=1024）、
  decision="rejected"、rejected_at。
- validator：reason_detail 长度、receipt_digests 非空唯一；
  `validate_against_work_order` 绑定 Acceptor 签名（key_bindings[5]）且
  非 Maintainer。
- signing.py 注册域 `acceptance-rejection-receipt`。
- schema_registry：_OBJECT_PATHS / _SCHEMA_FACTORIES / _FROZEN_V01_DIGESTS
  新增对象（digest `cab32016...`），registry digest 更新为 `b543abb2...`；
  生成 specs/v0.1 与包内 src/openworkproof/schemas/v0.1（--mirror）；
  测试锚点常量（tests/test_schema_registry.py 的 OBJECT_PATHS /
  FROZEN_V01_DIGESTS / SCHEMA_FILENAMES）同步。
- 测试：规范对象通过、非法 reason_code / 超长 detail / 重复 digest 拒绝。

### Task 2 存储与回放（`1215475`）

- 新表 `acceptance_rejection_receipts`（rejection_id PK、
  work_order_digest UNIQUE、acceptance_request_receipt_id UNIQUE、json）。
- `_validated_acceptance_rejections`：镜像 acceptance 校验（canonical、
  WorkOrder 绑定、Acceptor 签名、request 绑定）。
- `_derive_protocol_transaction_version` 增加 `acceptance_rejections` 参数。
- `_validated_receipt_prefix` 后缀校验支持双终态：accepted（现有）或
  rejected（新），且二者互斥、request tip 必须 awaiting_human。
- 新增 `rejection_id` 域函数、`_expected_rejection_payload`、
  `validate_rejection_bindings`（在 acceptance.py）。
- 测试：插入行后 replay 重建 rejected 终态；篡改行拒绝；非 awaiting_human
  tip 拒绝。

### Task 3 原子事务（`f323f2c`）

- `reject_acceptance_transaction`：锁、冻结秒、require_current_context、
  awaiting_human 门、request tip 绑定、Acceptor 签名、rejected_at 时间窗
  （>= request.occurred_at、<= now、<= expires_at、<= deadline）、
  证据快照/ID/payload 一致性、BEGIN IMMEDIATE 内互斥检查 + 插入 + 状态
  推进（awaiting_human -> rejected, version+1）、COMMIT-ACK 丢失时
  `_readback_rejection_committed` 证明后抛 AcceptanceCommittedError、
  readback 失败抛 AcceptanceCommitIndeterminateError。
- 测试：happy path（状态 ("rejected", 8)）、错误角色签名、future
  rejected_at（零写入）、COMMIT-ACK 丢失恢复、readback indeterminate。

### Task 4 互斥（`0c2786c`）

- 测试：accept 后 reject / reject 后 accept / 二次 rejection 全部
  fail-closed 零写入。
- **发现并修复生产 bug**：`require_current_context`（runtime_context.py）
  的版本推导只传 `acceptance_receipts=()`，导致任何 acceptance/rejection
  提交后的 context 校验永远失败（acceptance 路径同受影响）。修复为读取
  `_validated_acceptance_receipts` + `_validated_acceptance_rejections`
  参与版本计算。
- `_current_run_tests_context`（test_mcp_server.py）补终态覆盖
  （accepted/rejected/frozen 从 state 行读取），使测试基建反映账本终态。
- 终态语义：derive_authorization_context 是纯函数（仅从 prefix 推导），
  无法重建终态 -> require_current_context 对终态 context 必然失败 ->
  调用方走 readback 幂等确认（"the exact rejection is already committed"），
  这是正确 fail-closed，测试据此断言。

### Task 5 离线验签（`776eba9`）

- `verify_acceptance_bundle` 增加 `rejection` 参数：与 acceptance 恰好
  二选一（互斥校验），rejection 分支调 `validate_rejection_bindings`。
- 测试：rejection bundle 离线验证通过；双终态同时给出被拒；rejection
  重建式篡改 / evidence 字节篡改 / 公钥替换均 fail closed。

### Task 6 验证与收尾

- focused 11 套件：**1058 passed**（含 signing 域集合测试更新，
  `043ce41`）。
- candidate 完整门：**146 passed**（image 63 + integration 83）。
- full required-live：**2226 passed、0 failed、0 skip、exit 0**（536s）。
- 新候选库存绑定 `043ce41`（commit `d39d052`），未覆盖历史库存。
- pip check / compileall / git diff check 通过；Docker 容器与卷残留 0。
- README/status 更新：拒绝路径从"尚未完成"移除，计数更新。

## 4. 关键坑与经验

- rejection 的 `causal_graph_root` 必须用 **report 的 root**（报告前缀），
  不是完整 prefix 的 root（测试 helper 一开始用错导致 binding 失败）。
- `"rejected_at < request.occurred_at"` 分支在同秒构造下遮蔽 300s stale
  分支（request.occurred_at == fixed_now），stale 端到端不可达，代码保留
  检查，测试覆盖可达路径（future）。
- dataclasses.replace 触发 pydantic `__post_init__`——execution id 必须
  合法 64 hex。
- 终态（accepted/rejected）下 context 重建无法精确复现 -> 事务走
  readback 幂等路径，属于协议预期而非缺陷。

## 5. 验证门结果

| 门 | 结果 |
|---|---|
| 独立专项（test_acceptor_rejection） | 18 passed |
| focused 协议套件 | 1058 passed（292s） |
| candidate 完整门 | 146 passed（200s） |
| full required-live | 2226 passed、0 failed、0 skip、exit 0（536s） |
| pip / compileall / diff | 通过 |
| Docker 容器与卷残留 | 0 |

## 6. 当前状态与待办

- 分支 `codex/acceptor-rejection`：8+ 个 commit（含计划/规格），
  领先 origin/main **11** 个提交，工作树干净。
- 未合并、未推送（等待用户选择与审核）。
- 后续边界（status.md 权威清单）：真实无网执行器 driver、MCP/CLI/
  AgentTeams、Developer mode、repo_read/rollback handler、deny/rollback
  生产事务、ResolutionManifest 独立重哈希、真实外部 Acceptor、演示、
  交付验证签署、赛事。
