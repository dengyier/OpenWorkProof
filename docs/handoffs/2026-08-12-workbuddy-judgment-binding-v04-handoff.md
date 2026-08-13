# OpenWorkProof Judgment-to-Action Binding v0.4 — WorkBuddy 交接文档

> 快照时间：2026-08-12 23:08 CST  
> 交接状态：**Task 1–5 已本地提交；Task 6 有未提交实现，局部门已绿，但尚未完成最终双审、提交、候选库存绑定、推送或合并。**  
> 本文是当前磁盘状态的接手入口，不是发布说明，也不证明客户采用、验收、付款或结算。

## 1. WorkBuddy 首先必须使用的工作区

```text
仓库：/Users/molin/Project/openWorkProof-scope-bound-verification-v03
分支：codex/judgment-action-binding-v04
HEAD：ef892b16349327808f3398041de187b8ad9a4c15
远端：git@github.com:dengyier/OpenWorkProof.git
origin/main：fe719e95fd5b34a9a5c00bb137c56db22c430fd3
分支关系：HEAD 相对 origin/main 领先 38 个提交、落后 0 个提交
远端同名分支：不存在
```

不要切换到 `/Users/molin/Project/openWorkProof` 开发；本轮 v0.4 的活动工作树就是上面的隔离目录。

接手后的第一条命令：

```bash
cd /Users/molin/Project/openWorkProof-scope-bound-verification-v03
git status --short --branch
git rev-parse HEAD
git diff --check
```

严禁在读取本文件和当前 diff 前执行 `git reset --hard`、`git checkout -- .`、`git clean -fd`、rebase、force push 或覆盖生成。

## 2. 权威规格与实施计划

- 设计规格：`docs/superpowers/specs/2026-08-12-openworkproof-judgment-action-binding-v04-design.md`
- 实施计划：`docs/superpowers/plans/2026-08-12-openworkproof-judgment-action-binding-v04-implementation.md`
- 当前计划状态：Task 1–5 已勾选；Task 6 的 6 个步骤仍未勾选；Task 7–16 未开始。

协议边界：

1. v0.4 把客户事前 `JudgmentCommitment`、Manager `ActionBindingManifest`、Agent 请求和执行回执连接成可验证因果链。
2. v0.1–v0.3 的 Schema、签名字节、历史账本和离线包必须保持兼容。
3. 绑定有效不等于交付质量正确，不等于 Acceptance、付款、结算、部署或客户采用。
4. 不新增支付轨、区块链、Dashboard、第二个 Adapter 或通用策略语言。

## 3. 已完成并提交的阶段

| 阶段 | 状态 | 关键提交 |
|---|---|---|
| Task 1：关闭 required-live socket shutdown race | 已提交 | `06ec82f`, `3f7b8c4`, `cc99f12` |
| Task 2：v0.4 closed models / signing domains | 已提交 | `88cc478`, `50de358`, `5a3475a`, `e7ad201` |
| Task 3：冻结 v0.4 schema registry | 已提交 | `e57b3f0`, `97825a8` |
| Task 4：append-only JudgmentCommitment transaction | 已提交 | `aa9fa71`, `5d68364`, `fd7cb45`, `6f07b09` |
| Task 5：ActionBindingManifest commit / supersession | 已提交 | `ff67e54`, `ef892b1` |

Task 5 已实现的关键不变量：canonical Adapter Profile 原始字节与 SHA-256、完整 WorkOrder TestProfile 精确覆盖、完整 Manifest 历史回放、Scope 原始权限谓词、图的 root/fork/cycle/disconnect 校验、mutating tool 仅使用 write roots、COMMIT-ACK 精确回读。

## 4. Task 6 当前未提交实现

目标：任何 v0.4 code-delivery 工具在 Driver、配额扣减和业务输出之前，必须通过原生 Judgment/Manifest 绑定门。

当前实现已覆盖：

- 显式 `AgentRequestV04` 版本解析；不从 metadata 推断升级。
- 公共 legacy 授权入口拒绝 V04 绕过；存在 active Manifest 时拒绝 legacy downgrade。
- `authorize_bound_action()` 联合验证旧授权语义、Judgment/Manifest 绑定、工具、动作、路径、nonce、执行事实和 high-risk checkpoint。
- v0.4 拒绝返回闭合原因码，包括 `AUTH_FRESHNESS_INVALID`、`AUTH_SIGNATURE_INVALID`、`AUTH_SUBJECT_MISMATCH` 和 `BINDING_*`。
- v0.4 deny audit 使用显式 v0.4 Receipt，而不是把新请求隐藏塞进旧 v0.1 Schema。
- 新增显式 `ToolCallReceiptV04` / `RollbackReceiptV04` sibling、`ActionReceiptV04` adapter、版本路由和 v0.4 ActionReceipt Schema。
- 旧 v0.1 ActionReceipt Schema 与签名字节保持不变。
- 混合 v0.1/v0.4 Receipt 在 state、evidence、verification、delivery package 中按显式版本路由。
- 外部 actor trust-map 仍参与验签，不能用 Receipt 自带公钥替代信任映射。
- 已启动任务恢复时，按 `reserved_at` 和历史授权前缀证明当时 Manifest 有效；允许随后 supersede，但不允许伪造历史绕过。
- 已提交 Receipt + 残留 handler journal 的恢复只清理 journal，不重复启动 Driver，不重复写 Receipt，也不把自己的 nonce 误判为新重放。

### 当前 tracked 修改

```text
specs/v0.4/schema-registry.json
src/openworkproof/binding_transactions.py
src/openworkproof/delivery_package.py
src/openworkproof/evidence.py
src/openworkproof/mcp_server.py
src/openworkproof/models.py
src/openworkproof/policy.py
src/openworkproof/schema_registry.py
src/openworkproof/schemas/v0.4/schema-registry.json
src/openworkproof/signing.py
src/openworkproof/state.py
src/openworkproof/verification.py
tests/test_binding_schema_v04.py
```

### 当前 untracked 文件

```text
specs/v0.4/action-receipt.schema.json
src/openworkproof/schemas/v0.4/action-receipt.schema.json
tests/test_binding_gateway_v04.py
specs/.openworkproof-schema-lock-3255890a9d34c27e
src/openworkproof/schemas/.openworkproof-schema-lock-a522d3b3c46f24fc
```

最后两个 `.openworkproof-schema-lock-*` 是本次生成中断后残留的 **0-byte 临时锁文件**。WorkBuddy 应先确认没有 Schema 生成进程，再只删除这两个精确文件；不要运行宽泛 `git clean`。

当前已跟踪 diff（不含新 Schema、测试和本文）：约 `759 insertions / 125 deletions`。实施计划 Task 6 的 `Files:` 清单仍是最初四文件版本，提交前必须按真实最小依赖更新，不能继续声称只改四个文件。

## 5. 2026-08-12 23:08 CST 的 fresh 验证真值

### Task 6 专项

```bash
./.venv/bin/python -m pytest tests/test_binding_gateway_v04.py -q
```

结果：`46 passed, 9 warnings in 10.82s`，退出码 0。

### Task 6 + policy/MCP/runner/schema 规定联合门

```bash
./.venv/bin/python -m pytest \
  tests/test_binding_gateway_v04.py \
  tests/test_policy.py \
  tests/test_mcp_server.py \
  tests/test_run_tests_runner.py \
  tests/test_repo_read_transaction.py \
  tests/test_binding_schema_v04.py \
  tests/test_schema_registry.py -q
```

结果：`370 passed, 2 skipped, 9 warnings in 39.97s`，退出码 0。

- 2 个 skip：真实 Landlock 仅 Linux；required-live immutable-image 门另跑。
- 9 个 warning：已知 macOS pytest `rm_rf` 清理只读/symlink 临时目录告警；不得通过全局过滤器掩盖，也不得误写成新线程异常。

### 非测试检查

```text
pip check：PASS
compileall：PASS
git diff --check：PASS
v0.4 runtime/spec schema diff：PASS
```

### Schema 哈希

```text
v0.1 action-receipt（必须保持）：
1aba0e2a9cf3b55478d5def0ef7f89d84976fc22798bb6d709d21afb31cedde8

v0.4 action-receipt（runtime 与 specs 相同）：
7a7cd836da6f15bc003e96bc7b0b6ac1357c422f09395da9da050ec2f66f181e

v0.4 schema-registry（runtime 与 specs 相同）：
66dea3711f1aa0f725b84f96b042e3b34e17713ace2f1e497df9628a2830d88d
```

### 当前明确未闭环的 candidate 门

```bash
./.venv/bin/python -m pytest tests/test_candidate_supplychain_integration.py -q
```

结果：`2 failed, 81 passed, 1 skipped, 9 warnings in 130.30s`。

失败测试：

1. `test_current_candidate_inventory_binds_execution_runner`
2. `test_current_candidate_inventory_binds_fixed_test_source`

两项均为 `current candidate definition ... matched 0`。原因是 Task 6 修改了 candidate source allowlist 内源码，但代码尚未提交，所以不存在能绑定当前 definition/revision 的不可变 inventory。**不要修改测试或复用/覆盖旧 inventory 来“消红”。** 新 inventory 必须在取得稳定提交 revision 后按 Task 16 流程新建。

最近一次完整 pytest 是最终 closed-code 修订前的中间快照：`2874 passed, 4 failed, 7 skipped`；其中 2 个 Schema 冻结清单失败已经修复，2 个 candidate 失败仍存在。因为后续又修改了代码，这个数字不能作为当前最终全量证据。

## 6. 仍未满足的 Task 6 完成条件

1. 最后一次 closed-code 修订后，独立 spec review 和独立 quality review 被会话中断；当前没有最终双 `READY`。
2. 最终磁盘快照尚未跑一遍完整 portable suite；当前只有专项/联合门真值。
3. Task 6 所有改动尚未提交，计划的 6 个步骤仍未勾选。
4. candidate inventory 需等代码提交后生成；Task 16 前不能宣称 release gate 全绿。
5. required-live Docker、严格 thread-warning、candidate artifact root、clean-cache/OCI 链尚未为本 revision 执行。
6. 当前分支未推送、未合并、未开 PR；远端同名分支不存在。

## 7. WorkBuddy 的精确接手顺序

### A. 冻结并审查现有 diff

```bash
cd /Users/molin/Project/openWorkProof-scope-bound-verification-v03
git status --short --branch
git diff -- src/openworkproof/models.py src/openworkproof/signing.py
git diff -- src/openworkproof/policy.py src/openworkproof/mcp_server.py
git diff -- src/openworkproof/state.py src/openworkproof/evidence.py
git diff -- src/openworkproof/verification.py src/openworkproof/delivery_package.py
git diff -- src/openworkproof/binding_transactions.py src/openworkproof/schema_registry.py
git diff -- tests/test_binding_gateway_v04.py tests/test_binding_schema_v04.py
```

审查重点：

- 旧 v0.1 factory/adapter/schema/hash 未改写。
- 新 V04 Receipt 的 outer signature domain 确实使用 0.4。
- 所有混合账本读取点均显式按 `protocol_version` 路由。
- 新执行只接受 current Manifest；恢复执行验证 `reserved_at` 历史 Manifest。
- `state.py` 同时验证外部 trust-map 和 nested claim 权威。
- 所有可审计拒绝使用闭合码；格式损坏原始字节可作为解析异常。
- 没有提前实现 Task 7 deterministic adapter、Task 8 BindingDecision 或 Task 10 AuthorityCheckpoint。

### B. 清理精确临时锁并重跑生成确定性

只在确认没有生成器运行后删除两个精确 0-byte lock。随后按 Task 3 已有生成方式分别生成到两个临时目录，比较 runtime/spec bytes；不要直接把第一次生成结果当权威。

必须证明：

1. 新 V04 Receipt 对 v0.4 Schema 通过。
2. 同一 V04 Receipt 对旧 v0.1 Schema 拒绝。
3. legacy Receipt 对旧 v0.1 Schema 通过。
4. v0.1 hash 仍是 `1aba0e2a...`。

### C. 重跑门并取得双审

先跑第 5 节联合门，再补：

```bash
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests/test_binding_gateway_v04.py tests/test_binding_schema_v04.py
git diff --check
```

然后安排两个互相独立、只读的审查：

- Spec review：逐条对 Task 6 Steps 1–5 和设计 §9。
- Quality/security review：恢复并发、版本路由、外部 trust-map、closed-code deny audit、无重复 Driver/Receipt。

任何 Important/Minor 都先写 RED 再修；修后必须重新双审。

### D. Task 6 提交边界

只有当联合门全绿、双审 READY 且工作树只含解释得清的 Task 6 文件时：

1. 更新实施计划 Task 6 `Files:` 为真实文件集合。
2. 勾选 Task 6 Steps 1–5。
3. 暂存精确 Task 6 文件，检查 `git diff --cached --stat`。
4. 提交代码：

```bash
git commit -m "feat: deny unbound v0.4 actions before execution"
```

5. 提交后重跑 Task 6 专项和联合门。
6. 将 Step 6 勾选，并用单独 docs commit 记录 Task 6 完成。

不要在此阶段推送、合并或生成虚假的 release-green 状态。candidate inventory 是 revision-bound；若严格按原计划，应在 Task 16 统一新建并跑 required-live。若项目 Owner 决定 Task 6 提交后立即闭合 candidate，则必须新建 inventory，不能修改历史 inventory，并把这作为单独供应链提交和证据门。

### E. 进入 Task 7

Task 6 完成后，下一项是：`Task 7: Implement the Deterministic GitHub Code-Delivery Adapter`。

严格只做首个 GitHub code-delivery adapter：先冻结 canonical fixtures，再写 mapping RED，最后实现纯 canonicalization。不要添加第二 adapter、LLM judgment 路径或通用策略语言。

## 8. 禁止错误表述

当前最多可以说：

> OpenWorkProof v0.4 Judgment-to-Action Binding 的 Task 1–5 已在本地分支提交；Task 6 原生执行前绑定门已有未提交实现，fresh 专项和联合回归通过，但最终双审、完整全量、revision-bound candidate、required-live、提交、推送和合并尚未完成。

不能说：

- “Task 6 已发布/已合并/已推送”
- “v0.4 全部开发完成”
- “全量测试零失败”
- “候选镜像已经绑定当前 revision”
- “客户已验收、采用、付款或结算”
- “赛事已提交或官方接受”

## 9. 给 WorkBuddy 的复制粘贴任务说明

```text
请在 /Users/molin/Project/openWorkProof-scope-bound-verification-v03 的
codex/judgment-action-binding-v04 分支继续工作。

先完整阅读：
1. docs/handoffs/2026-08-12-workbuddy-judgment-binding-v04-handoff.md
2. docs/superpowers/specs/2026-08-12-openworkproof-judgment-action-binding-v04-design.md
3. docs/superpowers/plans/2026-08-12-openworkproof-judgment-action-binding-v04-implementation.md

当前 HEAD ef892b1，Task 1-5 已提交；Task 6 是未提交 dirty snapshot。
不要 reset/clean/切换目录，不要覆盖旧 Schema 或历史 candidate inventory。

先冻结并审查当前 diff，清理两个精确 0-byte schema lock，重跑 Task 6 规定联合门、
schema 双向互操作断言、pip/compileall/diff-check，并取得独立 spec + quality 双 READY。
若有缺陷，严格先写 RED 再最小修复。只有全部通过后才更新 Task 6 计划文件清单、
勾选并提交 feat: deny unbound v0.4 actions before execution；提交后重新验证。

不得推送或合并，除非项目 Owner 另行明确授权。Task 6 完成后按计划进入 Task 7。
```

---

## 最终状态更新（2026-08-13 02:5x CST）

> 上文是 2026-08-12 23:08 的交接快照，仅代表当时磁盘状态。截至
> 2026-08-13，v0.4 已全部完成并收口：

- Task 6–16 全部实现并**已推送远端 main**（`main == origin/main == c5f605a`）
- 独立只读双审 READY（B1/B2 已修复）；candidate inventory 绑定
  `c3275f4`；candidate 两套件零失败（`test_image_supply_chain` 68 +
  `test_candidate_supplychain_integration` 98，含 live）
- required-live 全量零失败零 skip；Docker 29.5.2 下经
  `supply-chain/images/convert_docker_archive.py` 生成 docker-v2 契约归档
- 诚实边界不变：无客户采用、无付费 SOW、无定金（全部 not_evidenced）；
  pilot 材料见 `docs/pilot/`

本文件同时保留历史快照与最终状态，读者以最新更新为准。
