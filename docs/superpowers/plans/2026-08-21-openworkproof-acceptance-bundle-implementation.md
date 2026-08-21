# OpenWorkProof Acceptance Bundle 0.1 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to execute this plan task-by-task. Each Task must
> follow strict RED → GREEN → focused regression → review → commit. Do not
> batch unrelated Tasks into one commit.

**Goal:** 在不修改 v0.1–v0.5 冻结协议字节的前提下，交付 Acceptor 签名的
`AcceptanceDecisionBindingV01` 与可完全离线复核的 Acceptance Bundle 0.1，证明
Surface v0.5 VerificationDecision、CompositionReport、验收请求和接受/拒绝终态属于
同一交付。

**Architecture:** v0.5 customer-private Delivery Package 仍是机器验证权威；Surface
Bundle 仍是环境与报告外层；Acceptance Bundle 作为第二层 companion，原样嵌套已验证
Surface，并补齐旧式验收回放材料。Acceptor 对旧式 terminal receipt 和新的跨版本
binding 分别显式签名。外层 manifest 只做文件完整性，不建立信任。

**Tech Stack:** Python 3.10–3.13、Pydantic v2、RFC 8785 JCS、Ed25519/
cryptography、SQLite append-only ledger、argparse CLI、AgentTeams Matrix demo、pytest、
JSON Schema Draft 2020-12。

---

## 0. 规格、边界与执行纪律

权威设计：
`docs/superpowers/specs/2026-08-21-openworkproof-acceptance-bundle-design.md`

当前执行分支：`codex/openworkproof-13-dual-surface`。不得直接在 `main` 开发；不得在
本计划中 push、merge、tag、发布 PyPI/MCP 或声称客户采用。

每个 Task 固定执行：

1. 只写该 Task 的失败测试；
2. 运行精确命令并保存可复现 RED；
3. 写最小生产实现；
4. 运行精确测试、相邻回归、`pip check`、`compileall`、`git diff --check`；
5. 做只读规格/质量复核；
6. 只提交该 Task 文件，不改写历史 commit。

全程保持以下事实边界：

- `VERIFIED != ACCEPTED != PAID != SETTLED != LEGAL_AUDIT_PASSED`；
- Acceptance Bundle 0.1 不支持 transition history；
- 缺 binding 的历史 AcceptanceReceipt 仍可按旧协议读取，但不能导出本格式；
- AgentTeams 不持有 Acceptor 私钥，不自动做人工决定；
- 不修改 v0.1–v0.5 已发布 schema、registry、签名字节或 frozen hash。

## 1. 目标文件

### 1.1 新建

| 文件 | 单一职责 |
|---|---|
| `src/openworkproof/acceptance_bundle.py` | Acceptance Bundle manifest/result、稳定扫描、离线验证、原子导出 |
| `tests/test_acceptance_decision_binding_v01.py` | binding 模型、签名、事务、时间、幂等与不可变测试 |
| `tests/test_acceptance_bundle_v01.py` | bundle round-trip、交叉绑定、篡改、路径与原子导出测试 |
| `tests/test_agentteams_acceptance_bundle_v13.py` | AgentTeams 等待、接受、拒绝、超时与 provenance 测试 |

### 1.2 修改

| 文件 | 变更 |
|---|---|
| `src/openworkproof/models.py` | 新增 companion `AcceptanceDecisionBindingV01` 与严格适配器 |
| `src/openworkproof/signing.py` | 只新增 `acceptance-decision-binding` 0.1 签名域 |
| `src/openworkproof/evidence.py` | 新增 append-only binding 表、索引和 immutable triggers |
| `src/openworkproof/acceptance.py` | binding prepare/commit/load/readback 事务与权威重放 |
| `src/openworkproof/companion_schema_registry.py` | 注册 binding、bundle manifest/result companion schema |
| `src/openworkproof/services.py` | Acceptance Bundle build/verify facade |
| `src/openworkproof/cli.py` | `acceptance-bundle-build/verify` 与闭合退出码 |
| `src/openworkproof/__init__.py` | 懒加载公开 API，不引入 import side effect |
| `agentteams/scripts/run_openworkproof_13_demo.py` | 裸 receipt 改为外部 bundle，停在 ready_for_acceptance |
| `README.md`、`README_en.md` | 双签流程、CLI、诚实边界 |
| `docs/status.md` | 记录实现与真实测试结果，不写客户/付款推断 |
| `tests/test_companion_schema_registry.py` | companion schema 集合、双目录与旧 hash 冻结 |
| `tests/test_v02_interfaces.py` | 服务/CLI/公共接口契约 |
| `tests/test_documentation_boundaries.py` | README/status 边界断言 |
| `specs/companion-v0.1/*.json` | 发布镜像，由生成器写入 |
| `src/openworkproof/schemas/companion-v0.1/*.json` | wheel 内 companion schema，由生成器写入 |

---

## Task 1：冻结基线与跨版本攻击的 RED 证明

**Files:**
- Create: `tests/test_acceptance_decision_binding_v01.py`
- Modify: none in production

- [ ] **Step 1: 记录工作树、revision 与冻结摘要**

```bash
git status --short --branch
git rev-parse HEAD
./.venv/bin/python -m pytest -q \
  tests/test_acceptance.py \
  tests/test_acceptance_v03.py \
  tests/test_acceptance_v05.py \
  tests/test_delivery_package_v05.py \
  tests/test_surface_bundle_v01.py \
  tests/test_signing.py \
  tests/test_schema_registry.py
./.venv/bin/python -m pip check
```

Expected：记录实际 passed/failed/skipped/warnings；不复制历史数字。

- [ ] **Step 2: 写“各自有效但未绑定”的失败测试**

构造同一 WorkOrder 下：

1. v0.5 `VerificationDecision A == VERIFIED`；
2. 旧式 `CompositionReport/AcceptanceReceipt B`；
3. 两条签名链分别有效；
4. 断言新的 cross-binding validator 必须拒绝 A+B。

同时冻结旧 `AcceptanceReceipt 0.1`、v0.5 VerificationDecision 和主 schema registry
hash 不变。

- [ ] **Step 3: 运行并观察 RED**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_acceptance_decision_binding_v01.py -k \
  'unbound_cross_version_pair or frozen'
```

Expected：collection/ImportError 或缺 validator 导致 FAIL；不得先写生产实现。

- [ ] **Step 4: 仅提交测试基线（若仓库惯例允许测试先行 commit）**

若保持红测试会阻断分支共享，则不单独提交，留到 Task 2 同 commit；必须在执行日志记录
RED 命令、失败数和根因。

---

## Task 2：AcceptanceDecisionBindingV01 模型、签名域与 companion schema

**Files:**
- Modify: `src/openworkproof/models.py`
- Modify: `src/openworkproof/signing.py`
- Modify: `src/openworkproof/acceptance_bundle.py`
- Modify: `src/openworkproof/companion_schema_registry.py`
- Modify: `tests/test_acceptance_decision_binding_v01.py`
- Modify: `tests/test_companion_schema_registry.py`
- Regenerate: `src/openworkproof/schemas/companion-v0.1/*.json`
- Regenerate: `specs/companion-v0.1/*.json`

- [ ] **Step 1: 扩充 RED 矩阵**

覆盖：closed schema、严格类型、unknown fields、Digest64、canonical UTC、terminal kind 与
ID 字段一致、确定性 `binding_id`、非 Acceptor key、错误签名、错误 WorkOrder、错误
Decision/report/request/terminal、nonce 漂移、恶意 model subclass 重校验。

- [ ] **Step 2: 实现最小模型和签名路由**

在 `models.py` 新增：

- `AcceptanceDecisionBindingV01`；
- `ACCEPTANCE_DECISION_BINDING_V01_ADAPTER`；
- `acceptance_decision_binding_id(...)` 纯函数。

在 `signing.py` 只把 `acceptance-decision-binding` 加入 v0.1 canonical/signed domain。
不得改变任何旧 domain 的 canonical bytes。

- [ ] **Step 3: 将三个新对象加入 companion registry**

新增 object types：

- `acceptance-decision-binding`；
- `acceptance-bundle-manifest`；
- `acceptance-bundle-result`。

Manifest/result 模型可先放入 `acceptance_bundle.py` 的最小模型壳；不得实现文件 I/O。

- [ ] **Step 4: 双目标确定性生成**

```bash
./.venv/bin/python -m openworkproof.companion_schema_registry \
  --destination src/openworkproof/schemas/companion-v0.1 \
  --mirror specs/companion-v0.1
tmp1="$(mktemp -d)"
tmp2="$(mktemp -d)"
./.venv/bin/python -m openworkproof.companion_schema_registry --destination "$tmp1"
./.venv/bin/python -m openworkproof.companion_schema_registry --destination "$tmp2"
diff -ru "$tmp1" "$tmp2"
diff -ru "$tmp1" src/openworkproof/schemas/companion-v0.1
```

- [ ] **Step 5: GREEN 与冻结兼容门**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_acceptance_decision_binding_v01.py \
  tests/test_companion_schema_registry.py \
  tests/test_signing.py \
  tests/test_schema_registry.py
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests
git diff --check
```

- [ ] **Step 6: 提交**

```bash
git add src/openworkproof/models.py src/openworkproof/signing.py \
  src/openworkproof/acceptance_bundle.py \
  src/openworkproof/companion_schema_registry.py \
  src/openworkproof/schemas/companion-v0.1 \
  specs/companion-v0.1 \
  tests/test_acceptance_decision_binding_v01.py \
  tests/test_companion_schema_registry.py
git commit -m "feat: define acceptance decision binding"
```

---

## Task 3：append-only binding 账本与 prepare/sign/commit 事务

**Files:**
- Modify: `src/openworkproof/evidence.py`
- Modify: `src/openworkproof/acceptance.py`
- Modify: `tests/test_acceptance_decision_binding_v01.py`

- [ ] **Step 1: 写事务 RED**

覆盖 accepted/rejected 两终态：

- 正确 Acceptor 签名提交；
- prepare 返回 exact signing payload，不接收私钥；
- current v0.5 Decision 必须 VERIFIED；
- binding 精确匹配唯一 terminal、CompositionReport 与 acceptance request；
- non-Acceptor、错误 key、坏签名、stale/superseded Decision 拒绝；
- exact replay 返回 already-committed truth；
- 同 ID 不同 payload、同 terminal 第二 binding 拒绝；
- UPDATE/DELETE 和关系漂移物理拒绝；
- pre-COMMIT 零写、真实 COMMIT 后 ACK 丢失回读、readback unavailable；
- 并发 identical 恰一 committed + 一 already_committed；冲突并发仅一行。

- [ ] **Step 2: 新增最小表结构**

`acceptance_decision_bindings_v01` 至少保存：binding ID/digest、WorkOrder digest、
Decision ID、terminal ID、canonical JSON、committed_at。添加必要 query index、唯一
terminal 约束、WorkOrder/Decision 外键和 UPDATE/DELETE triggers。用 PRAGMA 测试冻结
精确索引集合，避免无意 auto-index 膨胀。

- [ ] **Step 3: 实现 prepare/load/commit**

公开 API：

```python
prepare_acceptance_decision_binding(...)
commit_acceptance_decision_binding(...)
load_current_acceptance_decision_binding(...)
```

事务必须在 target lock 内重新加载完整 v0.5 Decision chain、验收 suffix、report/request
和 WorkOrder Acceptor binding。`bound_at` 使用调用方冻结的 canonical transaction time；
历史回放用已存 committed_at 验证，不用 wall clock 重写事实。

- [ ] **Step 4: 运行 GREEN 与相邻回归**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_acceptance_decision_binding_v01.py \
  tests/test_acceptance.py tests/test_acceptance_v03.py tests/test_acceptance_v05.py \
  tests/test_settlement_readiness.py tests/test_replay.py
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests
git diff --check
```

- [ ] **Step 5: 提交**

```bash
git add src/openworkproof/evidence.py src/openworkproof/acceptance.py \
  tests/test_acceptance_decision_binding_v01.py
git commit -m "feat: commit acceptance decision bindings"
```

---

## Task 4：Acceptance Bundle 文件模型与稳定快照读取

**Files:**
- Modify: `src/openworkproof/acceptance_bundle.py`
- Create: `tests/test_acceptance_bundle_v01.py`

- [ ] **Step 1: 写路径与 manifest RED**

覆盖 exact file set、UTF-8 byte 排序唯一、JCS canonical JSON、绝对路径、`..`、反斜杠、
NUL、symlink、hardlink、FIFO、device、文件数/单文件/总大小、读时 inode/mtime/size
漂移、manifest summary digest 不一致。

- [ ] **Step 2: 实现只读稳定扫描**

复用 `surface_bundle.py` 已验证的安全语义；若直接复用 private helper 会形成不稳定耦合，
只提取最小 `bundle_io.py` 前必须先有 Surface 回归证明字节与错误分类不变。不要为了
“通用化”重构无关逻辑。

- [ ] **Step 3: 实现 manifest parse/compose，不实现语义验收**

只完成：文件扫描、entry hashing、required allowlist、manifest canonical parse 和 verify
script exact bytes。此 Task 不调用 ledger，不判断 ACCEPTED/REJECTED。

- [ ] **Step 4: GREEN**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_acceptance_bundle_v01.py -k 'manifest or path or link or limit or stable'
./.venv/bin/python -m pytest -q tests/test_surface_bundle_v01.py
git diff --check
```

- [ ] **Step 5: 提交**

```bash
git add src/openworkproof/acceptance_bundle.py tests/test_acceptance_bundle_v01.py
git commit -m "feat: validate acceptance bundle snapshots"
```

---

## Task 5：完整离线验证与同一交付 binding

**Files:**
- Modify: `src/openworkproof/acceptance_bundle.py`
- Modify: `tests/test_acceptance_bundle_v01.py`

- [ ] **Step 1: 写 round-trip 与拼接攻击 RED**

构造有效 accepted 与 rejected fixture，并新增：

- Surface Decision A + terminal/report B（同 WorkOrder）拼接；
- Decision/terminal/report/request 任一 ID 或 digest 替换；
- 攻击者自签 binding 后同步全部外层摘要；
- 缺失、重复、错误 Acceptor key、错误 deterministic ID；
- current Decision superseded；
- accept+reject 同时存在；
- 旧式验收有效但缺 binding；
- Surface 为 REFUTED/UNKNOWN/public/diagnostic；
- transition history 存在。

- [ ] **Step 2: 按固定顺序实现 verifier**

`verify_acceptance_bundle_directory()` 必须：

1. 稳定扫描并验证外层 exact manifest；
2. 在临时 snapshot 中调用 `verify_surface_bundle()`；
3. 从已验证 customer-private Delivery Package 重放 WorkOrder、v0.5 Decision 与 receipts；
4. 解析 grants/attempts/reports/committed evidence/terminal/binding；
5. 调用既有 `verify_acceptance_bundle()`；
6. 只从 WorkOrder 唯一 Acceptor binding 验证 companion signature；
7. 精确比较 Decision/report/request/terminal 的 ID 和 digest；
8. 返回 `ACCEPTED` 或 `REJECTED`，不读取磁盘预写 status。

- [ ] **Step 3: 闭合错误与退出语义单元测试**

验证函数只抛 `AcceptanceBundleError`；底层 JSON/Pydantic/SQLite/OSError 不得泄漏为
未分类异常。合法拒绝是验证成功的业务终态，不是 operational error。

- [ ] **Step 4: GREEN**

```bash
./.venv/bin/python -m pytest -q tests/test_acceptance_bundle_v01.py -k 'verify or round_trip or swap or binding'
./.venv/bin/python -m pytest -q \
  tests/test_surface_bundle_v01.py tests/test_delivery_package_v05.py \
  tests/test_acceptance.py tests/test_acceptance_v05.py
git diff --check
```

- [ ] **Step 5: 提交**

```bash
git add src/openworkproof/acceptance_bundle.py tests/test_acceptance_bundle_v01.py
git commit -m "feat: replay acceptance bundles offline"
```

---

## Task 6：从权威账本原子导出 Acceptance Bundle

**Files:**
- Modify: `src/openworkproof/acceptance_bundle.py`
- Modify: `tests/test_acceptance_bundle_v01.py`

- [ ] **Step 1: 写 exporter RED**

覆盖：accepted/rejected 导出、缺 binding、多个 terminal、transition、Surface/ledger
WorkOrder 不同、Decision 不同、evidence root 越界、输入输出重叠、目标已存在、并发同目标、
pre-commit、rename ACK 不确定、cleanup 故障。

- [ ] **Step 2: 实现只读一致性快照**

在 ledger target lock + read transaction 内，用现有权威 loader 获取所有验收材料。不得
直接信任裸 SQL JSON。证据文件必须按 committed evidence index 从 `evidence_root`
安全读取并重算 digest/size。

- [ ] **Step 3: 实现 sibling stage + self-verify + no-replace commit**

流程：随机同级 stage → 写完整文件 → fsync → 调离线 verifier 自验 → 确认目标仍不存在
→ rename。异常后若目标可完整回读为 exact manifest，返回 committed truth；否则报
indeterminate/operational error。cleanup error 不得掩盖 committed 状态。

- [ ] **Step 4: GREEN 与残留检查**

```bash
./.venv/bin/python -m pytest -q tests/test_acceptance_bundle_v01.py
find "$(dirname "$TMPDIR")" -maxdepth 1 -name '.openworkproof-acceptance-*' -print
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests
git diff --check
```

- [ ] **Step 5: 提交**

```bash
git add src/openworkproof/acceptance_bundle.py tests/test_acceptance_bundle_v01.py
git commit -m "feat: export acceptance bundles atomically"
```

---

## Task 7：Services、CLI、公开 API 与 verify.sh

**Files:**
- Modify: `src/openworkproof/services.py`
- Modify: `src/openworkproof/cli.py`
- Modify: `src/openworkproof/__init__.py`
- Modify: `src/openworkproof/acceptance_bundle.py`
- Modify: `tests/test_v02_interfaces.py`
- Modify: `tests/test_acceptance_bundle_v01.py`

- [ ] **Step 1: 写接口 RED**

断言以下接口存在且 import 无写入副作用：

```text
owp acceptance-bundle-build LEDGER SURFACE --evidence-root PATH --output DIR
owp acceptance-bundle-verify DIR
```

退出码：ACCEPTED=0、REJECTED=2、operational error=4。JSON 输出必须含 terminal、
WorkOrder、Surface/Decision/terminal/binding digest 与固定边界句。

- [ ] **Step 2: 实现薄 facade 和 CLI**

Services/CLI 只能调用核心模块，不复制 verifier 逻辑。生成的 `verify.sh` 只执行
`python -m openworkproof.acceptance_bundle "${1:-.}"`。

- [ ] **Step 3: 子进程测试**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_v02_interfaces.py tests/test_acceptance_bundle_v01.py -k 'cli or service or verify_script or public_api'
```

- [ ] **Step 4: 提交**

```bash
git add src/openworkproof/services.py src/openworkproof/cli.py \
  src/openworkproof/__init__.py src/openworkproof/acceptance_bundle.py \
  tests/test_v02_interfaces.py tests/test_acceptance_bundle_v01.py
git commit -m "feat: expose acceptance bundle interfaces"
```

---

## Task 8：AgentTeams 外部人工验收闭环

**Files:**
- Modify: `agentteams/scripts/run_openworkproof_13_demo.py`
- Create: `tests/test_agentteams_acceptance_bundle_v13.py`
- Modify: `tests/test_agentteams_workflow_v13.py`

- [ ] **Step 1: 写 AgentTeams RED**

覆盖：

- parser 不再接受 `--acceptance-receipt`；
- 新参数 `--acceptance-bundle`；
- 流程到 `ready_for_acceptance` 后释放锁并轮询外部目录；
- ACCEPTED 正常结束；REJECTED 可验证结束且不宣称交付成功；
- 无效目录、超时、announcement failure 退出 4；
- 不生成 key/receipt/binding，不读取 private key；
- provenance 只含 bundle/terminal/binding/event-id digest 与终态，不含 token、正文、
  私钥、绝对路径。

- [ ] **Step 2: 最小接入核心 verifier**

脚本不得重写验证逻辑；只调用 `verify_acceptance_bundle_directory()` 并把闭合结果投影
为 demo state。Matrix announcement 失败不得改变已经验证的 bundle 事实，但进程必须
明确报告外部通知失败。

- [ ] **Step 3: GREEN**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_agentteams_acceptance_bundle_v13.py \
  tests/test_agentteams_workflow_v13.py \
  tests/test_agentteams_adapters.py
git diff --check
```

- [ ] **Step 4: 提交**

```bash
git add agentteams/scripts/run_openworkproof_13_demo.py \
  tests/test_agentteams_acceptance_bundle_v13.py \
  tests/test_agentteams_workflow_v13.py
git commit -m "feat: require verified human acceptance in agentteams"
```

---

## Task 9：系统性攻击、故障与隐私矩阵

**Files:**
- Modify: `tests/test_acceptance_decision_binding_v01.py`
- Modify: `tests/test_acceptance_bundle_v01.py`
- Modify: `tests/test_agentteams_acceptance_bundle_v13.py`
- Modify production only when a new RED proves a defect

- [ ] **Step 1: 参数化全对象篡改**

对 binding、terminal、report、request、WorkOrder、Decision、grant、attempt、receipt、
committed evidence 和 outer manifest 逐字段做 `model_dump → mutate → model_validate →
必要时重签`。证明拒绝发生在语义层，而不只是坏签名提前失败。

- [ ] **Step 2: 完整文件系统攻击**

覆盖目录交换、TOCTOU、hardlink/symlink/FIFO、权限错误、读时变化、超限、同目标并发、
stage/backup/lock 残留。禁止使用不可移植的 sleep 竞态；使用 barrier/event/proxy
确定性注入。

- [ ] **Step 3: 秘密与绝对路径扫描**

扫描所有导出文件和 provenance：不得出现 Matrix token、Ed25519 private bytes、测试
secret、聊天全文、`/Users/` 或 worktree 绝对路径。

- [ ] **Step 4: GREEN**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_acceptance_decision_binding_v01.py \
  tests/test_acceptance_bundle_v01.py \
  tests/test_agentteams_acceptance_bundle_v13.py
```

- [ ] **Step 5: 提交**

```bash
git add tests/test_acceptance_decision_binding_v01.py \
  tests/test_acceptance_bundle_v01.py \
  tests/test_agentteams_acceptance_bundle_v13.py
# 若 RED 证明并修复了生产缺陷，只逐文件 add 实际修复文件；禁止 add 整个目录。
git commit -m "test: close acceptance bundle attack matrix"
```

提交前运行 `git diff --cached --name-only`，确保没有带入无关变化。

---

## Task 10：文档、示例与声明边界

**Files:**
- Modify: `README.md`
- Modify: `README_en.md`
- Modify: `docs/status.md`
- Modify: `tests/test_documentation_boundaries.py`

- [ ] **Step 1: 写文档 RED**

断言中英文 README 同时包含：双签原因、prepare/sign/commit、build/verify CLI、退出码、
AgentTeams 外部验收、缺 binding 拒绝，以及：

```text
VERIFIED != ACCEPTED != PAID/SETTLED/LEGAL AUDIT/ADOPTION
```

- [ ] **Step 2: 更新文档**

只写已实现与本次 fresh test 事实。真实三 Agent、人工 Acceptor、客户采用、SOW、定金、
支付和上游采纳没有新外部证据时继续 `not_evidenced`。

- [ ] **Step 3: GREEN 与提交**

```bash
./.venv/bin/python -m pytest -q tests/test_documentation_boundaries.py tests/test_package.py
git diff --check
git add README.md README_en.md docs/status.md tests/test_documentation_boundaries.py
git commit -m "docs: explain offline human acceptance"
```

---

## Task 11：聚焦、便携、required-live 与 candidate 供应链门

**Files:**
- Create/Modify only if source allowlist requires it:
  `supply-chain/images/candidates/<final-revision>.json`
- Modify: `docs/status.md` only with fresh exact results

- [ ] **Step 1: 聚焦协议门**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_acceptance_decision_binding_v01.py \
  tests/test_acceptance_bundle_v01.py \
  tests/test_agentteams_acceptance_bundle_v13.py \
  tests/test_acceptance.py tests/test_acceptance_v03.py tests/test_acceptance_v05.py \
  tests/test_delivery_package_v05.py tests/test_surface_bundle_v01.py \
  tests/test_companion_schema_registry.py tests/test_schema_registry.py \
  tests/test_signing.py tests/test_v02_interfaces.py
```

- [ ] **Step 2: portable 全量**

```bash
./.venv/bin/python -m pytest -q
```

记录真实 passed/failed/skipped/warnings 和耗时。任何失败必须归因并闭环，不能用历史
计数覆盖。

- [ ] **Step 3: candidate 两套件**

先运行现有静态和 live candidate tests。若 source allowlist 改动导致 inventory 0 match，
按仓库既有 `prepare_context.py`、OCI/Docker archive、
`convert_docker_archive.py` 流程为最终 revision 新建不可变 inventory；不得覆盖历史文件。

- [ ] **Step 4: required-live 全量**

从被唯一选中的 inventory 读取 fully-qualified RepoDigest 与 artifact root，设置仓库要求
的 `OPENWORKPROOF_REQUIRE_LIVE` 等环境变量，运行完整 pytest。目标是 0 failed；是否允许
AgentTeams live skip 必须按当前 marker/规则如实记录，不擅自改规则迎合数字。

- [ ] **Step 5: 非测试门**

```bash
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests
git diff --check
docker ps -a --filter label=openworkproof --format '{{.ID}}'
docker volume ls --filter label=openworkproof --format '{{.Name}}'
git status --short --branch
```

- [ ] **Step 6: 供应链与状态提交**

只在 inventory/状态确有变化时提交：

```bash
git add supply-chain/images/candidates docs/status.md
git commit -m "build: bind acceptance bundle candidate inventory"
```

---

## Task 12：独立双审与分支收口

**Files:**
- Modify only files required by proven review findings
- Modify: this plan checkboxes after evidence exists

- [ ] **Step 1: 独立规格审查**

审查者逐条对照设计第 1–9 节，重点证明：

- outer manifest 不是 trust root；
- Acceptor binding 防止同 WorkOrder 拼接；
- current v0.5 Decision、report、request、terminal 一一对应；
- frozen v0.1–v0.5 bytes 不变；
- transition history fail closed；
- AgentTeams 不自动验收。

- [ ] **Step 2: 独立质量/安全审查**

检查 COMMIT-ACK、并发、历史回放、schema interoperability、path/TOCTOU、secret 泄漏、
CLI exit code 和测试是否真正命中语义层。Critical/Important 必须先 RED 后修；Minor
逐项说明处理或明确非阻断理由。

- [ ] **Step 3: 复跑受影响门并更新勾选**

所有勾选必须有命令、revision 和结果证据。不得把“计划已写”当成“实现已完成”。

- [ ] **Step 4: 分支交付选择**

实现、验证和双审全部完成后，使用 `superpowers:finishing-a-development-branch`，向用户
提供：保持本地、推远端分支/PR、或合并 main。没有用户明确授权不得 push/merge/tag/
publish。

---

## Final Checklist

- [ ] 旧 v0.1–v0.5 schema/hash/signing bytes 未变化
- [ ] companion schema 双目录逐字节一致
- [ ] Acceptor terminal 与 cross-version binding 均为显式独立签名
- [ ] 同 WorkOrder 拼接攻击被离线 verifier 拒绝
- [ ] accepted/rejected round-trip 在全新临时目录通过
- [ ] 缺 binding、旧 terminal、transition history 均 fail closed
- [ ] exporter exact snapshot、self-verify、no-replace、ACK-loss 闭环
- [ ] CLI 0/2/4 退出码与 JSON 输出闭合
- [ ] AgentTeams 不接收裸 receipt、不持私钥、不自动验收
- [ ] 导出物无 token、私钥、消息全文和绝对路径
- [ ] focused、portable、candidate、required-live 结果均为 fresh evidence
- [ ] pip check、compileall、diff check 与 Docker 残留门通过
- [ ] 独立规格审查 READY
- [ ] 独立质量/安全审查 READY
- [ ] README/README_en/status 与真实实现和证据一致
- [ ] 未经授权未 push、merge、tag、发布或宣称外部采用
