# OpenWorkProof Acceptance Bundle 0.1 — DeepSeek Harness 交接

交接时间：2026-08-21（Asia/Shanghai）

## 1. 目标与边界

继续执行：

`docs/superpowers/plans/2026-08-21-openworkproof-acceptance-bundle-implementation.md`

当前只剩 Task 11（完整验证门）和 Task 12（独立双审、计划勾选与分支交付选择）。

禁止事项：

- 不 push、merge、tag、publish 或 release；
- 不切换到 main 开发；
- 不覆盖历史 candidate inventory；
- 不修改冻结 v0.1–v0.5 schema/signing bytes，除非新 RED 证明且先报告；
- 不把本地测试、Bundle、HTTP 200 或配置写成客户采用、付款、人工验收或上游采纳；
- 不把 AgentTeams preflight/外部验收门写成完整三 Agent 真实执行。

外部事实边界继续保持：

```yaml
customer_adoption: not_evidenced
paid_sow: not_evidenced
deposit: not_evidenced
upstream_adoption: not_evidenced
agentteams_live_execution: not_evidenced
human_acceptance: not_evidenced
```

## 2. 精确工作区

```text
repo: /Users/molin/Project/openWorkProof
worktree: /Users/molin/Project/openWorkProof/.worktrees/openworkproof-13-dual-surface
branch: codex/openworkproof-13-dual-surface
HEAD: 238d933
```

交接时工作树在创建本文件前是干净的。此交接文件是唯一预期未提交变化；先运行：

```bash
cd /Users/molin/Project/openWorkProof/.worktrees/openworkproof-13-dual-surface
git status --short --branch
git log -1 --oneline
```

## 3. 已完成提交

```text
d1d649e docs: design offline acceptance bundle
1110068 docs: bind acceptance to verification decision
39747c0 docs: plan offline acceptance bundle implementation
e174f0c feat: define acceptance decision binding
561a5f2 feat: commit acceptance decision bindings
fbd0583 feat: validate acceptance bundle snapshots
0858db5 feat: replay acceptance bundles offline
2895c5e feat: export acceptance bundles atomically
9def941 feat: expose acceptance bundle interfaces
167ae24 feat: require verified human acceptance in agentteams
a0f17d5 test: close acceptance bundle attack matrix
238d933 docs: explain offline human acceptance
```

实现范围：

- Acceptor-signed `AcceptanceDecisionBindingV01`；
- prepare → external sign → append-only commit；
- Acceptance Bundle outer manifest、离线 replay、原子 no-replace export；
- CLI/Services/public API 与 ACCEPTED=0、REJECTED=2、operational=4；
- AgentTeams `--acceptance-bundle` 外部人工验收门；
- tamper/filesystem/concurrency/ACK-loss/privacy 测试矩阵；
- README、README_en、status 的双签与商业事实边界。

## 4. 新鲜验证证据

已完成：

```text
Task 8 prescribed gate: 49 passed, 1 skipped (live AgentTeams not required)
Task 8 adjacent Acceptance Bundle/interface regression: 75 passed
Task 9 attack/privacy matrix: 134 passed in 196.80s
Task 10 documentation/package gate: 10 passed
Task 11 focused protocol gate: 365 passed in 241.19s
pip check / compileall / git diff --check: passed before handoff
```

portable 全量 `./.venv/bin/python -m pytest -q --tb=short` 已启动，但用户要求停止开发，
因此使用 Ctrl-C 中止。该次运行没有完成，不能记为 passed、failed 或基线证据。

## 5. 下一步执行顺序

### 5.1 Task 11 portable 全量

```bash
./.venv/bin/python -m pytest -q
```

记录完整 passed/failed/skipped/warnings/耗时。任何失败先按 systematic debugging 定位，
先写/确认 RED 再做最小修复。

### 5.2 candidate 两套件

```bash
./.venv/bin/python -m pytest -q \
  tests/test_image_supply_chain.py \
  tests/test_candidate_supplychain_integration.py
```

若因 source allowlist 变化出现 inventory `0 match`，使用仓库现有：

- `supply-chain/images/prepare_context.py`
- OCI/Docker archive 构建流程
- `supply-chain/images/convert_docker_archive.py`

为最终 revision 新建：

`supply-chain/images/candidates/<final-revision>.json`

不得修改或覆盖历史 inventory。新 inventory 提交后再重跑 candidate 两套件。

### 5.3 required-live 全量

从唯一匹配 inventory 读取：

- fully-qualified execution image RepoDigest；
- `OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT`；
- 其他 inventory 指定的 live 参数。

至少设置：

```text
OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1
OPENWORKPROOF_DOCKER_TEST_IMAGE=docker.io/...@sha256:...
OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT=/absolute/artifact/root
```

运行完整 pytest。AgentTeams live 是否 skip 必须按现有 marker 如实记录；禁止为追求
0 skip 修改规则。

### 5.4 非测试门

```bash
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests
git diff --check
docker ps -a --filter label=openworkproof --format '{{.ID}}'
docker volume ls --filter label=openworkproof --format '{{.Name}}'
git status --short --branch
```

只把本轮新建的 Docker 容器/卷算作本轮残留，不删除未知或用户资源。

### 5.5 Task 12 双审与收口

逐条核对设计 1–9 节，重点审查：

- outer manifest 不是 trust root；
- binding 阻止同 WorkOrder 拼接；
- current Decision/report/request/terminal 一一对应；
- transition history fail closed；
- CLI 0/2/4；
- path/TOCTOU、secret、COMMIT-ACK、并发；
- AgentTeams 不生成 Acceptor authority，也不自动验收。

Critical/Important 必须先 RED 后修。最终更新实施计划复选框与 `docs/status.md` 的新鲜
精确数字。未经用户再次明确授权，不执行 push/merge/tag/publish。

## 6. 特别提醒

旧计划 `2026-08-21-openworkproof-13-commercial-ecosystem-implementation.md` 的“完整真实
演示入口”仍未完成；本轮 Task 8 只实现外部验收 Bundle gate。不要扩大宣称。
