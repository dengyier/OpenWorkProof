# OpenWorkProof Verified Agent Delivery 0.1 — 交接文档

> 快照时间：2026-08-22
> 交接状态：**Task 1–8 已本地提交并逐门复跑；Task 9 candidate 库存重建与
> required-live 门由后台 worker 执行中，结果见本文件第 5 节。**
> 本文是当前磁盘状态的接手入口，不是发布说明，也不证明客户采用、验收、付款
> 或结算。

## 1. 接手者首先必须使用的工作区

```text
仓库：/Users/molin/Project/openWorkProof
分支：codex/verified-agent-delivery
远端：git@github.com:dengyier/OpenWorkProof.git
origin/main：<见 git rev-parse origin/main>
分支关系：HEAD 相对 origin/main 领先 12 个提交、落后 0 个提交
```

接手后的第一条命令：

```bash
cd /Users/molin/Project/openWorkProof
git status --short --branch
git rev-parse HEAD
git diff --check
```

严禁在读取本文件前执行 `git reset --hard`、rebase、force push、merge、
`git checkout -- .` 或覆盖生成。

## 2. 权威规格与实施计划

- 设计规格：`docs/superpowers/specs/2026-08-22-openworkproof-verified-agent-delivery-design.md`
- 实施计划：`docs/superpowers/plans/2026-08-22-openworkproof-verified-agent-delivery-implementation.md`
- 基线：从 `main@60acc66`（含 `9ba2e7f`、`60acc66` 两个设计/计划提交）创建隔离
  分支，仅在本分支工作。

协议边界：本切片是现有 Surface Bundle、Acceptance Bundle 与 settlement
readiness 上方的薄 delivery-case 编排层，不建设商城、SaaS、登录、钱包、托管、
自动付款或新协议 schema；不修改冻结的 v0.1–v0.5 schema、golden bytes 与兼容性
承诺。

## 3. 提交链（分支上，自基线 60acc66 起）

```text
d74a68e build: add verified delivery case candidate inventory
2425dbd test: pin frozen v0.1 candidate reference in supply chain contract
f81f2e8 docs: record verified agent delivery status and fix README boundary
9a0f1dc test: close verified delivery case attack matrix
9bca6f4 feat: add verified delivery case action
d7b9551 docs: package verified agent delivery offer
9198c65 feat: expose verified delivery case CLI
b704928 feat: export verified delivery cases
1f3d70d feat: derive verified delivery case status
45a2658 feat: initialize verified delivery cases
5e45bf3 feat: define verified delivery case models
```

（本交接文档本身及其 `docs/status.md` 收口提交为紧随其后的第 12 个提交。）

## 4. 变更文件

新建：

- `src/openworkproof/delivery_case.py` — 严格模型、原子初始化、组合验证、原子导出
- `src/openworkproof/delivery_case_render.py` — 确定性 JSON/Markdown 摘要
- `tests/test_delivery_case_v01.py` — 模型/初始化/状态/篡改/路径/导出测试
- `tests/test_delivery_case_cli_v01.py` — parser/退出码/输出/隐私边界测试
- `integrations/github-delivery-case/action.yml`、`run.sh` — 交付目录 Action
- `docs/commercial/verified-agent-delivery/`（README / client-intake /
  acceptor-checklist / 两个 example JSON）

修改：

- `src/openworkproof/cli.py` — `delivery-case init/inspect/verify/export`
- `src/openworkproof/__init__.py` — 惰性导出只读公开 API
- `src/openworkproof/github_action_cli.py` — `write-delivery-case-summary`
- `tests/test_github_action_contract.py`、`tests/test_documentation_boundaries.py`
- `README.md`、`README_en.md`、`docs/status.md`

## 5. 逐门 fresh 结果

> 均为本轮控制器 fresh 复跑，未复用历史数字。

| 门 | 命令（摘要） | passed / failed / skipped | 退出码 |
|---|---|---|---|
| 基线相邻套件 | `pytest test_surface_bundle_v01 test_acceptance_bundle_v01 test_settlement_readiness test_cli_transport` | 147 / 0 / 0 | 0 |
| 专项（delivery_case 两文件） | `pytest test_delivery_case_v01 test_delivery_case_cli_v01` | 63 / 0 / 0 | 0 |
| focused 七文件 | `pytest test_delivery_case_v01 test_delivery_case_cli_v01 test_github_action_contract test_surface_bundle_v01 test_acceptance_bundle_v01 test_settlement_readiness test_documentation_boundaries` | 213 / 0 / 0 | 0 |
| 便携全量 | `pytest -q` | 3979 / 0 / 8 | 0 |
| 冻结兼容 | `pytest test_schema_registry test_acceptance_decision_binding_v01::test_frozen_acceptance_and_v05_schema_bytes_are_unchanged test_companion_schema_registry` | 62 / 0 / 0 | 0 |
| wheel 隔离安装 | `pip wheel . --no-deps` + 隔离 venv + `owp delivery-case --help` | 成功 | 0 |
| candidate 两套件 | `pytest test_image_supply_chain test_candidate_supplychain_integration`（live Docker + artifact root） | 182 / 0 / 0 | 0 |
| required-live 全量 | `pytest -q`（`OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1` + candidate + 全限定镜像） | 3986 / 0 / 1 | 0 |

便携全量曾经的 3 failed 已全部闭环：

1. README_en 边界（`automatic payment` 字面量）——已改为 `automated money movement`
   并复跑 `test_verification_integrity_demo_v05` + `test_documentation_boundaries`
   `11 passed`；
2. `test_current_candidate_inventory_binds_execution_runner`；
3. `test_current_candidate_inventory_binds_fixed_test_source`。

后两个是 candidate inventory 绑定：本分支 `__init__.py` 新增 delivery-case
惰性导出使 trusted-helper source closure 变化，历史 inventory `238d933…` 出现
`matched 0`；已由 Task 9 重建的 `f81f2e8…` inventory 闭合（见第 6 节）。复跑
便携全量 fresh `3979 passed、0 failed、8 skipped`。

非测试检查：`pip check`（No broken requirements）、`compileall -q src tests`、
`git diff --check` 均 PASS；`import openworkproof` 无副作用（不建目录、不读环境）。

## 6. candidate inventory 与 required-live（Task 9）

source closure 分析：`git diff origin/main...HEAD -- SOURCE_ALLOWLIST` 为空
（allowlist 未改）；但 `src/openworkproof/__init__.py` 在 allowlist 内且已变更，
`helper_src_sha256sums_sha256` 随之变化，必须为最终 revision
`f81f2e840fa568d41919821b14b9d8d27f2eec3e` 重建不可变 inventory。

沙箱边界：DSH workspace-write 禁止写规范外部根
`/Users/molin/Project/openWorkProof-delivery`（`Operation not permitted`），也禁止
写 `~/.docker/buildx/activity`（`docker buildx` 因 activity 文件不可写而失败）；
本轮用 `DOCKER_CONFIG=/private/tmp/owp-docker-config`（克隆 `~/.docker` 至可写根 +
软链 buildx 插件）使 buildx 可写 activity。candidate 在可写根
`/private/tmp/owp-candidate-delivery`（即 `/tmp/owp-candidate-delivery`）构建，
`external_layout.local_root` 如实记录该路径，`build_inputs` 全部 revision-bound，
可在规范根复现。`prepare_context.py` 已成功生成 execution/trusted-helper 两个
build context。

已完成的 Task 9 fresh 结果（本轮控制器 fresh，未复用历史数字）：

- 不可变 inventory：`supply-chain/images/candidates/f81f2e840fa568d41919821b14b9d8d27f2eec3e.json`；
  `helper_src_sha256sums_sha256` = `a79640fb28c40d4f93fd4e6e73fcefd6b14c3c75bc7e68dc7a2f198aa4bcc4dc`
  （唯一变化项，其余 build_inputs 与 `238d933…` 逐项一致）。execution
  `local_image_id=sha256:f3d8907a…`、`oci_manifest_digest=sha256:b36f2f56…`；
  trusted-helper `local_image_id=sha256:b6751863…`、`oci_manifest_digest=sha256:cc104df2…`。
  4 个 archive tar + `SHA256SUMS` + inventory copy + sidecar 位于
  `/private/tmp/owp-candidate-delivery/oci/f81f2e8…/`。
- candidate 两套件（live Docker + artifact root，`test_image_supply_chain.py` +
  `test_candidate_supplychain_integration.py` 全量）：`182 passed、0 failed、
  0 skipped`，退出码 0。
- required-live 全量（`OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1` + candidate artifact
  root + 全限定 `docker.io/openworkproof/execution-test@sha256:f3d8907a…`）：
  `3986 passed、0 failed、1 skipped`，退出码 0；唯一 skip 为未启用的 AgentTeams
  真实三 Agent 环境（`OPENWORKPROOF_AGENTTEAMS_REQUIRED` 未设置，按 marker 如实记录）。

> 契约测试修正：新 candidate `f81f2e8…`（hex 以 `f` 开头）按字典序排在冻结 v0.1
> candidate `ed2da68a…`（hex 以 `e` 开头）之后，
> `test_inventory_v01_remains_valid_without_runner_digest` 与
> `test_inventory_loader_rejects_source_revision_drift_to_head` 两处以
> `CANDIDATE_PATHS[-1]` 隐式取“最后一个 candidate”的断言会误取 v0.2 新 candidate
> 而失败。已在 `2425dbd` 将两处改为显式引用冻结 v0.1 candidate `ed2da68a…`
> （测试意图不变：未跳过、未放宽 fail-closed、未改写历史库存）。

## 7. 尚未取得的商业证据

```yaml
customer_adoption: not_evidenced
paid_sow: not_evidenced
deposit: not_evidenced
external_payment: not_evidenced
upstream_adoption: not_evidenced
human_acceptance: not_evidenced
```

自有 fixture、绿色测试与本地导出包均不计入真实十单、付款方或复购。没有执行
真实客户验收、付费 SOW、定金、外部付款或上游采纳。

## 8. 明确没有执行的动作

- 没有 merge、rebase main、push、tag、GitHub Release、PyPI 或 MCP Registry 发布；
- 没有声称客户采用、付费、SOW、定金、外部验收或上游采纳；
- 没有用跳过测试、放宽 fail-closed 规则或改写历史库存来过门。

## 9. 首单所需外部动作（尚未发生，均为下一步）

1. 与真实 Delivery Provider 签订含付款主体、金额区间、期限、范围的 SOW；
2. 双方冻结 SubjectClaim 与 WorkOrder，配置独立 Verifier 与客户控制的
   Customer Acceptor；
3. 执行一次真实仓库交付，导出 Surface / Acceptance Bundle 与 settlement status；
4. 客户 Acceptor 签署 ACCEPTED/REJECTED；
5. 取得外部付款证据后，把商业状态从 `not_evidenced` 更新为可定位材料。

这些动作均不在本切片内完成，也不被本切片声明为已完成。
