# OpenWorkProof 当前状态与边界

> 本文档是项目实现状态的权威记录。README 只保留概览，
> 「已经完成什么」和「尚未完成什么」的完整清单以本文为准。

## DeepSeek Harness 插件 V0.1 外部发布 READY 本地候选（2026-08-29）

隔离分支与独立插件仓库已完成外部发布 READY 的本地收口：

- 锁定 `DeepSeek Harness 0.1.1-rc.2`、插件 `0.1.0`、OpenWorkProof `1.4.0`；
- 打包后的插件已安装进全新临时 DSH profile，并由 `--dump-config` 确认 bundle 生效；
- Enforce 的单调最终 guard 阻断原生 `write`、`edit`、`bash`、`pwsh`、
  `str_replace_editor`、`cordis_define`、`cordis_run` 修改面，OWP patch/test 工具只发送
  闭合参数；
- 一次性 Git 夹具完成授权 patch、冻结测试、独立 Git 回读、外部 Acceptor 签名、
  Acceptance 绑定、交付导出、离线复核与篡改拒绝；
- Core DSH focused：`77 passed / 0 failed / 0 skipped`；插件：`56 passed / 0 failed /
  0 skipped`，typecheck、build 与真实打包宿主 live-preflight 均通过；
- candidate 两套件（artifact root + 强制 live Docker）：`186 passed / 0 failed /
  0 skipped`；required-live 全量门在 `OPENWORKPROOF_AGENTTEAMS_REQUIRED=1`、
  `AGENTTEAMS_HOMESERVER=http://127.0.0.1:18080` 与只读取自本机 `agentteams-manager`
  容器的 `AGENTTEAMS_MATRIX_TOKEN` 下以 `4333 passed / 0 failed / 0 skipped`
  通过（1480.88s，退出码 0）；
- 不可变 candidate inventory
  `supply-chain/images/candidates/28e25b839f45260a89c2f0c5ee957723c3d05fc9.json`
  （inventory commit `c7ae9c7`，绑定 source revision `28e25b8`，不改写历史库存）；
- 全新环境已安装 `openworkproof-1.4.0-py3-none-any.whl` 并启动
  `owp dsh-bridge --help`；最终 wheel/sdist/插件包 SHA-256 见
  `release-candidates` 目录的 `SHA256SUMS`。

当前仍是本地候选：供应链与 required-live 本地门已闭合、技术上达到外部发布 READY，但未
创建插件远端、未发布 npm/PyPI、未合并或推送 core、未在第二台环境外部复现、无客户采用、
无 DeepSeek 官方背书、无生产使用。通用案例初始化器和独立 Verifier 服务编排仍需由集成方
准备；本地夹具不能写成任意仓库零配置交付。两轮内部自审不能替代计划要求的两份独立只读
审查。

```yaml
customer_adoption: not_evidenced
deepseek_endorsement: not_evidenced
npm_publication: not_evidenced
pypi_publication: not_evidenced
external_reproduction: not_evidenced
production_use: not_evidenced
```

## Human Agency Profile 0.1：Task 9 供应链与全量门收口（2026-08-24）

Human Agency Profile 0.1 已在隔离分支完成本地供应链与 required-live 验证；本节
覆盖本文前面同一 profile 下“candidate inventory / Task 9 尚未完成”的阶段性表述。
没有合并 `main`，没有推送远端：

- agency focused（含 schema constraints / registry）：`235 passed`，0 failed、
  0 skipped；相邻 policy / MCP / repo-read / retraction / acceptance / schema 回归：
  `309 passed`，0 failed、0 skipped；
- `prepare_context.py` 从 source revision
  `aa38f8907208f2602357cef08fbdb24c98f85399` 的 Git blob 生成 revision 专属
  execution / trusted-helper build contexts；两镜像均以 `linux/arm64`、
  `--network none`、固定基础镜像与提交时间构建；
- 新增不可变 inventory
  `supply-chain/images/candidates/aa38f8907208f2602357cef08fbdb24c98f85399.json`，
  不改写历史库存；对应 inventory commit 为 `7eeb2fc`；
- candidate 两套件（artifact root + live Docker）：`183 passed`，0 failed、
  0 skipped（620.27s）；execution image 为
  `docker.io/openworkproof/execution-test@sha256:bd9f894d57b0bc4bcaa74b7bc60b09b9a618040e6692fe47e30f833a13dbc5ec`；
- 首轮 required-live 基线为 `4264 passed、1 skipped`，唯一 skip 明确来自未启用
  `OPENWORKPROOF_AGENTTEAMS_REQUIRED`；随后使用仅驻留于进程内存的 Matrix token
  启用真实 AgentTeams 三角色 preflight，并与 live Docker、当前 inventory、严格
  `PytestUnhandledThreadExceptionWarning` 同门复跑，最终为 **4265 passed、
  0 failed、0 skipped**（1300.67s，退出码 0）；
- `pip check`、`compileall src tests examples`、`git diff --check`：PASS；
  OpenWorkProof 测试容器与卷残留均为 0。仍运行的 AgentTeams 服务容器属于现有
  本地三 Agent 环境，不是测试残留。

诚实边界：这些结果证明本地分支代码、离线工件与本机 live 环境的可复核性；不证明
客户采用、付费、外部人工 Acceptor 验收、生产部署、远端发布或法律合规。

```yaml
customer_adoption: not_evidenced
payment: not_evidenced
external_human_acceptance: not_evidenced
production_deployment: not_evidenced
remote_merge_or_push: not_performed
```

## Human Agency Profile 0.1：离线包文档真相复审修复（2026-08-24）

Task 8 独立复审发现协议文档的精确 bundle 布局遗漏实现强制的 `verify.sh`，且
`key-free` 会掩盖 WorkOrder 内存在验签公钥；示例 docstring 还把“无应用层写入”
绝对化为“不写 filesystem”，忽略 Python 可能生成 bytecode cache。本轮只修正文档与
回归测试，未改协议实现、main 或 candidate inventory，未 push：

- 离线包现准确写为 `private-key-free, self-contained`，精确列出
  `agency-manifest.json`、`agency/work-order.json`、`verify.sh` 与三类历史对象目录；
  文档中的 `verify.sh` 字节直接由测试与生产 `AGENCY_VERIFY_SCRIPT` 对照，并明确其
  SHA-256/size 受 manifest entry 覆盖、执行位与字节由 verifier 固定。
- 示例改为“无 application-level filesystem 或 ledger 写入”；普通解释器可能生成
  `.pyc`，属于解释器缓存而非协议副作用。验证命令使用
  `PYTHONDONTWRITEBYTECODE=1` 隔离该环境行为。
- fresh：文档边界 `23 passed`；Task 8 门 `88 passed`（23 + 25 + 40）；schema 门
  `60 passed`；样例双跑 stdout 字节一致、退出码 0。

商业与外部证据边界不变：

```yaml
customer_adoption: not_evidenced
payment: not_evidenced
upstream_adoption: not_evidenced
```

## Human Agency Profile 0.1：文档真相审计修复（2026-08-24，commit `fix: correct human agency documentation claims`）

独立审计对 Task 8 文档切片发现 3 个 P1 + 1 个 P2。本 commit 只做最小修复，未改协议
代码、main、candidate inventory，未 push、未做 Task 9：

- P1-1：`examples/human_agency_profile_v01.py` 此前打印 `work_order_digest` 与
  `profile_id`，二者由本轮 ephemeral Ed25519 密钥派生，双跑 diff 必然失败，却自称
  "输出稳定"。修复后保留临时随机密钥（签名/验证仍用真实密钥），stdout 只打印稳定
  事实：`profile verified  : True`、`resolved status   : active`、
  `owp.repo_read : delegated -> allowed`、`owp.apply_patch : reserved ->
  AGENCY_HUMAN_DECISION_REQUIRED` 与两条边界；不再打印随机 digest/id/私钥。新增
  回归测试 `test_human_agency_example_output_is_byte_stable_and_secret_free`
  （连续运行两次、stdout 字节完全相同、退出码 0、无 64 位 hex digest/id、无
  `ed25519:` key、无 PRIVATE KEY）。
- P1-2：`docs/protocol/human-agency-profile-v0.1.md` 的 "one unsigned genesis
  profile" 错误，改为 "one signature-verified genesis profile with no incoming
  transition"（genesis 同样被 Acceptor 签名验证，无入边 transition）；三种对象均
  签名。新增 `test_human_agency_protocol_doc_genesis_is_signature_verified` 锁定。
- P1-3：README_en / protocol 的 "Acceptor-signed transition/profile can revoke or
  replace the grant" 过宽且错误（不修改 CapabilityGrant），改为 "only an
  Acceptor-signed transition can revoke the active profile or supersede it with
  another Acceptor-signed profile"；中文 README 改为同等精确表述 "只有 Acceptor
  签名的 transition 才能撤销当前 profile 或将其替换为另一个 Acceptor 签名的
  profile"（appeal 不改权限）。相应边界测试
  `test_human_agency_appeal_records_but_never_restores` 精确锁定中英文。
- P2：本状态文档 Task 8 小节此前称样例"输出稳定"，已改为"双跑 stdout 字节一致、
  只打印稳定事实、无随机 digest/id/私钥"，不再称随机摘要输出稳定。

本轮 fresh 测量（控制器 fresh，未复用历史数字）：

- 样例双跑：`./.venv/bin/python examples/human_agency_profile_v01.py` 连续两次
  stdout 字节完全一致，退出码 0；
- 文档边界 `tests/test_documentation_boundaries.py`：`21 passed`（含 3 条新增/精确化
  边界测试）；
- Task 8 门 `test_documentation_boundaries.py + test_agency_models_v01.py +
  test_agency_end_to_end_v01.py`：`86 passed`（21 + 25 + 40）；
- schema 门 `test_agency_schema_constraints_v01.py +
  test_agency_schema_registry_v01.py + test_package.py`：`60 passed`；
- `pip check` / `compileall src tests examples` / `git diff --check`：PASS。

```yaml
customer_adoption: not_evidenced
payment: not_evidenced
upstream_adoption: not_evidenced
```

诚实边界不变：未改 main、未 push、未重建 candidate inventory、未做 Task 9；全量
inventory boundary（`test_current_candidate_inventory_binds_*`）仍待 Task 9 重建。

## Human Agency Profile 0.1：受保护 apply-patch executor（2026-08-24）

隔离分支 `codex/human-agency-profile-v01` 新增真实 `execute_apply_patch` 事务入口，
复用 `repo_tools.apply_patch_in_candidate_workspace` 与既有 `PatchRequest`/`PatchResult`，
与 repo-read/run-tests/rollback 同一锁域与 fail-closed/idempotent 语义（current-context
→ 基础授权 → opt-in `agency_authorize` profile callback → receipt preflight → handler
reservation/started → patch handler → 独立 postcondition 校验 → `PatchResultEvidence` +
patch/result EvidenceRefs → Sidecar 签名 receipt →
`complete_receipt_publication(..., _borrowed_lock_descriptor=...)` → cleanup）。
`c201dee`（`fix: verify apply patch authority and postconditions`）修复 review blockers：

- 签名精确校验 `request.tool_name == "owp.apply_patch"` 与 `arguments_digest`，
  patch 字节 digest/size 与 `ApplyPatchArguments` 精确一致，Sidecar key 匹配
  execution controller。deny 时 handler 不调用、业务表零写入（bookkeeping 除外）。
- 授权先行（P1-1）：`execution_facts` 现传入 v0.1 `authorize_tool_call` 与 v0.4
  `_require_bound_action` 两条授权路径，policy 在 handler 之前证明 `controller_id`
  是权威 WorkOrder 的 Sidecar key。非 Sidecar 的合法角色 key：v0.1 抛
  `AuthorizationPolicyError("prospective execution controller is not the Sidecar")`、
  v0.4 抛 `ToolCallDenied(AUTH_SUBJECT_MISMATCH)`，先于 agency callback 与 handler，
  工作区字节+HEAD 与业务表零变化；Sidecar 私钥 key_id 匹配权威 controller 的显式
  校验保持不变。正确 Sidecar 路径保持绿色。
- 不可信 handler postcondition（P1-2）：新增公开
  `repo_tools.validate_patch_result_against_candidate(request, result)`，在 handler
  返回后、证据/receipt 发布前调用。它独立重解析 canonical patch、重读 parent files、
  重放 apply phase，重算期望 candidate commit/tree/manifest/changed_paths/evidence，
  逐字段比对 `PatchResult`/`PatchResultEvidence`（含 changed_paths），再独立校验
  live candidate workspace 恰好处于期望 head/tree/manifest、无多余/隐藏改动。自洽
  但伪造的 result、伪造 commit/manifest/changed_paths、额外未声明路径写入均
  `RECOVERY_REQUIRED`，receipt 不发布，journal 仅保留 STARTED_UNCONFIRMED 作
  fail-closed 协调；真实 `apply_patch_in_candidate_workspace` 保持绿色。
- handler journal 最小兼容扩展：V6 schema 增加 `owp.apply_patch`；V5（紧邻前一个
  签名绑定 schema）非空行原子重建逐列保留（绝不伪造签名），空表 drop/rebuild；
  旧 V3/V4 及更旧 predecessor 迁移行为不变。apply_patch 与 repo-read/rollback 同为
  非 typed-driver 工具，recovery (B) 走 `_recover_handler_executions` 不针对当前
  profile 重新授权，不产生 mixed-mode 歧义，故不引入 run-tests 的 Sidecar 签名
  agency binding；`ActionReceipt` 本身不携带 Human Agency 证明（binding 仅作 executor
  锁内 recovery 协调）。V5→V6 迁移测试现保留真正非 NULL 的 Sidecar 签名 run-tests
  agency_binding + canonical agency_binding_json，并证明后续 load/verification。
- 本轮 fresh 测量（控制器 fresh，未复用历史数字；Task5 Step4 audit closure）：
  - 专项 `tests/test_apply_patch_transaction.py`：`18 passed`（新增 pre-COMMIT
    insert-then-rollback 精确回滚、post-receipt workspace drift fail-closed 两测试）；
  - `test_agency_end_to_end_v01.py`：`28 passed`（superseded-allow 与 recovery 均用
    真实 repo_tools handler）；
  - `test_receipt_chain.py`（publication atomicity）：`413 passed`；
  - mcp/policy/repo_tools focused（test_mcp_server/test_policy/test_sandbox）：
    `512 passed, 4 skipped`（4 skip 均为已分类 Docker live / immutable image 边界）；
  - `pip check` / `compileall` / `git diff --check`：PASS。
- Owner 威胁模型边界（新增，2026-08-24）：`execute_apply_patch` 的 receipt 只认证不可变
  Git candidate commit 与由 patch evidence 派生的确定性 manifest（内容寻址证据），不承诺
  可变 worktree 在验证后永久保持干净；handler 是受信任的同步进程内适配器，可能失败或
  返回伪造/错误数据，敌意 handler 派生延迟子进程、或同用户/root 的带外进程改写/删除
  workspace/Git store，都在 coordinator 隔离边界之外——不声称能阻止敌意 OS 进程；后续
  动作必须重新校验当前 candidate checkpoint 并在 drift 时 fail closed（下一条 candidate
  操作在 `_verify_candidate_checkpoint` 处先于任何 patch 应用拒绝）；本切片不添加投机性
  workspace lock 或 sandboxing。该边界由新增测试
  `test_execute_apply_patch_rejects_workspace_drift_before_next_candidate_operation`
  证明（成功 receipt 后带外漂移 worktree，下一条 candidate 操作拒绝且不改写认证 commit）。
- 诚实边界不变：apply-patch executor 完成前不得声称 supersede 后 apply-patch 已可
  安全执行；`owp.apply_patch` 仍以 reserved profile 在人类决策处保留，只有 Acceptor
  签署 supersede 后执行；不宣称 ActionReceipt 携带 Agency 证明；全量 inventory
  boundary（`test_current_candidate_inventory_binds_*` 因 candidate definition 变化
  需 Task 9 重建）仍未闭合，不标记 READY。

## Human Agency Profile 0.1：最小 protected dispatcher（2026-08-24）

同一隔离分支新增最小 protected dispatcher `mcp_server.dispatch_protected_agent_action`，
支持设计 §7 的 `owp.repo_read`、`owp.apply_patch`、`owp.run_tests`、`owp.rollback_patch`
四工具，并新增四个 typed keyword bundle（`RepoReadDispatch`/`ApplyPatchDispatch`/
`RunTestsDispatch`/`RollbackDispatch`）：

- dispatcher 不持锁、不预加载 Agency history、不缓存 profile 快照、不做 base/agency
  授权，只按签名 `request.tool_name` 路由，并校验 bundle 形状（未知工具、错配、缺失、
  多余 bundle 均 fail closed 且无 handler 副作用）；不接收独立 `tool_name` 或 `now`，
  时间只来自已构造的 `AuthorizationContext.transaction_time`，trusted `clock` 仅转发给
  executor。
- 延迟零参 `agency_authorize` callback 只捕获 immutable ledger path/context/request，
  在 executor 已持有 target lock 的临界区内才调用 `load_agency_history` +
  `authorize_agency_profile_layer`；锁外不加载 history，避免锁外闭包的 TOCTOU。
- 旧 `execute_repo_read` 等入口默认 `agency_authorize=None` 语义不变；dispatcher 是
  opt-in 新入口。

新增 12 条测试（`tests/test_agency_end_to_end_v01.py`，合计 40 条）：

- 四工具精确路由、未知工具 fail closed、bundle 错配/缺失/多余 fail closed、v0.1 与
  v0.4 请求路由、非 AgentRequest 拒绝；
- apply-patch 完整状态链：repo-read delegated allowed → apply-patch reserved 返回
  `AGENCY_HUMAN_DECISION_REQUIRED` 且 handler 零调用零写入 → Manager appeal 记录后仍
  reserved → Acceptor supersede 到 replacement profile 后真实 patch allowed →
  revoke 后签名历史解析为 `revoked`；
- revoke 后四工具（repo-read/apply-patch/run-tests/rollback）全部返回
  `AGENCY_PROFILE_REQUIRED`，handler/driver 零调用零写入（run-tests/rollback 复用既有
  生产 fixture，不伪造授权）；
- 确定性 history-loader 在 executor 锁内才调用（非阻塞 flock probe，无 sleep）。

本轮 fresh 测量（控制器 fresh，未复用历史数字）：agency end-to-end `40 passed`；
agency-policy/policy/repo-read/apply-patch `144 passed`；mcp/binding/recomposition
`126 passed`；`pip check` / `compileall` / `git diff --check` PASS。独立 review 未发现
P0/P1/P2，Task 5 实现切片 READY；分支发布仍受 Task 9 全量 inventory 重建约束。

## Human Agency Profile 0.1：offline boundary bundle（2026-08-24）

同一隔离分支 `codex/human-agency-profile-v01` 新增 `agency_bundle.py`，导出最小、无私钥、
可离线验证的 authorization boundary bundle。独立审查发现 P1：原 `AgencyBundleManifestV01`
未签名，攻击者可无钥删除 revoke/supersede 后缀并重写 `evaluated_at`/`current_status`，把
已撤销 bundle 重放为 active。Owner 决策采用 WorkOrder 内 Sidecar key binding 作为自包含
snapshot attestation 修复：

- `AgencyBundleManifestV01` 改为 `SignedProtocolModel`，`_signed_domain="manifest"` v0.1，
  含 digest/signature_alg/signer_key_id/signature；签名覆盖 `work_order_digest`、
  `evaluated_at`、`current_status`、`current_profile_id`、`boundary` 与全部 `entries`
  （path/SHA-256/size），不加无效自哈希。
- `export_agency_bundle` 必须显式接收 `sidecar_private_key: Ed25519PrivateKey`（不默认、不读
  环境），`compose_agency_manifest` 亦必须显式签名；导出前显式校验私钥匹配 WorkOrder Sidecar
  binding，错误角色 fail closed。验证器加载并验证 WorkOrder identity bindings 后，只接受
  Sidecar role binding 并 `verify_payload("manifest", ...)`；验证器仍不接受 `now`、不访问
  ledger/network/环境私钥/系统时钟；verify.sh/CLI 只用于验证、不含私钥。
- 错误角色/伪签名/篡改 manifest/截断合法 supersede 链/删除 revoke 后缀/重写
  evaluated_at+status 均 fail closed；保留 extra empty directory RED test 与 `_scan_tree`
  精确目录集合修复。
- 边界不变：Sidecar 签名固定的是“声称的 `evaluated_at`”，不证明真实世界时间，仍非 TSA；
  一个更早但签名有效的旧 bundle 仍是可验证的历史快照，不是“当前此刻”证明。消费方必须检查
  返回的 `evaluated_at` 是否满足自身新鲜度策略，不能把离线验签等同于抗重放时间证明。

本轮 fresh 测量（控制器 fresh，未复用历史数字）：
`tests/test_agency_bundle_v01.py` `39 passed`（30 原测试 + 9 新回归：wrong role
signer/export 拒绝、signed p1→p2 bundle 删后缀无钥重建拒绝、revoked 删 revoke 回滚拒绝、
evaluated_at/status coherent rewrite 拒绝、manifest 签名字节/签名者篡改拒绝、verifier
monkeypatch ledger/system time/network/private-key 纯净性）；bundle+acceptance
`test_agency_bundle_v01.py + test_acceptance_bundle_v01.py` `113 passed`；agency focused
（models/history/policy/ledger/bundle/end_to_end）`178 passed`；`pip check`/`compileall`/
`git diff --check` PASS。第二轮独立 review 未发现 P0/P1/P2，Task 6 实现切片 READY；尚未
合并/推送，全量 inventory boundary 仍待 Task 9 重建。

## Human Agency Profile 0.1：独立 schema registry 冻结与公开 API（2026-08-24）

同一隔离分支 `codex/human-agency-profile-v01` 新增独立
`agency_schema_registry.py` 与 `schemas/agency-v0.1/`（三种 Acceptor 签名协议对象
schema + registry），并扩展 `__init__.py` 最小懒加载公开 API：

- 独立 registry 只冻结计划列出的三种对象：`human-agency-profile`、
  `agency-profile-transition`、`agency-appeal`；`schema_version` 为
  `openworkproof-agency-schema-registry/0.1`，`protocol_version=0.1`，entries 按
  object_type UTF-8 排序且每条精确 SHA-256，无自引用。**未触碰**主 v0.1–v0.5
  冻结 registry、`_FROZEN_V01_DIGESTS` 或主 `schema-registry.json` digest，也未把
  agency 对象加入任何既有 `_OBJECT_PATHS_BY_VERSION`。
- `generate_agency_schemas(destination)` 单目标安全事务（resolved-target preflight、
  lock、staging 读回、backup/commit/rollback、COMMIT-ACK 精确读回、cleanup），
  生成 bytes 与 packaged bytes 逐字节一致；`authoritative_agency_schema(object_type)`
  返回 canonical bytes 且未知对象 `ValueError` fail closed；`verify_packaged_agency_schemas()`
  经 `importlib.resources` 读 packaged `schemas/agency-v0.1` 并与生成锚点比对，漂移/缺文件/
  非 canonical 均 `RuntimeError`。
- `__init__.py` 最小懒加载公开：Agency 三模型、commit/load 六函数、
  `authorize_tool_call_with_agency_profile` + `dispatch_protected_agent_action`、
  `export_agency_bundle` + `verify_agency_bundle_directory` +
  `AgencyBundleManifestV01` + `AgencyBundleVerificationResultV01`；未导出 evidence
  私有锁/SQL helper。`pyproject.toml` package-data 追加 `schemas/agency-v0.1/*.json`，
  无新增依赖。
- 边界：`AgencyBundleManifestV01` 现为 Sidecar 签名模型，但本 Task 只冻结三种
  agency 对象 schema，未加入 bundle schema（计划未列，不擅自扩大）。

本轮 fresh 测量（控制器 fresh，未复用历史数字）：
`tests/test_agency_schema_registry_v01.py` `17 passed`；计划 Step 4 门
（agency_schema_registry + test_schema_registry + test_package）`60 passed`；
agency focused 七文件门 `195 passed`；相邻协议回归（policy/mcp_server/repo_read/
retraction/acceptance_bundle/schema_registry）`309 passed`；`python -m build` 成功
（wheel 内含全部 4 个 agency schema 资源）；wheel `--no-deps --target` 隔离安装后
`importlib.resources`/`authoritative_agency_schema`/`verify_packaged_agency_schemas`
可读且 sha256 一致；`pip check`/`compileall`/`git diff --check` PASS。

诚实边界不变：customer_adoption/payment/upstream_adoption 仍 `not_evidenced`；全量
inventory boundary（`test_current_candidate_inventory_binds_*` 因 candidate definition
变化需 Task 9 重建）仍未闭合；本 Task 未改 main、未 push、未重建 candidate inventory、
未做 Task 8。

### Task 7 独立审查 P2 修复（2026-08-24，commit `fix: recover agency schema publish acks`）

只做最小修改，未改 schema bytes/registry digest/公开集合本身，未做 Task 8/重建
inventory/main/push：

- P2-1：`agency_schema_registry._commit_staged_directories` 的
  `target.replace(backup)` 在已真实落地却抛 OSError（ACK loss）时未记录 backup，导致
  本次失败后 target 缺失。修复采用与 stage→target 相同的 readback 式 committed-truth
  判断：仅当 `target` 不存在且预期 backup 已作为目录存在时记录已移动并继续事务；歧义
  fail closed 且由既有 rollback/cleanup 收敛。新增两条故障注入：monkeypatch `Path.replace`
  仅对旧 target→backup 真实 replace 后抛 OSError（收敛到完整新 target、零残留）；backup
  rename 真失败未落地（旧 target 精确保持、零残留）。
- P2-2：`openworkproof/__init__.py` 新增 side-effect-free `__dir__`
  （`sorted(set(globals()) | set(__all__))`）。fresh import 与 installed wheel 上
  `dir(openworkproof)` 包含全部 `__all__`（含 Task 7 新增 15 项 agency 导出），不触发
  lazy import，`__all__`/`__getattr__`/`__dir__` 一致。

本轮 fresh 测量（控制器 fresh，未复用历史数字）：
`tests/test_agency_schema_registry_v01.py` `20 passed`；计划 Step 4 门
（agency_schema_registry + test_schema_registry + test_package）`64 passed`；agency
focused 七文件门 `198 passed`；主/companion registry 回归 `61 passed`；并发
`test_supersession_concurrency_yields_single_winner` `1 passed`；相邻协议回归
（policy/mcp_server/repo_read/retraction/acceptance_bundle/schema_registry）`309 passed`；
`python -m build` 成功；wheel `--no-deps --target` 隔离安装后 `dir(openworkproof)`/
`importlib.resources`/`verify_packaged_agency_schemas` 全绿；`pip check`/`compileall`/
`git diff --check` PASS。

诚实边界不变：customer_adoption/payment/upstream_adoption 仍 `not_evidenced`；全量
inventory boundary（`test_current_candidate_inventory_binds_*`）仍待 Task 9 重建；本
commit 未改 main、未 push、未重建 candidate inventory、未做 Task 8。

### Task 7 独立审查 P1 修复（2026-08-24，commit `fix: constrain agency schema contracts`）

agency v0.1 JSON Schema 此前太浅：纯 Pydantic `model_json_schema` 只对
digest/key/signature/time 字段输出裸 `type: string`，`Draft202012Validator` 会接受
明显畸形的对象。本 commit 只在 `src/openworkproof/agency_schema_registry.py` 对三个
独立 agency schema 做确定性 post-processing 约束增强并重新生成 packaged schema 与独立
registry，**未改** core `models.py`、既有主 schema registry v0.1、Task 8、candidate
inventory、main 或远端：

- 可表达的约束（确定性、进生成 pipeline）：Digest/ID/nonce（语义为 Digest64 的字段）
  `pattern ^[0-9a-f]{64}$`；`signer_key_id` `pattern ^ed25519:[0-9a-f]{64}$`；
  `signature` 未填充 base64url 64 字节签名 `pattern ^[A-Za-z0-9_-]{86}$`；canonical UTC
  时间戳 `format date-time` + `pattern ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`；
  非空标识符 `minLength 1`、可确认字段 `maxLength 128`（`appellant_subject_id`）。
- `HumanAgencyProfileV01`：`delegated_actions` 与 `reserved_decisions` 至少一边非空
  （`anyOf` 两分支各 `minItems 1`）；`reserved_decisions` `maxItems 5`；集合型数组
  （delegated/reserved/escalation/blocked_tools）`uniqueItems true`；`appeal_roles`
  固定且仅为 Developer/Manager/Verifier 此顺序（`prefixItems` + `const` + `min/max 3`）；
  保留 `additionalProperties false`。
- `AgencyProfileTransitionV01`：`if/then` 约束 `revoked` => replacement 两字段均为
  `null`；`superseded` => 两者均为 Digest64 字符串。`replacement != target` 仍属语义
  验证，写入 `$comment`。
- `AgencyAppealV01`：digest/key/signature/time/nonce 与唯一性同样收紧。
- 每个根 schema 与 `$defs` 对象带 `$comment`：OpenWorkProof semantic validation remains
  mandatory after JSON Schema validation; canonical ordering, content-derived
  id/digest recomputation, cross-object/WorkOrder bindings and Ed25519 signatures are
  not fully expressed here —— 不把无法用 JSON Schema 可靠表达的语义伪装成已覆盖。

RED 测试（`tests/test_agency_schema_constraints_v01.py`，新增）直接使用
`jsonschema.Draft202012Validator`、不调用 Pydantic，覆盖：恶意 transition（坏
digest/signature/time/replacement）逐类结构错误、revoked 携带 replacement 拒绝、
superseded 缺 replacement 拒绝、bad digest/key/signature/time 逐类拒绝、delegated+reserved
都空拒绝、reserved>5 拒绝、appeal_roles 错角色/错顺序拒绝、可表达重复项（escalation 与
blocked_tools）拒绝、合法 packaged 实例仍通过、以及一条“结构 schema 通过但
OpenWorkProof 语义验证拒绝”的边界测试（内容派生 `profile_id` 不匹配）——用于证明不能
宣称 Schema 与 Pydantic 完全等价。

本轮 fresh 测量（控制器 fresh，未复用历史数字）：
`tests/test_agency_schema_constraints_v01.py` `37 passed`；
`tests/test_agency_schema_registry_v01.py` `20 passed`；agency schema 门
（schema_registry + schema_constraints + test_schema_registry + test_package）
`101 passed`；agency focused 八文件门（七文件 + schema_constraints）`235 passed`；
主/companion registry 回归 `61 passed`；相邻协议回归
（policy/mcp_server/repo_read/retraction/acceptance_bundle/schema_registry）
`309 passed`；`python -m build` 成功（wheel 内 4 个 agency schema 资源与生成锚点
sha256 一致）；wheel `--no-deps --target` 隔离安装后 `verify_packaged_agency_schemas`/
`authoritative_agency_schema`/硬化约束均生效；`pip check`/`compileall`/`git diff --check`
PASS。主 v0.1–v0.5 与 companion registry 字节完全未变；独立 registry digest 已随硬化
schema 更新。

诚实边界不变：customer_adoption/payment/upstream_adoption 仍 `not_evidenced`；全量
inventory boundary（`test_current_candidate_inventory_binds_*`）仍待 Task 9 重建；本
commit 未改 main、未 push、未重建 candidate inventory、未做 Task 8。

## Human Agency Profile 0.1：文档、双语边界与使用样例（2026-08-24，commit `docs: explain verifiable human agency boundaries`）

Task 8 完成，只做文档、双语边界与使用样例，未改协议代码、main、candidate inventory，
未 push：

- 新增 `docs/protocol/human-agency-profile-v0.1.md`：面向工程师，含 why、三对象
  （`HumanAgencyProfileV01`/`AgencyProfileTransitionV01`/`AgencyAppealV01`）、角色与
  签名权威、状态/撤销/替换/appeal、授权先行（基础授权先于 agency layer 且同一 target
  lock 内）、protected dispatcher 四工具、offline bundle、schema+semantic 验证边界、
  threat model/fail-closed、最小 API 示例、诚实未完成/非承诺边界。
- 新增 `examples/human_agency_profile_v01.py`：仅进程内生成 WorkOrder-bound profile、
  Acceptor Ed25519 签名、verify、判定一个 delegated（`owp.repo_read`）与一个 reserved
  （`owp.apply_patch` → `AGENCY_HUMAN_DECISION_REQUIRED`）；不写私钥文件、不联网、无
  账本副作用、不暗示生产部署；双跑 stdout 字节一致，只打印稳定事实、无随机
  digest/id/私钥（P1 审计修复）。
- `README.md`/`README_en.md` 各新增一段三条事实的实验能力入口 + protocol/example 链接，
  中英文语义对齐，未重写其它段落。
- `tests/test_documentation_boundaries.py` 新增 9 条文档真相边界测试（RED→GREEN）。

明确并测试的边界：

- Human Agency Profile 是 WorkOrder 绑定、Acceptor 签名、机器可验证的授权/保留决策
  边界；不是员工评分、绩效监控、法律责任转移、自动担责、资金托管或合规认证。
- appeal 只记录请求，不恢复/扩大权限；只有 Acceptor 签名的 transition 才能撤销当前
  profile 或将其替换为另一个 Acceptor 签名的 profile。
- JSON Schema 只做结构门；内容派生 ID、WorkOrder 绑定、Ed25519 签名、因果/时间语义
  仍需 OWP verifier。
- offline bundle 是签名时点的历史快照，不是 TSA/current-state 证明；使用方须应用
  freshness policy。

fresh 测量（控制器 fresh，未复用历史数字）：

- `tests/test_documentation_boundaries.py`：`19 passed`（含 9 条新增边界测试）；
- Task 8 门 `test_documentation_boundaries.py + test_agency_models_v01.py +
  test_agency_end_to_end_v01.py`：`84 passed`（19 + 25 + 40）；
- agency schema 门 `test_agency_schema_constraints_v01.py +
  test_agency_schema_registry_v01.py + test_package.py`：`60 passed`；
- `examples/human_agency_profile_v01.py`：退出码 0，双跑 stdout 字节一致，只打印
  稳定事实、无随机 digest/id、无私钥（P1 审计修复后复测）；
- `pip check` / `compileall src examples` / `git diff --check`：PASS。

```yaml
customer_adoption: not_evidenced
payment: not_evidenced
upstream_adoption: not_evidenced
```

诚实边界不变：未改 main、未 push、未重建 candidate inventory、未做 Task 9；全量
inventory boundary（`test_current_candidate_inventory_binds_*`）仍待 Task 9 重建，
不把 inventory 预期失败混入 Task 8。

## Verified Agent Delivery 0.1 本地实现（2026-08-22）

隔离分支 `codex/verified-agent-delivery` 已按计划实现首个商业产品切片
`OpenWorkProof Verified Agent Delivery`：`delivery_case.py` 严格闭合模型 +
安全原子初始化 + 从真实 Surface/Acceptance/Settlement 证据派生状态 +
确定性摘要与原子导出 + 四条 CLI 命令 + 商业交付模板 + GitHub delivery-case
composite Action。它只是既有 Surface Bundle、Acceptance Bundle 与 settlement
readiness 上方的薄编排层，不建设商城、SaaS、登录、钱包、托管或自动付款。

- 实现内容：`delivery_case.py`（闭合模型、`initialize_delivery_case`、
  `inspect_delivery_case`、`export_delivery_case`、`verify_exported_delivery_case`）、
  `delivery_case_render.py`（确定性 JSON/Markdown 摘要）、
  `delivery-case init/inspect/verify/export` CLI（`verify` 退出码闭合为
  `READY_FOR_SETTLEMENT_REVIEW=0`、`REFUTED=2`、`REJECTED=2`、`UNKNOWN=3`、
  `operational=4`）、`integrations/github-delivery-case/` composite Action、
  `docs/commercial/verified-agent-delivery/` 商业模板与 README 双语言入口。
- 本轮 fresh 测量（控制器 fresh，未复用历史数字）：
  - 专项 63 测试（`test_delivery_case_v01.py` + `test_delivery_case_cli_v01.py`）
    fresh：`63 passed`（82.93s）；
  - focused 七文件门：`213 passed`（217.97s）；
  - 便携全量：`3975 passed、3 failed、8 skipped`（1362.29s）。8 skip 均为已分类
    platform/live 边界（AgentTeams 真实环境、candidate artifact root、Landlock、
    immutable image）。3 failed 中 1 个为 README_en 边界（`automatic payment`
    字面量），已改为 `automated money movement` 并复跑相关测试通过；另 2 个为
    `test_current_candidate_inventory_binds_*`（当前 source closure 因
    `__init__.py` 新增 delivery-case lazy export 而变化，历史 inventory
    `238d933…` 0 match），需 Task 9 重建 candidate inventory 后闭合；
  - wheel 隔离安装：`pip wheel . --no-deps` 成功，隔离 venv 安装
    `openworkproof-1.3.0`，`owp delivery-case --help` 显示四个子命令，
    `import openworkproof` 无副作用；
  - `pip check` / `compileall` / `git diff --check`：PASS。
- 诚实边界不变：不托管资金、不等于付款、不构成法律审计；`READY_FOR_SETTLEMENT_REVIEW`
  不等于完成结算；客户采用、付费 SOW、定金、外部付款、上游采纳均为
  `not_evidenced`。自有 fixture 与导出包不计入真实十单、付款方或复购。

### Task 9 candidate 收口（2026-08-22，HEAD d74a68e）

- source closure 分析：`SOURCE_ALLOWLIST` 文件列表未变（`delivery_case.py` 不进入
  trusted-helper 镜像）；但 `__init__.py` 在 allowlist 内且已变更，`helper_src_sha256sums_sha256`
  由 `ce0ae8ff…` 变为 `a79640fb…`，必须重建不可变 inventory。
- 沙箱：DSH 禁止写 `~/.docker/buildx/activity`，用 `DOCKER_CONFIG=/private/tmp/owp-docker-config`
  使 buildx 可写 activity；candidate 在 `/private/tmp/owp-candidate-delivery` 构建
  （`external_layout.local_root` 如实记录，build_inputs 全部 revision-bound）。
- 不可变 inventory：`supply-chain/images/candidates/f81f2e840fa568d41919821b14b9d8d27f2eec3e.json`；
  4 个 archive tar + `SHA256SUMS` + inventory copy + sidecar。execution
  `local_image_id=sha256:f3d8907a…` / `oci_manifest_digest=sha256:b36f2f56…`；
  trusted-helper `local_image_id=sha256:b6751863…` / `oci_manifest_digest=sha256:cc104df2…`。
- fresh 门（本轮控制器 fresh，非历史计数）：
  - candidate 两套件（live Docker + artifact root）：`182 passed、0 failed、0 skipped`；
  - required-live 全量：`3986 passed、0 failed、1 skipped`（唯一 skip 为未启用的
    AgentTeams 真实三 Agent 环境，按 marker 如实记录）；
  - 便携全量（candidate 重建后复跑）：`3979 passed、0 failed、8 skipped`；
  - `pip check` / `compileall` / `git diff --check` / wheel 隔离安装：PASS。
- 契约测试修正：新 candidate `f81f2e8…`（hex 以 `f` 开头）按字典序排在冻结 v0.1
  candidate `ed2da68a…`（hex 以 `e` 开头）之后，`test_inventory_v01_remains_valid_without_runner_digest`
  与 `test_inventory_loader_rejects_source_revision_drift_to_head` 两处以
  `CANDIDATE_PATHS[-1]` 隐式取 v0.1 candidate 的断言会误取 v0.2 新 candidate。
  已在 `2425dbd` 改为显式引用 `ed2da68a…`（测试意图不变，未跳过/未放宽/未改写历史库存）。
- 未执行：merge / rebase / push / tag / GitHub Release / PyPI / MCP Registry 发布。

```yaml
customer_adoption: not_evidenced
paid_sow: not_evidenced
deposit: not_evidenced
external_payment: not_evidenced
```

## 1.3.0 双入口本地候选（2026-08-21）

- 商业入口：GitHub Action 已能从客户私有 v0.5 Delivery Package 和已签环境
  指纹生成 Surface Bundle，并通过 `owp surface-verify` 离线复核。
- 生态入口：AgentTeams / MCP 共用同一证据核心；Manager、Developer、Verifier
  的角色、密钥和 Matrix 事件 ID 均被显式绑定。
- 跨入口一致性：GitHub 与 AgentTeams 共享中立执行投影；平台身份只进入各自
  完整指纹，不污染共同事实摘要。
- AgentTeams 真实运行目前只完成安全 preflight。当前环境缺 Matrix token，且
  Worker 模型端曾返回额度不足；没有真实三 Agent 工作结果，也没有人工
  Acceptor 终态。
- Task 14 已完成本地 focused、冻结兼容、candidate live 与 required-live 运行：
  focused `207 passed / 1 skipped`；冻结兼容 `167 passed`；portable 全量
  `3766 passed / 8 skipped`（均为已分类 platform/live 条件）；candidate live
  `180 passed / 0 skipped`；required-live 全量 `3773 passed / 1 skipped`，无
  unhandled-thread warning。required-live 唯一 skip 为未启用的 AgentTeams 真实
  三 Agent 环境。
- 因 Task 11 真实三 Agent 执行、人工 Acceptor 终态与独立双审仍未取证，Task 14
  的严格 `0 skipped` 发布门尚未闭合；1.3.0 仍是本地候选，未发布。
- 下文凡将 1.2.0 写作“当前”或“待发布”的段落均是带日期的历史快照；当前
  状态以本节为准。

```yaml
customer_adoption: not_evidenced
paid_sow: not_evidenced
deposit: not_evidenced
upstream_adoption: not_evidenced
agentteams_live_execution: not_evidenced
human_acceptance: not_evidenced
```

### Acceptance Bundle 0.1 本地实现（2026-08-21）

- 本地分支已实现 `AcceptanceDecisionBindingV01`：Verifier 的 v0.5 Decision 与
  Acceptor 的 ACCEPTED/REJECTED 终态分别签名，再由 Acceptor companion binding
  精确绑定 WorkOrder、Decision、CompositionReport、验收请求和终态 receipt。
- 已实现 `prepare → sign → commit` 追加式事务、Acceptance Bundle 原子导出、
  纯离线目录重放、Python/Services/CLI 接口与闭合退出码：`ACCEPTED=0`、
  `REJECTED=2`、`operational=4`。缺失或不匹配 binding 时 fail closed。
- AgentTeams 演示参数已从裸 receipt 改为 `--acceptance-bundle DIRECTORY`；外部
  人工验收门只调用核心 verifier，Matrix announcement 失败不改变已验证终态，
  但进程以 operational error 报告通知失败。
- 本轮 Task 9 三文件攻击/隐私矩阵 fresh：`134 passed`。覆盖 companion binding
  关联字段、有效签名对象集合重组、外层摘要同步篡改、committed evidence 篡改、
  链接/FIFO/容量/读时漂移、并发、ACK-loss、cleanup、provenance 不覆盖与秘密/
  绝对路径扫描。
- 以上均为本地工程事实；没有执行新的真实三 Agent 工作流，也没有取得人工客户
  验收、客户采用、付费 SOW、定金或上游采纳证据。

### Acceptance Bundle 0.1 Task 11–12 完成（2026-08-21，HEAD 238d933）

- fresh 门结果（本轮复跑，非历史计数）：
  - focused 协议门：`365 passed`（278.14s，本轮复跑）；
  - portable 全量：`3907 passed、0 failed、8 skipped`（1075.71s；8 skip 均为
    platform/live 边界）；
  - candidate 两套件（portable）：`180 passed、0 failed、1 skipped`（598.09s；
    1 skip 为 artifact root）；
  - required-live 全量：`3914 passed、0 failed、1 skipped`（1378.58s；唯一
    skip 为未启用的 AgentTeams 真实三 Agent 环境，按 marker 如实记录）。
- source allowlist 变化（acceptance.py / evidence.py / models.py / signing.py /
  __init__.py 五文件）使历史 inventory b974722 出现 `0 match`；本轮按
  prepare_context → buildx → convert_docker_archive → docker load 流程为最终
  revision 新建不可变 inventory：
  `supply-chain/images/candidates/238d9339a1d9fa2f00b4adb315a5ee14b51acb7e.json`
  （唯一变化的 build_inputs 为 helper_src_sha256sums_sha256=ce0ae8ff…；execution
  digest=sha256:8b926ccb…，helper digest=sha256:fe9a8fb9…）。历史 inventory 未覆盖。
- 沙箱边界：DSH workspace-write 禁止写规范外部根 /Users/molin/Project/openWorkProof-delivery
  （升级 danger-full-access 无审批通道，fail closed）；本轮候选在
  /private/tmp/owp-candidate-delivery 构建，inventory local_root 如实记录该路径；
  build_inputs 全部 revision-bound，可在规范根复现。首次 required-live 因 Docker
  Desktop daemon 中途崩溃（7 个 live 测试 "daemon unavailable"）失败，已重启
  daemon 并复跑通过。
- 独立双审：规格审查 6 项全部 CONFIRMED（0 Critical / 0 Important）；质量/安全审查
  APPROVE-WITH-NOTES（0 Critical / 0 Important / 6 Minor，均为回放保真/测试覆盖
  polish，无可利用缺陷）。
- 边界不变：真实三 Agent、人工验收、客户采用、付费 SOW、定金、上游采纳：
  not_evidenced。

`VERIFIED != ACCEPTED != PAID/SETTLED/LEGAL AUDIT/ADOPTION`

## 当前发布事实（以本次命令和公开回读为准）

- 干净基线 revision（Task 1 起点，不含候选改动）：
  `5cecd4265cbf2b7b118914f386fec87e7de744c4`。
- 基线三文件命令与精确结果（controller fresh，在干净基线 revision
  `5cecd426…` 上复跑，未含任何候选改动）：
  - `./.venv/bin/python -m pytest -q tests/test_package.py
    tests/test_documentation_boundaries.py tests/test_schema_registry.py`
    ：`47 passed in 3.07s`。
- Task 1 candidate diff（尚未提交，无 commit SHA）加入 CI 契约测试后，
  Harness 复跑三文件命令：
  - `./.venv/bin/python -m pytest -q tests/test_package.py
    tests/test_documentation_boundaries.py tests/test_schema_registry.py`
    ：`48 passed in 3.91s`。该结果属 candidate 改动后的复跑，不归入干净基线
    revision `5cecd426…` 已有事实，也不预写任何未来 commit SHA。
- 本轮其余命令与精确结果：
  - `./.venv/bin/python -m pytest -q tests/test_documentation_boundaries.py
    tests/test_package.py`：7 passed、0 failed、0 skipped、0 warnings（0.02s）；
  - `./.venv/bin/python -m pip check`：No broken requirements found；
  - `./.venv/bin/python -m compileall -q src tests`：通过；
  - `git diff --check`：通过。
- 公开回读（来源与回读时间如实标注；回读失败/无结论一律 `not_evidenced`，禁止
  猜测）：
  - Python package（PyPI，来源
    `https://pypi.org/pypi/openworkproof/json`，回读 2026-08-20T19:27Z）：
    最新版本 `1.2.0`；
  - GitHub Release（来源
    `https://api.github.com/repos/dengyier/OpenWorkProof/releases/latest`，
    回读 2026-08-20T19:27Z）：最新 `v1.2.0`（published 2026-08-16T09:31:26Z）；
  - MCP Registry（来源
    `https://registry.modelcontextprotocol.io/v0.1/servers?search=openworkproof`，
    回读 2026-08-20T19:31:58Z，HTTP 200）：返回
    `io.github.dengyier/OpenWorkProof` 版本 `1.2.0`、package `openworkproof`
    版本 `1.2.0`、official metadata `isLatest: true`、publishedAt
    `2026-08-16T09:59:03.383097Z`。以上仅为公开注册表回读结果，不扩大为
    生态采纳或上游采纳。
- 客户采用、付费 SOW、付款、续费、上游采纳：`not_evidenced`。
- 历史测试数字保留为历史记录（见下文各阶段小节），不覆盖、不冒充本快照的当前
  结果。

## Dual Verifier v0.5 本地开发状态（Phase 3，2026-08-19）

`main` 本地新增 Dual Verifier（双独立密钥交叉验证）：high_risk 决策要求
双套 arm results（每 arm 每个 verifier binding 各一套），`compose` 逐字段
交叉验证全部承载结论字段（expectation_status / execution_status /
mutation_status / reason_codes / action_receipt_ids / observed_* /
scope_expectation_status / population_observations / control_observation /
evidence snapshot），任一不一致 → 组合失败（`VerificationInputError`，临时
折中：v0.6 决策模型支持双套引用后用 `DUAL_VERIFIER_DIVERGENCE` 正式入账）。
决策引用完整双套，commit/replay/离线包均从决策自身引用（`selected_ids`）
重跑交叉验证，不依赖签名数推导独立性；prepare 用每 (arm, verifier) 最新；
commit stale 门要求决策引用集精确等于 prepare 会加载的那一套（验证者不能
引用自己的旧轮压掉更新的失败轮）。单验证者集合 → UNKNOWN（independence
不足）；split 覆盖拒绝；standard 语义不变；v0.1–v0.4 冻结面未触碰，v0.5
schema 仅新增 `DUAL_VERIFIER_DIVERGENCE` reason code（走 schema-registry
流程重新生成 + 更新冻结锚点 + 刷新冻结 demo bundle）。

- 独立双审 **7 轮**（spec + quality/security）全部 REJECT 关闭后终审
  APPROVE + APPROVE-WITH-NOTES：R1（只比 evidence snapshot → 逐字段收敛）、
  R2（双验证者路径 prepare/commit/replay 不可达 → 决策自证全链双套）、
  N1（签名数推导独立性恒真 → 删除 flag）、N8（commit stale 粒度 → 引用集
  精确等于 prepare 加载集，质量审查 PoC 原样重跑验证）、N9（每
  (arm, verifier) 行数门）等；终审 Notes 清理（imports 上移、死检查删除、
  报错文案、§4.2 注释、自报 created_at 诚实边界）已落实。
- fresh 测量（2026-08-19，HEAD `6e56bb0`）：
  - v0.5 focused：**dual-verifier 10 测试 + retraction/delivery/schema 全绿**；
  - 全量便携：**3358 passed、0 failed、6 skipped**（非 Linux 环境 skip）；
  - candidate 重建：`supply-chain/images/candidates/837dbb10….json`
    （4 归档 + SHA256SUMS + sidecar），candidate 两套件 + inventory-binds/
    selector 全绿（live Docker）；
  - **required-live 全量**（
    `docker.io/openworkproof/execution-test@sha256:3065c0005c…`）：
    **3543 passed、0 failed、0 skipped，零 warning**（13 分 35 秒）；
  - pip check / compileall / git diff --check：PASS；
  - Docker 残留：本任务零残留。
- 诚实边界不变：无客户采用、无付费 SOW、无定金、无上游采纳（全部
  `not_evidenced`）；Dual Verifier 证明"协议要求双验证者收敛"，不证明
  "任何实际交付都经双验证"、"验证者诚实"或"无共谋"；分歧不入账不可审计、
  单验证者可无痕阻断全部 high_risk、配对时间差未强制、新鲜度按验证者自报
  `created_at`（backdate 与不发布等价）——均为 spec §6 诚实记录的边界。
- 本地 HEAD `6e56bb0`，领先 origin 若干提交，未 push。

## RetractionReceipt v0.5 本地开发状态（Phase 2，2026-08-19）

`main` 本地新增 RetractionReceipt（语义可撤销性）：`RetractionReceiptV05`
模型 + `retraction-receipt` 签名域（Manager/Verifier 签发，Acceptor 撤销验收
仍走 `AcceptanceTransitionReceipt`）、`commit_retraction_receipt` append-only
事务、`receipt_retraction_status` / `retraction_chain` 查询、决策兼容（被
`refuted` 撤销的 causal receipt → 决策 `UNKNOWN` + `RECEIPT_RETRACTED`，
contradicted arm 时 REFUTED 优先；replay 按 `decided_at` 协议时间界定）、
离线包导出 retraction 链 + 离线重放。新增 reason code `RECEIPT_RETRACTED`
（走 schema-registry 流程重新生成 v0.5 decision schema + 更新冻结锚点 +
刷新冻结 demo bundle）。改动仅新增 v0.5 sibling 对象 + 新表 + 语义收紧，
v0.1–v0.4 冻结面未触碰。

- 独立双审两轮 REJECT 全部修复：schema 冻结锚点漂移、决策 replay 焊死
  （按 `retracted_at` 协议时间 as_of 界定）、nonce 未闭合（进共享扫描）、
  离线 `RECEIPT_RETRACTED` 决策包 replay bug。
- fresh 测量（2026-08-19，HEAD `27ac7bb`）：
  - v0.5 focused：**477 passed、0 failed**（含 41 个新 retraction/schema 测试）；
  - candidate 两套件（live Docker）：**178 passed、0 failed**；
  - **required-live 全量**（
    `docker.io/openworkproof/execution-test@sha256:5f64e46c…`）：
    **3532 passed、0 failed、0 skipped，零 warning**（13 分 28 秒）；
  - pip check / compileall / git diff --check：PASS；
  - Docker 残留：本任务零残留。
- 候选：`supply-chain/images/candidates/27ac7bb….json`（绑定 HEAD）。
- 诚实边界不变：无客户采用、无付费 SOW、无定金、无上游采纳（全部
  `not_evidenced`）；本段是本地工程状态，不是发布/推送/验收声明。
- 本地 HEAD `27ac7bb`，领先 origin 14 提交，未 push。

## Negative-Control Rot Defense 本地开发状态（Phase 1，2026-08-18）

`main` 本地新增负控 rot 防御：负控契约的 `expected_failure_signature.reason_codes`
必须精确等于注册目标失败码（`semantic_regression→MUTATION_CAUGHT`，
`required_target_coverage→SCOPE_REQUIRED_TARGET_MISSING`），基础设施/依赖漂移码
（`EXEC_DEPENDENCY_DRIFT`、`EXEC_COMMAND_FAILED`、`EXEC_TIMEOUT`、
`EXEC_CRASHED`、`EXEC_WORKSPACE_DRIFT`、`EVIDENCE_MISSING`、
`MUTATION_CLASSIFIER_UNAVAILABLE` 等）在 Profile 构造期即被拒绝——负控只因
依赖/schema/基础设施漂移失败时不再派生 `proven`（Skillselion rot 攻击，
规格 §12 威胁模型第 9 条）。改动仅限 v0.5 语义校验 + 模块常量，未触碰
v0.1–v0.4 冻结面、签名字节或 JSON Schema。

- 提交：`b80af80`（本地 follow-up，未 push）；独立双审 spec + quality 均
  APPROVE-WITH-NOTES（无 Critical/Important）。
- 候选已按新 revision 重建：`supply-chain/images/candidates/b80af80….json`。
- fresh 测量（2026-08-18）：
  - v0.5 focused（10 文件）：**410 passed、0 failed**（原 401 + 新增 12 rot 测试）；
  - 冻结兼容：`216 passed、0 failed`；
  - candidate 两套件（live Docker + artifact root）：**177 passed、0 failed**；
  - **required-live 全量**（
    `docker.io/openworkproof/execution-test@sha256:6184e274…`）：
    **3506 passed、0 failed、0 skipped，零 warning**（12 分 45 秒）；
  - pip check / compileall / git diff --check：PASS；
  - Docker 残留：本任务零残留（5 个 agentteams 容器与 9 个数据卷为既有）。
- 诚实边界不变：无客户采用、无付费 SOW、无定金、无上游采纳（全部
  `not_evidenced`）；本段是本地工程状态，不是发布/推送/验收声明。

## Verification Integrity v0.5 本地开发状态

`main` 分支已实现 v0.5 验证完整性协议：人口契约/观察（eligible 与
selected 分离）、负控契约/失败签名、`VERIFIED / REFUTED / UNKNOWN` 三态
决策矩阵、追加式账本事务层、三种隐私视图的离线交付包、只读 CLI/MCP
评估入口，以及规格 §12 全部 15 类攻击的对抗测试矩阵。Rich #4196 自建
演示覆盖人口盲区（`POPULATION_CAPTURE_FAILED`）、负控腐化
（`CONTROL_FAILURE_SIGNATURE_MISMATCH`）与修复后完整链 `VERIFIED`，其
冻结交付包离线重放为 `VERIFICATION PASSED`。

Task 15 发布门已重建候选并复测，最终测量（2026-08-15，独立总审修复与终审 Minor
闭环后的最终重建）。**第三轮独立审计（2026-08-16，Batch A–E）已闭环**：全部
A–H 发现经攻击测试 RED→最小修复→逐批独立双审→total 复审通过；候选已按最终
修订重建，下方数字为第三轮 HEAD fresh 测量。

- candidate source revision（**当前 = 1.2.0 本地待发布候选**）：
  `d0bec9d2f2c3cf12568fa866d16be1a56de4aa9c`；不可变库存：
  `supply-chain/images/candidates/d0bec9d2f2c3cf12568fa866d16be1a56de4aa9c.json`；
- Python 本地待发布分发版本 `1.2.0`；冻结协议 Schema `0.1`–`0.5`；
- v0.5 focused 套件（10 个文件，命令：
  `pytest tests/test_acceptance_v05.py tests/test_control_integrity_v05.py
  tests/test_delivery_package_v05.py tests/test_population_integrity_v05.py
  tests/test_verification_integrity_adapters_v05.py
  tests/test_verification_integrity_adversarial_v05.py
  tests/test_verification_integrity_demo_v05.py
  tests/test_verification_integrity_interfaces_v05.py
  tests/test_verification_integrity_models_v05.py
  tests/test_verification_integrity_transactions_v05.py`）：
  **1.2.0 本地待发布候选 fresh `401 passed、0 failed`**（68 秒）；
- 冻结兼容（v0.2/v0.3/v0.4 models/schema/delivery/settlement/acceptance）：
  `216 passed、0 failed`（审计基线 fresh，本轮未触碰 v0.1–v0.4 冻结面；
  亦随 required-live 全量一并复跑）；
- 便携全量（`pytest -q`，未设置 live-Docker 环境变量）：
  **1.2.0 本地待发布候选 fresh `3487 passed、0 failed、7 skipped`**（15 分 07 秒；
  skip 均为未设置 artifact root、live-Docker 或 immutable image 所致明确边界，
  已由下方 required-live 零 skip 全量门覆盖）；
- candidate 两套件（live Docker + artifact root + 全限定镜像引用）：
  **1.2.0 本地待发布候选 fresh `176 passed、0 failed`**（含 live Docker 与上下文
  重建身份链；库存 `d0bec9d…`）；
- **required-live 全量**（live Docker + 全限定
  `docker.io/openworkproof/execution-test@sha256:6d0dadec750eb498ed4d2260b4de65f33ed1c146adda6e64ec8ba588f7a88097` +
  `-W 'error::pytest.PytestUnhandledThreadExceptionWarning'`）：
  **1.2.0 本地待发布候选 fresh `3494 passed、0 failed、0 skipped`**（14 分 19 秒，
  零 warning）；审计基线 fresh 为 3456；
- Rich #4196 v0.5 交付包离线重放：`VERIFICATION PASSED / VERIFIED /
  READY_FOR_ACCEPTANCE`（无网络、无原始账本；本轮 demo/M2 套件 fresh 重放）；
- Docker 残留：本任务零残留容器/卷；本机另有 5 个运行中的 agentteams
  容器与 9 个既有数据卷（非本任务创建，未清理）；
- 归档哈希（**当前 `d0bec9d…`**）：execution docker
  `3bd8a5e4b7bf26a3d456489d32bb598e858cceab4371b8748a4120c74415c13e`、
  execution OCI
  `d171485483d4ceba29ee9ad6a5f0e78ede501a8d393760810814178557b4bf37`、
  trusted-helper docker
  `add3fe59def68fedd09830de9021ce8377106cd9068e4557d9aceb7227b27eb1`、
  trusted-helper OCI
  `8d5821e0e23a2dc6819a82174d524e2dcc77c2f372dfdb1743d95c0f67836abd`；

> 历史绑定（非当前快照，保留原字节供复核）：上一轮最终候选
> `a305f7204053f08312613dddb3a0ce7533ce4806`、审计基线
> `d460c876a7f3046fd1d338951d964bce6d1a6be1`（2 Critical + 5 Important +
> 终审 leap-second Minor 闭环的实现提交）与硬化前绑定
> `66d242e…`，以及更早的 `18732766…`/`ca9c911…`/`ca5df6c3…`
> 库存均已随后续源码变更失效，仅作为历史记录保留，不再匹配当前定义。
- 独立总审修复记录：离线包决策只取重放签名真值（public/diagnostic 一律
  UNAUTHENTICATED/NOT_READY）；selector 全部参数冻结进 spec digest 且 node id
  只来自受控 canonical collector（-I 隔离 + conftest-free + pytest.py shadow
  拒绝）；当前决策历史在全部入口完整重放（父结果校验+重 compose+committed_at
  因果序，leap second 拒绝）；控制证据走闭合 canonical 文档解析器；venv
  启动器绑定 invocation/target/pyvenv.cfg；CLI 决策退出码统一
  VERIFIED=0/UNKNOWN=3/REFUTED=4；事务矩阵、六表族物理篡改与计划真值补齐；
  converter 成员安全与 config 派生平台；pytest 临时目录清理噪声消除
  （全门零 warning）。
外部状态边界：

```yaml
customer_adoption: not_evidenced
paid_sow: not_evidenced
deposit: not_evidenced
upstream_adoption: not_evidenced
commercial_validation: not_evidenced
```

绿色测试与离线重放是本地协议能力证据，不表示客户愿意付费、已获得第三方
认证、已减少验收争议、已被上游项目采用或已部署。以上是本地开发状态，不是
发布、推送或验收声明。

## Judgment-to-Action Binding v0.4 稳定性前置修复

Task 1 只修复 `TeamNetworkService` 的关闭期 `close/accept` 竞态，不改变
任何协议对象、签名、账本、状态机或授权语义。修复前的 100 轮真实 TCP
回归稳定捕获 100 个未处理的
`AttributeError: 'NoneType' object has no attribute 'accept'`。修复后，监听
socket 在生命周期锁内复制到局部引用；只有 stop event 已设置且 errno 为
`EBADF`、`EINVAL`、`ENOTSOCK`/`WSAENOTSOCK` 或 macOS 实测的
`ECONNABORTED` 时才按正常关闭退出，其他 accept 错误继续抛出。关闭监听器
前先执行 `shutdown(SHUT_RDWR)`，用 barrier fake socket 证明 wakeup 发生在
close 前，并用 macOS 和 `linux/arm64` 的真实 socket 证明已进入阻塞
`accept()` 的线程会在 1 秒 join 门内退出。Linux probe 使用冻结
`openworkproof/execution-test:3e8f7b863f7936ded99c76d02b84d8e641e80640`
镜像并返回
`LINUX_BLOCKED_ACCEPT_PASS`。

start 的 socket 创建、listen、线程发布与 `Thread.start()` 现在全部位于同一
生命周期锁内；join 只能观察到已启动线程，并发 close 不能被迟到的 start
清除，已完成 close 后的 start 被明确拒绝。setup 或 thread-start 失败会关闭
局部 socket 且不发布半初始化状态。close/shutdown 只忽略明确 allowlist 中的
已关闭错误；即使 shutdown 失败也会尝试 close，`EIO` 等非预期清理错误会
向调用方抛出。测试 fixture 会显式关闭并 join 全部服务线程，100 轮回归每轮
都用 `try/finally` 清理连接与线程。

本切片 focused 结果：正确放置 pytest warning filter 后，
`tests/test_team_network_client.py` 为 `25 passed`，没有
`PytestUnhandledThreadExceptionWarning`；使用隔离临时根执行 `-W error`
同样为 `25 passed`。计划中的字面命令把 `-W` 放在 `-m pytest` 之前，
本机 Python 因 pytest 尚未导入而报告
`Invalid -W option ignored: invalid module name: 'pytest'`；将同一 filter
交给 pytest 解析后才得到上述有效门结果。三文件稳定性回归
`test_team_network_client.py + test_mcp_server.py + test_cli_transport.py` 为
`115 passed、9 warnings`，`git diff --check` 通过；这 9 项均为下述默认
临时根的既有清理 warning，不含未处理线程异常。

macOS 默认 pytest 临时根仍有既有清理警告，精确内容为
`PytestWarning: (rm_rf) error removing .../test_execute_rejects_invalid_f1/fixed-tests`
与 `OSError: [Errno 66] Directory not empty`。owner 是
`tests/test_run_tests_runner.py::test_execute_rejects_invalid_fixed_test_before_started_or_process[symlink]`：
该参数化用例把 `fixed-tests` 设为只读并留下 symlink；它不由本 Task 1 的
网络线程或文件句柄产生。默认临时根下的 `-W error` 因 pytest session
cleanup 将这个既有 warning 升级而非零退出；本切片没有全局过滤或弱化它，
也没有越过三文件范围修改其 owner 测试。以上是本地测试证据，不表示 v0.4
协议工作已完成、required-live 候选已重新冻结、分支已合并或远端已发布。

## Scope-Bound Verification v0.3 本地开发状态

隔离分支 `codex/scope-bound-verification-v03` 已实现签名
`EvaluationScopeManifest`、确定性 selector、必选目标映射、Observed Scope
比较、v0.3 Profile/Arm/Decision 并行表、三种 Delivery Package 隐私视图、
CLI/Python 接口和两个只读 MCP Scope 工具。MCP 没有新增 Scope 签名、
Scope 提交或 Acceptance 决策权限。

Rich #4196 的新增 v0.3 材料是 OpenWorkProof 自有协议演示：旧检查为绿但
遗漏必选 NBSP 回归时结论为 `UNKNOWN / SCOPE_REQUIRED_TARGET_MISSING`；
修复范围后，正臂通过、负控被捕获、两臂人口一致，私有包在无网络、无账本
条件下离线重放为 `VERIFICATION PASSED / VERIFIED /
READY_FOR_ACCEPTANCE`。这不是 Rich 上游已采用、客户案例、客户验收、付款、
资金释放、自动结算或正式部署证据。

Task 15 已在 source revision
`3e8f7b863f7936ded99c76d02b84d8e641e80640` 上完成最终供应链、便携全量、
required-live 和三代离线包复核。对应不可变 inventory 为
`supply-chain/images/candidates/3e8f7b863f7936ded99c76d02b84d8e641e80640.json`，
SHA-256 为 `151b982482a8f155f165aaf45acae895469ffcc5b45f6d81cae5abae5c4e71fb`；
历史 inventory 未覆盖。归档位于
`/Users/molin/Project/openWorkProof-delivery/oci/3e8f7b863f7936ded99c76d02b84d8e641e80640/`，
本轮发布门记录于 `2026-08-11 23:19 CST`。

本轮 fresh 发布门：v0.3 focused 套件 `160 passed`；修复兼容测试探针后，
focused 联合门 `161 passed`；便携全量 `2497 passed、0 failed、6 skipped、
8 warnings`（199.06 秒）；image supply-chain 静态契约 `67 passed`；
candidate artifact chain `1 passed、83 deselected`；required-live 全量
`2654 passed、0 failed、0 skipped、7 warnings`（338.25 秒）。Python
3.12.13、OpenWorkProof module/distribution 1.1.1、Docker client/server
29.5.2、执行平台 `linux/arm64`。warnings 为 pytest 在 macOS 临时目录中
清理已结束子进程测试残留时报告的 `Directory not empty`，未隐藏或改写为
零警告。

Rich #4196 的 v0.1、v0.2、v0.3 三份冻结包均在清空代理变量的独立进程中
离线复核为 `VERIFICATION PASSED`；v0.2 与 v0.3 还分别报告
`VERIFIED / READY_FOR_ACCEPTANCE`，v0.3 Scope 状态为 `satisfied`。这些结果
只证明冻结演示材料的协议重放，不证明 Rich 上游采用或客户验收。

21 天商业试点中的 User、付费方和 Customer Acceptor 都是假设或待填写项；
`commercial_validation: not_evidenced`。本地 release candidate 完成也不等于
远端推送、分支合并、部署、客户接受、付款、资金释放或赛事提交。

## Evidence Lifecycle v0.2 本地开发状态

隔离分支 `codex/verifiable-delivery-pilot` 已实现 v0.2 SubjectClaim、正负
验证臂、VerificationDecision、追加式验收状态、Delivery Package、离线审计、
结算就绪度，以及对应 CLI/MCP 接口。Rich #4196 与 Dify #33013 以新增文件
提供 v0.2 离线复现样本，历史 v0.1 包保持不变。21 天运营工具包位于
`docs/pilot/`。

Task 16 已在 source revision
`64f6ba65a26e0038e6ce8be7925913a4cc7726a3` 上完成最终供应链、便携全量、
required-live 和离线包复核。对应不可变 inventory 为
`supply-chain/images/candidates/64f6ba65a26e0038e6ce8be7925913a4cc7726a3.json`，
SHA-256 为 `3dbaff42728c71bd1194f3a2b9fa0844ecf7190a32aee4b937ad1a83d017c268`；
历史 inventory 未覆盖。可复现 OCI descriptor 的 created 值绑定 source
revision 时间 `2026-08-11T04:35:13Z`，本轮发布门验证记录于
`2026-08-11 15:55 CST`。

本轮 fresh 发布门：focused v0.2 套件 `173 passed`；便携全量
`2484 passed、0 failed、7 skipped、1 warning`（278.54 秒）；image
supply-chain 静态契约 `66 passed`；candidate artifact chain
`1 passed、82 deselected`；required-live 全量
`2491 passed、0 failed、0 skipped、1 warning`（296.89 秒）。两份 v0.2
包在清空代理变量的独立进程中均离线复核为
`VERIFIED / READY_FOR_ACCEPTANCE`。warning 为既有
`team_network_client` 服务重启测试的关闭期线程竞态，未隐藏，也未改写为
零警告。Docker owner 标签下的容器和卷残留为 0。

上述状态只证明本地分支实现、候选工件和冻结样本通过本轮技术门，不证明
客户接受、付费试点、资金释放、正式部署、商业采用、分支合并、远端发布、
赛事提交或融资结果。

## 当前已经实现的能力

当前公开 main 分支已经实现并验证：

- WorkOrder、CapabilityGrant、ActionReceipt 和 AcceptanceReceipt 模型；
- RFC 8785 JCS 规范化、Ed25519 签名和域分离摘要；
- 五角色身份绑定、Agent/Human 嵌套签名和 Sidecar 回执；
- 状态机、谓词注册表和严格 JSON/字节边界；
- 四类协议对象的 JSON Schema 和注册表；
- 确定性源码工件、受限补丁、WorkspaceManifest 和离线重放；
- SQLite 权威账本初始化和唯一 Root Grant 激活；
- child Grant 原子签发、永久 ID 预留、policy-deny 审计历史；
- child Grant 原子撤销、签名历史回放和 duplicate nonce 防重；
- Receipt、Grant、attempt、reservation、event、state 和 version 闭包；
- 300 秒历史时钟重放、61 条常规 Receipt 容量门；
- 并发确认快照、提交事实分类、成功发行唯一性和并发撤销单胜。
- 从签名 Receipt 重放 Grant 余额、single-use 次数和撤销状态；
- parent 直接计费与 child 额度预留合并计算，child 消费不重复扣减
  parent；
- deny 零计费、失败但已启动的工具/回滚计费，以及 direct-call
  角色交集。
- Manager-only `owp.start_retry` 原子消费固定 `repair_rounds=1`，
  并完成 `needs_rework → retrying`；
- 从已提交的 PatchResultEvidence、Verifier 失败和成功回滚重建当前
  rework episode，拒绝错误槽位、篡改字节和证据命名空间置换；
- `STATE_DENIED`、`ROLE_DENIED`、`CAPABILITY_DENIED` 和
  `QUOTA_EXHAUSTED` 的 start-retry 闭合顺序、零计费审计及并发单胜。
- group-aware 证据 staging、POSIX no-replace 发布、整组提交标记、
  崩溃恢复和已提交证据读取门；
- 证据 authority/journal 精确覆盖、固定 publication ID、锚定目录
  描述符和提交前后命名根身份校验；
- SQLite 提交事实三态、COMMIT-ACK 不确定性分类，以及锁、连接和
  文件描述符的独立清理故障上报。
- `commit_receipt_with_publications` Phase 2 原子提交原语：在同一
  `BEGIN IMMEDIATE` 中写入 signed ToolCall Receipt、父边、配额事件、
  `COMMITTING` publication journal、状态版本和全局序号；
- 从当前 ledger、Grant、请求参数、pending evidence 和 Sidecar 提供的
  trusted ResolutionManifest 重算谓词事实；支持成功与已启动但失败的
  `apply_patch` 收据，并对成功结果追加 PatchResult 交叉校验；
- pending 文件名/打开 inode、evidence root 和 ledger 命名身份的
  多阶段锚定，以及 SQLite 清理后的最终文件门和权威账本复核。
- `complete_receipt_publication` Phase 1→4 协调器：在同一目标锁下依次
  完成 pending staging、Receipt/journal 原子提交、no-replace 发布和
  整组 `COMMITTED` 标记；返回前再次重放完整账本、核对配额事件并
  重哈希最终证据；
- Phase 2 提交真值未知时停止后续发布；Receipt 已提交后的发布、
  标记、最终读取门或锁清理故障统一保留为需恢复的 committed truth。
- `validate_grant_chain` 五输入离线验证器：对 Grant、拒绝尝试、
  ActionReceipt 和五个 WorkOrder 绑定公钥执行有界单次快照，重建
  确定性索引，并验证完整签名授权历史；
- 独立的因果回放层：重建每条 Receipt 当时可见的不可变因果快照，
  校验唯一 genesis、精确父集、active patch、rework/rollback、
  approval、composition/recomposition 和 independent-result episode；
- 独立的策略回放层：重算 Grant 衰减、余额、撤销、single-use、
  角色/能力/审批/谓词/配额拒绝优先级，以及 Sidecar 签名的
  ResolutionManifest 解析断言；
- evidence-incomplete 独立验证的新执行上下文、失败封存、
  compose previous-report 绑定、审批有效期上限和 proactive rollback
  拒绝审计均已进入真实签名回归。
- Task 8A `derive_authorization_context` 纯函数：冻结 WorkOrder、规范化
  Grant/Receipt 前缀、可信 UTC 事务秒、逐字节 committed evidence 与
  ReplayCheckpoint，复用既有因果/策略 reducer 推导一次实时决策所需的
  不可变上下文；它不执行工具，也不写入账本。
- Task 8B1 `authorize_tool_call` 纯函数：对签名 AgentRequest、
  精确类型化参数和 Sidecar 分配的测试执行事实进行事前授权；
  按固定顺序检查状态、角色、Grant 能力、人工批准、静态谓词和
  配额，仅返回 `PolicyDecision`，不启动 handler、不扣减配额、
  不签发 Receipt，也不写入账本。
- Task 8B2 `validate_human_decision` 纯函数：验证 HumanDecision 的
  WorkOrder、签名人与角色、300 秒摄入窗口；审批必须精确绑定一张
  尚未决策的高风险请求及其 scope、digest 和 expiry，终止决策无需
  预先请求；仅返回 `PolicyDecision`，不签发 Receipt、不改变状态。
- Task 8B3 `validate_rollback` 纯函数：验证 Developer rollback 请求的
  WorkOrder、Grant、签名和 300 秒新鲜度，绑定当前 active patch 的
  receipt/digest 与 ReplayCheckpoint HEAD；仅开放尚未完成 rollback 的
  needs-rework failure episode，并执行角色、能力和 tool_calls 配额判定。
- Task 13 首个 `owp.run_tests` 可信协调切片：在同一目标锁下
  重放当前授权上下文，事前检查证据槽位与成功/失败 Receipt
  形态，通过内部 `handler_executions` journal 持久化
  `RESERVED → STARTED_UNCONFIRMED` 启动边界，然后仅启动一次
  可信 handler；正常结果进入
  stage→commit→publish→mark committed，handler 异常则提交
  已扣费、无证据附件的 `allow/failed + HANDLER_ERROR` Receipt。
- Task 14 独立 Acceptor 权威：WorkOrder 扩为六角色身份绑定
  （Acceptor 密钥独立于 Maintainer），AcceptanceReceipt 仅接受
  WorkOrder 绑定的 Acceptor 签名，final-acceptance 请求必须声明
  `required_role = Acceptor`，v0.1 schema 与注册表锚点已随模型
  权威重生成。
- Task 15 确定性 proof composition：`CompositionReport` 作为
  可重哈希的权威账本工件，`owp.compose_proof` 在单目标锁与一个
  `BEGIN IMMEDIATE` 内原子提交 Manager 发起收据、报告行、
  proof_composed 收据、配额事件、状态与版本；局部缺失证据的
  首次合成收敛为 `evidence_incomplete`。
- Task 16 final-acceptance 事务链：`request_acceptance_transaction`
  从 proof_ready 原子进入 awaiting_human（1 小时 + WorkOrder 期限
  约束），`prepare_acceptance` 在无私钥输入下返回唯一可外部签名的
  规范草稿，`commit_acceptance` 仅接受 WorkOrder 绑定 Acceptor 的
  签名并原子提交 `accepted` 状态；compose 收据引发的状态转换与
  Acceptor 验收转换已在状态机中由收据级校验授权。

## 当前验证快照

- v0.2 最终 source revision：
  `64f6ba65a26e0038e6ce8be7925913a4cc7726a3`；Python 3.12.13，
  OpenWorkProof module/distribution 均为 `1.1.1`，Docker 29.5.2
  `linux/arm64`；
- v0.2 focused 发布门：173 passed；
- v0.2 便携全量：2484 passed、0 failed、7 skipped、1 warning，
  退出码 0，耗时 278.54 秒；7 项 skip 均为便携模式下明确要求 artifact
  root、Linux Landlock 或 immutable Docker image 的 live 路径；
- v0.2 image supply-chain：66 passed；candidate artifact chain：
  1 passed、82 deselected；
- v0.2 required-live 全量：2491 passed、0 failed、0 skipped、1 warning，
  退出码 0，耗时 296.89 秒；
- Rich #4196 与 Dify #33013 v0.2 包在清空代理变量的独立进程中均为
  `VERIFICATION PASSED / VERIFIED / READY_FOR_ACCEPTANCE`；这不是客户
  AcceptanceReceipt；
- Acceptance 事务专项：40 passed；
- Acceptance、Contract、Signing、State、Composition、Policy、
  Receipt-chain、MCP 与 Schema focused 门：1058 passed；
- 干净 Python 3.12 editable 环境：模块版本与 distribution metadata 均为
  `1.1.1`，`tests/test_package.py` 1 passed；
- M0 修复前本地全量基线：2283 passed、2 failed、7 skipped、1 warning；
  两个失败均为 current candidate inventory 匹配数 0，版本测试已通过；
- 新增不可变候选库存：`supply-chain/images/candidates/
  e5e6d565bed346bcc0afd36ac08ed818bd2063a3.json`；历史库存未覆盖；
- image supply-chain 静态契约：65 passed；current inventory 的 runner 与
  fixed-test-source 选择器：2 passed；
- candidate artifact chain（required-live Docker）：1 passed、82 deselected，
  Docker/OCI archive、live image、revision 重建与断网 smoke 全链通过；
- 全量测试（required-live Docker）：2293 passed、0 failed、0 skipped、
  1 warning，退出码 0，耗时 480.31 秒；warning 为既有
  `team_network_client` 服务重启测试中的关闭期线程竞态，未隐藏；
- M2 Rich #4196 演示专项：test_delivery_m2 5 passed（repo_read 管道
  output_digest 精确重算、apply_patch active patch、verifier 本地验证、
  compose→独立→recompose proof_ready、外部 Acceptor 子进程签名 + 离线
  bundle 验签）；M1 外部 Acceptor 专项：test_delivery_m1 8 passed；
- M3 交付验证签署专项：docs/delivery-signoff/ 冻结清单 + SHA256SUMS
  （112 项）+ Owner/见证人 Ed25519 签署 + 离线复核脚本全部通过；
- 本轮精确验收修复提交：`cac4b51739d1bd1f18069fc957fe116bb8bb2d42`；
- 独立结果与 recomposition 专项：test_independent_recomposition
  34 passed（独立 episode 推导、槽位一对一映射、前置闸门七项拒绝、
  独立基础设施失败精确回放与新签名重试、失败零 EvidenceRef、
  recomposition 五维 proof_ready、COMMIT-ACK 回读、并发一个赢家、
  非通过封印、双报告离线验签与一一对应绑定、语义层重签篡改拒绝、
  报告/收据/关联因子/公钥/四类账本表篡改拒绝、STARTED_UNCONFIRMED
  恢复、pre-COMMIT/cleanup/锁释放故障保持提交）；
- 独立规格复核：7B4_SPEC_PASS；
- 独立质量复核：7B4_QUALITY_PASS；
- pip check、compileall 和 git diff check：通过；
- OpenWorkProof Docker 容器与卷残留：0。

历史验证窗口曾暴露 schema registry 交叉进程写入和 detached-survivor
pidfile 就绪竞态；本轮又观察到 `team_network_client` 关闭期线程 warning。
最新 required-live 门仍为 2293/2293 通过、0 failed、0 skipped，但这些历史
与 warning 保留在记录中，不把一次最终绿灯改写成“从未出现过不稳定性”。

## 重要边界

上述 Task 7B3a、7B3b Phase 2、7B3c 协调器和 Task 7B4 离线授权链
验证稳定切片已经完成本地实现与独立复核。Task 8A 已新增实时授权
上下文的纯推导与证据/检查点绑定；Task 8B1 已新增纯事前
工具授权；Task 8B2 已新增纯 HumanDecision 授权；Task 8B3 已新增
纯 rollback 事前授权。Task 8A/8B1/8B2/8B3 均尚未进行独立
Acceptor 复核。
当前实现包含
`stage_pending_evidence_group`、`publish_group_no_replace`、
`mark_publication_group_committed`、`recover_evidence_publications`
和 `require_all_publications_committed` 五个 group-aware 基础原语，
`commit_receipt_with_publications` 的 Phase 2 提交原语，以及串联
Phase 1→4 和最终权威读取门的 `complete_receipt_publication`。
`validate_grant_chain` 可以验证签名授权链和 Sidecar 签名的
ResolutionManifest 解析断言，但五输入 API 没有独立读取并重哈希
ResolutionManifest 原始字节。
当前只接入了 `owp.run_tests(test_mode=verifier)` 的首个可调用
handler 协调切片；真实无网 Docker 测试执行器生产 driver 与
MCP 传输服务器、Developer mode 生产入口尚未接入（当前以确定性
fake driver 完成全部协调与恢复切片验证）。当前目标锁与内部 journal 能区分：
只有 `RESERVED` 的崩溃可清理并安全重试；Receipt 已提交但 journal
未清理时可按已提交事实收敛；`STARTED_UNCONFIRMED` 且无 Receipt
时只返回 `RECOVERY_REQUIRED`，不重跑、不补造 Receipt 或扣费事实。
从旧开发快照打开的 ledger 会在目标锁内仅新增这张内部表，
不改变 Receipt、sequence、配额、协议状态或状态版本。
要自动收敛该不确定分支，仍需真实无网执行器提供稳定
execution ID 和可验证启动/结果回执。deny Receipt 与 rollback
生产事务尚未完成；acceptance 生产事务（compose/request/prepare/
commit）已实现并验证。独立结果执行 episode 与五维 recomposition
链已实现并验证（含独立失败收据精确回放与失败后新签名重试），
交付验证执行门仍为 FAIL；deny/rollback 生产事务、真实无网执行器
生产 driver、MCP 传输服务器与 Acceptor 拒绝路径仍为边界。

## 已完成（按任务切片）

- 项目方向与初赛方案设计；
- 协议模型、签名、状态、谓词和 Schema；
- Task 6A 确定性源码、补丁和重放原语；
- Task 7B2a 账本初始化、Root/child Grant 签发与 child Grant 撤销切片；
- Task 7B2b 签名历史额度、single-use、撤销和角色语义回放切片；
- Task 7B2c Manager `start_retry` 原子消费、rework episode 与 committed
  evidence 读取门；
- Task 7B3a group-aware staging、no-replace publication、整组提交、
  崩溃恢复和 committed publication gate；
- Task 7B3a 独立规格和质量复核。
- Task 7B3b Phase 2 Receipt/quota/state/sequence 与 COMMITTING journal
  原子提交，以及权威谓词、文件身份和 commit-truth 复核；
- Task 7B3b 独立规格和质量复核。
- Task 7B3c 单锁串联 stage、commit、publish、mark committed 和最终
  权威读取门，并保留各故障阶段的 receipt/publication 真值；
- Task 7B3c 独立规格和质量复核。
- Task 7B4 将授权因果回放与策略回放拆为单一职责模块，使
  `validate_grant_chain` 成为有界五输入编排器，并完成合法重组链、
  拒绝审计、独立验证新鲜性与失败封存的离线验证；
- Task 7B4 独立规格和质量复核。
- Task 8A 不可变实时授权上下文：规范化有界 Grant/Receipt 前缀，重放
  既有因果与策略，逐字节验证 committed evidence，并将 active patch
  结果绑定到 ReplayCheckpoint 的 candidate commit 与 manifest digest。
- Task 8B1 纯事前工具授权：校验请求签名、参数摘要、300 秒新鲜度、
  角色/工具矩阵、Grant 能力与配额、路径根、人工批准、测试 Profile、
  ReplayCheckpoint、独立执行标识和组合版本；只判定 handler 资格。
- Task 8B2 纯 HumanDecision 授权：验证签名、WorkOrder 与 Maintainer
  身份，精确绑定审批请求、范围、有效期和唯一决策，并允许无需预先
  请求的 Maintainer 终止；只判定决策资格，不落账、不改变状态。
- Task 8B3 纯 rollback 事前授权：验证 Developer 请求签名、Grant、
  300 秒新鲜度、唯一 active patch 目标、ReplayCheckpoint HEAD、
  needs-rework failure episode、角色、能力与配额；不执行 workspace
  回滚、不签 Receipt、不扣减配额。
- Task 13 首个 Verifier `run_tests` 协调切片：锁内复核账本/证据
  快照、事前预留证据槽位、启动单次 handler、Sidecar 签署 Receipt，
  并对正常结果完成四阶段证据发布；已启动的 handler 异常会
  扣减 `tool_calls` 并提交无附件失败 Receipt，事前策略拒绝不启动
  handler；内部执行 journal 已用真实子进程崩溃注入验证
  RESERVED 安全重试、未确认启动阻断与已提交 Receipt 自动收敛；
  旧 ledger 可受锁迁移内部 journal schema，不伪造协议版本步。
- Task 14 六角色信任模型：Acceptor 独立密钥绑定、AcceptanceReceipt
  签名权威迁移、final-acceptance 角色矩阵与 v0.1 schema 重生成。
- Task 15 确定性 CompositionReport 与 `owp.compose_proof` 原子合成。
- Task 16 独立验收事务链：原子 final-acceptance 请求、无密钥
  prepare 草稿与 Acceptor 签名 commit（awaiting_human → accepted）。
- Task 17 `run_tests` 真实无网执行器生产路径：DockerRunTestsExecutor
  驱动 execute_run_tests_production（稳定 execution ID、启动/结果回执、
  STARTED_UNCONFIRMED 恢复，required-live 真实 Docker 执行已验证）。
- Task 18 repo_pipeline 生产级仓库读取-分析管道（本地路径 / GitHub URL
  输入、递归遍历 + 目录过滤 + 语言识别、统一数据模型、可扩展分析层、
  canonical JSON 输出、分级日志与类型化错误；13 测试）。
- Task 19 CLI 与 MCP 传输层（owp 命令：status/run-tests/repo-read；
  MCP stdio 服务器：owp_status/owp_run_tests/owp_repo_read 工具，
  承载 JSON 协议消息转发到协调器）。
- Task 20 AgentTeams 执行接入层（execution_adapter：TeamTask/TeamTaskResult、
  AgentTeamClient 协议 + LocalTeamClient 参考实现、TeamExecutionAdapter
  数据转换/协议适配/状态同步/错误隔离/分级日志，团队→开发者闭环 6 测试）。
- Task 21 真实团队网络客户端（team_network_client：TCP 会话 + token 鉴权 +
  指数退避重试 + 环境配置 + 结构化日志；参考 TeamNetworkService 服务端；
  网络版适配器端到端闭环 6 测试；阿里云 AgentTeams SDK 为治理面 API 且无
  Python 版——执行面网络层按文档化 TCP 协议实现，SDK 接入点保留在适配器）。
- Task 22 交付验证层 M1：真实外部 Acceptor 端到端验证（独立子进程 +
  真实 TCP、隔离/接受/拒绝/冲突/一致/超时/断连/重试，8 测试）。
- Task 23 交付验证层 M2：Rich #4196 五角色 9 步演示证据链（init →
  repo_read → apply_patch → run_tests → compose → 独立 Verifier →
  recompose → 外部 Acceptor 签名 → 离线验签）端到端可复现，5 测试；
  同时修复真实因果缺口：repo_read 之后 apply_patch 的语义父规则
  （composition.py），既有链行为不变。
- Task 24 交付验证层 M3：交付验证签署（冻结 HEAD 14fd7d6、SHA256SUMS
  112 项、Owner/见证人 Ed25519 明文签署、git tag delivery-signoff-2026-08-07）。
- Task 25 交付验证层 M4：赛事材料（8 类材料核对清单 + 质量检查 +
  离线验签说明，docs/delivery-materials-checklist.md）。
- Task 26 rollback 生产事务：execute_rollback（授权 → 执行 → 签名 →
  单锁原子提交 RollbackReceipt，handler journal RESERVED/STARTED
  恢复，6 测试：成功/验证失败/异常 RECOVERY_REQUIRED/拒绝不启动/
  旧 journal 迁移/cleanup 失败收敛）；deny 内建于各收据
  （policy_decision=deny + 同态拒绝收据，见状态机与 policy 回放）。
- Task 27 deny 收据生产入口：produce_deny_receipt（策略拒绝时可选记录
  不可变同态 deny 收据：零配额、零证据、状态不变、直接原子写 receipts
  表；与嵌套 claim 的 nonce 一致保证外收据校验通过；2 测试：同态拒绝
  落账 + 非拒绝决策拒绝）。

## 尚未完成

- 其他 ToolCall handler 与 evidence publication 的调用闭包，
  rollback handler 结果/Receipt 闭包的扩展边界；
- 真实外部 Acceptor 的人类签署与独立环境复现（本地子进程/TCP 验证
  已完成；外部个人复核属线下事件，不由本仓库保证）；
- 正式赛事提交、入围或获奖。

> required-live 最终门历史测量已通过（2293 passed、0 failed、0 skipped，
> 候选库存已为本轮冻结定义闭包生成），不再列入未完成。

## 许可证状态

仓库已采用 Apache License 2.0（见根目录 LICENSE 文件），
版权主体为成都星火领航科技有限公司。

## 项目主体说明

技术 Owner：dengyier
独立 Acceptor：待定（当前不绑定真实个人）
版权主体：成都星火领航科技有限公司

以上角色已经作为项目责任角色记录，但不能据此推断交付验证人类签署、
独立验收已经完成。

## Judgment-to-Action Binding v0.4 实现状态

当前开发分支（codex/judgment-action-binding-v04）已完成 v0.4 协议栈
Task 6–14。全部为本地/分支状态：**未发布、未推送、未合并、未被任何客户
采用，未产生任何付款或结算证据。**

| Task | 内容 | 状态 |
|---|---|---|
| 6 | 执行前原生绑定门（零执行/零配额/零业务输出） | ✅ 已实现 |
| 7 | 确定性 GitHub code-delivery 适配器 | ✅ 已实现 |
| 8 | BindingDecision 组合与验签（外部 trust map） | ✅ 已实现 |
| 9 | 决策账本（append-only + 并发单赢家 + 恢复） | ✅ 已实现 |
| 10 | AuthorityCheckpoint 外部权威链（as-of） | ✅ 已实现 |
| 11 | Acceptance/SettlementReadiness 双门 | ✅ 已实现 |
| 12 | v0.4 离线包导出与诚实隐私视图 | ✅ 已实现 |
| 13 | Python/CLI/只读 MCP 服务契约 | ✅ 已实现 |
| 14 | 注册攻击矩阵 C0+A1–A18 + 4 holdouts + 自营 demo | ✅ 已实现 |

### 未完成（Task 15–16 及发布门）

- 文档与 21 天试点材料（Task 15，进行中）
- revision-bound candidate inventory、required-live 全量、完整便携全量、
  推送/合并/PR（Task 16 与发布门）
- 任何客户验收、付费 SOW、定金、上游采纳：**not_evidenced**

## 真值边界声明

`BOUND`（绑定决定）只表示「行动与记录判断一致」，**不等于**判断正确、
代码无缺陷、客户验收、付款或结算。本协议不产生付款凭证；付款状态必须
来自外部商业证据，未取得前一律 `not_evidenced`。

## Task 16 发布门真值（2026-08-13 fresh）

### 已通过

- 聚焦 v0.4 套件（12 文件）：**334 passed，0 failed**
- 冻结兼容套件（v0.2/v0.3）：**161 passed，0 failed**
- 便携全量：**3032 passed，2 failed，7 skipped**（6 分 52 秒）
  - 2 failed 为预期：`test_current_candidate_inventory_binds_execution_runner` /
    `test_current_candidate_inventory_binds_fixed_test_source`（candidate 尚未重建绑定）
  - 7 skipped：真实 Landlock（仅 Linux）、live Docker 未启用
- 独立只读双审：B1（A17 攻击缺口）、B2（非高风险 checkpoint 虚称 current）已修复并复审 **READY**；修复后相关回归 86 + 277 passed
- 非测试检查：pip check / compileall / git diff --check / Docker 残留：PASS

### 未通过/未执行（如实记录）

- **candidate inventory 未重建**：`OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT`
  （wheelhouse + deb 闭包）在本环境未配置，无法执行 prepare_context.py +
  Buildx + docker load 的完整供应链流程
- **required-live 未执行**：真实 Landlock 仅 Linux；本机 macOS 无法满足
  零 skip
- 分支未推送、未合并、未开 PR（等待 Owner 授权）

### Warning 分类（便携全量）

- macOS pytest `rm_rf` 清理只读/symlink 临时目录告警（既有已知类别）
- 未统计到未处理线程异常（live 门未跑，不声称零）

### 双审发现修复记录

- B1：`validate_v04_acceptance_chain` 增加 manifest↔scope 配对检查；
  A17 重写为 selector 篡改的伪造 scope 真实攻击（SCOPE_CHAIN_MISMATCH）
- B2：非高风险 composer 对 checkpoint 证据 fail-closed（INDETERMINATE missing），
  不再虚称 current

## Task 16 发布门执行更新（2026-08-13，candidate 已绑定）

### 新通过

- **candidate inventory 已构建并绑定**：revision `c3275f4`（allowlist 扩展后
  的实现提交）——`prepare_context.py` 生成 build-contexts、buildx 构建
  execution + trusted-helper 双镜像（linux/arm64，--network none）、
  docker/oci 归档、inventory json + sha256 签名
  （`supply-chain/images/candidates/c3275f4...json`）
- **candidate 绑定门转 GREEN**：`test_current_candidate_inventory_binds_*`
  2 passed；`test_image_supply_chain` 68 passed；candidate 集成套件
  96 passed / 1 failed（下）
- **required-live（容器内 Linux）**：Landlock 探针 15 passed、
  `test_run_tests_runner` 全量 **107 passed 零 skip**、
  `test_sandbox` 全量 **336 passed（含 live Docker 容器）**
- 非测试检查：pip check / compileall / git diff --check / Docker 残留：PASS

### 剩余已知缺口（如实记录）

- `test_candidate_artifact_chain`：本机 Docker 29.5.2 的 buildx/`docker save`
  输出 OCI v1 manifest，而该测试固化期望 docker v2 manifest（历史归档为
  旧工具版本产物）。属**工具版本环境差异**，非协议缺陷；candidate 绑定、
  OCI 归档校验、live 探针均已通过。
- 便携全量的 7 个 skip 已在 live 模式复跑消除（runner/sandbox 零 skip）；
  全量 live 复跑（2654 规模）需 Linux 主机或完整 live 环境，未在本会话执行。
- 分支未推送、未合并到远端（main 已本地合并，origin/main 落后 59 个提交）。

## 最终收口真值（2026-08-13，覆盖前述过期表述）

> 本节为最终状态。上文若与本节冲突，以本节为准：旧表述「Task 15–16 未完成」、
> 「未推送、未合并」「candidate 未重建」「required-live 未执行」以及
> 「candidate 集成套件 96 passed / 1 failed（工具版本差异）」均已被实际结果
> 取代。

### 审查问题修复记录（2026-08-13）

1. **candidate artifact_chain 零失败**：新增 `supply-chain/images/
   convert_docker_archive.py`（OCI→docker-v2 契约转换工具，幂等、原子写入、
   修剪未引用 blob），按测试契约重新生成双归档（docker v2 manifest +
   RepoTags 列表 + 三键 annotations；OCI 保留 platform）。inventory `c3275f4`
   的 local_image_id 更新为 docker v2 manifest digest（execution `4b0b917d` /
   trusted-helper `f93b088f`）。
2. **candidate 两套件零失败**：`test_image_supply_chain` 68 passed +
   `test_candidate_supplychain_integration` 98 passed（含 live Docker）。
3. **required-live 全量**：live 环境下全量 **3056 passed / 0 failed /
   0 skipped**（9m02s；便携 3049 + 7 skip 全部转执行）。严格线程告警以
   pytest 参数 `-W 'error::pytest.PytestUnhandledThreadExceptionWarning'`
   生效——计划已修正原 `PYTHONWARNINGS` 环境变量方式（其无法在 pytest 导入
   前解析 pytest 模块名）。
4. **实施计划修复**：Task 11 Step 1（Create 文件名 + Add acceptance-gate
   RED tests 标题）与 Task 16 Step 1（focused v0.4 suite 标题/代码围栏/
   命令首行）恢复为原始规格；Task 16 Steps 1–10 与 Final Self-Review
   Checklist（14 项，含无 TODO/占位符/未解析类型核验）全部勾选。
5. **分支状态**：`main == origin/main == c5f605a`（已推送）；Task 15 已完成
   并提交；工作树已收口（.DS_Store 忽略，docs/handoffs/ 纳入版本库）。

### 最终门结果

| 门 | 结果 |
|---|---|
| v0.4 聚焦套件 | 334 passed / 0 failed |
| 冻结兼容（v0.2/v0.3） | 161 passed / 0 failed |
| 便携全量 | 3049 passed / 7 skipped / 9 warnings（macOS rm_rf 清理类） |
| **required-live 全量** | **3056 passed / 0 failed / 0 skipped** |
| candidate 两套件 | 68 + 98 passed（零失败，含 live） |
| 独立只读双审 | READY（B1/B2 修复后复审通过） |
| pip check / compileall / diff --check / Docker 残留 | PASS |

诚实边界（不可声称）：无客户采用、无付费 SOW、无定金、无上游采纳
（全部 `not_evidenced`）；pilot 材料见 `docs/pilot/`；仓库仅工程交付，
不构成商业事实。
