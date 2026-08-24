# Human Agency Profile v0.1 夜间联合审查记录

日期：2026-08-24（Asia/Shanghai）

分支：`codex/human-agency-profile-v01`

边界：本记录只证明本地分支实现与本轮测试结果，不等于已合并、已推送、已发布或已被外部采用。

## 已完成

Tasks 1–4 已实现：

1. 三类闭合签名对象：`HumanAgencyProfileV01`、`AgencyProfileTransitionV01`、
   `AgencyAppealV01`；
2. 不以最大时间戳兜底的唯一 current profile 图解析；
3. `WorkOrder ∩ Grant ∩ profile` 三层交集授权与稳定错误码；
4. 三类对象的 append-only SQLite 提交、不可变触发器、COMMIT-ACK exact readback、
   全历史结构校验、整行 canonical 校验与独立 `committed_at`。

关键提交：

- `d70b7bb fix: harden human agency ledger truth`
- `9f79097 docs: record human agency implementation checkpoint`

## 独立验证证据

DeepSeek Harness 先写入敌对测试，RED 为 `14 failed, 22 passed`；修复后
`tests/test_agency_ledger_v01.py` 为 `36 passed`。

Codex 随后独立运行：

```text
tests/test_agency_models_v01.py
tests/test_agency_history_v01.py
tests/test_agency_policy_v01.py
tests/test_agency_ledger_v01.py
tests/test_retraction_receipt_v05.py
tests/test_policy.py
tests/test_mcp_server.py

269 passed in 25.83s
```

同时：

- `python -m pip check`：通过；
- `python -m compileall -q src tests`：退出码 0；
- `git diff --check`：通过；
- 记录时工作树干净。

尚未运行 Task 9 的 candidate 两套件与 required-live 全量门，因此不能声称整仓全量通过。

## Task 5 安全审查结论

原计划的锁外闭包包装器不能直接实现：

- 包装器先持锁再调用现有 executor，会在新的文件描述符上第二次 `flock`，存在自锁死；
- 包装器不持锁或先释放锁再调用 executor，Acceptor 可在 profile 判定与执行器加锁之间提交
  revoke/supersede，形成 TOCTOU；
- 当前只有 repo-read、run-tests、rollback 的事务 executor，没有 `execute_apply_patch`。

推荐的最小可靠方案是：对全新 action（A）在现有 executor 已持有的 target-lock 临界区内，
完成基础授权后、任何 preflight/reservation/handler/receipt 写入前，执行可选的
profile-only authorization callback。先前已 RESERVED / STARTED_UNCONFIRMED action 的
reconciliation/finalization（B）不得针对当前 profile 重新授权，而是重放存储的 request
truth，因此后续 revoke 不追溯；幂等的 bookkeeping/schema/evidence recovery（C）可在本次
请求的 agency 门之前发生，并从“拒绝的新 action 零业务写入”不变量中排除。callback 默认
`None`，保持旧 API 默认语义不变；protected dispatcher 只负责传入延迟加载的 callback，
不在锁外预先解析 history。

`apply_patch` 必须二选一：

1. v0.1 明确只保留 reserved/deny，不宣称 supersede 后可真实执行；
2. 另立任务实现具备相同 lock/reservation/publication/recovery 语义的
   `execute_apply_patch`。

### run-tests 混合模式 recovery 绑定

run-tests journal 新增向后兼容的 Sidecar 签名 agency binding，防止 legacy
`agency_authorize=None` 的未受保护预约被后续受保护 call 恢复并“洗白”为受保护结果：

- legacy 预约存 `agency_binding=NULL` 且 `agency_binding_json=NULL`，digest 沿用
  `openworkproof/authorization-ledger-prefix/v0.1`；受保护预约在 `_enforce` 成功后存固定
  exact marker `openworkproof/handler-agency-bound/v0.1`，并把 canonical envelope 写入
  `agency_binding_json`，digest 换为域分离的
  `openworkproof/authorization-ledger-prefix-agency/v0.1`（仅 defense-in-depth）。envelope 由
  execute_run_tests 已验证的 Ed25519 Sidecar 私钥在内置签名域
  `openworkproof/handler-agency-binding/v0.1`（仅限 v0.1）签名，至少绑定 domain/claim type、
  `work_order_digest`、`execution_id`、`request_digest`、`authorization_prefix_digest`、agency
  marker、controller/signer key id 与 `reserved_at`；load/recovery 按权威 WorkOrder 的精确
  Sidecar KeyBinding 校验，身份不匹配、非 canonical/重复键/超限 JSON、错误角色或密钥、
  digest/signature 无效一律 fail closed（RECOVERY_REQUIRED）。
- recovery 不针对当前 profile 重新授权存储请求：受保护 caller 恢复 agency-bound 存储 action
  时正常 finalize/return 且不重复调用 callback；受保护 caller 恢复 legacy-unbound 的
  CLOSED_RESULT/ABSENT 时，先发布 receipt、cleanup 并删除 journal，再抛
  `HandlerCoordinationError('AGENCY_UNBOUND_RECOVERY')`；legacy caller 可恢复任一类。
- schema 迁移：空 predecessor 按原样 drop/rebuild；非空的 V3（紧邻前一个可信无标记 schema）
  行原子重建为 unbound 并保留；V4（紧邻前一个 unsigned-marker schema）非空 NULL-marker 行
  原子重建为 unbound 并保留；V4 非空非 NULL-marker 行不可信，fail closed 且绝不伪造签名；
  V2 及更旧 schema 的非空行保持 fail closed。
- 威胁边界：agency binding 是 executor 锁内 recovery 协调的内部控制，ActionReceipt 本身不
  携带 Agency 证明；不向外宣称受保护结果。

## Task 5 Step 4 审计收口（Owner 威胁模型边界）

2026-08-24 最终审计收口确定 `execute_apply_patch` 的威胁模型边界：

- receipt 只认证不可变 Git candidate commit 与由 patch evidence 派生的确定性 manifest
  （内容寻址证据），不承诺可变 worktree 在验证后永久保持干净。
- handler 是受信任的同步进程内适配器，可能失败或返回伪造/错误数据；敌意 handler 派生
  延迟子进程、或同用户/root 的带外进程改写/删除 workspace/Git store，都在本 coordinator
  的隔离边界之外——不声称能阻止敌意 OS 进程。
- 后续动作必须重新校验当前 candidate checkpoint，并在 drift 时 fail closed：下一条
  candidate 操作在 `_verify_candidate_checkpoint` 处先于任何 patch 应用拒绝。本切片不
  添加投机性的 workspace lock 或 sandboxing。

P2 测试证据补齐与 drift 证明：

- `test_execute_apply_patch_precommit_insert_failure_rolls_back_exactly`：monkeypatch
  `evidence._insert_receipt_and_publication_group` 先调用真实 insert、再于 SQLite COMMIT
  前抛 `sqlite3.OperationalError`；断言 receipt/receipt_parents/evidence_publications/
  sequence/state/grant-event 业务行精确回滚（`_business_tables` 与逐表计数均等于 before），
  handler journal 保持 STARTED_UNCONFIRMED，真实 workspace 已含不可变 patch，孤儿 pending
  evidence 由 `recover_evidence_publications` 幂等清理；与 staging-entry 失败明确区分。
- `test_execute_apply_patch_rejects_workspace_drift_before_next_candidate_operation`：
  成功 receipt 后带外写漂移 worktree，下一条 candidate 操作
  (`apply_patch_in_candidate_workspace`) 在 `_verify_candidate_checkpoint` 处先于任何
  patch 应用拒绝 drift，认证 commit 不被改写。

本轮 fresh 门（控制器 fresh）：apply-patch transaction `18 passed`；agency end-to-end
`28 passed`；receipt_chain publication atomicity `413 passed`；mcp/policy/repo_tools
focused `512 passed, 4 skipped`；`pip check`/`compileall`/`git diff --check` PASS。

## Task 5 Step 5 审计记录（protected dispatcher + 完整状态链）

2026-08-24 实现最小 protected dispatcher `mcp_server.dispatch_protected_agent_action`
（commit `feat: dispatch protected agent actions`），只按签名 `request.tool_name` 路由四
工具，新增 typed keyword bundle，不持锁、不预加载 history、不做 base/agency 授权；延迟
`agency_authorize` callback 只捕获 immutable ledger path/context/request，在 executor 已
持有 target lock 的临界区内才加载 history 并调用 `authorize_agency_profile_layer`。
dispatcher 不接收独立 `tool_name`/`now`，未知工具/错配 bundle 均 fail closed。

新增 12 条测试：四工具路由、未知工具、bundle 错配/缺失/多余、v0.1 与 v0.4、非
AgentRequest 拒绝、apply-patch 完整状态链（repo-read allowed → apply-patch reserved →
appeal 仍 denied → supersede 真实 patch allowed → revoke 后 resolved status=revoked）、
revoke 后四工具全部 `AGENCY_PROFILE_REQUIRED` 零 handler/driver 零写入、确定性
history-loader-在锁内 proof（非阻塞 flock probe，无 sleep）。

本轮 fresh 门（控制器 fresh）：agency end-to-end `40 passed`；agency-policy/policy/
repo-read/apply-patch `144 passed`；mcp/binding/recomposition `126 passed`；
`pip check`/`compileall`/`git diff --check` PASS。Task 5 仍不标记 READY：dispatcher 与
完整状态链尚未经独立 review；全量 inventory boundary 仍需 Task 9 重建。

## Task 6 真实性审查结论

设计要求 bundle 包含受 profile 约束的 request/decision/receipt，但当前协议存在两个事实：

- reserved deny 按规格零 receipt 写入，离线包无法证明“某次请求确实被拒绝”；
- 现有 ActionReceipt 没有 `agency_profile_id` 绑定，离线包无法证明“某次执行发生在指定
  profile 下”。

因此现阶段可真实实现的是 **agency boundary bundle**：证明 WorkOrder、公钥绑定、profiles、
transitions、appeals 以及某一冻结评估时刻的边界状态；它不能被描述为一次执行的 enforcement
proof。若要后者，需要新签名拒绝对象或带 profile 绑定的新 receipt schema，属于后续协议版本。

## Owner 决策（四项选择已收口）

2026-08-24 Owner 已在实施计划 Task 6 头部给出决策，原“待确认的四项选择”全部收口：

1. v0.1 bundle 采用 **authorization boundary bundle**，不是某次调用的 enforcement proof；
2. 已新增真实 `execute_apply_patch`（Task 5 Step 4 完成），不再保持 reserved/deny 占位；
3. 接受 exporter 在 target lock 内冻结、可校验但非时间戳机构背书的 `evaluated_at`；
4. `current_status` 增加 `expired`。

四项确认前“Tasks 5–6 保持未完成”的表述已过时：Task 5 已实现并经独立 review；Task 6
（导出最小离线 human agency boundary bundle）已实现，见实施计划 Task 6 各 Step 的完成
证据。这是协议真实性边界，不是测试或编码困难；本记录不声明已合并、已推送或已被外部采用。

## Task 6 独立审查 P1/P2 修复（Sidecar snapshot attestation）

独立审查发现 P1：原 `AgencyBundleManifestV01` 未签名，攻击者可无钥删除 revoke/supersede
后缀并重写 `evaluated_at`/`current_status`，使已撤销 bundle 被重放为 active。Owner 决策采用
WorkOrder 内 Sidecar key binding 作为自包含 snapshot attestation：

- `AgencyBundleManifestV01` 改为 `SignedProtocolModel`，`_signed_domain="manifest"` v0.1，
  含 digest/signature_alg/signer_key_id/signature；签名覆盖 `work_order_digest`、
  `evaluated_at`、`current_status`、`current_profile_id`、`boundary` 与全部 `entries`
  （path/SHA-256/size），不加无效自哈希。
- `export_agency_bundle` 必须显式接收 `sidecar_private_key: Ed25519PrivateKey`（不默认、不读
  环境）；`compose_agency_manifest` 亦必须显式签名；导出前显式校验私钥匹配 WorkOrder Sidecar
  binding，错误角色 fail closed。
- 验证器加载并验证 WorkOrder identity bindings 后，只接受 Sidecar role binding 并
  `verify_payload("manifest", ...)`；错误角色/伪签名/篡改 manifest/截断合法 supersede 链/
  删除 revoke 后缀/重写 evaluated_at+status 均 fail closed。验证器仍不接受 `now`、不访问
  ledger/network/环境私钥/系统时钟；verify.sh/CLI 只用于验证、不含私钥。
- 补 RED→GREEN 回归：wrong role signer/export 拒绝、signed p1→p2 bundle 删后缀无钥重建拒绝、
  revoked 删 revoke 回滚拒绝、evaluated_at/status coherent rewrite 拒绝、manifest 签名字节/
  签名者篡改拒绝、extra empty directory 拒绝（保留）、verifier monkeypatch ledger/system
  time/network/private-key access 纯净性证明。
- 边界不变：Sidecar 签名固定的是“声称的 `evaluated_at`”，不证明真实世界时间，仍非 TSA；
  更早但签名有效的 bundle 仍是历史快照，消费方须自行执行新鲜度策略，不能把它当作抗重放的
  当前状态证明。
  本记录不声明已合并、已推送或已被外部采用。
