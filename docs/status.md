# OpenWorkProof 当前状态与边界

> 本文档是项目实现状态的权威记录。README 只保留概览，
> 「已经完成什么」和「尚未完成什么」的完整清单以本文为准。

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
