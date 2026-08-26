# OpenWorkProof for DeepSeek Harness V0.1 交接

日期：2026-08-26（Asia/Shanghai）

边界：本文只记录本地实现、提交、打包与验证事实，不表示已合并、已推送、已发布、已被
DeepSeek 官方认可、已在外部环境复现或已有用户采用。

## 仓库与产物

### OpenWorkProof Core

- 路径：`/Users/molin/Project/openWorkProof/.worktrees/deepseek-harness-plugin-v01`
- 分支：`codex/deepseek-harness-plugin-v01`
- 实现 revision：`ca2d36692aa74bd797743987ef553cdc3415c01e`
- candidate inventory commit：`a9e67cc`
- 远端：`origin = git@github.com:dengyier/OpenWorkProof.git`
- 本地候选版本：`1.4.0`，未发布
- wheel：`openworkproof-1.4.0-py3-none-any.whl`
- wheel SHA-256：`adbddba3fa99d4d82d41638fb63db1eb5a7f0809d8529eef48d5dea0d1d7bb75`
- sdist SHA-256：`a710f3cb827d2194993e675878eb10768fde3aed1d06698343a020b08bcdca04`

### DeepSeek Harness 插件

- 路径：`/Users/molin/Project/openworkproof-dsh-plugin`
- 分支：`main`
- HEAD：`f8d1ea94ed1008d4aefbb7de71a640f5bfa2e338`
- 远端：未配置
- 插件版本：`0.1.0`，未发布
- 精确兼容宿主：`DeepSeek Harness 0.1.1-rc.2`
- tarball：`openworkproof-dsh-plugin-0.1.0.tgz`
- tarball SHA-256：`8c48b3cba4333b024b284dca0704e82ae6f9471edc1cb278d95990d02c7ff49b`
- 最终预检环境：Node `v23.11.0`、Python `3.12.13`、OpenWorkProof `1.4.0`

## 实现事实

- `designed`：完成，V0.1 只覆盖单仓库、串行 patch/test、Audit/Enforce 两模式。
- `implemented`：完成，包含 Cordis 插件、JSONL bridge、事前授权、单调最终 guard、
  闭合 patch/test 工具、观察记录、独立 Git 回读、验收草稿和交付导出协议面。
- `tested`：本地聚焦、插件、打包、live preflight、candidate 与 required-live 均通过；
  两份独立只读审查与第二台环境复现未完成。
- `committed`：两个本地仓库均已提交实现；本交接与计划收口提交除外。
- `packaged`：完成本地 wheel、sdist、插件 tarball；没有发布。
- `merged`：未执行。
- `pushed`：未执行。
- `published`：PyPI/npm/插件市场均未执行。
- `installed in another environment`：未证明；临时 clean profile 属同一本机。
- `externally reproduced`：`not_evidenced`。
- `used`：只有本地确定性夹具，真实用户使用 `not_evidenced`。
- `adopted`：`not_evidenced`。

## 验证记录

- Core DSH + patch/rollback 聚焦：`388 passed / 4 environment-gated skipped`。
- Task 13 精确 DSH 聚焦门：`38 passed`。
- 排除 `test_candidate_supplychain_integration.py` 与 `test_image_supply_chain.py` 后的整仓
  回归：`4119 passed / 7 environment-gated skipped`（635.20s）。7 项分别来自未要求真实
  AgentTeams、非 Linux Landlock 和未提供 live Docker 镜像。
- 插件：`30 passed`；typecheck、build 通过。
- 新不可变 candidate inventory：
  `supply-chain/images/candidates/ca2d36692aa74bd797743987ef553cdc3415c01e.json`
  （commit `a9e67cc`）；四个 archive、`SHA256SUMS`、revision 命名库存副本与 sidecar
  均在 `/Users/molin/Project/openWorkProof-delivery/oci/ca2d36692aa74bd797743987ef553cdc3415c01e/`。
- candidate 两套件（artifact root + `OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1`）：
  `184 passed / 0 failed / 0 skipped`（919.21s，退出码 0）。
- required-live 全量（candidate artifact root + 全限定 execution RepoDigest + 严格线程告警）：
  `4309 passed / 0 failed / 1 skipped`（1643.91s，退出码 0）；唯一 skip 为未设置
  `OPENWORKPROOF_AGENTTEAMS_REQUIRED` 时的 `live AgentTeams not required`。
- 打包预检：PASS；确认精确 profile 装载、Enforce 阻断原生 `write/edit/bash`、授权令牌
  单次消费、闭合 action payload、真实 OWP 交付夹具、离线篡改拒绝。
- 全新 venv 安装 wheel 后，`owp dsh-bridge --help` 与版本 `1.4.0` 通过。
- `pip check`、`compileall src tests examples`、`git diff --check`：PASS。
- 插件 tarball 仅含构建 JS、类型声明、patch/profile、双语 README、LICENSE、SECURITY 与
  package metadata；没有 fixture、source map、私钥或秘密材料。

## 尚未闭环的发布门

1. 计划要求的两份独立只读审查尚未取得。当前只有两轮内部自审。
2. `owp dsh-bridge --stdio` 默认没有面向任意仓库的生产 handler assembler；通用 case
   初始化、独立 Verifier 服务和外部 Acceptor 工作流仍由集成方提供。因此当前是开发者
   预览与确定性参考闭环，不是零配置生产产品。
3. 第二台机器外部复现、插件远端、npm/PyPI 发布、插件市场上架和真实用户采用均未取证。

## 内部审查结论

### 规格与第一性原理审查

已确认 V0.1 的最小因果链为：授权在执行前、原生后果工具在 Enforce 中被阻断、patch 与
冻结测试绑定同一 case、Verifier 通过独立 Git 视图回读、Acceptor 私钥不进入 Harness、
导出包可离线验证。没有发现需要扩大 V0.1 范围的新问题。通用 runtime assembler 缺口是
公开限制，也是进入公开市场前最重要的产品化工作。

### 安全与产物审查

已确认 Manager、Verifier、Acceptor 私钥不在 case/插件/导出包中；决策 token 只在内存中
单次使用；重复/错配/过期状态 fail closed；Agent 没有验收签名面；打包内容没有秘密或
本机路径 source map。Bridge 子进程继承宿主环境，因此文档明确禁止把权威私钥放入
Harness 环境变量。该内部审查不替代独立安全复审。

## 外部事实边界

```yaml
customer_adoption: not_evidenced
payment: not_evidenced
production_use: not_evidenced
organizational_verifier_independence: not_evidenced
deepseek_endorsement: not_evidenced
npm_publication: not_evidenced
pypi_1_4_0_publication: not_evidenced
marketplace_listing: not_evidenced
external_reproduction: not_evidenced
```

## 后续选择（互不蕴含）

1. 保持两个仓库本地，先完成独立双审；
2. 补通用 case/runtime assembler，再做第二台机器外部复现；
3. 独立决定是否本地合并 core、创建/推送插件远端；
4. npm、PyPI、插件市场发布与社区公告必须另行授权。
