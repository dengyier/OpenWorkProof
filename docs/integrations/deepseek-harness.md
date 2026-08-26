# OpenWorkProof for DeepSeek Harness V0.1

> 为 DeepSeek Harness 的代码变更增加事前授权、执行证据、独立复核与人工验收。

本文对应本地候选 `OpenWorkProof 1.4.0`、插件 `0.1.0` 与
`DeepSeek Harness 0.1.1-rc.2`。三者目前组成开发者预览，不是已发布的兼容承诺。

## 一句话边界

Audit emits ObservationRecord. Enforce denies native write/edit/bash.

Audit 只记录适配器看见的事实，不能事后把未授权动作升级成 ActionReceipt。Enforce
要求每次 OWP 变更先取得与执行身份精确绑定的一次性决策令牌，并由单调最终 guard 阻断
原生 `write`、`edit` 和不受限 `bash`。

```text
VERIFIED != ACCEPTED != PAID/SETTLED/LEGAL AUDIT/ADOPTION
```

Manager and Acceptor private keys remain outside Harness. Verifier 私钥也由外部验证进程
持有，不进入插件或 Python bridge。

## 它解决什么

对一个冻结的代码变更，适配器把以下事实连成一条可复核链：

```text
WorkOrder / CapabilityGrant
        -> pre-execution PolicyDecision
        -> OWP-owned patch and frozen tests
        -> ActionReceipt and durable event correlation
        -> independent Git readback and test rerun
        -> external Acceptor decision
        -> offline-verifiable delivery export
```

它不判断隐藏推理，不证明未观察到的副作用，不保证冻结的业务标准本身正确，也不替人
接受交付。

## 兼容性

| 组件 | 本地候选 | 当前证据 |
|---|---:|---|
| DeepSeek Harness | `0.1.1-rc.2` | 精确版本 profile 安装、配置组合与 guard 预检 |
| OpenWorkProof Core | `1.4.0` | 本地源码候选，真实协议夹具闭环 |
| DSH plugin | `0.1.0` | 本地 tarball，尚未发布 npm |
| Node.js | `v23.11.0` | 本地预检环境，不是最低兼容范围 |
| Python | `3.12.13` | 本地预检环境；Core 仍以项目元数据为准 |

由于 DeepSeek Harness 本身仍处于 Developer Preview，任何升级都必须重新跑兼容性和
打包预检，不能只放宽版本范围。

## 安装本地候选

前提：本机已有 `pnpm`、精确版本 DSH、可运行的 `owp`，并持有本地打包产物。

```bash
cd /path/to/openworkproof-dsh-plugin
pnpm install --frozen-lockfile
pnpm build
pnpm pack --pack-destination dist

dsh plugin --profile owp-preview add \
  /absolute/path/openworkproof-dsh-plugin-0.1.0.tgz
dsh --profile owp-preview --dump-config
```

默认 bundle 是 Audit。Enforce 必须显式叠加 profile，并指向一个已经冻结、权限为私有、
且不含 Manager、Verifier、Acceptor 私钥的 case 目录：

```bash
export OWP_CASE_DIRECTORY=/absolute/path/to/private-case
dsh --profile owp-preview \
  --patch "$DSH_HOME/profiles/owp-preview/node_modules/@openworkproof/dsh-plugin/profiles/owp-verified.patch.yml"
```

不要把私钥放入环境变量、命令行、仓库、session 日志或导出包。

## 五分钟开发者夹具

该夹具验证发布物的连接面以及一条真实 OWP 协议链；它不是客户项目初始化器。

```bash
cd /path/to/openworkproof-dsh-plugin
pnpm test
pnpm typecheck
pnpm build
pnpm pack --pack-destination dist
node scripts/live-preflight.mjs \
  dist/openworkproof-dsh-plugin-0.1.0.tgz
```

预期 `PASS` 并列出：packed profile loaded、native write/edit/bash denied、单调授权、
闭合 action payload、真实 OWP delivery fixture、offline tamper rejected。该脚本在临时
DSH_HOME 安装 tarball，结束后删除临时 profile；不会发布包或联系外部服务。

## 验证、外部验收与离线复核

case 打开后，先用 `/owp-evidence` 查看证据是否已形成因果关联，再由
`/owp-verify` 把精确的补丁 ActionReceipt 交给 Core 独立回读。只有 bridge 返回
`VERIFIED`，插件才显示“等待人工验收”；`UNKNOWN` 或 `REFUTED` 不会被升级。

```text
/owp-status
/owp-evidence
/owp-verify
/owp-export
```

`VERIFIED` 后，Agent 只能请求无签名草稿。Acceptor 在 Harness 外审阅并签名，再提交
Acceptance binding。插件不生成、保存或调用 Acceptor 私钥。

```bash
owp dsh-case acceptance-draft CASE_DIR --output acceptance-draft.json
# 外部 Acceptor 独立签名并按集成流程提交
owp dsh-case export CASE_DIR --output-directory PUBLIC_DELIVERY_DIR
# 插件 /owp-export 生成的完整离线证据包：
owp audit-replay CUSTOMER_PRIVATE_DELIVERY_DIR
```

`owp dsh-case export` 的 public 包和插件 `/owp-export` 的 customer-private 包是两种
明确不同的导出。后者保留完整离线回放所需材料，并使用 `owp audit-replay`。导出后修改
任何受 manifest 约束的文件，复核必须失败。

## 文件、进程与网络行为

插件会：

- 读取已声明的 case 目录、工具名称、闭合参数摘要和 Harness 事件标识；
- 启动本地 `owp dsh-bridge --stdio` 子进程；
- 通过 JSONL 与 bridge 通信，stdout 只承载协议，stderr 只承载诊断；
- 将签名 ObservationRecord 写入 case 的 evidence root；
- 在 Enforce 中只把短期、一次性决策令牌保存在内存。

插件不会：

- 读取或保存 Manager、Verifier、Acceptor 私钥；
- 收集隐藏推理、任意 shell argv、环境变量全量或仓库外文件；
- 自行发送遥测或访问 OpenWorkProof 服务；
- 托管资金、执行付款或代表客户验收。

DeepSeek Harness 自身及用户安装的其他插件可能有独立网络或遥测行为，应分别审阅其
配置和隐私政策。

## 证据保留与卸载

session 事件、ledger、evidence root 和已导出 delivery case 是不同证据层。卸载插件
不会自动删除它们。需要保留争议复核能力时，应按组织策略保存账本、证据包和公开密钥；
删除前先验证已归档导出。

```bash
dsh plugin --profile owp-preview remove @openworkproof/dsh-plugin
```

卸载只移除 profile 依赖，不撤销既有签名对象，也不删除 case、ledger 或导出物。

## 已知限制

- V0.1 只支持单仓库、串行的 `owp_apply_patch` 与 `owp_run_tests`；
- Codex、ChatGPT、Claude Code 是未来适配目标，不是当前支持声明；
- 通用 case 初始化、组织级密钥托管、独立 Verifier 服务与外部 Acceptor 流程由集成方
  提供；本仓库夹具不等于零配置生产部署；
- Audit 无法证明未经过 Harness 工具管线的副作用；
- 角色密钥不同不自动证明组织独立；
- 本地预检、GitHub 代码和测试数量均不证明客户采用、付款、生产效果或 DeepSeek 背书。

```yaml
customer_adoption: not_evidenced
deepseek_endorsement: not_evidenced
npm_publication: not_evidenced
external_reproduction: not_evidenced
```

## 安全报告

安全问题请使用仓库的
[GitHub Private Security Advisory](https://github.com/dengyier/OpenWorkProof/security/advisories/new)，
不要在公开 Issue 中附带私钥、客户仓库、账本或未脱敏证据。
