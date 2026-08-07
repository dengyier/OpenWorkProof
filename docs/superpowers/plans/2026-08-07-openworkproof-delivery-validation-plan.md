# OpenWorkProof Delivery Validation Implementation Plan

Date: 2026-08-07

Branch: `codex/acceptor-rejection` (delivery-validation phase)

Status: Draft plan — requires user approval before execution

## 1. 总体框架

交付验证层四大环节按依赖顺序推进：

```text
环节 1 真实外部 Acceptor（验收权威真实验证）
   ↓
环节 2 Rich #4196 演示（完整五角色工作流，用环节 1 的真实 Acceptor）
   ↓
环节 3 交付验证签署（材料冻结 + 人类签署 + 存档）
   ↓
环节 4 赛事材料（完整/规范/可复现，含 1-3 的产出物）
```

前置基线（当前已就绪，见 status.md）：核心协议层 ~100%、真实 Docker 执行器、
repo 管道、CLI/MCP 传输、AgentTeams 执行接入层、双终态验收事务（含拒绝路径）、
离线验签、候选库存（多 revision 不可变）。

## 2. 环节 1：真实外部 Acceptor

### 2.1 目标

让**独立于本系统的真实个人/工具**充当 Acceptor，在隔离环境用其自身私钥对
`prepare_acceptance` 草稿（无密钥的盲文摘要）签名，提交 `acceptance-receipt`
并验证 `accepted` 终态；同时验证拒绝路径（`rejection`）。

### 2.2 接入方式

1. 协议已支持：`request_acceptance_transaction` → `prepare_acceptance`
   （返回不含签名、可外部签名的规范草稿）→ 外部 Acceptor 私钥签名 →
   `commit_acceptance`（仅接受 WorkOrder 绑定 Acceptor 密钥）。
2. 外部环境：独立机器/容器，仅获得（a）WorkOrder 绑定公钥、（b）
   `prepare_acceptance` 草稿 JSON、（c）签名工具（Ed25519）；
   不接触系统私钥、不接触账本写权限。
3. 传输：草稿经 CLI/MCP 导出为 JSON 文件，签名结果 JSON 回传。

### 2.3 验证流程（端到端脚本）

| 步骤 | 操作 | 预期 |
|---|---|---|
| 1 | 构造 proof_ready WorkOrder（五维闭环） | `proof_ready` 状态 |
| 2 | `request_acceptance_transaction` | `awaiting_human` + request 收据 |
| 3 | `prepare_acceptance` 导出草稿 | 无密钥、字段完整、digest 可离线重算 |
| 4 | 外部环境独立重哈希 + 签名 | 签名有效、rejected_at/ accepted_at 合规 |
| 5 | `commit_acceptance`（签名收据） | `accepted` 终态、收据入账 |
| 6 | 外部拒绝路径（可选） | `rejected` 终态、互斥生效 |
| 7 | `verify_acceptance_bundle` 离线复核 | 双路径验签通过 |

### 2.4 验收标准

- 签名者 = WorkOrder 绑定 Acceptor 公钥（signer_key_id 匹配）；
- 时间窗（300s 新鲜度、request 有效期内、deadline 前）；
- 证据快照/报告 digest/因果根精确绑定；
- accepted 与 rejected 互斥（同一 request 二选一）；
- 离线复核（`verify_acceptance_bundle`）在无系统访问下通过；
- 拒绝路径独立验证（rejection 收据绑定 + 终态）。

### 2.5 兼容性与安全性

- 密钥隔离：外部 Acceptor 私钥不出其环境；系统侧只有公钥绑定；
- 草稿无密钥：`prepare_acceptance` 不含签名材料，可安全分发；
- 签名验证：`commit_acceptance`/`validate_acceptance_bindings` 全量校验；
- 审计：收据不可变入账，篡改任何字段离线复核即拒绝。

### 2.6 所需资源

- 一台隔离环境（可为本机子进程/容器模拟，最终真实个人复核）；
- Acceptor Ed25519 密钥对（生成后公钥绑定进 WorkOrder）；
- CLI/MCP 传输层（草稿导出/回传）。

## 3. 环节 2：Rich #4196 演示

### 3.1 目标

基于真实开源 Issue [Textualize/Rich #4196](https://github.com/Textualize/rich/issues/4196)
（固定上游提交 `9d8f9a372cc5916fd4781fec207ced7ddac2f08f`）演示完整五角色
工作流，产出可复现的证据链。

### 3.2 演示场景与步骤

| 步骤 | 操作 | 预期结果 |
|---|---|---|
| 1 | 初始化 WorkOrder（固定上游 commit + 五角色绑定） | `running`，root grant 激活 |
| 2 | Developer `repo_read`（管道读取候选文件） | repo_read 收据 + output_digest |
| 3 | Developer `apply_patch`（修复 #4196 的补丁） | patch 收据 + active patch |
| 4 | Developer `run_tests`（developer 模式） | 测试收据 |
| 5 | Manager 首次 `compose_proof` | 首份报告（evidence_incomplete） |
| 6 | 独立 Verifier `run_tests`（新鲜上下文） | 独立结果收据 |
| 7 | Manager `recompose_proof`（绑定首报告 digest） | 第二份报告 → `proof_ready` |
| 8 | `request_acceptance` + 外部 Acceptor 签名 + commit | `accepted` 终态 |
| 9 | 导出证据包 + 离线验签 | 第三方可复核 |

### 3.3 预期结果

- 每步收据入账、状态迁移符合状态机；
- 首份报告不可变（evidence_incomplete），独立结果 + recomposition 后
  `proof_ready`；
- 完整链（9 步）可在 CLI/MCP 上重放；离线 bundle 验签通过。

### 3.4 准备工作与环境配置

- 交付验证环境（`/Users/molin/Project/openWorkProof-delivery`）+ 候选镜像 + wheelhouse；
- 固定上游 Rich 提交 checkout；演示脚本（Python/CLI 顺序调用）；
- Acceptor 密钥（环节 1 产出）；
- 演示记录（每步收据 digest + 状态快照）。

## 4. 环节 3：交付验证签署

### 4.1 目标

对冻结交付物做人类签署与存档，确保材料在签署后不可变、可追溯。

### 4.2 签署流程

1. **冻结**：环节 1-2 产出物 + 代码/文档/测试报告进入冻结清单；
2. **哈希**：逐文件 SHA-256，生成 `SHA256SUMS`（不可变锚点）；
3. **签署**：技术 Owner（dengyier）与独立见证人对清单签名（Ed25519/明文签署）；
4. **存档**：签名单 + 哈希清单 + 时间戳存入 `docs/delivery-signoff/`（版本化提交）。

### 4.3 所需材料清单

- 源码（HEAD 提交 SHA）、specs/plans、README/status；
- 全量测试报告（required-live 计数 + 退出码）；
- 演示证据链（环节 2）、Acceptor 验证记录（环节 1）；
- 许可证（Apache-2.0）、候选库存 digest 清单。

### 4.4 角色与职责

| 角色 | 职责 |
|---|---|
| 技术 Owner（dengyier） | 冻结、哈希、签署、存档 |
| 独立见证人 | 复核清单、联署 |
| 独立 Acceptor | 环节 1 验收签署（如参与交付验证签署则联署） |

### 4.5 验证与存档机制

- 存档后 `git tag` 冻结点（如 `delivery-signoff-2026-08-07`）；
- 哈希清单复核脚本（重算比对）；
- 存档目录只读约定 + 提交记录可追溯。

## 5. 环节 4：赛事材料

### 5.1 目标

准备并验证全部赛事提交材料，内容完整、格式规范、可复现。

### 5.2 材料清单（初稿）

| 类别 | 材料 | 状态 |
|---|---|---|
| 项目说明 | README / 30 秒理解 / 市场定位 | 已有，待最终审校 |
| 协议文档 | specs（4 份设计 + 实施）、schema、离线验签说明 | 已有 |
| 代码 | 源码（HEAD）、requirements-lock、候选库存 | 已有 |
| 验证 | 全量测试报告、focused/candidate/full 计数 | 已有，本地计数已更新；required-live 最终数待候选库存对齐 HEAD 后复跑 |
| 演示 | 环节 2 证据链 + 记录 | ✅ 已完成（M2，test_delivery_m2 + rich-4196-demo-log） |
| 签署 | 环节 3 交付验证签名单 + 哈希 | ✅ 已完成（M3，docs/delivery-signoff/ + tag） |
| 法律 | Apache-2.0 LICENSE、版权主体声明 | 已有 |
| 补充 | 路线图/边界声明、已知限制 | 已有 |

### 5.3 质量检查标准（Checklist）

- 完整性：清单逐项存在且为最新版本；
- 规范性：Markdown/JSON/SQLite 格式校验、无真实姓名泄漏（项目要求）；
- 可复现性：`git clone` + lock 安装 + `pytest -q`（required-live）可复跑；
- 一致性：README/status 计数与最终门结果一致；
- 边界诚实：不宣称"独立验收完成"（本地 recomposition 非外部人类验收）。

### 5.4 所需资源

- 最终门结果（full required-live 最终数）；
- 环节 1-3 产出物；
- 材料清单核对脚本（可选）。

## 6. 执行顺序与里程碑

```text
M1 环节 1 外部 Acceptor 端到端验证通过（含拒绝路径）      [可本地闭环]
M2 环节 2 演示证据链产出 + 离线复核                       [可本地闭环]
M3 环节 3 交付验证冻结/签署/存档（tag）                    [需 Owner 参与]
M4 环节 4 材料清单齐备 + 质量检查通过 + 最终门复跑        [交付]
```

## 7. 边界与诚实声明

- 真实外部 Acceptor 的"独立个人复核"无法由本仓库单方证明——本计划提供
  协议/工具/流程使外部复核可执行，实际外部个人签署属线下事件；
- 交付验证签署与赛事结果不由本仓库保证，仅提供完整可交付材料。
