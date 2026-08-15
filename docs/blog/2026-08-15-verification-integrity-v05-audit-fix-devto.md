---
title: "独立总审驱动的修复：OpenWorkProof v0.5 验证完整性的七个批次"
published: false
description: "一次外部独立总审发现 2 个 Critical 与 5 个 Important 缺陷，我们用攻击测试先行、最小修复、逐批双审的方式全部闭环，并用不可变候选库存与 required-live 全量门重新冻结发布。"
tags: security, python, opensource, testing
---

# 独立总审驱动的修复：OpenWorkProof v0.5 验证完整性的七个批次

> 仓库：[github.com/dengyier/OpenWorkProof](https://github.com/dengyier/OpenWorkProof)
> 本次更新：`af00586..39369db`（15 个本地提交，最终候选库存 `d460c876a7f3…`）

## TL;DR

OpenWorkProof v0.5（Verification Integrity）在“验证了哪些文件”之外，把**选择前的合格人口（eligible population）**和**负向控制失败的原因（negative control failure signature）**一并冻结进签名协议。在上一轮交付之后，我们请外部做了独立总审，得到 **2 个 Critical + 5 个 Important + 若干 Minor**。这篇记录我们如何用“先写攻击测试记 RED、再做最小修复、逐批独立双审”的方式全部闭环，并用不可变候选库存重新跑完五道门——包括一次 **3456 passed / 0 failed / 0 skipped / 零 warning** 的 required-live 全量门。

## 背景：v0.5 在证明什么

v0.3 证明“声明范围与观察范围精确一致”。但它测不到两类盲区：

1. **人口盲区**：执行引擎能看到多个合格测试，选择器却选出了零个。运行本身正常结束，旧协议会把它当成绿灯。
2. **负控腐化**：注册的变异体确实失败了，但失败原因（错误码 / predicate 签名）与注册签名不一致——“碰巧失败”不等于“按预期失败”。

v0.5 的三态决策矩阵是单调的：`VERIFIED`（人口 matched + 负控 proven + 正臂满足）、`REFUTED`（负控 survived）、`UNKNOWN`（其余一切）。`UNKNOWN` 是安全结论，不是系统崩溃。

## 独立总审发现了什么

外部总审没有接受我们的实现者自述，而是亲手复现了攻击：

- **Critical 1 — 离线包真实性**：`scope-coverage-report.json` 是普通自哈希 JSON。customer_private 重放完签名对象后**丢弃了重算的 Decision**、最终返回 report 里的字段；public/diagnostic 视图连签名对象都没有，却能返回 `READY_FOR_ACCEPTANCE`。复现：篡改 report 的 decision 并同步 manifest 的 hash/size，验签依然通过；公开包甚至可以从零伪造 `VERIFIED`。
- **Critical 2 — selector 输入未冻结**：git 选择器的 spec digest 不含 allowlist/excluded/required locators；pytest 的不含 selector_args/required_node_ids；pytest adapter 还把 stdout 里**任意带 `::` 的行**当权威 node id。复现：两套不同的 allowlist 或 selector_args 在输出相同时产生字节完全一致的 observation/evidence，均 satisfied。
- **Important 1**：决策加载只校验 Decision 与 parent ID，不加载/校验 Arm Result、不重新 compose、不校验 committed_at——删除全部 Arm Result 行后仍能加载出 `VERIFIED`。
- **Important 2**：控制证据 PROVEN 只要求 refs 非空 + 自报 FailureSignature 相等，任意 `{"arm": "negative"}` JSON 可得到 proven。
- **Important 3**：`Path.resolve()` 把 `.venv/bin/python` 解引用成 base Python，`-m pytest` 丢 site-packages 报 ModuleNotFoundError。
- **Important 4**：CLI 的 UNKNOWN/REFUTED 可 exit 0；audit-explain/compare 不走 v0.5 派生函数。
- **Important 5**：测试矩阵若干条目“以测试名存在代替覆盖”，计划里的测试文件名是幻影。

## 修复方式：攻击测试先行（RED → 最小修复 → 双审）

每个发现都先写**攻击形状的测试**并确认它对旧代码 RED，再做最小修复，提交后由两个独立子代理分别做规格审查与质量/安全审查，Critical/Important 不闭环不进入下一批。批次如下：

### 批 A：离线包只信重放的签名真值
customer_private 的决策/状态只来自 `_load_v05_objects_and_evidence` 重新 compose 的 Decision（签名验证 + signing-bytes 相等），report 与重放结果**逐字段 exact compare**，任何分叉 fail closed；public/diagnostic 没有签名 redacted attestation，一律返回 `UNAUTHENTICATED / NOT_READY`。攻击测试：伪造 report decision + 同步 manifest、从零伪造公开包。

### 批 B：把选择器的全部输入冻结进 digest
git/pytest 的允许/排除/必选参数全部 canonical 化后进入 `selector_spec_digest`；node id 只来自**受控 canonical collector**（`pytest_collection_finish` 写闭合 JSON 文件），stdout 永不解析。审查员随后又演示了 nested `conftest.py`（trylast hook）与根目录 `pytest.py` shadow 两条绕过——分别用 **conftest-free 拒绝**与 **`-I` 隔离**堵上，各配回归测试。

### 批 C：决策历史在每一个入口完整重放
`_load_current_decision_v05` 现在按 parent 关系加载 canonical Arm Result，逐行校验 id/digest/权威/签名/证据，对每个链节用其 predecessor 重新 compose 并要求 signing-bytes 相等，同时校验 profile/result/decision 的 committed_at 规范性与因果单调序（leap second 也拒绝）。攻击测试：删父行、换行、时间篡改、relation drift。

### 批 D：闭合的控制证据解析器
定义 9 键的 `openworkproof-control-evidence/0.5` canonical 文档，ledger 与离线包**共用同一个 resolver**；proven 必须满足 `证据事实 == 签名观察 == 注册期望`。攻击测试：旧形状 blob、事实矛盾、证据缺失。

### 批 E：尊重 venv 启动器
保留绝对 invocation 路径（不解引用最终 symlink），另行绑定真实 target、`pyvenv.cfg` 与 executable digest；真实 `.venv` 回归测试跑通真实 pytest 收集。

### 批 F：CLI 退出码与派生视图统一
`VERIFIED=0 / UNKNOWN=3 / REFUTED=4`（未识别值 fail-closed 为 3）；audit-explain/compare 复用 `explain_integrity_package` / `compare_integrity_packages`；端到端 CLI 测试覆盖三种判决。

### 批 G：矩阵、供应链与计划真值
补齐 Profile/Arm/Decision 的 insert/before-COMMIT/readback 故障、同 id 冲突并发、六个 v0.5 表族的物理篡改（含验收转移表）；converter 拒绝重复 tar 成员/绝对路径/`..`，平台从真实 config 派生而非重标；消除 pytest 临时目录清理噪声；修正计划中的幻影文件名与 `_ledger_delivery_protocol` 文本。

## 重新冻结发布：不可变候选库存 + 五道门

任何 allowlist 内源码的改动都会使旧库存失效（这正是供应链接口的设计），所以终审的 Minor 闭环后我们重建了候选：

- 候选库存：`supply-chain/images/candidates/d460c876a7f3046fd1d338951d964bce6d1a6be1.json`（全限定 `docker.io/…@sha256:2acf4820…`）
- focused v0.5：**370 passed**
- 冻结兼容 v0.2–v0.4：**216 passed**
- 便携全量：**3348 passed / 0 failed / 6 skipped**
- candidate 两套件（live Docker）：**173 passed**
- **required-live 全量：3456 passed / 0 failed / 0 skipped，零 warning**（10m57s）
- Rich #4196 离线交付包：**VERIFICATION PASSED**（无网络、无原始账本）

## 边界（诚实声明）

这是协议能力与自有演示（Rich #4196）的工程交付：绿色测试与离线重放**不等于**客户采用、付费 SOW、定金、上游采纳或商业验证——这些状态一律标记 `not_evidenced`。OpenWorkProof 是互补层：它冻结一次工作的授权、范围证据、人口完整性与负控语义，不替代 MCP/A2A 的互操作与身份能力，更不构成付款或结算的自动执行。

如果你在验证“Agent 到底验证了什么”上踩过类似的坑，欢迎在评论区聊聊；也欢迎独立复现我们的攻击测试与候选供应链。
