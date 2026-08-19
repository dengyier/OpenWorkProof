# Dual Verifier 交叉验证 v0.5 设计规格（独立执行收敛）

> 日期：2026-08-19
> 状态：待审查（Phase 3 设计，社区升级方向 #4）
> 协议基线：v0.5（Verification Integrity，已闭环）

## 1. 背景与社区输入

Giulio D'Erme 在代码审查中发现 **self-reported exit code 漏洞**：一个持有
有效密钥的 Verifier 可以声明 `expectation_status="satisfied"` +
`MUTATION_CAUGHT`，而实际测试从未运行或结果被伪造。当前协议只验证签名和
reason-code 自洽，**不验证声明的执行结果与证据一致**——"持有有效密钥但撒谎
的验证者"可以制造假 VERIFIED。

mansio 在审计评论中补充了独立性批评：**"dual sub-agent review isn't
independence"**——两个 agent 审查同一份材料、受同一上下文影响，不构成独立
验证。现有 high_risk 的"双 verifier 签名同一 draft"正是这种形式：两个验证者
签同一个结论，无法防止"一个撒谎验证者伪造 exit code 后另一个照签"。

社区共识（Giulio 原文）：
1. **两个独立密钥的 Verifier 重新执行**；
2. **output_digest 必须一致**（交叉验证收敛）；
3. 替换"单 Verifier 接受"为"双 Verifier 收敛"；
4. 引入第二个独立信任域的 Verifier。

## 2. 当前缺口（现状 vs 需求）

| 现有机制 | 覆盖 | 缺口 |
|---|---|---|
| high_risk 双 verifier bindings（v0.2+） | 协议声明 2 个不同 verifier 身份 | **不要求两者都实际执行**；一个验证者可产生全部 arm results |
| high_risk 双决策签名（v0.5） | 2 个 verifier 签同一 draft | **签同一结论**，不验证独立执行；撒谎验证者照签 |
| `independent_verifier` episode（mcp） | 同一验证者在 evidence_incomplete 状态重跑 | **同密钥重跑**，非独立信任域 |
| `verifier_independent_result` evidence slot | 1 个独立结果槽 | 只能一份，无交叉验证 |
| `assess_independence` | 检查 subject/key/controller/context 多样性 | 只查**一套** arm results 内的多样性，不要求跨验证者收敛 |

**核心缺口**：协议允许"一个验证者伪造 exit code + 另一个照签同一结论"，
没有任何机制要求**两个独立验证者的执行结果（output digest）交叉验证一致**。

## 3. 设计目标与非目标

### 3.1 目标

1. high_risk 决策必须由**两个不同 verifier binding 各自独立产生**的
   arm results 组成（每个验证者覆盖全部 arm）。
2. 两个验证者的**正臂 evidence snapshot digest 必须一致**（交叉收敛）——
   两个独立执行对同一断言产生同一证据摘要，撒谎验证者无法与诚实验证者
   收敛。
3. 交叉验证不一致 → 决策 **UNKNOWN**（`DUAL_VERIFIER_DIVERGENCE`），
   不信任任一验证者。
4. 保持标准（non-high_risk）语义不变：单验证者可接受。
5. 三态决策兼容：VERIFIED 仅当双验证者收敛 + 其他条件全满足。

### 3.2 非目标

- 不实现同容器/新容器的执行调度（那是执行层，协议只要求证据收敛）；
- 不实现"每个收据都双验证"（只 high_risk 决策级）；
- 不实现动态选择第三个验证者仲裁分歧（分歧即 UNKNOWN，留给后续）；
- 不改 v0.1–v0.5 冻结面（新增 v0.5 sibling 或纯语义收紧）。

## 4. 协议设计

### 4.1 决策组合要求（`compose_verification_decision_v05`）

high_risk 时，arm results 必须是**两套**（每 arm 每个 verifier binding 各一套）：

```text
arm results 必须来自恰好 2 个不同的 verifier binding
  - 每个 binding 覆盖全部 arm（每个 arm_id 在该验证者集合中出现一次）
  - 每 (arm, verifier) 恰好一条结果（重复行拒绝——N9）
  - 每 arm 的两套结果必须在全部承载结论的字段上一致：
      expectation_status / execution_status / mutation_status / reason_codes /
      action_receipt_ids / observed_member_count / observed_population_digest /
      observed_required_target_ids / scope_expectation_status /
      population_observations / control_observation / evidence snapshot digest
  - 任一字段不一致 -> 决策组合失败（VerificationInputError），不产生决策
    （分歧 = 证据冲突，无法形成可重放决策；调用方重跑直到收敛或降级）
```

收敛后决策**引用完整双套**（每 arm 两个不同验证者的结果），并由两个验证者
签名。可重放性由**决策自证**实现：commit/replay/离线包均从**决策自身的
引用**（`selected_ids`）重跑交叉验证——不依赖签名数推导独立性，追加的后续
验证轮次不影响已提交决策的可重放性（N7）。新决策的 prepare 用
**每 (arm, verifier) 最新**（`latest_per_verifier`，按验证者**自报的
`created_at`** 取最新）——追加轮次后新决策用最新双套。**commit 的 stale 门
要求决策引用的结果集精确等于 prepare 会加载的那一套**（high_risk 为每
(arm, verifier) 最新，standard 为每 arm 最新）：
验证者不能引用自己的旧轮压掉更新的失败轮（N8），手工挑选引用的伪造决策
在 commit 被拒绝。

低风险（standard）时语义不变（单套 arm results，单验证者可接受；决策引用
每 arm 一条）。

### 4.2 交叉收敛判定

对每个 arm_id，两套结果的**全部承载结论字段**必须一致：

```text
expectation_status / execution_status / mutation_status / reason_codes /
action_receipt_ids / observed_member_count / observed_population_digest /
observed_required_target_ids / scope_expectation_status /
population_observations / control_observation / evidence snapshot digest
```

任一字段不一致 → `VerificationInputError("high-risk verifiers diverged;
no decision can be formed")`，不产生决策。

> **设计决策（临时折中，v0.6 演进）**：分歧不产生 `UNKNOWN` 决策，而是
> 组合失败。原因：冻结的 v0.5 决策模型每 arm 恰好一个引用
> （`arm_results` 一对一），双套引用违反它、单套引用 replay 时丢失分歧
> 信号。`DUAL_VERIFIER_DIVERGENCE` reason code 保留在 v0.5 schema
> （已走 registry 流程），作为 v0.6 决策模型支持双套引用后的正式分歧态。
> 当前分歧的诚实表达是 `VerificationInputError`：调用方重跑直到收敛或
> 降级为 standard 验证。

`evidence_snapshot_digest` 由既有 `evidence_snapshot_digest()` 从 arm result
的 evidence refs 计算（compose 已在用）。

### 4.3 新 reason code

```text
DUAL_VERIFIER_DIVERGENCE   # 双验证者证据摘要不一致
```

high_risk 且单验证者结果 → 复用既有 `INDEPENDENCE_INSUFFICIENT`（不新造）。

### 4.4 签名与决策

- high_risk 决策仍要求 2 个 verifier 签名（既有逻辑不变）；
- 组合阶段先验证双验证者逐字段收敛，再产生 draft，最后两个验证者签名；
- 撒谎验证者伪造 exit code → 其结论字段与诚实验证者不一致 → 组合失败，
  签名不产生；
- 分歧时 compose 抛 `VerificationInputError`，不产生决策——这是诚实的
  证据冲突表达，调用方重跑或降级。

### 4.5 威胁模型

1. 单验证者伪造全部 arm results → high_risk 要求 2 个 binding，单验证者
   集合不满足 → 组合失败或 independence 不足。
2. 两个验证者共谋（同一执行）→ 无法防御（信任模型假设至少一个诚实）；
   但共谋需两个独立密钥 + 两个独立上下文，攻击面翻倍。
3. 一个撒谎验证者伪造 exit code（expectation_status/execution_status 等）→
   结论字段与诚实验证者不一致 → 组合失败（漏洞关闭）。
4. 两个验证者都诚实但环境噪声不同 → 结论字段不一致 → 组合失败（安全方向，
   成本是重试直到环境收敛，或接受标准验证）。
5. 验证者引用同一份伪造证据 → 结论字段可能一致 → 需攻击者同时控制两个
   独立验证者 + 证据发布（超出单验证者信任模型，记录为边界）。

## 5. 测试与验收标准

### 5.1 决策组合

- high_risk + 单验证者 arm results → UNKNOWN（independence 不足）；
- high_risk + 双验证者收敛 → VERIFIED（其他条件满足）；
- high_risk + 双验证者任一结论字段不一致 → `VerificationInputError`
  （分歧不可得决策；临时折中，见 §4.2）；
- high_risk + split 覆盖（正臂 A 负臂 B）→ 拒绝；
- standard + 单验证者 → VERIFIED（既有语义不变）；
- high_risk 决策 commit/replay/离线包：全链加载双套重跑交叉验证，
  单验证者（第二验证者只联署）或伪造 VERIFIED → commit 拒绝
  （recompose 与签名不匹配）。

### 5.2 攻击测试（RED）

- 撒谎验证者伪造 exit code（expectation_status 等与诚实验证者不同）→
  `VerificationInputError`（漏洞关闭）；
- 单验证者冒充双验证者（同一密钥两套结果）→ 拒绝；
- 第二验证者只联署不产出 → commit 拒绝（recompose 单套 → UNKNOWN
  ≠ 签名 VERIFIED）；
- 伪造 VERIFIED draft → commit 拒绝（draft mismatch）。

### 5.3 冻结面

- v0.1–v0.5 schema、golden bytes、冻结 bundle 不变（若无 schema 变更）；
  若加 `DUAL_VERIFIER_DIVERGENCE` reason code，走 schema-registry 流程。

## 6. 诚实边界

- 本规格是协议能力，不是客户案例、付款、上游采纳或商业验证。
- Dual Verifier 证明"协议要求双验证者收敛"，不证明"任何实际交付都经双验证"、
  "验证者诚实"或"无共谋"。
- **分歧不入账的代价（临时折中）**：验证者矛盾（divergence）导致组合失败，
  不产生可审计的 `UNKNOWN` 决策——审计方无法从账本区分"验证者互相矛盾"与
  "没人验证"；运营方可以重跑到收敛只发布成功，且任一被绑定的验证者可以
  阻断全部 high_risk 决策且不留痕迹。这是 §4.2 记录的临时折中，v0.6 决策
  模型支持双套引用后应以正式的 `DUAL_VERIFIER_DIVERGENCE` 状态入账。
- **配对规则**：`latest_per_verifier` 允许不同验证者引用不同轮次的
  结果配对（如 A@00:16 配 B@00:10），只要逐字段收敛即判 VERIFIED——这是
  可辩护的（每 (arm, verifier) 各自最新），但配对的时间差未强制一致。
- **新鲜度是验证者自报的 `created_at`**：协议按验证者写入结果的
  `created_at` 取最新，不验证该时间戳的真实性（仅约束在 binding/profile
  有效窗内）。验证者可以把失败轮 backdate 到窗内更早时刻使其永不被选为
  最新——这不扩大攻击者可达的结果集（与根本不发布失败轮等价，均已覆盖），
  但账本会残留一条被决策忽略的 contradicted 行，审计方无法仅凭账本区分
  "backdated 的失败轮"与"正常的历史失败轮"。
- 所有外部状态保持 `not_evidenced`。
