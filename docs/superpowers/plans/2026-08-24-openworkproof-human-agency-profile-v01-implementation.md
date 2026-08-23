# OpenWorkProof Human Agency Profile 0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to implement this plan task-by-task. Use
> `superpowers:subagent-driven-development` only when the user explicitly asks
> for delegated workers. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在不修改冻结 WorkOrder v0.1、CapabilityGrant 与既有执行入口语义的
前提下，新增由 WorkOrder Acceptor 签名的 Human Agency Profile，使企业能够明确
哪些 Agent 动作可以委托、哪些决策必须由人保留、何时升级给人，以及如何申诉、
替换和撤销，并让受保护执行入口在调用 handler 前 fail closed。

**Architecture:** 新增独立 sibling profile，而不是扩展 WorkOrder。`agency.py`
负责闭合模型、签名绑定与历史解析；`agency_policy.py` 只计算 WorkOrder、Grant 与
当前 profile 的集合交集；`agency_ledger.py` 以追加式事务保存 profile、transition
和 appeal；`agency_bundle.py` 导出无私钥、可离线验证的最小证据包。现有执行 API
保持兼容，新增 opt-in 受保护入口，先验证 profile，再调用既有事务。

**Tech Stack:** Python 3.10–3.13、Pydantic v2、Ed25519、RFC 8785 JCS、SQLite、
现有 OpenWorkProof WorkOrder/Grant/Policy/MCP 事务、pytest。

---

## 0. 权威规格、硬边界与成功标准

权威规格：
`docs/superpowers/specs/2026-08-24-openworkproof-human-agency-profile-v01-design.md`

实施起点：`codex/human-agency-profile-v01@60cd05f`。若起点变化，先记录新 HEAD，
不得静默沿用计划中的 commit 假设。

首版硬边界：

- 不修改冻结的 WorkOrder v0.1、CapabilityGrant 或既有 schema digest。
- 不把 Human Agency Profile 宣称为 Agent OS、员工考核系统或法律合规结论。
- 不实现 SaaS、账号体系、支付、托管、担保、结算、市场或可视化后台。
- 不让申诉对象直接恢复权限；只有 Acceptor 签名的 transition/new profile 改变
  当前权限。
- 不让调用方通过时间戳挑选“最新”profile；历史有 fork、cycle、缺失 replacement
  或多终点时必须 fail closed。
- 不将 reserved decision 的描述文本交给 LLM 自由解释。首版运行时只执行明确映射
  到当前 WorkOrder tool name 的规则。
- 现有 `execute_repo_read`、`execute_run_tests` 等入口保持原语义；新约束仅由新的
  protected API 显式启用。

首个闭环成功标准：

1. WorkOrder 与 Grant 同时允许 `owp.repo_read`、`owp.apply_patch`。
2. 当前 profile 仅委托 `owp.repo_read`，并保留 `owp.apply_patch` 给人。
3. 受保护的 repo-read 正常提交；受保护的 apply-patch 返回
   `AGENCY_HUMAN_DECISION_REQUIRED`，handler 调用数为 0，账本全表快照不变。
4. Manager appeal 只被记录，不改变权限。
5. Acceptor 签名的新 profile 与 `superseded` transition 生效后，apply-patch 才能执行。
6. Acceptor `revoked` transition 生效后，受保护入口返回 `AGENCY_PROFILE_REQUIRED`。
7. 导出的 bundle 在无数据库、无私钥环境中能验证 WorkOrder/profile/history/appeal
   的签名、摘要、链结构与当前状态；任意篡改均失败。

每个 Task 固定执行：RED → 最小 GREEN → 相邻回归 → `pip check` →
`compileall` → `git diff --check` → 单一职责 commit。不得用扩大 allowlist、跳过
required-live 或修改历史 candidate inventory 来换取绿灯。

## 0.1 目标文件

### 新建

| 文件 | 单一职责 |
|---|---|
| `src/openworkproof/agency.py` | 三类闭合模型、ID/digest、签名验证、current profile 历史解析 |
| `src/openworkproof/agency_policy.py` | WorkOrder ∩ Grant ∩ profile 的纯授权决策 |
| `src/openworkproof/agency_ledger.py` | 追加式 profile/transition/appeal 事务与查询 |
| `src/openworkproof/agency_bundle.py` | 确定性导出与纯离线验证 |
| `src/openworkproof/agency_schema_registry.py` | 独立 agency-v0.1 schema registry，不触碰冻结主 registry |
| `src/openworkproof/schemas/agency-v0.1/*.json` | 三对象与 registry 的冻结 JSON Schema |
| `tests/test_agency_models_v01.py` | 模型、签名、WorkOrder/角色绑定 |
| `tests/test_agency_history_v01.py` | supersede/revoke/fork/cycle/current resolver |
| `tests/test_agency_policy_v01.py` | 三层交集、错误码、reserved/delegated 互斥 |
| `tests/test_agency_ledger_v01.py` | 原子提交、nonce、并发、ACK 丢失回读 |
| `tests/test_agency_bundle_v01.py` | 离线验签、确定性、路径安全、篡改矩阵 |
| `tests/test_agency_end_to_end_v01.py` | 首个真实受保护执行闭环 |
| `tests/test_agency_schema_registry_v01.py` | schema 生成、冻结与 wheel 可发现性 |

### 修改

| 文件 | 变更 |
|---|---|
| `src/openworkproof/signing.py` | 仅增加三个独立签名域；不改旧域语义 |
| `src/openworkproof/evidence.py` | 仅把 agency 表加入幂等 schema 初始化 |
| `src/openworkproof/mcp_server.py` | 增加显式 opt-in protected wrapper，不改旧函数默认行为 |
| `src/openworkproof/__init__.py` | 懒加载公开的构建、提交、解析与验证 API |
| `pyproject.toml` | 打包 `schemas/agency-v0.1/*.json`，不新增依赖 |
| `README.md`、`README_en.md` | 增加 Human Agency Profile 实验能力与诚实边界 |
| `docs/status.md` | 写入 fresh 测试事实，不写商业采用结论 |
| `supply-chain/images/trusted-helper/SOURCE_ALLOWLIST` | 仅当 required-live 闭包确实加载新模块时精确追加 |
| `supply-chain/images/candidates/<revision>.json` | allowlist 绑定变化时新增不可变库存 |

---

## Task 1：冻结基线并实现三类闭合签名对象

**Files:**
- Create: `tests/test_agency_models_v01.py`
- Create: `src/openworkproof/agency.py`
- Modify: `src/openworkproof/signing.py`

- [x] **Step 1: 记录干净基线并运行相邻测试**

```bash
git status --short --branch
git rev-parse HEAD
./.venv/bin/python -m pytest -q \
  tests/test_policy.py \
  tests/test_retraction_receipt_v05.py \
  tests/test_control_integrity_v05.py
./.venv/bin/python -m pip check
```

Expected：记录真实 passed/failed/skipped；除已确认规格与计划外没有未解释修改。

- [x] **Step 2: 写模型 RED 测试**

至少覆盖：

```python
def test_profile_requires_sorted_disjoint_tool_sets() -> None:
    payload = _signed_profile_payload(
        delegated_actions=(_delegated_action("owp.repo_read"),),
        reserved_decisions=(_reserved_decision("owp.repo_read"),),
    )
    with pytest.raises(ValidationError, match="disjoint"):
        HumanAgencyProfileV01.model_validate(payload)


def test_profile_is_bound_to_exact_work_order_and_acceptor() -> None:
    case = _agency_case()
    profile = _signed_profile(case)
    assert profile.work_order_digest == case.work_order.digest
    assert verify_human_agency_profile(profile, case.work_order)


def test_appeal_signer_must_match_declared_role_and_subject() -> None:
    case = _agency_case()
    appeal = _signed_appeal(case, role="Manager", signing_role="Developer")
    assert not verify_agency_appeal(appeal, case.work_order)
```

Expected：导入失败或对象不存在，测试为 RED。

- [x] **Step 3: 实现最小闭合模型**

`agency.py` 使用 `ProtocolModel` / `SignedProtocolModel`，模型字段固定为：

```python
class DelegatedActionV01(ProtocolModel):
    action_id: Digest64
    tool_name: str
    autonomy: Literal["delegated"]


class ReservedDecisionV01(ProtocolModel):
    decision_id: Digest64
    decision_kind: Literal[
        "scope_or_criteria_change",
        "external_publication",
        "external_communication",
        "acceptance",
        "payment_or_settlement",
    ]
    blocked_tools: tuple[str, ...]
    required_role: Literal["Acceptor"]


class EscalationConditionV01(ProtocolModel):
    condition_code: Literal[
        "reserved_decision_requested",
        "scope_change_requested",
        "evidence_incomplete",
        "verifier_conflict",
        "authorization_revoked",
        "deadline_or_quota_exceeded",
    ]


class RevocationAndAppealPolicyV01(ProtocolModel):
    revocation_mode: Literal["acceptor_signed_transition"]
    appeal_mode: Literal["signed_request_then_acceptor_decision"]
    appeal_roles: tuple[Literal["Developer", "Manager", "Verifier"], ...]


class HumanAgencyProfileV01(SignedProtocolModel):
    _signed_domain = "human-agency-profile"
    schema_version: Literal["openworkproof-human-agency-profile/0.1"]
    profile_id: Digest64
    work_order_digest: Digest64
    delegated_actions: tuple[DelegatedActionV01, ...]
    reserved_decisions: tuple[ReservedDecisionV01, ...]
    escalation_conditions: tuple[EscalationConditionV01, ...]
    revocation_and_appeal: RevocationAndAppealPolicyV01
    valid_from: CanonicalUTCTime
    expires_at: CanonicalUTCTime
    issued_at: CanonicalUTCTime
    nonce: Digest64


class AgencyProfileTransitionV01(SignedProtocolModel):
    _signed_domain = "agency-profile-transition"
    schema_version: Literal["openworkproof-agency-profile-transition/0.1"]
    transition_id: Digest64
    work_order_digest: Digest64
    target_profile_id: Digest64
    target_profile_digest: Digest64
    transition: Literal["revoked", "superseded"]
    replacement_profile_id: Digest64 | None
    replacement_profile_digest: Digest64 | None
    reason_code: Literal["human_withdrawal", "scope_changed", "risk_changed", "correction"]
    transitioned_at: CanonicalUTCTime
    nonce: Digest64


class AgencyAppealV01(SignedProtocolModel):
    _signed_domain = "agency-appeal"
    schema_version: Literal["openworkproof-agency-appeal/0.1"]
    appeal_id: Digest64
    work_order_digest: Digest64
    profile_id: Digest64
    profile_digest: Digest64
    appellant_role: Literal["Manager", "Developer", "Verifier"]
    appellant_subject_id: Identifier
    requested_change_digest: Digest64
    reason_code: Literal[
        "task_blocked",
        "scope_mismatch",
        "evidence_available",
        "verifier_disagreement",
    ]
    created_at: CanonicalUTCTime
    nonce: Digest64
```

辅助嵌套对象必须 `extra="forbid"`、immutable、UTF-8 sorted unique，并限制文本长度。
`delegated_actions` 按 `tool_name` 排序且唯一；`reserved_decisions` 可包含不映射工具的
声明性条目，但 `blocked_tools` 中的每个值都必须属于当前 WorkOrder `allowed_tools`。
同一 profile 中 `reserved_decisions.decision_kind` 必须唯一且最多 5 条；同类决定的
多个工具合并进同一条 `blocked_tools`，防止冗余条目无界放大签名载荷。
`appeal_roles` 必须固定为 `("Developer", "Manager", "Verifier")`，不得由调用者扩展。
`profile_id`、`transition_id`、`appeal_id` 及 delegated/decision 子对象 ID 必须按设计
§5 的独立 domain，由不含自身 ID、digest、signature 的 canonical payload 唯一推导；
其中 `decision_id` domain 固定为 `openworkproof/reserved-decision/v0.1`。
`requested_change_digest` 绑定 proposed delegated/reserved closed JSON；原始理由不进入
协议真理。

- [x] **Step 4: 增加三个独立签名域**

在 `signing.py` 的 v0.1 canonical/signed domain 中仅追加：

```python
"human-agency-profile"
"agency-profile-transition"
"agency-appeal"
```

不改变旧对象的 canonical bytes。补快照断言，确认既有 WorkOrder digest 不变。

- [x] **Step 5: 实现 WorkOrder 绑定验签**

规则：profile 与 transition 只接受 WorkOrder `Acceptor` key；appeal 只接受声明的
Manager/Developer/Verifier 且 subject/key 三者一致；所有对象必须 exact
`work_order_digest`，签名、digest、ID、时间窗均有效。

- [x] **Step 6: 运行测试与提交**

```bash
./.venv/bin/python -m pytest -q tests/test_agency_models_v01.py tests/test_policy.py
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests/test_agency_models_v01.py
git diff --check
git add src/openworkproof/agency.py src/openworkproof/signing.py tests/test_agency_models_v01.py
git commit -m "feat: define human agency profile objects"
```

---

## Task 2：实现唯一 current profile 历史解析器

**Files:**
- Create: `tests/test_agency_history_v01.py`
- Modify: `src/openworkproof/agency.py`

- [x] **Step 1: 写历史 RED 矩阵**

覆盖 genesis、supersede、revoke、缺 replacement、replacement digest 不一致、时间倒流、
cycle、一个前驱两条 transition、多个 genesis、多终点、过期 profile。关键断言：

```python
@pytest.mark.parametrize(
    "mutation",
    ("fork", "cycle", "missing_replacement", "multiple_genesis", "time_reversal"),
)
def test_invalid_history_never_selects_latest_by_timestamp(mutation: str) -> None:
    with pytest.raises(AgencyProfileHistoryError):
        resolve_current_human_agency_profile(*_mutated_history(mutation))
```

- [x] **Step 2: 实现纯函数 resolver**

```python
@dataclass(frozen=True, slots=True)
class ResolvedAgencyProfile:
    status: Literal["active", "revoked"]
    current_profile: HumanAgencyProfileV01 | None
    ordered_profile_ids: tuple[str, ...]
    ordered_transition_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AgencyProfileHistory:
    profiles: tuple[HumanAgencyProfileV01, ...]
    transitions: tuple[AgencyProfileTransitionV01, ...]


def resolve_current_human_agency_profile(
    work_order: WorkOrder,
    profiles: Sequence[HumanAgencyProfileV01],
    transitions: Sequence[AgencyProfileTransitionV01],
    *,
    now: datetime,
) -> ResolvedAgencyProfile
```

解析顺序必须由 signed graph 决定，不允许用最大时间戳兜底。`superseded` 必须找到 exact
replacement id/digest；`revoked` 必须 replacement id/digest 均为 `None` 且成为唯一终点。

- [x] **Step 3: 运行测试与提交**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_agency_models_v01.py \
  tests/test_agency_history_v01.py
./.venv/bin/python -m compileall -q src tests/test_agency_history_v01.py
git diff --check
git add src/openworkproof/agency.py tests/test_agency_history_v01.py
git commit -m "feat: resolve human agency profile history"
```

---

## Task 3：实现三层交集授权与稳定错误码

**Files:**
- Create: `src/openworkproof/agency_policy.py`
- Create: `tests/test_agency_policy_v01.py`

- [x] **Step 1: 写纯策略 RED 测试**

矩阵至少包含：profile 缺失、history invalid、profile 过期、work-order binding 错误、
reserved tool、未委托 tool、三层都允许、appeal 存在但仍拒绝、声明性保留项不误伤
无关工具。

```python
def test_reserved_action_is_denied_after_base_policy_allows() -> None:
    decision = authorize_tool_call_with_agency_profile(
        case.context,
        case.profile_history,
        case.apply_patch_request,
        case.apply_patch_arguments,
    )
    assert decision.allowed is False
    assert decision.error_code == "AGENCY_HUMAN_DECISION_REQUIRED"
```

- [x] **Step 2: 实现组合器，不复制基础授权逻辑**

实现签名与设计 §7 保持一致：

```python
def authorize_tool_call_with_agency_profile(
    context: AuthorizationContext,
    profile_history: AgencyProfileHistory,
    request: AgentRequest,
    request_arguments: ToolRequestArguments,
    execution_facts: ProspectiveExecutionFacts | None = None,
) -> PolicyDecision
```

先调用现有 `authorize_tool_call`。基础策略拒绝时原样返回；基础策略允许后，调用
Task 2 resolver 从完整 history 解析唯一 current profile，再应用 profile：

```python
delegated_tool_names = frozenset(
    action.tool_name for action in profile.delegated_actions
)
reserved_tool_names = frozenset(
    tool_name
    for decision in profile.reserved_decisions
    for tool_name in decision.blocked_tools
)
if request.tool_name in reserved_tool_names:
    return PolicyDecision(
        allowed=False,
        decision="deny",
        error_code="AGENCY_HUMAN_DECISION_REQUIRED",
        reason="human agency profile reserves this decision",
    )
if request.tool_name not in delegated_tool_names:
    return PolicyDecision(
        allowed=False,
        decision="deny",
        error_code="AGENCY_ACTION_NOT_DELEGATED",
        reason="human agency profile does not delegate this action",
    )
return base_decision
```

决定对象复用现有闭合 `PolicyDecision`，reason 使用固定字面量，不进行自由文本推理。
缺失、invalid、expired、binding invalid 的 history 分别稳定映射到计划 §0 的四个错误码。

- [x] **Step 3: 运行测试与提交**

```bash
./.venv/bin/python -m pytest -q tests/test_agency_policy_v01.py tests/test_policy.py
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests/test_agency_policy_v01.py
git diff --check
git add src/openworkproof/agency_policy.py tests/test_agency_policy_v01.py
git commit -m "feat: enforce human agency authorization intersection"
```

---

## Task 4：实现追加式账本事务与 COMMIT-ACK 回读

**Files:**
- Create: `src/openworkproof/agency_ledger.py`
- Create: `tests/test_agency_ledger_v01.py`
- Modify: `src/openworkproof/evidence.py`

- [x] **Step 1: 写事务 RED 测试**

覆盖：profile commit、transition commit、appeal commit、重复 nonce、重复 ID、错误 signer、
错误 WorkOrder、before-commit 注入全表零写入、commit-ack loss exact readback、readback
failure indeterminate、双线程同一 target 只有一个 supersession 成功、cleanup failure 不改已提交
真相。

- [x] **Step 2: 以幂等方式增加三表**

在现有 `_SCHEMA` 增加：

```sql
CREATE TABLE human_agency_profiles_v01 (
    profile_id TEXT PRIMARY KEY,
    work_order_digest TEXT NOT NULL,
    profile_digest TEXT NOT NULL UNIQUE,
    profile_json TEXT NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    issued_at TEXT NOT NULL,
    committed_at TEXT NOT NULL
);
CREATE TABLE agency_profile_transitions_v01 (
    transition_id TEXT PRIMARY KEY,
    work_order_digest TEXT NOT NULL,
    target_profile_id TEXT NOT NULL UNIQUE,
    target_profile_digest TEXT NOT NULL,
    replacement_profile_id TEXT,
    replacement_profile_digest TEXT,
    transition TEXT NOT NULL,
    transition_digest TEXT NOT NULL UNIQUE,
    transition_json TEXT NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    transitioned_at TEXT NOT NULL,
    committed_at TEXT NOT NULL
);
CREATE TABLE agency_appeals_v01 (
    appeal_id TEXT PRIMARY KEY,
    work_order_digest TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    profile_digest TEXT NOT NULL,
    requested_change_digest TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    appeal_digest TEXT NOT NULL UNIQUE,
    appeal_json TEXT NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    committed_at TEXT NOT NULL
);
```

每表保存 canonical JSON、digest、work_order_digest、nonce、signed time 与独立的
`committed_at` 操作时间；nonce 在对象类型内唯一。`committed_at` 不进入签名对象或
离线协议真理，只用于账本运维追踪。不得用 update/delete 表示替换或撤销。

- [x] **Step 3: 实现三类 commit 与只读 load**

公开函数：

```python
commit_human_agency_profile(ledger_path, profile, *, fault=None)
commit_agency_profile_transition(ledger_path, transition, *, fault=None)
commit_agency_appeal(ledger_path, appeal, *, fault=None)
load_agency_history(ledger_path, work_order_digest)
load_current_human_agency_profile(ledger_path, *, now)
load_agency_appeals(ledger_path, work_order_digest)
```

复用 `evidence._acquire_target_lock`、`BEGIN IMMEDIATE`、defensive readback 和 cleanup
模式。COMMIT 应答丢失后只有 exact committed truth 才抛带 committed payload 的
`AgencyCommittedError`；无法确认则 `AgencyCommitIndeterminateError`。

- [x] **Step 4: 验证零写入与并发原子性**

before-COMMIT 故障前后对 `sqlite_master` 中全部 user table 做有序快照，不只检查新表。
并发测试不得依赖 sleep 判胜，必须断言唯一签名链终点。

- [x] **Step 5: 运行测试与提交**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_agency_models_v01.py \
  tests/test_agency_history_v01.py \
  tests/test_agency_ledger_v01.py \
  tests/test_retraction_receipt_v05.py
./.venv/bin/python -m compileall -q src tests/test_agency_ledger_v01.py
git diff --check
git add src/openworkproof/agency_ledger.py src/openworkproof/evidence.py tests/test_agency_ledger_v01.py
git commit -m "feat: commit human agency history atomically"
```

---

## Task 5：新增 opt-in 受保护执行入口

> **2026-08-24 Owner 决策：** 采用 executor 锁内 opt-in callback；不得使用锁外闭包。
> 同时补真实 `execute_apply_patch`，完成前不声称 supersede 后 apply-patch 可安全执行。

**Files:**
- Create: `tests/test_agency_end_to_end_v01.py`
- Modify: `src/openworkproof/mcp_server.py`
- Modify: `src/openworkproof/agency_policy.py`

- [ ] **Step 1: 拆出 profile-only 判定并写 RED 测试**

在 `agency_policy.py` 新增：

```python
def authorize_agency_profile_layer(
    context: AuthorizationContext,
    profile_history: AgencyProfileHistory,
    request: AgentRequest,
) -> PolicyDecision:
    ...
```

该函数不重复基础 policy，只解析 current profile 并执行 reserved/delegated 判定。既有
`authorize_tool_call_with_agency_profile` 先运行基础 policy；基础 allow 后复用该函数，保持
基础安全错误优先。测试覆盖现有错误码矩阵和允许结果一致性。

- [ ] **Step 2: 在现有三个 executor 的同一锁域接入 callback**

为 `execute_repo_read`、`execute_run_tests`、`execute_rollback` 增加仅关键字可选参数：

```python
agency_authorize: Callable[[], PolicyDecision] | None = None
```

三个 executor 都必须在已持有 target lock、existing context 与基础授权通过之后，且在任何
preflight、reservation、handler 或业务写入之前执行：

```python
if agency_authorize is not None:
    agency_decision = agency_authorize()
    if not agency_decision.allowed:
        raise ToolCallDenied(agency_decision)
```

callback 必须延迟加载 ledger history；不得在 executor 加锁前捕获 profile 快照。默认
`None` 的旧调用路径必须通过原有测试，证明默认语义不变。

- [ ] **Step 3: 写锁内原子性与撤销竞态测试**

使用真实初始化 ledger 与记录型 handler。对 repo-read/run-tests/rollback 至少证明：

```python
before = _all_user_table_snapshot(ledger)
calls = 0
with pytest.raises(ToolCallDenied) as caught:
    execute_repo_read(..., agency_authorize=reserved_decision)
assert caught.value.decision.error_code == "AGENCY_HUMAN_DECISION_REQUIRED"
assert calls == 0
assert _all_user_table_snapshot(ledger) == before
```

并发测试用事件屏障而非 sleep：protected executor 持锁进入 callback 后，Acceptor revoke
必须等待；executor 只可依据同一锁域内已加载的历史执行。下一次调用必须观察 revoke 并拒绝。

- [ ] **Step 4: 实现真实 `execute_apply_patch` 事务入口**

签名沿用现有 executor 风格：接收 ledger/evidence root、`AuthorizationContext`、签名
`AgentRequest`、`ApplyPatchArguments`、`ProspectiveExecutionFacts`、Sidecar 私钥、candidate
workspace handler 与 trusted clock，并提供同样的 `agency_authorize=None` opt-in seam。

实现必须复用 `repo_tools.apply_patch_in_candidate_workspace`，并完成：current-context → 基础
authorization → profile callback → receipt 容量 preflight → handler reservation/started →
patch handler → `PatchResultEvidence` 与 patch/result EvidenceRefs → Sidecar 签名 receipt →
`complete_receipt_publication(..., _borrowed_lock_descriptor=lock_descriptor)` → cleanup/recovery。
不得复制测试中的手工 receipt fixture 作为生产实现；COMMIT-ACK、STARTED_UNCONFIRMED、
handler failure 与 cleanup failure 语义要与 repo-read/run-tests/rollback 对齐。

- [ ] **Step 5: 实现最小 protected dispatcher 与完整状态链**

支持设计 §7 的 `owp.repo_read`、`owp.apply_patch`、`owp.run_tests` 与
`owp.rollback_patch`。dispatcher 不持锁、不预加载 history，只按签名
`request.tool_name` 选择 executor，并向 executor 传入延迟 callback。不得接收独立
`tool_name` 或 `now`；未知工具 fail closed。

同一测试依次证明：repo-read allowed；apply-patch reserved；appeal 后仍 reserved；Acceptor
supersession 后 apply-patch allowed；revoke 后所有 protected tool 返回
`AGENCY_PROFILE_REQUIRED`。同时回归旧 `execute_repo_read`，证明未选择新入口时行为不变。

- [ ] **Step 6: 分阶段运行测试与提交**

```bash
./.venv/bin/python -m pytest -q tests/test_agency_policy_v01.py tests/test_policy.py
git add src/openworkproof/agency_policy.py tests/test_agency_policy_v01.py
git commit -m "refactor: separate human agency policy layer"

./.venv/bin/python -m pytest -q \
  tests/test_agency_end_to_end_v01.py \
  tests/test_repo_read_transaction.py \
  tests/test_mcp_server.py
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests/test_agency_end_to_end_v01.py
git diff --check
git add src/openworkproof/mcp_server.py src/openworkproof/agency_policy.py tests/test_agency_end_to_end_v01.py
git commit -m "feat: protect agent execution with human agency profiles"
```

---

## Task 6：导出最小离线验证 bundle

> **2026-08-24 Owner 决策：** v0.1 是 authorization boundary bundle，不是某次调用的
> enforcement proof；使用 exporter 冻结的 `evaluated_at`，接受其非 TSA 边界；状态增加
> `expired`。

**Files:**
- Create: `src/openworkproof/agency_bundle.py`
- Create: `tests/test_agency_bundle_v01.py`

- [ ] **Step 1: 写 boundary bundle RED 测试**

覆盖 active/revoked/expired、固定 clock 下确定性双导出、无私钥、
symlink/hardlink/path traversal、额外文件、缺文件、WorkOrder/profile/transition/appeal 任一
字节篡改、签名有效但链 fork、manifest 摘要篡改、manifest 状态与重新解析结果不一致。

- [ ] **Step 2: 实现闭合 manifest 与结果**

```python
class AgencyBundleManifestV01(ProtocolModel):
    schema_version: Literal["openworkproof-agency-bundle/0.1"]
    work_order_digest: Digest64
    evaluated_at: CanonicalUTCTime
    current_status: Literal["active", "revoked", "expired"]
    current_profile_id: Digest64 | None
    boundary: Literal["authorization evidence, not legal or employment judgment"]
    entries: tuple[AgencyBundleManifestEntryV01, ...]


class AgencyBundleVerificationResultV01(ProtocolModel):
    schema_version: Literal["openworkproof-agency-bundle-result/0.1"]
    work_order_digest: Digest64
    evaluated_at: CanonicalUTCTime
    current_status: Literal["active", "revoked", "expired"]
    current_profile_id: Digest64 | None
    appeal_count: SafeNonNegativeInt
    boundary: Literal["authorization evidence, not legal or employment judgment"]
```

- [ ] **Step 3: 实现确定性导出和纯离线验证**

允许的精确布局：

```text
agency-manifest.json
agency/work-order.json
agency/profiles/<profile_id>.json
agency/transitions/<transition_id>.json
agency/appeals/<appeal_id>.json
verify.sh
```

manifest entry 固定为 relative POSIX path、SHA-256、size；UTF-8 路径排序，manifest 本身不
自哈希。写入使用 staging + fsync + no-replace rename。exporter 在 target lock 内用 trusted
clock 冻结 canonical UTC second `evaluated_at`；verifier 不接受独立 `now`，只用 manifest
时间重新解析完整历史，并核对 active/revoked/expired 与 current profile。验证器只信
manifest 与文件内容，不访问 ledger、网络、环境私钥或系统时间；WorkOrder 内 key bindings
即为验签公钥来源。

额外/缺失文件、非普通文件、symlink、`st_nlink != 1`、路径越界、非 canonical JSON、摘要
或 size 不符、跨 WorkOrder、错误签名、引用缺失、fork/cycle/disconnected/time reversal、
appeal 目标不一致和重算状态不一致全部 fail closed。结果必须保留非法律/雇佣判断边界。

- [ ] **Step 4: 运行测试与提交**

```bash
./.venv/bin/python -m pytest -q tests/test_agency_bundle_v01.py tests/test_acceptance_bundle_v01.py
./.venv/bin/python -m compileall -q src tests/test_agency_bundle_v01.py
git diff --check
git add src/openworkproof/agency_bundle.py tests/test_agency_bundle_v01.py
git commit -m "feat: export offline human agency bundles"
```

---

## Task 7：冻结独立 schema registry 与公开 API

**Files:**
- Create: `src/openworkproof/agency_schema_registry.py`
- Create: `src/openworkproof/schemas/agency-v0.1/human-agency-profile.schema.json`
- Create: `src/openworkproof/schemas/agency-v0.1/agency-profile-transition.schema.json`
- Create: `src/openworkproof/schemas/agency-v0.1/agency-appeal.schema.json`
- Create: `src/openworkproof/schemas/agency-v0.1/schema-registry.json`
- Create: `tests/test_agency_schema_registry_v01.py`
- Modify: `src/openworkproof/__init__.py`
- Modify: `pyproject.toml`

- [ ] **Step 1: 写 registry RED 测试**

断言生成内容与 packaged bytes 完全一致、registry 路径 UTF-8 排序、SHA-256 正确、未知对象
fail closed、wheel 安装后 `importlib.resources` 可读取；同时确认主 v0.1 registry digest 不变。

- [ ] **Step 2: 实现独立 registry 并生成 schema**

不要把 agency 对象塞进已有 `_FROZEN_V01_DIGESTS`。提供：

```python
generate_agency_schemas(destination: Path) -> None
authoritative_agency_schema(object_type: str) -> bytes
verify_packaged_agency_schemas() -> None
```

- [ ] **Step 3: 增加最小懒加载 API**

公开模型、commit/load、protected authorization、bundle export/verify；不要导出 evidence 私有锁
函数或内部 SQL helper。

- [ ] **Step 4: 运行测试与提交**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_agency_schema_registry_v01.py \
  tests/test_schema_registry.py \
  tests/test_package_installation.py
./.venv/bin/python -m build
./.venv/bin/python -m pip check
git diff --check
git add src/openworkproof/agency_schema_registry.py src/openworkproof/schemas/agency-v0.1 \
  src/openworkproof/__init__.py pyproject.toml tests/test_agency_schema_registry_v01.py
git commit -m "feat: publish human agency profile schemas"
```

---

## Task 8：文档、双语边界与使用样例

**Files:**
- Modify: `README.md`
- Modify: `README_en.md`
- Modify: `docs/status.md`
- Create: `docs/protocol/human-agency-profile-v0.1.md`
- Create: `examples/human_agency_profile_v01.py`
- Modify: `tests/test_documentation_boundaries.py`

- [ ] **Step 1: 写文档边界 RED 测试**

禁止把该能力写成法律合规、自动担责、员工评分、资金托管、客户采用或已产生收入。中英文
必须同时说明：profile 是可验证授权边界；appeal 不恢复权限；Acceptor 才能替换/撤销。

- [ ] **Step 2: 编写最小可运行样例**

样例只演示生成 WorkOrder-bound profile、签名、验证、判定 reserved tool；不得生成真实私钥
文件或暗示生产部署。

- [ ] **Step 3: 更新 README 与 status**

README 只增加一段实验能力入口、三条事实和链接。`docs/status.md` 使用 fresh test count，
并保持 `customer_adoption/payment/upstream_adoption = not_evidenced`，除非出现独立外部证据。

- [ ] **Step 4: 运行测试与提交**

```bash
./.venv/bin/python examples/human_agency_profile_v01.py
./.venv/bin/python -m pytest -q \
  tests/test_documentation_boundaries.py \
  tests/test_agency_models_v01.py \
  tests/test_agency_end_to_end_v01.py
./.venv/bin/python -m compileall -q src examples
git diff --check
git add README.md README_en.md docs/status.md docs/protocol/human-agency-profile-v0.1.md \
  examples/human_agency_profile_v01.py tests/test_documentation_boundaries.py
git commit -m "docs: explain verifiable human agency boundaries"
```

---

## Task 9：全量门、供应链绑定与分支收口

**Files:**
- Modify only if required: `supply-chain/images/trusted-helper/SOURCE_ALLOWLIST`
- Create only if required: `supply-chain/images/candidates/<revision>.json`
- Modify: `docs/status.md`
- Modify: this plan (checkboxes only after evidence exists)

- [ ] **Step 1: 运行 agency focused 门**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_agency_models_v01.py \
  tests/test_agency_history_v01.py \
  tests/test_agency_policy_v01.py \
  tests/test_agency_ledger_v01.py \
  tests/test_agency_bundle_v01.py \
  tests/test_agency_end_to_end_v01.py \
  tests/test_agency_schema_registry_v01.py
```

Expected：0 failed、0 skipped；记录真实 passed 和退出码。

- [ ] **Step 2: 运行相邻协议回归**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_policy.py \
  tests/test_mcp_server.py \
  tests/test_repo_read_transaction.py \
  tests/test_retraction_receipt_v05.py \
  tests/test_acceptance_bundle_v01.py \
  tests/test_schema_registry.py
```

- [ ] **Step 3: 运行 candidate 两套件**

先按仓库现有命令确认 candidate inventory 是否唯一绑定当前 source allowlist revision。若
只因本分支修改了 allowlist 内文件而失配，按既有不可变流程生成新 inventory；不得改写历史
inventory，也不得把失败称为外部噪音。

- [ ] **Step 4: 运行 required-live 全量门**

使用仓库当前文档中的 required-live Docker 命令，不从旧报告复制测试数。要求：退出码 0、
0 failed、0 skipped、严格线程告警开启。记录耗时与 Docker 容器/卷残留。

- [ ] **Step 5: 非测试验证**

```bash
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests examples
git diff --check
git status --short
```

- [ ] **Step 6: 更新事实状态并提交**

只把本轮 fresh 结果写入 `docs/status.md`；计划 checkbox 只勾选有日志证据的步骤。

```bash
git add docs/status.md docs/superpowers/plans/2026-08-24-openworkproof-human-agency-profile-v01-implementation.md \
  supply-chain/images/trusted-helper/SOURCE_ALLOWLIST supply-chain/images/candidates
git commit -m "docs: close human agency profile verification"
```

若 supply-chain 路径未变化，不要为了命令整齐而产生空修改。

- [ ] **Step 7: 审核与集成选择**

按 `requesting-code-review` 做独立审查，优先检查：默认兼容、handler 前拒绝、全表零写入、
appeal 不授权、Acceptor 绑定、fork/cycle fail closed、bundle 无私钥、旧 schema digest 不变。
修复 P1/P2 后重新过对应门。最后使用 `finishing-a-development-branch`，由用户明确选择
合并、推送或保持分支；不得把本地绿灯写成远端已合并。

---

## Final Checklist

- [ ] WorkOrder v0.1、CapabilityGrant 与旧 schema digest 完全未变。
- [ ] 旧执行 API 默认语义未变，新 profile 仅在 opt-in protected API 生效。
- [ ] WorkOrder ∩ Grant ∩ profile 三层均允许才执行。
- [ ] reserved tool 在 handler 前拒绝，handler 0 calls，全表零写入。
- [ ] appeal 可验证但不授权；只有 Acceptor transition 改变 current profile。
- [ ] supersede/revoke 链对 fork、cycle、缺失对象、多终点和时间倒流 fail closed。
- [ ] COMMIT-ACK 丢失可 exact readback；不确定时显式 indeterminate。
- [ ] bundle 无私钥、可离线验证、确定性、抗路径与篡改攻击。
- [ ] 中英文文档不宣称法律结论、客户采用、付款、托管或市场已成立。
- [ ] focused、adjacent、candidate、required-live 与非测试门均有 fresh 证据。
- [ ] 工作树干净；本地提交、远端推送、合并状态分别报告。
