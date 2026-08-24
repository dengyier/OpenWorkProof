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
>
> **2026-08-24 mixed-mode recovery：** run-tests journal 的受保护预约写入 Sidecar 签名的
> canonical agency-binding envelope（内置签名域 `openworkproof/handler-agency-binding/v0.1`，
> 仅限 v0.1），至少绑定 domain/claim type、`work_order_digest`、`execution_id`、
> `request_digest`、`authorization_prefix_digest`、agency marker、controller/signer key id 与
> `reserved_at`；load/recovery 按权威 WorkOrder 的精确 Sidecar KeyBinding 校验，身份不匹配、
> 非 canonical/重复键/超限 JSON、错误角色或密钥、digest/signature 无效一律 fail closed。
> 固定 exact marker `openworkproof/handler-agency-bound/v0.1` + 域分离 digest
> `openworkproof/authorization-ledger-prefix-agency/v0.1` 仅作 defense-in-depth；legacy 与
> repo-read/rollback 存 NULL 并沿用 `openworkproof/authorization-ledger-prefix/v0.1`。受保护
> caller 恢复 legacy-unbound 的 CLOSED_RESULT/ABSENT 时，先发布 receipt、cleanup、删除
> journal，再抛 `HandlerCoordinationError('AGENCY_UNBOUND_RECOVERY')`；恢复 agency-bound 时不
> 重复调用 callback。schema 迁移：空表按原样 drop/rebuild；非空的 V3（紧邻前一个可信无标记
> schema）行原子重建为 unbound 并保留；V4（紧邻前一个 unsigned-marker schema）非空
> NULL-marker 行原子重建为 unbound 并保留，非空非 NULL-marker 行 fail closed（绝不伪造签名）；
> V2 及更旧 schema 的非空行保持 fail closed。agency binding 是 recovery 内部控制，ActionReceipt
> 本身不携带 Agency 证明。Task5 Steps 1–3 仅在全部新增测试通过时保持勾选。

**Files:**
- Create: `tests/test_agency_end_to_end_v01.py`
- Modify: `src/openworkproof/mcp_server.py`
- Modify: `src/openworkproof/agency_policy.py`

- [x] **Step 1: 拆出 profile-only 判定并写 RED 测试**

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

- [x] **Step 2: 在现有三个 executor 的同一锁域接入 callback**

为 `execute_repo_read`、`execute_run_tests`、`execute_rollback` 增加仅关键字可选参数：

```python
agency_authorize: Callable[[], PolicyDecision] | None = None
```

三个 executor 对全新 action（A）都必须在已持有 target lock、existing context 与基础授权
通过之后，且在任何 preflight、reservation、handler 或 receipt 写入之前执行：

```python
if agency_authorize is not None:
    agency_decision = agency_authorize()
    if not agency_decision.allowed:
        raise ToolCallDenied(agency_decision)
```

先前已 RESERVED / STARTED_UNCONFIRMED action 的 reconciliation/finalization（B）不针对
当前 profile 重新授权，而是重放存储的 request truth；幂等的 bookkeeping/schema/evidence
recovery（C）可在本次请求的 agency 门之前发生，因此 callback 不再声明先于
prior-action recovery/repair。

callback 必须延迟加载 ledger history；不得在 executor 加锁前捕获 profile 快照。默认
`None` 的旧调用路径必须通过原有测试，证明默认语义不变。

- [x] **Step 3: 写锁内原子性与撤销竞态测试**

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

- [x] **Step 4: 实现真实 `execute_apply_patch` 事务入口**

签名沿用现有 executor 风格：接收 ledger/evidence root、`AuthorizationContext`、签名
`AgentRequest`、`ApplyPatchArguments`、`ProspectiveExecutionFacts`、Sidecar 私钥、candidate
workspace handler 与 trusted clock，并提供同样的 `agency_authorize=None` opt-in seam。

实现必须复用 `repo_tools.apply_patch_in_candidate_workspace`，并完成：current-context → 基础
authorization → profile callback → receipt 容量 preflight → handler reservation/started →
patch handler → `PatchResultEvidence` 与 patch/result EvidenceRefs → Sidecar 签名 receipt →
`complete_receipt_publication(..., _borrowed_lock_descriptor=lock_descriptor)` → cleanup/recovery。
不得复制测试中的手工 receipt fixture 作为生产实现；COMMIT-ACK、STARTED_UNCONFIRMED、
handler failure 与 cleanup failure 语义要与 repo-read/run-tests/rollback 对齐。

> **2026-08-24 已实现（commit `feat: execute protected apply patch`）：**
> `execute_apply_patch` 复用 `repo_tools.apply_patch_in_candidate_workspace` 与
> `PatchRequest`/`PatchResult`，按 repo-read/rollback 同一锁域执行 current-context →
> 基础授权 → agency callback → patch receipt preflight → reservation/started →
> handler → `PatchResultEvidence` + patch/result EvidenceRefs → Sidecar 签名 receipt →
> `complete_receipt_publication(..., trusted_resolution_manifest=..., _borrowed_lock_descriptor=...)`
> → journal cleanup。签名校验 `request.tool_name` 与 `arguments_digest` 精确一致，
> patch 字节 digest/size 与 `ApplyPatchArguments` 精确一致，Sidecar key 匹配 controller。
> handler journal 新增 V6 schema（`tool_name` 增加 `owp.apply_patch`，repo-read/rollback
> 分支同列扩为 `owp.apply_patch`，二者 agency 域均为 NULL），V5（紧邻前一个签名绑定
> schema）非空行原子重建并逐列保留（不伪造签名），空表 drop/rebuild；旧 V3/V4 及更旧
> predecessor 行为不变。apply_patch 与 repo-read/rollback 同为非 typed-driver 工具，其
> recovery (B) 走 `_recover_handler_executions`（RESERVED 无 receipt → 清理 C；
> STARTED_UNCONFIRMED + committed receipt → finalize B），不针对当前 profile 重新授权，
> 不产生 mixed-mode 歧义，故无需 run-tests 的 Sidecar 签名 agency binding；ActionReceipt
> 本身仍不携带 Agency 证明。覆盖测试：真实 temp workspace 成功、reserved deny 零
> handler/零业务写入、superseded allow、revoke deny、handler failure、pre-COMMIT 零写入、
> COMMIT-ACK recovery、STARTED_UNCONFIRMED 无 callback recovery、cleanup failure 保留
> committed truth、patch digest drift fail closed、并发恰好一个结果、V5→V6 迁移、旧路径
> 不受影响。focused：apply-patch/agency/mcp/repo-read 120 passed；policy/agency/sandbox
> 532 passed 4 skipped；delivery_m2/receipt_chain 418 passed；全量 4121 passed 2 failed
> 8 skipped（2 failed 均为既有 `test_current_candidate_inventory_binds_*`，candidate
> definition 含 `evidence.py`，本分支早期 agency 提交已改变其字节，历史 inventory 0
> match，需 Task 9 重建 candidate inventory，非 Step 4 回归）；`pip check`/`compileall`/
> `git diff --check` PASS。
>
> > **2026-08-24 review-blocker 修复（commit `fix: verify apply patch authority and
> > postconditions`）：**
> > 补齐两处 review blocker，未实现 dispatcher/bundle/schema registry、未 merge/push、
> > 未大范围重构。P1-1 授权先行：`execute_apply_patch` 现把 `execution_facts` 传入
> > v0.1 `authorize_tool_call` 与 v0.4 `_require_bound_action`，policy 在 handler 前证明
> > `controller_id` 是权威 WorkOrder 的 Sidecar key（非 Sidecar 合法角色 key：v0.1
> > `AuthorizationPolicyError`、v0.4 `ToolCallDenied(AUTH_SUBJECT_MISMATCH)`，先于 agency
> > callback 与 handler，工作区/业务表零变化），Sidecar 私钥↔controller 显式校验保留。
> > P1-2 不可信 handler postcondition：新增公开
> > `repo_tools.validate_patch_result_against_candidate`，handler 返回后、证据/receipt
> > 发布前独立重算并比对全部 `PatchResult`/`PatchResultEvidence` 字段（含 changed_paths），
> > 并校验 live candidate workspace 恰在期望 head/tree/manifest、无多余/隐藏改动；伪造
> > 自洽 result、伪造 commit/manifest/changed_paths、额外未声明路径写入均
> > `RECOVERY_REQUIRED` 且不发布 receipt。agency superseded-allow 与并发测试改用真实
> > repo_tools handler。P2 测试证据：新增真实 COMMIT-ACK-loss（真提交后丢 ACK，重试
> > 收敛为一条 committed receipt 且不重跑 handler）与真实 pre-COMMIT 注入（commit 前抛错，
> > 业务表/证据零写入、仅保留 journal bookkeeping，且与 handler 失败区分）；V5→V6 迁移
> > 测试升级为保留真正非 NULL 的 Sidecar 签名 run-tests agency_binding + canonical
> > agency_binding_json 并证明后续 load/verification。focused：apply-patch/agency/mcp/
> > repo-read 129 passed；policy/agency/sandbox 560 passed 4 skipped；recomposition/
> > receipt_chain/binding 588 passed；全量 4130 passed 2 failed 8 skipped（2 failed
> > 均为既有 `test_current_candidate_inventory_binds_*`，需 Task 9 重建）。后续独立
> > review 未发现 P0/P1/P2，Task5 实现切片 READY；分支发布仍受 Task 9 inventory 重建约束。
>
> > **2026-08-24 Owner 威胁模型边界 + Task5 Step4 audit closure（本 commit）：**
> > `execute_apply_patch` 的 receipt 只认证不可变 Git candidate commit 与由 patch evidence
> > 派生的确定性 manifest（内容寻址证据），不承诺可变 worktree 在验证后永久保持干净。
> > handler 是受信任的同步进程内适配器，可能失败或返回伪造/错误数据；敌意 handler 派生
> > 延迟子进程、或同用户/root 的带外进程改写/删除 workspace/Git store，都在本 coordinator
> > 的隔离边界之外——不声称能阻止敌意 OS 进程。后续动作必须重新校验当前 candidate
> > checkpoint 并在 drift 时 fail closed：下一条 candidate 操作在
> > `_verify_candidate_checkpoint` 处先于任何 patch 应用拒绝。本切片不添加投机性的
> > workspace lock 或 sandboxing。
> >
> > P2 测试证据补齐：新增 `test_execute_apply_patch_precommit_insert_failure_rolls_back_exactly`
> > ——monkeypatch `evidence._insert_receipt_and_publication_group` 先调用真实 insert、再于
> > SQLite COMMIT 前抛 `sqlite3.OperationalError`，断言 receipt/receipt_parents/
> > evidence_publications/sequence/state/grant-event 业务行精确回滚（`_business_tables`
> > 与逐表计数均等于 before），handler journal 保持 STARTED_UNCONFIRMED，真实 workspace
> > 已含不可变 patch，孤儿 pending evidence 由 `recover_evidence_publications` 幂等清理；
> > 与 staging-entry 失败（`stage_pending_evidence_group` 注入）明确区分。另新增
> > `test_execute_apply_patch_rejects_workspace_drift_before_next_candidate_operation`
> > ——成功 receipt 后带外写漂移 worktree，下一条 candidate 操作
> > (`apply_patch_in_candidate_workspace`) 在 `_verify_candidate_checkpoint` 处先于任何
> > patch 应用拒绝 drift，认证 commit 不被改写。

- [x] **Step 5: 实现最小 protected dispatcher 与完整状态链**

支持设计 §7 的 `owp.repo_read`、`owp.apply_patch`、`owp.run_tests` 与
`owp.rollback_patch`。dispatcher 不持锁、不预加载 history，只按签名
`request.tool_name` 选择 executor，并向 executor 传入延迟 callback。不得接收独立
`tool_name` 或 `now`；未知工具 fail closed。

同一测试依次证明：repo-read allowed；apply-patch reserved；appeal 后仍 reserved；Acceptor
supersession 后 apply-patch allowed；revoke 后所有 protected tool 返回
`AGENCY_PROFILE_REQUIRED`。同时回归旧 `execute_repo_read`，证明未选择新入口时行为不变。

> **2026-08-24 已实现（本 commit，`feat: dispatch protected agent actions`）：**
> `mcp_server.py` 新增 `dispatch_protected_agent_action` + 四个 typed keyword bundle
> （`RepoReadDispatch`/`ApplyPatchDispatch`/`RunTestsDispatch`/`RollbackDispatch`）。dispatcher
> 不持锁、不预加载 history、不做 base/agency 授权，只按签名 `request.tool_name` 路由并校验
> bundle 形状（未知工具 / 错配 / 缺失 / 多余 bundle 均 fail closed，无 handler 副作用）；时间只
> 来自 `AuthorizationContext.transaction_time`，dispatcher 只转发 `clock`。延迟零参
> `agency_authorize` callback 只捕获 immutable ledger path/context/request，在 executor 已持有
> target lock 的临界区内才调用 `load_agency_history` + `authorize_agency_profile_layer`。测试新增
> 12 条：四工具路由、未知工具、bundle 错配/缺失/多余、v0.1 与 v0.4 路由、非 AgentRequest 拒绝、
> apply-patch 完整状态链（repo-read allowed → apply-patch reserved 零 handler/零写入 → appeal 仍
> denied → supersede 真实 patch allowed → revoke 后 resolved status=revoked）、revoke 后四工具全部
> `AGENCY_PROFILE_REQUIRED` 且 handler/driver 零调用零写入、确定性 history-loader-在锁内 proof
> （非阻塞 flock probe，无 sleep）。focused：agency end-to-end `40 passed`；agency-policy/policy/
> repo-read/apply-patch `144 passed`；mcp/binding/recomposition `126 passed`；`pip check`/`compileall`/
> `git diff --check` PASS。独立 review 未发现 P0/P1/P2，Task 5 实现切片 READY；全量
> inventory boundary（`test_current_candidate_inventory_binds_*`）仍需 Task 9 重建后才能发布。

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
>
> **2026-08-24 Owner 决策（独立审查 P1 修复，Sidecar snapshot attestation）：** 原 manifest
> 未签名，攻击者可无钥删除 revoke/supersede 后缀并重写 `evaluated_at`/status。修复采用
> WorkOrder 内 Sidecar key binding 作为自包含 snapshot attestation：
> `AgencyBundleManifestV01` 改为 `SignedProtocolModel`，`_signed_domain="manifest"` v0.1，
> 包含 digest/signature_alg/signer_key_id/signature；`export_agency_bundle` 必须显式接收
> `sidecar_private_key: Ed25519PrivateKey`（不得默认/环境读取），`compose_agency_manifest`
> 也必须显式签名；验证器加载并验证 WorkOrder identity bindings 后，只接受 Sidecar role
> binding 并 `verify_payload("manifest", ...)`。manifest signature 覆盖 `work_order_digest`、
> `evaluated_at`、`current_status`、`current_profile_id`、`boundary` 和全部 `entries`
> （path/SHA-256/size），不加无效自哈希。错误角色/伪签名/篡改 manifest/截断合法 supersede
> 链/删除 revoke 后缀/重写 evaluated_at+status 均 fail closed。Sidecar 签名固定“声称的
> evaluated_at”，但不证明真实世界时间——仍非 TSA，仅内容寻址且不可伪造。

**Files:**
- Create: `src/openworkproof/agency_bundle.py`
- Create: `tests/test_agency_bundle_v01.py`

- [x] **Step 1: 写 boundary bundle RED 测试**

覆盖 active/revoked/expired、固定 clock 下确定性双导出、无私钥、
symlink/hardlink/path traversal、额外文件、缺文件、WorkOrder/profile/transition/appeal 任一
字节篡改、签名有效但链 fork、manifest 摘要篡改、manifest 状态与重新解析结果不一致。

- [x] **Step 2: 实现闭合 manifest 与结果**

```python
class AgencyBundleManifestV01(SignedProtocolModel):
    _signed_domain = "manifest"
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

- [x] **Step 3: 实现确定性导出和纯离线验证**

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
即为验签公钥来源。manifest 由 WorkOrder Sidecar key 签名（snapshot attestation），验证器
在验证 identity bindings 后只接受 Sidecar role binding 并 `verify_payload("manifest", ...)`；
`compose_agency_manifest` 与 `export_agency_bundle` 都必须显式接收 `sidecar_private_key`，
verify.sh/CLI 只用于验证、不含私钥。

额外/缺失文件、非普通文件、symlink、`st_nlink != 1`、路径越界、非 canonical JSON、摘要
或 size 不符、跨 WorkOrder、错误签名、引用缺失、fork/cycle/disconnected/time reversal、
appeal 目标不一致和重算状态不一致全部 fail closed。结果必须保留非法律/雇佣判断边界。

- [x] **Step 4: 运行测试与提交**

```bash
./.venv/bin/python -m pytest -q tests/test_agency_bundle_v01.py tests/test_acceptance_bundle_v01.py
./.venv/bin/python -m compileall -q src tests/test_agency_bundle_v01.py
git diff --check
git add src/openworkproof/agency_bundle.py tests/test_agency_bundle_v01.py
git commit -m "feat: export offline human agency bundles"
```

> **2026-08-24 已实现（commit `feat: export offline human agency bundles`）：**
> 新增 `src/openworkproof/agency_bundle.py` 与 `tests/test_agency_bundle_v01.py`。manifest
> 与 result 模型精确落地（`AgencyBundleManifestV01`/`AgencyBundleVerificationResultV01` +
> `AgencyBundleManifestEntryV01`，boundary 固定为
> `authorization evidence, not legal or employment judgment`）；允许布局精确为
> `agency-manifest.json`、`agency/work-order.json`、`agency/profiles/<id>.json`、
> `agency/transitions/<id>.json`、`agency/appeals/<id>.json`、`verify.sh`。导出在 target
> lock 内用 trusted clock 冻结 canonical UTC second `evaluated_at`，用
> `resolve_human_agency_profile_structure` + 时间窗重算 active/revoked/expired 与
> current profile；写入走 staging + fsync + no-replace rename。验证器纯离线：只信
> manifest 与文件字节，从 WorkOrder key bindings 验签，不接受独立 `now`、不访问
> ledger/网络/环境私钥/系统时间；额外/缺失文件、非普通文件、symlink、`st_nlink != 1`、
> 路径越界、非 canonical JSON、摘要/size 不符、跨 WorkOrder、错误签名、引用缺失、
> fork/cycle/disconnected/time reversal、appeal 目标不一致、manifest status/digest 与
> 重算不一致全部 fail closed。
>
> 测试矩阵覆盖 active/revoked/expired 导出、固定 clock 双导出字节一致、无私钥（逐字节
> 扫描私钥 raw bytes + PEM 头）、symlink/hardlink/path traversal、额外/缺失文件、
> WorkOrder/profile/transition/appeal 逐对象字节篡改、manifest entry digest 篡改、
> manifest status/work_order_digest 与重算不一致、非 canonical JSON、错误 verify.sh、
> 有效签名下的 multiple-genesis/fork（多出边）/cycle/disconnected-cycle/missing
> replacement/time reversal、appeal 目标不一致、跨 WorkOrder profile、closed model。
> RED 为 `ModuleNotFoundError`；GREEN：`tests/test_agency_bundle_v01.py` 30 passed；
> 计划 Step 4 门 `test_agency_bundle_v01.py + test_acceptance_bundle_v01.py` 104 passed
> （30 + 74 acceptance regression）；agency focused 回归（models/history/policy/ledger/
> end_to_end）139 passed；`pip check`/`compileall`/`git diff --check` PASS。
>
> > **2026-08-24 独立审查 P1/P2 修复（未提交，工作树）：** manifest 改为 Sidecar snapshot
> > attestation（见本 Task 头部 Owner 决策）。`AgencyBundleManifestV01` 改为
> > `SignedProtocolModel`（`_signed_domain="manifest"` v0.1），`compose_agency_manifest` 与
> > `export_agency_bundle` 均显式接收并校验 `sidecar_private_key`，验证器只接受 Sidecar role
> > binding 并 `verify_payload("manifest", ...)`；删除 unused import `openworkproof.evidence`。
> > 补 RED→GREEN 回归 9 条：wrong role signer/export 拒绝、signed p1→p2 bundle 删后缀无钥重建
> > 拒绝、revoked 删 revoke 回滚拒绝、evaluated_at/status coherent rewrite 拒绝、manifest
> > 签名字节/签名者篡改拒绝、verifier monkeypatch ledger/system time/network/private-key 纯净性；
> > 保留 extra empty directory RED test 与 `_scan_tree` 精确目录集合修复。GREEN：
> > `tests/test_agency_bundle_v01.py` `39 passed`；bundle+acceptance `113 passed`；
> > agency focused（models/history/policy/ledger/bundle/end_to_end）`178 passed`；
> > `pip check`/`compileall`/`git diff --check` PASS。第二轮独立 review 未发现 P0/P1/P2，
> > Task 6 实现切片 READY。更早但签名有效的 bundle 仍是其 `evaluated_at` 时刻的历史快照，
> > 消费方须自行执行新鲜度策略；离线验签不声称 TSA 或抗旧快照重放。未 commit、未 push；
> > Task 7 未扩大。

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

- [x] **Step 1: 写 registry RED 测试**

断言生成内容与 packaged bytes 完全一致、registry 路径 UTF-8 排序、SHA-256 正确、未知对象
fail closed、wheel 安装后 `importlib.resources` 可读取；同时确认主 v0.1 registry digest 不变。

- [x] **Step 2: 实现独立 registry 并生成 schema**

不要把 agency 对象塞进已有 `_FROZEN_V01_DIGESTS`。提供：

```python
generate_agency_schemas(destination: Path) -> None
authoritative_agency_schema(object_type: str) -> bytes
verify_packaged_agency_schemas() -> None
```

- [x] **Step 3: 增加最小懒加载 API**

公开模型、commit/load、protected authorization、bundle export/verify；不要导出 evidence 私有锁
函数或内部 SQL helper。

- [x] **Step 4: 运行测试与提交**

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

> **2026-08-24 已实现（本 commit，`feat: publish human agency profile schemas`）：**
> 新增 `src/openworkproof/agency_schema_registry.py` 与
> `src/openworkproof/schemas/agency-v0.1/`（`human-agency-profile.schema.json`、
> `agency-profile-transition.schema.json`、`agency-appeal.schema.json`、
> `schema-registry.json`）与 `tests/test_agency_schema_registry_v01.py`。独立 registry
> 只冻结计划列出的三种 Acceptor 签名协议对象 schema，registry schema_version 为
> `openworkproof-agency-schema-registry/0.1`，`protocol_version=0.1`，entries 按
> object_type UTF-8 排序且每条精确 SHA-256，无自引用；**未触碰**
> `schema_registry._FROZEN_V01_DIGESTS`、主 v0.1 `schema-registry.json` digest，也未把
> agency 对象加入任何 v0.1–v0.5 `_OBJECT_PATHS_BY_VERSION`。实现
> `generate_agency_schemas(destination)`（single-target 安全事务：resolved-target
> preflight、lock、staging 读回校验、backup/commit/rollback、COMMIT-ACK 精确读回、cleanup）、
> `authoritative_agency_schema(object_type) -> bytes`（未知对象 `ValueError` fail closed，
> 返回 canonical bytes）与 `verify_packaged_agency_schemas()`（`importlib.resources`
> 读 `schemas/agency-v0.1` 并与确定性生成锚点逐字节比对，漂移/缺文件/非 canonical 均
> `RuntimeError`）。`__init__.py` 新增最小懒加载公开 API：Agency 三模型
> （`HumanAgencyProfileV01`/`AgencyProfileTransitionV01`/`AgencyAppealV01`）、
> commit/load 六函数、`authorize_tool_call_with_agency_profile` +
> `dispatch_protected_agent_action`、`export_agency_bundle` +
> `verify_agency_bundle_directory` + `AgencyBundleManifestV01` +
> `AgencyBundleVerificationResultV01`；未导出 evidence 私有锁/SQL helper。`pyproject.toml`
> package-data 追加 `schemas/agency-v0.1/*.json`，无新增依赖。
>
> > **边界：** `AgencyBundleManifestV01` 现为 Sidecar 签名模型，但 Task 7 只冻结计划列出的
> > 三种 agency 对象 schema，未擅自加入 bundle schema（计划 Step 2 签名未列 bundle）。
> > 计划 Step 4 命令引用 `tests/test_package_installation.py`，但仓库实际文件为
> > `tests/test_package.py`（package/version/installation 契约测试），按实际文件执行。
> >
> > fresh 测量（本轮控制器 fresh，未复用历史数字）：`tests/test_agency_schema_registry_v01.py`
> > `17 passed`；计划 Step 4 门 `test_agency_schema_registry_v01.py + test_schema_registry.py +
> > test_package.py` `60 passed`；agency focused 七文件门 `195 passed`；相邻协议回归
> > （policy/mcp_server/repo_read/retraction/acceptance_bundle/schema_registry）`309 passed`；
> > `python -m build` 成功产出 `openworkproof-1.3.0-py3-none-any.whl` 与 sdist，wheel 内含全部
> > 4 个 agency schema 资源；wheel `--no-deps --target` 隔离安装后
> > `importlib.resources`/`authoritative_agency_schema`/`verify_packaged_agency_schemas`
> > 全部可读且 sha256 一致；`pip check`/`compileall`/`git diff --check` PASS。全量
> > inventory boundary（`test_current_candidate_inventory_binds_*`）仍待 Task 9 重建，本
> > Task 未改 main、未 push、未重建 candidate inventory、未做 Task 8。
>
> > **2026-08-24 独立审查 P2 修复（commit `fix: recover agency schema publish acks`）：**
> > 修复 Task 7 两个 P2，只做最小修改，未改 schema bytes/registry digest/公开集合本身，未做
> > Task 8/重建 inventory/main/push。P2-1：`_commit_staged_directories` 的
> > `target.replace(backup)` 在已真实落地却抛 OSError（ACK loss）时未记录 backup，导致本次
> > 失败后 target 缺失。现采用与 stage→target 相同的 readback 式 committed-truth 判断：仅当
> > `target` 不存在且预期 backup 已作为目录存在时记录已移动并继续事务；歧义 fail closed 且
> > 由既有 rollback/cleanup 收敛。补两条故障注入（monkeypatch `Path.replace` 仅对旧
> > target→backup 真实 replace 后抛 OSError；backup rename 真失败未落地），断言收敛到完整新
> > target 或精确恢复旧 target，且不残留 target 缺失/backup/stage/lock。P2-2：`__init__.py`
> > 新增 side-effect-free `__dir__`（`sorted(set(globals()) | set(__all__))`），fresh import 与
> > installed wheel 上 `dir(openworkproof)` 包含全部 `__all__`（含新增 15 项 agency 导出），
> > 不触发 lazy import，`__all__`/`__getattr__`/`__dir__` 一致。
> >
> > fresh 测量（本轮控制器 fresh，未复用历史数字）：`tests/test_agency_schema_registry_v01.py`
> > `20 passed`；计划 Step 4 门 `test_agency_schema_registry_v01.py + test_schema_registry.py +
> > test_package.py` `64 passed`；agency focused 七文件门 `198 passed`；主/companion registry
> > 回归 `61 passed`；并发 `test_supersession_concurrency_yields_single_winner` `1 passed`；
> > 相邻协议回归（policy/mcp_server/repo_read/retraction/acceptance_bundle/schema_registry）
> > `309 passed`；`python -m build` 成功；wheel `--no-deps --target` 隔离安装后
> > `dir(openworkproof)`/`importlib.resources`/`verify_packaged_agency_schemas` 全绿；
> > `pip check`/`compileall`/`git diff --check` PASS。全量 inventory boundary
> > （`test_current_candidate_inventory_binds_*`）仍待 Task 9 重建，本 commit 未改 main、
> > 未 push、未重建 candidate inventory、未做 Task 8。
>
> > **2026-08-24 独立审查 P1 修复（commit `fix: constrain agency schema contracts`）：**
> > Task 7 的 agency v0.1 JSON Schema 此前太浅：纯 Pydantic `model_json_schema` 对
> > digest/key/signature/time 只输出裸 `type: string`，`Draft202012Validator` 接受明显畸形
> > 对象。本 commit 只在 `src/openworkproof/agency_schema_registry.py` 对三个独立 agency schema
> > 做确定性 post-processing 约束增强并重新生成 packaged schema 与独立 registry，未改 core
> > `models.py`、既有主 schema registry v0.1、Task 8、candidate inventory、main 或远端：
> >
> > - 可表达约束进生成 pipeline（确定性）：Digest/ID/nonce `pattern ^[0-9a-f]{64}$`；
> >   `signer_key_id` `pattern ^ed25519:[0-9a-f]{64}$`；`signature`
> >   `pattern ^[A-Za-z0-9_-]{86}$`；canonical UTC 时间戳 `format date-time` +
> >   `pattern ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`；非空标识符
> >   `minLength 1`、`appellant_subject_id` `maxLength 128`。
> > - `HumanAgencyProfileV01`：`delegated_actions` 与 `reserved_decisions` 至少一边非空
> >   （`anyOf`）；`reserved_decisions` `maxItems 5`；集合型数组 `uniqueItems true`；
> >   `appeal_roles` 固定顺序 `prefixItems`+`const`+`min/max 3`；保留 `additionalProperties false`。
> > - `AgencyProfileTransitionV01`：`if/then` 约束 `revoked` => replacement 均 `null`；
> >   `superseded` => 均为 Digest64 字符串；`replacement != target` 写入 `$comment`（语义）。
> > - `AgencyAppealV01`：digest/key/signature/time/nonce 与唯一性同样收紧。
> > - 每个根 schema 与 `$defs` 带 `$comment` 声明 structural schema + mandatory semantic
> >   validation 边界，不伪装无法表达的语义。
> >
> > RED 测试（`tests/test_agency_schema_constraints_v01.py`，新增）直接用
> > `jsonschema.Draft202012Validator`、不调用 Pydantic；恶意 transition（坏
> > digest/signature/time/replacement）、revoked 携带 replacement、superseded 缺 replacement、
> > bad digest/key/signature/time 逐类、delegated+reserved 都空、reserved>5、appeal_roles
> > 错角色/错顺序、可表达重复项均拒绝；合法 packaged 实例仍通过；保留一条“结构 schema 通过
> > 但 OpenWorkProof 语义验证拒绝”的边界测试。生成结果确定性、generated bytes == packaged、
> > 独立 registry digest 更新、主 v0.1–v0.5/companion registry 字节完全未变。
> >
> > fresh 测量（本轮控制器 fresh，未复用历史数字）：`test_agency_schema_constraints_v01.py`
> > `37 passed`；`test_agency_schema_registry_v01.py` `20 passed`；agency schema 门
> > `101 passed`；agency focused 八文件门 `235 passed`；主/companion registry 回归 `61 passed`；
> > 相邻协议回归 `309 passed`；`python -m build` 成功；wheel `--no-deps --target` 隔离安装后
> > `verify_packaged_agency_schemas`/`authoritative_agency_schema`/硬化约束全绿；
> > `pip check`/`compileall`/`git diff --check` PASS。未改 main、未 push、未重建 candidate
> > inventory、未做 Task 8。

---

## Task 8：文档、双语边界与使用样例

**Files:**
- Modify: `README.md`
- Modify: `README_en.md`
- Modify: `docs/status.md`
- Create: `docs/protocol/human-agency-profile-v0.1.md`
- Create: `examples/human_agency_profile_v01.py`
- Modify: `tests/test_documentation_boundaries.py`

- [x] **Step 1: 写文档边界 RED 测试**

禁止把该能力写成法律合规、自动担责、员工评分、资金托管、客户采用或已产生收入。中英文
必须同时说明：profile 是可验证授权边界；appeal 不恢复权限；Acceptor 才能替换/撤销。

- [x] **Step 2: 编写最小可运行样例**

样例只演示生成 WorkOrder-bound profile、签名、验证、判定 reserved tool；不得生成真实私钥
文件或暗示生产部署。

- [x] **Step 3: 更新 README 与 status**

README 只增加一段实验能力入口、三条事实和链接。`docs/status.md` 使用 fresh test count，
并保持 `customer_adoption/payment/upstream_adoption = not_evidenced`，除非出现独立外部证据。

- [x] **Step 4: 运行测试与提交**

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

## Task 8 审计修复（commit `fix: correct human agency documentation claims`）

独立审计发现 Task 8 文档切片 3 个 P1 + 1 个 P2，本 commit 只做最小修复，未改协议
代码、main、candidate inventory，未 push、未做 Task 9：

- [x] **P1-1（RED→GREEN）**：新增 `test_human_agency_example_output_is_byte_stable_and_secret_free`
  （连续运行样例两次 stdout 字节完全相同、退出码 0、无随机 digest/id/私钥），
  RED 后删除 `examples/human_agency_profile_v01.py` 对 `work_order_digest`/`profile_id`
  的打印，保留临时随机 Ed25519 密钥但只打印稳定事实
  （`profile verified  : True`、`resolved status   : active`、
  `owp.repo_read : delegated -> allowed`、`owp.apply_patch : reserved ->
  AGENCY_HUMAN_DECISION_REQUIRED` 与边界），输出由实际 tuple 生成并断言。
- [x] **P1-2（RED→GREEN）**：新增 `test_human_agency_protocol_doc_genesis_is_signature_verified`，
  RED 后把 `docs/protocol/human-agency-profile-v0.1.md` 的 "one unsigned genesis
  profile" 改为 "one signature-verified genesis profile with no incoming transition"
  （三种对象均签名）。
- [x] **P1-3（RED→GREEN）**：精确化 `test_human_agency_appeal_records_but_never_restores`
  RED 后把 README_en / protocol 的 "revoke or replace the grant" 改为
  "only an Acceptor-signed transition can revoke the active profile or supersede it
  with another Acceptor-signed profile"；中文 README 改为 "只有 Acceptor 签名的
  transition 才能撤销当前 profile 或将其替换为另一个 Acceptor 签名的 profile"
  （appeal 不改权限）。
- [x] **P2**：`docs/status.md` 不再称"输出稳定/随机摘要输出稳定"，改为"双跑 stdout
  字节一致、只打印稳定事实、无随机 digest/id/私钥"；补一段审计修复 fresh 证据并保留
  `customer_adoption/payment/upstream_adoption = not_evidenced`。

```bash
./.venv/bin/python examples/human_agency_profile_v01.py   # 双跑 stdout 字节一致，退出码 0
./.venv/bin/python -m pytest -q tests/test_documentation_boundaries.py            # 21 passed
./.venv/bin/python -m pytest -q tests/test_documentation_boundaries.py \
  tests/test_agency_models_v01.py tests/test_agency_end_to_end_v01.py             # 86 passed
./.venv/bin/python -m pytest -q tests/test_agency_schema_constraints_v01.py \
  tests/test_agency_schema_registry_v01.py tests/test_package.py                  # 60 passed
./.venv/bin/python -m pip check                       # No broken requirements found
./.venv/bin/python -m compileall -q src tests examples # PASS
git diff --check                                      # PASS
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
