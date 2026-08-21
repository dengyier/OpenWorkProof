# OpenWorkProof Verified Agent Delivery 0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把现有 Surface Bundle、Acceptance Bundle 和 settlement readiness
组合成一个可初始化、检查、验证和导出的单笔 Agent 可验证交付产品，同时保持付款、
客户采用和法律结论在协议边界之外。

**Architecture:** 新增 `delivery_case.py` 作为无数据库、无私钥的薄编排层：订单目录
只保存非敏感别名、外部证据摘要和既有可验证包；每次检查都重新调用底层验证器，
不信任磁盘中的预写状态。CLI、GitHub Action 和 Markdown 摘要只是同一派生结果的
不同视图，不引入第二真相源。

**Tech Stack:** Python 3.10–3.13、Pydantic v2、RFC 8785 JCS、现有
Surface/Acceptance/Settlement 验证器、argparse、GitHub composite action、pytest。

---

## 0. 权威规格、执行边界与目标文件

权威规格：
`docs/superpowers/specs/2026-08-22-openworkproof-verified-agent-delivery-design.md`

执行前从 `main@9ba2e7f` 创建隔离分支。不得在本计划中实现商城、登录、计费系统、
钱包、托管、自动付款、新协议 schema 或客户私钥操作。不得把自有 fixture、测试通过
或本地导出包写成客户采用或付款证据。

每个 Task 固定执行：RED → 最小 GREEN → 相邻回归 → `pip check` → `compileall` →
`git diff --check` → 单一职责 commit。

### 0.1 新建文件

| 文件 | 单一职责 |
|---|---|
| `src/openworkproof/delivery_case.py` | 严格模型、目录初始化、组合验证、原子导出 |
| `src/openworkproof/delivery_case_render.py` | 从验证结果生成确定性 JSON/Markdown 摘要 |
| `tests/test_delivery_case_v01.py` | 模型、初始化、状态推导、篡改、路径与导出测试 |
| `tests/test_delivery_case_cli_v01.py` | parser、退出码、错误输出和隐私边界测试 |
| `integrations/github-delivery-case/action.yml` | 验证现成交付目录并上传结果 |
| `integrations/github-delivery-case/run.sh` | composite action 的闭合退出码脚本 |
| `docs/commercial/verified-agent-delivery/README.md` | 对外可执行的单笔交付说明 |
| `docs/commercial/verified-agent-delivery/client-intake.md` | 客户准入与任务冻结模板 |
| `docs/commercial/verified-agent-delivery/acceptor-checklist.md` | 独立 Acceptor 操作清单 |
| `docs/commercial/verified-agent-delivery/sow-reference.example.json` | 非敏感 SOW 摘要引用样例 |
| `docs/commercial/verified-agent-delivery/payer-status.example.json` | 外部付款证据摘要样例 |

### 0.2 修改文件

| 文件 | 变更 |
|---|---|
| `src/openworkproof/cli.py` | 增加 `delivery-case init/inspect/verify/export` |
| `src/openworkproof/__init__.py` | 懒加载公开只读 API |
| `pyproject.toml` | 不增加依赖；仅在需要时更新 package metadata 关键词 |
| `tests/test_github_action_contract.py` | 新交付目录 Action 的安全与退出码契约 |
| `tests/test_documentation_boundaries.py` | 商业状态、付款与担保边界扫描 |
| `README.md`、`README_en.md` | 增加首个商业产品入口及四条命令 |
| `docs/status.md` | 记录 fresh 测试，不推断商业采用 |
| `supply-chain/images/trusted-helper/SOURCE_ALLOWLIST` | 仅当运行闭包需要新模块时追加精确文件 |
| `supply-chain/images/candidates/<revision>.json` | 若 allowlist 绑定改变，新增不可变库存 |

---

## Task 1：冻结基线并定义 delivery case 闭合模型

**Files:**
- Create: `tests/test_delivery_case_v01.py`
- Create: `src/openworkproof/delivery_case.py`

- [ ] **Step 1: 记录基线并运行相邻套件**

```bash
git status --short --branch
git rev-parse HEAD
./.venv/bin/python -m pytest -q \
  tests/test_surface_bundle_v01.py \
  tests/test_acceptance_bundle_v01.py \
  tests/test_settlement_readiness.py \
  tests/test_cli_transport.py
./.venv/bin/python -m pip check
```

Expected：记录实际 passed/failed/skipped；工作树除已确认设计与计划外无未解释修改。

- [ ] **Step 2: 写模型 RED 测试**

在 `tests/test_delivery_case_v01.py` 写入以下闭合断言：

```python
import pytest
from pydantic import ValidationError

from openworkproof.delivery_case import (
    DeliveryCaseManifestV01,
    ExternalEvidenceReferenceV01,
)


def test_case_manifest_is_closed_and_contains_no_runtime_status() -> None:
    payload = {
        "schema_version": "openworkproof-delivery-case/0.1",
        "case_id": "1" * 64,
        "profile": "coding-agent",
        "buyer_alias": "buyer",
        "delivery_provider_alias": "provider",
        "created_at": "2026-08-22T00:00:00Z",
    }
    case = DeliveryCaseManifestV01.model_validate(payload)
    assert "case_stage" not in case.model_fields
    with pytest.raises(ValidationError):
        DeliveryCaseManifestV01.model_validate({**payload, "case_stage": "ACCEPTED"})


@pytest.mark.parametrize("field", ("reference_digest", "observed_at"))
def test_not_evidenced_reference_cannot_carry_evidence(field: str) -> None:
    payload = {
        "schema_version": "openworkproof-external-evidence/0.1",
        "status": "not_evidenced",
        "reference_digest": None,
        "observed_at": None,
    }
    payload[field] = "2" * 64 if field == "reference_digest" else "2026-08-22T00:00:00Z"
    with pytest.raises(ValidationError):
        ExternalEvidenceReferenceV01.model_validate(payload)
```

- [ ] **Step 3: 运行模型测试确认 RED**

```bash
./.venv/bin/python -m pytest -q tests/test_delivery_case_v01.py -k 'manifest or reference'
```

Expected：FAIL/collection error，原因是 `openworkproof.delivery_case` 尚不存在。

- [ ] **Step 4: 实现最小闭合模型**

在 `src/openworkproof/delivery_case.py` 定义以下公开类型，使用
`ConfigDict(extra="forbid", frozen=True, strict=True,
revalidate_instances="subclass-instances")`：

```python
from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import ConfigDict, model_validator

from openworkproof.models import Digest64, ProtocolModel


_CONFIG = ConfigDict(
    extra="forbid",
    frozen=True,
    strict=True,
    revalidate_instances="subclass-instances",
)


class DeliveryCaseStage(str, Enum):
    SCOPE_DRAFTED = "SCOPE_DRAFTED"
    SOW_REFERENCED = "SOW_REFERENCED"
    READY_FOR_VERIFICATION = "READY_FOR_VERIFICATION"
    VERIFIED = "VERIFIED"
    REFUTED = "REFUTED"
    UNKNOWN = "UNKNOWN"
    READY_FOR_ACCEPTANCE = "READY_FOR_ACCEPTANCE"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    READY_FOR_SETTLEMENT_REVIEW = "READY_FOR_SETTLEMENT_REVIEW"
    EXTERNAL_PAYMENT_EVIDENCED = "EXTERNAL_PAYMENT_EVIDENCED"


class DeliveryCaseManifestV01(ProtocolModel):
    model_config = _CONFIG
    schema_version: Literal["openworkproof-delivery-case/0.1"]
    case_id: Digest64
    profile: Literal["coding-agent"]
    buyer_alias: str
    delivery_provider_alias: str
    created_at: datetime


class ExternalEvidenceReferenceV01(ProtocolModel):
    model_config = _CONFIG
    schema_version: Literal["openworkproof-external-evidence/0.1"]
    status: Literal["not_evidenced", "external_reference_present"]
    reference_digest: Digest64 | None
    observed_at: datetime | None

    @model_validator(mode="after")
    def _closed_reference(self) -> "ExternalEvidenceReferenceV01":
        present = self.status == "external_reference_present"
        if present != (self.reference_digest is not None and self.observed_at is not None):
            raise ValueError("external evidence status and reference must agree")
        return self
```

再增加 `DeliveryCaseResultV01`，字段固定为：`case_id`、`case_stage`、
`verification_decision`、`acceptance_decision`、`settlement_readiness`、
`sow_evidence`、`payment_evidence`、`surface_manifest_digest`、
`acceptance_binding_digest`、排序唯一的 `reason_codes`，以及字面量边界
`not payment, completed settlement, legal audit, or customer adoption`。

- [ ] **Step 5: GREEN、质量门并提交**

```bash
./.venv/bin/python -m pytest -q tests/test_delivery_case_v01.py -k 'manifest or reference'
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests
git diff --check
git add src/openworkproof/delivery_case.py tests/test_delivery_case_v01.py
git commit -m "feat: define verified delivery case models"
```

Expected：模型测试 PASS；提交不包含 CLI、文档或既有协议修改。

---

## Task 2：安全、原子的订单目录初始化

**Files:**
- Modify: `src/openworkproof/delivery_case.py`
- Modify: `tests/test_delivery_case_v01.py`

- [ ] **Step 1: 写初始化 RED 测试**

```python
from datetime import datetime, timezone
import json

from openworkproof.delivery_case import initialize_delivery_case


def test_initialize_case_writes_only_closed_non_secret_templates(tmp_path) -> None:
    root = tmp_path / "case"
    result = initialize_delivery_case(
        root,
        case_id="3" * 64,
        now=datetime(2026, 8, 22, tzinfo=timezone.utc),
    )
    assert result.case_id == "3" * 64
    assert sorted(
        str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()
    ) == [
        "case.json",
        "commercial/payer-status.json",
        "commercial/scorecard.json",
        "commercial/sow-reference.json",
    ]
    assert json.loads((root / "commercial/sow-reference.json").read_text())["status"] == "not_evidenced"


def test_initialize_case_never_overwrites_existing_target(tmp_path) -> None:
    root = tmp_path / "case"
    root.mkdir()
    (root / "owner.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(DeliveryCaseError, match="already exists"):
        initialize_delivery_case(root, case_id="3" * 64)
    assert (root / "owner.txt").read_text(encoding="utf-8") == "keep"
```

另写 `symlink target`、pre-commit 故障、rename 冲突、cleanup 失败和 umask/文件权限测试。

- [ ] **Step 2: 运行并确认 RED**

```bash
./.venv/bin/python -m pytest -q tests/test_delivery_case_v01.py -k 'initialize'
```

Expected：FAIL，缺少 `initialize_delivery_case`。

- [ ] **Step 3: 实现固定目录和 no-replace 提交**

实现签名：

```python
def initialize_delivery_case(
    case_root: Path,
    *,
    case_id: str | None = None,
    now: datetime | None = None,
) -> DeliveryCaseManifestV01:
    """Create one closed case directory without overwriting any target."""
```

固定要求：

1. `case_id` 缺省使用 `secrets.token_hex(32)`；
2. `now` 缺省使用 `datetime.now(timezone.utc)` 并规范为秒精度 UTC；
3. 首版别名固定初始化为 `buyer` 和 `delivery-provider`；如需修改，只允许编辑
   `case.json` 后重新走严格解析，不为 CLI 增加个人信息参数；
4. 在目标同级 `tempfile.mkdtemp(prefix=".owp-delivery-case-")` 中写入；
5. JSON 使用 `rfc8785.dumps(model.model_dump(mode="json"))`；
6. 文件权限 `0o600`，目录权限 `0o700`；
7. 创建 `protocol/`、`surface/`、`acceptance/`、`settlement/` 空目录；
8. 用 `os.rename` 前再次确认目标不存在；目标存在时不覆盖；
9. cleanup 失败抛 `DeliveryCaseError`，但不得删除调用方原有目标。

`scorecard.json` 的固定键为：`outreach_sent`、`buyer_interviewed`、`sow_signed`、
`deposit_evidenced`、`delivery_verified`、`customer_accepted`、
`external_payment_evidenced`、`repeat_order_evidenced`；值全部初始化为
`not_evidenced`，不允许自由增键。

- [ ] **Step 4: GREEN 与提交**

```bash
./.venv/bin/python -m pytest -q tests/test_delivery_case_v01.py -k 'initialize'
./.venv/bin/python -m compileall -q src tests
git diff --check
git add src/openworkproof/delivery_case.py tests/test_delivery_case_v01.py
git commit -m "feat: initialize verified delivery cases"
```

---

## Task 3：从现有证明重新推导订单状态

**Files:**
- Modify: `src/openworkproof/delivery_case.py`
- Modify: `tests/test_delivery_case_v01.py`

- [ ] **Step 1: 建立真实 bundle fixture 的 RED 状态矩阵**

复用 `surface_source`、Acceptance Bundle fixture 和 settlement ledger，参数化断言：

先写最早的可达状态测试：

```python
from datetime import datetime, timezone
import rfc8785

from openworkproof.delivery_case import (
    ExternalEvidenceReferenceV01,
    initialize_delivery_case,
    inspect_delivery_case,
)


def test_inspect_case_with_sow_but_no_surface_is_sow_referenced(tmp_path) -> None:
    root = tmp_path / "case"
    initialize_delivery_case(
        root,
        case_id="3" * 64,
        now=datetime(2026, 8, 22, tzinfo=timezone.utc),
    )
    sow = ExternalEvidenceReferenceV01(
        schema_version="openworkproof-external-evidence/0.1",
        status="external_reference_present",
        reference_digest="4" * 64,
        observed_at=datetime(2026, 8, 22, tzinfo=timezone.utc),
    )
    (root / "commercial/sow-reference.json").write_bytes(
        rfc8785.dumps(sow.model_dump(mode="json"))
    )
    result = inspect_delivery_case(root)
    assert result.case_stage == "SOW_REFERENCED"
    assert result.reason_codes == ("SURFACE_MISSING",)
```

再用仓库真实 Surface/Acceptance fixture 分别写六个独立测试，固定断言：

| Surface | Acceptance | Settlement | 期望 stage | 必须 reason |
|---|---|---|---|---|
| `UNKNOWN` | 无 | 无 | `UNKNOWN` | `SURFACE_UNKNOWN` |
| `REFUTED` | 无 | 无 | `REFUTED` | `SURFACE_REFUTED` |
| `VERIFIED` | 无 | 无 | `READY_FOR_ACCEPTANCE` | `ACCEPTANCE_MISSING` |
| `VERIFIED` | `REJECTED` | 无 | `REJECTED` | `CUSTOMER_REJECTED` |
| `VERIFIED` | `ACCEPTED` | 无 | `ACCEPTED` | `SETTLEMENT_STATUS_MISSING` |
| `VERIFIED` | `ACCEPTED` | `ACCEPTED_FOR_SETTLEMENT` | `READY_FOR_SETTLEMENT_REVIEW` | `PAYMENT_NOT_EVIDENCED` |

增加以下攻击测试：独立有效但不同 Surface 被拼入 Acceptance、settlement decision id
与签名 binding 不一致、预写 `delivery-result.json` 为成功、SOW/pay status 非 canonical、
绝对路径、symlink、hardlink、FIFO、未知文件、单文件/总大小超限。所有攻击均不得返回
正向状态。

- [ ] **Step 2: 运行状态矩阵确认 RED**

```bash
./.venv/bin/python -m pytest -q tests/test_delivery_case_v01.py -k 'inspect or stage or splice'
```

Expected：FAIL，缺少组合检查器。

- [ ] **Step 3: 实现只读组合验证顺序**

实现：

```python
def inspect_delivery_case(case_root: Path) -> DeliveryCaseResultV01:
    root = _canonical_case_root(case_root)
    snapshot = _scan_case_tree(root)
    case = _load_case(snapshot["case.json"])
    sow = _load_external_reference(snapshot["commercial/sow-reference.json"])
    payment = _load_external_reference(snapshot["commercial/payer-status.json"])
    if sow.status == "not_evidenced":
        return _result(case, "SCOPE_DRAFTED", sow=sow, payment=payment,
                       reasons=("SOW_NOT_EVIDENCED",))
    if "surface/surface-manifest.json" not in snapshot:
        return _result(case, "SOW_REFERENCED", sow=sow, payment=payment,
                       reasons=("SURFACE_MISSING",))

    surface = verify_surface_bundle(root / "surface")
    if surface.report.decision_status != "VERIFIED":
        status = surface.report.decision_status
        return _result(case, status, sow=sow, payment=payment,
                       surface=surface,
                       reasons=(f"SURFACE_{status}",))
    if "acceptance/acceptance-manifest.json" not in snapshot:
        return _result(case, "READY_FOR_ACCEPTANCE", sow=sow, payment=payment,
                       surface=surface, reasons=("ACCEPTANCE_MISSING",))

    acceptance = verify_acceptance_bundle_directory(root / "acceptance")
    if acceptance.surface_manifest_digest != surface.manifest_digest:
        raise DeliveryCaseError("surface and acceptance do not describe one delivery")
    if acceptance.terminal_decision == "REJECTED":
        return _result(case, "REJECTED", sow=sow, payment=payment,
                       surface=surface, acceptance=acceptance,
                       reasons=("CUSTOMER_REJECTED",))
    if "settlement/settlement-status.json" not in snapshot:
        return _result(case, "ACCEPTED", sow=sow, payment=payment,
                       surface=surface, acceptance=acceptance,
                       reasons=("SETTLEMENT_STATUS_MISSING",))
    return _verified_settlement_result(
        root, snapshot, case, sow, payment, surface, acceptance
    )
```

`_verified_settlement_result` 必须：

1. 从已通过 Acceptance Bundle 验证的
   `acceptance/acceptance/decision-binding.json` 重解析
   `AcceptanceDecisionBindingV01`；
2. 严格解析 `SettlementSnapshot`；
3. 要求 `current_decision_id == binding.verification_decision_id`；
4. 只把 `ACCEPTED_FOR_SETTLEMENT` 或 `READY_FOR_SETTLEMENT_REVIEW` 映射为
   `READY_FOR_SETTLEMENT_REVIEW`；
5. `payment.status == external_reference_present` 时只映射
   `EXTERNAL_PAYMENT_EVIDENCED`，同时保留边界“OWP 未验证付款真实性”；
6. reason codes 排序且来自闭合集合，未知字符串直接拒绝。

- [ ] **Step 4: GREEN 与相邻回归**

```bash
./.venv/bin/python -m pytest -q tests/test_delivery_case_v01.py -k 'inspect or stage or splice'
./.venv/bin/python -m pytest -q \
  tests/test_surface_bundle_v01.py \
  tests/test_acceptance_bundle_v01.py \
  tests/test_settlement_readiness.py
git diff --check
```

- [ ] **Step 5: 提交**

```bash
git add src/openworkproof/delivery_case.py tests/test_delivery_case_v01.py
git commit -m "feat: derive verified delivery case status"
```

---

## Task 4：确定性摘要与原子导出

**Files:**
- Create: `src/openworkproof/delivery_case_render.py`
- Modify: `src/openworkproof/delivery_case.py`
- Modify: `tests/test_delivery_case_v01.py`

- [ ] **Step 1: 写 renderer/export RED 测试**

```python
from openworkproof.delivery_case import export_delivery_case
from openworkproof.delivery_case_render import render_delivery_summary


def test_summary_answers_business_questions_without_overclaim(verified_result) -> None:
    rendered = render_delivery_summary(verified_result)
    for text in ("Who authorized", "What was executed", "Who verified", "Can the buyer accept", "Settlement review"):
        assert text in rendered
    assert "payment completed" not in rendered.lower()
    assert "guaranteed" not in rendered.lower()
    assert "/Users/" not in rendered


def test_export_is_no_replace_and_self_verifies(case_root, tmp_path) -> None:
    output = tmp_path / "export"
    first = export_delivery_case(case_root, output)
    assert first.case_stage == "READY_FOR_SETTLEMENT_REVIEW"
    with pytest.raises(DeliveryCaseError, match="already exists"):
        export_delivery_case(case_root, output)
```

增加 manifest exact file set、SHA-256、篡改、secret pattern、symlink/hardlink/FIFO、
pre-COMMIT、COMMIT-ACK、cleanup 和并发同目标测试。

- [ ] **Step 2: 运行并确认 RED**

```bash
./.venv/bin/python -m pytest -q tests/test_delivery_case_v01.py -k 'summary or export'
```

- [ ] **Step 3: 实现纯 renderer**

`render_delivery_summary(result)` 只接收 `DeliveryCaseResultV01`，输出固定顺序的
UTF-8 Markdown；禁止读文件、网络或墙钟。正文必须显示：case id 前 12 位、验证决定、
人工验收、结算审核状态、SOW/付款证据状态、reason codes 和边界。

JSON 使用：

```python
def render_delivery_result(result: DeliveryCaseResultV01) -> bytes:
    return rfc8785.dumps(result.model_dump(mode="json"))
```

- [ ] **Step 4: 实现原子导出与自验**

`export_delivery_case(case_root, output)` 固定顺序：稳定扫描源目录 →
`inspect_delivery_case` → 同级随机临时目录复制 allowlist 文件 → 写
`delivery-result.json` 和 `delivery-summary.md` → 生成完整性
`delivery-case-manifest.json` → 在临时目录调用 `verify_exported_delivery_case` →
no-replace rename。

完整性 manifest 明确标注：`integrity only; not an authorization, acceptance, payment,
or legal trust root`。验证器不得因为外层哈希正确而跳过内部 Surface/Acceptance 重放。

- [ ] **Step 5: GREEN、回归并提交**

```bash
./.venv/bin/python -m pytest -q tests/test_delivery_case_v01.py
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests
git diff --check
git add src/openworkproof/delivery_case.py \
  src/openworkproof/delivery_case_render.py tests/test_delivery_case_v01.py
git commit -m "feat: export verified delivery cases"
```

---

## Task 5：四个 CLI 命令与闭合退出码

**Files:**
- Create: `tests/test_delivery_case_cli_v01.py`
- Modify: `src/openworkproof/cli.py`
- Modify: `src/openworkproof/__init__.py`

- [ ] **Step 1: 写 parser、输出和退出码 RED 测试**

```python
import json
import openworkproof.cli as cli


def test_delivery_case_parser_exposes_four_actions() -> None:
    parser = cli.build_parser()
    for action in ("init", "inspect", "verify", "export"):
        args = parser.parse_args(["delivery-case", action, "case"] + (
            ["--output-directory", "export"] if action == "export" else []
        ))
        assert args.command == "delivery-case"
        assert args.delivery_case_action == action


@pytest.mark.parametrize(
    ("stage", "exit_code"),
    (
        ("READY_FOR_SETTLEMENT_REVIEW", 0),
        ("EXTERNAL_PAYMENT_EVIDENCED", 0),
        ("REFUTED", 2),
        ("REJECTED", 2),
        ("UNKNOWN", 3),
        ("SCOPE_DRAFTED", 3),
        ("SOW_REFERENCED", 3),
        ("READY_FOR_ACCEPTANCE", 3),
        ("ACCEPTED", 3),
    ),
)
def test_delivery_case_verify_has_closed_exit_codes(monkeypatch, capsys, stage, exit_code):
    monkeypatch.setattr(cli, "cli_delivery_case_verify", lambda _: {"case_stage": stage})
    assert cli.app(["delivery-case", "verify", "case"]) == exit_code
    assert json.loads(capsys.readouterr().out)["case_stage"] == stage
```

再覆盖 operational error=4、JSON/text 输出、错误中不泄漏绝对路径、CLI 无
`private_key`/支付账号参数、`init` 已存在目标、`export` no-replace。

- [ ] **Step 2: 运行并确认 RED**

```bash
./.venv/bin/python -m pytest -q tests/test_delivery_case_cli_v01.py
```

- [ ] **Step 3: 接入 argparse 与薄函数**

parser 结构固定为：

```python
delivery_case = sub.add_parser("delivery-case", help="verified delivery case operations")
delivery_case_sub = delivery_case.add_subparsers(
    dest="delivery_case_action", required=True
)
for action in ("init", "inspect", "verify"):
    command = delivery_case_sub.add_parser(action)
    command.add_argument("case_directory")
export = delivery_case_sub.add_parser("export")
export.add_argument("case_directory")
export.add_argument("--output-directory", required=True)
```

用户可见命令必须精确为：

```bash
owp delivery-case init CASE_DIR
owp delivery-case inspect CASE_DIR
owp delivery-case verify CASE_DIR
owp delivery-case export CASE_DIR --output-directory OUTPUT_DIR
```

薄函数只调用 `initialize_delivery_case`、`inspect_delivery_case`、
`verify_exported_delivery_case`、`export_delivery_case`；不得复制验证逻辑。

Operational error 输出固定：

```json
{
  "schema_version": "openworkproof-delivery-case-result/0.1",
  "case_stage": null,
  "reason_codes": ["OPERATIONAL_ERROR"],
  "boundary": "not payment, completed settlement, legal audit, or customer adoption"
}
```

- [ ] **Step 4: 公开 API 采用惰性导入**

在 `src/openworkproof/__init__.py` 的既有 lazy export 机制中仅导出：

```python
"DeliveryCaseError",
"DeliveryCaseManifestV01",
"DeliveryCaseResultV01",
"initialize_delivery_case",
"inspect_delivery_case",
"export_delivery_case",
"verify_exported_delivery_case",
```

导入 `openworkproof` 不得触发磁盘扫描、创建目录或读取环境变量。

- [ ] **Step 5: GREEN 与提交**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_delivery_case_cli_v01.py \
  tests/test_cli_transport.py \
  tests/test_v02_interfaces.py
./.venv/bin/python -m compileall -q src tests
git diff --check
git add src/openworkproof/cli.py src/openworkproof/__init__.py \
  tests/test_delivery_case_cli_v01.py
git commit -m "feat: expose verified delivery case CLI"
```

---

## Task 6：商业交付模板与事实边界测试

**Files:**
- Create: `docs/commercial/verified-agent-delivery/README.md`
- Create: `docs/commercial/verified-agent-delivery/client-intake.md`
- Create: `docs/commercial/verified-agent-delivery/acceptor-checklist.md`
- Create: `docs/commercial/verified-agent-delivery/sow-reference.example.json`
- Create: `docs/commercial/verified-agent-delivery/payer-status.example.json`
- Modify: `tests/test_documentation_boundaries.py`
- Modify: `README.md`
- Modify: `README_en.md`

- [ ] **Step 1: 先写文档契约 RED 测试**

在 `tests/test_documentation_boundaries.py` 增加：

```python
def test_verified_delivery_docs_close_commercial_boundaries() -> None:
    root = ROOT / "docs/commercial/verified-agent-delivery"
    combined = "\n".join(path.read_text(encoding="utf-8") for path in root.iterdir())
    for literal in (
        "Delivery Provider",
        "Customer Acceptor",
        "not_evidenced",
        "READY_FOR_SETTLEMENT_REVIEW",
        "不托管资金",
        "不等于付款",
        "停止条件",
    ):
        assert literal in combined
    for forbidden in ("保证回款", "自动付款", "法律公证", "已有客户采用"):
        assert forbidden not in combined
```

另验证两个 example JSON 均可被 `ExternalEvidenceReferenceV01` 严格解析，且默认
`not_evidenced`。

- [ ] **Step 2: 运行并确认 RED**

```bash
./.venv/bin/python -m pytest -q tests/test_documentation_boundaries.py -k 'verified_delivery'
```

- [ ] **Step 3: 编写直接可用模板**

`README.md` 固定包含：目标用户、准入条件、九项交付物、21 天/8 人日/2,000 元内部
上限、继续/停止条件、四种收费单元和全部诚实边界。`client-intake.md` 必须要求真实
仓库、任务单、付款主体、独立 Acceptor、验收条件和排除项；缺任何一项不得开工。

`sow-reference.example.json` 与 `payer-status.example.json` 必须使用以下初始值：

```json
{
  "schema_version": "openworkproof-external-evidence/0.1",
  "status": "not_evidenced",
  "reference_digest": null,
  "observed_at": null
}
```

README 中新增最短路径，但继续展示：

```text
customer_adoption: not_evidenced
paid_sow: not_evidenced
deposit: not_evidenced
external_payment: not_evidenced
```

- [ ] **Step 4: GREEN、语言边界与提交**

```bash
./.venv/bin/python -m pytest -q tests/test_documentation_boundaries.py
git diff --check
git add docs/commercial/verified-agent-delivery README.md README_en.md \
  tests/test_documentation_boundaries.py
git commit -m "docs: package verified agent delivery offer"
```

---

## Task 7：GitHub 交付目录 Action

**Files:**
- Create: `integrations/github-delivery-case/action.yml`
- Create: `integrations/github-delivery-case/run.sh`
- Modify: `tests/test_github_action_contract.py`

- [ ] **Step 1: 写 Action RED 契约**

```python
DELIVERY_CASE_ACTION = ROOT / "integrations/github-delivery-case/action.yml"
DELIVERY_CASE_SCRIPT = ROOT / "integrations/github-delivery-case/run.sh"


def test_delivery_case_action_accepts_no_private_or_payment_inputs() -> None:
    action = DELIVERY_CASE_ACTION.read_text(encoding="utf-8")
    script = DELIVERY_CASE_SCRIPT.read_text(encoding="utf-8")
    assert "case-directory" in action
    assert "output-directory" in action
    for forbidden in ("private-key", "bank", "wallet", "payment-token"):
        assert forbidden not in action.lower()
        assert forbidden not in script.lower()
```

复用现有 fake-bin 方法，参数化 `READY_FOR_SETTLEMENT_REVIEW=0`、`REFUTED=2`、
`UNKNOWN=3`、operational=4；断言 `always()` 上传 artifact，日志不出现 case 绝对路径。

- [ ] **Step 2: 运行并确认 RED**

```bash
./.venv/bin/python -m pytest -q tests/test_github_action_contract.py -k 'delivery_case'
```

- [ ] **Step 3: 实现最小 composite action**

`action.yml` 只定义：`case-directory`、`output-directory`，输出：`case-stage`、
`case-id`、`artifact-path`。`run.sh` 固定执行：

```bash
set -euo pipefail
umask 077
owp delivery-case verify "$OWP_CASE_DIRECTORY" >"$RUNNER_TEMP/owp-case-result.json"
status=$?
owp delivery-case export "$OWP_CASE_DIRECTORY" \
  --output-directory "$OWP_CASE_OUTPUT"
python -m openworkproof.github_action_cli write-delivery-case-summary \
  "$RUNNER_TEMP/owp-case-result.json" "$GITHUB_STEP_SUMMARY" "$GITHUB_OUTPUT"
exit "$status"
```

实际脚本须在 `verify` 周围临时 `set +e` 捕获 0/2/3/4，其他退出码改为 4；只有
输出目标不存在时才运行 export。summary helper 必须严格解析
`DeliveryCaseResultV01`，不得直接拼接未验证 JSON 字段。

- [ ] **Step 4: GREEN 与提交**

```bash
chmod 755 integrations/github-delivery-case/run.sh
./.venv/bin/python -m pytest -q tests/test_github_action_contract.py
git diff --check
git add integrations/github-delivery-case tests/test_github_action_contract.py \
  src/openworkproof/github_action_cli.py
git commit -m "feat: add verified delivery case action"
```

---

## Task 8：完整攻击矩阵、便携安装和发布文档

**Files:**
- Modify: `tests/test_delivery_case_v01.py`
- Modify: `tests/test_delivery_case_cli_v01.py`
- Modify: `tests/test_package.py`
- Modify: `pyproject.toml` only if wheel contents require an explicit change
- Modify: `docs/status.md`

- [ ] **Step 1: 补齐攻击与故障矩阵**

必须覆盖：

```text
case.json unknown field / non-canonical JSON / bad digest
SOW and payment status contradiction
surface byte tamper and manifest rehash attempt
acceptance byte tamper and cross-case splice
settlement decision-id mismatch
prewritten positive delivery-result.json
symlink / hardlink / FIFO / device / path traversal
file count / per-file / total-size overflow
secret-like value and absolute path leakage
pre-COMMIT / COMMIT-ACK / cleanup fault
two writers exporting the same target
REFUTED / UNKNOWN / REJECTED exact exit codes
```

每个失败测试同时断言：源目录未修改、目标未生成或保持原字节、错误输出不含私密
绝对路径。

- [ ] **Step 2: 聚焦与 portable 门**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_delivery_case_v01.py \
  tests/test_delivery_case_cli_v01.py \
  tests/test_github_action_contract.py \
  tests/test_surface_bundle_v01.py \
  tests/test_acceptance_bundle_v01.py \
  tests/test_settlement_readiness.py \
  tests/test_documentation_boundaries.py

./.venv/bin/python -m pytest -q
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests
git diff --check
```

Expected：以实际 fresh 结果为准，0 failed；默认 portable suite 的既有显式 skip 可保留，
不得把未运行的 live test 写成通过。

- [ ] **Step 3: 构建 wheel 并验证隔离安装**

```bash
build_root="$(mktemp -d)"
./.venv/bin/python -m pip wheel . --no-deps -w "$build_root/dist"
./.venv/bin/python -m venv "$build_root/venv"
"$build_root/venv/bin/python" -m pip install "$build_root"/dist/openworkproof-*.whl
"$build_root/venv/bin/owp" delivery-case --help
"$build_root/venv/bin/python" -c \
  'import openworkproof; print(openworkproof.__version__)'
```

Expected：wheel 安装成功；四个子命令可见；import 无副作用。

- [ ] **Step 4: 如实更新状态并提交**

`docs/status.md` 只记录刚刚运行的命令、revision、passed/failed/skipped 与边界；不得
写“已有十单”“客户采用”或“完成结算”。

```bash
git add tests/test_delivery_case_v01.py tests/test_delivery_case_cli_v01.py \
  tests/test_package.py pyproject.toml docs/status.md
git commit -m "test: close verified delivery case release gates"
```

只添加实际发生变化的文件。

---

## Task 9：candidate 与 required-live 收口

**Files:**
- Modify if required: `supply-chain/images/trusted-helper/SOURCE_ALLOWLIST`
- Create if required: `supply-chain/images/candidates/<final-revision>.json`
- Modify: `docs/status.md`
- Create: `docs/handoffs/2026-08-22-verified-agent-delivery-handoff.md`

- [ ] **Step 1: 判断 source closure 是否变化**

```bash
git diff origin/main...HEAD -- \
  supply-chain/images/trusted-helper/SOURCE_ALLOWLIST \
  src/openworkproof
python supply-chain/images/prepare_context.py --help
```

若新运行入口会进入 trusted-helper 镜像，必须把
`src/openworkproof/delivery_case.py` 与 `delivery_case_render.py` 及其真实 import 闭包
加入 allowlist；若不进入镜像，不得为了形式修改 allowlist。

- [ ] **Step 2: 需要时生成 revision 专属不可变库存**

严格复用 `supply-chain/images/README.md` 的 current 0.2 流程：以最终 source revision
生成 build contexts，分别构建 execution/trusted-helper OCI 与 Docker archives，实测
digest/RepoDigest/labels，生成新的 candidate JSON；不得覆盖或改写历史 inventory。

- [ ] **Step 3: 运行 candidate 两套件**

```bash
OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1 \
OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT="/absolute/candidate/artifacts" \
./.venv/bin/python -m pytest -q -m supplychain \
  tests/test_image_supply_chain.py \
  tests/test_candidate_supplychain_integration.py
```

Expected：0 failed、0 skipped。artifact root 必须替换成执行者实际生成并核验的绝对
目录，不能保留示例值运行。

- [ ] **Step 4: 运行 required-live 全量**

按仓库 README 和当前 CI 约定启用 Docker、candidate、AgentTeams 等 required-live
环境后执行完整 pytest。目标：0 failed；任何 required-live skip 都必须解释，不能把
历史数字复制成 fresh 结果。

- [ ] **Step 5: 写交接文档并提交收口**

交接文档必须列出：分支、commit 链、逐门 fresh 结果、candidate inventory、工作树、
尚未取得的商业证据、没有执行的 merge/push/release，以及首单所需外部动作。

```bash
git add supply-chain/images/trusted-helper/SOURCE_ALLOWLIST \
  supply-chain/images/candidates docs/status.md \
  docs/handoffs/2026-08-22-verified-agent-delivery-handoff.md
git commit -m "build: close verified delivery case candidate"
git status --short --branch
```

只添加实际变化文件；本计划不授权 push、merge、tag、PyPI 或 MCP Registry 发布。

---

## Final Checklist

- [ ] `delivery-case` 只编排已有权威验证器，没有复制协议逻辑
- [ ] `case.json` 不保存派生状态、私钥、Token、支付正文或客户源码
- [ ] Surface 与 Acceptance 必须精确属于同一交付
- [ ] settlement decision id 必须匹配已验证 Acceptor binding
- [ ] `UNKNOWN`、`REFUTED`、`REJECTED` 均 fail closed
- [ ] `READY_FOR_SETTLEMENT_REVIEW` 明确不等于付款或完成结算
- [ ] 外部付款状态只表示有摘要引用，不表示 OWP 验证资金事实
- [ ] 导出采用稳定扫描、exact allowlist、自验和 no-replace 原子提交
- [ ] GitHub Action 不接受私钥或支付凭证参数
- [ ] 中英文 README 与状态文档不声称客户采用、付款或上游采纳
- [ ] focused、portable、wheel、candidate、required-live 均记录 fresh 证据
- [ ] 自有演练不计入真实十单、付款方或复购
- [ ] 未经单独授权不 merge、push、tag 或发布
