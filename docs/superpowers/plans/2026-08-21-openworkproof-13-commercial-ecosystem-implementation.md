# OpenWorkProof 1.3 商业入口与生态演示实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在不修改 v0.1–v0.5 冻结协议的前提下，交付共享 Surface Bundle、GitHub PR/CI 商业入口，以及复用同一核心证据的 AgentTeams/MCP 三 Agent 演示。

**Architecture:** 既有 v0.5 Delivery Package 保持内层权威包；1.3 新增独立 companion 0.1 环境指纹、确定性验证报告和 Surface Bundle 外层清单。GitHub 与 AgentTeams 只负责把平台事实投影到中立输入并渲染核心结果，不能各自实现判定逻辑。

**Tech Stack:** Python 3.10–3.13、Pydantic v2、RFC 8785 JCS、Ed25519/cryptography、argparse CLI、GitHub composite action、MCP、AgentTeams Matrix API、pytest、JSON Schema Draft 2020-12。

---

## 0. 规格、范围与执行纪律

设计规格：
`docs/superpowers/specs/2026-08-21-openworkproof-13-commercial-ecosystem-design.md`

实施顺序固定为 P0 → P1 → P2 → P3。P3 不得阻塞 P2。每个 Task 均执行：

1. 写失败测试；
2. 运行精确测试并记录 RED；
3. 写最小实现；
4. 运行精确测试与相邻回归；
5. `pip check`、`compileall`、`git diff --check`；
6. 只提交本 Task 文件。

不得在本计划中实现 v0.6 divergence ledger、正式 A2A、支付、GitLab、企业控制台
或多租户服务。商业采用、付款和上游采纳继续标记 `not_evidenced`。

## 1. 文件结构

### 1.1 新建文件

| 文件 | 单一职责 |
|---|---|
| `src/openworkproof/environment_fingerprint.py` | companion 0.1 环境指纹模型、签名与验证 |
| `src/openworkproof/verification_report.py` | 从已验证 Delivery Package + 环境指纹确定性组合报告 |
| `src/openworkproof/surface_bundle.py` | 构建、验证和读取 Surface Bundle 外层包 |
| `src/openworkproof/companion_schema_registry.py` | 生成/读取独立 companion schema registry |
| `src/openworkproof/adapters/github_surface.py` | GitHub 环境来源文档到中立指纹 payload 的投影 |
| `src/openworkproof/github_action_cli.py` | GitHub Action 专用的 key-file 读取、Surface 构建与 summary 输出 |
| `src/openworkproof/agentteams_workflow.py` | 三角色 sender binding、消息 envelope 和演示状态机 |
| `integrations/github/action.yml` | 可复用 GitHub composite action |
| `integrations/github/run.sh` | 调用 1.3 CLI、写 Job Summary 和 outputs |
| `.github/workflows/ci.yml` | 便携测试、冻结兼容和包一致性 CI |
| `.github/workflows/github-action-smoke.yml` | 仓库内 GitHub Action fixture smoke |
| `agentteams/team-v13.yaml` | Manager/Developer/Verifier 三角色 Team 资源 |
| `agentteams/workers-v13.yaml` | Developer/Verifier MCP 与身份约束 |
| `agentteams/scripts/run_openworkproof_13_demo.py` | 真实 Matrix 调度与证据记录入口 |
| `agentteams/scripts/record_openworkproof_13_demo.sh` | 经显式屏幕源配置启动录屏并执行演示 |
| `agentteams/fixtures/agentscope-2239-task.json` | 固定演示任务、预期 artifact 与验收条件 |
| `examples/github-action/.github/workflows/openworkproof.yml` | 第三方仓库最小接入示例 |
| `examples/github-action/README.md` | 示例输入、secret 边界和本地复核命令 |
| `tests/test_environment_fingerprint_v01.py` | 环境模型、签名、信任与攻击测试 |
| `tests/test_companion_schema_registry.py` | companion schema 生成与旧冻结面测试 |
| `tests/test_verification_report_v01.py` | 三态组合与确定性报告测试 |
| `tests/test_surface_bundle_v01.py` | 包构建、篡改、路径与离线验证测试 |
| `tests/test_github_surface.py` | GitHub 投影、漂移和缺失字段测试 |
| `tests/test_github_action_contract.py` | action 文件、shell 退出码与输出测试 |
| `tests/test_agentteams_workflow_v13.py` | sender binding、返工、ACK 丢失与重复消息测试 |
| `tests/test_surface_conformance_v13.py` | GitHub/AgentTeams 共用核心摘要测试 |
| `tests/fixtures/github/pull_request.json` | 固定 GitHub PR event fixture |
| `tests/fixtures/surface/README.md` | companion 与 Surface Bundle fixture 约束 |
| `specs/companion-v0.1/*.json` | 第三方审阅用 companion schema 镜像 |
| `src/openworkproof/schemas/companion-v0.1/*.json` | wheel 内权威 companion schema |

### 1.2 修改文件

| 文件 | 变更 |
|---|---|
| `pyproject.toml` | 打包 companion schema；发布时升至 1.3.0 |
| `src/openworkproof/__init__.py` | 发布时升至 1.3.0；懒加载新公共 API |
| `src/openworkproof/delivery_package.py` | 只新增 v0.5 只读 trust/report facts API，不改既有验证结果 |
| `src/openworkproof/services.py` | 新增 surface build/verify facade |
| `src/openworkproof/cli.py` | 新增 surface 命令与 0/2/3/4 退出码 |
| `src/openworkproof/mcp_transport.py` | 增加 surface verify/report 只读工具 |
| `src/openworkproof/agentteams_matrix_client.py` | timeline 保留真实 event id |
| `README.md`、`README_en.md` | 1.3 安装、GitHub/AgentTeams 使用和诚实边界 |
| `docs/status.md` | 当前事实重写，不把历史快照冒充当前状态 |
| `docs/pilot/README.md` | 21 天付费试点输入、交付物、验收与非目标 |
| `server.json`、`mcp.json` | 仅在发布 Task 更新版本 |

## Task 1：基线、事实卫生与基础 CI（P0）

**Files:**
- Create: `.github/workflows/ci.yml`
- Modify: `docs/status.md`
- Modify: `tests/test_documentation_boundaries.py`
- Test: `tests/test_package.py`

- [ ] **Step 1: 在隔离 worktree 建立执行分支并记录基线**

执行时先使用 `superpowers:using-git-worktrees`，从已包含设计与本计划的 `main`
创建 `codex/openworkproof-13-dual-surface`。运行：

```bash
git status --short --branch
git rev-parse HEAD
./.venv/bin/python -m pytest -q \
  tests/test_package.py \
  tests/test_documentation_boundaries.py \
  tests/test_schema_registry.py
./.venv/bin/python -m pip check
```

Expected：工作树干净；测试退出码 0；记录实际 passed/failed/skipped/warnings，
不得复制旧计数。

- [ ] **Step 2: 写 CI 契约失败测试**

在 `tests/test_documentation_boundaries.py` 新增：

```python
def test_portable_ci_runs_tests_and_frozen_compatibility() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "python -m pytest -q" in workflow
    assert "tests/test_schema_registry.py" in workflow
    assert "python -m pip check" in workflow
    assert "python -m compileall -q src tests" in workflow
    assert "OPENWORKPROOF_REQUIRE_LIVE" not in workflow
```

- [ ] **Step 3: 运行测试观察 RED**

```bash
./.venv/bin/python -m pytest \
  tests/test_documentation_boundaries.py::test_portable_ci_runs_tests_and_frozen_compatibility -q
```

Expected：FAIL，`.github/workflows/ci.yml` 不存在。

- [ ] **Step 4: 创建最小 CI**

`.github/workflows/ci.yml`：

```yaml
name: CI
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  portable:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install -e '.[dev]'
      - run: python -m pip check
      - run: python -m compileall -q src tests
      - run: python -m pytest -q
      - run: python -m pytest -q tests/test_schema_registry.py tests/test_signing.py tests/test_package.py
```

- [ ] **Step 5: 重写 `docs/status.md` 顶部当前状态**

顶部只保留一次当前快照，采用：

```markdown
## 当前发布事实（以本次命令和公开回读为准）

- Python package / GitHub Release / MCP Registry：分别记录独立回读结果；
- 最新测试：记录命令、revision、passed/failed/skipped/warnings；
- 客户采用、付费 SOW、付款、续费、上游采纳：`not_evidenced`；
- 历史测试数字属于历史记录，不能覆盖当前快照。
```

填入 Step 1 的实际结果，不写估算数字。

- [ ] **Step 6: 运行 P0 回归并提交**

```bash
./.venv/bin/python -m pytest -q tests/test_documentation_boundaries.py tests/test_package.py
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests
git diff --check
git add .github/workflows/ci.yml docs/status.md tests/test_documentation_boundaries.py
git commit -m "ci: add portable verification gate"
```

Expected：全部退出码 0；提交不包含版本升级。

## Task 2：环境指纹模型、签名与信任绑定（P1）

**Files:**
- Create: `src/openworkproof/environment_fingerprint.py`
- Create: `tests/test_environment_fingerprint_v01.py`

- [ ] **Step 1: 写模型与签名 RED 测试**

```python
from openworkproof.environment_fingerprint import (
    EnvironmentFingerprintPayloadV01,
    SignedEnvironmentFingerprintV01,
    sign_environment_fingerprint,
    verify_environment_fingerprint,
)

def test_complete_fingerprint_round_trips(verifier_private_key) -> None:
    payload = EnvironmentFingerprintPayloadV01.model_validate(COMPLETE_PAYLOAD)
    signed = sign_environment_fingerprint(payload, verifier_private_key)
    trust = {signed.collector_key_id: verifier_private_key.public_key()}
    assert verify_environment_fingerprint(signed, trust)
    rebuilt = SignedEnvironmentFingerprintV01.model_validate_json(
        signed.model_dump_json()
    )
    assert rebuilt == signed

def test_partial_fingerprint_requires_closed_reasons() -> None:
    bad = {
        **COMPLETE_PAYLOAD,
        "collection_status": "partial",
        "runner_image_digest": None,
        "missing_reason_codes": [],
    }
    with pytest.raises(ValueError):
        EnvironmentFingerprintPayloadV01.model_validate(bad)
```

参数化攻击测试覆盖：extra field、63/65 位 digest、非 UTC 秒级时间、
complete+missing、partial 无缺失字段、unavailable 却带已采集摘要、坏签名、
错误 key id、未信任 key、篡改 source revision、恶意模型子类。

- [ ] **Step 2: 运行测试观察 RED**

```bash
./.venv/bin/python -m pytest tests/test_environment_fingerprint_v01.py -q
```

Expected：collection ERROR，模块不存在。

- [ ] **Step 3: 实现闭合模型**

`environment_fingerprint.py` 公共类型：

```python
CollectionStatus = Literal["complete", "partial", "unavailable"]
MissingReasonCode = Literal[
    "RUNNER_IMAGE_UNAVAILABLE",
    "CONTAINER_DIGEST_UNAVAILABLE",
    "TOOLCHAIN_LOCK_UNAVAILABLE",
    "SANDBOX_POLICY_UNAVAILABLE",
    "WORKFLOW_IDENTITY_UNVERIFIED",
]

class EnvironmentFingerprintPayloadV01(ProtocolModel):
    schema_version: Literal["openworkproof-execution-environment/0.1"]
    source_revision: str
    runner_os: str
    runner_arch: str
    runner_image_digest: Digest64 | None
    container_image_digest: Digest64 | None
    toolchain_lock_digest: Digest64 | None
    command_digest: Digest64
    arguments_digest: Digest64
    environment_allowlist_digest: Digest64
    sandbox_policy_digest: Digest64 | None
    workflow_identity_digest: Digest64 | None
    collection_status: CollectionStatus
    missing_reason_codes: tuple[MissingReasonCode, ...]
    collected_at: CanonicalUTCTime
    collector_actor_id: str

class SignedEnvironmentFingerprintV01(ProtocolModel):
    payload: EnvironmentFingerprintPayloadV01
    digest: Digest64
    signature_alg: Literal["Ed25519"]
    collector_key_id: KeyId
    signature: Signature
```

两个类单独设置 `revalidate_instances="subclass-instances"`。校验器要求：

- complete：五个可缺失摘要全部存在，missing 为空；
- partial：至少一项存在、至少一项缺失，原因精确覆盖缺失字段；
- unavailable：五项全为空，原因精确覆盖五项；
- 集合 UTF-8 排序且唯一；字符串有显式长度上限。

- [ ] **Step 4: 实现固定签名字节与 trust map 验证**

```python
def environment_signing_bytes(
    payload: EnvironmentFingerprintPayloadV01,
    collector_key_id: str,
) -> bytes:
    return rfc8785.dumps({
        "domain": "openworkproof/execution-environment/v0.1",
        "payload": payload.model_dump(mode="json"),
        "signature_alg": "Ed25519",
        "collector_key_id": collector_key_id,
    })

def sign_environment_fingerprint(payload, private_key):
    collector_key_id = key_id(private_key.public_key())
    encoded = environment_signing_bytes(payload, collector_key_id)
    return SignedEnvironmentFingerprintV01(
        payload=payload,
        digest=hashlib.sha256(encoded).hexdigest(),
        signature_alg="Ed25519",
        collector_key_id=collector_key_id,
        signature=_encode_base64url(private_key.sign(encoded)),
    )
```

`_encode_base64url` 在本模块内按既有 signing 规则最小实现，避免导入私有 API：

```python
def _encode_base64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
```

`verify_environment_fingerprint` 必须从调用方 `trust_map` 取公钥；不得信任包内
自带公钥。先比较 key id 与 digest，再验 Ed25519 签名。

- [ ] **Step 5: 运行模型回归并提交**

```bash
./.venv/bin/python -m pytest tests/test_environment_fingerprint_v01.py -q
./.venv/bin/python -m pytest tests/test_signing.py tests/test_verification_integrity_models_v05.py -q
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests
git diff --check
git add src/openworkproof/environment_fingerprint.py tests/test_environment_fingerprint_v01.py
git commit -m "feat: add signed execution environment evidence"
```

## Task 3：独立 companion schema registry（P1）

**Files:**
- Create: `src/openworkproof/companion_schema_registry.py`
- Create: `tests/test_companion_schema_registry.py`
- Create: `src/openworkproof/schemas/companion-v0.1/execution-environment.schema.json`
- Create: `src/openworkproof/schemas/companion-v0.1/schema-registry.json`
- Create: `specs/companion-v0.1/execution-environment.schema.json`
- Create: `specs/companion-v0.1/schema-registry.json`
- Modify: `pyproject.toml`

- [ ] **Step 1: 写 companion 与冻结面 RED 测试**

```python
def test_companion_generation_is_deterministic(tmp_path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    generate_companion_schemas(first)
    generate_companion_schemas(second)
    assert file_bytes(first) == file_bytes(second)

def test_protocol_v01_to_v05_anchors_are_unchanged() -> None:
    for version in ("0.1", "0.2", "0.3", "0.4", "0.5"):
        assert schema_registry._generated_files(version=version) == runtime_bytes(version)
```

首轮只注册 `execution-environment`；Task 5 再加入 report。

- [ ] **Step 2: 运行测试观察 RED**

```bash
./.venv/bin/python -m pytest tests/test_companion_schema_registry.py -q
```

Expected：collection ERROR，companion registry 不存在。

- [ ] **Step 3: 实现独立生成器**

```python
COMPANION_VERSION = "0.1"
OBJECT_PATHS = {
    "execution-environment": "execution-environment.schema.json",
}
SCHEMA_FACTORIES = {
    "execution-environment": SignedEnvironmentFingerprintV01.model_json_schema,
}

def generated_companion_files() -> dict[str, bytes]:
    schemas = {
        OBJECT_PATHS[name]: rfc8785.dumps(factory())
        for name, factory in SCHEMA_FACTORIES.items()
    }
    registry = {
        "schema_version": "openworkproof-companion-schema-registry/0.1",
        "document_version": COMPANION_VERSION,
        "schemas": [
            {
                "object_type": name,
                "path": OBJECT_PATHS[name],
                "sha256": hashlib.sha256(schemas[OBJECT_PATHS[name]]).hexdigest(),
            }
            for name in sorted(OBJECT_PATHS)
        ],
    }
    return {"schema-registry.json": rfc8785.dumps(registry), **schemas}

def generate_companion_schemas(destination: Path, *, mirror: Path | None = None) -> None:
    files = generated_companion_files()
    targets = (destination,) if mirror is None else (destination, mirror)
    _write_companion_transaction(targets, files)
```

`_write_companion_transaction` 按现有 `schema_registry.write_authoritative_schemas`
的事务语义本地实现：解析并锁定两个 target、分别写 sibling stage、校验完整文件集、
备份旧目录、COMMIT 两目录、失败时回滚、ACK 丢失时逐字节回读，最后清理 stage/
backup。禁止先 `rmtree(output)` 再 replace。测试注入 pre-COMMIT、第二 target COMMIT、
COMMIT-ACK 与 cleanup 故障，并断言 runtime/spec 要么同时为旧版本，要么同时为新版本。

生成器复用既有安全落盘原则，但不得把 companion 加进协议
`_OBJECT_PATHS_BY_VERSION`。

- [ ] **Step 4: 生成 runtime/spec 双目录**

```bash
./.venv/bin/python -m openworkproof.companion_schema_registry \
  --destination src/openworkproof/schemas/companion-v0.1 \
  --mirror specs/companion-v0.1
diff -ru src/openworkproof/schemas/companion-v0.1 specs/companion-v0.1
```

Expected：`diff` 退出码 0；把实际 SHA-256 固化为 companion anchors。

- [ ] **Step 5: 打包 schema 并提交**

`pyproject.toml` package-data 增加：

```toml
"schemas/companion-v0.1/*.json"
```

运行：

```bash
./.venv/bin/python -m pytest tests/test_companion_schema_registry.py tests/test_schema_registry.py -q
./.venv/bin/python -m pip install -e .
./.venv/bin/python -m pytest tests/test_package.py -q
git diff --check
git add pyproject.toml src/openworkproof/companion_schema_registry.py \
  src/openworkproof/schemas/companion-v0.1 specs/companion-v0.1 \
  tests/test_companion_schema_registry.py
git commit -m "feat: register companion evidence schemas"
```

## Task 4：从已验证 Delivery Package 导出只读信任与报告事实（P1）

**Files:**
- Modify: `src/openworkproof/delivery_package.py`
- Modify: `tests/test_delivery_package_v05.py`
- Modify: `tests/test_dual_verifier_v05.py`
- Modify: `docs/superpowers/specs/2026-08-21-openworkproof-13-commercial-ecosystem-design.md`

- [x] **Step 1: 写只读 facts RED 测试**

```python
def test_load_surface_facts_comes_only_from_verified_package(rich_v05_package) -> None:
    facts = load_surface_facts(rich_v05_package)
    assert facts.decision in {"VERIFIED", "REFUTED", "UNKNOWN"}
    assert len(facts.work_order_digest) == 64
    assert len(facts.source_revision) == 40
    assert facts.risk_class in {"standard", "high_risk"}
    assert facts.trusted_verifier_keys

def test_load_surface_facts_rejects_tampered_inner_package(tampered_v05_package) -> None:
    with pytest.raises(DeliveryPackageError):
        load_surface_facts(tampered_v05_package)
```

- [x] **Step 2: 运行测试观察 RED**

```bash
./.venv/bin/python -m pytest tests/test_delivery_package_v05.py -q -k surface_facts
```

Expected：FAIL，`load_surface_facts` 不存在。

- [x] **Step 3: 增加冻结只读返回类型**

```python
@dataclass(frozen=True, slots=True)
class DeliverySurfaceFacts:
    decision: Literal["VERIFIED", "REFUTED", "UNKNOWN"]
    reason_codes: tuple[str, ...]
    work_order_digest: str
    source_revision: str
    risk_class: Literal["standard", "high_risk"]
    decision_digests: tuple[str, ...]
    acceptance_receipt_digest: str | None
    evidence_closed_at: str
    trusted_verifier_keys: Mapping[str, Ed25519PublicKey]
    trusted_verifier_subjects: Mapping[str, str]
```

`load_surface_facts(root)` 先调用 `verify_delivery_package(root)`，再用现有 v0.5
loader 读取 WorkOrder/Profile/Decision。`trusted_verifier_keys` 只包含已验证、由
WorkOrder Manager 签署并绑定到该 WorkOrder 的 VerificationProfile 中的 Verifier
binding。WorkOrder 是信任根，Profile 是其显式委托层；这样 standard 保持单
Verifier，而 high-risk 可使用两个独立 Verifier。`trusted_verifier_subjects` 从同一
Profile binding 派生，用于把环境指纹的 `collector_actor_id` 绑定回签名主体。
public/diagnostic/legacy 包直接拒绝。

- [x] **Step 4: 增加篡改与信任角色矩阵**

完整 JSON 重建后分别篡改 WorkOrder key role、public key、source revision、
decision digest、manifest entry，均要求 fail closed。不得用 `model_copy`
绕过 Pydantic 重校验。

- [x] **Step 5: 回归并提交**

```bash
./.venv/bin/python -m pytest tests/test_delivery_package_v05.py tests/test_signing.py -q
git diff --check
git add src/openworkproof/delivery_package.py tests/test_delivery_package_v05.py \
  tests/test_dual_verifier_v05.py \
  docs/superpowers/specs/2026-08-21-openworkproof-13-commercial-ecosystem-design.md \
  docs/superpowers/plans/2026-08-21-openworkproof-13-commercial-ecosystem-implementation.md
git commit -m "feat: expose verified delivery surface facts"
```

## Task 5：确定性 VerificationReport（P1）

**Files:**
- Create: `src/openworkproof/verification_report.py`
- Create: `tests/test_verification_report_v01.py`
- Modify: `src/openworkproof/companion_schema_registry.py`
- Modify: `tests/test_companion_schema_registry.py`
- Regenerate: `src/openworkproof/schemas/companion-v0.1/*.json`
- Regenerate: `specs/companion-v0.1/*.json`

- [x] **Step 1: 写三态组合 RED 测试**

```python
@pytest.mark.parametrize(
    ("delivery", "fingerprints", "expected"),
    [
        ("REFUTED", (), "REFUTED"),
        ("UNKNOWN", (), "UNKNOWN"),
        ("VERIFIED", (COMPLETE_VERIFIER_A,), "VERIFIED"),
        ("VERIFIED_HIGH_RISK", (COMPLETE_VERIFIER_A,), "UNKNOWN"),
        (
            "VERIFIED_HIGH_RISK",
            (COMPLETE_VERIFIER_A, COMPLETE_VERIFIER_B),
            "VERIFIED",
        ),
        ("VERIFIED", (PARTIAL_VERIFIER_A,), "UNKNOWN"),
    ],
)
def test_report_status_is_fail_closed(delivery, fingerprints, expected):
    report = compose_verification_report(delivery, fingerprints)
    assert report.decision_status == expected
```

另测两个 fingerprint source revision 不一致、相同 key 重复、坏签名、未被
WorkOrder 信任、重渲染摘要变化、墙钟变化影响结果。

- [x] **Step 2: 运行测试观察 RED**

```bash
./.venv/bin/python -m pytest tests/test_verification_report_v01.py -q
```

Expected：collection ERROR，模块不存在。

- [x] **Step 3: 实现闭合报告模型和组合规则**

```python
ReportReasonCode = Literal[
    "DELIVERY_REFUTED",
    "DELIVERY_UNKNOWN",
    "DELIVERY_UNAUTHENTICATED",
    "ENVIRONMENT_INCOMPLETE",
    "ENVIRONMENT_COUNT_INSUFFICIENT",
    "ENVIRONMENT_SOURCE_MISMATCH",
    "ENVIRONMENT_SIGNATURE_INVALID",
    "ENVIRONMENT_SUBJECT_MISMATCH",
]

class VerificationReportV01(ProtocolModel):
    schema_version: Literal["openworkproof-verification-report/0.1"]
    bundle_digest: Digest64
    replay_result_digest: Digest64
    decision_status: Literal["VERIFIED", "REFUTED", "UNKNOWN"]
    reason_codes: tuple[ReportReasonCode, ...]
    work_order_digest: Digest64
    source_revision: str
    environment_fingerprint_digests: tuple[Digest64, ...]
    verification_decision_digests: tuple[Digest64, ...]
    acceptance_receipt_digest: Digest64 | None
    evidence_closed_at: CanonicalUTCTime
    renderer_version: Literal["openworkproof-report-renderer/0.1"]
```

组合优先级：`REFUTED` 优先；既有 `UNKNOWN` 保持；`VERIFIED` 仅在环境要求
满足时保留。high_risk 要求两个不同受信 Verifier 的 complete 指纹；standard
要求一个 complete 指纹。1.3 不提供允许 partial 的新 Scope 字段，因此 partial
一律 UNKNOWN。

`bundle_digest` 明确定义为内层 v0.5 Delivery Package `manifest.json` 的 SHA-256，
不是外层 SurfaceManifest digest，避免 report ↔ surface manifest 循环引用。
`replay_result_digest` 对除自身外的完整 canonical report payload 求 SHA-256；
`evidence_closed_at` 来自 Delivery Package，不读取当前墙钟。
所有传入的环境指纹（包括 Delivery 已为 REFUTED/UNKNOWN 时）仍必须完成签名、
source revision 与 Profile 主体绑定审计；high-risk 的两个 complete 指纹必须来自
两个不同受信 key。首版输入只接受精确 tuple/list 且最多两个元素，避免无界遍历。

- [x] **Step 4: 实现静态 HTML renderer**

```python
def render_report_html(report: VerificationReportV01) -> bytes:
    status = html.escape(report.decision_status)
    reasons = "".join(
        f"<li>{html.escape(code)}</li>" for code in report.reason_codes
    )
    return (
        "<!doctype html><meta charset='utf-8'>"
        "<title>OpenWorkProof Verification Report</title>"
        f"<h1>{status}</h1><ul>{reasons}</ul>"
        "<p>该报告不证明付款、合同履行或客户验收已经发生。</p>"
    ).encode("utf-8")
```

真实实现使用静态 CSS、无脚本、无外链，所有文本 `html.escape`。HTML 只渲染
报告模型字段，不接收 adapter 自由 metadata。

- [x] **Step 5: 加入 report schema 并提交**

更新 companion `OBJECT_PATHS`/`SCHEMA_FACTORIES`，重新生成双目录：

```bash
./.venv/bin/python -m openworkproof.companion_schema_registry \
  --destination src/openworkproof/schemas/companion-v0.1 \
  --mirror specs/companion-v0.1
diff -ru src/openworkproof/schemas/companion-v0.1 specs/companion-v0.1
./.venv/bin/python -m pytest tests/test_verification_report_v01.py \
  tests/test_companion_schema_registry.py -q
git diff --check
git add src/openworkproof/verification_report.py \
  src/openworkproof/companion_schema_registry.py \
  src/openworkproof/schemas/companion-v0.1 specs/companion-v0.1 \
  tests/test_verification_report_v01.py tests/test_companion_schema_registry.py
git commit -m "feat: derive deterministic verification reports"
```

## Task 6：Surface Bundle 构建与离线验证（P1）

**Files:**
- Create: `src/openworkproof/surface_bundle.py`
- Create: `tests/test_surface_bundle_v01.py`
- Create: `tests/fixtures/surface/README.md`

- [x] **Step 1: 写包结构与攻击 RED 测试**

```python
def test_surface_bundle_round_trips_offline(
    tmp_path, signed_fingerprint, rich_v05_package
):
    output = tmp_path / "surface"
    build_surface_bundle(rich_v05_package, (signed_fingerprint,), output)
    result = verify_surface_bundle(output)
    assert result.report.decision_status == "VERIFIED"
    assert result.report == VerificationReportV01.model_validate_json(
        (output / "report.json").read_bytes()
    )

@pytest.mark.parametrize("target", [
    "surface-manifest.json",
    "report.json",
    "report.html",
    "environments/00.json",
    "delivery-package/manifest.json",
])
def test_surface_bundle_rejects_each_tampered_layer(surface_bundle, target):
    flip_one_byte(surface_bundle / target)
    with pytest.raises(SurfaceBundleError):
        verify_surface_bundle(surface_bundle)
```

路径矩阵覆盖 `../`、绝对路径、symlink、hardlink、FIFO、重复 path、大小超限、
文件数超限、manifest 漏项和多项。

- [x] **Step 2: 运行测试观察 RED**

```bash
./.venv/bin/python -m pytest tests/test_surface_bundle_v01.py -q
```

Expected：collection ERROR，模块不存在。

- [x] **Step 3: 实现外层 manifest 与安全复制**

```python
class SurfaceManifestEntry(ProtocolModel):
    path: str
    sha256: Digest64
    size_bytes: int

class SurfaceManifestV01(ProtocolModel):
    schema_version: Literal["openworkproof-surface-bundle/0.1"]
    delivery_manifest_digest: Digest64
    report_digest: Digest64
    entries: tuple[SurfaceManifestEntry, ...]
```

`entries` 覆盖除 `surface-manifest.json` 自身外的全部普通文件；
`report_digest` 是 canonical `report.json` bytes 的 SHA-256。外层 manifest 不进入
VerificationReport 的 `bundle_digest`，验证器先验外层完整性，再重放内层与报告。

固定目录：

```text
surface-manifest.json
delivery-package/<原 v0.5 package 全部文件>
environments/00.json
environments/01.json
report.json
report.html
verify.sh
```

先写 sibling 临时目录，全部验证后 `os.replace` 提交。输入输出不得重叠；复制
只接受普通单链接文件；上限固定为 4096 文件、单文件 64 MiB、总计 512 MiB。

- [x] **Step 4: 实现离线验证顺序**

1. 安全读取并重算 SurfaceManifest 每个 entry；
2. 调用 `verify_delivery_package(delivery-package/)`；
3. 从内层包加载受信 Verifier keys；
4. 验证环境签名、source revision 和角色数量；
5. 重新组合 VerificationReport；
6. 比较 canonical report JSON 与 HTML renderer bytes；
7. 返回重算结果，不信任磁盘报告中的 status。

- [x] **Step 5: 回归并提交**

```bash
./.venv/bin/python -m pytest tests/test_surface_bundle_v01.py \
  tests/test_delivery_package_v05.py tests/test_verification_report_v01.py -q
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests
git diff --check
git add src/openworkproof/surface_bundle.py tests/test_surface_bundle_v01.py \
  tests/fixtures/surface/README.md
git commit -m "feat: add offline-verifiable surface bundles"
```

## Task 7：CLI、Services 与 MCP 三态出口（P1）

**Files:**
- Modify: `src/openworkproof/services.py`
- Modify: `src/openworkproof/cli.py`
- Modify: `src/openworkproof/mcp_transport.py`
- Modify: `src/openworkproof/__init__.py`
- Modify: `tests/test_cli_transport.py`
- Modify: `tests/test_v02_interfaces.py`

- [x] **Step 1: 写 CLI 0/2/3/4 RED 测试**

```python
@pytest.mark.parametrize(
    ("status", "expected"),
    [("VERIFIED", 0), ("REFUTED", 2), ("UNKNOWN", 3)],
)
def test_surface_verify_uses_closed_exit_codes(monkeypatch, status, expected):
    monkeypatch.setattr(
        cli,
        "cli_surface_verify",
        lambda _: {"decision_status": status},
    )
    assert cli.app(["surface-verify", "bundle"]) == expected

def test_surface_verify_operational_error_is_four(monkeypatch):
    monkeypatch.setattr(
        cli,
        "cli_surface_verify",
        mock.Mock(side_effect=CliError("bad")),
    )
    assert cli.app(["surface-verify", "bundle"]) == 4
```

四种退出都必须在 stdout 输出同一闭合 JSON envelope：
`{"decision_status": ..., "reason_codes": ..., "bundle_digest": ...}`；运行故障时
`decision_status` 为 `null`、reason code 为 `OPERATIONAL_ERROR`，细节写 stderr，
以便 GitHub summary 在失败时仍能生成且不泄露绝对路径。

保留旧 command 的历史退出码；0/2/3/4 只用于新增 `surface-*` 命令，避免 minor
release 破坏既有脚本。

- [x] **Step 2: 运行测试观察 RED**

```bash
./.venv/bin/python -m pytest tests/test_cli_transport.py -q -k surface
```

Expected：FAIL，parser 不认识命令。

- [x] **Step 3: 新增 facade 与 parser**

```python
def cli_surface_build(delivery_package, fingerprints, output_path) -> dict:
    return OpenWorkProofServices().build_surface(
        Path(delivery_package),
        tuple(Path(path) for path in fingerprints),
        Path(output_path),
    )

def cli_surface_verify(package) -> dict:
    return OpenWorkProofServices().verify_surface(Path(package))
```

parser：

```text
owp surface-build DELIVERY --fingerprint FILE [--fingerprint FILE] --output DIR
owp surface-verify SURFACE
```

`surface-build` 不接受 raw private key；签名必须在 build 前完成。

- [x] **Step 4: 新增 MCP 只读工具**

```python
@mcp.tool()
def owp_verify_surface_bundle(package_path: str) -> dict[str, Any]:
    return OpenWorkProofServices().verify_surface(Path(package_path))

@mcp.tool()
def owp_render_surface_report(package_path: str) -> dict[str, Any]:
    verified = OpenWorkProofServices().verify_surface(Path(package_path))
    return {
        "report": verified["report"],
        "boundary": "not payment or acceptance",
    }
```

两个工具只读，不写账本、不签名、不接受私钥。

- [x] **Step 5: 回归并提交**

```bash
./.venv/bin/python -m pytest tests/test_cli_transport.py tests/test_v02_interfaces.py \
  tests/test_surface_bundle_v01.py -q
git diff --check
git add src/openworkproof/services.py src/openworkproof/cli.py \
  src/openworkproof/mcp_transport.py src/openworkproof/__init__.py \
  tests/test_cli_transport.py tests/test_v02_interfaces.py
git commit -m "feat: expose surface bundle verification"
```

## Task 8：GitHub 环境投影与漂移门（P2）

**Files:**
- Create: `src/openworkproof/adapters/github_surface.py`
- Create: `tests/test_github_surface.py`
- Create: `tests/fixtures/github/pull_request.json`

- [x] **Step 1: 写 GitHub adapter RED 测试**

```python
def test_github_projection_matches_pr_head(fixed_github_env):
    source = GitHubExecutionSourceV01.from_environment(fixed_github_env)
    payload = project_github_environment(source, expected_revision="a" * 40)
    assert payload.source_revision == "a" * 40
    assert payload.collection_status == "complete"

def test_github_projection_rejects_revision_drift(fixed_github_env):
    with pytest.raises(GitHubSurfaceError, match="source revision drift"):
        project_github_environment(
            GitHubExecutionSourceV01.from_environment(fixed_github_env),
            expected_revision="b" * 40,
        )
```

另测缺 `GITHUB_SHA`、PR head 与 GITHUB_SHA 不同、fork 来源、未提供 immutable
runner/container digest、secret 不进入 dump、workflow identity 只存摘要。
`run_action_fixture` 是本地 runner 集成路径；Task 9 的 smoke workflow 是
GitHub-hosted runner 集成路径，两者都必须通过。

- [x] **Step 2: 运行测试观察 RED**

```bash
./.venv/bin/python -m pytest tests/test_github_surface.py -q
```

Expected：collection ERROR，模块不存在。

- [x] **Step 3: 实现平台来源模型与投影**

```python
class GitHubExecutionSourceV01(ProtocolModel):
    schema_version: Literal["openworkproof-github-execution-source/0.1"]
    repository: str
    event_name: str
    source_revision: str
    workflow_ref: str
    job: str
    run_id: str
    run_attempt: str
    runner_os: str
    runner_arch: str
    runner_image_digest: Digest64 | None
    container_image_digest: Digest64 | None
```

`from_environment` 只读取显式 allowlist；禁止遍历完整 `os.environ`。
`project_github_environment` 对 workflow fields 的 canonical projection 求摘要，
不把 repository、run id 或 workflow ref 原文写入中立指纹。

`pull_request` 事件的 `GITHUB_SHA` 是 merge ref；adapter 单独保存它用于 workflow
identity 摘要，并把实际 checkout revision 与 event 中的 PR head SHA 比较。这样既
拒绝 checkout 漂移，也不会把 GitHub 的正常 merge-ref 语义误判成漂移。

- [x] **Step 4: 实现缺失字段的诚实降级**

runner/container/toolchain/sandbox 任一不可得时，把精确 missing reason 写入
payload。不得补全零 digest，也不得用 mutable image tag 代替 digest。

- [x] **Step 5: 回归并提交**

```bash
./.venv/bin/python -m pytest tests/test_github_surface.py \
  tests/test_environment_fingerprint_v01.py -q
git diff --check
git add src/openworkproof/adapters/github_surface.py \
  tests/test_github_surface.py tests/fixtures/github/pull_request.json
git commit -m "feat: project github execution context"
```

## Task 9：GitHub composite action 与 PR 报告（P2）

**Files:**
- Create: `src/openworkproof/github_action_cli.py`
- Create: `integrations/github/action.yml`
- Create: `integrations/github/run.sh`
- Create: `tests/test_github_action_contract.py`
- Create: `.github/workflows/github-action-smoke.yml`
- Create: `examples/github-action/.github/workflows/openworkproof.yml`
- Create: `examples/github-action/README.md`

- [x] **Step 1: 写 action 契约 RED 测试**

```python
def test_action_never_accepts_private_key_as_cli_argument() -> None:
    script = (ROOT / "integrations/github/run.sh").read_text()
    assert "--private-key" not in script
    assert "OWP_COLLECTOR_PRIVATE_KEY_FILE" in script
    assert "$GITHUB_STEP_SUMMARY" in script
    assert "$GITHUB_OUTPUT" in script

def test_action_preserves_surface_exit_code(tmp_path) -> None:
    completed = run_action_fixture(tmp_path, decision="UNKNOWN")
    assert completed.returncode == 3
```

- [x] **Step 2: 运行测试观察 RED**

```bash
./.venv/bin/python -m pytest tests/test_github_action_contract.py -q
```

Expected：FAIL，action 文件不存在。

- [x] **Step 3: 创建 action 输入输出**

`integrations/github/action.yml`：

```yaml
name: OpenWorkProof Verify Delivery
description: Build and verify an offline-verifiable Agent delivery report
inputs:
  delivery-package:
    required: true
  collector-private-key-file:
    required: true
  runner-image-digest:
    required: false
  container-image-digest:
    required: false
  toolchain-lock-file:
    required: true
  sandbox-policy-file:
    required: true
  output-directory:
    required: false
    default: openworkproof-surface
outputs:
  decision:
    value: ${{ steps.verify.outputs.decision }}
  bundle-digest:
    value: ${{ steps.verify.outputs.bundle_digest }}
  artifact-path:
    value: ${{ steps.verify.outputs.artifact_path }}
runs:
  using: composite
  steps:
    - uses: actions/setup-python@v5
      with:
        python-version: "3.12"
    - shell: bash
      run: python -m pip install "$GITHUB_ACTION_PATH/../.."
    - id: verify
      shell: bash
      env:
        OWP_COLLECTOR_PRIVATE_KEY_FILE: ${{ inputs.collector-private-key-file }}
        OWP_DELIVERY_PACKAGE: ${{ inputs.delivery-package }}
        OWP_RUNNER_IMAGE_DIGEST: ${{ inputs.runner-image-digest }}
        OWP_CONTAINER_IMAGE_DIGEST: ${{ inputs.container-image-digest }}
        OWP_TOOLCHAIN_LOCK_FILE: ${{ inputs.toolchain-lock-file }}
        OWP_SANDBOX_POLICY_FILE: ${{ inputs.sandbox-policy-file }}
        OWP_SURFACE_OUTPUT: ${{ inputs.output-directory }}
      run: "$GITHUB_ACTION_PATH/integrations/github/run.sh"
    - if: always()
      uses: actions/upload-artifact@v4
      with:
        name: openworkproof-evidence-bundle
        path: openworkproof-evidence-bundle.tar.gz
```

- [x] **Step 4: 实现 shell 的错误与摘要边界**

`run.sh`：

```bash
#!/usr/bin/env bash
set -euo pipefail
umask 077
test -f "${OWP_COLLECTOR_PRIVATE_KEY_FILE:?missing collector key file}"
python -m openworkproof.github_action_cli build \
  --delivery-package "$OWP_DELIVERY_PACKAGE" \
  --collector-key-file "$OWP_COLLECTOR_PRIVATE_KEY_FILE" \
  --toolchain-lock-file "$OWP_TOOLCHAIN_LOCK_FILE" \
  --sandbox-policy-file "$OWP_SANDBOX_POLICY_FILE" \
  --output "$OWP_SURFACE_OUTPUT"
set +e
owp surface-verify "$OWP_SURFACE_OUTPUT" >"$RUNNER_TEMP/owp-result.json"
status=$?
set -e
python -m openworkproof.github_action_cli write-summary \
  "$RUNNER_TEMP/owp-result.json" "$GITHUB_STEP_SUMMARY" "$GITHUB_OUTPUT"
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 \
  --numeric-owner -czf openworkproof-evidence-bundle.tar.gz \
  -C "$(dirname "$OWP_SURFACE_OUTPUT")" "$(basename "$OWP_SURFACE_OUTPUT")"
exit "$status"
```

`github_action_cli build` 从 key file descriptor 读取并立即关闭；不打印 key、不复制
进 artifact。它依次投影 GitHub allowlist 环境、签环境指纹、调用公共
`build_surface_bundle`；不得复制 verifier 或 report 判定。summary 只显示四问、
三态、reason codes、bundle digest 和诚实边界。归档在已验证目录之后生成，归档
本身不是新的信任根；下载后仍须解包并执行 `owp surface-verify`。
`write-summary` 必须写出 `artifact_path=openworkproof-evidence-bundle.tar.gz`；
UNKNOWN/REFUTED 也先生成并上传证据再保留 3/2 退出码，artifact 上传失败则保持
operational failure，不得回写 success。

- [x] **Step 5: 增加仓库内 smoke workflow**

smoke 使用冻结测试 key fixture 和测试 Delivery Package，只验证 action plumbing；
workflow 名称与 summary 必须带 `fixture`，防止误称生产信任。真实 secret 不入库。
同时加入 `examples/github-action/` 最小第三方接入示例，明确 key 必须来自 GitHub
secret 写入的临时文件，不能把测试 key 当作生产 key。

- [x] **Step 6: 回归并提交**

```bash
chmod +x integrations/github/run.sh
./.venv/bin/python -m pytest tests/test_github_action_contract.py \
  tests/test_github_surface.py tests/test_surface_bundle_v01.py -q
bash -n integrations/github/run.sh
git diff --check
git add src/openworkproof/github_action_cli.py integrations/github \
  .github/workflows/github-action-smoke.yml examples/github-action \
  tests/test_github_action_contract.py
git commit -m "feat: add github verification action"
```

## Task 10：AgentTeams 消息契约与三角色状态机（P3）

**Files:**
- Create: `src/openworkproof/agentteams_workflow.py`
- Create: `tests/test_agentteams_workflow_v13.py`
- Modify: `src/openworkproof/agentteams_matrix_client.py`
- Modify: `tests/test_agentteams_adapters.py`

- [x] **Step 1: 写 sender binding 与返工 RED 测试**

```python
def test_three_distinct_senders_complete_rework_loop(workflow):
    workflow.accept(manager_dispatch())
    workflow.accept(developer_result(attempt=1))
    workflow.accept(verifier_result(attempt=1, decision="REFUTED"))
    workflow.accept(developer_result(attempt=2))
    outcome = workflow.accept(
        verifier_result(attempt=2, decision="VERIFIED")
    )
    assert outcome.state == "ready_for_acceptance"
    assert outcome.attempt == 2

def test_role_name_with_same_sender_is_rejected(workflow):
    forged = verifier_result(sender="@dev-worker:hs", decision="VERIFIED")
    with pytest.raises(AgentTeamsWorkflowError, match="sender binding"):
        workflow.accept(forged)
```

另测同 key 两角色、重复 event id、乱序消息、错误 task id、artifact digest 不符、
超过一次返工、ACK 丢失、消息成功但核心提交失败、核心提交成功但消息失败。

- [x] **Step 2: 运行测试观察 RED**

```bash
./.venv/bin/python -m pytest tests/test_agentteams_workflow_v13.py -q
```

Expected：collection ERROR，模块不存在。

- [x] **Step 3: 实现结构化消息 envelope**

```python
class AgentTeamsRoleBinding(ProtocolModel):
    role: Literal["Manager", "Developer", "Verifier"]
    matrix_user_id: str
    openworkproof_key_id: KeyId

class AgentTeamsWorkflowMessageV01(ProtocolModel):
    schema_version: Literal["openworkproof-agentteams-message/0.1"]
    task_id: Digest64
    event_id: str
    sender: str
    role: Literal["Manager", "Developer", "Verifier"]
    phase: Literal["dispatch", "development", "verification"]
    attempt: Literal[1, 2]
    artifact_path: str | None
    artifact_digest: Digest64 | None
    decision: Literal["VERIFIED", "REFUTED", "UNKNOWN"] | None
```

Matrix body 必须是该 JSON，不接受 `DEV_RESULT <token>` 自由文本作为协议真相。
raw event id 仅进入本地 provenance；核心报告不使用它判定。

- [x] **Step 4: 实现纯状态机与幂等**

```text
awaiting_dispatch -> awaiting_development -> awaiting_verification
awaiting_verification + REFUTED/UNKNOWN(attempt 1) -> awaiting_development(attempt 2)
awaiting_verification + VERIFIED -> ready_for_acceptance
attempt 2 非 VERIFIED -> not_ready
```

以 `(task_id, event_id)` 去重；相同事件相同 payload 精确幂等，不同 payload 冲突。
平台发送在核心状态落盘后执行；发送失败返回 `committed_but_unannounced`，不能
回滚核心真相。

- [x] **Step 5: 为 Matrix timeline 保留 event id**

把 `read_timeline` 返回值扩展为：

```python
{"event_id": "$evt", "sender": "@dev:hs", "body": "{...}"}
```

同步修改全部仓库调用点和旧测试；不得从 body 伪造 event id。

- [x] **Step 6: 回归并提交**

```bash
./.venv/bin/python -m pytest tests/test_agentteams_workflow_v13.py \
  tests/test_agentteams_adapters.py tests/test_team_network_client.py -q
git diff --check
git add src/openworkproof/agentteams_workflow.py \
  src/openworkproof/agentteams_matrix_client.py \
  tests/test_agentteams_workflow_v13.py tests/test_agentteams_adapters.py
git commit -m "feat: bind agentteams roles to evidence workflow"
```

## Task 11：AgentTeams/MCP 真实三 Agent 演示（P3）

**Files:**
- Create: `agentteams/team-v13.yaml`
- Create: `agentteams/workers-v13.yaml`
- Create: `agentteams/scripts/run_openworkproof_13_demo.py`
- Create: `agentteams/scripts/record_openworkproof_13_demo.sh`
- Create: `agentteams/fixtures/agentscope-2239-task.json`
- Modify: `agentteams/README.md`
- Modify: `tests/test_agentteams_workflow_v13.py`

- [ ] **Step 1: 写 live 前置门测试**

```python
@pytest.mark.agentteams
def test_live_team_has_three_distinct_roles():
    if os.environ.get("OPENWORKPROOF_AGENTTEAMS_REQUIRED") != "1":
        pytest.skip("live AgentTeams not required")
    result = run_live_preflight()
    assert result.roles == ("Manager", "Developer", "Verifier")
    assert len(set(result.matrix_user_ids)) == 3
    assert len(set(result.openworkproof_key_ids)) == 3
```

required-live 演示命令设置该变量，因此不能 skip；普通 portable suite 可 skip。

- [ ] **Step 2: 运行测试观察 RED**

```bash
OPENWORKPROOF_AGENTTEAMS_REQUIRED=1 \
./.venv/bin/python -m pytest tests/test_agentteams_workflow_v13.py -q -k live_team
```

Expected：FAIL，v13 资源或运行入口不存在；若 AgentTeams 未运行，必须明确为
preflight failure，不能伪装通过。

- [ ] **Step 3: 创建三角色资源**

`team-v13.yaml` 使用 AgentTeams 的 Manager `default`，Developer 与 Verifier
分别绑定 `dev-worker`、`verifier-worker`。两个 Worker 挂同一 OWP MCP server；
Developer 仅获 repo_read/apply_patch/run_tests，Verifier 仅获
repo_read/run_tests/surface verify，Verifier 不得获 apply_patch。

- [ ] **Step 4: 实现真实演示入口**

脚本参数：

```text
--room TEAM_ROOM
--task-file TASK_JSON
--delivery-package PATH
--output PATH
--timeout-seconds 900
--max-rework 1
--record-provenance PATH
--acceptance-receipt PATH
```

顺序：controller preflight → Manager dispatch → 等 Developer structured result
→ 检查 artifact digest → Verifier 通过 MCP 独立验证 → 非 VERIFIED 时返工一次
→ 构建 Surface Bundle → 停在 `ready_for_acceptance` → 人类 Acceptor 在既有验收
事务中签署 receipt → 脚本只读取 `--acceptance-receipt` 并离线核验 → 最终离线复核。
脚本不得替代人类点击确认、不得生成 Acceptor 私钥，也不得把“报告 VERIFIED”改写为
“客户已验收”。
receipt 文件若尚不存在，脚本在 `--timeout-seconds` 内轮询但不持有事务锁；出现后
必须用现有 `acceptance.validate_acceptance_bindings` 对 WorkOrder、CompositionReport
和完整 receipt history 重放，不能只验 receipt 自签名。

provenance 只保存 event id SHA-256、角色、阶段、时间、artifact digest 和 decision；
token、消息全文、私钥、绝对本地路径不得写入。

录屏 wrapper 不猜测 macOS 屏幕设备编号，要求调用方显式设置
`OWP_SCREEN_RECORD_INPUT`，用 `ffmpeg -f avfoundation` 写入用户指定路径；开始前
逐项检查 Element 只显示目标 room、桌面通知关闭、无 token/终端 secret，结束时向
ffmpeg 发送 `q` 并用 `ffprobe` 验证视频可解码。未满足前置条件直接退出，不启动演示。

- [ ] **Step 5: 真实运行并保存新鲜证据**

```bash
OPENWORKPROOF_AGENTTEAMS_REQUIRED=1 \
./.venv/bin/python agentteams/scripts/run_openworkproof_13_demo.py \
  --room '#agentteams-team-owp-team:matrix-local.agentteams.io:18080' \
  --task-file agentteams/fixtures/agentscope-2239-task.json \
  --delivery-package .artifacts/rich-4196-v05-delivery \
  --output .artifacts/agentteams-v13-surface \
  --record-provenance .artifacts/agentteams-v13-provenance.json \
  --acceptance-receipt .artifacts/human-acceptance-receipt.json
```

比赛录屏使用同一命令，不另写一套 demo：

```bash
OWP_SCREEN_RECORD_INPUT='1:none' \
agentteams/scripts/record_openworkproof_13_demo.sh \
  .artifacts/agentteams-v13-demo.mp4 -- \
  ./.venv/bin/python agentteams/scripts/run_openworkproof_13_demo.py \
  --room '#agentteams-team-owp-team:matrix-local.agentteams.io:18080' \
  --task-file agentteams/fixtures/agentscope-2239-task.json \
  --delivery-package .artifacts/rich-4196-v05-delivery \
  --output .artifacts/agentteams-v13-surface \
  --record-provenance .artifacts/agentteams-v13-provenance.json \
  --acceptance-receipt .artifacts/human-acceptance-receipt.json
```

先用现有 exporter 生成规范目录包；不得修改验证器去接受 JSON envelope 文件替代
目录包。证据必须显示三个不同 Matrix sender、三个不同 OWP key id、至少一次
真实 MCP 工具调用和离线复核结果。

- [ ] **Step 6: 回归并提交代码与脱敏说明**

```bash
./.venv/bin/python -m pytest tests/test_agentteams_workflow_v13.py \
  tests/test_agentteams_adapters.py -q
git diff --check
git add agentteams/team-v13.yaml agentteams/workers-v13.yaml \
  agentteams/scripts/run_openworkproof_13_demo.py \
  agentteams/scripts/record_openworkproof_13_demo.sh \
  agentteams/fixtures/agentscope-2239-task.json agentteams/README.md \
  tests/test_agentteams_workflow_v13.py
git commit -m "feat: add three-agent verification demo"
```

不提交 `.artifacts/` 原始录制或凭据；公开证据另经人工脱敏审查。

## Task 12：跨 Surface conformance（A+C 共同验收）

**Files:**
- Create: `tests/test_surface_conformance_v13.py`
- Modify: `src/openworkproof/environment_fingerprint.py`
- Modify: `src/openworkproof/adapters/github_surface.py`
- Modify: `src/openworkproof/agentteams_workflow.py`

- [ ] **Step 1: 写同一规范输入 RED 测试**

```python
def test_github_and_agentteams_share_core_digest(normalized_execution_input):
    github_payload = github_surface.project_source(
        normalized_execution_input.github
    )
    agentteams_payload = agentteams_workflow.project_source(
        normalized_execution_input.agentteams
    )
    assert core_execution_digest(github_payload) == core_execution_digest(
        agentteams_payload
    )
```

- [ ] **Step 2: 写平台 metadata 污染攻击**

增加 100 个随机 GitHub env/Matrix event 字段，不在 allowlist 的字段不得改变
core digest；改变 source revision、command、args、sandbox 或 toolchain 必须改变。

- [ ] **Step 3: 实现显式 core projection**

```python
def core_execution_projection(
    payload: EnvironmentFingerprintPayloadV01,
) -> dict:
    raw = payload.model_dump(mode="json")
    raw.pop("workflow_identity_digest")
    raw.pop("collected_at")
    raw.pop("collector_actor_id")
    return raw

def core_execution_digest(
    payload: EnvironmentFingerprintPayloadV01,
) -> str:
    return hashlib.sha256(
        rfc8785.dumps(core_execution_projection(payload))
    ).hexdigest()
```

该 digest 只用于 conformance 与调试，不替代完整 signed fingerprint digest。

- [ ] **Step 4: 回归并提交**

```bash
./.venv/bin/python -m pytest tests/test_surface_conformance_v13.py \
  tests/test_github_surface.py tests/test_agentteams_workflow_v13.py -q
git diff --check
git add src/openworkproof/environment_fingerprint.py \
  src/openworkproof/adapters/github_surface.py \
  src/openworkproof/agentteams_workflow.py tests/test_surface_conformance_v13.py
git commit -m "test: enforce shared surface evidence contract"
```

## Task 13：文档、试点 SOP 与 1.3 版本面

**Files:**
- Modify: `README.md`
- Modify: `README_en.md`
- Modify: `docs/status.md`
- Modify: `docs/pilot/README.md`
- Modify: `pyproject.toml`
- Modify: `src/openworkproof/__init__.py`
- Modify: `server.json`
- Modify: `mcp.json`
- Modify: `tests/test_documentation_boundaries.py`
- Modify: `tests/test_package.py`

- [ ] **Step 1: 写版本与诚实边界 RED 测试**

```python
def test_release_metadata_is_130() -> None:
    assert pyproject_version() == "1.3.0"
    assert openworkproof.__version__ == "1.3.0"
    assert json.loads((ROOT / "server.json").read_text())["version"] == "1.3.0"
    assert json.loads((ROOT / "mcp.json").read_text())["version"] == "1.3.0"

def test_docs_do_not_claim_unearned_commercial_status() -> None:
    text = all_public_docs()
    for claim in ("已有付费客户", "已完成结算", "保证正确", "上游已采纳"):
        assert claim not in text
    assert "not_evidenced" in text
```

- [ ] **Step 2: 运行测试观察 RED**

```bash
./.venv/bin/python -m pytest tests/test_package.py \
  tests/test_documentation_boundaries.py -q -k '130 or unearned'
```

Expected：版本测试 FAIL，当前仍为 1.2.0。

- [ ] **Step 3: 更新版本与双语文档**

README 顺序：

1. 一句话商业问题；
2. GitHub Action 5 分钟路径；
3. 四问报告示例；
4. 三态与离线验证；
5. AgentTeams/MCP 三 Agent 演示；
6. 技术协议细节；
7. `not_evidenced` 边界。

所有测试数量在 Task 14 fresh 门后回填，不能预写。

- [ ] **Step 4: 更新 21 天试点 SOP**

`docs/pilot/README.md` 写明：输入是一个真实私有/脱敏仓库、一个 Agent PR 流程、
客户提供的 Verifier key binding 和验收人；交付物是三次 Surface Bundle、差异
报告、人工验收 SOP；不包含代开发、付款担保、法律审计和无限运维。

- [ ] **Step 5: 回归并提交**

```bash
./.venv/bin/python -m pip install -e .
./.venv/bin/python -m pytest tests/test_package.py \
  tests/test_documentation_boundaries.py -q
./.venv/bin/python -m pip check
git diff --check
git add README.md README_en.md docs/status.md docs/pilot/README.md \
  pyproject.toml src/openworkproof/__init__.py server.json mcp.json \
  tests/test_package.py tests/test_documentation_boundaries.py
git commit -m "docs: publish openworkproof 1.3 surfaces"
```

## Task 14：独立审查、供应链与最终发布门

**Files:**
- Modify only when required by review findings
- Create candidate inventory under `supply-chain/images/candidates/` if source allowlist changed
- Update `docs/status.md` only with fresh results

- [ ] **Step 1: 运行 focused 门**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_environment_fingerprint_v01.py \
  tests/test_companion_schema_registry.py \
  tests/test_verification_report_v01.py \
  tests/test_surface_bundle_v01.py \
  tests/test_github_surface.py \
  tests/test_github_action_contract.py \
  tests/test_agentteams_workflow_v13.py \
  tests/test_surface_conformance_v13.py
```

Expected：0 failed；记录实际 passed/skipped/warnings。

- [ ] **Step 2: 运行冻结兼容与便携全量**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_schema_registry.py tests/test_signing.py \
  tests/test_delivery_package_v02.py tests/test_delivery_package_v03.py \
  tests/test_delivery_package_v04.py tests/test_delivery_package_v05.py
./.venv/bin/python -m pytest -q
```

Expected：0 failed；portable 环境允许已分类 platform skip，不允许新 warning。

- [ ] **Step 3: 请求独立 spec 与 quality/security 双审**

spec 审查逐条映射设计 §3–§15；quality/security 攻击：自签公钥、报告/内层包
分叉、路径穿越、archive bomb、GitHub source drift、Matrix sender 冒充、
ACK 丢失、三态退出码吞并、secret 泄露。任一 Critical/Important 未关闭不得继续。

- [ ] **Step 4: 按最终 revision 重建 candidate inventory**

仅当 source allowlist 变化时执行既有供应链流程；历史 inventory 不覆盖。运行：

```bash
OPENWORKPROOF_REQUIRE_LIVE=1 \
./.venv/bin/python -m pytest -q \
  tests/test_image_supply_chain.py \
  tests/test_candidate_supplychain_integration.py
```

Expected：0 failed、0 skipped。命令使用当前真实测试文件名。

- [ ] **Step 5: 运行 required-live 全量**

使用新 inventory 选择出的全限定 immutable RepoDigest 和 artifact root：

```bash
OPENWORKPROOF_REQUIRE_LIVE=1 \
OPENWORKPROOF_ARTIFACT_ROOT="$ARTIFACT_ROOT" \
OPENWORKPROOF_DOCKER_TEST_IMAGE="$FULLY_QUALIFIED_REPODIGEST" \
./.venv/bin/python -W error::pytest.PytestUnhandledThreadExceptionWarning \
  -m pytest -q
```

Expected：0 failed、0 skipped、无 unhandled-thread warning。不得以中止运行、
历史运行或 focused 运行替代。

- [ ] **Step 6: 非测试门与状态回填**

```bash
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests
git diff --check
git status --short
docker ps --filter label=openworkproof --format '{{.ID}}'
docker volume ls --filter label=openworkproof --format '{{.Name}}'
```

把实际 revision、命令、passed/failed/skipped/warnings 写入 `docs/status.md`：

```bash
git add docs/status.md supply-chain/images/candidates
git commit -m "build: bind openworkproof 1.3 release candidate"
```

- [ ] **Step 7: 完成分支但不擅自发布**

使用 `superpowers:finishing-a-development-branch`。先向用户展示提交序列、测试
证据、仍为 `not_evidenced` 的商业状态，再由用户决定 merge、push、tag、PyPI、
MCP Registry 与 GitHub Release；本计划不预授权外部发布。

## 2. 规格覆盖自审索引

| 设计规格要求 | 计划任务 |
|---|---|
| 一套 Core、A/C 双 surface | Tasks 6、8–12 |
| v0.1–v0.5 冻结 | Tasks 3、14 |
| companion 环境指纹 | Tasks 2–3 |
| 确定性报告 | Task 5 |
| 0/2/3/4 三态退出码 | Task 7 |
| GitHub Action/PR Check/HTML/JSON/证据包 | Tasks 8–9 |
| AgentTeams 三 Agent 与返工闭环 | Tasks 10–11 |
| 同一核心摘要与证据包 | Task 12 |
| 安全、ACK 丢失、篡改与并发 | Tasks 2、4、6、10、14 |
| 21 天付费试点但不虚构采用 | Task 13 |
| CI、文档、分发和 required-live | Tasks 1、13–14 |
| v0.6/A2A/支付等非目标 | §0 与 Task 14 审查边界 |
