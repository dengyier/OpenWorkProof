# OpenWorkProof for DeepSeek Harness V0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to implement this plan task-by-task. Use
> `superpowers:subagent-driven-development` only when the user explicitly asks
> for delegated workers. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build one externally reproducible DeepSeek Harness plugin that denies
native mutating-tool bypasses, executes one authorized code change through
OpenWorkProof-owned tools, independently reruns the frozen checks, and exports
an offline-verifiable human acceptance or rejection bundle.

**Architecture:** The existing Python OpenWorkProof package remains the only
protocol authority and gains a closed JSONL bridge plus a bounded DSH case
orchestrator. A separate TypeScript bundle registers `owp_apply_patch` and
`owp_run_tests`, combines async authorization with a monotonic final guard, and
correlates live tool results with durable session events. Audit emits signed
observation facts only; Enforce denies native `write`, `edit`, and unrestricted
`bash`, and Manager/Acceptor private keys never enter Harness.

**Tech Stack:** Python 3.10–3.13, Pydantic v2, Ed25519, RFC 8785 JCS, SQLite,
existing OpenWorkProof transactions, TypeScript, Node.js 20+, pnpm 10,
DeepSeek Harness `0.1.1-rc.2`, Cordis plugins, Vitest, pytest.

---

## 0. Authority, repositories, and hard boundaries

Authoritative design:
`docs/superpowers/specs/2026-08-26-openworkproof-deepseek-harness-plugin-v01-design.md`

Frozen core starting revision:
`61b76e8` on `/Users/molin/Project/openWorkProof`.

Implementation uses two local repositories:

```text
/Users/molin/Project/openWorkProof
/Users/molin/Project/openworkproof-dsh-plugin
```

The second path does not exist at plan time. Task 1 creates a local Git
repository only. Creating a GitHub repository, pushing, publishing npm/PyPI,
posting to Discussions, or announcing support requires separate user authority
and direct post-action verification.

Hard boundaries:

- V0.1 supports DeepSeek Harness `0.1.1-rc.2` only until another exact version
  passes the same live compatibility gate.
- Enforce exposes only `owp_apply_patch` and `owp_run_tests` as consequential
  tools. Native `write`, `edit`, and unrestricted `bash` are denied.
- The Agent may never supply an arbitrary test command. It supplies only the
  digest of a Manager-frozen test profile.
- Audit records `DshObservationRecordV01`; it never backfills an ActionReceipt
  after an unauthorized action.
- Manager and Acceptor private keys remain outside the Harness process, bridge
  arguments, environment, case directory, and exported public evidence.
- The Sidecar and Developer keys do not prove verifier or acceptor independence.
- Parallel tool calls, nested subagents, multiple sessions per case, and
  out-of-band mutations produce `UNKNOWN` or fail closed.
- No task changes frozen WorkOrder v0.1 or existing schema bytes. New DSH
  objects live in an independent companion surface.
- Public claims stop at the highest directly evidenced state: local, tested,
  committed, installable, externally reproduced, published, used, and adopted
  remain separate.

Every task follows RED → minimal GREEN → adjacent regression → `pip check` or
`pnpm test` → `git diff --check` → one single-purpose commit.

## 0.1 Target file map

### OpenWorkProof core repository

| File | Responsibility |
|---|---|
| `src/openworkproof/dsh_protocol.py` | closed bridge messages, observation record, error codes, canonical IDs |
| `src/openworkproof/dsh_case.py` | case manifest, exact decision-token store, key/path boundary validation |
| `src/openworkproof/dsh_execution.py` | adapt OWP-owned patch/test calls to existing transactions |
| `src/openworkproof/dsh_verifier.py` | independent Git readback, changed-path checks, frozen test rerun |
| `src/openworkproof/dsh_bridge.py` | JSONL stdio loop, version negotiation, idempotent dispatch, ACK recovery |
| `tests/test_dsh_protocol_v01.py` | strict models, canonicalization, observation/receipt boundary |
| `tests/test_dsh_case_v01.py` | case loading, key exclusion, token replay/expiry, path checks |
| `tests/test_dsh_execution_v01.py` | patch/test transaction adapters and zero-write denial paths |
| `tests/test_dsh_verifier_v01.py` | repository readback, test rerun, wrong criterion and tamper cases |
| `tests/test_dsh_bridge_v01.py` | stdio framing, recovery, operational/protocol error separation |
| `tests/test_dsh_end_to_end_v01.py` | disposable Git fixture through export and offline replay |
| `src/openworkproof/cli.py` | `dsh-bridge`, `dsh-case`, and external acceptance-draft commands |
| `src/openworkproof/signing.py` | DSH companion signing domains only |
| `pyproject.toml` | eventual 1.4.0 release metadata after release authorization |
| `README.md`, `README_en.md` | developer-preview install, exact scope, claims and non-claims |
| `docs/integrations/deepseek-harness.md` | bilingual workflow, threat model, file/key locations, uninstall |

### DeepSeek Harness plugin repository

| File | Responsibility |
|---|---|
| `package.json` | npm bundle manifest and exact DSH development compatibility |
| `pnpm-lock.yaml` | reproducible dependency graph |
| `tsconfig.json`, `vitest.config.ts` | build and unit-test configuration |
| `cordis.patch.yml` | Audit bundle rows; Enforce is an explicit profile override |
| `profiles/owp-verified.patch.yml` | Enforce configuration and native-mutator denial |
| `src/config.ts` | strict `audit`/`enforce` configuration and preflight |
| `src/bridge-client.ts` | child process, JSONL requests, timeouts, restart and shutdown |
| `src/policy.ts` | async authorization, token set, monotonic guard |
| `src/tools.ts` | `owp_apply_patch` and `owp_run_tests` definitions |
| `src/evidence.ts` | `tools/result` plus `session/event` correlation |
| `src/commands.ts` | `/owp-status`, `/owp-evidence`, `/owp-export` |
| `src/index.ts` | compose plugin effects only |
| `test/*.test.ts` | focused TypeScript behavior tests |
| `test/fixtures/fake-bridge.mjs` | deterministic bridge process for plugin tests |
| `scripts/live-preflight.mjs` | exact-version profile load and disposable-repo live gate |
| `README.md`, `README_zh.md` | bilingual installation and security boundaries |
| `SECURITY.md` | threat assumptions and vulnerability reporting |

---

### Task 1: Prove the exact DeepSeek Harness extension seams

**Files:**
- Create repository: `/Users/molin/Project/openworkproof-dsh-plugin`
- Create: `package.json`
- Create: `cordis.patch.yml`
- Create: `src/index.ts`
- Create: `test/compatibility.test.ts`
- Create: `tsconfig.json`
- Create: `vitest.config.ts`

- [x] **Step 1: Create the local repository and exact dependency baseline**

```bash
mkdir /Users/molin/Project/openworkproof-dsh-plugin
cd /Users/molin/Project/openworkproof-dsh-plugin
git init -b main
pnpm init
pnpm add -D typescript@5.9.2 vitest@3.2.4 \
  @deepseek-ai/dsh@0.1.1-rc.2 \
  @deepseek-ai/cordis@4.0.1 \
  @deepseek-ai/dsh-tools@0.1.1-rc.2 \
  @deepseek-ai/dsh-session@0.1.1-rc.2 \
  @deepseek-ai/dsh-commands@0.1.1-rc.2
```

Expected: a local repository exists; no remote exists; the lockfile resolves
the exact release-candidate versions or the task stops with a recorded package
availability conflict.

- [x] **Step 2: Write the RED compatibility test**

```ts
import { describe, expect, it } from 'vitest'
import { createCompatibilityProbe } from '../src/index.js'

describe('DeepSeek Harness compatibility', () => {
  it('requires async pre-execute, monotonic guard, result and durable events', () => {
    expect(createCompatibilityProbe()).toEqual({
      dshVersion: '0.1.1-rc.2',
      asyncPreExecute: true,
      monotonicGuard: true,
      liveResult: true,
      durableSessionEvent: true,
      commands: true,
    })
  })
})
```

Run: `pnpm vitest run test/compatibility.test.ts`

Expected: FAIL because `src/index.ts` does not export the probe.

- [x] **Step 3: Add the minimal bundle manifest and probe**

`package.json` must contain:

```json
{
  "name": "@openworkproof/dsh-plugin",
  "version": "0.1.0",
  "type": "module",
  "main": "lib/index.js",
  "files": ["lib", "cordis.patch.yml", "profiles", "README.md", "README_zh.md", "SECURITY.md"],
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "test": "vitest run",
    "typecheck": "tsc -p tsconfig.json --noEmit"
  },
  "dsh": {"bundle": {"patch": "./cordis.patch.yml"}}
}
```

`cordis.patch.yml`:

```yaml
- insert:
    - id: openworkproof-dsh
      name: '@openworkproof/dsh-plugin'
      config:
        mode: audit
        bridgeCommand: owp
        bridgeArgs: [dsh-bridge, --stdio]
```

`src/index.ts` initially exports the exact probe and an empty `apply()` so that
the profile can load without changing behavior.

- [x] **Step 4: Verify bundle composition against exact DSH**

```bash
pnpm test
pnpm typecheck
pnpm build
pnpm pack --pack-destination dist
pnpm exec dsh plugin --profile owp-compat add ./dist/openworkproof-dsh-plugin-0.1.0.tgz
pnpm exec dsh --profile owp-compat --dump-config
```

Expected: test and typecheck PASS; dump contains an
`@openworkproof/dsh-plugin` layer. If guard, event, or command APIs do not match
the exact package, stop Enforce development and record the incompatibility.

- [x] **Step 5: Commit the compatibility spike**

```bash
git add package.json pnpm-lock.yaml tsconfig.json vitest.config.ts \
  cordis.patch.yml src/index.ts test/compatibility.test.ts
git commit -m "chore: prove DeepSeek Harness plugin seams"
```

---

### Task 2: Define closed DSH bridge and observation objects

**Files:**
- Create: `src/openworkproof/dsh_protocol.py`
- Create: `tests/test_dsh_protocol_v01.py`
- Modify: `src/openworkproof/signing.py`

- [x] **Step 1: Write strict-model RED tests**

```python
def test_audit_observation_never_claims_authorization() -> None:
    record = _signed_observation(
        authorization_status="not_evidenced",
        receipt_digest=None,
    )
    assert verify_dsh_observation(record, _adapter_public_key())


def test_observation_rejects_action_receipt_without_authorization() -> None:
    with pytest.raises(ValidationError, match="receipt requires authorized"):
        _signed_observation(
            authorization_status="not_evidenced",
            receipt_digest="a" * 64,
        )


def test_bridge_message_is_closed_and_canonical() -> None:
    request = DshBridgeRequestV01.model_validate(_hello_request())
    assert canonical_bytes(request) == rfc8785.dumps(request.model_dump(mode="json"))
    with pytest.raises(ValidationError):
        DshBridgeRequestV01.model_validate({**_hello_request(), "extra": True})
```

Run: `./.venv/bin/python -m pytest -q tests/test_dsh_protocol_v01.py`

Expected: RED import failure.

- [x] **Step 2: Implement the closed companion models**

`dsh_protocol.py` defines immutable `extra="forbid"` objects:

```python
class DshExecutionIdentityV01(ProtocolModel):
    session_id: Identifier
    call_id: Identifier
    root_call_id: Identifier
    tool_name: Literal["owp_apply_patch", "owp_run_tests", "write", "edit", "bash"]
    arguments_digest: Digest64


class DshObservationRecordV01(SignedProtocolModel):
    _signed_domain = "dsh-observation-record"
    schema_version: Literal["openworkproof-dsh-observation/0.1"]
    record_id: Digest64
    host: Literal["deepseek-harness"]
    host_version: Literal["0.1.1-rc.2"]
    adapter_version: Literal["0.1.0"]
    execution: DshExecutionIdentityV01
    authorization_status: Literal["not_evidenced", "authorized", "denied"]
    live_result_digest: Digest64 | None
    durable_call_sequence: int | None
    durable_result_sequence: int | None
    receipt_digest: Digest64 | None
    evidence_gap_codes: tuple[Literal[
        "AUTHORIZATION_NOT_EVIDENCED",
        "DURABLE_CALL_MISSING",
        "DURABLE_RESULT_MISSING",
        "EVENT_SEQUENCE_CONFLICT",
        "OUT_OF_BAND_EXECUTION",
    ], ...]
    observed_at: CanonicalUTCTime
    nonce: Digest64
```

The validator requires UTF-8 sorted unique gap codes, paired durable call/result
sequences, and `receipt_digest` only when authorization is `authorized` and no
gap exists. `record_id` is derived from canonical content excluding signature,
digest, and itself.

Bridge requests and responses use a discriminated `message_type` union; the
closed request types are `hello`, `case_open`, `authorization_check`,
`observation_commit`, `action_execute`, `verify_request`, `acceptance_draft`,
`export_request`, and `shutdown`.

- [x] **Step 3: Add only the companion signing domain**

In `signing.py`, add `dsh-observation-record` to the v0.1 signed-domain set.
Do not change any existing domain or canonical bytes.

- [x] **Step 4: Run focused and signing regressions**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_dsh_protocol_v01.py \
  tests/test_signing.py \
  tests/test_schema_registry.py
./.venv/bin/python -m pip check
git diff --check
```

Expected: all PASS.

- [x] **Step 5: Commit**

```bash
git add src/openworkproof/dsh_protocol.py src/openworkproof/signing.py \
  tests/test_dsh_protocol_v01.py
git commit -m "feat: define DeepSeek Harness bridge protocol"
```

---

### Task 3: Freeze case configuration and private-key boundaries

**Files:**
- Create: `src/openworkproof/dsh_case.py`
- Create: `tests/test_dsh_case_v01.py`

- [x] **Step 1: Write RED tests for case and key isolation**

```python
def test_case_rejects_manager_or_acceptor_private_keys(tmp_path: Path) -> None:
    case = _write_case(tmp_path)
    (case / "acceptor-private-key.hex").write_text("00" * 32)
    with pytest.raises(DshCaseError, match="human private key"):
        load_dsh_case(case)


def test_case_requires_exact_repository_revision(tmp_path: Path) -> None:
    case = _write_case(tmp_path)
    _git(case / "repo", "commit", "--allow-empty", "-m", "drift")
    with pytest.raises(DshCaseError, match="source revision"):
        load_dsh_case(case)


def test_decision_token_is_exact_one_use() -> None:
    store = DecisionTokenStore(clock=_clock)
    token = store.issue(_execution(), expires_at=_future())
    assert store.consume(token, _execution())
    assert not store.consume(token, _execution())
```

- [x] **Step 2: Implement `DshCaseManifestV01`**

The manifest contains exact absolute runtime paths but signs only stable public
identities and relative scope:

```python
class DshCaseManifestV01(ProtocolModel):
    schema_version: Literal["openworkproof-dsh-case/0.1"]
    case_id: Digest64
    work_order_digest: Digest64
    source_revision: ObjectId40
    repository_root: str
    allowed_path_roots: tuple[CanonicalRoot, ...]
    denied_path_roots: tuple[CanonicalRoot, ...]
    allowed_tools: tuple[Literal["owp_apply_patch", "owp_run_tests"], ...]
    test_profile_digest: Digest64
    ledger_path: str
    evidence_root: str
    sidecar_key_path: str
    developer_key_path: str
    mode: Literal["audit", "enforce"]
```

`load_dsh_case()` rejects symlinks, roots outside the repository/case parent,
non-regular key files, key modes broader than `0600`, wrong current revision,
Manager/Acceptor private-key filenames or JSON keys, and unknown files in the
case control directory.

- [x] **Step 3: Implement exact one-use decision tokens**

```python
@dataclass(frozen=True, slots=True)
class DecisionToken:
    token: str
    execution_digest: str
    expires_at: datetime


class DecisionTokenStore:
    def issue(self, execution: DshExecutionIdentityV01, *, expires_at: datetime) -> DecisionToken:
        ...

    def consume(self, token: str, execution: DshExecutionIdentityV01) -> bool:
        ...
```

The implementation stores SHA-256 of the random 32-byte token, binds the
canonical execution digest, deletes on first consume, and rejects expired,
mismatched, missing, or replayed tokens without exception-driven allow.

- [x] **Step 4: Verify path, permission, replay and expiry matrices**

Run:

```bash
./.venv/bin/python -m pytest -q tests/test_dsh_case_v01.py
./.venv/bin/python -m pytest -q tests/test_policy.py
./.venv/bin/python -m pytest -q tests/test_mcp_server.py \
  -k "authorization_prefix_digest or stale_context"
git diff --check
```

Expected: all PASS.

- [x] **Step 5: Commit**

```bash
git add src/openworkproof/dsh_case.py tests/test_dsh_case_v01.py
git commit -m "feat: freeze DeepSeek Harness case boundaries"
```

---

### Task 4: Add the OWP-owned patch execution adapter

**Files:**
- Create: `src/openworkproof/dsh_execution.py`
- Create: `tests/test_dsh_execution_v01.py`

- [x] **Step 1: Write patch RED tests**

```python
def test_unauthorized_patch_never_calls_handler_or_writes_ledger(case) -> None:
    before = _snapshot_all_tables(case.ledger)
    with pytest.raises(DshExecutionDenied, match="OWP_AUTHORIZATION_DENIED"):
        execute_dsh_patch(case, _out_of_scope_patch(), clock=case.clock)
    assert case.patch_handler_calls == 0
    assert _snapshot_all_tables(case.ledger) == before


def test_authorized_patch_uses_existing_transaction(case) -> None:
    result = execute_dsh_patch(case, _in_scope_patch(), clock=case.clock)
    assert result.receipt.tool_name == "owp.apply_patch"
    assert result.changed_paths == ("src/example.txt",)
    assert result.receipt.digest == _replay_receipt(case)
```

- [x] **Step 2: Define the closed tool input**

```python
class DshApplyPatchInputV01(ProtocolModel):
    schema_version: Literal["openworkproof-dsh-apply-patch/0.1"]
    case_id: Digest64
    execution: DshExecutionIdentityV01
    decision_token: Digest64
    patch_utf8: str
    target_paths: tuple[CanonicalRoot, ...]
```

The adapter parses the patch with existing `repo_tools` logic, requires derived
paths to equal sorted declared paths, consumes the exact decision token, builds
the canonical `ApplyPatchArguments`/AgentRequest, and invokes existing
`execute_apply_patch()` with `apply_patch_in_candidate_workspace` as handler.

- [x] **Step 3: Implement without a post-hoc receipt path**

The only success path is:

```python
return execute_apply_patch(
    case.ledger_path,
    evidence_root=case.evidence_root,
    context=context,
    request=request,
    request_arguments=arguments,
    execution_facts=facts,
    sidecar_private_key=case.sidecar_private_key,
    patch_bytes=patch_bytes,
    candidate_workspace=case.candidate_workspace,
    handler=repo_tools.apply_patch_in_candidate_workspace,
    clock=clock,
)
```

Do not add a function that signs a receipt for a mutation already performed by
native DSH `write` or `edit`.

- [x] **Step 4: Run patch, policy, atomicity, and recovery tests**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_dsh_execution_v01.py \
  tests/test_apply_patch.py \
  tests/test_binding_transactions.py
git diff --check
```

Expected: all PASS; denial snapshots have zero writes.

- [x] **Step 5: Commit**

```bash
git add src/openworkproof/dsh_execution.py tests/test_dsh_execution_v01.py
git commit -m "feat: execute Harness patches through OWP"
```

---

### Task 5: Add external frozen test execution and independent Git verification

**Files:**
- Modify: `src/openworkproof/dsh_execution.py`
- Create: `src/openworkproof/dsh_verifier.py`
- Modify: `tests/test_dsh_execution_v01.py`
- Create: `tests/test_dsh_verifier_v01.py`

- [x] **Step 1: Write test and verifier RED cases**

```python
def test_agent_cannot_supply_an_arbitrary_command(case) -> None:
    payload = _run_tests_input(profile_digest="f" * 64)
    with pytest.raises(DshExecutionDenied, match="TEST_PROFILE_MISMATCH"):
        execute_dsh_tests(case, payload, clock=case.clock)


def test_independent_verifier_rejects_out_of_scope_file(case) -> None:
    (case.repo / "secrets.txt").write_text("drift")
    result = verify_dsh_code_change(case, clock=case.clock)
    assert result.status == "REFUTED"
    assert "OUT_OF_SCOPE_CHANGE" in result.reason_codes


def test_valid_signature_wrong_criterion_is_refuted(case) -> None:
    result = verify_dsh_code_change(case, criterion_digest="0" * 64, clock=case.clock)
    assert result.status == "REFUTED"
    assert "CRITERION_BINDING_MISMATCH" in result.reason_codes
```

- [x] **Step 2: Implement `execute_dsh_tests()`**

The tool input contains only `case_id`, execution identity, decision token, and
the frozen `test_profile_digest`. The bridge loads the command and fixed test
source from Manager-signed case inputs and delegates to a separate Verifier
worker. That worker owns the distinct Verifier credential and invokes existing
`execute_run_tests()`; the bridge validates the exact returned receipt and
committed correlation factors. The Harness and bridge never receive the
Verifier private key. The Agent never supplies argv, image digest, workspace
manifest, or verifier source bytes.

- [x] **Step 3: Implement independent verifier output**

```python
class DshVerificationResultV01(ProtocolModel):
    schema_version: Literal["openworkproof-dsh-verification/0.1"]
    case_id: Digest64
    status: Literal["VERIFIED", "REFUTED", "UNKNOWN"]
    source_revision: ObjectId40
    candidate_revision: ObjectId40 | None
    changed_paths: tuple[CanonicalRoot, ...]
    artifact_digests: tuple[Digest64, ...]
    test_profile_digest: Digest64
    test_exit_code: int | None
    reason_codes: tuple[str, ...]
    verified_at: CanonicalUTCTime
```

`verify_dsh_code_change()` independently scans Git status/tree, checks allowed
and denied roots, hashes declared files, reruns the frozen verifier profile,
replays authorization/receipt causality, and emits `UNKNOWN` when repository
identity or durable evidence cannot be read atomically.

- [x] **Step 4: Run verification and test-driver regressions**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_dsh_execution_v01.py \
  tests/test_dsh_verifier_v01.py \
  tests/test_run_tests_runner.py \
  tests/test_verification_report_v01.py \
  tests/test_verification_transactions_v02.py \
  tests/test_verification_transactions_v03.py
git diff --check
```

Expected: all PASS.

- [x] **Step 5: Commit**

```bash
git add src/openworkproof/dsh_execution.py src/openworkproof/dsh_verifier.py \
  tests/test_dsh_execution_v01.py tests/test_dsh_verifier_v01.py
git commit -m "feat: independently verify Harness code changes"
```

---

### Task 6: Implement the JSONL bridge and CLI entry points

**Files:**
- Create: `src/openworkproof/dsh_bridge.py`
- Create: `tests/test_dsh_bridge_v01.py`
- Modify: `src/openworkproof/cli.py`

- [x] **Step 1: Write RED framing and recovery tests**

```python
def test_bridge_stdout_contains_jsonl_only(tmp_path: Path) -> None:
    result = _run_bridge([_hello_line(), _shutdown_line()], tmp_path)
    assert result.returncode == 0
    assert all(json.loads(line) for line in result.stdout.splitlines())


def test_lost_action_ack_reads_back_committed_truth(bridge_case) -> None:
    bridge_case.drop_next_response("action_execute")
    first = bridge_case.call(_authorized_patch_request())
    assert first.error_code == "COMMIT_ACK_LOST"
    second = bridge_case.call(_same_request())
    assert second.status == "already_committed"
    assert bridge_case.receipt_count == 1


def test_protocol_denial_is_not_operational_failure(bridge_case) -> None:
    response = bridge_case.call(_out_of_scope_request())
    assert response.ok is False
    assert response.error_kind == "protocol_denial"
    assert response.error_code == "OWP_AUTHORIZATION_DENIED"
```

- [x] **Step 2: Implement deterministic dispatch**

`run_stdio_bridge(stdin, stdout, stderr, clock)` reads one bounded UTF-8 JSON
object per line, validates the discriminated request, dispatches exactly one
handler, and writes exactly one canonical JSON response. It rejects lines over
1 MiB, duplicate request IDs with different bytes, non-monotonic sequence,
wrong session, unsupported version, and messages after shutdown.

Diagnostics use `stderr`; imported modules may not print to stdout.

- [x] **Step 3: Add CLI commands**

Add parsers and dispatch for:

```text
owp dsh-bridge --stdio
owp dsh-case inspect CASE_DIR
owp dsh-case verify CASE_DIR
owp dsh-case acceptance-draft CASE_DIR --output FILE
owp dsh-case export CASE_DIR --output-directory DIR
```

`acceptance-draft` calls existing
`prepare_acceptance_decision_binding()` and writes canonical bytes without a
private key or signature. No CLI command accepts an Acceptor private key.

- [x] **Step 4: Run CLI, bridge, ACK-loss, and package tests**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_dsh_bridge_v01.py \
  tests/test_cli_transport.py \
  tests/test_package.py \
  tests/test_acceptance_bundle_v01.py
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests
git diff --check
```

Expected: all PASS and stdout framing remains clean.

- [x] **Step 5: Commit**

```bash
git add src/openworkproof/dsh_bridge.py src/openworkproof/cli.py \
  tests/test_dsh_bridge_v01.py
git commit -m "feat: add DeepSeek Harness stdio bridge"
```

---

### Task 7: Implement the TypeScript bridge client and preflight

**Files:**
- Create: `src/config.ts`
- Create: `src/bridge-client.ts`
- Create: `test/bridge-client.test.ts`
- Create: `test/fixtures/fake-bridge.mjs`

- [x] **Step 1: Write RED bridge-client tests**

```ts
it('negotiates exact versions before any case request', async () => {
  const bridge = await startFakeBridge({ hostVersion: '0.1.1-rc.2' })
  const client = await BridgeClient.start(config(bridge.command))
  expect(client.ready).toEqual({
    bridgeVersion: '0.1.0',
    openworkproofVersion: '1.3.0',
    hostVersion: '0.1.1-rc.2',
  })
})

it('fails closed on timeout and malformed stdout', async () => {
  await expect(BridgeClient.start(config('fake-bridge-malformed')))
    .rejects.toThrow('OWP_BRIDGE_PROTOCOL_ERROR')
})
```

- [x] **Step 2: Implement strict configuration**

```ts
export interface OwpPluginConfig {
  readonly mode: 'audit' | 'enforce'
  readonly bridgeCommand: string
  readonly bridgeArgs: readonly string[]
  readonly caseDirectory: string
  readonly requestTimeoutMs: number
}
```

Defaults are `audit`, `owp`, `['dsh-bridge', '--stdio']`, no implicit case
directory, and 5000 ms. Enforce without an explicit case directory fails at
startup.

- [x] **Step 3: Implement process ownership and JSONL requests**

`BridgeClient` owns one child process, reserves stdout for JSONL, forwards
stderr to DSH diagnostics with secret redaction, allocates monotonic sequence
and SHA-256 request IDs, rejects unknown response IDs, limits a line to 1 MiB,
uses exact timeout/abort behavior, and sends `shutdown` before termination.

- [x] **Step 4: Verify unit behavior**

```bash
pnpm test -- test/bridge-client.test.ts
pnpm typecheck
pnpm build
```

Expected: PASS; orphan child count is zero after every test.

- [x] **Step 5: Commit**

```bash
git add src/config.ts src/bridge-client.ts test/bridge-client.test.ts \
  test/fixtures/fake-bridge.mjs
git commit -m "feat: connect plugin to OWP bridge"
```

---

### Task 8: Register OWP-owned tools and the unbypassable guard

**Files:**
- Create: `src/policy.ts`
- Create: `src/tools.ts`
- Create: `test/policy.test.ts`
- Create: `test/tools.test.ts`
- Modify: `src/index.ts`
- Create: `profiles/owp-verified.patch.yml`

- [x] **Step 1: Write guard and bypass RED tests**

```ts
it.each(['write', 'edit', 'bash'])('denies native mutator %s in enforce', async name => {
  const decision = await runThroughPlugin({ mode: 'enforce', name, arguments: {} })
  expect(decision).toEqual({ kind: 'deny', reason: 'OWP_NATIVE_MUTATOR_DENIED' })
})

it('allows one exact OWP execution and rejects token replay', async () => {
  const exec = execution('owp_apply_patch', inScopePatch())
  await policy.preExecute(exec)
  expect(policy.guard(exec)).toBeUndefined()
  expect(policy.guard(exec)).toBe('OWP_DECISION_TOKEN_MISSING')
})

it('cannot be bypassed by an earlier pre-execute allow', async () => {
  const result = await shortCircuitBeforeOwp(execution('write', {}))
  expect(result.error?.message).toContain('OWP_NATIVE_MUTATOR_DENIED')
})
```

- [x] **Step 2: Implement async authorization plus symbol-token guard**

```ts
const NATIVE_MUTATORS = new Set(['write', 'edit', 'bash'])
const OWP_TOOLS = new Set(['owp_apply_patch', 'owp_run_tests'])
const allowed = new Set<ToolExecutionToken>()

ctx.on('tools/pre-execute', async (exec, next) => {
  if (!OWP_TOOLS.has(exec.name)) return next()
  const decision = await bridge.authorize(executionEnvelope(exec))
  if (decision.kind !== 'allow') return { kind: 'deny', reason: decision.errorCode }
  allowed.add(exec.token)
  return { kind: 'allow' }
})

ctx.tools.guard(exec => {
  if (config.mode === 'enforce' && NATIVE_MUTATORS.has(exec.name)) {
    return 'OWP_NATIVE_MUTATOR_DENIED'
  }
  if (!OWP_TOOLS.has(exec.name)) return undefined
  return allowed.delete(exec.token) ? undefined : 'OWP_DECISION_TOKEN_MISSING'
})
```

The bridge still validates and consumes its own wire decision token inside the
tool body; the symbol set only prevents Harness-pipeline bypass.

- [x] **Step 3: Register two closed tools**

`owp_apply_patch` accepts only `patch_utf8` and sorted `target_paths`.
`owp_run_tests` accepts only `test_profile_digest`. Their bodies call
`action_execute` and return the bridge's closed result. They do not call native
`write`, `edit`, or `bash` and do not accept arbitrary argv.

`profiles/owp-verified.patch.yml` restates the complete plugin config with
`mode: enforce`; it never modifies DSH core rows to weaken native sandboxing.

- [x] **Step 4: Run plugin policy and tool tests**

```bash
pnpm test -- test/policy.test.ts test/tools.test.ts
pnpm typecheck
pnpm build
```

Expected: PASS, including earlier-listener bypass and replay cases.

- [x] **Step 5: Commit**

```bash
git add src/policy.ts src/tools.ts src/index.ts profiles/owp-verified.patch.yml \
  test/policy.test.ts test/tools.test.ts
git commit -m "feat: enforce OWP-owned Harness tools"
```

---

### Task 9: Correlate live results with committed session events

**Files:**
- Core modify: `src/openworkproof/dsh_protocol.py`
- Core modify: `src/openworkproof/dsh_bridge.py`
- Core modify: `tests/test_dsh_bridge_v01.py`
- Create: `src/evidence.ts`
- Create: `test/evidence.test.ts`
- Modify: `src/index.ts`

- [x] **Step 1: Write RED correlation tests**

```ts
it('commits only after live result and durable call/result agree', async () => {
  const correlator = new EvidenceCorrelator(bridge)
  correlator.observeLive(exec, successResult())
  correlator.observeDurable(session, toolCallEvent(10, exec.callId))
  correlator.observeDurable(session, toolResultEvent(11, exec.callId))
  await expect(correlator.flush(exec.callId)).resolves.toMatchObject({ gapCodes: [] })
})

it.each(['missing', 'duplicate', 'reordered', 'substituted'])('%s event is UNKNOWN', async kind => {
  const result = await correlatedFixture(kind)
  expect(result.status).toBe('UNKNOWN')
  expect(result.receiptDigest).toBeUndefined()
})
```

- [x] **Step 2: Implement bounded correlation state**

`EvidenceCorrelator` keeps one session and one in-flight call, hashes the frozen
live result, accepts only contiguous durable sequence, pairs `tool/call` and
`tool/result` by call ID, and sends `observation_commit` after both sides exist.
It emits an explicit gap and clears state on duplicate, reorder, wrong session,
unknown call, nested call, or parallel in-flight call.

The adapter sends only a closed observation draft. The Python bridge binds any
claimed receipt to the exact action result previously committed in that bridge
session, signs the record with the case-owned Sidecar key, and stores the
canonical record immutably. No signing key enters the TypeScript process.

- [x] **Step 3: Attach exact DSH events**

Register:

```ts
ctx.on('tools/result', (exec, result) => correlator.observeLive(exec, result))
ctx.on('session/event', (session, event) => correlator.observeDurable(session, event))
```

Audit commits `DshObservationRecordV01`. Enforce may expose a receipt digest
only when the bridge already committed the OWP transaction and the durable
event pair agrees.

- [x] **Step 4: Run correlation and existing compatibility tests**

```bash
pnpm test -- test/evidence.test.ts test/compatibility.test.ts
pnpm typecheck
pnpm build
```

Expected: PASS; no test upgrades missing evidence to success.

- [x] **Step 5: Commit**

```bash
git add src/evidence.ts src/index.ts test/evidence.test.ts
git commit -m "feat: correlate Harness evidence durably"
```

---

### Task 10: Add bilingual human commands without signing acceptance

**Files:**
- Create: `src/commands.ts`
- Create: `test/commands.test.ts`
- Modify: `src/index.ts`

- [x] **Step 1: Write RED command tests**

```ts
it('shows verified as awaiting human acceptance', async () => {
  const result = await executeCommand('/owp-status', bridgeStatus('VERIFIED'))
  expect(result.text).toContain('VERIFIED — AWAITING HUMAN ACCEPTANCE')
  expect(result.text).not.toContain('ACCEPTED')
})

it('exports an acceptance draft but exposes no signing command', async () => {
  expect(commandNames()).toEqual(['owp-evidence', 'owp-export', 'owp-status'])
  expect(await executeCommand('/owp-export')).toMatchObject({ kind: 'text' })
})
```

- [x] **Step 2: Register the three commands**

Use `ctx.commands.register()` for `owp-status`, `owp-evidence`, and
`owp-export`. Language follows plugin config `zh-CN` or `en`; stable protocol
state identifiers remain English. Export calls the bridge and returns only the
created local path, digest, and verification instruction.

- [x] **Step 3: Assert the negative authority surface**

There is no `owp-accept`, `owp-sign`, private-key input, generic shell command,
or Agent-callable acceptance tool. Documentation sends the human to the
external `owp dsh-case acceptance-draft` flow.

- [x] **Step 4: Run command and full plugin tests**

```bash
pnpm test
pnpm typecheck
pnpm build
```

Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add src/commands.ts src/index.ts test/commands.test.ts
git commit -m "feat: add bilingual OWP Harness commands"
```

---

### Task 11: Close the disposable Git fixture end to end

**Files:**
- Create: `tests/test_dsh_end_to_end_v01.py`
- Create: `tests/fixtures/dsh-code-change/`
- Create: `scripts/create_dsh_fixture.py`
- Create in plugin repo: `scripts/live-preflight.mjs`

- [ ] **Step 1: Write the Python end-to-end RED test**

The test must perform this exact sequence:

```python
def test_verified_code_change_closed_loop(tmp_path: Path) -> None:
    case = create_dsh_fixture(tmp_path)
    assert deny_native_out_of_scope_write(case).code == "OWP_NATIVE_MUTATOR_DENIED"
    patch = execute_authorized_patch(case)
    assert patch.receipt_digest
    test_result = execute_frozen_tests(case)
    assert test_result.exit_code == 0
    verification = verify_dsh_code_change(case, clock=case.clock)
    assert verification.status == "VERIFIED"
    draft = prepare_external_acceptance_draft(case)
    assert "signature" not in draft.payload
    accepted = externally_sign_and_commit_fixture_acceptance(case, draft)
    export = export_dsh_case(case)
    assert verify_exported_delivery_case(export).case_stage == "ACCEPTED"
    tamper_one_artifact(export)
    with pytest.raises(DeliveryCaseError):
        verify_exported_delivery_case(export)
```

- [ ] **Step 2: Create the deterministic fixture builder**

The fixture creates a small Git repository, signed WorkOrder/Grant/binding,
separate Developer/Sidecar/Verifier keys, Manager and Acceptor keys outside the
case directory, a fixed test profile, candidate workspace, ledger and evidence
root. All timestamps are injected and all expected digests are deterministic.

- [ ] **Step 3: Add a real DSH live preflight**

`scripts/live-preflight.mjs` installs the packed plugin into a temporary
profile, starts exact DSH with the fixture workspace, confirms the bundle in
`--dump-config`, runs the closed tool sequence through the tool runtime, and
checks that native `write` is denied. It records exact DSH, plugin, OWP, Node,
Python and artifact versions.

- [ ] **Step 4: Run focused end-to-end gates**

Core:

```bash
./.venv/bin/python -m pytest -q tests/test_dsh_end_to_end_v01.py
```

Plugin:

```bash
pnpm test
pnpm build
pnpm pack --pack-destination dist
node scripts/live-preflight.mjs dist/openworkproof-dsh-plugin-0.1.0.tgz
```

Expected: deny, authorized patch, frozen tests, verification, external
acceptance, export, clean replay, and tamper failure all pass for the exact
artifacts.

- [ ] **Step 5: Commit both repositories**

Core:

```bash
git add tests/test_dsh_end_to_end_v01.py tests/fixtures/dsh-code-change \
  scripts/create_dsh_fixture.py
git commit -m "test: close verified Harness code change"
```

Plugin:

```bash
git add scripts/live-preflight.mjs
git commit -m "test: add live DeepSeek Harness preflight"
```

---

### Task 12: Document installation, security, and exact claim boundaries

**Files:**
- Core modify: `README.md`, `README_en.md`, `docs/status.md`
- Core create: `docs/integrations/deepseek-harness.md`
- Plugin create: `README.md`, `README_zh.md`, `SECURITY.md`
- Core modify: `tests/test_documentation_boundaries.py`

- [ ] **Step 1: Write documentation RED assertions**

Add literal checks for:

```python
for literal in (
    "DeepSeek Harness 0.1.1-rc.2",
    "Audit emits ObservationRecord",
    "Enforce denies native write/edit/bash",
    "VERIFIED != ACCEPTED",
    "Manager and Acceptor private keys remain outside Harness",
    "customer_adoption: not_evidenced",
    "deepseek_endorsement: not_evidenced",
):
    assert literal in combined_docs
```

- [ ] **Step 2: Write the bilingual user journey**

Documentation must contain exact install, Audit/Enforce distinction, five-minute
fixture, external acceptance, offline verification, uninstall, evidence
retention, files/processes/network behavior, collected/excluded fields, known
limitations, and compatibility table.

Do not describe local live preflight as adoption, production use, customer
delivery, or DeepSeek endorsement.

- [ ] **Step 3: Add package security disclosures**

`SECURITY.md` states that the plugin is trusted local code, spawns `owp`, can
observe declared tool metadata, cannot prove unobserved side effects, and keeps
human authority keys outside its process. It gives a private vulnerability
contact already authorized for the project or points to GitHub private security
advisories; it must not invent an inbox.

- [ ] **Step 4: Verify documentation and package rendering**

```bash
./.venv/bin/python -m pytest -q tests/test_documentation_boundaries.py
git diff --check
```

Plugin:

```bash
pnpm pack --pack-destination dist
tar -tf dist/openworkproof-dsh-plugin-0.1.0.tgz
```

Expected: docs tests PASS; tarball contains built JS, patch files, bilingual
README, license and security policy, but no source maps with local paths,
fixtures, secrets, or private keys.

- [ ] **Step 5: Commit both documentation changes**

Core:

```bash
git add README.md README_en.md docs/status.md \
  docs/integrations/deepseek-harness.md tests/test_documentation_boundaries.py
git commit -m "docs: explain verified DeepSeek Harness delivery"
```

Plugin:

```bash
git add README.md README_zh.md SECURITY.md package.json
git commit -m "docs: publish Harness plugin boundaries"
```

---

### Task 13: Run release-candidate verification and supply-chain binding

**Files:**
- Core modify only if required: `pyproject.toml`, `server.json`, `mcp.json`, package-version tests
- Core modify only if source allowlist closure requires it: `supply-chain/images/trusted-helper/SOURCE_ALLOWLIST`
- Core create when required: `supply-chain/images/candidates/<revision>.json`
- Plugin create: `dist/openworkproof-dsh-plugin-0.1.0.tgz` outside Git or in release staging only
- Plugin create: `dist/SHA256SUMS` outside Git or in release staging only

- [ ] **Step 1: Run focused protocol and plugin gates**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_dsh_protocol_v01.py \
  tests/test_dsh_case_v01.py \
  tests/test_dsh_execution_v01.py \
  tests/test_dsh_verifier_v01.py \
  tests/test_dsh_bridge_v01.py \
  tests/test_dsh_end_to_end_v01.py
```

Plugin:

```bash
pnpm test
pnpm typecheck
pnpm build
```

Expected: zero failures and zero unclassified skips.

- [ ] **Step 2: Run core regressions before version changes**

```bash
./.venv/bin/python -m pytest -q
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests
git diff --check
```

If required-live/candidate gates require Docker or a new immutable candidate
inventory, follow the repository's existing inventory-generation procedure;
never overwrite a historical candidate and never weaken the allowlist to make
tests green.

- [ ] **Step 3: Build and verify exact distributable artifacts**

Core:

```bash
./.venv/bin/python -m build
python -m venv /tmp/owp-dsh-install
/tmp/owp-dsh-install/bin/pip install dist/openworkproof-1.4.0-py3-none-any.whl
/tmp/owp-dsh-install/bin/owp dsh-bridge --help
```

Plugin:

```bash
pnpm pack --pack-destination dist
shasum -a 256 dist/openworkproof-dsh-plugin-0.1.0.tgz > dist/SHA256SUMS
node scripts/live-preflight.mjs dist/openworkproof-dsh-plugin-0.1.0.tgz
```

Expected: clean-environment install and live preflight PASS for the exact wheel
and tarball. Version `1.4.0` is a release-candidate metadata decision only;
publishing remains unauthorized.

- [ ] **Step 4: Obtain two independent read-only reviews**

Review A checks specification compliance and first-principles scope. Review B
checks code/security, key custody, fail-closed behavior, package contents, and
artifact/revision binding. Every P0/P1 finding must be fixed and both focused
and regression gates rerun before READY.

- [ ] **Step 5: Commit release-candidate metadata only after exact gates pass**

```bash
git add pyproject.toml server.json mcp.json tests/test_package.py \
  supply-chain/images
git commit -m "build: prepare DeepSeek Harness bridge release candidate"
```

Omit files that did not change. Do not tag, push, publish, or announce.

---

### Task 14: Present integration choices without assuming publication authority

**Files:**
- Modify: this plan, checking only steps supported by direct evidence
- Create: `docs/handoffs/2026-08-26-deepseek-harness-plugin-v01.md`

- [ ] **Step 1: Record exact repository states**

For both repositories record branch, full HEAD, worktree status, remote state,
artifact SHA-256, focused/full test counts, DSH/OWP/Node/Python versions, and
review outcomes.

- [ ] **Step 2: Record evidence levels separately**

The handoff must distinguish:

```text
designed
implemented
tested
committed
merged
pushed
packaged
published
installed in another environment
externally reproduced
used
adopted
```

- [ ] **Step 3: State unresolved boundaries**

Always report current evidence for customer adoption, payment, production use,
organizational verifier independence, DeepSeek endorsement, npm publication,
PyPI publication, and public marketplace/directory listing.

- [ ] **Step 4: Offer explicit finishing choices**

Present separately:

1. keep both repositories local for another review;
2. merge the core feature locally;
3. create/push the plugin remote;
4. publish release candidates;
5. run an external reproduction before publication.

No choice implies another.

- [ ] **Step 5: Commit the handoff**

```bash
git add docs/handoffs/2026-08-26-deepseek-harness-plugin-v01.md \
  docs/superpowers/plans/2026-08-26-openworkproof-deepseek-harness-plugin-v01.md
git commit -m "docs: hand off DeepSeek Harness plugin candidate"
```

## Final verification checklist

- [ ] Exact DSH version and official APIs rechecked at implementation time.
- [ ] Native `write`, `edit`, and unrestricted `bash` denied in Enforce.
- [ ] OWP-owned patch/test tools are the only consequential success path.
- [ ] Another pre-execution listener cannot bypass the monotonic guard.
- [ ] Audit never creates an ActionReceipt without prior authorization.
- [ ] Live results and durable session events correlate exactly.
- [ ] Independent Git readback and frozen test rerun can return REFUTED/UNKNOWN.
- [ ] Manager and Acceptor private keys never enter Harness or exports.
- [ ] Agent has no acceptance-signing surface.
- [ ] Clean export verifies offline; tampering fails.
- [ ] Plugin tarball installs into a clean exact-version profile.
- [ ] Core wheel and plugin tarball belong to the reviewed revisions.
- [ ] Focused, adversarial, regression, candidate, and required-live gates pass.
- [ ] Documentation claims match direct evidence.
- [ ] Merge, push, registry publication, community announcement, real use, and adoption remain separately verified states.
