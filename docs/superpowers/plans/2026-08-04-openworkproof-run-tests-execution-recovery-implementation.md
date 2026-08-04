# OpenWorkProof Verifier `run_tests` Execution Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one real, immutable, no-network Docker execution path for Verifier `owp.run_tests` that recovers covered controller crashes without repeating Docker start, Receipt publication, or quota charge.

**Architecture:** Extend the existing handler journal with the signed request and canonical execution contract, keep `mcp_server.py` as the protocol coordinator, and add typed Docker execution/reconciliation primitives to `repo_tools.py`. A frozen standalone runner in the execution image emits canonical start/result envelopes; the Sidecar validates those facts before using the existing evidence publication and signed Receipt transaction.

**Tech Stack:** Python 3.12, SQLite, Pydantic 2.13.4, RFC 8785, Ed25519, Git 2.47.3, Docker 29.5.2, pytest 9.1.1, OCI image-layout archives.

---

## Execution Boundary

- Work only in `/Users/molin/Project/openWorkProof` on branch `codex/run-tests-execution-recovery`.
- Design authority:
  `docs/superpowers/specs/2026-08-04-openworkproof-run-tests-execution-recovery-design.md`
  at commit `e419c7d` or a descendant containing the same approved requirements.
- Do not add Developer mode, real rollback execution, MCP transport, CLI,
  AgentTeams, AcceptanceReceipt, LICENSE, registry publication, or Day 0 claims.
- Keep the Sidecar private key outside Docker.
- Do not overwrite any historical candidate inventory, context, or archive.
- Add one focused failing test, observe the expected failure, implement only
  that behavior, rerun focused tests, and commit before starting the next task.
- Before each commit, stage only the named files and run
  `git diff --cached --check`.

## File Map

- Modify `src/openworkproof/repo_tools.py`: internal execution contracts,
  candidate snapshot extraction, deterministic Docker bindings, typed
  reconciliation, and the concrete runtime driver.
- Modify `src/openworkproof/evidence.py`: versioned handler journal schema.
- Modify `src/openworkproof/mcp_server.py`: journal persistence, recovery, typed
  execution outcome handling, and Receipt integration.
- Create `supply-chain/images/execution/run_tests_runner.py`: standalone frozen
  in-container contract/snapshot/test runner.
- Modify `supply-chain/images/execution/Dockerfile`: copy and freeze the runner
  entrypoint.
- Modify `supply-chain/images/prepare_context.py`: bind runner Git bytes into
  revision-specific execution contexts.
- Modify `supply-chain/images/README.md`: document the candidate execution and
  recovery boundary.
- Modify `tests/test_sandbox.py`: pure contract, snapshot, Docker binding,
  reconciliation, and required-live driver tests.
- Create `tests/test_run_tests_runner.py`: standalone runner contract and
  subprocess tests.
- Modify `tests/test_mcp_server.py`: journal, coordination, Receipt, quota, and
  crash-recovery tests.
- Modify `tests/test_prepare_image_context.py`: runner context binding tests.
- Modify `tests/test_image_supply_chain.py`: versioned candidate inventory and
  runner image-definition tests.
- Modify `tests/test_candidate_supplychain_integration.py`: current-definition
  selection and live artifact-chain tests.
- Create one new
  `supply-chain/images/candidates/$OWP_SOURCE_REVISION.json` only after the
  final code-definition revision exists.

### Task 1: Freeze Internal Execution Contracts and Canonical Codecs

**Files:**

- Modify: `src/openworkproof/repo_tools.py`
- Modify: `tests/test_sandbox.py`

- [ ] **Step 1: Write RED tests for the exact contract, marker, and result**

Add imports and tests that construct these exact typed values:

```python
def test_run_tests_execution_contract_round_trips_canonical_bytes() -> None:
    contract = repo_tools.RunTestsExecutionContract(
        execution_id="1" * 64,
        request_digest="2" * 64,
        arguments_digest="3" * 64,
        candidate_workspace_id="4" * 64,
        source_artifact_sha256="5" * 64,
        source_commit="6" * 40,
        candidate_commit="7" * 40,
        workspace_manifest_digest="8" * 64,
        container_image_digest="sha256:" + "9" * 64,
        command_digest="a" * 64,
        fixed_test_source_digest="b" * 64,
    )
    encoded = repo_tools.encode_run_tests_execution_contract(contract)
    assert encoded == rfc8785.dumps(
        {
            "arguments_digest": "3" * 64,
            "candidate_commit": "7" * 40,
            "candidate_workspace_id": "4" * 64,
            "command_digest": "a" * 64,
            "container_image_digest": "sha256:" + "9" * 64,
            "execution_id": "1" * 64,
            "fixed_test_source_digest": "b" * 64,
            "request_digest": "2" * 64,
            "schema_version": "openworkproof-run-contract/0.1",
            "source_artifact_sha256": "5" * 64,
            "source_commit": "6" * 40,
            "test_mode": "verifier",
            "tool_name": "owp.run_tests",
            "workspace_manifest_digest": "8" * 64,
        }
    )
    assert repo_tools.decode_run_tests_execution_contract(encoded) == contract
```

Also add:

```python
def test_run_tests_result_requires_one_closed_outcome() -> None:
    with pytest.raises(ValueError, match="closed outcome"):
        repo_tools.RunTestsResultEnvelope(
            execution_id="1" * 64,
            execution_contract_digest="2" * 64,
            actual_exit_code=1,
            failure_code="TIMEOUT",
            stdout_bytes=0,
            stdout_sha256=hashlib.sha256(b"").hexdigest(),
            stderr_bytes=0,
            stderr_sha256=hashlib.sha256(b"").hexdigest(),
        )
```

Parametrize decoder rejection for empty bytes, 8193 bytes, duplicate keys,
unknown keys, trailing newline, BOM, non-canonical key order, wrong scalar
types, developer mode, wrong tool name, and result exit codes outside `0..255`.

- [ ] **Step 2: Run the contract tests and observe RED**

Run:

```bash
./.venv/bin/python -m pytest tests/test_sandbox.py -k 'run_tests_execution_contract or run_tests_result' -q
```

Expected: collection or attribute failure because the three types and codecs
do not exist.

- [ ] **Step 3: Add the minimal exact types and strict codecs**

Add these package types near the existing Docker dataclasses:

```python
RunTestsFailureCode = Literal["OUTPUT_LIMIT", "TIMEOUT", "DISK_LIMIT"]


@dataclass(frozen=True, slots=True)
class RunTestsExecutionContract:
    execution_id: str
    request_digest: str
    arguments_digest: str
    candidate_workspace_id: str
    source_artifact_sha256: str
    source_commit: str
    candidate_commit: str
    workspace_manifest_digest: str
    container_image_digest: str
    command_digest: str
    fixed_test_source_digest: str


@dataclass(frozen=True, slots=True)
class RunTestsStartedEnvelope:
    execution_id: str
    execution_contract_digest: str


@dataclass(frozen=True, slots=True)
class RunTestsResultEnvelope:
    execution_id: str
    execution_contract_digest: str
    actual_exit_code: int | None
    failure_code: RunTestsFailureCode | None
    stdout_bytes: int
    stdout_sha256: str
    stderr_bytes: int
    stderr_sha256: str

    def __post_init__(self) -> None:
        completed = self.actual_exit_code is not None and self.failure_code is None
        failed = self.actual_exit_code is None and self.failure_code is not None
        if completed == failed:
            raise ValueError("run-tests result does not contain one closed outcome")
```

Implement exact RFC 8785 encoders and duplicate-key-rejecting JSON decoders.
Every decoder must read at most 8193 bytes, require exact keys, reconstruct the
typed value, re-encode it, and require byte equality before returning. Use the
three schema versions from the design and no permissive defaults.

Add:

```python
FROZEN_VERIFIER_ARGV = (
    "/opt/venv/bin/python",
    "-I",
    "-m",
    "pytest",
    "-q",
)


def frozen_verifier_command_digest() -> str:
    return hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/verifier-command/v0.1",
                "argv": list(FROZEN_VERIFIER_ARGV),
            }
        )
    ).hexdigest()
```

- [ ] **Step 4: Run GREEN and existing sandbox regression**

Run:

```bash
./.venv/bin/python -m pytest tests/test_sandbox.py -q
```

Expected: all sandbox tests pass; Docker tests may perform only their existing
precise environment skip when required-live is not enabled.

- [ ] **Step 5: Commit Task 1**

```bash
git add src/openworkproof/repo_tools.py tests/test_sandbox.py
git diff --cached --check
git commit -m "feat: freeze run tests execution contracts"
```

### Task 2: Extract a Closed Candidate Execution Snapshot

**Files:**

- Modify: `src/openworkproof/repo_tools.py`
- Modify: `tests/test_trusted_helper.py`
- Modify: `tests/test_sandbox.py`

- [ ] **Step 1: Write a successful snapshot RED test**

Reuse the trusted-helper candidate fixture and add:

```python
def test_prepare_candidate_execution_snapshot_returns_exact_files(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    result = repo_tools.prepare_candidate_execution_snapshot(
        repo_tools.CandidateExecutionSnapshotRequest(
            runtime_root=candidate.runtime_root,
            workspace_id=candidate.workspace_id,
            source_artifact_sha256=candidate.source_artifact_sha256,
            expected_head_commit=candidate.head_commit,
            expected_workspace_manifest_digest=candidate.workspace_manifest_digest,
        )
    )
    assert result.head_commit == candidate.head_commit
    assert result.workspace_manifest_digest == candidate.workspace_manifest_digest
    assert result.plan.files == (
        repo_tools.SourceFile(path="README.md", mode="100644", content=b"base\n"),
    )
```

- [ ] **Step 2: Run RED**

```bash
./.venv/bin/python -m pytest tests/test_trusted_helper.py::test_prepare_candidate_execution_snapshot_returns_exact_files -q
```

Expected: FAIL because the request, result, and function do not exist.

- [ ] **Step 3: Implement the package-private snapshot boundary**

Add:

```python
@dataclass(frozen=True, slots=True)
class CandidateExecutionSnapshotRequest:
    runtime_root: Path
    workspace_id: str
    source_artifact_sha256: str
    expected_head_commit: str
    expected_workspace_manifest_digest: str


@dataclass(frozen=True, slots=True)
class CandidateExecutionSnapshot:
    head_commit: str
    workspace_manifest_digest: str
    plan: ExecutionSnapshotPlan
```

`prepare_candidate_execution_snapshot` must reuse the existing candidate
control/Git/index/workspace checkpoint verification. Read every regular file
through descriptor-relative `O_NOFOLLOW` opens, require one link, bound each
file to the existing 1 MiB limit and the whole manifest to 512 entries, compare
pre/open/post identity and SHA-256, and re-scan the full workspace identity
after all bytes are read. Feed the exact `SourceFile` tuple into
`derive_execution_snapshot_plan`. Reject any symlink, hardlink, special file,
extra file, manifest mismatch, or identity drift as `RECOVERY_REQUIRED`.

- [ ] **Step 4: Add adversarial snapshot tests one at a time**

Cover sibling in-place change, globally woven ABA, 513th entry before open,
symlink, hardlink, FIFO, oversize file, wrong source digest, wrong HEAD, wrong
manifest digest, control replacement, index drift, and fd cleanup after every
failure. Reuse the existing checkpoint hooks rather than sleeping.

- [ ] **Step 5: Run GREEN**

```bash
./.venv/bin/python -m pytest tests/test_trusted_helper.py tests/test_sandbox.py -q
```

Expected: all focused tests pass without new skips.

- [ ] **Step 6: Commit Task 2**

```bash
git add src/openworkproof/repo_tools.py tests/test_trusted_helper.py tests/test_sandbox.py
git diff --cached --check
git commit -m "feat: close candidate execution snapshots"
```

### Task 3: Version the Handler Journal and Persist Recovery Inputs

**Files:**

- Modify: `src/openworkproof/evidence.py`
- Modify: `src/openworkproof/mcp_server.py`
- Modify: `tests/test_mcp_server.py`

- [ ] **Step 1: Write journal schema RED tests**

Add a test that opens a newly initialized ledger and asserts:

```python
columns = connection.execute(
    "PRAGMA table_info(handler_executions)"
).fetchall()
assert {row[1] for row in columns} >= {
    "request_json",
    "execution_contract_json",
    "execution_contract_digest",
}
```

Add inserts proving that `owp.run_tests` rejects null recovery fields while
`owp.rollback_patch` rejects non-null recovery fields.

- [ ] **Step 2: Run RED**

```bash
./.venv/bin/python -m pytest tests/test_mcp_server.py -k 'journal_schema or recovery_fields' -q
```

Expected: FAIL because the columns are absent.

- [ ] **Step 3: Define the versioned schema exactly**

Rename the current two-tool schema to
`_HANDLER_EXECUTION_SCHEMA_V1`. Define the new current schema with the three
nullable text columns and this closed CHECK:

```sql
CHECK (
    (
        tool_name = 'owp.run_tests'
        AND request_json IS NOT NULL
        AND execution_contract_json IS NOT NULL
        AND execution_contract_digest IS NOT NULL
    )
    OR
    (
        tool_name = 'owp.rollback_patch'
        AND request_json IS NULL
        AND execution_contract_json IS NULL
        AND execution_contract_digest IS NULL
    )
)
```

Retain the original run-tests-only legacy schema constant. Update
`_ensure_handler_execution_schema` to recognize both predecessors, migrate only
an empty table inside the existing transaction, and reject a non-empty old
table with `RECOVERY_REQUIRED`.

- [ ] **Step 4: Persist and reload exact request/contract bytes**

Change `_reserve_handler_execution` to accept
`RunTestsExecutionContract | None`. For run-tests rows, serialize the signed
AgentRequest with RFC 8785, enforce the existing request byte limit, encode the
contract, compute its SHA-256, and insert all three fields. For rollback rows,
insert nulls.

Add a private loader returning:

```python
@dataclass(frozen=True, slots=True)
class _StoredRunTestsExecution:
    execution_id: str
    request: AgentRequest
    contract: repo_tools.RunTestsExecutionContract
    reserved_at: datetime
    state: Literal["RESERVED", "STARTED_UNCONFIRMED"]
```

The loader must parse and re-verify canonical request bytes, request digest,
contract digest, duplicated journal fields, Verifier tool/mode, and trusted UTC
second. It must not accept the next caller's request as a substitute.

- [ ] **Step 5: Add migration and tamper tests**

Cover empty V1 migration, empty legacy migration, non-empty V1 rejection,
non-empty legacy rejection, duplicate-key request JSON, non-canonical request,
contract digest mismatch, journal-column mismatch, developer contract, and
rollback insertion/regression.

- [ ] **Step 6: Run GREEN**

```bash
./.venv/bin/python -m pytest tests/test_mcp_server.py -q
./.venv/bin/python -m pytest tests/test_receipt_chain.py -q
```

Expected: all MCP and receipt-chain tests pass.

- [ ] **Step 7: Commit Task 3**

```bash
git add src/openworkproof/evidence.py src/openworkproof/mcp_server.py tests/test_mcp_server.py
git diff --cached --check
git commit -m "feat: persist run tests recovery inputs"
```

### Task 4: Add Deterministic Docker Bindings and Pure Reconciliation

**Files:**

- Modify: `src/openworkproof/repo_tools.py`
- Modify: `tests/test_sandbox.py`

- [ ] **Step 1: Write deterministic binding RED tests**

Add:

```python
def test_derive_run_tests_docker_binding_is_stable_and_closed() -> None:
    binding = repo_tools.derive_run_tests_docker_binding("a" * 64)
    assert binding.execution_id == "a" * 64
    assert binding.container_name == "owp-run-" + "a" * 32
    assert binding.staging_container_name == "owp-stage-" + "a" * 32
    assert binding.workspace_volume_name == "owp-workspace-" + "a" * 32
    assert binding.output_volume_name == "owp-output-" + "a" * 32
    assert binding.ownership_token == hashlib.sha256(
        b"openworkproof/docker-run/v0.1\x00" + b"a" * 64
    ).hexdigest()
```

These fixed prefixes plus the first 32 execution-ID characters are the naming
contract. Every resulting Docker identifier is below 64 ASCII bytes; full
identity still comes only from the ownership label and contract digest.

- [ ] **Step 2: Run RED**

```bash
./.venv/bin/python -m pytest tests/test_sandbox.py -k 'run_tests_docker_binding or reconcile_run_tests' -q
```

Expected: FAIL because the binding and reconciliation types do not exist.

- [ ] **Step 3: Add the pure binding and observation types**

Add:

```python
@dataclass(frozen=True, slots=True)
class RunTestsDockerBinding:
    execution_id: str
    ownership_token: str
    staging_container_name: str
    container_name: str
    workspace_volume_name: str
    output_volume_name: str


@dataclass(frozen=True, slots=True)
class RunTestsDockerObservation:
    staging_container: Mapping[str, Any] | None
    container: Mapping[str, Any] | None
    workspace_volume: Mapping[str, Any] | None
    output_volume: Mapping[str, Any] | None
    started: RunTestsStartedEnvelope | None
    result: RunTestsResultEnvelope | None


RunTestsRecoveryAction = Literal[
    "SAFE_TO_RETRY",
    "CLEAN_PRESTART",
    "WAIT_RUNNING",
    "RESUME_RESULT",
    "CLEAN_COMMITTED",
    "UNRESOLVED",
]
```

Add a pure `reconcile_run_tests_docker_execution` that takes the journal state,
binding, observations, and `receipt_matches: bool`. It must implement the exact
state table from design section 8. `RESUME_RESULT` requires a stopped owned
container, matching immutable image/config/mount observations, matching start
marker, and matching closed result. Wrong ownership or contradictory facts are
always `UNRESOLVED`.

- [ ] **Step 4: Add the full state table tests**

Cover absent, partial pre-start, created-never-started, running, paused,
restarting, dead, exited-with-result, exited-without-result, malformed result,
wrong contract, committed Receipt, unowned replacement, and multiple resource
identity mismatches. Assert reconciliation does not produce Docker commands;
it returns only a typed action.

- [ ] **Step 5: Run GREEN**

```bash
./.venv/bin/python -m pytest tests/test_sandbox.py -k 'run_tests_docker_binding or reconcile_run_tests' -q
```

Expected: all new pure tests pass.

- [ ] **Step 6: Commit Task 4**

```bash
git add src/openworkproof/repo_tools.py tests/test_sandbox.py
git diff --cached --check
git commit -m "feat: derive run tests recovery actions"
```

### Task 5: Freeze the Standalone Runner and Execution Image Context

**Files:**

- Create: `supply-chain/images/execution/run_tests_runner.py`
- Create: `tests/test_run_tests_runner.py`
- Modify: `supply-chain/images/execution/Dockerfile`
- Modify: `supply-chain/images/prepare_context.py`
- Modify: `tests/test_prepare_image_context.py`
- Modify: `tests/test_image_supply_chain.py`
- Modify: `supply-chain/images/README.md`

- [ ] **Step 1: Write runner RED tests**

Load the standalone file with `importlib.util.spec_from_file_location` and add:

```python
def test_runner_writes_exact_started_and_completed_result(tmp_path: Path) -> None:
    workspace, output = _runner_roots(tmp_path)
    contract = _write_contract(workspace, expected_exit=0)
    result = runner.main(
        ("execute",),
        workspace_root=workspace,
        output_root=output,
        process_runner=lambda argv, cwd: runner.ProcessOutcome(
            exit_code=0,
            failure_code=None,
            stdout=b"ok",
            stderr=b"",
        ),
    )
    assert result == 0
    assert json.loads((output / "started.json").read_bytes())[
        "execution_id"
    ] == contract["execution_id"]
    assert json.loads((output / "result.json").read_bytes())[
        "actual_exit_code"
    ] == 0
```

Add exact failure tests for argv, duplicate keys, non-canonical contract,
wrong command digest, candidate file drift, symlink, pre-existing marker,
output limit, timeout, disk limit, and atomic-write failure.

- [ ] **Step 2: Run RED**

```bash
./.venv/bin/python -m pytest tests/test_run_tests_runner.py -q
```

Expected: FAIL because the standalone runner file does not exist.

- [ ] **Step 3: Implement the standalone runner**

The file may import only Python standard-library modules. Define:

```python
FROZEN_VERIFIER_ARGV = (
    "/opt/venv/bin/python",
    "-I",
    "-m",
    "pytest",
    "-q",
)
MAX_CONTRACT_BYTES = 8_192
MAX_RESULT_BYTES = 8_192
MAX_COMBINED_STDIO_BYTES = 1_048_576
WALL_CLOCK_TIMEOUT_SECONDS = 120
```

Implement two fixed modes:

- `stage`: read one normalized bounded snapshot stream from stdin, reject
  symlinks/special files/duplicates/traversal, materialize candidate files plus
  the reserved root `run-contract.json`, re-read every candidate file, and
  print one exact canonical summary only after the expected manifest closes;
- `execute`: re-read the candidate manifest excluding only the reserved control
  file, atomically write `started.json`, run only `FROZEN_VERIFIER_ARGV`, enforce
  the output/time limits incrementally, and atomically write the exact result.

Freeze the staging stream itself instead of relying on tar implementation
details:

```text
ASCII magic: openworkproof-snapshot-stream/0.1\n
4-byte unsigned big-endian header length
header bytes
concatenated payload bytes in header order
```

The header is ASCII JSON produced with
`json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`
and encoded as ASCII. Its closed keys are `schema_version`, `files`, and
`contract`; each file has exactly `path`, `mode`, `size_bytes`, and `sha256`,
and the contract has exactly `size_bytes` and `sha256`. Candidate paths are
strict ASCII-byte ordered and may not equal `run-contract.json`; the contract
payload is last. Enforce 126 files, 512 path bytes, 1 MiB per file, 8 MiB total
candidate content, 8 KiB contract, 64 KiB header, and 8,527,872 bytes for the
entire stream. Reject trailing bytes.

The staging summary is the exact canonical ASCII JSON object containing only
`execution_id`, `execution_contract_digest`, and
`workspace_manifest_digest`, followed by one newline and bounded to 512 bytes.
Recompute the manifest with the same ordered regular-file and derived-directory
records plus `openworkproof/workspace-manifest/v0.1` domain separation already
used by `repo_tools.workspace_manifest_digest`; exclude `run-contract.json`.
The `execute` mode performs the same recomputation before writing
`started.json`.

Do not call a shell, `communicate()`, or import OpenWorkProof. Use selectors and
process-group TERM/KILL behavior consistent with the existing bounded-process
tests. Failure before a closed result exits nonzero without inventing result
bytes.

- [ ] **Step 4: Freeze the image entrypoint and context assembler**

Change the execution Dockerfile to include:

```dockerfile
COPY run_tests_runner.py /opt/openworkproof/run_tests_runner.py
ENTRYPOINT ["/opt/venv/bin/python", "-I", "/opt/openworkproof/run_tests_runner.py"]
CMD ["execute"]
```

Add `execution_runner` to `prepare_context.py` tracked paths, copy exact Git
blob bytes into the execution context, and include the runner in generated
tracked-input drift checks. Update fixture repositories and tests so untracked
worktree drift is ignored but revision-blob drift changes the generated runner.

- [ ] **Step 5: Add static image and README tests**

Require the exact entrypoint/CMD, regular non-symlink runner bytes, no shell
entrypoint, no OpenWorkProof package install, and no Sidecar key or Docker
socket. Document that this remains an execution-test candidate and does not
establish final helper, registry, Acceptor, D8, or Day 0.

- [ ] **Step 6: Run GREEN**

```bash
./.venv/bin/python -m pytest tests/test_run_tests_runner.py tests/test_prepare_image_context.py tests/test_image_supply_chain.py -q
```

Expected: all static and portable runner/image tests pass.

- [ ] **Step 7: Commit Task 5**

```bash
git add supply-chain/images/execution/run_tests_runner.py \
  supply-chain/images/execution/Dockerfile \
  supply-chain/images/prepare_context.py \
  supply-chain/images/README.md \
  tests/test_run_tests_runner.py \
  tests/test_prepare_image_context.py \
  tests/test_image_supply_chain.py
git diff --cached --check
git commit -m "build: freeze verifier execution runner"
```

### Task 6: Implement the Concrete Docker Execution Driver

**Files:**

- Modify: `src/openworkproof/repo_tools.py`
- Modify: `tests/test_sandbox.py`

- [ ] **Step 1: Write a fake-CLI lifecycle RED test**

Add a scripted Docker runner that records exact argv and returns controlled
JSON inspections. Assert one normal call performs:

```python
assert observed_commands == (
    preflight_container_ls,
    preflight_volume_ls,
    create_workspace_volume,
    create_staging_container,
    start_staging_attached_interactive,
    inspect_staging,
    remove_staging,
    create_output_volume,
    create_execution_container,
    inspect_image,
    inspect_execution_container,
    inspect_workspace_volume,
    inspect_output_volume,
    start_execution_detached,
    wait_execution,
    inspect_execution_after_wait,
    copy_output_envelopes,
)
```

The exact tuples must come from the plan object, not be assembled in the test
with loose substring matching.

- [ ] **Step 2: Run RED**

```bash
./.venv/bin/python -m pytest tests/test_sandbox.py -k 'docker_run_tests_driver' -q
```

Expected: FAIL because the driver does not exist.

- [ ] **Step 3: Add one concrete driver with a narrow test seam**

Define:

```python
@dataclass(frozen=True, slots=True)
class RunTestsExecutionOutcome:
    action: Literal[
        "SAFE_TO_RETRY",
        "WAIT_RUNNING",
        "CLOSED_RESULT",
        "UNRESOLVED",
    ]
    result: RunTestsResultEnvelope | None


@dataclass(frozen=True, slots=True)
class RunTestsPreparationOutcome:
    action: Literal["READY_TO_START", "UNRESOLVED"]


DockerCommandRunner = Callable[
    [tuple[str, ...], bytes | None, float],
    subprocess.CompletedProcess[bytes],
]


class RunTestsExecutionDriver(Protocol):
    def prepare(
        self,
        contract: RunTestsExecutionContract,
        snapshot: CandidateExecutionSnapshot,
    ) -> RunTestsPreparationOutcome:
        raise NotImplementedError

    def start_and_wait(
        self,
        contract: RunTestsExecutionContract,
    ) -> RunTestsExecutionOutcome:
        raise NotImplementedError

    def reconcile(
        self,
        contract: RunTestsExecutionContract,
        *,
        receipt_matches: bool,
    ) -> RunTestsExecutionOutcome:
        raise NotImplementedError

    def cleanup(self, contract: RunTestsExecutionContract) -> None:
        raise NotImplementedError


class DockerRunTestsExecutor:
    def __init__(
        self,
        *,
        docker_binary: Path,
        candidate_runtime_root: Path,
        image_reference: str,
        run: DockerCommandRunner | None = None,
    ) -> None:
        self._docker_binary = docker_binary
        self._candidate_runtime_root = candidate_runtime_root
        self._image_reference = image_reference
        self._run = run if run is not None else _run_docker_command

    def prepare(
        self,
        contract: RunTestsExecutionContract,
        snapshot: CandidateExecutionSnapshot,
    ) -> RunTestsPreparationOutcome:
        return _prepare_run_tests_docker(self, contract, snapshot)

    def start_and_wait(
        self,
        contract: RunTestsExecutionContract,
    ) -> RunTestsExecutionOutcome:
        return _start_and_wait_run_tests_docker(self, contract)

    def reconcile(
        self,
        contract: RunTestsExecutionContract,
        *,
        receipt_matches: bool,
    ) -> RunTestsExecutionOutcome:
        return _reconcile_run_tests_docker(self, contract, receipt_matches)

    def cleanup(self, contract: RunTestsExecutionContract) -> None:
        _cleanup_run_tests_docker(self, contract)
```

`_run_docker_command` is the sole production adapter around `subprocess.run`:
it accepts the exact argv tuple, optional stdin bytes, and timeout, always uses
`shell=False`, captures bounded bytes, and sets `check=False`. The injected
`DockerCommandRunner` is the only process seam; callers cannot replace policy,
resource derivation, parsers, or inspection validators. Validate the three
constructor inputs once and keep all lifecycle helpers private.

Use the existing Docker plan and cleanup functions. Extend them only where the
staging resource and detached start require explicit typed commands. Transfer
the canonical snapshot stream to staging stdin with an exact byte limit. Read
envelopes from the stopped execution container using `docker cp ... -` and a
strict single-root tar parser that rejects extra members, links, devices,
duplicates, traversal, and oversized content.

`prepare` performs absence preflight, workspace staging, output-volume and
execution-container creation, immutable inspection, and never-started proof;
it must not issue Docker start. `start_and_wait` first re-inspects the exact
owned container in never-started `created` state, then issues the sole detached
start and only observes/waits/reads afterwards. `reconcile` derives the old
candidate snapshot request from the executor's configured canonical runtime
root plus `candidate_workspace_id`, `source_artifact_sha256`, source commit,
and manifest digest in the stored contract; it re-runs the Task-2 checkpoint
before trusting any resource. Missing root, snapshot mismatch, or identity
drift returns `UNRESOLVED` and retains the journal/resources.

- [ ] **Step 4: Add cleanup and uncertainty tests**

Cover every partial create position, Docker CLI timeout, daemon error, create
success with lost ACK, wrong owner label, staging mismatch, execution running,
result missing, result mismatch, committed Receipt cleanup, retained unowned
resource, and fd/process cleanup. Require reverse-order removal and no broad
name/glob deletion.

- [ ] **Step 5: Add required-live focused tests**

Under `OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1`, assemble a revision-bound temporary
execution context from the current clean Task-5 commit, build an ephemeral
`openworkproof/execution-test-dev:<revision>` image with `--network none` and
`--pull=false`, and pass its immutable inspected image ID to the test. Prove
actual resource creation, detached start, exact containment, closed exit,
envelope extraction, and zero residue. Remove only that validated temporary
context and tag after the test. Mark the test with `pytest.mark.docker` and
retain the existing precise portable skip when the required-live flag is
absent.

- [ ] **Step 6: Run GREEN**

```bash
OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1 \
./.venv/bin/python -m pytest tests/test_sandbox.py -k 'docker_run_tests_driver' -q
```

Expected: all driver tests pass with zero required-live skip.

- [ ] **Step 7: Commit Task 6**

```bash
git add src/openworkproof/repo_tools.py tests/test_sandbox.py
git diff --cached --check
git commit -m "feat: execute verifier tests in Docker"
```

### Task 7: Integrate Recovery, Receipt Semantics, and Crash Windows

**Files:**

- Modify: `src/openworkproof/mcp_server.py`
- Modify: `tests/test_mcp_server.py`
- Modify: `tests/test_receipt_chain.py`

- [ ] **Step 1: Replace the callable-handler success test with a typed executor RED test**

Create a focused fake implementing the four protocol executor methods and
recording calls. Change the successful test to pass `execution_driver=` and
`candidate_snapshot_request=`. Require one execution, one TestResultEvidence,
one Receipt, one quota event, one state/version transition, and empty journal.

Run:

```bash
./.venv/bin/python -m pytest tests/test_mcp_server.py::test_execute_run_tests_completes_authorize_driver_publish_loop -q
```

Expected: FAIL because `execute_run_tests` still accepts `handler=` and has no
driver recovery path.

- [ ] **Step 2: Integrate stored contract construction and normal outcome handling**

Change the public internal signature to:

```python
def execute_run_tests(
    ledger_path: Path,
    *,
    evidence_root: Path,
    context: AuthorizationContext,
    request: AgentRequest,
    request_arguments: RunTestsArguments,
    execution_facts: ProspectiveExecutionFacts,
    candidate_snapshot_request: repo_tools.CandidateExecutionSnapshotRequest,
    sidecar_private_key: Ed25519PrivateKey,
    execution_driver: repo_tools.RunTestsExecutionDriver,
    clock: Callable[[], datetime],
) -> ToolCallReceipt:
```

Before reservation, require Verifier mode, frozen command digest, exact
candidate workspace/source binding, candidate commit/manifest binding, and
immutable image-reference agreement. Preflight the maximum canonical Receipt
for all three outcomes: expected exit, unexpected exit, and each infrastructure
failure code. Keep the existing target lock held through recovery,
authorization, Docker observation, publication, and cleanup. Create the
contract, reserve exact request/contract bytes, prepare the candidate snapshot, call
`execution_driver.prepare`, and require `READY_TO_START`. Only then atomically
mark `STARTED_UNCONFIRMED`; immediately call `start_and_wait` exactly once.
An owned, provably pre-start preparation failure cleans in reverse order and
deletes the reservation with no Receipt/quota event; uncertain ownership
retains the reservation and returns `RECOVERY_REQUIRED`. No code path may call
`start_and_wait` while the journal is still `RESERVED`.

Extend `_build_run_tests_receipt` with
`execution_error_code: Literal["OUTPUT_LIMIT", "TIMEOUT", "DISK_LIMIT"] | None`.
A completed expected exit publishes one TestResultEvidence, commits
`allow/succeeded`, charges once, and transitions to `locally_verified`. A
completed unexpected exit publishes one TestResultEvidence with the actual
exit, commits `allow/succeeded`, charges once, and transitions to
`needs_rework`. A closed infrastructure failure commits `allow/failed`, charges
once, publishes no TestResultEvidence, and keeps state unchanged.
`WAIT_RUNNING` and `UNRESOLVED` raise
`HandlerCoordinationError("RECOVERY_REQUIRED")` without a Receipt.

- [ ] **Step 3: Add old-execution recovery before new authorization**

When a stored run-tests row exists, load its signed request and contract, prove
the supplied current context has the same WorkOrder and exact pre-execution
ledger prefix, prove the Sidecar key matches the stored controller, and call
`execution_driver.reconcile` with `receipt_matches` derived from the ledger.

- `SAFE_TO_RETRY`: clean journal, then process the caller's request normally;
- `WAIT_RUNNING`: return `RECOVERY_REQUIRED`;
- closed result: construct and publish the old Receipt from stored bytes, clean
  old resources/journal, then return that old Receipt without executing the new
  request;
- committed match: cleanup only and then process the caller's request;
- unresolved: return `RECOVERY_REQUIRED`.

Do not authorize the old request a second time and do not use the new request's
nonce, model, arguments, or correlation fields.

- [ ] **Step 4: Add crash-injection tests in exact order**

Cover interruption after reservation, workspace volume, staging create,
staging removal, output volume, execution container, journal started mark,
Docker accepted start, result rename, Receipt commit, journal cleanup, and
resource cleanup. Each test opens a new SQLite connection and a fresh executor
instance to simulate controller restart.

For every case assert exact counts for:

```python
assert docker_start_count <= 1
assert receipt_count <= 1
assert quota_event_count <= 1
assert publication_count <= expected_publications
assert state_version_delta <= 1
```

Tests for a closed result must require equality to one. Unresolved tests must
require zero Receipt/quota/state writes and retained exact journal identity.

- [ ] **Step 5: Add rollback and denial regressions**

Run the existing rollback coordinator tests unchanged except fixture updates
needed for the new schema. Prove a rollback row stores null recovery fields,
does not invoke the Docker driver, and retains its existing
`STARTED_UNCONFIRMED` behavior. Prove policy denial, stale context, evidence
capacity failure, and wrong command digest never create Docker resources.

- [ ] **Step 6: Run focused and full portable GREEN**

```bash
./.venv/bin/python -m pytest tests/test_mcp_server.py tests/test_receipt_chain.py tests/test_policy.py -q
./.venv/bin/python -m pytest -q
```

Expected: all portable tests pass; only the established environment-gated
Docker tests may skip without the required-live flag.

- [ ] **Step 7: Commit Task 7**

```bash
git add src/openworkproof/mcp_server.py \
  tests/test_mcp_server.py \
  tests/test_receipt_chain.py
git diff --cached --check
git commit -m "feat: recover verifier test executions"
```

### Task 8: Rebuild Candidate Evidence and Run the Final Gate

**Files:**

- Modify: `tests/test_image_supply_chain.py`
- Modify: `tests/test_candidate_supplychain_integration.py`
- Modify: `tests/test_prepare_image_context.py`
- Modify: `supply-chain/images/README.md`
- Create: `supply-chain/images/candidates/$OWP_SOURCE_REVISION.json`

- [ ] **Step 1: Add versioned inventory and selector RED tests**

Support historical `openworkproof-image-candidate-inventory/0.1` records without
editing them. Require the new current record to use
`openworkproof-image-candidate-inventory/0.2` and add exactly
`execution.runner_sha256`. Add the runner path to current-definition selection
and require one unique current match across Dockerfile, lock, runner, helper
definition, helper allowlist, and helper source blobs.

Name the focused tests
`test_inventory_v01_remains_valid_without_runner_digest`,
`test_inventory_v02_requires_execution_runner_digest`, and
`test_current_candidate_inventory_binds_execution_runner`. Build the first two
from copied temporary inventory fixtures; the third must exercise the real
revision-named inventory set.

Run:

```bash
./.venv/bin/python -m pytest tests/test_image_supply_chain.py tests/test_candidate_supplychain_integration.py -q
```

Expected: the historical fixture remains GREEN and both v0.2/current-definition
tests are RED because the strict loader and current inventory do not yet bind
the runner.

- [ ] **Step 2: Implement version-aware validation, then commit the definition**

Change the strict loader so v0.1 accepts its historical exact execution keys
and v0.2 requires the same keys plus exactly `runner_sha256`. Reject every
unknown version and every cross-version field mixture. Add
`supply-chain/images/execution/run_tests_runner.py` to the selector definition
and README definition list. Do not edit historical inventory bytes.

Run the two fixture tests and selector mutation coverage that does not require
the not-yet-created current record:

```bash
./.venv/bin/python -m pytest \
  tests/test_image_supply_chain.py::test_inventory_v01_remains_valid_without_runner_digest \
  tests/test_image_supply_chain.py::test_inventory_v02_requires_execution_runner_digest \
  tests/test_candidate_supplychain_integration.py::test_candidate_inventory_selector_covers_every_tracked_definition \
  tests/test_candidate_supplychain_integration.py::test_candidate_inventory_selector_rejects_each_tracked_definition_mutation -q
git add tests/test_image_supply_chain.py \
  tests/test_candidate_supplychain_integration.py \
  tests/test_prepare_image_context.py \
  supply-chain/images/README.md
git diff --cached --check
git commit -m "test: version execution runner inventory"
```

Expected: the named fixture/mutation tests pass. The real current-inventory
selection test remains intentionally RED until the evidence commit is created.
This commit contains every final source, image-definition, test, and README
change; no such file may change after the next step.

- [ ] **Step 3: Freeze the final source revision**

After all code and test changes are committed and the worktree is clean:

```bash
set -e
OWP_REPO=/Users/molin/Project/openWorkProof
OWP_ARTIFACT_ROOT=/Users/molin/Project/openWorkProof-day0
OWP_SOURCE_REVISION=$(git rev-parse HEAD)
test ${#OWP_SOURCE_REVISION} -eq 40
test ! -e "$OWP_ARTIFACT_ROOT/build-contexts/$OWP_SOURCE_REVISION"
test ! -e "$OWP_ARTIFACT_ROOT/oci/$OWP_SOURCE_REVISION"
```

Do not amend this source revision after building candidate artifacts.

- [ ] **Step 4: Assemble and verify revision-specific contexts**

```bash
./.venv/bin/python supply-chain/images/prepare_context.py \
  --repo "$OWP_REPO" \
  --source-revision "$OWP_SOURCE_REVISION" \
  --wheelhouse "$OWP_ARTIFACT_ROOT/wheelhouse/linux-arm64-cp312-full" \
  --deb-closure "$OWP_ARTIFACT_ROOT/debs/linux-arm64-trixie-git" \
  --output-root "$OWP_ARTIFACT_ROOT/build-contexts/$OWP_SOURCE_REVISION"
```

Verify all generated `SHA256SUMS` and require the execution context to contain
exactly Dockerfile, requirements lock, runner, selected wheels, and their sums.

- [ ] **Step 5: Build, smoke, and export both images offline**

```bash
docker buildx build --load --platform linux/arm64 --network none --pull=false \
  --provenance=false \
  --build-arg "OWP_SOURCE_REVISION=$OWP_SOURCE_REVISION" \
  -t "openworkproof/execution-test:$OWP_SOURCE_REVISION" \
  "$OWP_ARTIFACT_ROOT/build-contexts/$OWP_SOURCE_REVISION/execution"
docker buildx build --load --platform linux/arm64 --network none --pull=false \
  --provenance=false \
  --build-arg "OWP_SOURCE_REVISION=$OWP_SOURCE_REVISION" \
  -t "openworkproof/trusted-helper-candidate:$OWP_SOURCE_REVISION" \
  "$OWP_ARTIFACT_ROOT/build-contexts/$OWP_SOURCE_REVISION/trusted-helper"
```

Run exact runner invalid-input smoke, a closed fixed verifier smoke, and helper
argv/empty-input failure smoke. Require empty stderr where specified by each
contract. Export Docker archives and true OCI archives under
`$OWP_ARTIFACT_ROOT/oci/$OWP_SOURCE_REVISION`, then create and verify
`SHA256SUMS`.

- [ ] **Step 6: Record the measured v0.2 inventory**

Create the revision-named JSON from actual Git blobs, context hashes,
`docker image inspect`, OCI descriptors, archive hashes, sizes, and runner
digest. Keep these claims false:

```json
{
  "acceptor_access": false,
  "clean_cache_reacquisition": false,
  "day0_pass": false,
  "final_trusted_helper": false,
  "registry_pushed": false
}
```

Keep license approval `PENDING`, SPDX `NOASSERTION`, and Acceptor path null.
Copy the inventory to the external archive directory and create its digest
sidecar without overwriting prior revisions.

- [ ] **Step 7: Run required-live focused and full gates**

```bash
OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT=/Users/molin/Project/openWorkProof-day0 \
OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1 \
./.venv/bin/python -m pytest \
  tests/test_run_tests_runner.py \
  tests/test_sandbox.py \
  tests/test_mcp_server.py \
  tests/test_trusted_helper.py \
  tests/test_image_supply_chain.py \
  tests/test_prepare_image_context.py \
  tests/test_candidate_supplychain_integration.py -q

OWP_EXECUTION_IMAGE_ID=$(docker image inspect \
  "openworkproof/execution-test:$OWP_SOURCE_REVISION" \
  --format '{{.Id}}')
OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT=/Users/molin/Project/openWorkProof-day0 \
OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1 \
OPENWORKPROOF_DOCKER_TEST_IMAGE="docker.io/openworkproof/execution-test@$OWP_EXECUTION_IMAGE_ID" \
./.venv/bin/python -m pytest -q
```

Expected: both commands exit 0 with zero required-live skip.

- [ ] **Step 8: Run non-test verification**

```bash
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests supply-chain/images
git diff --check
```

Recompute every wheel, Debian package, runner, helper source, Docker archive,
OCI archive, inventory, and sidecar hash. Require zero owned OpenWorkProof
container and volume residue.

- [ ] **Step 9: Commit the evidence stage**

Stage only the new inventory; every source, image-definition, test, and README
change was frozen in Step 2:

```bash
git add "supply-chain/images/candidates/$OWP_SOURCE_REVISION.json"
git diff --cached --check
git commit -m "build: bind verifier execution recovery candidate"
```

The evidence commit must have the exact source revision as its sole parent and
must not change product source or image definitions.

## Completion Checkpoint

Record:

- branch, source revision, and evidence commit;
- focused and full required-live counts and elapsed times;
- exact Docker image IDs and OCI manifest digests;
- execution runner, context, archive, inventory, and sidecar hashes;
- crash-window start/Receipt/quota/state/publication counts;
- `pip check`, compileall, diff, cleanup, and worktree status;
- independent specification and code-quality review results.

Keep local commit, merge, push, image-registry publication, Acceptor access,
clean-cache reacquisition, final helper, D8, Day 0, contest delivery, and
commercial validation as separate states. After all gates pass, use
`finishing-a-development-branch` and present the standard four branch options.
