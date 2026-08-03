# OpenWorkProof Trusted Helper `repo_read` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the helper candidate's generic Python argument surface with a fixed, failure-closed `repo_read` dispatcher that verifies a read-only candidate checkpoint before returning at most 64 KiB of one canonical file.

**Architecture:** `repo_tools.py` owns the package-private checkpoint and descriptor-anchored read boundary; `trusted_helper.py` owns only canonical framing, single-operation dispatch, closed responses, and exit codes. A second evidence stage rebuilds revision-bound contexts, images, archives, and inventory while retaining all final-helper, Acceptor, D8, and Day 0 boundaries.

**Tech Stack:** Python 3.12, dataclasses, Pydantic 2.13.4, RFC 8785, Git 2.47.3, Docker 29.5.2, pytest 9.1.1, OCI image-layout archives.

---

## Execution Boundary

- Execute from `/Users/molin/Project/openWorkProof` on `codex/trusted-helper-dispatch`.
- Design authority: `docs/superpowers/specs/2026-08-03-openworkproof-trusted-helper-repo-read-design.md` at `536498794d07ee51c044c4260cb07d1afe43da4d`.
- Do not modify MCP handlers, ledger, policy, Receipt models, signing, CLI, AgentTeams, LICENSE state, or remote Git state.
- Add one focused failing test, observe the expected failure, implement only that behavior, and rerun it.
- Before every commit, stage only the named files, verify the staged list, and run `git diff --cached --check`.
- Do not merge or push as part of this plan.

## File Map

- Modify `src/openworkproof/repo_tools.py`: read-only candidate verification and file read.
- Create `src/openworkproof/trusted_helper.py`: stdin/stdout dispatcher.
- Create `tests/test_trusted_helper.py`: focused core and framing tests.
- Modify `supply-chain/images/trusted-helper/Dockerfile` and `SOURCE_ALLOWLIST`.
- Modify `supply-chain/images/README.md`.
- Modify `tests/test_image_supply_chain.py`, `tests/test_prepare_image_context.py`, and `tests/test_candidate_supplychain_integration.py`.
- Create one new revision-named JSON file under `supply-chain/images/candidates/` after the exact code-definition commit exists.

### Task 1: Add the Read-Only Candidate File Boundary

**Files:**

- Modify: `src/openworkproof/repo_tools.py`
- Create: `tests/test_trusted_helper.py`

- [ ] **Step 1: Write the first successful-read test**

Create a candidate fixture with the existing `ParsedSourceArchive` and `initialize_candidate_workspace`, then add:

```python
def test_read_candidate_file_returns_exact_closed_result(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    result = repo_tools.read_candidate_file(
        repo_tools.CandidateReadRequest(
            runtime_root=candidate.runtime_root,
            workspace_id=candidate.workspace_id,
            source_artifact_sha256=candidate.source_artifact_sha256,
            expected_head_commit=candidate.head_commit,
            expected_workspace_manifest_digest=candidate.workspace_manifest_digest,
            path="README.md",
        )
    )
    assert result.content == b"base\n"
    assert result.output == RepoReadOutput(
        path="README.md",
        content_sha256=hashlib.sha256(b"base\n").hexdigest(),
        size_bytes=5,
        workspace_manifest_digest=candidate.workspace_manifest_digest,
    )
```

- [ ] **Step 2: Run RED**

```bash
./.venv/bin/python -m pytest tests/test_trusted_helper.py::test_read_candidate_file_returns_exact_closed_result -q
```

Expected: failure because `CandidateReadRequest` or `read_candidate_file` does not exist.

- [ ] **Step 3: Add the minimal typed API**

Import `RepoReadOutput` and add:

```python
CandidateReadFailureCode = Literal[
    "RECOVERY_REQUIRED", "PATH_DENIED", "FILE_CHANGED"
]

class CandidateReadError(RuntimeError):
    def __init__(self, code: CandidateReadFailureCode) -> None:
        super().__init__(code)
        self.code = code

@dataclass(frozen=True, slots=True)
class CandidateReadRequest:
    runtime_root: Path
    workspace_id: str
    source_artifact_sha256: str
    expected_head_commit: str
    expected_workspace_manifest_digest: str
    path: str

@dataclass(frozen=True, slots=True)
class CandidateReadResult:
    content: bytes
    output: RepoReadOutput
```

Implement `read_candidate_file` with this exact order:

```python
def read_candidate_file(request: CandidateReadRequest) -> CandidateReadResult:
    workspace = _candidate_from_read_request(request)
    manifest = _verify_candidate_checkpoint_read_only(workspace)
    content = _read_verified_candidate_path(workspace.worktree, request.path, manifest)
    return CandidateReadResult(
        content=content,
        output=RepoReadOutput(
            path=request.path,
            content_sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
            workspace_manifest_digest=request.expected_workspace_manifest_digest,
        ),
    )
```

`_candidate_from_read_request` validates exact types, absolute canonical runtime root, 64/40-hex bindings, and the existing canonical relative path. Candidate paths are derived only as `runtime_root/workspace_id/{control.json,git,worktree}`.

- [ ] **Step 4: Implement read-only Git and manifest checks**

Add `_run_git_read_only` with fixed `/usr/bin/git`, fixed config arguments, a 30-second timeout, and this exact environment:

```python
{
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
}
```

`_verify_candidate_checkpoint_read_only` runs only helper-authored arguments and checks:

```text
_validate_candidate_layout
rev-parse HEAD equals expected HEAD
cat-file -e expected-HEAD^{commit}
diff-index --cached --quiet expected-HEAD -- returns 0
scan_workspace_manifest from O_DIRECTORY|O_NOFOLLOW worktree fd
recomputed manifest digest equals expected digest
```

Do not call `git status` or `git write-tree`. Map any layout, control, Git, index, object, scan, or digest mismatch to `RECOVERY_REQUIRED`.

- [ ] **Step 5: Implement descriptor-anchored reading**

Walk every ancestor with `dir_fd`, `O_DIRECTORY`, and `O_NOFOLLOW`; open the leaf with `O_RDONLY|O_NOFOLLOW`. Decode the exact manifest path, require `type=regular`, `st_nlink=1`, and `st_size<=65_536`, then read exactly that size. Compare device, inode, mode, link count, uid, gid, size, mtime, ctime, and content digest across scan/open/read/final stat. Map unsafe/missing/wrong-type/oversize paths to `PATH_DENIED` and identity drift to `FILE_CHANGED`. Never return a prefix.

- [ ] **Step 6: Add one RED/GREEN vector at a time**

Cover zero and 65,536 bytes as success; 65,537 bytes, directory, symlink, ancestor symlink, hardlink, FIFO, socket, and missing path as `PATH_DENIED`; wrong source digest, HEAD, manifest, control, index, or worktree bytes as `RECOVERY_REQUIRED`; and monkeypatched post-read stat drift as `FILE_CHANGED`.

```bash
./.venv/bin/python -m pytest tests/test_trusted_helper.py -q
```

Expected: all Task 1 tests pass without skip.

- [ ] **Step 7: Commit Task 1**

```bash
set -e
git diff --cached --quiet
git add src/openworkproof/repo_tools.py tests/test_trusted_helper.py
test "$(git diff --cached --name-only | LC_ALL=C sort)" = "$(printf '%s\n' src/openworkproof/repo_tools.py tests/test_trusted_helper.py | LC_ALL=C sort)"
git diff --cached --check
git commit -m "feat: verify bounded candidate repo reads"
```

### Task 2: Add the Fixed Canonical Dispatcher

**Files:**

- Create: `src/openworkproof/trusted_helper.py`
- Modify: `tests/test_trusted_helper.py`

- [ ] **Step 1: Write canonical success and argv RED tests**

Build request bytes with `rfc8785.dumps`, invoke a testable `main(argv, stdin, stdout, runtime_root)`, and assert exact stdout and exit 0. Add one argv item and require exit 64 with exact canonical `REQUEST_INVALID`.

- [ ] **Step 2: Run RED**

```bash
./.venv/bin/python -m pytest tests/test_trusted_helper.py -k 'dispatcher' -q
```

Expected: import failure because `openworkproof.trusted_helper` does not exist.

- [ ] **Step 3: Implement exact framing and responses**

Create `trusted_helper.py` with:

```python
REQUEST_SCHEMA = "openworkproof-trusted-helper-request/0.1"
RESPONSE_SCHEMA = "openworkproof-trusted-helper-response/0.1"
MAX_REQUEST_BYTES = 8_192
RUNTIME_ROOT = Path("/runtime")
EXIT_BY_CODE = {
    "REQUEST_INVALID": 64,
    "RECOVERY_REQUIRED": 65,
    "PATH_DENIED": 66,
    "FILE_CHANGED": 67,
    "INTERNAL_ERROR": 70,
}
```

Read at most 8193 bytes. Use `json.loads` with duplicate-key rejection and require `rfc8785.dumps(value)==raw`. Require the exact seven-key object and `operation="repo_read"`. Construct `CandidateReadRequest`; never accept a runtime path or command.

Success is exactly:

```python
{
    "schema_version": RESPONSE_SCHEMA,
    "status": "ok",
    "result": result.output.model_dump(mode="json"),
    "content_b64url": base64.urlsafe_b64encode(result.content).decode("ascii").rstrip("="),
}
```

Failure is exactly:

```python
{
    "schema_version": RESPONSE_SCHEMA,
    "status": "error",
    "code": code,
}
```

`main` rejects argv before reading stdin, writes one `rfc8785.dumps` response without newline, never writes stderr, maps only `CandidateReadError.code`, and converts every unexpected exception to `INTERNAL_ERROR` without interpolation.

- [ ] **Step 4: Add the complete failure matrix**

Cover empty, 8193 bytes, two frames, BOM, trailing newline/space, duplicate keys, non-canonical order, non-object top level, missing/extra key, wrong type, uppercase/short digest, unknown operation, absolute/parent/backslash/NUL path, every `CandidateReadError`, and one unexpected exception. For each failure assert exact canonical response, exact exit, and absence of path, request, file bytes, exception class, and message.

- [ ] **Step 5: Run GREEN and the existing receipt-output contract**

```bash
./.venv/bin/python -m pytest tests/test_trusted_helper.py -q
./.venv/bin/python -m pytest tests/test_contract.py::test_repo_read_success_output_is_closed_and_rehashable -q
```

Expected: all pass without skip.

- [ ] **Step 6: Commit Task 2**

```bash
set -e
git diff --cached --quiet
git add src/openworkproof/trusted_helper.py tests/test_trusted_helper.py
test "$(git diff --cached --name-only | LC_ALL=C sort)" = "$(printf '%s\n' src/openworkproof/trusted_helper.py tests/test_trusted_helper.py | LC_ALL=C sort)"
git diff --cached --check
git commit -m "feat: restrict trusted helper dispatch"
```

### Task 3: Freeze the Candidate Image Definition

**Files:**

- Modify: `supply-chain/images/trusted-helper/Dockerfile`
- Modify: `supply-chain/images/trusted-helper/SOURCE_ALLOWLIST`
- Modify: `supply-chain/images/README.md`
- Modify: `tests/test_image_supply_chain.py`
- Modify: `tests/test_prepare_image_context.py`

- [ ] **Step 1: Write static RED tests**

Require the Dockerfile to contain:

```dockerfile
ENTRYPOINT ["/opt/venv/bin/python", "-I", "-m", "openworkproof.trusted_helper"]
CMD []
```

Require the allowlist to contain exactly `__init__.py`, `models.py`, `repo_tools.py`, and `trusted_helper.py`, and the generated context's `SHA256SUMS` to bind all four exact Git blobs.

- [ ] **Step 2: Run RED**

```bash
./.venv/bin/python -m pytest tests/test_image_supply_chain.py tests/test_prepare_image_context.py -q
```

Expected: failures on the old entrypoint, command, and three-file allowlist.

- [ ] **Step 3: Change only the image boundary**

Replace the old entrypoint/CMD with the fixed module entrypoint and `CMD []`; append only `src/openworkproof/trusted_helper.py` to `SOURCE_ALLOWLIST`; update the supply-chain README with `/runtime:ro`, argv rejection, the single `repo_read` operation, and the still-missing initialize/apply/rollback/rebuild/destroy operations.

- [ ] **Step 4: Run static and focused GREEN**

```bash
./.venv/bin/python -m pytest tests/test_trusted_helper.py tests/test_image_supply_chain.py tests/test_prepare_image_context.py -q
```

Expected: all pass. Historical inventories remain validated against their own Git revisions and are not rewritten.

- [ ] **Step 5: Commit the code-definition revision**

```bash
set -e
git diff --cached --quiet
git add supply-chain/images/trusted-helper/Dockerfile supply-chain/images/trusted-helper/SOURCE_ALLOWLIST supply-chain/images/README.md tests/test_image_supply_chain.py tests/test_prepare_image_context.py
OWP_EXPECTED_STAGED="supply-chain/images/trusted-helper/Dockerfile supply-chain/images/trusted-helper/SOURCE_ALLOWLIST supply-chain/images/README.md tests/test_image_supply_chain.py tests/test_prepare_image_context.py"
test "$(git diff --cached --name-only | LC_ALL=C sort)" = "$(printf '%s\n' $OWP_EXPECTED_STAGED | LC_ALL=C sort)"
git diff --cached --check
git commit -m "build: freeze trusted helper repo read entrypoint"
```

Save `OWP_SOURCE_REVISION=$(git rev-parse HEAD)`; only this exact commit is valid for Task 4.

### Task 4: Rebuild and Bind Candidate Artifacts

**Files:**

- Create: one measured `supply-chain/images/candidates/$OWP_SOURCE_REVISION.json`
- Modify: `tests/test_image_supply_chain.py`
- Modify: `tests/test_candidate_supplychain_integration.py`
- Modify: `supply-chain/images/README.md`

- [ ] **Step 1: Generate revision-specific contexts**

```bash
set -e
OWP_REPO=/Users/molin/Project/openWorkProof
OWP_ARTIFACT_ROOT=/Users/molin/Project/openWorkProof-day0
OWP_SOURCE_REVISION=$(git rev-parse HEAD)
test ${#OWP_SOURCE_REVISION} -eq 40
OWP_CONTEXT_ROOT="$OWP_ARTIFACT_ROOT/build-contexts/$OWP_SOURCE_REVISION"
test ! -e "$OWP_CONTEXT_ROOT"
./.venv/bin/python supply-chain/images/prepare_context.py --repo "$OWP_REPO" --source-revision "$OWP_SOURCE_REVISION" --wheelhouse "$OWP_ARTIFACT_ROOT/wheelhouse/linux-arm64-cp312-full" --deb-closure "$OWP_ARTIFACT_ROOT/debs/linux-arm64-trixie-git" --output-root "$OWP_CONTEXT_ROOT"
```

Verify every generated `SHA256SUMS`; helper source must be exactly the four modules plus `SHA256SUMS`.

- [ ] **Step 2: Build both images offline**

```bash
docker buildx build --load --platform linux/arm64 --network none --pull=false --build-arg "OWP_SOURCE_REVISION=$OWP_SOURCE_REVISION" -t "openworkproof/execution-test:$OWP_SOURCE_REVISION" "$OWP_CONTEXT_ROOT/execution"
docker buildx build --load --platform linux/arm64 --network none --pull=false --build-arg "OWP_SOURCE_REVISION=$OWP_SOURCE_REVISION" -t "openworkproof/trusted-helper-candidate:$OWP_SOURCE_REVISION" "$OWP_CONTEXT_ROOT/trusted-helper"
```

Require linux/arm64, `65532:65532`, exact revision/role labels, no license label, the four-token helper entrypoint, and empty command.

- [ ] **Step 3: Run live failure-closed smoke and export archives**

With empty stdin and then one argv item, require helper exit 64, empty stderr, and exact canonical `REQUEST_INVALID`. Do not override the entrypoint. Export revision-specific Docker archives with `docker save` and true OCI archives with `docker buildx --output type=oci` under `/Users/molin/Project/openWorkProof-day0/oci/$OWP_SOURCE_REVISION`; generate and verify `SHA256SUMS`, `oci-layout`, `index.json`, descriptors, config, layers, sizes, and digests.

- [ ] **Step 4: Record measured inventory and RED/GREEN selectors**

Create `supply-chain/images/candidates/$OWP_SOURCE_REVISION.json` from actual Git blobs, context manifests, `docker image inspect`, OCI descriptors, and archive bytes. Use revision-specific relative paths under `build-contexts/$OWP_SOURCE_REVISION/` and `oci/$OWP_SOURCE_REVISION/`. Keep registry push, Acceptor access, clean-cache reacquisition, final helper, and Day 0 false, with null Acceptor path.

Update tests to select the unique inventory whose tracked current Dockerfile and allowlist hashes match the working definitions. Fail on zero or multiple matches. Validate every historical inventory against its own Git revision.

- [ ] **Step 5: Run focused and full verification**

```bash
OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT=/Users/molin/Project/openWorkProof-day0 OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1 ./.venv/bin/python -m pytest tests/test_trusted_helper.py tests/test_image_supply_chain.py tests/test_prepare_image_context.py tests/test_candidate_supplychain_integration.py -q
OWP_EXECUTION_IMAGE_ID=$(docker image inspect "openworkproof/execution-test:$OWP_SOURCE_REVISION" --format '{{.Id}}')
OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT=/Users/molin/Project/openWorkProof-day0 OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1 OPENWORKPROOF_DOCKER_TEST_IMAGE="docker.io/openworkproof/execution-test@$OWP_EXECUTION_IMAGE_ID" ./.venv/bin/python -m pytest -q
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests supply-chain/images
git diff --check
```

Expected: focused and full tests pass with zero required-live skip; pip reports no broken requirements; compileall and diff check exit 0.

- [ ] **Step 6: Verify cleanup and commit inventory stage**

Require zero owned container/volume residue and recompute every context, config, archive, and sidecar hash from actual bytes.

```bash
set -e
git diff --cached --quiet
git add "supply-chain/images/candidates/$OWP_SOURCE_REVISION.json" supply-chain/images/README.md tests/test_image_supply_chain.py tests/test_candidate_supplychain_integration.py
OWP_EXPECTED_STAGED="supply-chain/images/candidates/$OWP_SOURCE_REVISION.json supply-chain/images/README.md tests/test_image_supply_chain.py tests/test_candidate_supplychain_integration.py"
test "$(git diff --cached --name-only | LC_ALL=C sort)" = "$(printf '%s\n' $OWP_EXPECTED_STAGED | LC_ALL=C sort)"
git diff --cached --check
git commit -m "build: bind repo read helper candidate"
```

## Completion Checkpoint

Record branch/HEAD, commits, focused/full test counts and elapsed times, pip/compile/diff/archive/OCI/cleanup results, image IDs, OCI manifest digests, and revision-specific external paths. Keep merge, push, Acceptor access, clean-cache reacquisition, final helper, D8, Day 0, contest delivery, and commercial validation separate and unproven. Then use `finishing-a-development-branch` and present the standard four branch options.
