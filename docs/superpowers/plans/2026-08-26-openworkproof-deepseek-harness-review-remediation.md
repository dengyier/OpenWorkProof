# OpenWorkProof DeepSeek Harness Review Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the rejected local candidate into one packed DeepSeek Harness
plugin that completes a real, receipt-bound, offline-verifiable code-change
chain through the ordinary OpenWorkProof CLI bridge.

**Architecture:** Keep the TypeScript bundle as a pinned-host adapter and the
Python package as the only protocol authority. Close the two P0 compatibility
failures first, then assemble production handlers, bind verification to exact
receipts and path-content pairs, make Audit activation honest, and replace the
mock-heavy preflight with one real packaged process chain.

**Tech Stack:** TypeScript 5.9, Node.js 20+, pnpm 10, DeepSeek Harness
`0.1.1-rc.2`, Python 3.10-3.13, Pydantic v2, Ed25519, SQLite, pytest, Vitest,
Docker candidate/required-live gates.

---

## Task 1: Close exact version and native-mutator P0s

**Files:**
- Modify: `/Users/molin/Project/openworkproof-dsh-plugin/src/compatibility.ts`
- Modify: `/Users/molin/Project/openworkproof-dsh-plugin/src/bridge-client.ts`
- Modify: `/Users/molin/Project/openworkproof-dsh-plugin/src/policy.ts`
- Modify: `/Users/molin/Project/openworkproof-dsh-plugin/src/tools.ts`
- Modify: `/Users/molin/Project/openworkproof-dsh-plugin/test/bridge-client.test.ts`
- Modify: `/Users/molin/Project/openworkproof-dsh-plugin/test/fixtures/fake-bridge.mjs`
- Modify: `/Users/molin/Project/openworkproof-dsh-plugin/test/policy.test.ts`
- Modify: `/Users/molin/Project/openworkproof-dsh-plugin/test/compatibility.test.ts`
- Create: `/Users/molin/Project/openworkproof-dsh-plugin/test/real-bridge.test.ts`
- Create: `/Users/molin/Project/openworkproof-dsh-plugin/test/packaged-runtime.test.ts`

- [x] **Step 1: Write RED tests**

Add assertions that the negotiated OpenWorkProof version is `1.4.0`, a real
`owp dsh-bridge --stdio` child accepts the tuple, and Enforce denies exactly
`write`, `edit`, `bash`, `pwsh`, and `str_replace_editor`.
Also pack into a clean profile and import the installed entry point.

- [x] **Step 2: Run RED tests**

```bash
cd /Users/molin/Project/openworkproof-dsh-plugin
pnpm vitest run test/bridge-client.test.ts test/real-bridge.test.ts test/policy.test.ts
```

Expected: failures show `1.3.0` and both missing native mutators.
The clean package additionally fails on unresolved host runtime modules.

- [x] **Step 3: Add one compatibility tuple and closed mutator set**

Export the tuple from `compatibility.ts`, import it in client/tests/preflight,
and set:

```ts
export const NATIVE_MUTATORS = new Set([
  'write',
  'edit',
  'bash',
  'pwsh',
  'str_replace_editor',
])
```

Emit closed `ToolDefinition` objects directly so the packed plugin uses the
host services injected by DSH and does not import a second runtime package set.

- [x] **Step 4: Run GREEN and full plugin regression**

```bash
pnpm test
pnpm typecheck
pnpm build
git diff --check
```

Expected: all pass with a real core handshake.

- [x] **Step 5: Commit the plugin P0 repair**

```bash
git add src test
git commit -m "fix: close Harness compatibility bypasses"
```

Completed in plugin commit `7fba1b9`; clean packed artifact SHA-256 observed
during the gate was
`4de25e6daa0fa8bb92e36f4a89fad4b8848a9b9c5f852ff0da49e0b4ccb5d972`.
This temporary artifact is verification evidence, not a published release.

## Task 2: Assemble production case handlers for the ordinary CLI bridge

**Files:**
- Create: `src/openworkproof/dsh_handlers.py`
- Modify: `src/openworkproof/dsh_bridge.py`
- Modify: `src/openworkproof/cli.py`
- Modify: `tests/test_dsh_bridge_v01.py`
- Create: `tests/test_dsh_handlers_v01.py`

**Discovered prerequisite:** the reviewed case schema freezes a source
checkout but does not bind a controlled candidate runtime or an external
Verifier transport. Add and test those bindings through case initialization
before Step 1; do not use `scripts/create_dsh_fixture.py` as production code.

Progress: `candidate_runtime_root` is now a private owned `0700` directory
outside all frozen/control paths. Cases that allow `owp_run_tests` now also
bind an in-case `verifier_socket_path`; the socket client and production
handler assembly remain to be implemented.

- [ ] **Step 1: Write RED ordinary-CLI tests**

Start the real CLI bridge, open a generated case, authorize one patch, execute
it, request verification, request an acceptance draft, and export. Assert none
of the responses returns `EXECUTION_CASE_UNAVAILABLE` or
`HANDLER_NOT_CONFIGURED`.

- [ ] **Step 2: Verify RED**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_dsh_handlers_v01.py tests/test_dsh_bridge_v01.py
```

Expected: the real CLI bridge has no handler factory.

- [ ] **Step 3: Implement one production factory**

`build_dsh_case_handlers(manifest, token_store)` constructs the four existing
`DshCaseHandlers` callables from validated manifest data. It calls existing
OpenWorkProof execution, verification, acceptance-binding, and export
functions; it does not duplicate protocol logic or load Manager/Acceptor keys.

- [ ] **Step 4: Wire the factory only into the ordinary CLI**

`run_stdio_bridge()` defaults to `DshBridgeApplication(clock=clock,
handler_factory=build_dsh_case_handlers)`. Unit tests may continue injecting
special handlers explicitly.

- [ ] **Step 5: Run GREEN and commit**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_dsh_handlers_v01.py tests/test_dsh_bridge_v01.py \
  tests/test_dsh_execution_v01.py tests/test_dsh_verifier_v01.py
./.venv/bin/python -m pip check
git diff --check
git add src/openworkproof tests
git commit -m "feat: assemble production Harness case handlers"
```

## Task 3: Bind verification to one receipt and path-content map

**Files:**
- Modify: `src/openworkproof/dsh_verifier.py`
- Modify: `src/openworkproof/dsh_protocol.py`
- Modify: `src/openworkproof/dsh_bridge.py`
- Modify: `tests/test_dsh_verifier_v01.py`
- Modify: `tests/test_dsh_end_to_end_v01.py`

- [x] **Step 1: Write RED collision and missing-binding tests**

Create two worktrees whose changed paths are identical but whose file contents
are swapped. Assert their canonical verification bytes differ. Remove or alter
the action receipt binding and assert UNKNOWN with a stable reason code.

- [x] **Step 2: Verify RED**

```bash
./.venv/bin/python -m pytest -q tests/test_dsh_verifier_v01.py
```

Expected: current separately sorted path and digest lists collide or verify
without the exact receipt.

- [x] **Step 3: Replace parallel collections with artifact bindings**

Add a strict immutable `{path, sha256}` object, candidate tree digest,
execution digest, and ActionReceipt digest to the verification result. Build
them in UTF-8 path order and include them in canonical bytes.

- [x] **Step 4: Require exact committed receipt truth**

The verifier reads the receipt associated with the requested case and execution
identity, validates causal replay, and returns UNKNOWN when zero or multiple
bindings exist. A successful ledger replay without this binding is insufficient.

- [x] **Step 5: Run GREEN and commit**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_dsh_verifier_v01.py tests/test_dsh_end_to_end_v01.py
git diff --check
git add src/openworkproof tests
git commit -m "fix: bind Harness verification to exact execution truth"
```

## Task 4: Make Audit activation and terminal UNKNOWN explicit

**Files:**
- Modify: `/Users/molin/Project/openworkproof-dsh-plugin/src/config.ts`
- Modify: `/Users/molin/Project/openworkproof-dsh-plugin/src/index.ts`
- Modify: `/Users/molin/Project/openworkproof-dsh-plugin/src/evidence.ts`
- Modify: `/Users/molin/Project/openworkproof-dsh-plugin/cordis.patch.yml`
- Modify: `/Users/molin/Project/openworkproof-dsh-plugin/test/evidence.test.ts`
- Create: `/Users/molin/Project/openworkproof-dsh-plugin/test/plugin-activation.test.ts`

- [x] **Step 1: Write RED configuration and shutdown tests**

Assert that an enabled Audit or Enforce plugin without `caseDirectory` fails
with `OWP_CASE_DIRECTORY_REQUIRED`, the shipped unconfigured patch is explicitly
disabled, and shutdown commits each incomplete correlation as UNKNOWN.

- [x] **Step 2: Verify RED**

```bash
pnpm vitest run test/plugin-activation.test.ts test/evidence.test.ts
```

- [x] **Step 3: Implement honest activation and drain**

Require a case for active modes, retain an installable disabled base profile,
and make `EvidenceCorrelator.drain()` finalize incomplete entries before bridge
shutdown. Do not synthesize ActionReceipt truth in Audit.

- [x] **Step 4: Run GREEN and commit**

```bash
pnpm test
pnpm typecheck
git diff --check
git add src test cordis.patch.yml
git commit -m "fix: make Harness audit evidence explicit"
```

## Task 5: Align export verification and all human-key exclusions

**Files:**
- Modify: `src/openworkproof/dsh_case.py`
- Modify: `src/openworkproof/cli.py`
- Modify: `tests/test_dsh_case_v01.py`
- Modify: `tests/test_dsh_end_to_end_v01.py`
- Modify: `/Users/molin/Project/openworkproof-dsh-plugin/src/commands.ts`
- Modify: `/Users/molin/Project/openworkproof-dsh-plugin/test/commands.test.ts`

- [ ] **Step 1: Write RED tests**

Assert that `verifier-private-key.hex` and nested verifier-private-key fields
are rejected, and that the exact command printed by `/owp-export` succeeds on
the produced package and fails after one-byte tampering.

- [ ] **Step 2: Verify RED**

```bash
./.venv/bin/python -m pytest -q \
  tests/test_dsh_case_v01.py tests/test_dsh_end_to_end_v01.py
cd /Users/molin/Project/openworkproof-dsh-plugin
pnpm vitest run test/commands.test.ts
```

- [ ] **Step 3: Apply the minimal custody and command corrections**

Extend forbidden external authority key names to Manager, Verifier, and
Acceptor. Make the DSH export handler and printed verifier refer to one actual
format; do not merely rename the command text.

- [ ] **Step 4: Run GREEN and commit each repository**

Run the focused tests, `pip check`, plugin typecheck, and `git diff --check`,
then make one single-purpose commit in each repository.

Progress: Manager/Verifier/Acceptor private-key exclusions are enforced, and
the plugin now prints `owp audit-replay`, the verifier for the delivery package
emitted by the current DSH export path. The final generated-package command
round trip remains gated on the production handler from Task 2.

## Task 6: Add restart-safe consequential ACK recovery

**Files:**
- Modify: `src/openworkproof/dsh_bridge.py`
- Modify: `src/openworkproof/dsh_case.py`
- Modify: `tests/test_dsh_bridge_v01.py`
- Modify: `/Users/molin/Project/openworkproof-dsh-plugin/src/bridge-client.ts`
- Modify: `/Users/molin/Project/openworkproof-dsh-plugin/test/bridge-client.test.ts`

- [ ] **Step 1: Write RED process-restart tests**

Inject ACK loss after a real commit, terminate the bridge, start a new bridge,
query by case plus execution/request identity, and assert the committed digest
is recovered without a second handler call. Assert unavailable truth becomes
UNKNOWN and is never retried automatically.

- [ ] **Step 2: Verify RED in both repositories**

Current in-memory response caches must fail the cross-process test.

- [ ] **Step 3: Persist and query committed truth minimally**

Use the case ledger/evidence store as the durable authority. Add a closed query
message only if existing receipt lookup cannot answer the exact execution
binding. The TypeScript client may reconnect and query; it must not replay a
consequential `action_execute` after an indeterminate timeout.

- [ ] **Step 4: Run GREEN and commit**

Run bridge, execution, client, and package regressions before the two
single-purpose commits.

Progress: the core bridge now performs an exact ledger readback by execution
context and action arguments before invoking a consequential handler; a fresh
bridge instance recovered a real committed patch receipt without replay, and
indeterminate readback returned UNKNOWN. The TypeScript client test proves one
write on timeout and no automatic retry. A separate OS-process kill/respawn
test is still required before this task is complete.

## Task 7: Replace the mock-heavy preflight with a real packed chain

**Files:**
- Modify: `/Users/molin/Project/openworkproof-dsh-plugin/scripts/live-preflight.mjs`
- Create: `/Users/molin/Project/openworkproof-dsh-plugin/scripts/create-live-case.mjs`
- Modify: `/Users/molin/Project/openworkproof-dsh-plugin/package.json`
- Modify: `scripts/create_dsh_fixture.py`
- Modify: `tests/test_dsh_end_to_end_v01.py`

- [ ] **Step 1: Write a RED real-chain assertion**

The preflight must reject any artifact whose packed code contains a wrong OWP
version and must fail unless logs prove: profile load, actual DSH call, actual
core bridge PID, case open, native-mutator denial, authorized OWP action,
observation commit, bound verification, clean export verification, and tamper
rejection.

- [ ] **Step 2: Remove mock proof substitutes**

Do not directly instantiate `OwpPolicy`, do not supply a fake bridge, and do not
count a separately run Python pytest fixture as the host integration result.

- [ ] **Step 3: Execute the packed chain**

Install the tarball into a clean `DSH_HOME`, create one disposable signed case,
launch the pinned host with the real plugin configuration and real CLI bridge,
run the bounded workflow, and verify the emitted export in a second process.

- [ ] **Step 4: Emit a composed manifest**

Write canonical JSON binding core/plugin commits, versions, artifact digests,
runtime versions, exact command, result, and boundary statement. Verify the
manifest in an automated test.

- [ ] **Step 5: Commit after the real chain passes**

Make separate core and plugin commits. Do not update release metadata before
this gate.

## Task 8: Rebuild immutable supply-chain evidence and obtain re-review

**Files:**
- Create: `supply-chain/images/candidates/<new-revision>.json`
- Modify: `README.md`
- Modify: `README_en.md`
- Modify: `docs/status.md`
- Modify: `docs/superpowers/plans/2026-08-26-openworkproof-deepseek-harness-plugin-v01.md`

- [ ] **Step 1: Run focused gates**

Run all DSH core tests, the full plugin suite, typecheck, build, pack, real
preflight, pip check, compileall, and diff checks.

- [ ] **Step 2: Build a new immutable candidate inventory**

Source changes invalidate the existing candidate. Generate new build contexts,
OCI/docker archives, hashes, labels, and inventory without overwriting history.

- [ ] **Step 3: Run candidate and required-live gates**

Record exact passed/failed/skipped counts and exit codes. A skip is reported,
not rewritten as zero.

- [ ] **Step 4: Obtain two independent read-only reviews**

Both reviewers receive exact core/plugin revisions, artifact paths, the
composed manifest, and the original findings. READY requires direct closure of
every P0/P1 finding.

- [ ] **Step 5: Update truthful docs and integration state**

Mark the original plan's review step complete only after both reviews are
READY. Keep merge, push, registry publication, announcement, use, and adoption
unresolved until separately authorized and verified.
