# OpenWorkProof Independent Result and Recomposition Implementation

Date: 2026-08-06

Branch: `codex/independent-recomposition`

Spec: `docs/superpowers/specs/2026-08-06-openworkproof-independent-recomposition-design.md`

## Execution Rules

- Reuse the existing `execute_run_tests` and `compose_proof_transaction`
  paths. Do not introduce a second test tool, a generic episode framework, or
  any public v0.1 Schema change.
- Close the four coordinator gaps listed in §3 of the spec only with failing
  tests that prove each one.
- Episode kind is derived from the authoritative current state inside the
  coordinator; callers do not pass an episode flag.
- All atomic transactions follow the existing `BEGIN IMMEDIATE` / COMMIT /
  readback exact-truth pattern. Unknown COMMIT acknowledgements never retry a
  semantic operation.
- Frozen causal and policy replay rules are not redesigned without a failing
  test that proves an inconsistency.
- Do not rewrite historical candidate inventories or external OCI artifacts.
- Python: `.venv/bin/python -m pytest -q`; freezes: python 3.12.13, Docker
  mirror, day0 artifact root at `/Users/molin/Project/openWorkProof-day0`,
  repository-qualified execution image at
  `docker.io/openworkproof/execution-test@sha256:677cfa55596a640cc5a3c6988a878d88da133fc59d7ab3a08ea72a1ad2ddb8ca`.
- No real-name binding in README, docs, or code.

## File Map

- Modify: `src/openworkproof/mcp_server.py`
- Modify: `src/openworkproof/acceptance.py`
- Modify: `tests/test_acceptance.py`
- Modify: `tests/test_mcp_server.py`
- Modify: `tests/conftest.py`
- New: `tests/test_independent_recomposition.py`
- Modify: `README.md`
- Modify: `docs/status.md`
- Modify: `docs/superpowers/plans/2026-08-06-openworkproof-independent-recomposition-implementation.md`

## Task 1: Restore the Five-Dimension WorkOrder Helper

**Files:**

- Modify: `tests/test_acceptance.py`
- Modify: `tests/test_mcp_server.py`

- [ ] **Step 1: Add a five-dimension WorkOrder helper**

  In `tests/test_acceptance.py`, keep the existing
  `_four_dimension_work_order` helper for the acceptance-only path and add a
  parallel `_five_dimension_work_order` helper that retains the
  `independent_result` dimension, the `verifier_independent_result`
  evidence artifact, and the `disclose_only` independence policy already
  defined on the baseline WorkOrder.

- [ ] **Step 2: Use the helper for recomposition scenarios**

  Add a `_recomposition_case` fixture that builds a five-dimension ledger
  reaching `locally_verified` and `evidence_incomplete` so the recomposition
  tests can reuse the canonical preconditions.

- [ ] **Step 3: Run GREEN**

  Run:

  ```bash
  ./.venv/bin/python -m pytest tests/test_acceptance.py -q
  ```

  Expected: PASS with no behavioural change in the acceptance slice.

## Task 2: Independent Slot Selection and State After

**Files:**

- Modify: `src/openworkproof/mcp_server.py`
- Modify: `tests/test_independent_recomposition.py`
- Modify: `tests/test_mcp_server.py`

- [ ] **Step 1: Write RED state-aware slot tests**

  Add tests in `tests/test_independent_recomposition.py` that drive a
  `run_tests` verifier call from `evidence_incomplete` with a fresh
  execution context and assert:

  - the receipt uses the `verifier_independent_result` slot (path and digest
    derived from the slot, payload identicality allowed per T1);
  - `state_before` and `state_after` are both `evidence_incomplete` for both
    a passing and a non-passing independent closed result;
  - `state_after` remains `locally_verified` and the `verifier_result`
    slot is still used when the prior state is `running` or `retrying`;
  - a second run from `evidence_incomplete` after the first independent
    result commits returns `RECOVERY_REQUIRED` (or a clear sealed-episode
    refusal) rather than overwriting the first slot.

- [ ] **Step 2: Run RED**

  Expected: FAIL because the slot is still always selected by the test
  mode string and the state transition still moves the receipt to
  `locally_verified`.

- [ ] **Step 3: Implement state-based episode derivation**

  Inside `_build_run_tests_receipt`, derive the closed episode from the
  current authoritative state before any other branching:

  - `current_state in {"running", "retrying"}` →
    `episode = "primary_verifier"`;
  - `current_state == "evidence_incomplete"` and the caller's role is
    `Verifier` and `test_mode == "verifier"` →
    `episode = "independent_verifier"`;
  - all other state/mode combinations raise the existing fail-closed
    handler error.

  Use the episode to pick the evidence slot purpose
  (`verifier_result` for primary, `verifier_independent_result` for
  independent), to keep `state_after = evidence_incomplete` when the
  episode is `independent_verifier`, and to extend the causal parents
  with the latest `proof_composed` SystemEventReceipt for the
  independent episode.

  Refactor `_next_test_reference` and `_causal_parents` to accept an
  explicit purpose and trigger rather than reading module globals.

- [ ] **Step 4: Run GREEN**

  Run:

  ```bash
  ./.venv/bin/python -m pytest tests/test_independent_recomposition.py tests/test_mcp_server.py -q
  ```

  Expected: PASS. The pre-existing primary verifier and developer tests
  remain green.

## Task 3: Independent Pre-Start Gate

**Files:**

- Modify: `src/openworkproof/mcp_server.py`
- Modify: `tests/test_independent_recomposition.py`

- [ ] **Step 1: Write RED pre-start rejection tests**

  Cover the spec §7 list with explicit failing tests. Each test must
  snapshot the journal, quota events, sequence counter, state row, version,
  receipts, evidence publications, and report rows before the call and
  require exact equality after the rejected call:

  - state other than `evidence_incomplete`;
  - no available `verifier_independent_result` slot;
  - the slot exists but a previous independent result already occupies it;
  - the payload exceeds the slot's declared `max_size_bytes`;
  - a prior successful independent-result ToolCallReceipt already exists in
    the prefix;
  - `execution_context_id` or `container_instance_id_digest` already
    appears in any charged run-tests history;
  - the active patch receipt id does not match the current
    `ReplayCheckpoint`.

- [ ] **Step 2: Run RED**

  Expected: FAIL because the current gate only checks the primary slot
  and `recovered evidence publications`.

- [ ] **Step 3: Implement the pre-start gate**

  Before reserving execution or invoking the Docker driver, call a new
  `_validate_independent_pre_start(context, request, arguments)` helper that
  enforces the seven checks. The helper must reuse the existing
  `recover_evidence_publications` and `require_all_publications_committed`
  primitives.

  Refuse by raising the frozen `HandlerCoordinationError` codes so the
  caller sees the same error surface as the existing primary run_tests
  path.

- [ ] **Step 4: Run GREEN**

  Run:

  ```bash
  ./.venv/bin/python -m pytest tests/test_independent_recomposition.py -q
  ```

  Expected: PASS with no behavioural change to the primary path.

## Task 4: Recomposition Supports `previous_report_digest`

**Files:**

- Modify: `src/openworkproof/acceptance.py`
- Modify: `tests/test_independent_recomposition.py`

- [ ] **Step 1: Write RED recomposition request tests**

  Add tests that drive a Manager `owp.compose_proof` request from
  `evidence_incomplete` with the correct `previous_report_digest` and
  assert:

  - recomposition requires `previous_report_digest` equal to the digest
    referenced by the latest `proof_composed` SystemEventReceipt;
  - recomposition with `previous_report_digest = null`, with a stale
    digest, with an unknown digest, or with any digest that is not the
    current trigger's report digest is rejected before any write;
  - recomposition requires the Manager authorization gate
    (signature, freshness, role, Grant, capability, nonce, quota,
    validity, current context) which is the same as initial composition;
  - recomposition continues to produce `evidence_incomplete` when the
    five-dimension chain is still incomplete.

- [ ] **Step 2: Run RED**

  Expected: FAIL because the current
  `_derive_compose_expected_arguments` always returns
  `previous_report_digest = None` and the request digest check therefore
  rejects a Manager request that correctly supplies the trigger digest.

- [ ] **Step 3: Implement recomposition argument derivation**

  Replace the hard-coded `previous_report_digest = None` with a
  state-driven value:

  - `current_state == "locally_verified"` →
    `previous_report_digest = None`;
  - `current_state == "evidence_incomplete"` →
    `previous_report_digest = composition_report_digest(latest report)`
    resolved from the latest `proof_composed` SystemEventReceipt.

  Add an explicit reject branch for any state other than those two so a
  recomposition cannot be bound to a stale or absent digest. Reuse
  `_current_report` and `_latest_proof_composed_trigger`.

- [ ] **Step 4: Run GREEN**

  Run:

  ```bash
  ./.venv/bin/python -m pytest tests/test_independent_recomposition.py tests/test_acceptance.py -q
  ```

  Expected: PASS with both slices green.

## Task 5: Recomposition Receipt Causality

**Files:**

- Modify: `src/openworkproof/acceptance.py`
- Modify: `tests/test_independent_recomposition.py`

- [ ] **Step 1: Write RED recomposition receipt tests**

  Drive a recomposition that succeeds and assert the recomposition Manager
  ToolCallReceipt has:

  - the recomposition Manager Grant issuance receipt as its first parent;
  - the latest `proof_composed` trigger as its second parent;
  - the successful independent-result ToolCallReceipt as its third
    parent;
  - all parents in sequence order and unique;
  - `previous_report_digest` recorded in the report derivation equals the
    latest trigger's report digest and the recomposition digest refers to
    the second report.

- [ ] **Step 2: Run RED**

  Expected: FAIL because the recomposition receipt currently parents only
  the Manager Grant issuance receipt and active patch, omitting the trigger
  and the independent result.

- [ ] **Step 3: Implement recomposition causal parents**

  Extend `_compose_causal_parents` so the recomposition branch returns
  the recomposition Manager Grant, the latest `proof_composed` trigger,
  and the successful independent-result receipt. Reject any recomposition
  request whose `previous_report_digest` does not equal the latest
  trigger's `composition_report_digest`.

- [ ] **Step 4: Run GREEN**

  Run:

  ```bash
  ./.venv/bin/python -m pytest tests/test_independent_recomposition.py -q
  ```

  Expected: PASS.

## Task 6: Second CompositionReport Closes All Five Dimensions

**Files:**

- Modify: `src/openworkproof/acceptance.py`
- Modify: `tests/test_independent_recomposition.py`

- [ ] **Step 1: Write RED second-report tests**

  Drive a successful recomposition and assert the second CompositionReport:

  - covers `authority`, `scope`, `execution`, `result`, and
    `independent_result` exactly once;
  - lists both the `verifier_result` and `verifier_independent_result`
    EvidenceRefs under `test_evidence_refs`, sorted by path;
  - selects the independent-result ToolCallReceipt as
    `IndependenceAssessment.verifier_reference`;
  - leaves `IndependenceAssessment.developer_reference` equal to the
    authoritative Developer execution receipt;
  - reaches `proof_ready` only after causal replay, policy replay,
    evidence rehash, independence assessment, and every global
    postcondition pass;
  - persists as an immutable row in `composition_reports`; the first
    row remains unchanged.

- [ ] **Step 2: Run RED**

  Expected: FAIL because the report currently selects the primary Verifier
  receipt as `verifier_reference` and `test_evidence_refs` does not look
  up the `verifier_independent_result` slot.

- [ ] **Step 3: Implement five-dimension report derivation**

  Replace the current Verifier receipt lookup with a purpose-based selector
  that walks the recomposition prefix and returns:

  - the unique `verifier_result` EvidenceRef;
  - the unique `verifier_independent_result` EvidenceRef;

  rejecting recomposition when either is missing, drifted, or duplicated.

  Extend `_derive_composition_report` to:

  - mark `independent_result` covered only when the
    `verifier_independent_result` EvidenceRef exists;
  - include both test evidence refs in `test_evidence_refs` ordered by
    path;
  - select the matching independent ToolCallReceipt as
    `verifier_reference`;
  - retain the Developer receipt as `developer_reference`;
  - emit warnings derived from the Developer versus independent-Verifier
    correlation factors;
  - conclude `proof_ready` when all five dimensions are covered.

- [ ] **Step 4: Run GREEN**

  Run:

  ```bash
  ./.venv/bin/python -m pytest tests/test_independent_recomposition.py tests/test_acceptance.py -q
  ```

  Expected: PASS.

## Task 7: Recomposition Atomic Transaction and COMMIT-ACK Readback

**Files:**

- Modify: `src/openworkproof/acceptance.py`
- Modify: `tests/test_independent_recomposition.py`

- [ ] **Step 1: Write RED atomic recomposition tests**

  Cover the recomposition path with the same atomicity guarantees already
  applied to the initial compose transaction:

  - pre-COMMIT failure leaves every table and counter unchanged;
  - COMMIT-ACK loss recovers the recomposition receipt, the second
    trigger, the second report row, and the recomposed state row through
    exact readback, and raises `AcceptanceCommittedError` carrying the
    second report and the two receipts;
  - readback failure returns `RECOVERY_REQUIRED` rather than fabricating
    a third independent result;
  - a proven commit never becomes uncommitted because connection close,
    lock release, or cleanup failed.

- [ ] **Step 2: Run RED**

  Expected: FAIL because recomposition currently reuses the compose path
  that always writes one initiator, one trigger, one report, and one
  state transition. The recomposition must additionally validate the
  first report and the independent result in lockstep with the second
  write.

- [ ] **Step 3: Implement recomposition transaction path**

  Reuse the existing `compose_proof_transaction` framework:

  - load the unique current first report and the unique current first
    trigger from the ledger;
  - load the successful independent result and verify its evidence bytes;
  - construct the recomposition Manager receipt with the recomposition
    causal parents from Task 5;
  - derive the canonical second report from Task 6;
  - construct the second `proof_composed` trigger whose
    `composition_report_digest` is the second report digest;
  - inside the same `BEGIN IMMEDIATE`, insert both receipts, the parent
    rows, the quota event, the new report row, the state transition, and
    the sequence updates;
  - on COMMIT-ACK failure, run `_readback_recompose_committed` to prove
    both the recomposition receipts and the second report are present
    and well-formed, then raise `AcceptanceCommittedError(committed=...)`
    or `AcceptanceCommitIndeterminateError` exactly as in the initial
    compose path.

- [ ] **Step 4: Run GREEN**

  Run:

  ```bash
  ./.venv/bin/python -m pytest tests/test_independent_recomposition.py -q
  ```

  Expected: PASS.

## Task 8: Concurrency and Sealed-Episode Tests

**Files:**

- Modify: `tests/test_independent_recomposition.py`

- [ ] **Step 1: Write RED concurrency tests**

  - two threads racing an independent run_tests call on the same ledger
    produce at most one execution winner, the second attempt returns a
    closed refusal, and the committed evidence is byte-identical to
    the first;
  - two threads racing a Manager recomposition produce at most one second
    report and one second trigger, with the second attempt returning a
    closed refusal;
  - a non-passing closed independent result seals the episode: the
    ledger rejects any further independent run_tests call and any
    recomposition call, and only separately implemented rejection,
    termination, or contract-expiry tails may follow.

- [ ] **Step 2: Run RED**

  Expected: FAIL because the existing target lock prevents byte-level
  corruption but does not yet serialize the new independent and
  recomposition paths.

- [ ] **Step 3: Implement concurrency seal**

  Add an explicit check in the recomposition transaction that the
  independent-result ToolCallReceipt is unique within the prefix and that
  no later `proof_composed` trigger follows it. Add an explicit refusal
  in the run_tests path when the independent slot is already occupied.

  Use the existing per-target lock for serialization. Keep the
  existing handler-side concurrency primitives untouched.

- [ ] **Step 4: Run GREEN**

  Run:

  ```bash
  ./.venv/bin/python -m pytest tests/test_independent_recomposition.py -q
  ```

  Expected: PASS.

## Task 9: Offline Replay and Tamper Tests

**Files:**

- Modify: `tests/test_independent_recomposition.py`

- [ ] **Step 1: Write RED offline replay test**

  Build a complete bundle containing the WorkOrder, all Grants, every
  ActionReceipt, both CompositionReports, every committed evidence
  payload, and the six public keys. Run the existing offline replay
  helper to assert:

  - replayed state and version match;
  - both report digests are reconstructed;
  - the first trigger references the first report;
  - the independent receipt references the first trigger and uses fresh
    execution identifiers;
  - recomposition references the first report digest and the
    independent result;
  - the second trigger references the second report;
  - the second report concludes `proof_ready` with five-dimension
    coverage and the correct `test_evidence_refs`.

- [ ] **Step 2: Write RED tamper tests**

  For each of `composition_reports`, `receipts`, `receipt_parents`,
  `evidence_publications`, the independent payload, the correlation
  factors, and any public key, mutate one byte and assert the offline
  replay refuses with a `RECOVERY_REQUIRED`-style error and that the
  live verification gate fails closed before any write.

- [ ] **Step 3: Run RED**

  Expected: FAIL because the offline replay helper currently does not
  recognise the `verifier_independent_result` evidence purpose and the
  tamper tests are not yet present.

- [ ] **Step 4: Implement offline replay and tamper coverage**

  Extend the offline replay helper to look up the
  `verifier_independent_result` evidence purpose when reconstructing the
  five-dimension coverage and when validating the recomposition trigger
  digest. Add the tamper tests as a parametrized table covering each
  mutation. Reuse the existing `recovery_required` and
  `replay_authorization_causality` failure paths.

- [ ] **Step 5: Run GREEN**

  Run:

  ```bash
  ./.venv/bin/python -m pytest tests/test_independent_recomposition.py -q
  ```

  Expected: PASS.

## Task 10: Full Required-Live Verification

**Files:** none

- [ ] **Step 1: Run the focused protocol suites**

  Run:

  ```bash
  time ./.venv/bin/python -m pytest \
    tests/test_acceptance.py \
    tests/test_independent_recomposition.py \
    tests/test_contract.py \
    tests/test_signing.py \
    tests/test_state.py \
    tests/test_proof_composition.py \
    tests/test_policy.py \
    tests/test_receipt_chain.py \
    tests/test_mcp_server.py \
    tests/test_schema_registry.py -q
  ```

  Expected: zero failures. Record exact count and elapsed time.

- [ ] **Step 2: Resolve the repository-qualified execution image**

  The frozen required-live execution candidate for this branch is the
  existing repository-qualified RepoDigest below. Verify it directly; do
  not invent or retag an image:

  ```bash
  export OPENWORKPROOF_DOCKER_TEST_IMAGE='docker.io/openworkproof/execution-test@sha256:677cfa55596a640cc5a3c6988a878d88da133fc59d7ab3a08ea72a1ad2ddb8ca'
  docker image inspect "$OPENWORKPROOF_DOCKER_TEST_IMAGE" >/dev/null
  ```

  Expected: exit 0. If inspect fails, stop rather than replacing the
  immutable reference.

- [ ] **Step 3: Run full required-live verification**

  Run with the exact existing artifact root:

  ```bash
  OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT=/Users/molin/Project/openWorkProof-day0 \
  OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1 \
  OPENWORKPROOF_DOCKER_TEST_IMAGE="$OPENWORKPROOF_DOCKER_TEST_IMAGE" \
  ./.venv/bin/python -m pytest -q
  ```

  Expected: zero failures and zero required-live skips. Record exact
  count and elapsed time.

- [ ] **Step 4: Run non-test verification**

  Run:

  ```bash
  ./.venv/bin/python -m pip check
  ./.venv/bin/python -m compileall -q src tests supply-chain/images
  git diff --check
  ```

  Require zero owned OpenWorkProof containers and volumes after the
  suite.

- [ ] **Step 5: Update only observed project facts**

  In README and `docs/status.md`:

  - state that the local five-dimension independent-result and
    recomposition path is implemented and tested;
  - replace stale test counts with the exact fresh counts from this task;
  - keep explicit boundaries for Acceptor rejection, real external
    Acceptor signing, registry publication, clean-cache reacquisition,
    final-helper, D8, Day 0, Rich demo, contest delivery, and external
    acceptance;
  - do not write "独立验收完成"; local recomposition success is not
    external human acceptance.

## Task 11: Completion Checkpoint

**Files:** none

- [ ] **Step 1: Record exact evidence**

  Record:

  - branch and implementation commit SHAs;
  - focused and full required-live counts/times;
  - schema file and registry hashes;
  - one full independent-then-recomposition object chain from
    `evidence_incomplete` to `proof_ready`;
  - concurrency, COMMIT-ACK, tamper, and offline replay results;
  - pip, compileall, diff, and Docker cleanup results;
  - clean worktree status.

- [ ] **Step 2: Keep external states separate**

  Explicitly retain as unproven:

  - real Acceptor assignment and signing;
  - Acceptor rejection transaction;
  - independent external environment reproduction;
  - registry publication and clean-cache reacquisition;
  - final trusted helper, D8, Day 0, Rich demo, contest submission,
    award, and commercial validation.

- [ ] **Step 3: Finish the branch**

  Invoke `finishing-a-development-branch`, rerun the required final
  verification it specifies, and present the standard integration
  choices. Do not merge or push without the user's explicit selection.
