# OpenWorkProof Acceptor Rejection Implementation

Date: 2026-08-07

Branch: `codex/acceptor-rejection`

Spec: `docs/superpowers/specs/2026-08-07-openworkproof-acceptor-rejection-design.md`

## Execution Rules

- Reuse the existing `commit_acceptance` transaction framework. Do not add a
  second request tool, a second state, or any public v0.1 Schema-breaking
  change beyond the new `acceptance-rejection-receipt` object.
- The rejection is signed by the same WorkOrder-bound Acceptor key; no
  seventh role.
- All atomic transactions follow the existing `BEGIN IMMEDIATE` / COMMIT /
  exact-readback pattern. Unknown COMMIT acknowledgements never retry a
  semantic operation.
- `rejected_at` freshness, expiry, and deadline rules mirror the acceptance
  path exactly.
- Mutually exclusive with acceptance: one request tip commits exactly one of
  accepted / rejected, enforced in the transaction and at the storage layer.
- Frozen causal and policy replay rules are not redesigned without a failing
  test that proves an inconsistency.
- Python: `.venv/bin/python -m pytest -q`; freezes: python 3.12.13, Docker
  mirror, day0 artifact root at `/Users/molin/Project/openWorkProof-day0`,
  repository-qualified execution image at
  `docker.io/openworkproof/execution-test@sha256:677cfa55596a640cc5a3c6988a878d88da133fc59d7ab3a08ea72a1ad2ddb8ca`.
- No real-name binding in README, docs, or code.

## File Map

- Modify: `src/openworkproof/models.py`
- Modify: `src/openworkproof/evidence.py`
- Modify: `src/openworkproof/acceptance.py`
- Modify: `src/openworkproof/state.py`
- Modify: `src/openworkproof/schema_registry.py` (regenerated)
- Modify: `specs/v0.1/*` (regenerated schema)
- Modify: `tests/test_acceptance.py`
- New: `tests/test_acceptor_rejection.py`
- Modify: `README.md`
- Modify: `docs/status.md`
- Modify: `docs/superpowers/plans/2026-08-07-openworkproof-acceptor-rejection-implementation.md`

## Task 1: AcceptanceRejectionReceipt Model

**Files:** `src/openworkproof/models.py`, `specs/v0.1/*`, `src/openworkproof/schema_registry.py`

- [ ] **Step 1: Write RED model tests**
  Add `tests/test_acceptor_rejection.py` with tests that construct an
  `AcceptanceRejectionReceipt` for a canonical awaiting_human case and
  assert:
  - the model accepts the canonical object and `decision == "rejected"`;
  - every invalid `reason_code`, an over-long `reason_detail`, a
    `rejected_at` before the request `occurred_at`, and a non-matching
    `acceptance_request_receipt_digest` fail model validation;
  - the schema registry round-trips the new object.

- [ ] **Step 2: Run RED**
  Expected: FAIL because `AcceptanceRejectionReceipt` does not exist.

- [ ] **Step 3: Implement the model**
  Add `AcceptanceRejectionReceipt(SignedProtocolModel)` per spec 4.1 with
  model validators: closed `reason_code`, bounded `reason_detail`,
  `decision == "rejected"`, request/report/evidence binding, and
  `rejected_at` ordering. Regenerate the v0.1 schema and registry.

- [ ] **Step 4: Run GREEN**
  Run:

  ```bash
  ./.venv/bin/python -m pytest tests/test_acceptor_rejection.py tests/test_schema_registry.py -q
  ```

  Expected: PASS.

## Task 2: Storage, Replay, and State Authorization

**Files:** `src/openworkproof/evidence.py`, `src/openworkproof/state.py`

- [ ] **Step 1: Write RED replay tests**
  Add tests that:
  - initialize a ledger for an awaiting_human work order, insert a
    rejection row directly, and assert `_replay_receipt_publication_ledger`
    reconstructs it and the terminal state is `rejected`;
  - assert a tampered rejection row (canonical JSON or signature) fails the
    replay;
  - assert `append_receipt`/`apply_state_transition` accepts a
    rejection-type transition from `awaiting_human` to `rejected` and
    rejects it from any other state.

- [ ] **Step 2: Run RED**
  Expected: FAIL because the table, validator, and state authorization do
  not exist.

- [ ] **Step 3: Implement storage and replay**
  - Add the `acceptance_rejection_receipts` table (spec 4.2).
  - Add `_validated_acceptance_rejections(connection, work_order)` that
    reads bounded rows, validates canonical JSON, WorkOrder binding,
    Acceptor signature, and request binding (mirror
    `_validated_acceptance_receipts`).
  - Extend `_readback`/suffix validation to accept a terminal state of
    `accepted` or `rejected` with the matching receipt class at the tip.
  - Authorize the rejection receipt type in `state.py` for the
    `awaiting_human -> rejected` same-state append under the human-gate
    tail.

- [ ] **Step 4: Run GREEN**
  Run:

  ```bash
  ./.venv/bin/python -m pytest tests/test_acceptor_rejection.py tests/test_state.py -q
  ```

  Expected: PASS.

## Task 3: Reject Transaction with COMMIT-ACK Readback

**Files:** `src/openworkproof/acceptance.py`

- [ ] **Step 1: Write RED transaction tests**
  Drive a canonical awaiting_human case and assert `reject_acceptance_transaction`:
  - commits the rejection row, the `rejected` state, the version bump, and
    the sequence update atomically;
  - rejects a wrong-role signer, a stale/future `rejected_at`, an expired
    request, a stale tip, and a report/snapshot mismatch before any write
    (table snapshot equality);
  - under COMMIT-ACK loss, reopens the ledger, proves the exact rejection
    and the `rejected` state, and raises `AcceptanceCommittedError` with
    the committed rejection;
  - under readback failure, raises `AcceptanceCommitIndeterminateError`
    rather than fabricating a second rejection.

- [ ] **Step 2: Run RED**
  Expected: FAIL because the transaction does not exist.

- [ ] **Step 3: Implement the transaction**
  Add `reject_acceptance_transaction` per spec 4.3, reusing the acceptance
  transaction skeleton: lock, frozen second, `require_current_context`,
  `awaiting_human` gate, request-tip binding, Acceptor signature check,
  evidence binding, time-window checks, mutual-exclusion check against both
  the accepted and rejected sides, one `BEGIN IMMEDIATE`, and the exact
  readback on COMMIT-ACK failure.

- [ ] **Step 4: Run GREEN**
  Run:

  ```bash
  ./.venv/bin/python -m pytest tests/test_acceptor_rejection.py tests/test_acceptance.py -q
  ```

  Expected: PASS with both slices green.

## Task 4: Mutual Exclusion and Failure Matrix

**Files:** `tests/test_acceptor_rejection.py`

- [ ] **Step 1: Write RED mutual-exclusion tests**
  - accept after reject: after a rejection commits, a later
    `commit_acceptance` for the same request fails and writes nothing;
  - reject after accept: after an acceptance commits, a later
    `reject_acceptance_transaction` fails and writes nothing;
  - a second rejection for the same request fails (storage UNIQUE);
  - table-snapshot equality for every rejected attempt.

- [ ] **Step 2: Run RED**
  Expected: FAIL for the cross-side checks that the transaction does not
  yet enforce.

- [ ] **Step 3: Implement the missing guard**
  Ensure the transaction and `_readback` check both the accepted and
  rejected sides for the request before writing, and that the storage
  layer enforces one rejection per request.

- [ ] **Step 4: Run GREEN**
  Run:

  ```bash
  ./.venv/bin/python -m pytest tests/test_acceptor_rejection.py -q
  ```

  Expected: PASS.

## Task 5: Offline Rejection Bundle and Tamper Matrix

**Files:** `src/openworkproof/acceptance.py`, `tests/test_acceptor_rejection.py`

- [ ] **Step 1: Write RED offline tests**
  - build a copied bundle with a rejection and verify it offline via
    `verify_acceptance_bundle(rejection=...)`; assert the rejection binds
    the same request tip and evidence snapshot;
  - tamper the rejection row, the evidence bytes, or a public key and
    assert the offline replay fails closed before any write.

- [ ] **Step 2: Run RED**
  Expected: FAIL because `verify_acceptance_bundle` has no rejection path.

- [ ] **Step 3: Implement offline rejection verification**
  Extend `verify_acceptance_bundle` with the optional `rejection` parameter
  per spec 4.5, binding it one-to-one onto the request tip.

- [ ] **Step 4: Run GREEN**
  Run:

  ```bash
  ./.venv/bin/python -m pytest tests/test_acceptor_rejection.py -q
  ```

  Expected: PASS.

## Task 6: Full Verification and Completion

**Files:** `README.md`, `docs/status.md`, this plan

- [ ] **Step 1: Run the focused protocol suites**
  Run:

  ```bash
  time ./.venv/bin/python -m pytest \
    tests/test_acceptance.py \
    tests/test_acceptor_rejection.py \
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
  Verify the frozen image directly; do not invent or retag an image:

  ```bash
  export OPENWORKPROOF_DOCKER_TEST_IMAGE='docker.io/openworkproof/execution-test@sha256:677cfa55596a640cc5a3c6988a878d88da133fc59d7ab3a08ea72a1ad2ddb8ca'
  docker image inspect "$OPENWORKPROOF_DOCKER_TEST_IMAGE" >/dev/null
  ```

  Expected: exit 0. If inspect fails, stop rather than replacing the
  immutable reference.

- [ ] **Step 3: Run full required-live verification**
  Run:

  ```bash
  OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT=/Users/molin/Project/openWorkProof-day0 \
  OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1 \
  OPENWORKPROOF_DOCKER_TEST_IMAGE="$OPENWORKPROOF_DOCKER_TEST_IMAGE" \
  ./.venv/bin/python -m pytest -q
  ```

  Expected: zero failures and zero required-live skips. Record exact count
  and elapsed time.

- [ ] **Step 4: Run non-test verification**
  Run:

  ```bash
  ./.venv/bin/python -m pip check
  ./.venv/bin/python -m compileall -q src tests supply-chain/images
  git diff --check
  ```

  Require zero owned OpenWorkProof containers and volumes after the suite.

- [ ] **Step 5: Update only observed project facts**
  In README and `docs/status.md`: state that the Acceptor rejection path is
  implemented and tested; replace stale counts with the exact fresh counts;
  keep explicit boundaries for real external Acceptor signing, termination
  and `FROZEN -> rejected` paths, `prepare_acceptance_rejection` drafts,
  CLI/MCP transmission, Day 0, and contest delivery.

- [ ] **Step 6: Record exact evidence and finish the branch**
  Record branch and implementation commit SHAs, focused/full counts,
  schema hashes, the rejection object chain from `awaiting_human` to
  `rejected`, mutual-exclusion and COMMIT-ACK results, and clean worktree
  status. Invoke `finishing-a-development-branch`, rerun the required final
  verification it specifies, and present the standard integration choices.
  Do not merge or push without the user's explicit selection.
