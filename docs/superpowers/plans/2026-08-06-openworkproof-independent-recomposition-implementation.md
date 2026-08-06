# OpenWorkProof Independent Result and Recomposition Implementation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the existing five-dimension OpenWorkProof protocol path from `evidence_incomplete`, through one fresh independent Verifier result and an explicitly authorized Manager recomposition, to a second immutable `CompositionReport` whose truthful terminal state is `proof_ready`.

**Architecture:** Extend only the existing durable `owp.run_tests` and `owp.compose_proof` coordinators. The authoritative ledger state selects the primary-versus-independent test episode; immutable evidence slots, causal parents, the previous report digest, signed receipts, atomic SQLite transactions, and exact COMMIT readback jointly prove the transition without adding a seventh role or changing the public v0.1 schemas.

**Tech Stack:** Python 3.12, Pydantic v2 frozen models, Ed25519 signatures, RFC 8785 canonical JSON, SQLite `BEGIN IMMEDIATE` transactions, Docker-backed test execution, pytest, Hypothesis, and the existing OpenWorkProof evidence/policy/causal replay modules.

---

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
- New: `tests/test_independent_recomposition.py`
- Modify: `README.md`
- Modify: `docs/status.md`
- Modify: `docs/superpowers/plans/2026-08-06-openworkproof-independent-recomposition-implementation.md`

## Task 0: Freeze the Baseline and Test Names

**Files:** none

- [x] **Step 1: Confirm the implementation branch and clean tree**

  Run:

  ```bash
  test "$(git branch --show-current)" = "codex/independent-recomposition"
  test -z "$(git status --porcelain)"
  git rev-parse HEAD
  git rev-parse main
  ```

  Expected: both `test` commands exit 0; record the two SHAs. Stop if the
  worktree is dirty instead of discarding unrelated changes.

- [x] **Step 2: Run the exact pre-change protocol baseline**

  Run:

  ```bash
  ./.venv/bin/python -m pytest \
    tests/test_mcp_server.py \
    tests/test_acceptance.py \
    tests/test_policy.py \
    tests/test_proof_composition.py -q
  ```

  Expected: zero failures. Record the exact passed count; this is the
  regression baseline, not evidence that the new path already works.

## Task 1: Build the Reusable Five-Dimension Scenario

**Files:**

- Modify: `tests/test_mcp_server.py:222-290`
- Create: `tests/test_independent_recomposition.py`

- [x] **Step 1: Make only the Verifier test quota configurable**

  Change the existing helper signature and its Verifier child grant. Keep the
  default at one so every pre-existing test is byte-for-byte equivalent:

  ```python
  def _run_tests_case(
      *,
      tmp_path: Path,
      signed_work_order: WorkOrder,
      role_keys,
      sidecar_receipt_factory,
      now: datetime,
      verifier_tool_calls: int = 1,
  ):
      # Existing setup is unchanged above the Verifier child grant.
      verifier = _child_grant(
          work_order,
          root,
          role_keys,
          label="handler-loop:verifier",
          subject_role="Verifier",
          updates={
              "quota": {
                  "tool_calls": verifier_tool_calls,
                  "repair_rounds": 0,
              }
          },
      )
  ```

- [x] **Step 2: Add the five-dimension scenario builder**

  In `tests/test_independent_recomposition.py`, define one helper that passes
  the unmodified `signed_work_order`, uses `verifier_tool_calls=2`, executes
  the primary Verifier run, commits the first composition, and returns the
  refreshed `evidence_incomplete` context:

  ```python
  def _independent_case(
      tmp_path,
      signed_work_order,
      ephemeral_role_keys,
      sidecar_receipt_factory,
      fixed_now,
  ):
      case = _run_tests_case(
          tmp_path=tmp_path,
          signed_work_order=signed_work_order,
          role_keys=ephemeral_role_keys,
          sidecar_receipt_factory=sidecar_receipt_factory,
          now=fixed_now,
          verifier_tool_calls=2,
      )
      _execute_run_tests_case(
          case,
          tmp_path,
          ephemeral_role_keys,
          _FakeRunTestsExecutionDriver(),
      )
      locally_verified = _current_run_tests_context(case, fixed_now)
      compose_request = _signed_compose_request(
          case,
          locally_verified,
          ephemeral_role_keys,
          fixed_now,
          previous_report_digest=None,
          nonce_label="independent:first-compose",
      )
      first = acceptance.compose_proof_transaction(
          case["ledger_path"],
          evidence_root=case["evidence_root"],
          context=locally_verified,
          request=compose_request,
          sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
          clock=lambda: fixed_now,
      )
      incomplete = _current_run_tests_context(case, fixed_now)
      assert incomplete.current_state == "evidence_incomplete"
      return case, first, incomplete
  ```

  Define the signing helper in the same file; accept only the digest and nonce
  label as variable protocol inputs:

  ```python
  def _signed_compose_request(
      case,
      context,
      role_keys,
      now,
      *,
      previous_report_digest,
      nonce_label: str,
  ) -> AgentRequest:
      manager = role_keys["Manager"][1]
      arguments = ComposeProofArguments(
          expected_state_version=len(context.ledger_prefix.receipts),
          previous_report_digest=previous_report_digest,
      )
      return AgentRequest.model_validate(
          sign_payload(
              "agent-request",
              {
                  "claim_type": "agent-request",
                  "work_order_digest": case["work_order"].digest,
                  "grant_id": case["root"].grant_id,
                  "actor_id": manager["subject_id"],
                  "actor_key_id": manager["key_id"],
                  "tool_name": "owp.compose_proof",
                  "arguments_digest": request_arguments_digest(
                      "owp.compose_proof", arguments
                  ),
                  "nonce": _grant_id(nonce_label),
                  "requested_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "authentication_method": "agent_signature",
                  "model_id": "model",
                  "model_version": "1",
                  "prompt_template_digest": "a" * 64,
                  "context_source_digest": "b" * 64,
              },
              role_keys["Manager"][0],
          )
      )
  ```

- [x] **Step 3: Prove the fixture without changing product behaviour**

  Add `test_five_dimension_case_stops_at_evidence_incomplete` and assert the
  first report covers four dimensions, marks `independent_result` false,
  and leaves exactly one immutable report row.

  Run:

  ```bash
  ./.venv/bin/python -m pytest \
    tests/test_independent_recomposition.py::test_five_dimension_case_stops_at_evidence_incomplete \
    tests/test_mcp_server.py tests/test_acceptance.py -q
  ```

  Expected: PASS; this task builds only the precondition fixture.

- [ ] **Step 4: Commit the fixture**

  ```bash
  git add tests/test_mcp_server.py tests/test_independent_recomposition.py
  git commit -m "test: build independent recomposition scenario"
  ```

## Task 2: Independent Slot Selection and State After

**Files:**

- Modify: `src/openworkproof/mcp_server.py`
- Modify: `tests/test_independent_recomposition.py`
- Modify: `tests/test_mcp_server.py`

- [x] **Step 1: Write RED state-aware slot tests**

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

- [x] **Step 2: Run RED**

  Expected: FAIL because the slot is still always selected by the test
  mode string and the state transition still moves the receipt to
  `locally_verified`.

- [x] **Step 3: Implement state-based episode derivation**

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

  Use this closed selector; do not add an episode field to
  `RunTestsArguments`:

  ```python
  def _run_tests_episode(
      context: AuthorizationContext,
      request: AgentRequest,
      arguments: RunTestsArguments,
  ) -> Literal["primary_verifier", "independent_verifier"]:
      binding = next(
          (
              item
              for item in context.work_order.key_bindings
              if item.subject_id == request.actor_id
              and item.key_id == request.actor_key_id
          ),
          None,
      )
      if binding is None or binding.role != "Verifier":
          raise HandlerCoordinationError("run-tests actor is not the Verifier")
      if arguments.test_mode != "verifier":
          raise HandlerCoordinationError("run-tests mode is not verifier")
      if context.current_state in {"running", "retrying"}:
          return "primary_verifier"
      if context.current_state == "evidence_incomplete":
          return "independent_verifier"
      raise HandlerCoordinationError("run-tests state is not executable")
  ```

  Map `primary_verifier` to purpose `verifier_result`; map
  `independent_verifier` to purpose `verifier_independent_result`. Pass that
  purpose into `_next_test_reference`. For the independent branch set
  `state_after = "evidence_incomplete"` regardless of the test exit code;
  the exit code remains truthful in `TestResultEvidence` and the causal replay
  determines whether recomposition is eligible.

  In `tests/test_mcp_server.py::_current_run_tests_context`, replace the
  hard-coded `evidence/verifier-result/` prefix with signed purpose paths so
  the refreshed replay checkpoint contains both results:

  ```python
  verifier_paths = {
      f"evidence/{artifact.path}"
      for artifact in case["work_order"].evidence_policy.artifacts
      if artifact.purpose in {
          "verifier_result",
          "verifier_independent_result",
      }
  }
  # Inside the existing receipt/reference loop:
  if reference.path in verifier_paths:
      verified.append(ResultEvidence.model_validate_json(payload))
  ```

- [x] **Step 4: Run GREEN**

  Run:

  ```bash
  ./.venv/bin/python -m pytest tests/test_independent_recomposition.py tests/test_mcp_server.py -q
  ```

  Expected: PASS. The pre-existing primary verifier and developer tests
  remain green.

- [x] **Step 5: Commit the state-derived episode**

  ```bash
  git add src/openworkproof/mcp_server.py \
    tests/test_independent_recomposition.py tests/test_mcp_server.py
  git commit -m "feat: commit independent verifier result"
  ```

## Task 3: Independent Pre-Start Gate

**Files:**

- Modify: `src/openworkproof/mcp_server.py`
- Modify: `tests/test_independent_recomposition.py`

- [x] **Step 1: Write RED pre-start rejection tests**

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

- [x] **Step 2: Run RED**

  Expected: the slot-purpose and trigger assertions FAIL. The freshness,
  reused execution identity, active patch, and prior-independent-result cases
  may already pass through `authorize_tool_call`; retain those tests as proof
  of gate ordering instead of duplicating policy logic.

- [x] **Step 3: Implement only the missing coordinator checks**

  Preserve the existing order in `execute_run_tests`: recovery, target lock,
  current-context check, `authorize_tool_call`, execution binding, receipt
  preflight, then reservation. Do not copy the policy predicates into a new
  validation subsystem.

  In the independent branch of `_preflight_run_tests_receipts`, require the
  current causal trigger and run `_next_test_reference` with purpose
  `verifier_independent_result` before `_reserve_handler_execution` can run:

  ```python
  if episode == "independent_verifier":
      trigger_id = context.causal_state.latest_composition_trigger_id
      if trigger_id is None:
          raise HandlerCoordinationError(
              "independent verifier trigger is unavailable"
          )
      if (
          context.independent_failure_terminal
          or context.causal_state.independent_result_receipt_id is not None
      ):
          raise HandlerCoordinationError("independent verifier episode is sealed")
  ```

  Let `authorize_tool_call` remain authoritative for reused execution ids,
  active-patch binding, role/capability/quota, and an already successful
  independent receipt. Let `_next_test_reference` remain authoritative for
  slot presence, uniqueness, media type, and maximum byte size. Assert in
  every rejection test that `execution_driver.prepare` and
  `execution_driver.start_and_wait` were never called.

- [x] **Step 4: Run GREEN**

  Run:

  ```bash
  ./.venv/bin/python -m pytest tests/test_independent_recomposition.py -q
  ```

  Expected: PASS with no behavioural change to the primary path.

- [x] **Step 5: Commit the pre-start gate**

  ```bash
  git add src/openworkproof/mcp_server.py tests/test_independent_recomposition.py
  git commit -m "fix: gate independent verifier execution"
  ```

## Task 4: Recomposition Supports `previous_report_digest`

**Files:**

- Modify: `src/openworkproof/acceptance.py`
- Modify: `tests/test_independent_recomposition.py`

- [x] **Step 1: Write RED recomposition request tests**

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

- [x] **Step 2: Run RED**

  Expected: FAIL because the current
  `_derive_compose_expected_arguments` always returns
  `previous_report_digest = None` and the request digest check therefore
  rejects a Manager request that correctly supplies the trigger digest.

- [x] **Step 3: Implement recomposition argument derivation**

  Replace the hard-coded `previous_report_digest = None` with a
  state-driven value:

  - `current_state == "locally_verified"` →
    `previous_report_digest = None`;
  - `current_state == "evidence_incomplete"` →
    `previous_report_digest = composition_report_digest(latest report)`
    resolved from the latest `proof_composed` SystemEventReceipt.

  Add an explicit reject branch for any state other than those two so a
  recomposition cannot be bound to a stale or absent digest. Add this bounded
  trigger lookup next to `_current_report`:

  ```python
  def _latest_proof_composed_trigger(
      context: AuthorizationContext,
  ) -> SystemEventReceipt:
      trigger_id = context.causal_state.latest_composition_trigger_id
      matches = tuple(
          receipt
          for receipt in context.ledger_prefix.receipts
          if isinstance(receipt, SystemEventReceipt)
          and receipt.receipt_id == trigger_id
          and receipt.system_event_name == "proof_composed"
      )
      if len(matches) != 1:
          raise AcceptanceTransactionError(
              "current composition trigger is unavailable"
          )
      return matches[0]
  ```

  Derive the expected request arguments inside the target lock:

  ```python
  if context.current_state == "locally_verified":
      expected_previous_report_digest = None
  elif context.current_state == "evidence_incomplete":
      current_report = _current_report(path, context.work_order)
      trigger = _latest_proof_composed_trigger(context)
      expected_previous_report_digest = composition_report_digest(current_report)
      if (
          getattr(trigger.cause, "composition_report_digest", None)
          != expected_previous_report_digest
      ):
          raise AcceptanceTransactionError(
              "current report does not match its proof-composed trigger"
          )
  else:
      raise AcceptanceTransactionError("composition state is invalid")

  expected = ComposeProofArguments(
      expected_state_version=len(context.ledger_prefix.receipts),
      previous_report_digest=expected_previous_report_digest,
  )
  ```

- [x] **Step 4: Run GREEN**

  Run:

  ```bash
  ./.venv/bin/python -m pytest tests/test_independent_recomposition.py tests/test_acceptance.py -q
  ```

  Expected: PASS with both slices green.

- [x] **Step 5: Commit current-report binding**

  ```bash
  git add src/openworkproof/acceptance.py tests/test_independent_recomposition.py
  git commit -m "feat: bind recomposition to current report"
  ```

## Task 5: Recomposition Receipt Causality

**Files:**

- Modify: `src/openworkproof/acceptance.py`
- Modify: `tests/test_independent_recomposition.py`

- [x] **Step 1: Write RED recomposition receipt tests**

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

- [x] **Step 2: Run RED**

  Expected: FAIL because the recomposition receipt currently parents only
  the Manager Grant issuance receipt and active patch, omitting the trigger
  and the independent result.

- [x] **Step 3: Implement recomposition causal parents**

  Extend `_compose_causal_parents` so the recomposition branch returns
  the recomposition Manager Grant, the latest `proof_composed` trigger,
  and the successful independent-result receipt. Reject any recomposition
  request whose `previous_report_digest` does not equal the latest
  trigger's `composition_report_digest`.

  Pass `ComposeProofArguments` into `_compose_causal_parents` and place this
  recomposition branch immediately after adding the issuance parent, before
  the existing active-patch/primary-test branch:

  ```python
  if arguments.previous_report_digest is not None:
      trigger_id = context.causal_state.latest_composition_trigger_id
      independent_id = context.causal_state.independent_result_receipt_id
      trigger = by_id.get(trigger_id)
      independent = by_id.get(independent_id)
      if (
          not isinstance(trigger, SystemEventReceipt)
          or trigger.system_event_name != "proof_composed"
          or getattr(trigger.cause, "composition_report_digest", None)
          != arguments.previous_report_digest
          or not isinstance(independent, ToolCallReceipt)
          or independent.tool_name != "owp.run_tests"
          or independent.execution_status != "succeeded"
      ):
          raise AcceptanceTransactionError(
              "recomposition causal parents are unavailable"
          )
      parents[trigger.receipt_id] = trigger
      parents[independent.receipt_id] = independent
      return tuple(
          receipt.receipt_id
          for receipt in sorted(parents.values(), key=lambda item: item.sequence)
      )
  ```

  In this branch do not also add the active patch or the primary Verifier
  receipt. The exact parent vector is Grant issuance, current composition
  trigger, independent result, in ledger sequence order.

- [x] **Step 4: Run GREEN**

  Run:

  ```bash
  ./.venv/bin/python -m pytest tests/test_independent_recomposition.py -q
  ```

  Expected: PASS.

- [ ] **Step 5: Commit recomposition causality**

  ```bash
  git add src/openworkproof/acceptance.py tests/test_independent_recomposition.py
  git commit -m "feat: commit recomposition causal parents"
  ```

## Task 6: Second CompositionReport Closes All Five Dimensions

**Files:**

- Modify: `src/openworkproof/acceptance.py`
- Modify: `tests/test_independent_recomposition.py`

- [x] **Step 1: Write RED second-report tests**

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

- [x] **Step 2: Run RED**

  Expected: FAIL because the report currently selects the primary Verifier
  receipt as `verifier_reference` and `test_evidence_refs` does not look
  up the `verifier_independent_result` slot.

- [x] **Step 3: Implement five-dimension report derivation**

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

  Resolve evidence paths from the signed WorkOrder rather than hard-coding a
  directory prefix:

  ```python
  def _evidence_path_for_purpose(work_order, purpose: str) -> str:
      matches = tuple(
          artifact.path
          for artifact in work_order.evidence_policy.artifacts
          if artifact.purpose == purpose
      )
      if len(matches) != 1:
          raise AcceptanceTransactionError(
              f"composition evidence purpose is not unique: {purpose}"
          )
      return f"evidence/{matches[0]}"
  ```

  At the start of `_derive_composition_report`, retain the returned causal
  state and derive completion eligibility from proven history:

  ```python
  causal_state = replay_authorization_causality(work_order, prefix)
  eligible_state = context.current_state in {"locally_verified", "proof_ready"}
  if context.current_state == "evidence_incomplete":
      eligible_state = (
          causal_state.independent_result_receipt_id is not None
          and not causal_state.independent_failure_terminal
      )
  complete = not missing_dimensions and eligible_state
  ```

  Choose the Verifier correlation reference by receipt identity, not by the
  first Verifier encountered:

  ```python
  verifier_receipt_id = causal_state.independent_result_receipt_id
  if verifier_receipt_id is None:
      verifier_receipt_id = next(
          (
              receipt.receipt_id
              for receipt in prefix
              if isinstance(receipt, ToolCallReceipt)
              and _role_for(receipt, work_order) == "Verifier"
              and any(
                  reference.path
                  == _evidence_path_for_purpose(work_order, "verifier_result")
                  for reference in receipt.evidence_refs
              )
          ),
          None,
      )
  verifier_receipt = next(
      (
          receipt
          for receipt in prefix
          if isinstance(receipt, ToolCallReceipt)
          and receipt.receipt_id == verifier_receipt_id
      ),
      None,
  )
  if verifier_receipt is None or verifier_receipt.correlation_factors is None:
      raise AcceptanceTransactionError(
          "composition requires a verifier execution reference"
      )
  ```

  Change `_sorted_unique_evidence_refs_for_test` to accept `work_order`, build
  the allowed path set from purposes `verifier_result` and
  `verifier_independent_result`, reject duplicate paths with differing
  digests, and return the path-sorted tuple.

- [x] **Step 4: Run GREEN**

  Run:

  ```bash
  ./.venv/bin/python -m pytest tests/test_independent_recomposition.py tests/test_acceptance.py -q
  ```

  Expected: PASS.

- [ ] **Step 5: Commit five-dimension report derivation**

  ```bash
  git add src/openworkproof/acceptance.py tests/test_independent_recomposition.py
  git commit -m "feat: derive independent composition report"
  ```

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

- [ ] **Step 2: Run the atomicity tests before adding new transaction code**

  Run the four named tests. Expected: the normal recomposition may already
  pass after Tasks 4-6 because `_insert_compose_rows` and
  `_readback_compose_committed` are report-agnostic. Fault-injection cases
  reveal any real gap. Do not add a second transaction implementation merely
  because this is the second report.

- [ ] **Step 3: Reuse and prove the existing atomic transaction**

  The intended production path remains exactly:

  ```python
  connection.execute("BEGIN IMMEDIATE")
  _insert_compose_rows(
      connection,
      work_order=work_order,
      initiator=initiator,
      trigger=trigger,
      report=report,
      current_state=context.current_state,
      current_version=state_row[1],
  )
  connection.execute("COMMIT")
  if not _readback_compose_committed(
      path,
      work_order=work_order,
      initiator=initiator,
      trigger=trigger,
      report=report,
      expected_state=trigger.state_after,
      expected_version=state_row[1] + 1,
  ):
      raise AcceptanceCommitIndeterminateError(
          "composition readback could not confirm the exact commit"
      )
  ```

  Before entering `BEGIN IMMEDIATE`, require the validated current report,
  its unique trigger, and the successful independent receipt established in
  Tasks 4-6. Keep insertion, state/version updates, sequence increments,
  quota charge, COMMIT-ACK recovery, and cleanup handling in the existing
  functions. Strengthen `_readback_compose_committed` itself to read
  `work_order_state` and require `(expected_state, expected_version)` in
  addition to the exact final receipt pair and report object. Update both the
  normal-COMMIT and lost-COMMIT-ACK calls with those two arguments. Do not
  create `_readback_recompose_committed`.

- [ ] **Step 4: Run GREEN**

  Run:

  ```bash
  ./.venv/bin/python -m pytest tests/test_independent_recomposition.py -q
  ```

  Expected: PASS.

- [ ] **Step 5: Commit recomposition transaction evidence**

  ```bash
  git add src/openworkproof/acceptance.py tests/test_independent_recomposition.py
  git commit -m "test: prove atomic proof recomposition"
  ```

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

  Expected: the tests may already serialize correctly because both coordinators
  borrow or acquire the same per-target lock. Any failure must identify a
  missing sealed-state check, not justify a new locking primitive.

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

- [ ] **Step 5: Commit concurrency and seal coverage**

  ```bash
  git add src/openworkproof/mcp_server.py src/openworkproof/acceptance.py \
    tests/test_independent_recomposition.py
  git commit -m "test: seal independent recomposition races"
  ```

## Task 9: Offline Replay and Tamper Tests

**Files:**

- Modify: `src/openworkproof/acceptance.py`
- Modify: `tests/test_independent_recomposition.py`

- [ ] **Step 1: Write RED offline replay test**

  Build a complete bundle containing the WorkOrder, all Grants, every
  ActionReceipt, both CompositionReports, every committed evidence
  payload, and the six public keys. Run the extended
  `verify_acceptance_bundle` with `reports=(first_report, second_report)` to
  assert:

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

  For the copied bundle, independently mutate one report, one receipt, the
  independent payload, one correlation factor, and one public key; each call
  must raise `AcceptanceTransactionError`. Separately mutate live-ledger rows
  in `composition_reports`, `receipts`, `receipt_parents`, and
  `evidence_publications`; rebuilding the authorization context must fail
  before any new receipt, quota event, report, state, or sequence write.

- [ ] **Step 3: Run RED**

  Expected: FAIL because `verify_acceptance_bundle` accepts only one current
  report and therefore cannot prove both signed report-to-trigger bindings.

- [ ] **Step 4: Implement exact two-report offline binding**

  Extract the report-prefix checks already present in
  `validate_acceptance_bindings` into a pure private helper:

  ```python
  def _validate_composition_report_binding(
      *,
      work_order,
      report: CompositionReport,
      receipts: tuple[ActionReceiptEnvelope, ...],
  ) -> CompositionReport:
      initiator_indexes = tuple(
          index
          for index, receipt in enumerate(receipts)
          if receipt.receipt_id == report.initiator_receipt_id
          and receipt.digest == report.initiator_receipt_digest
      )
      if len(initiator_indexes) != 1:
          raise AcceptanceTransactionError(
              "composition report initiator is not unique"
          )
      initiator_index = initiator_indexes[0]
      trigger = (
          receipts[initiator_index + 1]
          if initiator_index + 1 < len(receipts)
          else None
      )
      report_digest = composition_report_digest(report)
      report_prefix = receipts[: initiator_index + 1]
      report_refs = _sorted_unique_evidence_refs(report_prefix)
      if (
          report.work_order_digest != work_order.digest
          or not isinstance(trigger, SystemEventReceipt)
          or trigger.system_event_name != "proof_composed"
          or getattr(trigger.cause, "composition_report_digest", None)
          != report_digest
          or report.receipt_digests
          != tuple(receipt.digest for receipt in report_prefix)
          or report.causal_graph_root != causal_graph_root(report_prefix)
          or report.evidence_snapshot_digest
          != evidence_snapshot_digest(report_refs)
      ):
          raise AcceptanceTransactionError(
              "composition report does not match its authoritative prefix"
          )
      return report
  ```

  Add a pure `verify_composition_bundle` that validates the grant chain,
  constructs `AuthorizationLedgerPrefix`, validates all committed evidence,
  calls `replay_authorization_causality`, requires one supplied report per
  `proof_composed` trigger, validates each report with the helper above, and
  returns the last report. Add an optional keyword-only
  `reports: tuple[CompositionReport, ...] | None = None` to
  `verify_acceptance_bundle`; default it to `(report,)` for backward
  compatibility, pass it through `verify_composition_bundle`, require its last
  report to equal `report`, then run the existing AcceptanceReceipt binding.

  Parameterize copied-bundle tampering with named mutator callables. Every
  mutation must rebuild the affected frozen model instead of bypassing
  Pydantic validation, so the test proves either model validation or protocol
  replay fails closed for the right layer.

- [ ] **Step 5: Run GREEN**

  Run:

  ```bash
  ./.venv/bin/python -m pytest tests/test_independent_recomposition.py -q
  ```

  Expected: PASS.

- [ ] **Step 6: Commit offline replay support**

  ```bash
  git add src/openworkproof/acceptance.py tests/test_independent_recomposition.py
  git commit -m "feat: verify two-report bundles offline"
  ```

## Task 10: Full Required-Live Verification

**Files:** none

- [ ] **Step 1: Prove the frozen candidate inventory still matches**

  This feature changes `mcp_server.py` and `acceptance.py`, neither of which is
  in `supply-chain/images/trusted-helper/SOURCE_ALLOWLIST`; it does not change
  an image definition, lock, runner, fixed Verifier test, or allowlisted helper
  source. Therefore the existing immutable candidate should remain uniquely
  selectable. Verify that fact rather than creating a new inventory:

  ```bash
  OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT=/Users/molin/Project/openWorkProof-day0 \
  OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1 \
  ./.venv/bin/python -m pytest \
    tests/test_image_supply_chain.py \
    tests/test_candidate_supplychain_integration.py -q
  ```

  Expected: zero failures and zero skips. If the selector reports zero current
  matches, stop and inspect the actual tracked-definition diff; do not rewrite
  a historical inventory or silently retag an image.

- [ ] **Step 2: Run the focused protocol suites**

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

- [ ] **Step 3: Resolve the repository-qualified execution image**

  The frozen required-live execution candidate for this branch is the
  existing repository-qualified RepoDigest below. Verify it directly; do
  not invent or retag an image:

  ```bash
  export OPENWORKPROOF_DOCKER_TEST_IMAGE='docker.io/openworkproof/execution-test@sha256:677cfa55596a640cc5a3c6988a878d88da133fc59d7ab3a08ea72a1ad2ddb8ca'
  docker image inspect "$OPENWORKPROOF_DOCKER_TEST_IMAGE" >/dev/null
  ```

  Expected: exit 0. If inspect fails, stop rather than replacing the
  immutable reference.

- [ ] **Step 4: Run full required-live verification**

  Run with the exact existing artifact root:

  ```bash
  OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT=/Users/molin/Project/openWorkProof-day0 \
  OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1 \
  OPENWORKPROOF_DOCKER_TEST_IMAGE="$OPENWORKPROOF_DOCKER_TEST_IMAGE" \
  ./.venv/bin/python -m pytest -q
  ```

  Expected: zero failures and zero required-live skips. Record exact
  count and elapsed time.

- [ ] **Step 5: Run non-test verification**

  Run:

  ```bash
  ./.venv/bin/python -m pip check
  ./.venv/bin/python -m compileall -q src tests supply-chain/images
  git diff --check
  ```

  Require zero owned OpenWorkProof containers and volumes after the
  suite.

- [ ] **Step 6: Update only observed project facts**

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

- [ ] **Step 7: Commit only verified status claims**

  ```bash
  git add README.md docs/status.md \
    docs/superpowers/plans/2026-08-06-openworkproof-independent-recomposition-implementation.md
  git diff --cached --check
  git commit -m "docs: record independent recomposition verification"
  ```

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

## Plan Self-Review Record

- Spec coverage: §§6-11 map to Tasks 2, 3, 7, and 8; §§12-16 map to Tasks
  4-8; §17 maps to Task 9; §§18-20 map to Tasks 9-11.
- Public-contract boundary: no WorkOrder field, schema version, role, tool name,
  or test profile changes are planned. The only offline API extension is an
  optional keyword-only tuple of reports with a backward-compatible default.
- Type consistency: `previous_report_digest` is always a canonical
  `composition_report_digest`; independent identity comes only from
  `AuthorizationCausalState.independent_result_receipt_id`; trigger identity
  comes only from `latest_composition_trigger_id`; test evidence paths come
  from signed artifact purposes.
- Transaction consistency: both first composition and recomposition use
  `_insert_compose_rows` and `_readback_compose_committed`; no parallel
  transaction, alternate lock, semantic retry, or report overwrite is added.
- Evidence boundary: local tests can prove protocol mechanics and reproducible
  execution only. They do not prove a real Acceptor, external independence,
  registry publication, contest submission, award, or commercial validation.
- Placeholder scan: every code-changing step names its function, inputs,
  expected behavior, verification command, and owned file path.

## Execution Handoff

Plan execution has two supported modes:

1. **Subagent-Driven (recommended):** explicitly authorize dispatch; use
   `subagent-driven-development`, one fresh implementation worker per task,
   with specification and code-quality review between tasks.
2. **Inline Execution:** use `executing-plans` in this task, execute Tasks 0-11
   sequentially, and stop at the verification checkpoints before integration.

Neither mode authorizes merging to `main` or pushing to the remote. Those
remain separate user decisions after all required-live evidence is current.
