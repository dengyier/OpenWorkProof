# OpenWorkProof Independent Acceptance Transaction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a separately keyed Acceptor and close the atomic `proof_ready -> awaiting_human -> accepted` strong-success path from deterministic CompositionReport through externally signed AcceptanceReceipt.

**Architecture:** Keep protocol models in `models.py`, extract current-ledger/evidence snapshot revalidation from `mcp_server.py` into a focused internal `runtime_context.py`, and place composition/acceptance construction plus transactions in a new `acceptance.py`. Reuse the existing target lock, canonical JCS/signing functions, causal/policy replay, evidence publication gates, SQLite transaction/version rules, and committed-truth readback patterns.

**Tech Stack:** Python 3.12, Pydantic 2, RFC 8785 JCS, Ed25519/cryptography, SQLite, pytest, Docker required-live gates.

---

## Execution Rules

- Design authority:
  `docs/superpowers/specs/2026-08-06-openworkproof-acceptance-transaction-design.md`
  at commit `666ed6d44343c0ecc5dd226a9bf7c1fb1bde251c` or a descendant containing the
  same approved requirements.
- Work only on branch `codex/acceptance-transaction`; never implement on
  `main`.
- Do not name or bind a real Acceptor. Test identity is `acceptor-local`.
- Do not add rejection receipts, CLI, MCP transport, AgentTeams, Rich demo,
  image-registry claims, Day 0 claims, or contest-delivery claims.
- For every behavior: add one focused test, run it and observe the expected
  failure, implement the minimum production code, then rerun the focused test.
- Do not rewrite historical candidate inventories or external OCI artifacts.
- Do not change the public protocol version from `0.1`; this is an explicit
  unreleased v0.1-development compatibility break.

## File Map

**Create**

- `src/openworkproof/runtime_context.py` — package-internal current ledger,
  evidence, and replay-checkpoint revalidation shared by trusted handlers and
  acceptance transactions.
- `src/openworkproof/acceptance.py` — deterministic aggregate digests,
  CompositionReport construction, compose/request/prepare/commit operations,
  transaction errors, and committed-truth readback.
- `tests/test_acceptance.py` — focused model, digest, transaction, crash,
  stale-snapshot, and concurrency tests.

**Modify**

- `src/openworkproof/models.py` — sixth role, request-role matrix,
  CompositionReport, and Acceptor-signed AcceptanceReceipt validation.
- `src/openworkproof/signing.py` — exact six-key WorkOrder identity binding.
- `src/openworkproof/state.py` — Acceptor signature authority and final-request
  role validation.
- `src/openworkproof/evidence.py` — `composition_reports` schema, bounded report
  loader, acceptance-suffix validation, and shared transaction helpers.
- `src/openworkproof/mcp_server.py` — import extracted runtime-context
  revalidation without changing handler behavior.
- `src/openworkproof/schema_registry.py` — reviewed v0.1 development anchors.
- `src/openworkproof/schemas/v0.1/*.json` — regenerated canonical schemas.
- `specs/v0.1/*.json` — byte-identical public schema mirror.
- `tests/conftest.py` — deterministic and ephemeral Acceptor fixtures.
- `tests/test_contract.py`, `tests/test_signing.py`, `tests/test_state.py`,
  `tests/test_receipt_chain.py`, `tests/test_schema_registry.py` — role and
  signature expectations.
- `tests/test_mcp_server.py` — runtime-context extraction regression coverage.
- `README.md`, `docs/status.md` — fresh verified state only.

## Task 1: Establish a Clean Execution Baseline

**Files:** none

- [ ] **Step 1: Confirm branch and source authority**

Run:

```bash
git status --short --branch
git rev-parse HEAD
git merge-base --is-ancestor 666ed6d44343c0ecc5dd226a9bf7c1fb1bde251c HEAD
```

Expected: branch is `codex/acceptance-transaction`, worktree is clean, and the
ancestor command exits 0.

- [ ] **Step 2: Confirm the Python environment**

Run:

```bash
./.venv/bin/python --version
./.venv/bin/python -m pip check
```

Expected: Python 3.12 and `No broken requirements found.`

- [ ] **Step 3: Run the portable baseline**

Run:

```bash
./.venv/bin/python -m pytest -q
```

Expected: the existing suite passes. Record the exact count and elapsed time;
do not reuse the historical 2117 count as current evidence.

## Task 2: Separate Acceptor Authority in Models, Signatures, and State

**Files:**

- Modify: `src/openworkproof/models.py`
- Modify: `src/openworkproof/signing.py`
- Modify: `src/openworkproof/state.py`
- Modify: `tests/conftest.py`
- Modify: `tests/test_contract.py`
- Modify: `tests/test_signing.py`
- Modify: `tests/test_state.py`
- Modify: `tests/test_receipt_chain.py`

- [ ] **Step 1: Write the RED six-role contract test**

Add a focused test to `tests/test_contract.py` that appends a deterministic
Acceptor binding, points `acceptor_key_ids` at it, and expects a valid
WorkOrder:

```python
def test_work_order_binds_distinct_acceptor(
    work_order_dict: dict,
    key_bindings: list[dict],
) -> None:
    acceptor = deterministic_key_binding(
        "Acceptor", "acceptor-local", 6
    )
    candidate = copy.deepcopy(work_order_dict)
    candidate["key_bindings"] = [*key_bindings, acceptor]
    candidate["acceptor_key_ids"] = [acceptor["key_id"]]

    parsed = contract_models.WorkOrder.model_validate(candidate)

    assert parsed.key_bindings[-1].role == "Acceptor"
    assert parsed.acceptor_key_ids == (acceptor["key_id"],)
```

Import `deterministic_key_binding` from `conftest` in the same style as the
existing test helpers.

- [ ] **Step 2: Run RED**

Run:

```bash
./.venv/bin/python -m pytest tests/test_contract.py::test_work_order_binds_distinct_acceptor -q
```

Expected: FAIL because `Acceptor` is not an allowed role or the fixed role
order still requires five bindings.

- [ ] **Step 3: Implement the minimum six-role model**

In `src/openworkproof/models.py` make the closed role tuple and KeyBinding
literal exact:

```python
_KEY_ROLES = (
    "Maintainer",
    "Manager",
    "Developer",
    "Verifier",
    "Sidecar",
    "Acceptor",
)

class KeyBinding(ProtocolModel):
    role: Literal[
        "Maintainer",
        "Manager",
        "Developer",
        "Verifier",
        "Sidecar",
        "Acceptor",
    ]
    subject_id: Identifier
    key_id: KeyId
    public_key_b64url: PublicKeyB64Url
```

Replace the five-key WorkOrder check with:

```python
roles = tuple(binding.role for binding in self.key_bindings)
if roles != _KEY_ROLES:
    raise ValueError("key bindings must use the fixed role order")
subject_ids = tuple(binding.subject_id for binding in self.key_bindings)
key_ids = tuple(binding.key_id for binding in self.key_bindings)
if len(set(subject_ids)) != 6 or len(set(key_ids)) != 6:
    raise ValueError("key binding subjects and keys must be unique")
maintainer, manager, _, _, _, acceptor = self.key_bindings
if (
    self.issuer_id != maintainer.subject_id
    or self.signer_key_id != maintainer.key_id
    or self.acceptor_key_ids != (acceptor.key_id,)
):
    raise ValueError(
        "Maintainer must issue/sign and Acceptor must accept"
    )
```

Update every exact-five key count in `signing.py`, `state.py`, and
`evidence.py` to exact six. Do not replace the exact-count checks with open
ended membership checks.

- [ ] **Step 4: Move AcceptanceReceipt signer authority to Acceptor**

In `AcceptanceReceipt.validate_against_work_order` and
`state._validate_acceptance`, select `work_order.key_bindings[5]`. Preserve
WorkOrder signature validation at index 0.

Update `tests/conftest.py`:

```python
EPHEMERAL_ROLES = (
    "Maintainer",
    "Manager",
    "Developer",
    "Verifier",
    "Sidecar",
    "Acceptor",
)
```

Add the deterministic Acceptor binding to `key_bindings`, point every fixture
WorkOrder's `acceptor_key_ids` at it, and sign `signed_acceptance_receipt` with
`ephemeral_role_keys["Acceptor"][0]`.

- [ ] **Step 5: Add negative signer and alias tests**

Add parameterized tests proving that all five non-Acceptor keys fail
AcceptanceReceipt verification and that duplicate Acceptor/Maintainer subject
or key IDs make WorkOrder construction fail.

Run:

```bash
./.venv/bin/python -m pytest \
  tests/test_contract.py \
  tests/test_signing.py \
  tests/test_state.py \
  tests/test_receipt_chain.py -q
```

Expected: PASS outside the intentionally stale schema-anchor tests.

- [ ] **Step 6: Close the final-request role matrix**

Change `ApprovalRequestedReceipt.required_role` to
`Literal["Maintainer", "Acceptor"]` and extend `_validate_request`:

```python
expected_role = (
    "Maintainer"
    if self.request_kind == "high_risk_action"
    else "Acceptor"
)
if self.required_role != expected_role:
    raise ValueError("approval request role does not match request kind")
```

Update `state._validate_final_request` to require `Acceptor`. Add focused tests
showing high-risk Maintainer and final-acceptance Acceptor are valid while the
crossed combinations fail.

- [ ] **Step 7: Run the role-focused GREEN suite**

Run:

```bash
./.venv/bin/python -m pytest \
  tests/test_contract.py \
  tests/test_signing.py \
  tests/test_state.py \
  tests/test_receipt_chain.py -q
```

Expected: PASS.

## Task 3: Regenerate the Reviewed v0.1 Development Schemas

**Files:**

- Modify: `src/openworkproof/schema_registry.py`
- Modify: `tests/test_schema_registry.py`
- Replace generated: `src/openworkproof/schemas/v0.1/*.json`
- Replace generated: `specs/v0.1/*.json`

- [ ] **Step 1: Observe RED schema drift**

Run:

```bash
./.venv/bin/python -m pytest \
  tests/test_schema_registry.py::test_current_generators_match_frozen_v01_schema_anchors -q
```

Expected: FAIL because reviewed v0.1 development anchors still describe five
roles and Maintainer acceptance.

- [ ] **Step 2: Compute reviewed schema bytes and hashes without writing**

Run this exact read-only command:

```bash
./.venv/bin/python - <<'PY'
import hashlib
import rfc8785
from openworkproof.models import (
    ACTION_RECEIPT_ADAPTER,
    AcceptanceReceipt,
    CapabilityGrant,
    WorkOrder,
)

schemas = {
    "acceptance-receipt.schema.json": AcceptanceReceipt.model_json_schema(),
    "action-receipt.schema.json": ACTION_RECEIPT_ADAPTER.json_schema(),
    "capability-grant.schema.json": CapabilityGrant.model_json_schema(),
    "work-order.schema.json": WorkOrder.model_json_schema(),
}
digests = {
    name: hashlib.sha256(rfc8785.dumps(schema)).hexdigest()
    for name, schema in schemas.items()
}
registry = {
    "schema_version": "openworkproof-schema-registry/0.1",
    "protocol_version": "0.1",
    "schemas": [
        {
            "object_type": object_type,
            "path": path,
            "sha256": digests[path],
        }
        for object_type, path in {
            "acceptance-receipt": "acceptance-receipt.schema.json",
            "action-receipt": "action-receipt.schema.json",
            "capability-grant": "capability-grant.schema.json",
            "work-order": "work-order.schema.json",
        }.items()
    ],
}
digests["schema-registry.json"] = hashlib.sha256(
    rfc8785.dumps(registry)
).hexdigest()
for name in sorted(digests):
    print(name, digests[name])
PY
```

Expected: five lowercase SHA-256 lines. Capture them verbatim in the task log.

- [ ] **Step 3: Update both reviewed anchor maps**

Use `apply_patch` to replace exactly the five digest values in
`src/openworkproof/schema_registry.py` and `tests/test_schema_registry.py` with
the command output. Do not change filenames, object types, or protocol
version.

- [ ] **Step 4: Generate package and mirror schemas transactionally**

Run:

```bash
./.venv/bin/python -m openworkproof.schema_registry \
  src/openworkproof/schemas/v0.1 \
  --mirror specs/v0.1
```

Expected: exit 0; package and mirror contain the same five canonical files.

- [ ] **Step 5: Run schema GREEN**

Run:

```bash
./.venv/bin/python -m pytest tests/test_schema_registry.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit Acceptor authority**

Run:

```bash
git add \
  src/openworkproof/models.py \
  src/openworkproof/signing.py \
  src/openworkproof/state.py \
  src/openworkproof/evidence.py \
  src/openworkproof/schema_registry.py \
  src/openworkproof/schemas/v0.1 \
  specs/v0.1 \
  tests/conftest.py \
  tests/test_contract.py \
  tests/test_signing.py \
  tests/test_state.py \
  tests/test_receipt_chain.py \
  tests/test_schema_registry.py
git diff --cached --check
git commit -m "feat: separate acceptor authority"
```

Expected: one commit containing only role, signature, state, fixture, and
schema-authority changes.

## Task 4: Extract Current Runtime-Context Revalidation

**Files:**

- Create: `src/openworkproof/runtime_context.py`
- Modify: `src/openworkproof/mcp_server.py`
- Modify: `tests/test_mcp_server.py`

- [ ] **Step 1: Verify the existing characterization test**

The extraction is already covered by
`test_execute_run_tests_rejects_stale_context_before_second_handler`, which
changes the authoritative context before a second call and proves the handler
does not execute from a stale snapshot.

- [ ] **Step 2: Run the characterization test**

Run:

```bash
./.venv/bin/python -m pytest \
  tests/test_mcp_server.py::test_execute_run_tests_rejects_stale_context_before_second_handler -q
```

Expected before extraction: PASS. This freezes behavior rather than
introducing new behavior.

- [ ] **Step 3: Move, do not rewrite, the current-snapshot functions**

Create `runtime_context.py` with this error boundary:

```python
class RuntimeContextError(RuntimeError):
    """The supplied authorization context is not the current authority."""
```

Move `_committed_evidence_matches_context` and `_require_current_context` from
`mcp_server.py` into this module and rename the latter to
`require_current_context(ledger_path: Path, evidence_root: Path, context:
AuthorizationContext, now: datetime, lock_descriptor: int) -> None`. Preserve
descriptor anchoring, byte checks,
WorkOrder/prefix/state/version comparison, publication COMMITTED checks, and
exact `derive_authorization_context` equality. Translate internal errors to
`RuntimeContextError` without weakening messages.

In `mcp_server.py`, call `require_current_context` and translate
`RuntimeContextError` to `HandlerCoordinationError` at the existing boundary.

- [ ] **Step 4: Run extraction GREEN**

Run:

```bash
./.venv/bin/python -m pytest tests/test_mcp_server.py -q
```

Expected: PASS with no behavior changes.

## Task 5: Add the Deterministic CompositionReport Authority

**Files:**

- Modify: `src/openworkproof/models.py`
- Create: `src/openworkproof/acceptance.py`
- Create: `tests/test_acceptance.py`

- [ ] **Step 1: Write RED aggregate-digest tests**

Create `tests/test_acceptance.py` and add tests for exact formulas:

```python
def test_causal_graph_root_is_sequence_ordered(receipts) -> None:
    expected = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/causal-graph-root/0.1",
                "nodes": [
                    {
                        "receipt_id": receipt.receipt_id,
                        "receipt_digest": receipt.digest,
                        "parent_receipt_ids": list(
                            receipt.parent_receipt_ids
                        ),
                    }
                    for receipt in sorted(
                        receipts, key=lambda item: item.sequence
                    )
                ],
            }
        )
    ).hexdigest()
    assert causal_graph_root(tuple(reversed(receipts))) == expected
```

Add an equivalent evidence-snapshot test using path-byte-sorted EvidenceRefs.

- [ ] **Step 2: Run RED**

Run:

```bash
./.venv/bin/python -m pytest \
  tests/test_acceptance.py::test_causal_graph_root_is_sequence_ordered -q
```

Expected: FAIL because `openworkproof.acceptance` does not exist.

- [ ] **Step 3: Implement pure aggregate helpers**

Create `acceptance.py` with exact closed helpers:

```python
class AcceptanceTransactionError(RuntimeError):
    """Composition or acceptance failed before proven commit."""


class AcceptanceCommittedError(AcceptanceTransactionError):
    """The exact result committed but a later operation failed."""

    def __init__(self, message: str, committed: object) -> None:
        super().__init__(message)
        self.committed = committed


class AcceptanceCommitIndeterminateError(AcceptanceTransactionError):
    """Readback could prove neither rollback nor the exact commit."""


def causal_graph_root(
    receipts: tuple[ActionReceiptEnvelope, ...],
) -> str:
    ordered = tuple(sorted(receipts, key=lambda item: item.sequence))
    if ordered != receipts or len({item.receipt_id for item in ordered}) != len(ordered):
        raise AcceptanceTransactionError("receipt prefix is not canonical")
    nodes = [
        {
            "receipt_id": item.receipt_id,
            "receipt_digest": item.digest,
            "parent_receipt_ids": list(item.parent_receipt_ids),
        }
        for item in ordered
    ]
    return hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/causal-graph-root/0.1",
                "nodes": nodes,
            }
        )
    ).hexdigest()
```

Implement `evidence_snapshot_digest` with a canonical path-byte-sorted unique
EvidenceRef vector and `composition_report_digest` as SHA-256 of exact report
JCS bytes.

- [ ] **Step 4: Add CompositionReport to models**

Add a closed `CompositionReport(ProtocolModel)` immediately before
AcceptanceReceipt with the fields from design section 7.2. Reuse
`FinalArtifact`, `EvidenceRef`, `IndependenceAssessment`, `ReportDiagnostic`,
and `PredicateResult`. Its validator must enforce:

```python
if self.verifier_conclusion == "proof_ready":
    if (
        not self.causal_complete
        or self.unresolved_failures
        or not self.independence_assessment.satisfied
        or not self.global_postconditions_satisfied
    ):
        raise ValueError("proof-ready report is not closed")
else:
    if not self.unresolved_failures:
        raise ValueError("incomplete report requires closed diagnostics")
```

Also enforce sorted/unique artifacts, tests, warnings, failures, and exact
postcondition order.

- [ ] **Step 5: Add report-construction tests**

Cover:

- reversed input normalizes only where the API explicitly accepts unordered
  input;
- duplicate receipts or evidence paths fail;
- changed evidence bytes fail rehash before report construction;
- a complete report is `proof_ready`;
- missing evidence, failed independence, or failed postcondition produces
  `evidence_incomplete` with the correct closed diagnostic code;
- warnings are recomputed from shared correlation factors.

Run:

```bash
./.venv/bin/python -m pytest tests/test_acceptance.py -q
```

Expected: PASS for pure report tests.

## Task 6: Persist Reports and Commit Proof Composition Atomically

**Files:**

- Modify: `src/openworkproof/evidence.py`
- Modify: `src/openworkproof/acceptance.py`
- Modify: `tests/test_acceptance.py`
- Modify: `tests/test_receipt_chain.py`

- [ ] **Step 1: Write RED ledger-schema and tamper tests**

Add tests that initialize a fresh ledger and assert the exact table:

```sql
CREATE TABLE composition_reports (
    report_digest TEXT PRIMARY KEY,
    work_order_digest TEXT NOT NULL
        REFERENCES work_orders(work_order_digest),
    initiator_receipt_id TEXT NOT NULL UNIQUE
        REFERENCES receipts(receipt_id),
    initiator_receipt_digest TEXT NOT NULL,
    source_state_version INTEGER NOT NULL CHECK (source_state_version >= 0),
    report_json TEXT NOT NULL
)
```

Add a loader test that changes `report_json` without updating its digest and
expects closed validation.

- [ ] **Step 2: Run RED**

Run:

```bash
./.venv/bin/python -m pytest \
  tests/test_acceptance.py::test_ledger_schema_includes_composition_reports \
  tests/test_acceptance.py::test_composition_report_loader_rejects_tampered_json -q
```

Expected: both FAIL because the table and loader do not exist.

- [ ] **Step 3: Add schema and bounded loader**

Add the SQL statement to the authoritative schema tuple and include
`composition_reports` in every exact table-set check. Implement
`_validated_composition_reports(connection: sqlite3.Connection, work_order:
WorkOrder) -> tuple[CompositionReport, ...]` in `evidence.py`.

Use a hard cap equal to the maximum number of `proof_composed` receipts,
canonical JSON equality, report-model validation, raw-byte digest recompute,
WorkOrder binding, initiator ID/digest lookup, and one-to-one report/trigger
closure.

- [ ] **Step 4: Write RED compose transaction success test**

Build a current `AuthorizationContext` ending in `locally_verified`, a signed
Manager `owp.compose_proof` AgentRequest, and a Sidecar key. Assert one call to:

```python
result = compose_proof_transaction(
    ledger_path,
    evidence_root=evidence_root,
    context=context,
    request=compose_request,
    sidecar_private_key=sidecar_private_key,
    clock=lambda: fixed_now,
)
```

returns `CompositionTransactionResult` containing a Manager ToolCallReceipt,
CompositionReport, and Sidecar SystemEventReceipt; a fresh read must show the
two new sequences, one report row, one quota event, and `proof_ready`.

- [ ] **Step 5: Run RED**

Expected: FAIL because `compose_proof_transaction` is undefined.

- [ ] **Step 6: Implement compose construction and one transaction**

Define this result object:

```python
@dataclass(frozen=True, slots=True)
class CompositionTransactionResult:
    initiator_receipt: ToolCallReceipt
    report: CompositionReport
    trigger_receipt: SystemEventReceipt
```

Implement `compose_proof_transaction(ledger_path: Path, *, evidence_root:
Path, context: AuthorizationContext, request: AgentRequest,
sidecar_private_key: Ed25519PrivateKey, clock: Callable[[], datetime]) ->
CompositionTransactionResult`.

Inside the target lock:

1. freeze a trusted UTC second;
2. call `require_current_context`;
3. require Manager, `owp.compose_proof`, current state, Grant, nonce, quota, and
   exact `previous_report_digest` rules;
4. build sequence N Manager ToolCallReceipt, charging one `tool_calls` unit;
5. derive a report over the prefix including that receipt;
6. build sequence N+1 `proof_composed` SystemEventReceipt;
7. in one `BEGIN IMMEDIATE`, re-read state/version/sequence, insert the two
   receipts and parent edges, quota event, report row, and final state/version;
8. classify COMMIT truth by exact readback.

Do not call `complete_receipt_publication`: CompositionReport is ledger-backed
and the compose operation publishes no new WorkOrder evidence artifact.

- [ ] **Step 7: Add failure injection and incomplete tests**

Inject failures after initiator insert, report insert, trigger insert, quota
insert, state update, before COMMIT, and at COMMIT acknowledgement. Before
COMMIT, every table snapshot must be unchanged. Unknown acknowledgement must
return the exact committed result only when full readback matches.

From `locally_verified`, missing independent evidence must commit a report and
transition to `evidence_incomplete`. Recomposition that remains incomplete
must perform no same-state write.

- [ ] **Step 8: Run composition GREEN**

Run:

```bash
./.venv/bin/python -m pytest \
  tests/test_acceptance.py \
  tests/test_receipt_chain.py \
  tests/test_mcp_server.py -q
```

Expected: PASS.

- [ ] **Step 9: Commit deterministic proof composition**

Run:

```bash
git add \
  src/openworkproof/runtime_context.py \
  src/openworkproof/mcp_server.py \
  src/openworkproof/models.py \
  src/openworkproof/evidence.py \
  src/openworkproof/acceptance.py \
  tests/test_mcp_server.py \
  tests/test_acceptance.py \
  tests/test_receipt_chain.py
git diff --cached --check
git commit -m "feat: commit deterministic proof composition"
```

## Task 7: Commit the Final-Acceptance Request

**Files:**

- Modify: `src/openworkproof/acceptance.py`
- Modify: `tests/test_acceptance.py`

- [ ] **Step 1: Write RED request transaction test**

From a freshly committed `proof_ready` result, construct a Manager AgentRequest
for `owp.request_acceptance` whose exact arguments are:

```python
{
    "request_kind": "final_acceptance",
    "target_action_digest": target_action_digest,
    "required_role": "Acceptor",
    "requested_scope": {
        "work_order_digest": work_order.digest,
        "operation": "submit_final_acceptance",
        "composition_report_digest": report_digest,
    },
    "expires_at": request_expiry,
}
```

Call `request_acceptance_transaction` and assert an
ApprovalRequestedReceipt, one quota decrement, one new sequence, and atomic
`proof_ready -> awaiting_human`.

- [ ] **Step 2: Run RED**

Expected: FAIL because the function does not exist.

- [ ] **Step 3: Implement the request transaction**

Implement `request_acceptance_transaction(ledger_path: Path, *, evidence_root:
Path, context: AuthorizationContext, request: AgentRequest,
sidecar_private_key: Ed25519PrivateKey, expires_at: datetime, clock:
Callable[[], datetime]) -> ApprovalRequestedReceipt`.

Revalidate current context, exact report row/trigger closure, Manager role,
Grant, nonce, quota, request digest, target-action digest, expiry <= now + 3600
seconds, and expiry <= WorkOrder deadline. Build the Sidecar-signed receipt and
atomically insert receipt, parents, quota event, sequence, state, and version.

- [ ] **Step 4: Add zero-write negative tests**

Cover evidence-incomplete, old report digest, wrong role, wrong Manager key,
missing capability, exhausted quota, duplicate nonce, past expiry, >1-hour
expiry, and deadline overflow. Snapshot all authoritative tables before each
call and require exact equality after failure.

- [ ] **Step 5: Add request COMMIT-truth tests**

Inject pre-COMMIT and COMMIT-ACK failures. Exact committed readback may return
the existing receipt; mismatched or ambiguous readback returns
`RECOVERY_REQUIRED` and never retries with a new receipt ID.

- [ ] **Step 6: Run request GREEN**

Run:

```bash
./.venv/bin/python -m pytest tests/test_acceptance.py -q
```

Expected: PASS.

## Task 8: Prepare the External Acceptor Signing Draft

**Files:**

- Modify: `src/openworkproof/acceptance.py`
- Modify: `tests/test_acceptance.py`

- [ ] **Step 1: Write RED deterministic draft test**

Call `prepare_acceptance` twice against the same awaiting-human snapshot and
same trusted UTC second. Assert byte-identical canonical payload, the exact
domain, and deterministic acceptance ID.

- [ ] **Step 2: Run RED**

Expected: FAIL because `prepare_acceptance` is undefined.

- [ ] **Step 3: Implement the keyless draft**

Define:

```python
@dataclass(frozen=True, slots=True)
class AcceptanceSigningDraft:
    signing_domain: Literal["acceptance-receipt"]
    acceptance_id: str
    payload: FrozenDict
    canonical_payload: bytes
```

Implement `prepare_acceptance(ledger_path: Path, *, evidence_root: Path,
context: AuthorizationContext, clock: Callable[[], datetime]) ->
AcceptanceSigningDraft`.

The function must not accept any private key. Under the target lock it must
revalidate context, state, report, trigger, request, expiry, report bytes,
receipt prefix, evidence bytes, final artifact, independence, postconditions,
and warnings. Build the payload by copying authoritative report fields and
extending receipt digests through the request. Compute acceptance ID from the
exact design projection and serialize with RFC 8785 JCS.

- [ ] **Step 4: Add draft boundary tests**

Use `inspect.signature` to prove no private-key parameter exists. Cover expired
request, stale report row, changed evidence byte, changed replay checkpoint,
wrong state, and an existing acceptance row. Each must fail without writing.

- [ ] **Step 5: Run draft GREEN**

Run:

```bash
./.venv/bin/python -m pytest tests/test_acceptance.py -q
```

Expected: PASS.

## Task 9: Commit the Acceptor-Signed AcceptanceReceipt

**Files:**

- Modify: `src/openworkproof/acceptance.py`
- Modify: `src/openworkproof/evidence.py`
- Modify: `tests/test_acceptance.py`
- Modify: `tests/test_state.py`
- Modify: `tests/test_receipt_chain.py`

- [ ] **Step 1: Write RED success test**

Sign `draft.payload` outside the Sidecar boundary:

```python
signed = AcceptanceReceipt.model_validate(
    sign_payload(
        draft.signing_domain,
        dict(draft.payload),
        ephemeral_role_keys["Acceptor"][0],
    )
)
committed = commit_acceptance(
    ledger_path,
    evidence_root=evidence_root,
    context=awaiting_context,
    acceptance=signed,
    public_keys=public_keys,
    clock=lambda: fixed_now,
)
assert committed == signed
```

Fresh readback must show one AcceptanceReceipt and `accepted`; receipt
sequence remains unchanged and protocol transaction version increases by one.

- [ ] **Step 2: Run RED**

Expected: FAIL because `commit_acceptance` is undefined and acceptance-suffix
validation currently rejects every stored acceptance.

- [ ] **Step 3: Implement bounded acceptance-suffix validation**

Replace the current `Acceptance ledger suffix validation is unavailable`
branch with exact validation of one AcceptanceReceipt against:

- WorkOrder and Acceptor key;
- current final-acceptance request ID/digest;
- current report digest and canonical report fields;
- authoritative receipt prefix through the request;
- accepted state and derived version;
- absence of later ActionReceipts.

Keep `MAX_ACCEPTANCE_RECEIPTS = 1` and the WorkOrder unique constraint.

- [ ] **Step 4: Implement commit_acceptance**

Implement `commit_acceptance(ledger_path: Path, *, evidence_root: Path,
context: AuthorizationContext, acceptance: AcceptanceReceipt, public_keys:
Mapping[str, Ed25519PublicKey], clock: Callable[[], datetime]) ->
AcceptanceReceipt`.

Under the target lock, reconstruct the draft using `acceptance.accepted_at`,
require exact unsigned-field equality, verify digest/signature with only the
bound Acceptor key, require `request.occurred_at <= accepted_at <= now`,
`now - accepted_at <= 300 seconds`, and accepted_at <= request expiry and
WorkOrder deadline. In one `BEGIN IMMEDIATE`, insert the receipt and update
state/version. Do not advance `sequence_counter`.

- [ ] **Step 5: Add signer, stale, duplicate, and concurrency tests**

Cover all five non-Acceptor keys, a valid but unbound key, modified report
field, modified receipt vector, accepted_at before request, future accepted_at,
301-second-old accepted_at, expired request, changed evidence, changed
checkpoint, duplicate acceptance, and two concurrent identical submissions.
Exactly one concurrent call may perform the insert; the other may return the
same committed receipt only after exact readback.

- [ ] **Step 6: Add COMMIT fault tests**

Inject failure before insert, after insert, after state update, at COMMIT, and
after COMMIT acknowledgement. Pre-COMMIT snapshots remain exact. Unknown
acknowledgement reads back accepted state, version, and exact receipt before
classifying committed truth.

- [ ] **Step 7: Add offline verification test**

Copy WorkOrder, canonical report bytes, ActionReceipts, committed evidence
bytes, AcceptanceReceipt, and six bound public keys into an isolated temporary
directory. Without the live ledger connection, reparse, rehash, replay, and
verify the Acceptor signature and every AcceptanceReceipt/report binding.

- [ ] **Step 8: Run acceptance GREEN**

Run:

```bash
./.venv/bin/python -m pytest \
  tests/test_acceptance.py \
  tests/test_state.py \
  tests/test_receipt_chain.py \
  tests/test_mcp_server.py -q
```

Expected: PASS.

- [ ] **Step 9: Commit independent acceptance**

Run:

```bash
git add \
  src/openworkproof/acceptance.py \
  src/openworkproof/evidence.py \
  tests/test_acceptance.py \
  tests/test_state.py \
  tests/test_receipt_chain.py
git diff --cached --check
git commit -m "feat: commit independent acceptance"
```

## Task 10: Run Full Verification and Refresh Status Documents

**Files:**

- Modify: `README.md`
- Modify: `docs/status.md`

- [ ] **Step 1: Run focused protocol suites**

Run:

```bash
./.venv/bin/python -m pytest \
  tests/test_acceptance.py \
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

The frozen required-live execution candidate for this branch is the existing
repository-qualified RepoDigest below. Verify it directly; do not invent or
retag an image:

```bash
export OPENWORKPROOF_DOCKER_TEST_IMAGE='docker.io/openworkproof/execution-test@sha256:677cfa55596a640cc5a3c6988a878d88da133fc59d7ab3a08ea72a1ad2ddb8ca'
docker image inspect "$OPENWORKPROOF_DOCKER_TEST_IMAGE" >/dev/null
```

Expected: exit 0. If inspect fails, stop rather than replacing the immutable
reference.

- [ ] **Step 3: Run full required-live verification**

Run with the exact existing artifact root:

```bash
OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT=/Users/molin/Project/openWorkProof-day0 \
OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1 \
OPENWORKPROOF_DOCKER_TEST_IMAGE="$OPENWORKPROOF_DOCKER_TEST_IMAGE" \
./.venv/bin/python -m pytest -q
```

Expected: zero failures and zero required-live skips. Record exact count and
elapsed time.

- [ ] **Step 4: Run non-test verification**

Run:

```bash
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests supply-chain/images
git diff --check
```

Require zero owned OpenWorkProof containers and volumes after the suite.

- [ ] **Step 5: Update only observed project facts**

In README and `docs/status.md`:

- add the independent generic Acceptor role;
- add CompositionReport and the successful Acceptance transaction;
- replace stale test counts with the exact fresh counts from this task;
- keep explicit boundaries for rejection, real Acceptor identity, CLI/MCP,
  Rich demo, registry, clean-cache, final helper, D8, Day 0, contest delivery,
  and external acceptance.

Do not write “独立验收完成”; local synthetic Acceptor tests are not external
human acceptance.

- [ ] **Step 6: Verify documentation truth and commit**

Run:

```bash
rg -n -F '龙胜海' README.md docs && exit 1 || true
git diff --check
git add README.md docs/status.md
git diff --cached --check
git commit -m "docs: refresh verified project status"
```

Expected: no real-person Acceptor name and one documentation-only commit.

## Task 11: Completion Checkpoint

**Files:** none

- [ ] **Step 1: Record exact evidence**

Record:

- branch and four implementation commit SHAs;
- focused and full required-live counts/times;
- schema file and registry hashes;
- one successful compose/request/prepare/commit object chain;
- stale-signature, wrong-signer, duplicate, concurrency, and COMMIT-ACK results;
- pip, compileall, diff, and Docker cleanup results;
- clean worktree status.

- [ ] **Step 2: Keep external states separate**

Explicitly retain as unproven:

- real Acceptor assignment and signing;
- Acceptor rejection transaction;
- independent external environment reproduction;
- registry publication and clean-cache reacquisition;
- final trusted helper, D8, Day 0, Rich demo, contest submission, award, and
  commercial validation.

- [ ] **Step 3: Finish the branch**

Invoke `finishing-a-development-branch`, rerun the required final verification
it specifies, and present the standard integration choices. Do not merge or
push without the user's explicit selection.
