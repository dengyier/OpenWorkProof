# OpenWorkProof Independent Acceptor and Acceptance Transaction Design

Date: 2026-08-06

Status: Approved design

Target branch: `codex/acceptance-transaction`

## 1. Objective

Close the first production-grade strong-acceptance path:

```text
committed work evidence
  -> deterministic proof composition
  -> proof_ready
  -> Manager requests final acceptance
  -> awaiting_human
  -> independent Acceptor signs the exact authoritative snapshot
  -> atomic AcceptanceReceipt commit
  -> accepted
```

The implementation must preserve OpenWorkProof's central boundary: a result is
not accepted merely because an Agent, test runner, Manager, or Sidecar says it
is complete. Acceptance requires a separately keyed human Acceptor and an
authoritative, reproducible proof snapshot.

## 2. Current-State Constraints

The current repository already provides:

- signed WorkOrder, CapabilityGrant, ActionReceipt, and AcceptanceReceipt
  models;
- an authoritative SQLite ledger and target lock;
- causal and policy replay;
- immutable evidence staging, no-replace publication, committed-evidence
  gates, and crash recovery;
- pure state-transition validation;
- a `proof_composed` SystemEventReceipt shape;
- a final-acceptance ApprovalRequestedReceipt shape;
- a strong-success-only AcceptanceReceipt model.

The current implementation does not provide:

- a protocol-level Acceptor distinct from Maintainer;
- a rehashable CompositionReport preimage;
- a production proof-composition transaction;
- a production final-acceptance request transaction;
- an external-signing draft boundary;
- an atomic AcceptanceReceipt commit transaction.

The current v0.1 development model incorrectly requires the Maintainer to be
the sole issuer, signer, and acceptor. This design intentionally corrects that
development-time trust model before a production acceptance transaction is
added.

## 3. Scope

This slice includes:

1. an explicit sixth `Acceptor` role with a distinct key;
2. a development-time v0.1 model and schema update;
3. a deterministic CompositionReport model and ledger representation;
4. an atomic proof-composition transaction;
5. an atomic final-acceptance request transaction;
6. a read-only acceptance signing-draft operation;
7. an atomic AcceptanceReceipt commit transaction;
8. crash, stale-snapshot, duplicate, and concurrency coverage;
9. accurate README and status-document updates after verification.

## 4. Out of Scope

This slice does not add:

- a real person's name or production Acceptor credential;
- an Acceptor rejection receipt or rejection terminal transaction;
- CLI, MCP transport, AgentTeams, or a long-lived service;
- Rich #4196 end-to-end demo wiring;
- new tool handlers or Developer-mode execution;
- registry publication, clean-cache reacquisition, final-helper, D8, Day 0,
  contest-delivery, external-acceptance, or commercial-validation claims.

Invalid, incomplete, stale, expired, or incorrectly signed acceptance attempts
fail closed and do not change protocol state. A separately signed Acceptor
rejection path is the next independent terminal-state slice.

## 5. Trust and Role Model

### 5.1 Role Set

The ordered WorkOrder key bindings become:

1. `Maintainer`
2. `Manager`
3. `Developer`
4. `Verifier`
5. `Sidecar`
6. `Acceptor`

The order remains normative so existing constant-time role lookup patterns stay
simple and deterministic.

### 5.2 Identity Rules

- The Maintainer remains the sole WorkOrder issuer and WorkOrder signer.
- `acceptor_key_ids` must contain exactly the sixth binding's Acceptor key ID.
- All six subject IDs and key IDs must be unique.
- The Acceptor key must therefore differ from the Maintainer, Manager,
  Developer, Verifier, and Sidecar keys.
- The local development subject identifier is generic, such as
  `acceptor-local`; no real person is named or implied.
- The Acceptor receives no CapabilityGrant and no tool execution authority.
- Only the bound Acceptor key may sign an AcceptanceReceipt.

### 5.3 Development Compatibility Boundary

The project remains marked `0.1.0 (development)`. This is an intentional,
incompatible update to the unreleased v0.1 schema anchors.

Existing five-role development ledgers are not silently migrated into the new
trust model. They fail closed when loaded by the new code. No production data
migration is claimed or implemented in this slice.

## 6. Protocol Model Changes

### 6.1 KeyBinding and WorkOrder

`KeyBinding.role` adds `Acceptor`. WorkOrder validation requires the exact
six-role order and the identity rules in section 5.

The WorkOrder signer remains the Maintainer. The Acceptor is bound by the
signed WorkOrder but does not co-sign it.

### 6.2 Final Acceptance Request

`ApprovalRequestedReceipt.required_role` supports a closed role matrix:

- `high_risk_action` requires `Maintainer`;
- `final_acceptance` requires `Acceptor`.

The existing final-acceptance scope remains closed to:

```json
{
  "work_order_digest": "...",
  "operation": "submit_final_acceptance",
  "composition_report_digest": "..."
}
```

The target action digest remains derived from the canonical scope and the
existing final-acceptance domain.

### 6.3 AcceptanceReceipt

AcceptanceReceipt remains a strong-success-only object. Its signer must be the
WorkOrder's Acceptor binding. Validation must not fall back to Maintainer or an
externally supplied unbound public key.

The transaction layer adds stronger cross-object rules than the standalone
model can enforce:

- the referenced acceptance request exists, is current, and is unexpired;
- the request requires the bound Acceptor;
- the referenced CompositionReport exists and is the current proof-ready
  report;
- every duplicated report field matches the report exactly;
- the receipt-digest vector matches the authoritative history through the
  acceptance request;
- `accepted_at` is not before the request, is not in the future, is no more
  than 300 seconds older than the trusted commit time, and is not after request
  expiry or WorkOrder deadline.

### 6.4 Schema Registry

Regenerate the four v0.1 schemas and update the frozen registry digests only
from the changed model authority. Generated schemas remain canonical JCS and
the registry remains closed to the same four public object types.

CompositionReport and the internal signing draft are not added to the public
four-object protocol registry in this slice. CompositionReport is a canonical
ledger artifact whose digest is referenced by public receipts.

## 7. CompositionReport

### 7.1 Purpose

CompositionReport is the deterministic preimage behind
`composition_report_digest`. It prevents callers from passing an opaque digest
that the Sidecar cannot independently reproduce.

### 7.2 Fields

The closed report contains:

- `schema_version = openworkproof-composition-report/0.1`;
- `work_order_digest`;
- `initiator_receipt_id` and `initiator_receipt_digest`;
- `final_artifact`;
- sorted `artifact_digests`;
- `evidence_snapshot_digest`;
- an ordered, unique `receipt_digests` vector for the covered prefix;
- `causal_graph_root` and `causal_complete`;
- closed `evidence_coverage`;
- `independence_assessment`;
- sorted `test_evidence_refs`;
- sorted `unresolved_failures` and `warnings`;
- ordered `global_postconditions` and a derived satisfaction boolean;
- `verifier_conclusion`, either `proof_ready` or `evidence_incomplete`;
- trusted `composed_at` at UTC-second precision.

All arrays use explicit byte-order or protocol-order rules and reject
duplicates. No field accepts free-form diagnostic text.

### 7.3 Digest

`composition_report_digest` is the lowercase SHA-256 digest of the exact RFC
8785 JCS report bytes. The schema-version field provides the domain boundary.

The derived aggregate digests use these closed projections:

- `causal_graph_root` is SHA-256 over RFC 8785 JCS bytes containing domain
  `openworkproof/causal-graph-root/0.1` and an authoritative sequence-ordered
  node vector. Each node contains only its receipt ID, receipt digest, and
  exact parent receipt IDs.
- `evidence_snapshot_digest` is SHA-256 over RFC 8785 JCS bytes containing
  domain `openworkproof/evidence-snapshot/0.1` and a path-byte-sorted vector of
  the exact committed EvidenceRefs after every referenced payload has been
  rehashed.

These formulas are not configurable. The implementation exposes pure helpers
so offline verification and transaction construction use the same authority.

### 7.4 Covered Receipt Prefix

The report covers the authoritative ActionReceipt prefix ending at
`initiator_receipt_id`. It does not include the `proof_composed` receipt that
references the report, avoiding a digest cycle.

The later AcceptanceReceipt receipt vector covers the authoritative history
through the final ApprovalRequestedReceipt. It therefore contains the report's
covered prefix plus the `proof_composed` and final-acceptance request receipts.
The transaction validates this extension exactly.

## 8. Ledger Changes

Add a `composition_reports` table containing at minimum:

- report digest primary key;
- WorkOrder digest;
- initiator receipt ID and digest;
- canonical report JSON;
- the state version from which it was derived.

The existing `acceptance_receipts` table remains the AcceptanceReceipt
authority. Add or retain constraints sufficient to ensure at most one
AcceptanceReceipt per WorkOrder.

All new rows are loaded through bounded queries, canonical JSON parsing,
model validation, digest recomputation, WorkOrder binding, and cross-reference
validation. Raw database strings are never trusted as verified models.

## 9. Transaction 1: Proof Composition

The proof-composition transaction accepts a signed Manager AgentRequest for
`owp.compose_proof` and runs under the target lock and one `BEGIN IMMEDIATE`
transaction.

It must:

1. recover or reject incomplete evidence publications;
2. load and verify the authoritative WorkOrder, receipt history, grants,
   attempts, state, version, and sequence;
3. require the current state to be `locally_verified` or an allowed
   `evidence_incomplete` recomposition state;
4. validate and build the quota-charged Manager `owp.compose_proof`
   ToolCallReceipt as the composition initiator;
5. read and rehash every referenced committed evidence byte through the
   anchored evidence APIs;
6. replay causal and policy history including the initiator Receipt;
7. derive the final artifact, evidence coverage, independence assessment,
   diagnostics, and global postconditions;
8. construct and revalidate canonical CompositionReport bytes whose covered
   prefix ends at the initiator Receipt;
9. insert the report;
10. construct and sign the Sidecar `proof_composed` SystemEventReceipt whose
    cause binds the initiator digest and report digest;
11. insert both Receipts, both parent-edge sets, the Manager quota event, both
    sequence values, final state, and derived version atomically.

If the report is complete, the state becomes `proof_ready`. From
`locally_verified`, an incomplete report may move the state to
`evidence_incomplete`. Recomposition that remains incomplete performs no
same-state protocol write and returns a closed not-ready result.

The Manager initiator Receipt, report row, and proof-composed Receipt must
never be observable separately.

## 10. Transaction 2: Final Acceptance Request

The request transaction accepts a signed Manager AgentRequest and trusted
transaction time. It runs under the target lock and must:

1. load and replay the current authoritative context;
2. require `proof_ready` and the current CompositionReport;
3. verify request integrity, Manager role, Grant capability, quota, nonce,
   freshness, report digest, and expiry;
4. require `required_role = Acceptor`;
5. create the Sidecar-signed ApprovalRequestedReceipt;
6. atomically insert the receipt, parent edges, quota event, sequence, state
   version, and `awaiting_human` state.

The request expiry must be no later than both one hour after request time and
the WorkOrder deadline. This slice does not add request refresh; callers must
request acceptance within an interval that permits human review.

## 11. Read-Only Operation: Prepare Acceptance

`prepare_acceptance` runs under the target lock but does not write protocol
state. It must:

1. require `awaiting_human`;
2. load the unique current final-acceptance request and CompositionReport;
3. require the request to be unexpired;
4. re-read and rehash the report's complete evidence snapshot;
5. replay the authoritative receipt history through the request;
6. derive `acceptance_id` as SHA-256 over RFC 8785 JCS bytes containing domain
   `openworkproof/acceptance-id/0.1`, WorkOrder digest, request receipt ID and
   digest, CompositionReport digest, and evidence-snapshot digest;
7. construct the exact unsigned AcceptanceReceipt payload;
8. return canonical signing bytes and the `acceptance-receipt` signing domain.

The Acceptor private key is never an input. The returned draft contains no
credential, secret, or mutable callback.

`accepted_at` is frozen from the trusted preparation clock and included in the
signed payload. It uses UTC-second precision.

## 12. Transaction 3: Commit Acceptance

`commit_acceptance` accepts a fully signed AcceptanceReceipt, public keys,
trusted current time, ledger path, and evidence root. It does not accept a
caller-supplied CompositionReport or evidence summary.

Under the target lock it must:

1. load state, version, report, request, history, and committed evidence;
2. require `awaiting_human`, an unexpired request, and no existing acceptance;
3. reconstruct the expected acceptance payload using the receipt's
   `accepted_at` as the frozen signing time;
4. require exact field equality with the reconstructed payload;
5. verify the receipt digest and the bound Acceptor signature;
6. re-run standalone model, WorkOrder, state-transition, causal, policy,
   evidence, independence, and postcondition validation;
7. insert the AcceptanceReceipt and atomically update state to `accepted` and
   increment the protocol transaction version.

No ActionReceipt sequence is invented for AcceptanceReceipt. The existing
version derivation includes acceptance rows and must be rechecked after commit.

## 13. Commit Truth and Recovery

Every mutating operation distinguishes:

- pre-COMMIT failure: rollback is authoritative and no state change occurred;
- COMMIT acknowledged: committed truth;
- COMMIT acknowledgement unknown: read back under the target lock before
  classifying the result.

If readback proves the exact report, request, or acceptance was committed, the
operation returns or raises a committed-truth result that exposes the canonical
stored object. It must not retry the semantic operation.

If readback cannot establish either rollback or exact commit, return
`RECOVERY_REQUIRED`. Never create a second report, request, acceptance ID,
signature request, or AcceptanceReceipt to conceal uncertainty.

Cleanup and close failures are reported independently and never rewrite an
already committed protocol fact as uncommitted.

## 14. Failure Semantics

Closed errors include, at minimum:

- invalid six-role WorkOrder identity bindings;
- unsupported five-role development snapshot;
- composition state not eligible;
- evidence publication not committed;
- evidence bytes, manifest, Receipt, or report digest mismatch;
- causal, policy, independence, or global-postcondition failure;
- final acceptance requested before `proof_ready`;
- request report digest is not current;
- request expired or outside the WorkOrder deadline;
- signer is not the WorkOrder's Acceptor;
- stale acceptance payload;
- duplicate or concurrent acceptance;
- commit truth indeterminate.

All failures before a proven commit leave quota, state, version, sequence,
report, request, and acceptance tables unchanged.

## 15. Concurrency Rules

- All three mutating operations use the existing per-target lock.
- SQLite uses `BEGIN IMMEDIATE` for the authoritative write interval.
- The expected state and version are re-read inside the transaction.
- A WorkOrder has at most one current proof-ready report, one current
  final-acceptance request, and one AcceptanceReceipt.
- Concurrent duplicate requests or acceptances have one winner; losers read
  back and return the committed winner only if it is byte-identical.
- A stale but valid Acceptor signature cannot win after any authoritative
  prefix or evidence snapshot change.

## 16. Test Strategy

Implementation follows strict RED-GREEN-REFACTOR cycles. Each behavior starts
with one focused failing test whose expected failure is observed before
production code changes.

### 16.1 Contract and Schema Tests

- exact six-role order and uniqueness;
- Acceptor distinct from Maintainer;
- Maintainer remains WorkOrder signer;
- final acceptance requires Acceptor while high-risk approval still requires
  Maintainer;
- AcceptanceReceipt rejects every non-Acceptor signer;
- generated v0.1 schemas and registry anchors match model authority.

### 16.2 Composition Tests

- deterministic report bytes and digest under input reordering;
- exact receipt-prefix and initiator binding;
- byte-level evidence rehash;
- final commit and WorkspaceManifest binding;
- complete and incomplete conclusions;
- independence and warning recomputation;
- tampered evidence, Receipt, report row, or database cross-reference fails
  closed;
- report and proof-composed receipt are atomic under injected failures.

### 16.3 Request Tests

- Manager-only request after proof-ready;
- exact Acceptor role and report scope;
- quota, nonce, sequence, state, and version atomicity;
- incomplete, stale, expired, duplicate, and unauthorized requests produce no
  protocol write;
- COMMIT and COMMIT-ACK fault classification.

### 16.4 Prepare and Commit Tests

- deterministic unsigned payload;
- no private key input or persisted secret;
- Maintainer, Manager, Developer, Verifier, and Sidecar signatures rejected;
- unbound Acceptor key rejected;
- expired request and stale report rejected;
- post-signing ledger, evidence, commit, or manifest drift rejected;
- exact success transition `awaiting_human -> accepted`;
- acceptance row and state/version update are atomic;
- duplicate and concurrent single-winner behavior;
- COMMIT-ACK loss recovers the exact committed AcceptanceReceipt;
- offline validation from WorkOrder, report, receipts, evidence, and bound
  public keys.

### 16.5 Regression and Live Gates

After focused tests:

- run the complete test suite;
- run required-live Docker gates with the frozen candidate artifact root and
  repository-qualified execution image;
- run `pip check`, compileall, and `git diff --check`;
- require zero owned OpenWorkProof Docker container and volume residue;
- update README and `docs/status.md` with only fresh observed results.

## 17. Implementation Commits

Use four reviewable commits:

1. `feat: separate acceptor authority`
2. `feat: commit deterministic proof composition`
3. `feat: commit independent acceptance`
4. `docs: refresh verified project status`

Each code commit must pass its focused test set before the next begins. The
final documentation commit records actual verification output and retains all
external-state boundaries.

## 18. Completion Criteria

This design is implemented only when:

1. the six-role model and schemas are internally consistent;
2. proof composition produces a canonical rehashable report;
3. Manager compose Receipt, report, proof-composed Receipt, quota, state,
   version, and sequence commit atomically;
4. Manager can atomically request Acceptor review only from proof-ready;
5. preparation returns one exact externally signable payload without key
   custody;
6. only the bound Acceptor can sign the accepted outcome;
7. AcceptanceReceipt and accepted state commit atomically;
8. stale, duplicate, concurrent, and crash-window cases fail closed or recover
   exact committed truth;
9. focused, full, required-live, static, and cleanup gates pass;
10. project status documents report the new local facts without claiming
    independent human acceptance, Day 0, contest submission, or commercial
    validation.
