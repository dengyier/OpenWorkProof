# OpenWorkProof Acceptor Rejection Design

Date: 2026-08-07

Status: Draft design

Target branch: `codex/acceptor-rejection`

## 1. Objective

Close the missing rejection path of the final human-acceptance transaction:

```text
proof_ready
  -> Manager requests final acceptance (awaiting_human)
  -> Acceptor inspects the complete evidence chain
  -> Acceptor either accepts  -> accepted   (existing commit_acceptance)
  -> or Acceptor rejects      -> rejected   (this slice)
```

Today the state machine already allows `awaiting_human -> rejected`
(`ALLOWED_TRANSITIONS`), but no transaction, receipt type, replay rule, or
schema entry produces that terminal state. A human acceptance gate that can
only say "yes" is not a gate. This slice makes the rejection terminal state
reachable, signed by the same bound Acceptor authority, and verifiable
offline by a third party without access to any party's system.

## 2. Approved Decisions

- **D1:** Introduce a dedicated `AcceptanceRejectionReceipt` protocol object.
  The existing `AcceptanceReceipt` keeps its strict `decision: "accepted"`
  semantics, its closed-coverage validator, and its `accepted` schema entry
  unchanged. Rejection is a separate signed receipt type, not a widened
  literal on the acceptance receipt.
- **D2:** Rejection is signed by the same WorkOrder-bound Acceptor key that
  signs acceptance. No seventh role is added.
- **D3:** A rejection binds the current acceptance request, the current
  CompositionReport, and the exact evidence snapshot at rejection time. A
  rejection cannot be authored against a stale request, a missing report, or
  a mismatched evidence root.
- **D4:** Rejection is terminal and mutually exclusive with acceptance: from
  one `awaiting_human` request tip, either exactly one accepted receipt or
  exactly one rejected receipt commits. Once rejected, no further acceptance
  or rejection may commit.
- **D5:** Rejection reasons are closed literal codes, not free text:
  `EVIDENCE_INSUFFICIENT`, `INDEPENDENCE_UNSATISFIED`,
  `GLOBAL_POSTCONDITION_FAILED`, `BUSINESS_DECISION`. A short human-readable
  detail string is allowed alongside the code.
- **D6:** The rejection path reuses the existing atomic-transaction pattern
  (`BEGIN IMMEDIATE`, COMMIT, exact readback) and the existing
  `request_acceptance_transaction` request tip as its input. It does not add
  a second request tool or a new state.
- **D7:** A `prepare_acceptance_rejection` draft helper is out of scope for
  this slice. The Acceptor signs the complete rejection object directly, as
  `commit_acceptance` does today. Draft-preparation symmetry can be added in
  a later slice without a protocol change.

## 3. Current-State Constraints

The repository already provides:

- the `awaiting_human` protocol state and `awaiting_human -> rejected` in
  `ALLOWED_TRANSITIONS`;
- `request_acceptance_transaction`, `prepare_acceptance`, and
  `commit_acceptance` atomic transactions with COMMIT-ACK exact readback;
- `_readback_acceptance_committed` and the acceptance-suffix validation in
  the receipt prefix validator;
- `_validated_acceptance_receipts` reading `acceptance_receipts` rows and
  verifying the Acceptor signature;
- a six-role WorkOrder with the Acceptor key independent of Maintainer;
- offline verification via `verify_acceptance_bundle`;
- a v0.1 schema registry generated from the models.

The slice must not redesign the frozen causal/policy replay rules without a
failing test that proves an inconsistency.

## 4. Protocol Design

### 4.1 AcceptanceRejectionReceipt model

A new `SignedProtocolModel` with fields:

| field | type | notes |
|---|---|---|
| `protocol_version` | `"0.1"` | frozen |
| `rejection_id` | `Digest64` | unique, derived from signed payload |
| `work_order_digest` | `Digest64` | binds the WorkOrder |
| `acceptance_request_receipt_id` | `Digest64` | the exact request receipt |
| `acceptance_request_receipt_digest` | `Digest64` | request digest binding |
| `composition_report_digest` | `Digest64` | the report under review |
| `evidence_snapshot_digest` | `Digest64` | exact evidence snapshot |
| `receipt_digests` | `tuple[Digest64, ...]` | signed prefix digests |
| `causal_graph_root` | `Digest64` | causal root of the prefix |
| `reason_code` | `Literal[4 codes]` | closed reason vocabulary |
| `reason_detail` | `str` | short human-readable text |
| `decision` | `Literal["rejected"]` | fixed |
| `rejected_at` | `CanonicalUTCTime` | signing time |

Model validators enforce:

- `reason_code` in the closed set, `reason_detail` length bound;
- `rejected_at` bounds and ordering vs the request `occurred_at`;
- prefix digest/causal-root consistency with the bound request tip;
- `decision` is exactly `"rejected"`.

### 4.2 Storage

A new ledger table `acceptance_rejection_receipts` mirrors the
`acceptance_receipts` shape:

```sql
CREATE TABLE acceptance_rejection_receipts (
    rejection_id TEXT PRIMARY KEY,
    work_order_digest TEXT NOT NULL REFERENCES work_orders(work_order_digest),
    acceptance_request_receipt_id TEXT NOT NULL UNIQUE
        REFERENCES receipts(receipt_id),
    receipt_json TEXT NOT NULL
);
```

The `UNIQUE` on `acceptance_request_receipt_id` enforces D4 at the storage
layer (one rejection per request). The existing `acceptance_receipts`
`UNIQUE (acceptance_id)` and request binding enforce the accepted side; a
cross-table check in the transaction prevents one request from producing both
an accepted and a rejected receipt.

### 4.3 Reject transaction

`reject_acceptance_transaction(ledger_path, *, evidence_root, context,
rejection, clock)`:

1. Acquire the target lock, freeze the trusted UTC second, require the
   current context (`require_current_context`), and require
   `current_state == "awaiting_human"`.
2. Load the current report, the current acceptance request, and verify:
   - the request has not expired;
   - the request is the current ledger tip;
   - the rejection is signed by the WorkOrder-bound Acceptor key;
   - the rejection re-validates against the WorkOrder and the exact
     evidence prefix (report digest, evidence snapshot, receipt digests,
     causal root);
   - `rejected_at` is within `[request.occurred_at, now]`, within 300s of
     `now`, and within `request.expires_at` and the WorkOrder deadline.
3. Verify no accepted receipt already exists for this request and no
   rejection already exists (D4).
4. Inside one `BEGIN IMMEDIATE`: insert the rejection row, the state
   transition `awaiting_human -> rejected`, the version bump, and the
   sequence update.
5. On COMMIT-ACK loss, reopen the ledger and prove the exact rejection row,
   the rejected state, and the version; raise
   `AcceptanceCommittedError(committed=rejection)` or
   `AcceptanceCommitIndeterminateError` exactly as the acceptance path does.
   A proven commit never becomes uncommitted because connection close, lock
   release, or cleanup failed.

### 4.4 Replay and validation

- `_validated_acceptance_receipts` keeps validating accepted receipts.
- A new `_validated_acceptance_rejections` reads and validates rejection
  rows (canonical JSON, WorkOrder binding, Acceptor signature,
  request binding).
- The acceptance suffix check in the receipt-prefix validator accepts a
  terminal state of `accepted` or `rejected` and requires the matching
  receipt class at the tip.
- `state.py` authorizes the rejection receipt type for the same-state
  `awaiting_human -> rejected` transition under the human-gate tail rules.

### 4.5 Offline verification

`verify_acceptance_bundle` gains an optional `rejection` parameter: when
provided, it verifies the copied bundle with the rejection bound one-to-one
to the same request tip that the acceptance would have used, and returns the
rejection. `validate_grant_chain` remains the bounded five-input verifier;
the rejection binding is validated inside the same orchestrated bundle check.

### 4.6 Schema

The v0.1 schema and registry regenerate to include the
`acceptance-rejection-receipt` object with its fields and validator-derived
constraints.

## 5. Reason vocabulary

| code | meaning |
|---|---|
| `EVIDENCE_INSUFFICIENT` | the reviewed report/evidence chain does not close all required dimensions |
| `INDEPENDENCE_UNSATISFIED` | the independence assessment is not satisfied |
| `GLOBAL_POSTCONDITION_FAILED` | a global postcondition fails |
| `BUSINESS_DECISION` | the Acceptor rejects for business reasons despite a closed chain |

`reason_detail` is bounded (<= 1024 chars) and does not carry protocol
meaning; replay never branches on it.

## 6. Verification gates

- Focused protocol suites (acceptance, state, contract, signing, proof
  composition, policy, receipt chain, mcp server, schema registry) must stay
  green with zero failures.
- Full required-live run (Docker required, candidate-inventory bound) must
  reach exit code 0 with zero required-live skips.
- New tests: rejection happy path, mutual exclusion (accept after reject and
  reject after accept both fail), wrong-role signer, stale/future
  `rejected_at`, expired request, stale tip, report/snapshot mismatch,
  COMMIT-ACK loss readback, readback indeterminate, offline rejection bundle
  verification, tamper matrix on rejection rows/evidence/public keys.
- pip check, compileall, and `git diff --check` must pass; zero owned
  OpenWorkProof containers and volumes after the suite.

## 7. Boundaries (explicitly out of scope)

- Real external Acceptor identity and signing ceremony.
- `prepare_acceptance_rejection` draft helper (D7).
- Maintainer `termination` and `FROZEN -> rejected` paths (separate slice).
- CLI/MCP transmission of the rejection transaction.
- delivery signoff human signing and contest delivery.
