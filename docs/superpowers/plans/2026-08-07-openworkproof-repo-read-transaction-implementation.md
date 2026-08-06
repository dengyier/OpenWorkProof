# OpenWorkProof RepoRead Production Transaction Implementation

Date: 2026-08-07

Branch: `codex/acceptor-rejection`

Spec: `docs/superpowers/specs/2026-08-07-openworkproof-repo-read-transaction-design.md`

## Execution Rules

- Mirror the `execute_rollback` skeleton exactly (lock, frozen second,
  require_current_context, authorize, handler, complete_receipt_publication
  with empty payloads, finalize, COMMIT-ACK readback).
- No new evidence slot and no v0.1 work-order schema change (R3).
- No production wiring to the trusted-helper image in this slice; the handler
  seam is caller-supplied (R5).
- All atomic transactions follow the existing COMMIT / exact-readback pattern.

## File Map

- Modify: `src/openworkproof/mcp_server.py`
- Modify: `tests/test_mcp_server.py`
- New: `tests/test_repo_read_transaction.py`
- Modify: `README.md`, `docs/status.md`
- Modify: this plan

## Task 1: RED Tests

- [ ] Success path: Developer repo-read commits a receipt with
  `tool_name == "owp.repo_read"`, `evidence_refs == ()`, a bound
  `output_digest` equal to the canonical RepoReadOutput JSON digest, and
  `state_after == context.current_state`; the ledger prefix extends exactly.
- [ ] Wrong-role signer (Manager signs a repo-read request) is rejected before
  any write (table snapshot equality).
- [ ] Path outside the workspace manifest is rejected before any write.
- [ ] Handler returns an over-64-KiB output -> rejected (RECOVERY_REQUIRED or
  refusal) with no committed receipt.
- [ ] COMMIT-ACK loss recovers the exact receipt via readback and raises
  `AcceptanceCommittedError(committed=receipt)`.
- [ ] Readback failure raises `AcceptanceCommitIndeterminateError`.

## Task 2: Implement the Transaction

- [ ] Add `_preflight_repo_read_receipts` validating arguments, path against
  the manifest, and head-commit/manifest binding.
- [ ] Add `_readback_repo_read_committed`.
- [ ] Add `execute_repo_read` per spec 4.1.
- [ ] Add the repo-read request-arguments binding to the shared request-arg
  map if missing.

## Task 3: Offline Rehash Test

- [ ] Copy the committed RepoReadOutput JSON and rehash it; assert it equals
  the receipt `output_digest`.
- [ ] Tamper one byte of the output JSON and assert the rehash no longer
  matches (fail closed).

## Task 4: Verification and Close-Out

- [ ] Run focused suites; run full required-live to exit 0.
- [ ] Update README/status (repo_read handler implemented).
- [ ] pip/compileall/diff checks; zero owned containers/volumes.
- [ ] Record branch state; present integration choices; do not merge or push.
