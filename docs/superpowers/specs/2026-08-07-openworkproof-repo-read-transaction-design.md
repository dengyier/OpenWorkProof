# OpenWorkProof RepoRead Production Transaction Design

Date: 2026-08-07

Status: Draft design

Target branch: `codex/acceptor-rejection` (continues the protocol close-out line)

## 1. Objective

Close the last unhandled ToolCall in the core protocol: `owp.repo_read`.
The protocol layer already knows the tool (model arguments, role matrix,
prospective-state predicate, causal replay parent rule, trusted-helper
`CandidateReadRequest` contract), but the production coordinator has no
`execute_repo_read` handler, so a Developer cannot actually read a candidate
file through the ledger and get a signed receipt.

This slice adds the atomic transaction that authorizes, executes, signs, and
commits one repo-read call with the same COMMIT-ACK exact-readback guarantees
as `execute_rollback`.

## 2. Approved Decisions

- **R1:** `owp.repo_read` reads exactly one `CanonicalRoot` path per call
  (`RepoReadArguments.path`). No multi-path batch in this slice.
- **R2:** The receipt carries **no evidence attachment** (mirrors the rollback
  receipt). The `RepoReadOutput` JSON (path, content_sha256, size_bytes,
  workspace_manifest_digest) is bound to the receipt via `output_digest`, so a
  third party can rehash the output offline without a new evidence slot.
- **R3:** No new `EvidenceArtifact` purpose and no v0.1 work-order schema
  change. The evidence-policy slot set is frozen for this slice.
- **R4:** The transaction reuses the `execute_rollback` skeleton: target lock,
  frozen second, `require_current_context`, `validate` + `_preflight_*`,
  handler call, receipt build, `complete_receipt_publication` with empty
  payloads, `_finalize_handler_execution`, COMMIT-ACK handling.
- **R5:** The read is performed by a caller-supplied handler
  (`Callable[[CandidateReadRequest], CandidateReadResult]`), mirroring the
  rollback handler seam; production wiring to the trusted-helper image is a
  later transport slice.
- **R6:** `state_after` stays `context.current_state` (`running`/`retrying`);
  the read is same-state and does not transition the WorkOrder.

## 3. Current-State Constraints

- `RepoReadArguments(ProtocolModel)` with `path: CanonicalRoot` exists.
- `RepoReadOutput(ProtocolModel)` with 64 KiB size cap exists.
- `_prospective_state_allowed` allows `owp.repo_read` in
  `running`/`retrying`.
- `_prospective_role_allowed` allows `owp.repo_read` for the Developer role.
- Causal replay parents a repo-read receipt to `active_patch` when present.
- `repo_tools.CandidateReadRequest` / `CandidateReadResult` exist for the
  trusted-helper contract.
- `execute_rollback` provides the exact atomic skeleton to mirror.

## 4. Transaction Design

### 4.1 `execute_repo_read`

Signature:

```python
def execute_repo_read(
    ledger_path: Path,
    *,
    evidence_root: Path,
    context: AuthorizationContext,
    request: AgentRequest,
    execution_facts: ProspectiveExecutionFacts,
    sidecar_private_key: Ed25519PrivateKey,
    handler: Callable[[CandidateReadRequest], CandidateReadResult],
    clock: Callable[[], datetime],
) -> ToolCallReceipt:
```

Flow:

1. Recover evidence publications, acquire the target lock, ensure the
   handler-execution schema, recover stale executions, freeze the trusted
   UTC second.
2. Verify the Sidecar key matches the execution controller.
3. `require_current_context`; on failure, prove via readback that the exact
   repo-read receipt is already committed and raise
   `AcceptanceCommittedError(committed=receipt)`, otherwise re-raise.
4. `authorize_tool_call` (prospective authorization: state, role, grant,
   capability, quota). Denied -> `ToolCallDenied`.
5. `_preflight_repo_read_receipts` (new): validate the request arguments,
   the read path against the WorkspaceManifest allowlist, and the expected
   head-commit/manifest binding.
6. Build `CandidateReadRequest` from the context checkpoint and the path;
   reserve + mark-started the handler execution; call `handler`.
7. Build the `ToolCallReceipt`:
   - `tool_name = "owp.repo_read"`, `policy_decision = "allow"`;
   - `output_digest = sha256(canonical RepoReadOutput JSON)`;
   - `evidence_refs = ()`;
   - `state_after = context.current_state`;
   - `parent_receipt_ids` = grant issuance + active_patch (mirror
     `_causal_parents` behavior for repo_read).
8. `complete_receipt_publication(payloads={})`, finalize the execution, and
   release the lock. COMMIT-ACK loss and readback failure follow the exact
   rollback pattern (`AcceptanceCommittedError` /
   `AcceptanceCommitIndeterminateError`).

### 4.2 Readback

`_readback_repo_read_committed(ledger_path, *, work_order, receipt)` reopens
the ledger, replays the exact prefix, finds the repo-read receipt by
`receipt_id`, and returns True only when the receipt, the state row, and the
sequence agree.

### 4.3 Replay and offline verification

No new replay rule is needed: the causal parent rule for `owp.repo_read`
already exists. The output digest can be rehashed from the copied
`RepoReadOutput` JSON in offline verification tests.

## 5. Verification Gates

- Focused protocol suites stay green with zero failures.
- Full required-live run reaches exit code 0 with zero required-live skips.
- New tests: success path (receipt committed, state unchanged, output digest
  bound), wrong-role signer, missing/denied grant, stale context, COMMIT-ACK
  loss readback, readback indeterminate, path outside the workspace manifest,
  output over 64 KiB rejection, tampered output digest fails offline rehash.
- pip check, compileall, `git diff --check`; zero owned containers/volumes.

## 6. Boundaries

- Multi-path batch reads, recursive directory reads.
- Production wiring to the trusted-helper image (transport slice).
- Developer mode production entry and MCP transmission.
