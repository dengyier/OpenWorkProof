# OpenWorkProof Verifier `run_tests` Execution Recovery Design

**Status:** User-approved design, ready for implementation planning

**Date:** 2026-08-04

**Base revision:** `40dd889561faa5388b292a89920065ccca0b52e4`

**Target branch:** `codex/run-tests-execution-recovery`

## 1. Goal

Close the real execution and crash-recovery gap for the existing Verifier-only
`owp.run_tests` coordination path. A single authorized request must map to one
stable execution identity, at most one Docker start, at most one quota charge,
and at most one signed Receipt, even if the controller exits at any covered
coordination boundary.

This slice turns the existing `handler_executions` reservation into a durable
execution binding and connects it to the already implemented Docker containment
plan, candidate workspace checkpoint, evidence publication transaction, and
signed ToolCallReceipt path.

## 2. Scope

This design includes only:

- Verifier-mode `owp.run_tests`;
- one frozen test command mapping;
- an immutable, registry-qualified execution image reference;
- a one-use read-only candidate snapshot;
- deterministic Docker resource identities derived from `execution_id`;
- canonical execution contract, start marker, and result envelope;
- reconciliation of `RESERVED` and `STARTED_UNCONFIRMED` after controller
  restart;
- existing `stage -> commit -> publish -> mark committed` evidence and Receipt
  publication;
- revision-bound rebuild of affected candidate image evidence.

The following remain out of scope:

- Developer-mode tests;
- real rollback execution;
- deny Receipt production transactions;
- MCP transport, CLI, AgentTeams, or a long-lived worker service;
- additional tool handlers;
- AcceptanceReceipt and full proof composition;
- image-registry publication, Acceptor access, clean-cache reacquisition,
  final-helper status, D8, Day 0, contest delivery, or commercial validation;
- any LICENSE decision.

## 3. Existing Authorities Reused

The implementation must extend, not replace, these existing authorities:

- `mcp_server.execute_run_tests` owns authorization, target locking, quota and
  Receipt semantics;
- `handler_executions` owns unresolved handler execution truth;
- `repo_tools.derive_docker_execution_plan` and related inspection functions
  own the frozen Docker containment profile;
- the candidate checkpoint and execution snapshot primitives own workspace
  bytes, commit, and manifest identity;
- `complete_receipt_publication` owns the four-phase evidence and Receipt
  publication path;
- the Sidecar key owns protocol signatures and never enters the execution
  container.

Docker logs, process stdout, filesystem timestamps, and caller-provided resource
paths are not authorities.

## 4. Chosen Architecture

### 4.1 Protocol coordinator

`mcp_server.py` remains the protocol coordinator. It:

1. recovers committed evidence publications;
2. acquires the existing target lock;
3. validates and migrates an empty legacy handler journal when allowed;
4. reconciles any unresolved execution before considering a new request;
5. replays the current authorization context;
6. authorizes the request and preflights all possible Receipt shapes;
7. reserves the execution contract;
8. delegates resource preparation, start, observation, and cleanup to the
   Docker execution driver;
9. verifies the returned execution facts;
10. signs and publishes the existing TestResultEvidence and ToolCallReceipt;
11. clears the journal only after committed truth or safe pre-start cleanup is
    proven.

It does not assemble shell commands, parse Docker logs, or infer a result from
an exception string.

### 4.2 Docker execution driver

`repo_tools.py` owns a concrete, bounded Verifier execution driver. The driver
uses existing pure Docker plan and inspection functions and adds narrowly
scoped orchestration for:

- deterministic names and ownership token derivation;
- candidate snapshot staging through one short-lived, owned staging container;
- container and volume creation in the existing required order;
- pre-start image, container, mount, volume, and never-started inspection;
- detached start;
- bounded wait and observation;
- canonical envelope reads;
- reconciliation after restart;
- cleanup of only resources that still match the execution ownership binding.

The driver returns typed observations. It does not open the ledger, sign a
Receipt, select an evidence slot, or change protocol state.

### 4.3 Frozen in-container runner

The execution image gains one small, hash-bound runner entrypoint. It is not the
OpenWorkProof package and receives no signing material, Docker socket, network,
or arbitrary command string.

The runner:

1. reads one bounded canonical `/workspace/run-contract.json`;
2. accepts only schema version `openworkproof-run-contract/0.1`, tool
   `owp.run_tests`, and mode `verifier`;
3. requires the contract command digest to match the single frozen verifier
   command;
4. atomically writes `/output/started.json`;
5. launches only the frozen pytest argv with the existing timeout and combined
   output bounds;
6. atomically writes `/output/result.json` when it can produce a closed result;
7. exits without interpreting OpenWorkProof policy or signing protocol facts.

Atomic writes use a same-directory temporary regular file, file `fsync`,
no-replace rename, and directory `fsync`. Existing or non-regular target names
are rejected.

## 5. Stable Execution Identity and Resource Binding

The existing execution ID remains authoritative:

```text
sha256(canonical({
  domain: openworkproof/handler-execution/v0.1,
  request_digest,
  execution_context_id,
  container_instance_id_digest,
  controller_id
}))
```

Resource identifiers are deterministic lowercase names derived from a fixed
prefix plus a bounded prefix of `execution_id`. Full identity is carried in the
ownership label and execution contract digest; a shortened Docker name is never
accepted as sufficient identity.

The signed AgentRequest and execution contract are stored canonically in the
journal before resource creation. The journal retains the existing identity
columns and adds:

- `request_json`;
- `execution_contract_json`;
- `execution_contract_digest`.

`request_json` is bounded by the existing AgentRequest limit and must parse as
the exact signed request whose digest is stored in the row. The canonical
contract is bounded to 8 KiB and contains every RunTestsArguments field. On
every read, its digest and all fields duplicated by journal columns must match.
Together with the existing execution-fact columns and `reserved_at`, these
bytes are sufficient to reconstruct the old request and result without trusting
the next caller's request. Recovery must also prove that the supplied current
AuthorizationContext has the same WorkOrder and unchanged ledger prefix before
constructing the old Receipt.

Resource names and ownership token are re-derived from the full execution ID
rather than trusted from a host path or unvalidated JSON field. Deterministic
resources include the workspace volume, output volume, snapshot-staging
container, and execution container. The staging container is removed before
the execution container becomes start-eligible; its attempted identity remains
part of cleanup and crash recovery until absence is proven.

The Docker execution driver is configured with one absolute canonical
controller-owned candidate runtime root. This host path is not accepted from an
AgentRequest and is not mounted into the execution container. The contract
stores `candidate_workspace_id` and `source_artifact_sha256`, allowing recovery
to derive the candidate path under the configured root and re-run the existing
control/Git/workspace checkpoint verification. A restart configured with a
different or unavailable runtime root remains `RECOVERY_REQUIRED`.

No second execution-truth table is introduced.

## 6. Canonical Internal Contracts

### 6.1 Run contract

`run-contract.json` has exactly these fields:

```json
{
  "arguments_digest": "<sha256>",
  "candidate_commit": "<git-object-id>",
  "candidate_workspace_id": "<sha256>",
  "command_digest": "<sha256>",
  "container_image_digest": "sha256:<digest>",
  "execution_id": "<sha256>",
  "fixed_test_source_digest": "<sha256>",
  "request_digest": "<sha256>",
  "schema_version": "openworkproof-run-contract/0.1",
  "source_artifact_sha256": "<sha256>",
  "source_commit": "<git-object-id>",
  "test_mode": "verifier",
  "tool_name": "owp.run_tests",
  "workspace_manifest_digest": "<sha256>"
}
```

The serialized bytes must equal RFC 8785 output exactly. Duplicate keys,
unknown keys, trailing bytes, BOM, non-canonical ordering, wrong scalar types,
or values inconsistent with the authorized request are rejected before start.

### 6.2 Start marker

`started.json` has exactly:

```json
{
  "execution_contract_digest": "<sha256>",
  "execution_id": "<sha256>",
  "schema_version": "openworkproof-run-started/0.1"
}
```

It contains no container clock claim. Docker inspection establishes whether the
container engine accepted and entered the start lifecycle; the marker proves
that the frozen runner read the expected contract.

### 6.3 Result envelope

`result.json` is bounded to 8 KiB and has exactly:

```json
{
  "actual_exit_code": 0,
  "execution_contract_digest": "<sha256>",
  "execution_id": "<sha256>",
  "failure_code": null,
  "schema_version": "openworkproof-run-result/0.1",
  "stderr_bytes": 0,
  "stderr_sha256": "<sha256>",
  "stdout_bytes": 0,
  "stdout_sha256": "<sha256>"
}
```

The closed alternatives are:

- completed execution: `actual_exit_code` is an integer in `0..255` and
  `failure_code` is null;
- classified infrastructure failure: `actual_exit_code` is null and
  `failure_code` is exactly `OUTPUT_LIMIT`, `TIMEOUT`, or `DISK_LIMIT`.

Sizes and digests describe bounded diagnostic streams. Stream bytes are not
embedded in the protocol Receipt and are not used as policy truth. The host
must require the result envelope, Docker inspection, container exit state, and
volume identity to agree. A missing or contradictory result is unresolved,
not an inferred failure.

These three JSON artifacts are internal recovery inputs. They do not create a
new public OpenWorkProof protocol object or replace signed TestResultEvidence.

## 7. Normal Execution Flow

1. Recover evidence publications and acquire the target lock.
2. Reconcile the existing handler journal.
3. Freeze the current trusted second and replay current authorization context.
4. Authorize one Verifier `owp.run_tests` request.
5. Verify that `command_digest` matches the only frozen verifier command.
6. Preflight successful, test-failed, and infrastructure-failed Receipt sizes.
7. Build and atomically reserve the canonical execution contract as
   `RESERVED`.
8. Derive absent Docker resource names from `execution_id`.
9. Create the workspace volume, then use one deterministic staging container
   to materialize only the normalized `ExecutionSnapshotPlan` bytes. The
   staging container has no network, Docker socket, Sidecar key, or host
   credentials. It re-reads the staged bytes, recomputes the expected manifest,
   and exits successfully only on an exact match. Treat its exact bounded
   output as a pre-start preparation observation, not as protocol execution
   evidence. Remove it and prove its absence.
10. Create the output volume and execution container. Verify the frozen
    containment profile, read-only workspace mount, and immutable image
    reference. The frozen execution runner independently rechecks the snapshot
    manifest before writing `started.json` or invoking pytest.
11. Transition the journal to `STARTED_UNCONFIRMED` before issuing detached
    Docker start.
12. Start the container exactly once.
13. Observe container state and read canonical start/result envelopes through
    descriptor-anchored, no-symlink paths.
14. Recompute the existing TestResultEvidence payload from the stored old
    request, stored contract, validated current authority, and validated result
    facts.
15. Sign one ToolCallReceipt and execute the existing publication transaction.
16. Re-read committed Receipt truth.
17. Remove owned Docker resources and clear the execution journal.

The target lock remains held across this first implementation slice. Moving
long execution waits outside the lock would require a broader concurrency and
context-freshness design and is not part of this scope.

## 8. Recovery State Machine

Recovery runs before a new request is authorized.

### `RESERVED`

- no owned resources: delete the reservation; caller may retry;
- partially created, still-owned workspace, staging, output, or execution
  resources: inspect, clean in reverse order, then delete the reservation;
- any matching resource shows evidence of having started: treat the execution
  as started and follow `STARTED_UNCONFIRMED` recovery;
- resource exists with wrong owner, type, image, mount, or binding: retain the
  journal and return `RECOVERY_REQUIRED`.

### `STARTED_UNCONFIRMED`

- container is still running: retain everything and return
  `RECOVERY_REQUIRED`; never issue another start;
- container is still in never-started `created` state and no start marker
  exists: clean resources and reservation, allowing a later retry;
- container exited and a closed, matching result exists: resume evidence and
  Receipt publication from the old execution;
- container exited but result is missing, malformed, non-canonical, oversized,
  or mismatched: retain the execution and return `RECOVERY_REQUIRED`;
- a matching Receipt is already committed: Receipt truth wins; perform only
  idempotent resource and journal cleanup;
- a Receipt exists but does not exactly match the journal identity: retain the
  execution and fail closed.

At no point does recovery re-run authorization for the old execution, generate
a new nonce, call Docker start twice, or fabricate an execution result.

## 9. Receipt and State Semantics

### Tests meet the expected exit code

- `execution_status = succeeded`;
- publish one TestResultEvidence;
- charge one `tool_calls` unit;
- transition Verifier state to `locally_verified`.

### Tests execute but return another exit code

- `execution_status = succeeded` because the tool execution is closed;
- publish one TestResultEvidence with the actual exit code;
- charge one `tool_calls` unit;
- transition Verifier state to `needs_rework`.

### Closed infrastructure failure after confirmed start

- `execution_status = failed`;
- `execution_error_code` is `OUTPUT_LIMIT`, `TIMEOUT`, or `DISK_LIMIT`;
- publish no TestResultEvidence;
- charge one `tool_calls` unit;
- keep protocol state unchanged.

### Pre-start failure

Snapshot staging, Docker absence preflight, resource creation, or containment
inspection failure before start produces no Receipt and no quota charge. Owned
resources are cleaned if their identity remains provable.

### Unresolved post-start truth

Missing or contradictory execution facts produce no new Receipt. The journal
and provably owned resources are retained and the caller receives
`RECOVERY_REQUIRED`.

### Commit or cleanup uncertainty

If Receipt commit truth is unknown, existing committed-truth recovery rules
apply. Once a matching Receipt is proven committed, later cleanup failure cannot
cause a second Receipt, quota charge, or execution.

## 10. Security and Resource Boundaries

- Docker image references are registry-qualified `repository@sha256` values;
- pull is disabled and the inspected RepoDigest must match;
- network mode is `none`;
- the execution container root filesystem and workspace mount are read-only;
- only the short-lived pre-start staging container mounts the workspace volume
  writable, and it is removed before start authority exists;
- output is the only writable volume, excluding bounded `/tmp`;
- user is `65532:65532`, all capabilities are dropped, and
  `no-new-privileges` is required;
- Docker socket, Sidecar key, host credentials, and inherited host environment
  are never mounted or passed;
- command execution is a fixed argv mapping, never a shell string;
- snapshot materialization accepts only a canonical normalized snapshot stream;
  the staging container is deterministically named, ownership-labelled,
  networkless, and removed before start authority is derived;
- workspace snapshot, contract, marker, result, and diagnostic paths reject
  symlinks, hardlinks, special files, extra aliases, and identity drift;
- input and output JSON reject duplicate keys and require canonical bytes;
- output, time, process, memory, CPU, tmpfs, and path-size limits remain
  explicit and tested;
- cleanup removes only resources that still carry the exact ownership binding.

## 11. Journal Compatibility

The new handler journal schema extends the current schema with nullable
`request_json`, `execution_contract_json`, and `execution_contract_digest`
columns plus a table CHECK: all three are required for `owp.run_tests` and all
three are null for `owp.rollback_patch`. Migration is allowed only while holding
the target lock and only when the old table is empty. An empty compatible
legacy table may be replaced transactionally.

Any non-empty legacy table lacks a trustworthy execution contract and remains
`RECOVERY_REQUIRED`. The implementation must not synthesize a contract from the
current request, current workspace, Docker discovery, or mutable host state.

During recovery, the stored signed request and contract are authoritative for
the old execution, but the current ledger and committed evidence are re-read.
If the supplied AuthorizationContext does not bind the same WorkOrder and exact
pre-execution ledger prefix, recovery remains `RECOVERY_REQUIRED`; it does not
reuse the new caller's request or overwrite the old journal.

The rollback coordination path remains on its current behavior. It must neither
accept the new Verifier contract nor regress because the shared journal schema
changed.

## 12. Candidate Image and Evidence Update

Adding the frozen runner changes the execution-image definition. After the
exact code-definition revision exists, the implementation must:

1. bind runner bytes into the execution build context and its `SHA256SUMS`;
2. rebuild revision-specific execution and trusted-helper contexts offline;
3. rebuild both linux/arm64 candidate images with `--network=none` and no pull;
4. export Docker and true OCI image-layout archives;
5. record actual IDs, manifests, sizes, and hashes in a new revision-named
   inventory;
6. retain historical inventories and validate each against its own revision;
7. keep registry push, Acceptor access, clean-cache reacquisition, final helper,
   D8, and Day 0 claims false.

No existing evidence directory or inventory is overwritten.

## 13. Verification Plan

### Pure tests

- stable execution ID and Docker resource derivation;
- exact contract, marker, and result schemas;
- duplicate-key, non-canonical, unknown-field, trailing-byte, size, and type
  rejection;
- journal migration and duplicated-field cross-checking;
- state-machine transitions and failure-code priority;
- fixed command digest enforcement;
- typed Receipt outcomes for pass, test failure, and each infrastructure
  failure.

### Coordination and crash-injection tests

Inject termination after:

1. journal reservation;
2. workspace volume creation;
3. staging container creation and snapshot materialization;
4. staging-container removal;
5. output volume creation;
6. execution-container creation;
7. `STARTED_UNCONFIRMED` transition but before Docker start;
8. Docker accepting start but before `started.json` observation;
9. result rename but before Receipt construction;
10. Receipt commit but before journal cleanup;
11. journal cleanup but before Docker cleanup completes.

Each recovery case must prove the exact number of Docker starts, Receipts,
quota events, state/version changes, evidence publications, and surviving
resources.

### Adversarial tests

- pre-existing resource names;
- ownership-label replacement;
- image, mount, user, network, or volume-option drift;
- container ID or contract substitution;
- symlink, hardlink, FIFO, socket, and path replacement;
- result identity or exit-code contradiction;
- malformed, oversized, duplicate-key, or non-canonical envelopes;
- running container, dead container, daemon-unavailable, and cleanup failure;
- old non-empty journal schema;
- stale authorization context during a new call.

### Required-live tests

Use the immutable candidate execution image and real Docker daemon to prove:

- linux/arm64 image identity;
- no network, read-only root/workspace, bounded writable output and `/tmp`;
- UID/GID 65532 and no Docker socket;
- one detached start and closed result recovery;
- expected and unexpected pytest exits;
- timeout, output, and disk limits where a closed result can be produced;
- zero owned container and volume residue after closed success/failure paths;
- an unresolved path retains only the resources required for recovery and is
  cleaned by an explicit test teardown, not silently treated as success.

### Full regression

Run the complete project suite with candidate artifact root and required-live
Docker enabled. There must be zero required-live skips. Also run `pip check`,
`compileall`, `git diff --check`, all context/archive `SHA256SUMS`, inventory
schema checks, and residue checks.

## 14. Completion Criteria

The slice is complete only when all of the following are demonstrated:

1. every covered crash boundary recovers without a duplicate Docker start;
2. a closed execution produces exactly one signed Receipt and one quota charge;
3. a committed Receipt cannot be duplicated by cleanup failure;
4. an unprovable post-start result remains `RECOVERY_REQUIRED`;
5. successful and test-failed executions publish exact TestResultEvidence;
6. closed infrastructure failures use only the three existing error codes;
7. required-live full tests pass with zero skips;
8. all affected candidate artifacts are revision-bound and hash-verified;
9. no owned Docker residue remains after closed paths;
10. independent specification and code-quality reviews report no blocking
    issue.

These criteria establish only a Verifier `run_tests` candidate execution and
recovery slice. They do not establish a final trusted helper, independent
Acceptor acceptance, D8, Day 0, registry publication, contest delivery, or
commercial validation.
