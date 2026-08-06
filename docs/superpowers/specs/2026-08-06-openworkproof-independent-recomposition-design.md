# OpenWorkProof Independent Result and Recomposition Design

Date: 2026-08-06

Status: Approved design

Target branch: `codex/independent-recomposition`

## 1. Objective

Close the missing five-dimension proof path between the first incomplete
composition and the existing Acceptance transaction:

```text
Verifier run_tests passes
  -> Manager composes the first report
  -> evidence_incomplete because independent_result is absent
  -> the same bound Verifier runs the same frozen test profile
     in a fresh execution context and container instance
  -> the independent result is committed to its dedicated evidence slot
  -> Manager explicitly recomposes against the first report digest
  -> the second report replays the full five-dimension evidence chain
  -> proof_ready
  -> the existing request / prepare / commit Acceptance path
```

The slice proves that a locally passing result does not become acceptable
merely because one execution succeeded. The first report remains an immutable
statement of missing evidence. A second, independently executed result and a
new Manager-authorized composition are required before `proof_ready`.

## 2. Approved Decisions

The user approved the following closed choices:

- **A1:** retain the existing six-role WorkOrder. The independent result is
  signed for the same bound Verifier identity but must use a fresh execution
  context and container instance. No seventh role is added.
- **F1:** a completed independent test with a non-passing result seals the
  episode. It does not automatically retry or roll back. Only a separately
  designed rejection, termination, or contract-expiry path may follow.
- **R1:** a successful independent result does not automatically compose a
  new report. The Manager must explicitly sign a second
  `owp.compose_proof` request bound to the first report digest.
- **T1:** both Verifier executions use the same immutable Verifier TestProfile
  and fixed test source from the WorkOrder. Independence in this slice means
  fresh execution plus a separately committed independent-result evidence
  slot, not a second test-suite design authority.
- The implementation extends the existing `execute_run_tests` and
  `compose_proof_transaction` paths. It does not add a second test tool or a
  generic episode framework.

## 3. Current-State Constraints

The repository already provides:

- a required-live Docker `run_tests` execution driver with durable execution
  identity, reconciliation, cleanup, and committed-receipt recovery;
- `evidence_incomplete` and `proof_ready` protocol states;
- a WorkOrder evidence inventory that may contain exactly one
  `verifier_independent_result` artifact;
- causal and policy replay rules for an independent Verifier result after a
  `proof_composed` trigger;
- fresh execution-context and container-instance rejection;
- pure recomposition causal rules requiring the prior trigger, independent
  result, and `previous_report_digest`;
- atomic CompositionReport and Acceptance strong-success transactions.

The production coordinators still have four concrete gaps:

1. `execute_run_tests` always selects `verifier_result`, even while the
   authoritative state is `evidence_incomplete`;
2. the current receipt builder moves every passing Verifier call to
   `locally_verified` and omits the current composition trigger from an
   independent attempt's parents;
3. `compose_proof_transaction` currently constructs
   `previous_report_digest=None` in both initial and recomposition states;
4. report derivation does not deliberately select the independent Verifier
   receipt as the final verifier reference or include both declared Verifier
   evidence purposes in `test_evidence_refs`.

This slice closes only those coordinator and report-construction gaps. It does
not redesign the already frozen causal or policy model without a failing test
that proves a necessary inconsistency.

## 4. Scope

This slice includes:

1. state-aware classification of a normal Verifier run versus an independent
   Verifier run;
2. pre-start validation of the independent evidence slot and current
   composition authority;
3. exact independent-result causal parents and state semantics;
4. durable execution and committed-evidence recovery for the second run;
5. Manager-authorized recomposition bound to the latest report;
6. deterministic second-report construction over the complete authoritative
   prefix;
7. exact COMMIT-truth, concurrency, offline replay, and failure-injection
   tests;
8. README and status updates that state only locally verified facts.

## 5. Out of Scope

This slice does not add or claim:

- a second Verifier role, key, Grant authority, or test profile;
- a new public protocol object or a v0.1 public Schema change;
- automatic recomposition, retry, rollback, rejection, or acceptance;
- Acceptor rejection receipts or a rejected terminal transaction;
- Developer-mode execution or other ToolCall handlers;
- CLI, MCP transport, AgentTeams, or a long-lived service;
- Rich #4196 end-to-end demo completion;
- registry publication, clean-cache reacquisition, final-helper, D8, Day 0,
  contest delivery, external acceptance, or commercial validation.

## 6. Episode Classification

`execute_run_tests` derives the episode from the authoritative current state;
the caller cannot choose it with a new flag.

| Current state | Allowed mode | Episode | Evidence purpose |
|---|---|---|---|
| `running` / `retrying` | `verifier` | primary verifier result | `verifier_result` |
| `evidence_incomplete` | `verifier` | independent verifier result | `verifier_independent_result` |

All other state/mode combinations retain their existing fail-closed behavior.
The signed `RunTestsArguments` remain unchanged. The WorkOrder's one Verifier
TestProfile remains the sole command, image, expected exit code, and fixed
test-source authority for both episodes.

The coordinator must derive a local closed episode kind such as
`primary_verifier` or `independent_verifier` from the current context. This is
an implementation detail and is not serialized into a new public field.

## 7. Independent Pre-Start Gate

Before reserving an execution or invoking the Docker driver, an independent
attempt must prove all of the following from the current authoritative
context:

- current state is exactly `evidence_incomplete`;
- the active patch still exists and matches the current ReplayCheckpoint;
- there is exactly one latest `proof_composed` trigger;
- that trigger resolves to exactly one canonical current CompositionReport;
- the current report conclusion is `evidence_incomplete`;
- the current report covers the authoritative prefix that ended at its
  Manager initiator;
- no successful independent-result receipt already exists in the current
  episode;
- the WorkOrder declares exactly one unused
  `verifier_independent_result` slot;
- the payload can fit within that slot's declared maximum;
- the AgentRequest, nested signature, Verifier role, Grant, nonce, quota,
  validity interval, capability, command, image, checkpoint, and fixed test
  source pass the existing pure authorization gate;
- `execution_context_id` and `container_instance_id_digest` have never
  appeared in any charged run-tests history.

Any failure before durable reservation leaves the journal, quota, sequence,
state, version, receipts, evidence publications, and report rows unchanged.

## 8. Evidence Slot Selection

The result payload remains the canonical
`openworkproof-test-result/0.1` object derived from signed
`RunTestsArguments` and the actual exit code.

Slot selection is authoritative and state-aware:

- a primary Verifier result selects the first unused `verifier_result` slot;
- an independent Verifier result selects the unique unused
  `verifier_independent_result` slot;
- a caller cannot supply a purpose or path;
- a missing, duplicate, occupied, symlinked, oversized, or otherwise invalid
  slot fails before execution starts;
- the EvidenceRef path, digest, media type, and size are derived from the
  declared slot and exact canonical result bytes.

The independent payload may be byte-identical to the first payload because T1
reruns the same frozen tests. Its distinct authority comes from the signed
request, fresh correlation factors, exact causal parents, separate receipt,
dedicated EvidenceRef, and immutable publication path.

## 9. Independent Receipt Semantics

An independent `ToolCallReceipt` keeps the existing `owp.run_tests` tool name,
tool version, request arguments, quota, predicate, and Sidecar signature
rules. It differs from a primary Verifier receipt in these derived fields:

- `state_before = evidence_incomplete`;
- `state_after = evidence_incomplete` for every closed test result;
- `evidence_refs` points to the independent-result slot for a completed test;
- exact causal parents are:
  1. the Verifier Grant issuance receipt;
  2. the active patch receipt;
  3. the latest `proof_composed` trigger;
- correlation factors contain the new execution context, container instance,
  existing controller, and the frozen Verifier test-source digest.

The parent vector remains sequence-ordered and unique. Omitting or replacing
the current trigger makes the receipt invalid even if all other bytes and
signatures are valid.

## 10. Result and Failure Semantics

The execution driver has three distinct outcome classes.

### 10.1 Passing closed result

- publish the canonical independent test-result bytes;
- commit the independent ToolCallReceipt and quota event atomically with the
  existing evidence-publication protocol;
- keep the protocol state `evidence_incomplete`;
- expose the receipt as the one independent result eligible for
  recomposition.

### 10.2 Non-passing closed result

- publish the truthful independent test-result bytes and actual exit code;
- commit a successful tool execution whose `tests_passed` predicate is false;
- keep the protocol state `evidence_incomplete`;
- mark the independent episode terminal through existing causal replay;
- prohibit another independent test or recomposition;
- allow only separately implemented rejection, termination, or expiry tails.

### 10.3 Infrastructure failure or unknown execution truth

- `OUTPUT_LIMIT`, `TIMEOUT`, and `DISK_LIMIT` retain their existing closed
  failed-execution Receipt semantics and do not fabricate test-result bytes;
- `STARTED_UNCONFIRMED` returns `RECOVERY_REQUIRED` and uses the durable
  execution contract to reconcile rather than rerunning;
- a proven infrastructure failure may be followed by a new explicitly signed
  request with fresh execution identifiers if policy and quota still allow;
- no automatic retry is performed.

F1 applies to a completed, non-passing independent test. It does not convert an
unknown infrastructure outcome into a semantic test failure.

## 11. Durable Execution and COMMIT Truth

The second run reuses the existing persistent execution envelope and recovery
state machine. The stored contract continues to bind request digest,
arguments digest, candidate workspace identity, source and candidate commits,
workspace manifest, image, command, and fixed test source.

Recovery must reconstruct the independent episode from the stored reservation
and the authoritative ledger state. It must not silently reconstruct a primary
Verifier receipt. Recovery may publish and commit only the exact result bound
to the stored execution contract.

If evidence publication or receipt COMMIT acknowledgement is lost:

- read back the exact receipt, quota event, state/version, evidence journal,
  final EvidenceRef, and committed bytes;
- return or raise committed truth only if the canonical stored receipt and
  payload match the attempted result exactly;
- otherwise return `RECOVERY_REQUIRED`;
- cleanup or lock-release failure never rewrites a proven committed result as
  uncommitted.

## 12. Recomposition Request

The Manager explicitly sends the existing `owp.compose_proof` AgentRequest.
The expected `ComposeProofArguments` are derived from current authority:

- initial composition from `locally_verified` requires
  `previous_report_digest = null`;
- recomposition from `evidence_incomplete` requires
  `previous_report_digest` equal to the digest referenced by the current
  latest `proof_composed` trigger;
- `expected_state_version` retains the existing authoritative version rule;
- any caller-supplied digest that is null, stale, unknown, or not the current
  trigger's report digest is rejected before a new report is constructed.

The Manager request must pass the same signature, freshness, role, Grant,
capability, nonce, quota, validity, and current-context authorization applied
to initial composition.

## 13. Recomposition Causality

The recomposition Manager receipt uses exact sequence-ordered parents:

1. its authorizing Grant issuance receipt;
2. the latest `proof_composed` trigger for the incomplete report;
3. the successful independent-result ToolCallReceipt.

The active patch and primary Verifier result remain authoritative ancestors
through the first report episode and continue to appear in the complete
covered receipt vector. The second `proof_composed` trigger references only
the newly derived second report and the recomposition initiator, following the
existing no-digest-cycle rule.

No recomposition is allowed after a non-passing independent result, after a
newer composition trigger, or when any bound evidence bytes, report row,
receipt, checkpoint, Grant state, or WorkOrder field has drifted.

## 14. Second CompositionReport

The second report is a new immutable canonical object. It does not update or
replace the first report.

It is derived from the authoritative receipt prefix ending at the
recomposition Manager receipt and must include:

- the unchanged WorkOrder digest and final artifact;
- every exact receipt digest in protocol sequence order;
- both the primary and independent Verifier EvidenceRefs;
- all committed artifact EvidenceRefs in path-byte order;
- a recomputed evidence snapshot and causal graph root;
- five closed evidence dimensions: `authority`, `scope`, `execution`,
  `result`, and `independent_result`;
- a recomputed global postcondition vector;
- an `IndependenceAssessment` whose `verifier_reference` is the successful
  independent-result receipt and whose `developer_reference` remains the
  authoritative Developer execution receipt;
- warnings derived exactly from the Developer/independent-Verifier
  correlation-factor comparison;
- `test_evidence_refs` containing every declared and referenced
  `verifier_result` and `verifier_independent_result` artifact, sorted by path;
- no unresolved failures when the conclusion is `proof_ready`.

Test evidence selection must be based on the WorkOrder artifact-purpose
registry, not a hard-coded path prefix. This prevents a valid independent path
from being omitted merely because its directory name differs from
`verifier-result`.

The second report reaches `proof_ready` only when causal replay, policy replay,
evidence rehash, five-dimension coverage, independence assessment, and every
global postcondition all pass. If recomposition remains incomplete, the
episode stays `evidence_incomplete` and cannot manufacture a third independent
result or overwrite either prior report.

## 15. Atomic Recomposition Transaction

Under the existing per-target lock, recomposition must:

1. recover evidence publications;
2. rederive and require the exact current AuthorizationContext;
3. authorize the Manager request;
4. load and validate the unique current first report and trigger;
5. load and validate the successful independent result and its evidence bytes;
6. construct the Manager recomposition receipt;
7. derive and validate the canonical second report;
8. construct the second `proof_composed` trigger;
9. in one `BEGIN IMMEDIATE`, insert both receipts, parent rows, quota event,
   report row, state transition, sequence updates, and version update;
10. COMMIT and read back the exact canonical objects and atomic side effects.

Pre-COMMIT failure leaves every table and counter unchanged. Unknown COMMIT
acknowledgement follows exact readback and never performs a second semantic
composition. A proven commit remains committed truth if connection close,
lock release, or later cleanup fails.

## 16. Concurrency

- the target lock serializes independent execution reservation and
  recomposition;
- two concurrent independent requests may start at most one execution;
- after one independent result commits, another request is rejected unless
  exact readback proves it is the byte-identical already committed operation;
- two concurrent Manager recompositions may insert at most one second report
  and one second trigger;
- stale requests cannot be rebound to a newer report, result, checkpoint, or
  state version;
- no operation overwrites the first report, independent evidence bytes, or
  the second report.

## 17. Offline Replay

An isolated bundle containing the WorkOrder, Grants, ActionReceipts, both
CompositionReports, committed evidence bytes, and six public keys must verify
without the live ledger or Docker daemon.

Offline verification must:

- verify WorkOrder identity and all signatures;
- replay Grant, causal, policy, quota, state, and version history;
- rehash every referenced evidence payload;
- reconstruct both report digests;
- prove the first trigger references the first report;
- prove the independent receipt references the first trigger and uses fresh
  execution identifiers;
- prove recomposition references the first report digest and independent
  result;
- prove the second trigger references the second report;
- reproduce the second report's five-dimension coverage, independence
  assessment, test evidence refs, postconditions, and `proof_ready`
  conclusion.

## 18. Test Strategy

Implementation follows RED-GREEN-REFACTOR. Required tests include:

### 18.1 Success path

- initial composition deterministically produces `evidence_incomplete` when
  only `independent_result` is missing;
- independent execution uses the same frozen profile with fresh execution and
  container identifiers;
- the dedicated independent slot is selected and published;
- the independent receipt remains in `evidence_incomplete` and has exact
  parents;
- Manager recomposition requires the first report digest;
- the second report contains both test refs, the independent verifier
  reference, all five dimensions, and `proof_ready`;
- the existing final-acceptance request and AcceptanceReceipt commit accept
  the second report without a special-case bypass.

### 18.2 Fail-closed inputs

- missing, occupied, duplicate, oversized, or drifting independent evidence
  slot;
- stale context, invalid role, signature, Grant, nonce, quota, deadline,
  checkpoint, image, command, or test-source binding;
- reused execution context or container instance;
- missing, stale, null, unknown, or non-current `previous_report_digest`;
- missing or substituted first trigger, active patch, primary result,
  independent result, report row, or evidence bytes;
- a second independent result or third composition attempt.

### 18.3 Outcomes and recovery

- passing independent result;
- completed non-passing result seals the episode;
- `OUTPUT_LIMIT`, `TIMEOUT`, and `DISK_LIMIT` do not fabricate evidence;
- `STARTED_UNCONFIRMED` reconciles the stored execution rather than rerunning;
- evidence-publication, insert, parent, quota, state, sequence, version,
  COMMIT, COMMIT-ACK, close, cleanup, and lock-release fault injection;
- exact snapshots remain unchanged before proven commit;
- exact committed truth wins after proven commit.

### 18.4 Concurrency and offline verification

- concurrent independent requests have one execution winner;
- concurrent recomposition requests have one report winner;
- byte-identical committed readback is accepted and near-match objects are
  rejected;
- the complete two-report bundle verifies offline;
- tampering any report, receipt, parent, EvidenceRef, evidence payload,
  correlation factor, or public key fails closed.

## 19. Documentation and Evidence Boundaries

After fresh focused and full required-live verification, README and status may
state that the local five-dimension independent-result and recomposition path
is implemented and tested. They must retain as unproven:

- a separately identified external Verifier organization or person;
- real independent-environment reproduction outside the developer machine;
- Acceptor rejection and real external Acceptor signing;
- CLI/MCP/AgentTeams integration;
- registry, clean-cache, final-helper, D8, Day 0, Rich demo, contest delivery,
  award, customer, payment, or commercial validation.

## 20. Acceptance Criteria

This design is complete only when:

1. no public WorkOrder or v0.1 Schema change is required;
2. the episode kind is derived from current authority rather than supplied by
   the caller;
3. independent execution uses the frozen Verifier profile and fresh execution
   identifiers;
4. its result occupies the dedicated independent evidence slot;
5. its exact causal parents include the current first composition trigger;
6. a non-passing closed independent result seals the episode;
7. a Manager-signed recomposition binds the current first report digest;
8. the second report deterministically closes all five evidence dimensions and
   reaches `proof_ready` only after full replay;
9. the existing Acceptance success transaction consumes the second report;
10. crash, concurrency, exact readback, and offline tamper tests pass;
11. focused, candidate, full required-live, static, and cleanup gates pass;
12. documentation keeps local implementation, remote push, external
    verification, human acceptance, Day 0, contest delivery, and commercial
    validation as separate claims.
