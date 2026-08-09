# OpenWorkProof Evidence Lifecycle v0.2 Design

Date: 2026-08-09

Status: Approved design

Implementation target: a new `codex/evidence-lifecycle-v0.2` branch after
written-spec review and implementation-plan approval

## 1. Objective

Close the gap between cryptographically authentic execution and semantically
credible acceptance.

OpenWorkProof v0.1 can bind an identity, authorization, command, execution
context, evidence digest, causal history, composition report, and Acceptor
signature. That is necessary, but it is not sufficient to prove that a test or
other check was capable of falsifying the claim it purported to verify.

Evidence Lifecycle v0.2 adds an append-only verification and acceptance-status
layer:

```text
immutable ActionReceipt
  -> positive and negative evidence arms
  -> signed VerificationDecision: VERIFIED | REFUTED | UNKNOWN
  -> immutable AcceptanceReceipt
  -> append-only AcceptanceTransitionReceipt
  -> deterministic EffectiveAcceptance view
```

The design has five primary outcomes:

1. an exit code alone can never produce v0.2 `VERIFIED`;
2. every v0.2 `VERIFIED` conclusion contains a real falsification control;
3. later evidence can refute or make a previous conclusion unknown without
   rewriting any historical receipt;
4. verification authority remains separate from acceptance authority;
5. a third party can reproduce both the current verification conclusion and
   the effective acceptance state offline.

## 2. Problem Statement and Community Signal

Recent DEV Community feedback converged on four protocol-level objections:

- a signature proves who produced bytes, not that the bytes support the claim;
- a check that never fails can permanently certify a meaningless happy path;
- immutable execution evidence needs a separate, append-only conclusion
  lifecycle such as `VERIFIED -> REFUTED`;
- full cryptographic verification should be concentrated at meaningful trust
  boundaries and high-consequence actions rather than imposed blindly on every
  low-risk call.

Additional feedback emphasized practical adoption:

- record the exact commit, command, selected tests, container, report, and
  artifact rather than only a process exit code;
- independently rerun high-risk checks before acceptance;
- make verification cheap and portable;
- prove the design against a real workload rather than only protocol fixtures;
- target buyers that face a real audit loss, not demonstrations that merely
  need persuasion.

These comments are design signals, not protocol consensus or external
acceptance. Current repository behavior remains the implementation authority.
Where historical notes suggested that negative controls were already complete,
the current source takes precedence.

## 3. Current-State Constraints

The repository already provides:

- six separately bound roles, including Verifier and Acceptor;
- Ed25519 signatures, canonical JCS digests, causal receipt chains, and an
  authoritative SQLite ledger;
- pinned verifier commands, fixed test sources, container-image digests,
  workspace manifests, source and candidate commits;
- immutable evidence staging and publication with crash recovery;
- an independent Verifier rerun and proof recomposition path;
- deterministic CompositionReport and strong-success AcceptanceReceipt;
- atomic acceptance request and commit transactions with COMMIT-ACK readback;
- offline-replayable Rich #4196 and Dify #33013 evidence bundles.

The current implementation does not provide:

- a required negative-control arm for `tests_passed`;
- semantic inspection proving that a report or artifact supports a claim;
- a signed three-state verification conclusion;
- a way to supersede a previous verification conclusion;
- an Acceptor-signed withdrawal or supersession of an AcceptanceReceipt;
- a deterministic current/effective acceptance view;
- v0.1-to-v0.2 migration diagnostics;
- a single portable command that verifies the entire v0.2 lifecycle.

The present v0.1 `evaluate_tests_passed` path accepts a test claim when the
authoritative input is structurally bound and `actual_exit_code` equals
`expected_exit_code`. `test_evidence_digest` proves evidence identity, not the
meaning of its content. v0.2 must not reinterpret this legacy result as
semantic verification.

### 3.1 Release-Truth Prerequisite

Before feature implementation begins, the existing release truth must be
green. The most recent fresh full-suite observation is:

```text
2282 passed, 3 failed, 7 skipped
```

The three failures are:

1. current execution-runner candidate inventory matched zero revisions;
2. current fixed-test-source candidate inventory matched zero revisions;
3. installed distribution metadata reported `0.1.0` while the module and
   protocol package reported `1.1.1`.

M0 must repair these exact failures without weakening candidate-inventory or
package-version assertions. No v0.2 feature work is considered accepted until
the baseline suite is green.

## 4. Scope

This design includes:

1. `VerificationProfileV02`;
2. positive and negative verification arms;
3. `VerificationDecision` with `VERIFIED`, `REFUTED`, and `UNKNOWN`;
4. independent high-risk verification and deterministic result composition;
5. `AcceptanceTransitionReceipt` with withdrawal and supersession;
6. deterministic `EffectiveAcceptance` computation;
7. append-only ledger tables, parent edges, idempotency, and crash recovery;
8. offline CLI and minimal MCP operations;
9. v0.1 read compatibility with explicit migration diagnostics;
10. one real falsification demo based on Rich #4196 or Dify #33013;
11. security, tamper, concurrency, failure-injection, and performance gates;
12. documentation and a portable community conformance bundle.

## 5. Out of Scope

This slice does not add:

- a blockchain or cryptocurrency;
- a mandatory Sigstore, Rekor, Arweave, or other external transparency-log
  dependency;
- a hosted SaaS control plane, billing, customer dashboard, or settlement
  engine;
- automatic legal cancellation of a commercial agreement;
- semantic judgment by an LLM-as-judge;
- arbitrary user-defined predicate code executed inside the trusted verifier;
- automatic migration that invents missing v0.2 negative evidence;
- broad adapters for multiple Agent frameworks;
- production credentials, a named external Acceptor, customer acceptance, or
  commercial-validation claims.

Optional transparency anchoring and framework adapters may be designed after
the portable v0.2 lifecycle is complete.

## 6. Terminology and Separation of Authority

### 6.1 Execution Truth

Execution truth answers:

> Which identity, acting under which authorization, executed which operation
> against which pinned inputs and produced which bytes or failure?

ActionReceipt and the execution ledger remain authoritative for this question.

### 6.2 Verification Truth

Verification truth answers:

> Does the available evidence support, contradict, or fail to determine one
> precisely identified claim?

Only a Verifier may sign VerificationDecision. A Verifier cannot accept or
withdraw delivery.

### 6.3 Acceptance Authority

Acceptance authority answers:

> Does the bound Acceptor accept, withdraw, or replace the delivery in light of
> the current evidence and business rules?

Only the WorkOrder-bound Acceptor may sign AcceptanceReceipt or
AcceptanceTransitionReceipt. An Acceptor does not rewrite verification truth.

### 6.4 Effective Acceptance

EffectiveAcceptance is a deterministic read model, not a signed protocol
object. It combines the latest valid verification decision with the immutable
acceptance history. It never changes stored receipts.

### 6.5 Independent Verifier Authority

The existing WorkOrder-bound Verifier remains the primary Verifier.

For `high_risk`, VerificationProfileV02 also contains one narrowly scoped
independent Verifier binding signed by the Manager. That binding contains the
independent subject ID, Ed25519 public key, key ID, profile ID, WorkOrder
digest, validity interval, and the sole capability to execute and sign the
specified verification profile. It grants no general Agent tool authority and
cannot be reused across profiles.

The primary and independent subject IDs, key IDs, and public keys must differ.
The declared controller and execution-context factors must also differ for the
decision to become VERIFIED. A Manager signature authorizes the limited second
Verifier; it does not by itself prove operational independence, which remains
an evidence-backed IndependenceAssessment.

## 7. VerificationProfileV02

### 7.1 Purpose

VerificationProfileV02 is the Manager-signed contract for how a claim can be
verified or falsified. It prevents a Verifier from choosing an easier test,
changing the target, or omitting the negative control after seeing results.

### 7.2 Closed Fields

The model contains:

- `schema_version = openworkproof-verification-profile/0.2`;
- `profile_id`;
- `work_order_digest`;
- `subject_claim_digest`;
- `subject_kind`, initially closed to `tests_passed`;
- `assurance_level = standard | high_risk`;
- ordered, unique `verifier_bindings`;
- `positive_arm`;
- one or more sorted, unique `negative_arms`;
- `independent_verifier_required`;
- `max_evidence_bytes` and `max_output_bytes`;
- `created_at`, `expires_at`, and `nonce`;
- Manager signer identity and Ed25519 signature.

The first implementation keeps `subject_kind` closed to `tests_passed`.
Artifact-semantic predicates are a later independent slice.

### 7.3 Verification Arm

Each positive or negative arm binds:

- `arm_id` and `arm_kind = positive | negative`;
- `source_commit` and `candidate_commit`;
- optional `mutant_patch_digest` for negative arms;
- `workspace_manifest_digest`;
- `command_digest`;
- `container_image_digest`;
- `fixed_test_source_digest`;
- `expected_exit_codes` as a sorted, unique, non-empty set;
- `expected_outcome = pass | fail`;
- required evidence purposes and result-artifact paths.

The positive arm must have `expected_outcome = pass`. Every negative arm must
have `expected_outcome = fail` and must differ from the positive arm by a
Manager-pinned known-broken commit or mutant patch.

The model rejects a negative arm that is byte-identical to the positive arm,
uses an unbound mutation, omits its expected failure, or changes the fixed test
source after profile signing.

### 7.4 Assurance Levels

`standard` requires:

- one separately keyed Verifier;
- one positive arm;
- at least one negative arm;
- a pinned execution context.

`high_risk` additionally requires:

- the WorkOrder-bound primary Verifier and one Profile-bound, narrowly scoped
  independent Verifier;
- distinct controller and execution-context factors;
- both Verifiers to execute every required arm;
- deterministic result composition and both signatures over the same
  VerificationDecision payload before acceptance.

No assurance level permits exit-code-only verification.

## 8. Verification Evidence

### 8.1 Reuse of Existing Receipts

Each arm execution continues to produce existing ActionReceipt and immutable
evidence publications. v0.2 does not create a second execution ledger.

### 8.2 Required Evidence

For each arm, the committed evidence bundle contains or references:

- exact source, candidate, and optional mutant identities;
- exact command and selected-test manifest;
- container and workspace identities;
- observed exit code and execution status;
- stdout/stderr or a bounded canonical result artifact;
- report digest and required result-artifact digests;
- Verifier identity, key, controller, toolchain, and execution-context factors;
- causal parents linking the profile, triggering work, and prior decisions.

An evidence digest without the corresponding committed bytes is insufficient.

### 8.3 Infrastructure Failure versus Semantic Failure

Infrastructure failures include timeout, disk limit, output limit, unavailable
container, unavailable evidence, or lost execution confirmation. They do not
mean that the subject claim is false.

Semantic failures include:

- positive arm completes but does not satisfy the positive expectation;
- a negative arm unexpectedly satisfies the positive claim;
- a committed artifact contradicts the subject claim;
- a later valid evidence bundle demonstrates that the previous verification
  used the wrong target or insufficient test.

The two classes must use separate closed reason codes.

## 9. VerificationDecision

### 9.1 Closed Fields

VerificationDecision contains:

- `schema_version = openworkproof-verification-decision/0.2`;
- `decision_id`;
- `work_order_digest`;
- `profile_id` and `profile_digest`;
- `subject_claim_digest`;
- sorted arm-result references and their evidence digests;
- `assurance_level`;
- an IndependenceAssessment;
- `decision = VERIFIED | REFUTED | UNKNOWN`;
- sorted, unique closed `reason_codes`;
- `supersedes_decision_id` and `supersedes_decision_digest`, both null only for
  the first decision;
- causal parent receipt IDs and decision IDs;
- `decided_at` and nonce;
- a sorted `verifier_signatures` vector containing the required Verifier
  subject ID, key ID, signature algorithm, and signature over the exact same
  domain-separated decision payload.

Free-form human commentary is not part of the signed decision. User-facing
tools may map reason codes to explanatory text.

### 9.2 Single-Verifier Decision Rules

For `standard` assurance:

| Positive arm | Negative arms | Evidence | Decision |
| --- | --- | --- | --- |
| satisfies expectation | all fail as pinned | complete | VERIFIED |
| contradicts expectation | any | valid contradictory evidence | REFUTED |
| satisfies expectation | any unexpectedly passes | valid contradictory evidence | REFUTED |
| incomplete | incomplete | infrastructure or evidence unavailable | UNKNOWN |

### 9.3 High-Risk Composition Rules

For `high_risk` assurance:

- both independent Verifiers fully verify all arms and sign the same decision
  payload -> `VERIFIED`;
- any valid semantic refutation from either Verifier -> `REFUTED`;
- no semantic refutation, but either Verifier is incomplete -> `UNKNOWN`;
- shared key, controller, or execution context where independence is required
  -> `UNKNOWN` with a shared-factor reason;
- signature-only replay without actual arm execution -> `UNKNOWN`.

For `standard`, `verifier_signatures` contains exactly the WorkOrder-bound
primary Verifier. For `high_risk`, it contains exactly the primary and the
Profile-bound independent Verifier in byte-sorted key order. Missing, extra,
duplicate, or payload-divergent signatures are invalid protocol input and
produce no decision.

One valid contradiction is enough to refute the claim. Absence of complete
support is not enough to refute it and therefore yields `UNKNOWN`.

### 9.4 Invalid Input versus UNKNOWN

Malformed models, unknown signers, invalid signatures, digest drift, duplicate
array entries, incorrect causal parents, and stale authorization are invalid
protocol inputs. They fail closed and produce no VerificationDecision.

UNKNOWN is reserved for a validly authenticated verification attempt that
cannot determine the subject claim.

### 9.5 Supersession

Every decision after the first references the exact current decision it
supersedes. The old decision remains immutable and queryable.

Allowed append-only transitions are:

```text
none -> VERIFIED | REFUTED | UNKNOWN
VERIFIED -> VERIFIED | REFUTED | UNKNOWN
REFUTED -> VERIFIED | REFUTED | UNKNOWN
UNKNOWN -> VERIFIED | REFUTED | UNKNOWN
```

Repeating the exact same signed request and nonce is idempotent. Two different
decisions racing from the same predecessor produce one committed winner; the
loser receives a current-tip conflict and performs no additional writes.

## 10. AcceptanceTransitionReceipt

### 10.1 Purpose

AcceptanceTransitionReceipt lets the Acceptor withdraw or replace an existing
acceptance without mutating it.

### 10.2 Closed Fields

The receipt contains:

- `protocol_version = 0.2`;
- `transition_id`;
- `work_order_digest`;
- target `acceptance_id` and digest;
- target latest VerificationDecision ID and digest;
- `transition = withdrawn | superseded`;
- closed `reason_code`;
- optional replacement AcceptanceReceipt ID and digest, required only for
  `superseded`;
- causal parents;
- `decided_at`, nonce, bound Acceptor identity, and signature.

Initial reason codes are:

- `EVIDENCE_REFUTED`;
- `EVIDENCE_UNKNOWN`;
- `SCOPE_CHANGED`;
- `REPLACED_DELIVERY`;
- `MANUAL_WITHDRAWAL`.

### 10.3 Authority Rules

- Only the WorkOrder-bound Acceptor may sign the transition.
- A Verifier cannot withdraw acceptance.
- A Manager cannot substitute for the Acceptor.
- `superseded` requires an already committed replacement acceptance bound to
  the same WorkOrder.
- A withdrawn acceptance cannot become active again. A new AcceptanceReceipt
  is required.
- Duplicate, stale, cross-WorkOrder, or incorrectly signed transitions fail
  closed with zero writes.

## 11. EffectiveAcceptance

EffectiveAcceptance is computed from the validated ledger prefix.

The read model is:

```text
NONE        no committed AcceptanceReceipt
ACTIVE      latest acceptance is not withdrawn or superseded and latest
            VerificationDecision is VERIFIED
SUSPENDED   an acceptance exists, but latest verification is UNKNOWN or
            REFUTED, or the required current verification is missing
WITHDRAWN   the target acceptance has a valid withdrawal transition
SUPERSEDED  the target acceptance has a valid supersession transition
```

SUSPENDED is a fail-closed operational status, not an Acceptor signature and
not an assertion that a legal contract was automatically cancelled.

Acceptance creation in v0.2 requires the exact current VERIFIED decision.
Acceptance readback becomes SUSPENDED immediately when a valid later decision
is UNKNOWN or REFUTED. The Acceptor may then withdraw or replace the
acceptance.

## 12. End-to-End Flow

1. Manager signs VerificationProfileV02 before execution results are known.
2. Agent execution produces existing receipts and evidence.
3. Primary Verifier executes the positive arm and all negative arms in the
   pinned context.
4. High-risk profiles require the Profile-bound independent Verifier to
   execute the same profile in an independent context.
5. The ledger validates and atomically commits each Verifier's arm-result
   facts.
6. The system produces the exact canonical VerificationDecision signing draft;
   every required Verifier signs those same bytes, and the decision transaction
   validates all signatures before commit.
7. Acceptor may sign AcceptanceReceipt only against the exact current VERIFIED
   decision and authoritative evidence snapshot.
8. A later verification appends a new decision referencing the current one.
9. UNKNOWN or REFUTED makes EffectiveAcceptance SUSPENDED.
10. Acceptor may append a withdrawal or supersession transition.
11. Offline replay reconstructs the complete history and current read model.

## 13. Ledger and Atomicity

### 13.1 New Tables

The minimum new ledger tables are:

- `verification_profiles`;
- `verification_arm_results`;
- `verification_decisions`;
- `verification_decision_parents`;
- `acceptance_transitions`;
- `acceptance_transition_parents`.

Stored canonical JSON remains the replay authority. Indexed columns are
derived conveniences and must be revalidated against canonical bytes.

### 13.2 Transaction Boundaries

Profile commit, arm-result commit, decision commit, and acceptance-transition
commit are separate explicit transactions. Each transaction atomically writes:

- canonical signed object;
- parent edges;
- nonce/idempotency identity;
- sequence and current-tip index;
- any state/version row required for concurrency control.

No transaction updates or deletes a prior signed object.

### 13.3 COMMIT-ACK Recovery

The existing exact-truth readback pattern remains normative:

- proven committed -> return a committed-result error carrying the object;
- proven absent -> report not committed;
- unable to prove either -> report indeterminate and block blind retry.

### 13.4 Concurrency

Transactions use the existing target lock and `BEGIN IMMEDIATE` pattern.
Concurrent decisions from the same predecessor have exactly one winner.
Independent Verifier arm results may commit separately before composition, but
the decision transaction must consume an exact frozen set.

## 14. Backward Compatibility

### 14.1 Read Compatibility

v0.2 tools continue to parse and verify valid v0.1 receipts, composition
reports, acceptances, and evidence bundles.

### 14.2 No Semantic Upgrade

A v0.1 `tests_passed` result cannot become v0.2 VERIFIED merely because its
signature and digest chain are valid. Without a signed v0.2 profile and the
required negative-arm evidence, the migration result is UNKNOWN with
`LEGACY_NEGATIVE_CONTROL_MISSING`.

### 14.3 Migration Report

The offline verifier reports:

- legacy objects successfully authenticated;
- missing v0.2 profile or evidence;
- whether an independent rerun can be scheduled;
- exact fields that prevent v0.2 VERIFIED;
- no invented defaults or synthesized evidence.

## 15. CLI and MCP Surface

### 15.1 CLI

Minimum commands:

```text
owp verify-claim <bundle-or-ledger>
owp acceptance-status <bundle-or-ledger>
```

`verify-claim` emits:

- machine-readable canonical JSON;
- human-readable decision, reasons, arm summary, independence summary, and
  current predecessor;
- a nonzero process status for REFUTED, invalid input, or internal failure;
- a distinct documented process status for UNKNOWN.

`acceptance-status` emits the immutable acceptance history and the computed
EffectiveAcceptance status. It must not describe SUSPENDED as a legal
cancellation.

### 15.2 MCP

Minimum additive operations:

- submit a signed VerificationDecision;
- query the current VerificationDecision;
- query EffectiveAcceptance;
- submit a signed AcceptanceTransitionReceipt.

MCP transport does not become protocol authority. All operations call the same
pure validation and ledger transaction functions as the CLI.

## 16. Failure Taxonomy

Closed protocol failure classes:

### 16.1 Invalid Protocol Input

- invalid or unknown signature;
- canonical-byte or digest mismatch;
- malformed profile, result, decision, or transition;
- wrong role, key, WorkOrder, target, or causal parent;
- stale nonce or stale predecessor;
- missing committed evidence bytes.

Result: fail closed, zero writes, no VerificationDecision.

### 16.2 Semantic Refutation

- positive arm contradicts the subject claim;
- negative arm unexpectedly passes;
- valid artifact or later evidence contradicts the claim;
- valid rerun proves wrong target or insufficient check.

Result: signed REFUTED decision.

### 16.3 Epistemic or Infrastructure Uncertainty

- timeout, disk limit, output limit, unavailable image, unavailable evidence;
- incomplete independent rerun;
- required independence factors are shared;
- valid legacy bundle lacks v0.2 negative evidence.

Result: signed UNKNOWN decision when the attempt itself is validly
authenticated and sufficiently evidenced.

### 16.4 Transaction Uncertainty

- lost COMMIT response;
- readback cannot prove committed or absent;
- cleanup fails after a proven commit.

Result: reuse existing committed/indeterminate exception hierarchy; do not
retry blindly or misreport protocol truth.

## 17. Security and Privacy

- No raw secrets, private keys, environment variables, or unrestricted logs
  enter evidence bundles.
- stdout/stderr evidence remains bounded and follows the existing redaction
  policy.
- Mutant patches are canonical, size-bounded, path-restricted, and signed by
  the Manager through the profile.
- Verifiers execute only pinned commands in pinned containers; profiles cannot
  introduce arbitrary host execution.
- Independence assessment records correlation factors without disclosing
  unnecessary personal data.
- Optional external transparency anchoring, if later added, exports only
  approved digests and metadata.

## 18. Verification and Test Gates

### 18.1 M0 Baseline Gate

- all three known failures fixed without assertion weakening;
- complete existing suite green under its documented local and required-live
  modes;
- package version readback agrees across module, metadata, wheel, and sdist;
- current candidate inventory uniquely matches the implementation revision.

### 18.2 Model and Schema Matrix

- valid standard and high-risk profiles;
- empty, duplicate, identical, unbound, or incorrectly expected negative arms;
- invalid assurance/independence combinations;
- all three decisions and all transition variants;
- primary and Profile-bound independent Verifier authority and signature
  cardinality;
- canonical round-trip and frozen-schema drift checks.

### 18.3 Decision Matrix

- positive pass + negative fail -> VERIFIED;
- positive fail -> REFUTED;
- negative unexpectedly passes -> REFUTED;
- infrastructure failure -> UNKNOWN;
- shared high-risk factors -> UNKNOWN;
- valid contradiction from one independent Verifier -> REFUTED;
- incomplete second Verifier -> UNKNOWN.
- missing, duplicate, extra, or divergent decision signatures -> invalid with
  zero writes.

### 18.4 Tamper Matrix

Tamper and fully rebuild each model through normal validation for:

- profile fields and arm identities;
- evidence bytes and digests;
- signer key and signature;
- decision predecessor and reason codes;
- acceptance target and replacement;
- each new ledger table and parent-edge table.

Replay must fail closed at the correct layer.

### 18.5 Transaction Matrix

- pre-COMMIT injection gives exact zero-write snapshots;
- post-COMMIT ACK loss returns proven committed truth;
- indeterminate readback blocks retry;
- concurrent same-predecessor decisions have one winner;
- duplicate nonce is idempotent only for the exact same request;
- cleanup failure never duplicates signed objects.

### 18.6 Offline and Compatibility Gates

- third-party offline verification using public keys only;
- v0.1 bundle authenticates but reports UNKNOWN for v0.2 semantics;
- v0.2 bundle round-trips through CLI and MCP;
- EffectiveAcceptance recomputes identically from exported history;
- no network call is required for core verification.

### 18.7 Performance Gate

For the same fixed legacy fixture, protocol-only v0.2 parsing, signature,
replay, and read-model overhead may not regress by more than 10% from the v0.1
baseline without an explicit reviewed exception.

Test/container execution time is reported separately from protocol overhead.
Benchmarks publish fixture size, receipt count, environment, p50, and p95 so
the result is reproducible rather than promotional.

## 19. Real Falsification Demo

The first v0.2 demo uses one existing self-contained real-Issue package: Rich
#4196 or Dify #33013.

Required narrative:

1. candidate passes the existing positive test;
2. a Manager-pinned mutant or known-broken version is introduced;
3. the original insufficient check also passes the negative arm, producing
   REFUTED rather than a false VERIFIED;
4. the test is corrected so the candidate passes and the mutant fails;
5. two independent high-risk Verifiers reproduce the result;
6. a new VERIFIED decision enables acceptance;
7. later valid contradictory or incomplete evidence produces REFUTED or
   UNKNOWN and EffectiveAcceptance becomes SUSPENDED;
8. Acceptor appends withdrawal or a replacement acceptance;
9. an offline third party reconstructs the entire history.

The demo proves protocol behavior, not customer adoption, legal settlement,
production deployment, or external acceptance.

## 20. Development Slices

### M0: Restore Release Truth

- fix both candidate-inventory binding failures;
- fix installed-distribution version drift;
- re-run focused, full, packaging, and required-live gates;
- update public status only after fresh evidence.

### M1: v0.2 Models and Schemas

- VerificationProfileV02 and arm model;
- VerificationDecision and reason-code registry;
- AcceptanceTransitionReceipt;
- schema generation and cross-version parsing.

### M2: Positive and Negative Arm Execution

- pinned mutant/known-broken input handling;
- bounded result evidence;
- infrastructure versus semantic failure separation;
- standard-assurance decision derivation.

### M3: Independent Verification Composition

- two-key high-risk execution;
- exact shared decision draft and two-signature collection;
- independence and shared-factor checks;
- deterministic composition of multiple arm results;
- contradiction and incompleteness rules.

### M4: Ledger and Acceptance Lifecycle

- append-only tables and transactions;
- decision supersession;
- acceptance withdrawal and replacement;
- EffectiveAcceptance replay;
- concurrency and COMMIT-ACK recovery.

### M5: Portable Interfaces

- `owp verify-claim`;
- `owp acceptance-status`;
- four minimal MCP operations;
- canonical JSON plus human-readable reporting.

### M6: Real Demo and Benchmark

- one Rich or Dify mutant-based falsification demo;
- offline community conformance bundle;
- protocol-only and end-to-end benchmark;
- explicit non-adoption and non-settlement boundary.

### M7: Compatibility and Release

- complete regression, tamper, transaction, and required-live gates;
- v0.1 migration diagnostics;
- v0.2 protocol and CLI documentation;
- release notes and reproducible evidence inventory.

## 21. Completion Criteria

Evidence Lifecycle v0.2 is complete only when all of the following are true:

1. the M0 baseline is green;
2. no exit-code-only path can produce v0.2 VERIFIED;
3. every VERIFIED fixture contains at least one real negative arm;
4. REFUTED and UNKNOWN are distinguishable in models, transactions, CLI,
   replay, and documentation;
5. high-risk VERIFIED requires two independently keyed and executed results
   plus two valid signatures over one exact decision payload;
6. decisions are append-only and concurrent same-predecessor updates have one
   winner;
7. original acceptance receipts remain byte-identical after withdrawal or
   supersession;
8. EffectiveAcceptance is reproduced identically online and offline;
9. valid v0.1 evidence remains readable but is not silently upgraded;
10. the real-Issue demo covers VERIFIED, REFUTED or UNKNOWN, SUSPENDED, and
    WITHDRAWN or SUPERSEDED;
11. all model, tamper, transaction, failure-injection, compatibility,
    packaging, and required-live gates pass;
12. documentation makes no claim of customer adoption, legal cancellation,
    external acceptance, production deployment, or commercial validation
    without separate evidence.

## 22. Deferred Decisions

The following are deliberately deferred rather than left ambiguous inside
this slice:

- which Agent framework receives the first adapter;
- whether optional transparency anchoring uses Sigstore/Rekor, Arweave, or
  another backend;
- artifact-semantic predicate types beyond `tests_passed`;
- hosted policy management and enterprise dashboards;
- commercial pricing and customer-specific retention policies.

Each requires its own evidence, design approval, and implementation plan.
