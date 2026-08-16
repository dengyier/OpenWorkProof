# OpenWorkProof Verification Integrity v0.5 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add machine-verifiable population integrity and negative-control integrity to OpenWorkProof so a v0.5 decision can distinguish a complete verification, a surviving counterexample, and an untrustworthy verification boundary without changing any v0.1-v0.4 object or signing byte.

**Architecture:** Add v0.5 sibling Profile, Arm Result, and Decision models around the committed v0.3 Evaluation Scope. Keep pure integrity computation in a new `integrity.py` module; keep authority, append-only commit, concurrency, and exact readback in the existing verification transaction layer; extend the existing version routers, Delivery Package, CLI, and read-only MCP surfaces. The first adapter is deliberately closed to Git scope and Python/pytest collection, with structured failure signatures rather than free-form logs.

**Tech Stack:** Python 3.12, Pydantic v2, RFC 8785 JCS, Ed25519, SQLite append-only ledgers, pytest, Git, Docker Buildx, OCI/Docker archives.

---

## Execution Rules

1. Work in `/Users/molin/Project/openWorkProof` on `main`; do not create or delete another branch unless the user changes this decision.
2. Start from the plan commit and a clean worktree. Never overwrite user changes, historical inventories, evidence bundles, or frozen schemas.
3. For every behavior change: write the named test, run it and record RED, implement the minimum change, then run GREEN.
4. Use `model_dump(mode="json") -> mutate -> model_validate` for semantic tamper tests. Re-sign the rebuilt object when the test is intended to reach semantic validation.
5. Do not modify any file under `src/openworkproof/schemas/v0.1` through `v0.4` or `specs/v0.1` through `v0.4`.
6. A test pass, local package, comment, or public listing is not customer adoption, payment, upstream acceptance, deployment, or legal settlement.
7. Each task ends in one scoped commit after its listed gates pass. Do not push until the user explicitly asks.

## Fixed Design Decisions

- Source specification: `docs/superpowers/specs/2026-08-15-openworkproof-verification-integrity-v05-design.md` at or after commit `16f9de6`.
- v0.5 reuses the committed v0.3 `EvaluationScopeManifest`; there is no v0.5 scope sibling.
- The v0.5 canonical domains are `verification-profile`, `verification-arm-result`, and `verification-decision`. Profile and Arm Result use the generic single-signer helper; Decision retains the existing dedicated multi-Verifier signature set over v0.5 canonical bytes. Nested contracts and observations are covered by their parent signatures and cannot be signed independently.
- Empty population always maps to `UNKNOWN`, never `VERIFIED` and never an invented infrastructure failure.
- `CONTROL_SURVIVED` can produce `REFUTED` only when population integrity is `matched`; mismatched or unavailable controls produce `UNKNOWN`.
- The initial `control_target` set is exactly `semantic_regression` and `required_target_coverage`.
- The first adapters are Git diff closure and pytest collection. Dynamic SaaS streams, LLM judges, Merkle networks, generic policy languages, payment, and settlement are out of scope.

## File Map

### Create

- `src/openworkproof/integrity.py`
- `src/openworkproof/schemas/v0.5/verification-profile.schema.json`
- `src/openworkproof/schemas/v0.5/verification-arm-result.schema.json`
- `src/openworkproof/schemas/v0.5/verification-decision.schema.json`
- `src/openworkproof/schemas/v0.5/schema-registry.json`
- `specs/v0.5/verification-profile.schema.json`
- `specs/v0.5/verification-arm-result.schema.json`
- `specs/v0.5/verification-decision.schema.json`
- `specs/v0.5/schema-registry.json`
- `tests/test_verification_integrity_models_v05.py`
- `tests/test_population_integrity_v05.py`
- `tests/test_control_integrity_v05.py`
- `tests/test_verification_integrity_transactions_v05.py`
- `tests/test_verification_integrity_adapters_v05.py`
- `tests/test_delivery_package_v05.py`
- `tests/test_verification_integrity_interfaces_v05.py`
- `tests/test_acceptance_v05.py`
- `tests/test_verification_integrity_adversarial_v05.py`
- `tests/test_verification_integrity_demo_v05.py`
- `tests/integrity-demo/rich-4196/README.md`
- `tests/evidence-bundles/rich-4196-integrity-v05-delivery-package.json`

### Modify

- `src/openworkproof/models.py`
- `src/openworkproof/signing.py`
- `src/openworkproof/schema_registry.py`
- `src/openworkproof/scope.py`
- `src/openworkproof/evidence.py`
- `src/openworkproof/verification.py`
- `src/openworkproof/acceptance.py`
- `src/openworkproof/settlement.py`
- `src/openworkproof/delivery_package.py`
- `src/openworkproof/services.py`
- `src/openworkproof/cli.py`
- `src/openworkproof/mcp_transport.py`
- `src/openworkproof/__init__.py`
- `pyproject.toml`
- `tests/conftest.py`
- `tests/test_schema_registry.py`
- `tests/test_cli_transport.py`
- `tests/test_export_evidence_bundles.py`
- `tests/evidence-bundles/verify_evidence_bundle.py`
- `README.md`
- `README_en.md`
- `MCP_SERVER.md`
- `docs/offline-verification.md`
- `docs/status.md`
- `supply-chain/images/trusted-helper/SOURCE_ALLOWLIST`

## Spec Coverage Map

| Specification | Implementation tasks |
|---|---|
| v0.1-v0.4 frozen compatibility | 1, 3, 15 |
| Four nested objects and three siblings | 2 |
| Population contract and observation semantics | 4 |
| Control contract and failure-signature semantics | 5 |
| Append-only Profile/Result/Decision truth | 6, 7 |
| Three-state decision matrix | 7 |
| Git/pytest first adapter | 8 |
| Acceptance and settlement routing | 9 |
| Offline packages and privacy | 10 |
| Python/CLI/read-only MCP parity | 11 |
| Fifteen-class adversarial matrix | 12 |
| Self-owned real-Issue demo | 13 |
| Honest documentation and pilot boundary | 14 |
| Candidate inventory and required-live release gates | 15 |
| Independent review and handoff | 16 |

## Task 1: Freeze the Approved Baseline and Compatibility Anchors

**Files:**

- Modify: `tests/conftest.py`
- Create: `tests/test_verification_integrity_models_v05.py`

- [x] **Step 1: Prove repository and package identity**

Run:

```bash
cd /Users/molin/Project/openWorkProof
git status --short --branch
git log -2 --oneline
test "$(git branch --show-current)" = main
test -f docs/superpowers/specs/2026-08-15-openworkproof-verification-integrity-v05-design.md
./.venv/bin/python -m pip check
./.venv/bin/python - <<'PY'
from importlib.metadata import version
import openworkproof
print(openworkproof.__file__)
print(openworkproof.__version__, version("openworkproof"))
assert openworkproof.__version__ == version("openworkproof")
PY
```

Expected: clean worktree on `main`, source and installed distribution versions agree, and the approved design exists. Stop if the worktree contains unrelated changes.

- [x] **Step 2: Record a fresh pre-v0.5 baseline**

```bash
./.venv/bin/python -m pytest \
  tests/test_verification_models_v02.py \
  tests/test_verification_transactions_v02.py \
  tests/test_scope_models_v03.py \
  tests/test_scope_transactions_v03.py \
  tests/test_verification_transactions_v03.py \
  tests/test_binding_models_v04.py \
  tests/test_binding_transactions_v04.py \
  tests/test_schema_registry.py -q
```

Expected: zero failures. Record the actual pass/skip/warning counts; do not copy an older count into documentation.

- [x] **Step 3: Freeze representative golden bytes before adding v0.5**

Add fixtures for one deterministic v0.2 Profile, v0.3 Scope/Profile/Result/Decision, and v0.4 Binding object. Add a test that asserts their literal canonical-byte SHA-256 and signature values. Run the test twice and accept literals only if both runs match.

```bash
./.venv/bin/python -m pytest tests/test_verification_integrity_models_v05.py -q -k frozen
```

Expected RED on the first placeholder literals, then GREEN after replacing only the placeholders with the two-run stable values.

- [x] **Step 4: Commit only the passing baseline tests**

```bash
git add tests/conftest.py tests/test_verification_integrity_models_v05.py
git diff --cached --check
git commit -m 'test: freeze verification integrity baseline'
```

## Task 2: Add Closed v0.5 Models and Signing Domains

**Files:**

- Modify: `src/openworkproof/models.py`
- Modify: `src/openworkproof/signing.py`
- Modify: `tests/conftest.py`
- Modify: `tests/test_verification_integrity_models_v05.py`

- [x] **Step 1: Add import-only RED tests for all absent v0.5 types**

Import and instantiate these absent names inside the test module:

```python
PopulationContractV05
PopulationObservationV05
FailureSignatureV05
ControlContractV05
ControlObservationV05
VerificationIntegrityAssessmentV05
VerificationProfileV05
VerificationArmResultV05
VerificationDecisionDraftV05
VerificationDecisionV05
```

```bash
./.venv/bin/python -m pytest tests/test_verification_integrity_models_v05.py -q -k 'v05 and import'
```

Expected RED: import errors for the v0.5 names. Do not commit while this test is red.

- [x] **Step 2: Add RED invariant tests for the four nested objects**

Cover unknown fields, unsorted/duplicate tuples, count ranges, reduced fractions, empty-set rules, selector/engine mismatch, wrong nested digest, invalid validity windows, non-completed expected failure signatures, fixture/provocation drift, and incompatible control status. Assert exact domain formulas:

```python
assert population_contract_id(contract_payload) == hashlib.sha256(
    rfc8785.dumps({"domain": "openworkproof/population-contract/v0.5", "payload": contract_payload})
).hexdigest()
assert failure_signature_digest(signature) == hashlib.sha256(
    rfc8785.dumps({"domain": "openworkproof/failure-signature/v0.5", "payload": signature})
).hexdigest()
assert control_contract_id(contract_payload) == hashlib.sha256(
    rfc8785.dumps({"domain": "openworkproof/control-contract/v0.5", "payload": contract_payload})
).hexdigest()
```

Run and retain RED before implementation:

```bash
./.venv/bin/python -m pytest tests/test_verification_integrity_models_v05.py -q -k 'contract or observation or signature'
```

- [x] **Step 3: Implement bounded nested models and the exact closed reason-code set**

In `models.py`, add literal aliases and `ProtocolModel` classes. Use the existing `Digest64`, `CanonicalUTCTime`, `EvidenceRef`, and execution-status types. Enforce maximum 4096 population members and bounded non-empty arrays. Use integer numerator/denominator only; require `gcd(numerator, denominator) == 1` for observed non-empty capture.

Add exported pure helpers:

```python
def population_contract_id(contract: PopulationContractV05 | Mapping[str, object]) -> str: ...
def population_member_digest(member_ids: Sequence[str]) -> str: ...
def failure_signature_digest(signature: FailureSignatureV05) -> str: ...
def control_contract_id(contract: ControlContractV05 | Mapping[str, object]) -> str: ...
```

`population_member_digest(())` must return one stable canonical empty-set digest and not an all-zero sentinel.

Define `VerificationIntegrityReasonCode` as exactly:

```text
NO_ELIGIBLE_POPULATION
POPULATION_CAPTURE_FAILED
POPULATION_RULE_DRIFT
POPULATION_ENGINE_DRIFT
POPULATION_DIGEST_MISMATCH
POPULATION_CROSS_ARM_MISMATCH
POPULATION_EVIDENCE_MISSING
CONTROL_CONTRACT_EXPIRED
CONTROL_FIXTURE_DRIFT
CONTROL_PROVOCATION_DRIFT
CONTROL_FAILURE_SIGNATURE_MISMATCH
CONTROL_SURVIVED
CONTROL_EVIDENCE_MISSING
```

Tests must reject unknown codes, duplicates, unsorted codes, and status/code combinations outside the design mapping.

- [x] **Step 4: Implement v0.5 sibling models without changing ancestors**

Add:

```python
class VerificationProfileV05(VerificationProfileV03):
    _signed_version = "0.5"
    schema_version: Literal["openworkproof-verification-profile/0.5"]
    population_contracts: tuple[PopulationContractV05, ...]
    control_contracts: tuple[ControlContractV05, ...]

class VerificationArmResultV05(VerificationArmResultV03):
    _signed_version = "0.5"
    schema_version: Literal["openworkproof-verification-arm-result/0.5"]
    population_observations: tuple[PopulationObservationV05, ...]
    control_observation: ControlObservationV05 | None

class VerificationDecisionV05(VerificationDecisionV03):
    schema_version: Literal["openworkproof-verification-decision/0.5"]
    integrity_assessment: VerificationIntegrityAssessmentV05
```

The corresponding draft has no signature envelope. Profiles require exactly one population contract per Scope selector and one control contract per negative arm. Positive results forbid a control observation; negative results require exactly their own control observation.

- [x] **Step 5: Add version `0.5` to signing helpers**

Extend the version literal and closed maps in `signing.py`. The v0.5 generic single-signer domains are exactly:

```python
_V05_SIGNED_DOMAINS = frozenset(
    {"verification-profile", "verification-arm-result"}
)
```

Keep `verification-decision` in `_V05_CANONICAL_DOMAINS`; its dedicated Verifier signatures cover those canonical bytes and must not route through `sign_payload`. Tests must prove nested contract domains and generic Decision signing are rejected, Profile/Result verify only with version 0.5, a real v0.5 Decision signature verifies against its v0.5 canonical bytes, and Task 1's v0.1-v0.4 golden values remain byte-identical.

- [x] **Step 6: Run focused model and compatibility GREEN**

```bash
./.venv/bin/python -m pytest tests/test_verification_integrity_models_v05.py -q
./.venv/bin/python -m pytest \
  tests/test_verification_models_v02.py tests/test_scope_models_v03.py \
  tests/test_binding_models_v04.py tests/test_schema_registry.py -q
```

- [x] **Step 7: Commit**

```bash
git add src/openworkproof/models.py src/openworkproof/signing.py \
  tests/conftest.py tests/test_verification_integrity_models_v05.py
git diff --cached --check
git commit -m 'feat: add verification integrity v05 models'
```

## Task 3: Freeze and Package the v0.5 Schema Registry

**Files:**

- Modify: `src/openworkproof/schema_registry.py`
- Modify: `pyproject.toml`
- Modify: `tests/test_schema_registry.py`
- Create: `src/openworkproof/schemas/v0.5/*.json`
- Create: `specs/v0.5/*.json`

- [x] **Step 1: Write RED four-object registry tests**

Require version `0.5`, exactly three object schemas plus registry, canonical JSON, runtime/public byte equality, atomic generation, failed-generation rollback, and rejected cross-version lookup. Assert all frozen v0.1-v0.4 digests remain unchanged.

```bash
./.venv/bin/python -m pytest tests/test_schema_registry.py -q -k 'v05 or five_versions'
```

Expected RED: protocol version 0.5 is unknown.

- [x] **Step 2: Register only the three signed sibling schemas**

Add `V05_OBJECT_PATHS`, `V05_SCHEMA_FACTORIES`, `_FROZEN_V05_DIGESTS`, and `_FROZEN_V05_REGISTRY`. Nested object definitions remain `$defs` inside these schemas; do not publish them as independently signed protocol objects.

- [x] **Step 3: Generate twice into independent temporary roots**

```bash
TMP_A="$(mktemp -d)"
TMP_B="$(mktemp -d)"
./.venv/bin/python -m openworkproof.schema_registry --version 0.5 \
  --destination "$TMP_A/runtime" --mirror "$TMP_A/spec"
./.venv/bin/python -m openworkproof.schema_registry --version 0.5 \
  --destination "$TMP_B/runtime" --mirror "$TMP_B/spec"
diff -ru "$TMP_A/runtime" "$TMP_A/spec"
diff -ru "$TMP_A/runtime" "$TMP_B/runtime"
```

Expected: zero diff. Add the exact generated files using `apply_patch`; never copy over frozen version directories.

- [x] **Step 4: Add package data and freeze hashes**

Add `schemas/v0.5/*.json` to `pyproject.toml`. Freeze the observed v0.5 digests only after two deterministic generations agree. Re-run:

```bash
./.venv/bin/python -m pytest tests/test_schema_registry.py tests/test_package.py -q
```

- [x] **Step 5: Commit**

```bash
git add src/openworkproof/schema_registry.py src/openworkproof/schemas/v0.5 \
  specs/v0.5 pyproject.toml tests/test_schema_registry.py
git diff --cached --check
git commit -m 'feat: freeze verification integrity v05 schemas'
```

## Task 4: Compute Population Integrity as Pure Derived Truth

**Files:**

- Create: `src/openworkproof/integrity.py`
- Create: `tests/test_population_integrity_v05.py`
- Modify: `tests/conftest.py`

- [x] **Step 1: Write RED contract-to-scope tests**

Test exact one-to-one selector mapping, selector spec/engine equality, declared members as a non-empty subset of the rule's output, member-kind equality, no duplicate declaration across contracts, and exact union coverage of all source/test Scope members. Include missing contract, duplicate contract, orphan member, delivery-artifact member, and 4097-member cases.

```bash
./.venv/bin/python -m pytest tests/test_population_integrity_v05.py -q -k profile
```

Expected RED: `validate_population_contracts` does not exist.

- [x] **Step 2: Implement profile validation**

Add:

```python
def validate_population_contracts(
    profile: VerificationProfileV05,
    manifest: EvaluationScopeManifest,
) -> None: ...
```

Build rule/member indexes once, compare exact identifiers and digests, and reject invalid input. This function does not return an assessment because malformed signed profile input is not a valid `UNKNOWN` decision.

- [x] **Step 3: Write RED observation assessment tests**

Cover:

- eligible 0 / selected 0 / canonical empty digests => `empty`;
- eligible 400 / selected 0 => `capture_failed`;
- eligible 100 / selected 1 at minimum 1/100 => `matched`;
- 2/4 non-reduced fraction rejected as input;
- unchanged count with changed member digest => `drifted`;
- rule or engine digest drift => `drifted`;
- missing required evidence purpose => `unavailable`;
- selected members not equal declared members => `drifted`;
- cross-arm eligible or selected mismatch => `drifted`.

- [x] **Step 4: Implement deterministic population assessment**

```python
@dataclass(frozen=True, slots=True)
class PopulationAssessmentResult:
    status: Literal["matched", "empty", "capture_failed", "drifted", "unavailable"]
    reason_codes: tuple[VerificationIntegrityReasonCode, ...]

def assess_population_integrity(
    profile: VerificationProfileV05,
    manifest: EvaluationScopeManifest,
    results: Sequence[VerificationArmResultV05],
) -> PopulationAssessmentResult: ...
```

Use closed precedence: missing/unreplayable evidence -> unavailable; rule/engine/digest/cross-arm mismatch -> drifted; empty -> empty; below count/capture thresholds -> capture_failed; otherwise matched. Return sorted unique reason codes.

- [x] **Step 5: Run focused GREEN and commit**

```bash
./.venv/bin/python -m pytest tests/test_population_integrity_v05.py -q
./.venv/bin/python -m pytest tests/test_scope_building_v03.py tests/test_scope_models_v03.py -q
git add src/openworkproof/integrity.py tests/conftest.py \
  tests/test_population_integrity_v05.py
git diff --cached --check
git commit -m 'feat: derive population integrity deterministically'
```

## Task 5: Prove Negative Controls by Exact Failure Signature

**Files:**

- Modify: `src/openworkproof/integrity.py`
- Create: `tests/test_control_integrity_v05.py`
- Modify: `tests/conftest.py`

- [x] **Step 1: Write RED control-contract validation tests**

Require exactly one contract per negative arm, no contract for the positive arm, `fixture_digest == mutant_patch_digest`, exact arm id, valid window, recomputed provocation/failure digests, and unique control ids. Test unknown control target and expired contract rejection.

- [x] **Step 2: Write RED four-status observation tests**

Use this closed truth table:

| Applied fixture | Completed | Target failure | Signature match | Status |
|---|---:|---:|---:|---|
| yes | yes | yes | yes | `proven` |
| yes | yes | no | n/a | `survived` |
| yes | yes | yes | no | `mismatched` |
| no or unavailable | any | any | any | `unavailable` |

Assert dependency/schema/timeout failures cannot be reported as `proven` when the expected signature is semantic regression.

- [x] **Step 3: Implement pure control validation and aggregation**

```python
def validate_control_contracts(profile: VerificationProfileV05) -> None: ...

def assess_control_integrity(
    profile: VerificationProfileV05,
    results: Sequence[VerificationArmResultV05],
) -> ControlAssessmentResult: ...
```

Aggregate with precedence `survived` > `mismatched` > `unavailable`; only all-proven returns `proven`. Validate each observation against its own contract and result timestamp before aggregation.

- [x] **Step 4: Prove stderr and host noise do not affect signatures**

Build two raw executions with different stderr text, absolute paths, hostnames, durations, and temp directories but identical structured fields. Assert identical `FailureSignatureV05` and digest. Change one exit code, reason code, predicate id, or evidence purpose and assert a different digest.

- [x] **Step 5: Run GREEN and commit**

```bash
./.venv/bin/python -m pytest tests/test_control_integrity_v05.py -q
./.venv/bin/python -m pytest tests/test_verification_transactions_v03.py -q -k negative
git add src/openworkproof/integrity.py tests/conftest.py \
  tests/test_control_integrity_v05.py
git diff --cached --check
git commit -m 'feat: verify negative controls by failure signature'
```

## Task 6: Commit v0.5 Profiles and Arm Results Append-Only

**Files:**

- Modify: `src/openworkproof/evidence.py`
- Modify: `src/openworkproof/verification.py`
- Create: `tests/test_verification_integrity_transactions_v05.py`

- [x] **Step 1: Write RED DDL and Profile transaction tests**

Require tables `verification_profiles_v05`, `verification_arm_results_v05`, `verification_decisions_v05`, `verification_decision_parents_v05`, `acceptance_transitions_v05`, and `acceptance_transition_parents_v05`. For Profile commit cover Manager signature/role/grant/nonce/expiry, exact committed v0.3 Scope and WorkOrder/Claim binding, contract validation, idempotency, id conflict, pre-COMMIT zero write, COMMIT-then-raise readback, unavailable readback, cleanup failure, identical concurrency, and UPDATE/DELETE triggers.

- [x] **Step 2: Add parallel v0.5 tables without altering v0.3 DDL**

Each authoritative row stores business id, object digest, canonical JSON blob, signer nonce where applicable, relation ids, and canonical `committed_at`. Add foreign keys to the committed WorkOrder/Scope/Profile family. Add immutable triggers for every v0.5 table. Do not add mutable active/stale flags.

- [x] **Step 3: Implement Profile commit/load**

```python
def commit_verification_profile_v05(
    ledger: Path,
    profile: VerificationProfileV05,
    *,
    fault: _Fault | None = None,
) -> VerificationProfileV05: ...

def load_verification_profile_v05(
    ledger: Path,
    profile_id: str,
) -> VerificationProfileV05: ...
```

Load authoritative WorkOrder, Claim, Scope, keys, grants, and complete Profile history. Recompute contract bindings; do not accept digest-only shadow rows. Exact replay after expiry returns the committed truth because its original committed time remains valid; new objects after expiry are rejected.

- [x] **Step 4: Write RED Arm Result transaction tests**

Cover authorized Verifier signature/binding/time, exact Profile and Scope, complete population observations, positive/negative control cardinality, EvidenceRef availability/digest, result id conflict, stale Profile, old result reuse, all faults, two concurrency modes, and immutable rows.

- [x] **Step 5: Implement Arm Result commit/load**

```python
def commit_verification_arm_result_v05(
    ledger: Path,
    result: VerificationArmResultV05,
    *,
    fault: _Fault | None = None,
) -> VerificationArmResultV05: ...
```

Recompute Profile, Scope, evidence snapshot, population observation validity, and control observation validity inside the transaction. Never trust caller-supplied status alone.

- [x] **Step 6: Run transaction GREEN and compatibility regression**

```bash
./.venv/bin/python -m pytest tests/test_verification_integrity_transactions_v05.py -q -k 'profile or arm'
./.venv/bin/python -m pytest \
  tests/test_scope_transactions_v03.py tests/test_verification_transactions_v03.py \
  tests/test_binding_transactions_v04.py tests/test_replay.py -q
```

- [x] **Step 7: Commit**

```bash
git add src/openworkproof/evidence.py src/openworkproof/verification.py \
  tests/test_verification_integrity_transactions_v05.py
git diff --cached --check
git commit -m 'feat: commit verification integrity evidence'
```

## Task 7: Compose and Commit the Three-State v0.5 Decision

**Files:**

- Modify: `src/openworkproof/integrity.py`
- Modify: `src/openworkproof/verification.py`
- Modify: `tests/test_verification_integrity_transactions_v05.py`

- [x] **Step 1: Write RED decision matrix tests**

Assert these exact outcomes:

```text
matched + proven + positive satisfied + independent + v0.3 satisfied => VERIFIED
matched + survived                                             => REFUTED
empty/capture_failed/drifted/unavailable                       => UNKNOWN
matched + mismatched/unavailable control                       => UNKNOWN
matched + proven + positive contradicted                       => REFUTED
matched + proven + insufficient independence                   => UNKNOWN
```

Invalid profile/result/signature input must raise before any signed draft is returned.

- [x] **Step 2: Implement the assessment composer**

```python
def compose_verification_decision_v05(
    *,
    profile: VerificationProfileV05,
    manifest: EvaluationScopeManifest,
    arm_results: Sequence[VerificationArmResultV05],
    request: DecisionDraftRequest,
    previous_decision: VerificationDecisionV05 | None = None,
) -> VerificationDecisionDraftV05: ...
```

Call the existing v0.3 semantic checks, then population and control assessment. Build sorted unique reason codes and one `VerificationIntegrityAssessmentV05`. Do not call v0.3 composer and copy its final decision blindly; v0.5 owns the precedence table above.

- [x] **Step 3: Write RED Decision transaction and history tests**

Cover exact selected result set, current latest Results, one root, exact supersession, stale parent, fork, cycle, dangling parent, signature/role/time, parent time monotonicity, relation drift, idempotency, conflicting bytes, pre-COMMIT zero write, COMMIT ACK loss, cleanup failure, and identical/conflicting concurrency.

- [x] **Step 4: Implement prepare/commit/load with full-history replay**

```python
def prepare_verification_decision_v05(
    ledger: Path,
    request: DecisionDraftRequest,
) -> VerificationDecisionDraftV05: ...

def commit_verification_decision_v05(
    ledger: Path,
    decision: VerificationDecisionV05,
    *,
    fault: _Fault | None = None,
) -> VerificationDecisionV05: ...
```

Exact ACK readback confirms the exact historical row and parent relation even if a valid child supersedes during the ACK gap; it must not require the committed object still be current.

- [x] **Step 5: Run GREEN and commit**

```bash
./.venv/bin/python -m pytest tests/test_verification_integrity_transactions_v05.py -q
./.venv/bin/python -m pytest \
  tests/test_verification_transactions_v02.py \
  tests/test_verification_transactions_v03.py -q
git add src/openworkproof/integrity.py src/openworkproof/verification.py \
  tests/test_verification_integrity_transactions_v05.py
git diff --cached --check
git commit -m 'feat: commit verification integrity decisions'
```

## Task 8: Observe Eligible and Selected Populations in Git and Pytest

**Files:**

- Modify: `src/openworkproof/scope.py`
- Modify: `src/openworkproof/integrity.py`
- Create: `tests/test_verification_integrity_adapters_v05.py`

- [x] **Step 1: Write RED pytest eligible-versus-selected tests**

Create a committed temporary repository with four test nodes. Enumerate eligible nodes before applying marker/path/node-id filters, then select two. Assert stable sorted node ids, exact counts/digests, 2/4 reduced to 1/2, and EvidenceRefs for eligible and selected populations. Also cover no eligible nodes, selector yielding zero, collection error, timeout, required node omission, plugin autoload disabled, and engine digest drift.

- [x] **Step 2: Add one bounded pytest observation API**

```python
def observe_pytest_population(
    repo: Path,
    *,
    contract: PopulationContractV05,
    source_revision: str,
    candidate_commit: str,
    python_executable: Path,
    selector_args: Sequence[str],
    timeout_seconds: int,
) -> PopulationObservationBuildResult: ...
```

Use two explicit collection phases: eligible collection without the selection arguments and selected collection with the frozen arguments. Canonical identity is pytest node id; do not parse human summary lines as nodes.

- [x] **Step 3: Write RED Git eligible-versus-selected tests**

Cover add/modify/delete/rename, allowlist selection, exclusion, required target, path traversal, symlink, uncommitted content, revision drift, unchanged count with changed identity, and engine digest drift. Eligible is the committed diff closure; selected is the post-rule set.

- [x] **Step 4: Implement Git observation and structured failure signature builder**

```python
def observe_git_population(...) -> PopulationObservationBuildResult: ...

def build_failure_signature(
    *,
    execution_status: str,
    exit_codes: Sequence[int],
    reason_codes: Sequence[str],
    predicate_ids: Sequence[str],
    evidence_purposes: Sequence[str],
) -> FailureSignatureV05: ...
```

The builder rejects stderr, stdout, absolute paths, hostnames, durations, and arbitrary metadata because those fields are outside the signed structure.

- [x] **Step 5: Prove deterministic replay**

Run each adapter test twice with `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, `LC_ALL=C.UTF-8`, and `TZ=UTC`. Assert identical contract/observation/failure digests.

```bash
for run in 1 2; do
  ./.venv/bin/python -m pytest tests/test_verification_integrity_adapters_v05.py -q || exit 1
done
```

- [x] **Step 6: Commit**

```bash
git add src/openworkproof/scope.py src/openworkproof/integrity.py \
  tests/test_verification_integrity_adapters_v05.py
git diff --cached --check
git commit -m 'feat: observe pytest and git populations'
```

## Task 9: Route Acceptance and Settlement to v0.5 Decisions

**Files:**

- Modify: `src/openworkproof/acceptance.py`
- Modify: `src/openworkproof/settlement.py`
- Create: `tests/test_acceptance_v05.py`

- [x] **Step 1: Write RED version-router tests**

Test current v0.5 VERIFIED acceptance, v0.5 UNKNOWN/REFUTED rejection, v0.2/v0.3 unchanged behavior, missing decision, fabricated cross-version digest, ambiguous rows in multiple families, withdraw, supersede, and settlement readiness.

- [x] **Step 2: Extend the closed current-decision resolver**

Add protocol version `0.5` to the internal `CurrentVerificationRecord`. Require exactly one authoritative family match. A v0.5 acceptance transition writes only to v0.5 transition tables and cannot cite a v0.2/v0.3 decision.

- [x] **Step 3: Preserve public business-state semantics**

Keep `NOT_READY`, `READY_FOR_ACCEPTANCE`, `ACCEPTED_FOR_SETTLEMENT`, `SUSPENDED`, `WITHDRAWN`, and `SUPERSEDED`. Do not add automatic payment, escrow, or settlement execution.

- [x] **Step 4: Run GREEN and commit**

```bash
./.venv/bin/python -m pytest \
  tests/test_acceptance_v05.py tests/test_acceptance_v03.py \
  tests/test_acceptance.py tests/test_settlement_readiness.py -q
git add src/openworkproof/acceptance.py src/openworkproof/settlement.py \
  tests/test_acceptance_v05.py
git diff --cached --check
git commit -m 'feat: route acceptance to integrity decisions'
```

## Task 10: Export and Replay v0.5 Delivery Packages

**Files:**

- Modify: `src/openworkproof/delivery_package.py`
- Create: `tests/test_delivery_package_v05.py`
- Modify: `docs/offline-verification.md`

- [x] **Step 1: Write RED package-content and privacy tests**

Customer-private packages must contain Scope, v0.5 Profile, all Results, Decision, keys, eligible/selected population evidence, control fixture digest/provocation evidence, failure signatures, and schema registry. Diagnostic/public views must retain derived status and original object digests while applying their visibility rules.

Across every public package file assert absence of repository absolute paths, private locators, raw fixture bytes, pytest node ids, customer identity, secret patterns, stderr, hostnames, and temp directories.

- [x] **Step 2: Add explicit v0.5 protocol detection**

`_ledger_delivery_protocol` must return exactly one of `0.2`, `0.3`, or `0.5`; dual-family ambiguity is an error. Do not infer v0.5 from optional metadata. (v0.4 is the judgment-to-action binding protocol, not a delivery-package protocol.)

- [x] **Step 3: Implement offline v0.5 export and verification**

Add `_export_delivery_package_v05` and `_verify_v05_delivery_package`. Offline verification must load only package bytes, revalidate canonical schemas/signatures/authority/relations/evidence, recompute population and control assessment, and reproduce the same Decision without repository, network, or source ledger access.

- [x] **Step 4: Add explain and compare derived views**

Explain output must show eligible/selected counts, capture fraction, population status, each control target/status, decision, reason codes, and the boundary that verification evidence does not prove payment or customer acceptance. Compare output must identify rule, engine, population, fixture, provocation, and failure-signature changes.

- [x] **Step 5: Run package, privacy, and historical bundle tests**

```bash
./.venv/bin/python -m pytest tests/test_delivery_package_v05.py -q
./.venv/bin/python -m pytest \
  tests/test_delivery_package_v02.py tests/test_delivery_package_v03.py \
  tests/test_delivery_package_v04.py tests/test_v02_bundles.py -q
```

- [x] **Step 6: Commit**

```bash
git add src/openworkproof/delivery_package.py tests/test_delivery_package_v05.py \
  docs/offline-verification.md
git diff --cached --check
git commit -m 'feat: export verification integrity packages'
```

## Task 11: Expose v0.5 through One Python, CLI, and Read-Only MCP Contract

**Files:**

- Modify: `src/openworkproof/services.py`
- Modify: `src/openworkproof/cli.py`
- Modify: `src/openworkproof/mcp_transport.py`
- Modify: `src/openworkproof/__init__.py`
- Modify: `tests/test_cli_transport.py`
- Create: `tests/test_verification_integrity_interfaces_v05.py`
- Modify: `MCP_SERVER.md`

- [x] **Step 1: Write RED service-version routing tests**

Require `validate_profile`, `commit_arm_result`, `prepare_decision`, `commit_decision`, `build_delivery`, and `audit_delivery` to dispatch exact v0.5 schema versions. Unknown, missing, or ambiguous versions must fail closed; v0.2-v0.4 behavior remains unchanged.

- [x] **Step 2: Extend the service facade first**

Add exact model/transaction dispatch in `OpenWorkProofServices`. Add read-only methods:

```python
validate_population_observation(payload) -> dict
validate_control_observation(payload) -> dict
explain_integrity_package(package: Path) -> dict
```

Do not accept private keys or create signatures in the service, CLI, or MCP transport.

- [x] **Step 3: Extend existing CLI commands rather than adding duplicates**

Update `profile-validate`, `verify-positive`, `verify-negative`, `verify-compose`, `delivery-build`, `audit-replay`, `audit-explain`, and `audit-compare` for v0.5. Add only:

```text
owp integrity-observation validate population.json
owp control-observation validate control.json
```

Exit `0` for valid/satisfied, `1` for malformed/failed operation, `3` for UNKNOWN, and `4` for REFUTED. Always include structured status and reason codes.

- [x] **Step 4: Add two read-only MCP validation tools**

Register `owp_integrity_observation_validate` and `owp_control_observation_validate`; extend `owp_validate_profile` and `owp_run_verification` exact version routing. Assert no MCP tool signs, commits Scope/Profile, accepts delivery, or performs payment.

- [x] **Step 5: Run parity and type-hint gates**

```bash
./.venv/bin/python -m pytest \
  tests/test_verification_integrity_interfaces_v05.py \
  tests/test_cli_transport.py tests/test_scope_interfaces_v03.py \
  tests/test_binding_interfaces_v04.py -q
./.venv/bin/python - <<'PY'
from typing import get_type_hints
import inspect
import openworkproof.mcp_transport as module
for _, value in vars(module).items():
    if inspect.isfunction(value) and value.__annotations__:
        get_type_hints(value, vars(module), vars(module))
PY
```

- [x] **Step 6: Commit**

```bash
git add src/openworkproof/services.py src/openworkproof/cli.py \
  src/openworkproof/mcp_transport.py src/openworkproof/__init__.py \
  tests/test_cli_transport.py tests/test_verification_integrity_interfaces_v05.py \
  MCP_SERVER.md
git diff --cached --check
git commit -m 'feat: expose verification integrity interfaces'
```

## Task 12: Close the Fifteen-Class Adversarial and Recovery Matrix

**Files:**

- Create: `tests/test_verification_integrity_adversarial_v05.py`
- Modify only when a test reveals a defect: v0.5 implementation files from Tasks 2-11

- [x] **Step 1: Encode the exact protocol attack matrix**

Add parameterized cases for all specification section 12 attacks:

1. eligible 400 / selected 0 reported green;
2. zero eligible with non-empty selected;
3. same counts with changed rule digest;
4. same counts with changed member digest;
5. positive/negative population mismatch;
6. changed fixture with reused control id;
7. same failure with changed error/predicate signature;
8. unapplied provocation;
9. dependency/schema/infrastructure-only control failure;
10. Result after Profile expiry;
11. unknown/expired/wrong-role Profile;
12. old Result/Decision reuse after repair;
13. ledger relation/JSON/time/signature tamper;
14. COMMIT occurred and ACK disappeared;
15. public-package private locator/fixture/absolute-path leakage.

- [x] **Step 2: Force semantic tests past signature validation**

For each signed semantic tamper, rebuild the full model and re-sign with the authorized test key. Add a companion bad-signature test so the two error classes cannot be conflated.

- [x] **Step 3: Add full transaction fault and concurrency matrix**

For Profile, Result, and Decision inject insert failure, before-COMMIT, COMMIT failure, COMMIT-then-raise, readback unavailable, and cleanup failure. Snapshot every v0.5 authoritative table. Assert zero writes before COMMIT and exact committed truth afterward. Run identical and same-id-conflicting two-thread cases; identical must be exactly one `committed` plus one `already_committed`.

- [x] **Step 4: Add physical corruption probes**

Directly tamper every v0.5 row family with foreign keys temporarily disabled, then restore them before replay. Cover malformed canonical JSON, validly re-signed wrong authority, relation fork/cycle/dangling edge, noncanonical/inverted committed time, missing evidence, and modified registry/schema bytes. Every load/commit/package replay must fail closed.

- [x] **Step 5: Run the adversarial set three times**

```bash
for run in 1 2 3; do
  ./.venv/bin/python -m pytest tests/test_verification_integrity_adversarial_v05.py -q || exit 1
done
./.venv/bin/python -m pytest \
  tests/test_verification_integrity_models_v05.py \
  tests/test_population_integrity_v05.py tests/test_control_integrity_v05.py \
  tests/test_verification_integrity_transactions_v05.py \
  tests/test_verification_integrity_adapters_v05.py \
  tests/test_delivery_package_v05.py \
  tests/test_verification_integrity_interfaces_v05.py \
  tests/test_acceptance_v05.py \
  tests/test_verification_integrity_adversarial_v05.py -q
```

- [x] **Step 6: Commit only necessary fixes and the matrix**

```bash
git add tests/test_verification_integrity_adversarial_v05.py \
  src/openworkproof/models.py src/openworkproof/signing.py \
  src/openworkproof/scope.py src/openworkproof/integrity.py \
  src/openworkproof/evidence.py src/openworkproof/verification.py \
  src/openworkproof/acceptance.py src/openworkproof/settlement.py \
  src/openworkproof/delivery_package.py src/openworkproof/services.py \
  src/openworkproof/cli.py src/openworkproof/mcp_transport.py
git diff --cached --check
git commit -m 'test: close verification integrity adversarial matrix'
```

Before commit, inspect `git diff --cached --name-only`; remove any file not changed directly to fix a demonstrated test failure.

## Task 13: Build the Self-Owned Rich #4196 Integrity Demo

**Files:**

- Create: `tests/integrity-demo/rich-4196/README.md`
- Create: `tests/test_verification_integrity_demo_v05.py`
- Create: `tests/evidence-bundles/rich-4196-integrity-v05-delivery-package.json`
- Modify: `tests/test_export_evidence_bundles.py`
- Modify: `tests/evidence-bundles/verify_evidence_bundle.py`

- [x] **Step 1: Freeze provenance and claim boundaries**

The README must state:

```yaml
issue_source: https://github.com/Textualize/rich/issues/4196
demo_owner: OpenWorkProof
upstream_adoption: not_evidenced
customer_case: not_evidenced
commercial_validation: not_evidenced
```

Reuse the committed local demo fixture; do not modify the v0.2-v0.4 bundles.

- [x] **Step 2: Demonstrate the population blind spot**

Create one deterministic run where pytest can see multiple eligible tests but the selector chooses zero. Assert the command itself can finish cleanly while v0.5 produces `UNKNOWN / POPULATION_CAPTURE_FAILED`, not VERIFIED.

- [x] **Step 3: Demonstrate control rot**

Use one registered semantic mutant that produces the expected signature and one altered failure cause that still fails but mismatches the signature. Assert `proven` for the first and `UNKNOWN / CONTROL_FAILURE_SIGNATURE_MISMATCH` for the second.

- [x] **Step 4: Demonstrate the repaired full chain**

With complete selected population and exact negative control, commit Profile, positive/negative Results, and VERIFIED Decision. Export a customer-private package and reproduce the Decision offline without Git, ledger, or network.

- [x] **Step 5: Verify the immutable bundle and tamper failure**

```bash
./.venv/bin/python -m pytest tests/test_verification_integrity_demo_v05.py -q
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
  ./.venv/bin/python tests/evidence-bundles/verify_evidence_bundle.py \
  tests/evidence-bundles/rich-4196-integrity-v05-delivery-package.json
```

Expected: `VERIFICATION PASSED`; changing one population identity, control fixture digest, or failure-signature byte fails.

- [x] **Step 6: Commit**

```bash
git add tests/integrity-demo/rich-4196 \
  tests/test_verification_integrity_demo_v05.py \
  tests/evidence-bundles/rich-4196-integrity-v05-delivery-package.json \
  tests/test_export_evidence_bundles.py \
  tests/evidence-bundles/verify_evidence_bundle.py
git diff --cached --check
git commit -m 'test: add verification integrity real-issue demo'
```

## Task 14: Publish Honest Protocol and Pilot Documentation

**Files:**

- Modify: `README.md`
- Modify: `README_en.md`
- Modify: `MCP_SERVER.md`
- Modify: `docs/offline-verification.md`
- Modify: `docs/status.md`

- [x] **Step 1: Add RED documentation assertions**

In the interface/demo tests assert both READMEs mention v0.5 population and control integrity, preserve the three-state boundary, and contain `not_evidenced` language for customer/upstream/commercial status. Assert they do not contain claims of automatic payment, guaranteed correctness, customer adoption, or upstream adoption.

- [x] **Step 2: Update the Chinese and English product explanation**

Explain in business language: v0.3 proves what was selected; v0.5 additionally proves what was eligible before selection and whether a negative control failed for the intended reason. Keep technical object names in a secondary section.

- [x] **Step 3: Document operator commands and failure interpretation**

Update CLI/MCP/offline docs with exact v0.5 commands, exit statuses, package views, reason-code table, and recovery boundaries. State that UNKNOWN is a safe outcome, not a system crash.

- [x] **Step 4: Update status from fresh evidence only**
  （第三轮审计闭环：以 final fresh 结果更新；total 复审通过）

Record exact source revision, package version, protocol versions, focused counts, historical compatibility counts, candidate state, demo result, and:

```yaml
customer_adoption: not_evidenced
paid_sow: not_evidenced
deposit: not_evidenced
upstream_adoption: not_evidenced
commercial_validation: not_evidenced
```

- [x] **Step 5: Run docs/interface gates and commit**

```bash
./.venv/bin/python -m pytest \
  tests/test_verification_integrity_interfaces_v05.py \
  tests/test_verification_integrity_demo_v05.py tests/test_cli_transport.py -q
git diff --check
git add README.md README_en.md MCP_SERVER.md docs/offline-verification.md docs/status.md
git diff --cached --check
git commit -m 'docs: publish verification integrity protocol'
```

## Task 15: Bind the Candidate and Run Every Release Gate

**Files:**

- Modify: `supply-chain/images/trusted-helper/SOURCE_ALLOWLIST`
- Create: `supply-chain/images/candidates/${REV}.json`
- Modify: `docs/status.md`

- [x] **Step 1: Commit the exact trusted-helper source surface**

Add only runtime modules needed by offline v0.5 replay, expected to include `src/openworkproof/integrity.py` plus already allowlisted core files. Do not allowlist CLI, MCP, demo, or documentation sources.

```bash
git add supply-chain/images/trusted-helper/SOURCE_ALLOWLIST
git diff --cached --check
git commit -m 'build: include integrity replay source'
REV="$(git rev-parse HEAD)"
```

- [x] **Step 2: Run portable gates before candidate construction**

```bash
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests
./.venv/bin/python -m pytest -q \
  --ignore=tests/test_candidate_supplychain_integration.py
git diff --check
```

Expected: zero failures. Candidate tests are deferred only until the new committed revision has an inventory.

- [x] **Step 3: Prepare immutable build contexts**

```bash
REV="$(git rev-parse HEAD)"
BUILD_ROOT="$(mktemp -d)"
ARCHIVE_ROOT="$(mktemp -d)"
./.venv/bin/python supply-chain/images/prepare_context.py \
  --revision "$REV" --output-root "$BUILD_ROOT"
```

Inspect the generated context manifests and source hashes before building.

- [x] **Step 4: Build OCI and Docker archives from the same revision**

Use the repository's current candidate build commands and `supply-chain/images/convert_docker_archive.py`; produce execution-test and trusted-helper OCI archives plus Docker v2 archives. Never reuse historical archive hashes, RepoDigests, labels, image IDs, or sizes.

After load/tag, verify live image labels and RepoDigests correspond to `$REV`, and verify zero container/volume residue after probes.

- [x] **Step 5: Create one new candidate inventory**

Use the latest valid `openworkproof-image-candidate-inventory/0.2` file only as a structural reference. Recompute every input hash, archive hash, manifest digest, config digest, image ID, RepoDigest, label, entrypoint, command, byte size, and path. Write only:

```text
supply-chain/images/candidates/$REV.json
```

Do not rewrite a historical inventory.

- [x] **Step 6: Run candidate and required-live gates**
  （第三轮审计闭环：候选按 `a305f72…` 重建，required-live fresh
  3492/0/0 零 warning；total 复审通过）

The candidate/live gates are NOT self-contained without the delivery
artifact root, the live-Docker switch, and the fully-qualified image
reference: running the candidate suites bare yields the non-live subset
(e.g. `172 passed / 1 skipped` for the integration suite) and skips the
live drivers. The exact self-contained commands are:

```bash
export OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT=/Users/molin/Project/openWorkProof-delivery
export OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1
export OPENWORKPROOF_DOCKER_TEST_IMAGE=docker.io/openworkproof/execution-test@sha256:bc35711b843e6e2c479c52d486a1b2ed401cc90c7b15edb52b948206e9157abb
./.venv/bin/python -m pytest tests/test_image_supply_chain.py tests/test_candidate_supplychain_integration.py -q
./.venv/bin/python -m pytest -q \
  -W 'error::pytest.PytestUnhandledThreadExceptionWarning'
```

The `OPENWORKPROOF_DOCKER_TEST_IMAGE` digest must be taken from the
current candidate inventory's fully-qualified image reference after the
candidate rebuild (this round's source changes invalidate the previous
inventory); `OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1` is what turns the
sandbox live drivers on and eliminates the platform-only skips. Current
inventory: `supply-chain/images/candidates/a305f7204053f08312613dddb3a0ce7533ce4806.json`.

Expected: candidate suites zero failures and zero skip; required-live
full suite zero failures and zero skip. If a platform-only skip remains,
stop and resolve it rather than documenting the gate as complete.
Third-round audit Batch E: final counts and the plan's step checkmarks
are refreshed ONLY from the final fresh gate results after all batches
close and the total reviews pass; nothing above is re-checked early.

- [x] **Step 7: Verify package/bundle and cleanup state**

```bash
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
  ./.venv/bin/python tests/evidence-bundles/verify_evidence_bundle.py \
  tests/evidence-bundles/rich-4196-integrity-v05-delivery-package.json
docker ps -aq
docker volume ls -q
find supply-chain/images -name '*.lock' -size 0 -print
```

Expected: bundle passes; no task-created containers, volumes, or locks remain.

- [x] **Step 8: Record measured release truth and commit inventory**
  （第三轮审计闭环：库存 `a305f72…` 已提交，status/checklist 以 final
  fresh 数字更新；total 复审通过）

Update `docs/status.md` with exact commands, counts, duration, warnings, revision, inventory path, archive hashes, and honest external-state boundaries.

```bash
git add "supply-chain/images/candidates/$REV.json" docs/status.md
git diff --cached --check
git commit -m 'build: bind verification integrity candidate'
git status --short --branch
```

The checkpoint must distinguish local release-candidate completion from remote push, deployment, customer acceptance, payment, and upstream adoption.

## Task 16: Independent Review and Main-Branch Handoff

**Files:**

- Modify only for demonstrated defects: files changed by Tasks 2-15
- Modify: this plan, checking only completed steps after evidence exists

- [x] **Step 1: Run an independent specification review**

Review every section of the approved design against code, tests, schemas, package bytes, docs, and release evidence. Report findings with file/line references and Critical/Important/Minor severity. Do not accept the implementer's summary as proof.

- [x] **Step 2: Run an independent quality/security review**

Recheck authority, exact history, COMMIT truth, concurrency, selector blindness, control rot, schema compatibility, privacy leakage, and claim boundaries. Independently rerun at least the focused suite, frozen schema suite, candidate tests, and one offline bundle.

- [x] **Step 3: Fix findings through new RED tests**

For every accepted defect, add the smallest deterministic failing test, observe RED, implement a surgical fix, and rerun the affected and prescribed gates. Commit follow-ups without rewriting prior commits.

- [x] **Step 4: Complete the plan truthfully**

Check a step only after its evidence exists. Run:

```bash
rg -n '^- \[ \]' \
  docs/superpowers/plans/2026-08-15-openworkproof-verification-integrity-v05-implementation.md
./.venv/bin/python - \
  docs/superpowers/plans/2026-08-15-openworkproof-verification-integrity-v05-implementation.md <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding="utf-8")
for token in ("TO" + "DO", "T" + "BD", "PLACE" + "HOLDER", "same as " + "above"):
    assert token not in text, token
PY
git diff --check
git status --short --branch
```

Expected: no unchecked implementation step, no placeholder phrase, and a clean worktree.

- [x] **Step 5: Present remote integration as a separate choice**

Report final local HEAD, origin/main, ahead/behind, commits, exact test counts, inventory, package verification, remaining warnings, and all `not_evidenced` external states. Do not push automatically. Ask the user whether to push `main` only after all reviews pass.

## Plan Self-Review Gate

- [x] Every v0.5 type and reason code in the design appears in an implementation or test task.
- [x] Every one of the fifteen threat cases has an explicit adversarial test.
- [x] Every signed object has canonical model, schema, signing, authority, transaction, history, package, and tamper coverage.
- [x] Every transaction has pre-COMMIT zero-write, COMMIT-ACK, cleanup, exact replay, immutable row, and concurrency coverage.
- [x] Git and pytest adapters distinguish eligible from selected populations.
- [x] `VERIFIED / REFUTED / UNKNOWN` precedence is explicit and tested.
- [x] v0.1-v0.4 schemas, registries, golden bytes, packages, and version routers remain covered.
- [x] Public package privacy and commercial claim boundaries are executable tests, not prose only.
- [x] Candidate inventory is generated only after all source changes are committed.
- [x] No task implements dynamic streams, Merkle infrastructure, LLM judging, payment, settlement execution, EvidenceRequirementBinding, or a maturity dashboard.
