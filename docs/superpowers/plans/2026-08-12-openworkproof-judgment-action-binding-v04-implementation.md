# OpenWorkProof Judgment-to-Action Binding v0.4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a backward-compatible v0.4 protocol slice that proves an AI code-delivery action is bound to a customer-signed pre-execution judgment, a Manager-signed action manifest, a deterministic GitHub code-delivery adapter replay, a current verification decision, and—when required—an external authority checkpoint, without claiming that protocol validity is business truth, customer acceptance, payment, or settlement.

**Architecture:** Keep every v0.1–v0.3 signed object, schema, ledger row, and frozen bundle immutable. Add v0.4 sibling models, canonical domains, schemas, and append-only SQLite tables for `JudgmentCommitment`, `ActionBindingManifest`, `BindingDecision`, and optional `AuthorityCheckpoint`. A versioned AgentRequest binds the commitment and manifest before execution; the deterministic `openworkproof/code-delivery-github/0.1` adapter replays the mapping from signed judgment to observed action; acceptance and settlement-readiness use explicit v0.4 routing and fail closed. Delivery packages expose customer-private, diagnostic, and public views with distinct replay claims. The first release remains code-delivery-only and begins with the required-live shutdown-race stability slice.

**Tech Stack:** Python 3.12, Pydantic 2, RFC 8785 JCS, SHA-256, Ed25519/cryptography, SQLite, argparse, MCP SDK, pytest, Git, Docker Buildx, OCI/Docker archives, static HTML.

---

## Execution Rules

- Design authority: `docs/superpowers/specs/2026-08-12-openworkproof-judgment-action-binding-v04-design.md` at the plan commit.
- Compatibility authorities: frozen `specs/v0.1`, `specs/v0.2`, `specs/v0.3`, plus the v0.2 evidence-lifecycle and v0.3 scope-bound design specifications.
- Execute only in `/Users/molin/Project/openWorkProof-scope-bound-verification-v03` on a new implementation branch created from this plan commit. Do not implement in the original `/Users/molin/Project/openWorkProof` checkout.
- For every behavior: add the named failing test, run it and capture the expected RED, add the minimum implementation, rerun the focused test, then run the named regression set.
- Use `model_dump(mode="json") -> mutate -> model_validate()` for tamper cases; do not use `model_copy()` to bypass Pydantic validation.
- Never modify or overwrite a frozen v0.1–v0.3 schema, digest registry, evidence bundle, or candidate inventory.
- Do not refactor an old signed model into a new shared base. Duplicate stable fields into v0.4 siblings where inheritance would change frozen schemas or signing bytes.
- A structurally invalid package fails Layer 1 verification; it is not converted into `UNBOUND`. A semantically contradictory, structurally valid chain may be `UNBOUND`. Missing or unavailable proof is `INDETERMINATE`.
- `BOUND` requires positive evidence; absence of detected error is never sufficient.
- A v0.1–v0.3 history without v0.4 objects is `UNDECIDED` or `INDETERMINATE`, never silently `BOUND`.
- MCP remains read-only for v0.4 signing authority. Acceptor and Verifier private keys stay in external/offline signers.
- Do not add a dashboard, hosted SaaS, blockchain, payment rail, automatic settlement, general policy language, a second domain adapter, or LLM-as-truth.
- Do not claim customer use, SOW, deposit, acceptance, settlement, upstream adoption, production deployment, or revenue from local tests or documents.
- Use `apply_patch` for source/document changes. Commit only after each task's focused and regression commands are green.
- Record checkpoints after Tasks 1, 5, 10, 14, and 16 with commit, changed paths, observed RED, focused GREEN, regression result, warnings, unresolved risks, and worktree status.

## Resolved Implementation Decisions

1. v0.4 uses new canonical version `0.4` and new signed domains: `judgment-commitment`, `action-binding-manifest`, `authority-checkpoint`; `binding-decision` uses explicit detached verifier signatures like existing verification decisions.
2. `JudgmentCommitment` is signed by the WorkOrder-designated Customer Acceptor before action and intentionally does not include a WorkOrder digest. The manifest commit transaction proves signer authority against the WorkOrder.
3. `ActionBindingManifest` activates v0.4 for one WorkOrder without changing the historical WorkOrder schema. Exactly one current manifest is allowed; supersession is append-only and binds current id/digest.
4. `AgentRequestV04` is a sibling model, not an in-place extension of historical `AgentRequest`. Its digest is nested in the existing receipt path, so the receipt inherits the commitment/manifest binding without relying on metadata.
5. The first adapter id is exactly `openworkproof/code-delivery-github/0.1`. It accepts canonical data and Git-derived facts, never executes arbitrary customer code as a trusted mapper and never uses an LLM to infer missing intent.
6. `BindingDecision` has three outcomes: `BOUND`, `UNBOUND`, `INDETERMINATE`. Reason codes are fixed, sorted, unique, and outcome-compatible.
7. `AuthorityCheckpoint` is required only by a high-risk binding profile. Its truth is as-of a signed time/revision; resolver failure cannot produce `BOUND`.
8. v0.4 uses parallel tables: `judgment_commitments_v04`, `action_binding_manifests_v04`, `action_binding_manifest_parents_v04`, `binding_decisions_v04`, `binding_decision_parents_v04`, `authority_checkpoints_v04`, and `authority_checkpoint_parents_v04`.
9. Every v0.4 write uses target lock, `BEGIN IMMEDIATE`, stage/validate/commit, exact readback after success or ACK loss, idempotent identical replay, zero-write conflict rejection, and committed-truth preservation under cleanup faults.
10. Acceptance opens only when current v0.3 verification is `VERIFIED`, current v0.4 binding is `BOUND`, all identities/digests match, and required checkpoint is current. Settlement state is named `READY_FOR_SETTLEMENT_REVIEW`, never `paid` or `settled`.
11. Customer-private packages support full binding replay. Diagnostic and public views must say replay is unavailable when required private inputs are absent.
12. Commercial collateral is a falsifiable pilot hypothesis: RMB 30,000–50,000 including tax, 50% deposit, one real Issue/repository/baseline/Agent change/Customer Acceptor, with no revenue claim before external evidence exists.

## File Map

### Create

- `src/openworkproof/binding.py`
- `src/openworkproof/binding_transactions.py`
- `src/openworkproof/authority.py`
- `src/openworkproof/adapters/__init__.py`
- `src/openworkproof/adapters/code_delivery_github.py`
- `src/openworkproof/schemas/v0.4/judgment-commitment.schema.json`
- `src/openworkproof/schemas/v0.4/action-binding-manifest.schema.json`
- `src/openworkproof/schemas/v0.4/binding-decision.schema.json`
- `src/openworkproof/schemas/v0.4/authority-checkpoint.schema.json`
- `src/openworkproof/schemas/v0.4/schema-registry.json`
- Matching frozen files under `specs/v0.4/`
- `tests/test_binding_models_v04.py`
- `tests/test_binding_schema_v04.py`
- `tests/test_judgment_transactions_v04.py`
- `tests/test_binding_manifest_transactions_v04.py`
- `tests/test_binding_gateway_v04.py`
- `tests/test_code_delivery_binding_v04.py`
- `tests/test_binding_decision_v04.py`
- `tests/test_binding_transactions_v04.py`
- `tests/test_authority_checkpoint_v04.py`
- `tests/test_acceptance_binding_v04.py`
- `tests/test_delivery_package_v04.py`
- `tests/test_binding_interfaces_v04.py`
- `tests/test_binding_adversarial_v04.py`
- `tests/test_binding_holdout_v04.py`
- `tests/test_binding_demo_v04.py`
- `tests/binding-demo/rich-4196/README.md`
- `tests/binding-demo/rich-4196/judgment-input.json`
- `tests/binding-demo/rich-4196/clean-action.json`
- `tests/binding-demo/rich-4196/coherent-resign-attack.json`
- `tests/evidence-bundles/rich-4196-binding-v04-delivery-package.json`
- `docs/pilot/judgment-action-binding-21-day-offer.md`
- `docs/pilot/judgment-action-binding-sow-template.md`
- `docs/pilot/judgment-action-binding-acceptor-checklist.md`
- `docs/pilot/judgment-action-binding-result-template.md`

### Modify

- `src/openworkproof/models.py`
- `src/openworkproof/signing.py`
- `src/openworkproof/schema_registry.py`
- `src/openworkproof/evidence.py`
- `src/openworkproof/policy.py`
- `src/openworkproof/mcp_server.py`
- `src/openworkproof/mcp_transport.py`
- `src/openworkproof/services.py`
- `src/openworkproof/cli.py`
- `src/openworkproof/acceptance.py`
- `src/openworkproof/settlement.py`
- `src/openworkproof/delivery_package.py`
- `src/openworkproof/team_network_client.py`
- `src/openworkproof/__init__.py`
- `pyproject.toml`
- `tests/conftest.py`
- `tests/test_team_network_client.py`
- `tests/test_schema_registry.py`
- `tests/test_cli_transport.py`
- `tests/test_export_evidence_bundles.py`
- `tests/evidence-bundles/verify_evidence_bundle.py`
- `supply-chain/images/trusted-helper/SOURCE_ALLOWLIST`
- `README.md`
- `README_en.md`
- `MCP_SERVER.md`
- `docs/offline-verification.md`
- `docs/status.md`

## Spec Coverage Map

| Approved design area | Implementation tasks |
|---|---|
| Required-live shutdown race and warning classification | Task 1 |
| JudgmentCommitment model, authority and signed invariants | Tasks 2 and 4 |
| v0.4 schemas, registries and compatibility | Task 3 |
| ActionBindingManifest, active/superseding state | Task 5 |
| AgentRequestV04 pre-execution binding and zero-execution deny | Task 6 |
| Deterministic GitHub code-delivery adapter | Task 7 |
| BindingDecision rules, signatures, reason codes | Task 8 |
| Append-only transactions, ACK loss, concurrency and recovery | Task 9 |
| AuthorityCheckpoint chain, fork/rollback and as-of | Task 10 |
| Acceptance and settlement-readiness dual gate | Task 11 |
| Offline replay and three privacy views | Task 12 |
| Python/CLI/MCP read-only interfaces | Task 13 |
| C0/A1–A18, four holdouts, demo and tamper case | Task 14 |
| 21-day paid pilot hypothesis and honest documentation | Task 15 |
| Candidate inventory, portable/full/required-live gates and handoff | Task 16 |

## Task 1: Close the Required-Live Shutdown Race Before Protocol Work

**Files:**

- Modify: `src/openworkproof/team_network_client.py`
- Modify: `tests/test_team_network_client.py`
- Modify: `docs/status.md`

- [x] **Step 1: Create the implementation branch from the approved plan commit**

Run in `/Users/molin/Project/openWorkProof-scope-bound-verification-v03` after the user selects an execution mode:

```bash
test -z "$(git status --porcelain)"
git show HEAD:docs/superpowers/plans/2026-08-12-openworkproof-judgment-action-binding-v04-implementation.md >/dev/null
git show HEAD:docs/superpowers/specs/2026-08-12-openworkproof-judgment-action-binding-v04-design.md >/dev/null
git switch -c codex/judgment-action-binding-v04
git status --short --branch
```

Expected: a clean `codex/judgment-action-binding-v04` branch at the commit containing both approved documents. If the branch already exists, stop and inspect it; do not delete, reset, or reuse it blindly.

- [x] **Step 2: Reproduce the socket close/accept race**

Add a test that repeatedly starts the network client, blocks in `accept()`, closes it from another thread, and records uncaught thread exceptions:

```python
def test_close_while_accepting_has_no_uncaught_thread_exception(
    monkeypatch,
) -> None:
    uncaught: list[BaseException] = []
    monkeypatch.setattr(threading, "excepthook", lambda args: uncaught.append(args.exc_value))
    for _ in range(100):
        client = _started_test_client()
        client.close()
        client.join(timeout=1)
    assert uncaught == []
```

Run:

```bash
./.venv/bin/python -m pytest tests/test_team_network_client.py -q \
  -k close_while_accepting
```

Expected RED: the test captures `AttributeError: 'NoneType' object has no attribute 'accept'` or an equivalent uncaught close-race exception.

- [x] **Step 3: Hold a local socket reference and classify expected close errors**

In the accept loop, copy the socket under the existing synchronization boundary and call `accept()` only on that local object. Treat `EBADF`, `EINVAL`, and the platform-specific closed-socket error as normal only after the stop event is set; re-raise otherwise. Do not swallow unrelated network errors.

- [x] **Step 4: Add deterministic cleanup-warning coverage**

Add tests that close all client/server threads and file handles before temporary directories leave scope. Run focused tests with warnings promoted:

```bash
./.venv/bin/python -W error::pytest.PytestUnhandledThreadExceptionWarning \
  -m pytest tests/test_team_network_client.py -q
./.venv/bin/python -m pytest tests/test_team_network_client.py -q -W error
```

Expected GREEN: no unhandled thread exception. If a macOS temporary-directory warning remains, record the exact warning and owner; do not suppress it globally.

- [x] **Step 5: Run the stability regression set**

```bash
./.venv/bin/python -m pytest \
  tests/test_team_network_client.py \
  tests/test_mcp_server.py \
  tests/test_cli_transport.py -q
git diff --check
```

Expected: zero failures and no unclassified thread exception.

- [x] **Step 6: Commit the P0 fix**

```bash
git add src/openworkproof/team_network_client.py \
  tests/test_team_network_client.py docs/status.md
git commit -m "fix: close team network client without accept race"
```

## Task 2: Add Closed v0.4 Models and Canonical Domains

**Files:**

- Modify: `src/openworkproof/models.py`
- Modify: `src/openworkproof/signing.py`
- Modify: `tests/conftest.py`
- Create: `tests/test_binding_models_v04.py`

- [x] **Step 1: Add model tests before implementation**

Cover valid construction plus empty/sorted/unique/bounds/digest/signature-pairing failures for all four objects and `AgentRequestV04`:

```python
def test_judgment_commitment_requires_nonempty_closed_customer_intent(
    judgment_commitment_v04_dict,
) -> None:
    candidate = copy.deepcopy(judgment_commitment_v04_dict)
    candidate["acceptance_conditions"] = []
    with pytest.raises(ValidationError, match="acceptance_conditions"):
        JudgmentCommitment.model_validate(candidate)

def test_agent_request_v04_requires_exact_commitment_and_manifest_pairs(
    agent_request_v04_dict,
) -> None:
    candidate = copy.deepcopy(agent_request_v04_dict)
    candidate["action_binding_manifest_digest"] = None
    with pytest.raises(ValidationError, match="manifest"):
        AgentRequestV04.model_validate(candidate)
```

Run:

```bash
./.venv/bin/python -m pytest tests/test_binding_models_v04.py -q
```

Expected RED: imports for the new types fail.

- [x] **Step 2: Add exact enums and reason codes**

Add literals/enums for:

```python
BindingOutcome = Literal["BOUND", "UNBOUND", "INDETERMINATE"]
AuthorityStatus = Literal[
    "not_required", "current", "missing", "stale", "forked", "unavailable"
]
```

Add the fixed design-spec reason codes with validators enforcing sorted unique tuples and a closed allowed-code set per outcome.

- [x] **Step 3: Add signed v0.4 sibling models**

Implement:

```python
class JudgmentCommitment(SignedProtocolModel):
    _signed_domain = "judgment-commitment"
    _signed_version = "0.4"
    schema_version: Literal["openworkproof-judgment-commitment/0.4"]
    commitment_id: Digest64
    authority_namespace: Identifier
    subject_id: Identifier
    judgment_kind: Identifier
    judgment_artifact_uri: ProtocolString
    judgment_artifact_digest: Digest64
    normalized_facts_digest: Digest64
    disposition_digest: Digest64
    action_constraint_digest: Digest64
    adapter_id: ProtocolString
    adapter_version: ProtocolString
    adapter_profile_digest: Digest64
    repository: ProtocolString
    source_revision: ObjectId40
    target_branch: ProtocolString
    acceptance_condition_digests: tuple[Digest64, ...]
    excluded_scope_digests: tuple[Digest64, ...]
    required_artifact_digests: tuple[Digest64, ...]
    valid_from: CanonicalUTCTime
    expires_at: CanonicalUTCTime
    created_at: CanonicalUTCTime
    nonce: Digest64

class ActionBindingManifest(SignedProtocolModel):
    _signed_domain = "action-binding-manifest"
    _signed_version = "0.4"
    schema_version: Literal["openworkproof-action-binding-manifest/0.4"]
    binding_manifest_id: Digest64
    work_order_digest: Digest64
    judgment_commitment_id: Digest64
    judgment_commitment_digest: Digest64
    evaluation_scope_id: Digest64
    evaluation_scope_digest: Digest64
    adapter_id: ProtocolString
    adapter_version: ProtocolString
    adapter_profile_digest: Digest64
    allowed_tool_names: tuple[ProtocolString, ...]
    allowed_action_kinds: tuple[Identifier, ...]
    allowed_path_roots: tuple[CanonicalRoot, ...]
    required_test_profile_digests: tuple[Digest64, ...]
    source_revision: ObjectId40
    supersedes_binding_manifest_id: Digest64 | None
    supersedes_binding_manifest_digest: Digest64 | None
    causal_parent_manifest_ids: tuple[Digest64, ...]
    created_at: CanonicalUTCTime
    expires_at: CanonicalUTCTime
    nonce: Digest64

class AuthorityCheckpoint(ProtocolModel):
    schema_version: Literal["openworkproof-authority-checkpoint/0.4"]
    checkpoint_id: Digest64
    authority_namespace: Identifier
    subject_id: Identifier
    monotonic_revision: SafePositiveInt
    current_judgment_commitment_digest: Digest64
    predecessor_checkpoint_digest: Digest64 | None
    effective_at: CanonicalUTCTime
    expires_at: CanonicalUTCTime
    authority_key_id: KeyId
    signature_alg: Literal["Ed25519"]
    signature: Signature
    digest: Digest64

class AgentRequestV04(AgentRequest):
    _signed_domain = "agent-request"
    _signed_version = "0.4"
    schema_version: Literal["openworkproof-agent-request/0.4"]
    judgment_commitment_id: Digest64
    judgment_commitment_digest: Digest64
    action_binding_manifest_id: Digest64
    action_binding_manifest_digest: Digest64
```

Implement `BindingDecisionDraft`, `BindingDecisionSignature`, and `BindingDecision` with the exact fields in design section 6.4: decision/work-order/judgment/manifest/verification ids and digests, ordered receipt id/digest pairs, replay digest, optional checkpoint digest, outcome, closed reason codes, authority status, causal/supersession links, decision time, nonce, detached verifier signatures, and canonical digest. Do not change the old `AgentRequest` or verification decision classes.

- [x] **Step 4: Add canonical/signing domains**

Extend `signing.py` with version-scoped v0.4 canonical and signed domain sets. `AuthorityCheckpoint` uses explicit `authority_key_id` and detached authority signature bytes under `openworkproof/authority-checkpoint/v0.4`, avoiding a second inherited key-id field. Add tests that v0.1–v0.3 signing bytes are unchanged and that cross-domain/cross-version signatures fail.

- [x] **Step 5: Run focused and compatibility tests**

```bash
./.venv/bin/python -m pytest \
  tests/test_binding_models_v04.py \
  tests/test_signing.py \
  tests/test_scope_models_v03.py \
  tests/test_verification_models_v02.py -q
```

Expected: all green; frozen-model schema snapshots remain unchanged.

- [x] **Step 6: Commit the models**

```bash
git add src/openworkproof/models.py src/openworkproof/signing.py \
  tests/conftest.py tests/test_binding_models_v04.py
git commit -m "feat: add judgment action binding v0.4 models"
```

## Task 3: Freeze the v0.4 Schema Registry Without Touching Old Bytes

**Files:**

- Modify: `src/openworkproof/schema_registry.py`
- Modify: `pyproject.toml`
- Modify: `tests/test_schema_registry.py`
- Create: `tests/test_binding_schema_v04.py`
- Create: `src/openworkproof/schemas/v0.4/*.json`
- Create: `specs/v0.4/*.json`

- [x] **Step 1: Write version/registry RED tests**

Assert exact object paths, canonical registry bytes, runtime/spec parity, atomic replacement, cleanup after failure, and frozen v0.1–v0.3 digests:

```python
def test_v04_registry_contains_only_approved_binding_objects() -> None:
    registry = load_registry("0.4")
    assert [item["object_type"] for item in registry["schemas"]] == [
        "action-binding-manifest",
        "authority-checkpoint",
        "binding-decision",
        "judgment-commitment",
    ]
```

Run:

```bash
./.venv/bin/python -m pytest \
  tests/test_binding_schema_v04.py tests/test_schema_registry.py -q \
  -k 'v04 or frozen'
```

Expected RED: version `0.4` is unknown.

- [x] **Step 2: Register v0.4 factories and package data**

Add `V04_OBJECT_PATHS`, `V04_SCHEMA_FACTORIES`, version maps, and `schemas/v0.4/*.json` package data. Do not add unchanged old objects to v0.4 unless the registry test explicitly requires them.

- [x] **Step 3: Generate into temporary directories and compare**

```bash
tmp_runtime="$(mktemp -d)"
tmp_specs="$(mktemp -d)"
./.venv/bin/python -m openworkproof.schema_registry \
  --version 0.4 --output "$tmp_runtime"
./.venv/bin/python -m openworkproof.schema_registry \
  --version 0.4 --output "$tmp_specs"
diff -ru "$tmp_runtime" "$tmp_specs"
```

Expected: identical canonical output.

- [x] **Step 4: Install exact generated bytes and freeze hashes**

Use `apply_patch` to add the generated JSON bytes to runtime and `specs/v0.4`, then add reviewed SHA-256 anchors to `schema_registry.py`.

- [x] **Step 5: Run registry and package regressions**

```bash
./.venv/bin/python -m pytest \
  tests/test_binding_schema_v04.py \
  tests/test_schema_registry.py \
  tests/test_package.py -q
./.venv/bin/python -m pip check
git diff --check
```

- [x] **Step 6: Commit the frozen schema**

```bash
git add src/openworkproof/schema_registry.py \
  src/openworkproof/schemas/v0.4 specs/v0.4 \
  pyproject.toml tests/test_binding_schema_v04.py tests/test_schema_registry.py
git commit -m "feat: freeze judgment binding v0.4 schemas"
```

## Task 4: Commit Customer JudgmentCommitments Append-Only

**Files:**

- Modify: `src/openworkproof/evidence.py`
- Create: `src/openworkproof/binding_transactions.py`
- Create: `tests/test_judgment_transactions_v04.py`

- [x] **Step 1: Add transaction RED tests**

Cover valid commit, wrong role/key, invalid signature, expired window, duplicate nonce, same-id/different-payload conflict, identical idempotent replay, pre-COMMIT zero write, ACK loss exact readback, and cleanup failure.

```python
def test_commit_judgment_rejects_manager_signature_with_zero_writes(case) -> None:
    before = snapshot_all_tables(case.connection)
    with pytest.raises(BindingInputError, match="Acceptor"):
        commit_judgment_commitment(case.connection, case.manager_signed_judgment, case.context)
    assert snapshot_all_tables(case.connection) == before
```

Run:

```bash
./.venv/bin/python -m pytest tests/test_judgment_transactions_v04.py -q
```

Expected RED: table/function imports fail.

- [x] **Step 2: Add the append-only table**

Add `judgment_commitments_v04` with unique id, digest, nonce, signer key, canonical JSON, committed timestamp, and no update/delete API. Add only indexes required by WorkOrder-independent commitment lookup and signer/nonce uniqueness.

- [x] **Step 3: Implement the existing transaction pattern**

Implement `commit_judgment_commitment()` using the same target-lock, `BEGIN IMMEDIATE`, fault injection, commit/readback exception taxonomy, and exact canonical row comparison as v0.3 verification transactions.

- [x] **Step 4: Run focused and ledger regressions**

```bash
./.venv/bin/python -m pytest \
  tests/test_judgment_transactions_v04.py \
  tests/test_scope_transactions_v03.py \
  tests/test_verification_transactions_v03.py \
  tests/test_replay.py -q
```

- [x] **Step 5: Commit the transaction**

```bash
git add src/openworkproof/evidence.py src/openworkproof/binding_transactions.py \
  tests/test_judgment_transactions_v04.py
git commit -m "feat: commit customer judgments append only"
```

## Task 5: Commit and Supersede ActionBindingManifests

**Files:**

- Modify: `src/openworkproof/evidence.py`
- Modify: `src/openworkproof/binding_transactions.py`
- Create: `src/openworkproof/binding.py`
- Create: `tests/test_binding_manifest_transactions_v04.py`

- [x] **Step 1: Write pure manifest validation tests**

Test full digest-chain presence, Customer Acceptor signer authority, Manager manifest authority, validity intersection, WorkOrder/Judgment/Scope constraint intersection, sorted parents, and no path/tool/action expansion.

```python
@pytest.mark.parametrize("field", ["allowed_tool_names", "allowed_path_roots", "allowed_action_kinds"])
def test_manifest_cannot_expand_work_order_judgment_intersection(case, field) -> None:
    manifest = case.manifest_dict | {field: [*case.manifest_dict[field], "outside"]}
    with pytest.raises(BindingInputError, match="exceeds"):
        validate_action_binding_manifest(case.context, manifest)
```

- [x] **Step 2: Write active/supersession transaction tests**

Cover first active manifest, stale supersedes id/digest, missing parent, concurrent double winner, exact idempotent replay, and two different payloads for one id.

- [x] **Step 3: Add manifest tables and pure validator**

Add current/append-only relationships without a mutable `active` flag. Derive current as a committed manifest not superseded by a valid child. Reject forks and ambiguous current state.

- [x] **Step 4: Implement commit/readback**

Implement `commit_action_binding_manifest()` with authority verification against the WorkOrder key bindings and committed Judgment/Scope rows. It must not accept a merely well-formed, uncommitted object.

- [x] **Step 5: Run the focused transaction suite**

```bash
./.venv/bin/python -m pytest \
  tests/test_binding_manifest_transactions_v04.py \
  tests/test_judgment_transactions_v04.py \
  tests/test_scope_transactions_v03.py -q
```

- [x] **Step 6: Record checkpoint and commit**

```bash
git add src/openworkproof/evidence.py src/openworkproof/binding.py \
  src/openworkproof/binding_transactions.py \
  tests/test_binding_manifest_transactions_v04.py
git commit -m "feat: bind work orders to customer judgments"
```

## Task 6: Enforce Native Binding Before Any Tool Execution

**Files:**

- Modify: `specs/v0.4/schema-registry.json`
- Modify: `src/openworkproof/binding_transactions.py`
- Modify: `src/openworkproof/delivery_package.py`
- Modify: `src/openworkproof/evidence.py`
- Modify: `src/openworkproof/mcp_server.py`
- Modify: `src/openworkproof/models.py`
- Modify: `src/openworkproof/policy.py`
- Modify: `src/openworkproof/schema_registry.py`
- Modify: `src/openworkproof/schemas/v0.4/schema-registry.json`
- Modify: `src/openworkproof/signing.py`
- Modify: `src/openworkproof/state.py`
- Modify: `src/openworkproof/verification.py`
- Modify: `tests/test_binding_schema_v04.py`
- Create: `specs/v0.4/action-receipt.schema.json`
- Create: `src/openworkproof/schemas/v0.4/action-receipt.schema.json`
- Create: `tests/test_binding_gateway_v04.py`

- [x] **Step 1: Write zero-execution gateway RED tests**

For every rejected request, assert driver call count, quota, receipts/evidence/business output, and all protocol tables remain unchanged except one explicit deny audit receipt where the existing gateway contract requires it:

```python
def test_v04_request_missing_manifest_is_denied_before_execution(case) -> None:
    before = case.snapshot()
    result = execute_run_tests(case.context, request=case.request_without_manifest)
    assert result.decision == "deny"
    assert case.driver.calls == []
    assert case.quota_remaining() == before.quota
    assert case.business_output_rows() == before.business_output_rows
```

Cover missing pair fields, digest substitution, metadata-only reference, expired commitment, stale active manifest, wrong tool/action/path, reused nonce, and missing high-risk checkpoint.

- [x] **Step 2: Add a version-aware request parser/router**

Parse old `AgentRequest` unchanged. Parse v0.4 only when its explicit schema/version is present. Never infer v0.4 from metadata field names.

- [x] **Step 3: Implement `authorize_bound_action()`**

Validate the full WorkOrder → JudgmentCommitment → ActionBindingManifest → request digest chain and the live constraint intersection before invoking any repo/tool driver. Return closed reason codes, not free-form success semantics.

- [x] **Step 4: Bind receipts through the nested request digest**

Prove in tests that replacing only manifest/commitment references changes the request digest and invalidates the receipt signature. Do not copy these references into unsigned metadata as a substitute.

- [x] **Step 5: Run gateway regressions**

```bash
./.venv/bin/python -m pytest \
  tests/test_binding_gateway_v04.py \
  tests/test_policy.py \
  tests/test_mcp_server.py \
  tests/test_run_tests_runner.py \
  tests/test_repo_read_transaction.py -q
```

- [x] **Step 6: Commit the pre-execution gate**

```bash
git add src/openworkproof/models.py src/openworkproof/policy.py \
  src/openworkproof/mcp_server.py tests/test_binding_gateway_v04.py
git commit -m "feat: deny unbound v0.4 actions before execution"
```

## Task 7: Implement the Deterministic GitHub Code-Delivery Adapter

**Files:**

- Create: `src/openworkproof/adapters/__init__.py`
- Create: `src/openworkproof/adapters/code_delivery_github.py`
- Create: `tests/test_code_delivery_binding_v04.py`

- [x] **Step 1: Freeze canonical adapter fixtures**

Add canonical fixtures for Issue snapshot, repository identity, source revision, target branch, acceptance conditions, allowed/excluded paths, required artifacts, test profiles, and action kinds. Add byte-order and Unicode/path normalization tests.

- [x] **Step 2: Add mapping RED tests**

Cover exact clean mapping and explicit mismatches for action parameters, Issue snapshot, normalized facts, acceptance conditions, paths, artifact digests, candidate commit/workspace chain, scope targets, and undeclared side effects.

```python
def test_coherently_resigned_action_outside_judgment_is_unbound(case) -> None:
    attacked = case.resign_internal_chain(changed_path="docs/outside.md")
    replay = replay_code_delivery_binding(attacked)
    assert replay.outcome == "UNBOUND"
    assert replay.reason_codes == ("ACTION_OUTSIDE_APPROVED_SCOPE",)
```

- [x] **Step 3: Implement pure canonicalization**

Expose only these pure typed operations: `normalize_code_delivery_judgment(CodeDeliveryJudgmentInput) -> NormalizedJudgment`, `action_constraint_digest(CodeDeliveryAdapterProfile) -> str`, and `replay_code_delivery_binding(CodeDeliveryReplayInput) -> BindingReplayResult`.

No filesystem/network access occurs inside the mapping function. Callers supply immutable observations and digests.

- [x] **Step 4: Make adapter version drift explicit**

Unknown/mismatched `adapter_id`, `adapter_version`, or `adapter_profile_digest` returns `INDETERMINATE` with the exact drift reason; it never falls back to the latest adapter.

- [x] **Step 5: Run deterministic replay tests**

```bash
./.venv/bin/python -m pytest tests/test_code_delivery_binding_v04.py -q
PYTHONHASHSEED=1 ./.venv/bin/python -m pytest tests/test_code_delivery_binding_v04.py -q
PYTHONHASHSEED=777 ./.venv/bin/python -m pytest tests/test_code_delivery_binding_v04.py -q
```

Expected: identical serialized replay digests in both seeded runs.

- [x] **Step 6: Commit the adapter**

```bash
git add src/openworkproof/adapters tests/test_code_delivery_binding_v04.py
git commit -m "feat: replay github code delivery bindings"
```

## Task 8: Compose and Verify BindingDecisions

**Files:**

- Modify: `src/openworkproof/binding.py`
- Create: `tests/test_binding_decision_v04.py`

- [ ] **Step 1: Add outcome and reason-code RED tests**

Build a decision table covering:

- complete/current/exact replay + `VERIFIED` → `BOUND`;
- explicit action/judgment/mapping mismatch → `UNBOUND`;
- missing evidence/replay unavailable/version drift/authority unavailable → `INDETERMINATE`;
- `UNKNOWN` or `REFUTED` verification never → `BOUND`;
- no reason-code combination may contradict its outcome.

- [ ] **Step 2: Implement decision signing bytes**

Create `binding_decision_signing_bytes()` over the v0.4 canonical decision payload excluding digest and signatures. Validate verifier role, profile binding, sorted unique keys, one signature for standard and two independent signatures for high-risk.

- [ ] **Step 3: Implement the pure composer**

Expose one pure composer with keyword-only inputs: `judgment: JudgmentCommitment`, `manifest: ActionBindingManifest`, `verification: VerificationDecisionV03`, `receipts: tuple[ActionReceiptEnvelope, ...]`, `replay: BindingReplayResult`, `checkpoint: AuthorityCheckpoint | None`, and `request: BindingDecisionDraftRequest`; return `BindingDecisionDraft`.

The composer must recompute all references rather than trust caller-provided reason codes or digests.

- [ ] **Step 4: Add signature and semantic tamper tests**

Use full rebuilds. Include bad signature, extra/missing verifier, duplicated key, reordered receipts, changed replay digest, changed judgment, changed manifest, and validly re-signed but semantically inconsistent action.

- [ ] **Step 5: Run focused regressions**

```bash
./.venv/bin/python -m pytest \
  tests/test_binding_decision_v04.py \
  tests/test_code_delivery_binding_v04.py \
  tests/test_verification_transactions_v03.py -q
```

- [ ] **Step 6: Commit pure decisions**

```bash
git add src/openworkproof/binding.py tests/test_binding_decision_v04.py
git commit -m "feat: compose independently signed binding decisions"
```

## Task 9: Commit BindingDecisions with Concurrency and Recovery

**Files:**

- Modify: `src/openworkproof/evidence.py`
- Modify: `src/openworkproof/binding_transactions.py`
- Create: `tests/test_binding_transactions_v04.py`

- [ ] **Step 1: Add stage/commit/readback RED tests**

Cover incomplete input, current-manifest mismatch, stale verification, stale parent, pre-COMMIT fault, commit ACK loss, readback uncertainty, exact idempotency, same-id conflict, and cleanup fault.

- [ ] **Step 2: Add append-only decision tables**

Store canonical decision JSON and explicit parent/supersession rows. Currentness is derived from one non-superseded valid head. No mutable current flag.

- [ ] **Step 3: Implement transaction validation and exact readback**

Load every referenced object from committed tables, compare exact id/digest, rerun pure validation, insert atomically, commit, and read back the exact canonical row plus parents.

- [ ] **Step 4: Prove one concurrent current winner**

Use two real SQLite connections and a barrier. Both transactions start from the same current parent; exactly one may commit a superseding current decision. The loser must report conflict/committed truth and must not create a fork.

- [ ] **Step 5: Run transaction regressions**

```bash
./.venv/bin/python -m pytest \
  tests/test_binding_transactions_v04.py \
  tests/test_binding_decision_v04.py \
  tests/test_verification_transactions_v03.py -q
```

- [ ] **Step 6: Commit the decision ledger**

```bash
git add src/openworkproof/evidence.py src/openworkproof/binding_transactions.py \
  tests/test_binding_transactions_v04.py
git commit -m "feat: commit binding decisions with exact recovery"
```

## Task 10: Add AuthorityCheckpoint as an Optional High-Risk Trust Root

**Files:**

- Create: `src/openworkproof/authority.py`
- Modify: `src/openworkproof/evidence.py`
- Modify: `src/openworkproof/binding_transactions.py`
- Create: `tests/test_authority_checkpoint_v04.py`

- [ ] **Step 1: Write chain/as-of RED tests**

Cover valid genesis and successor, wrong authority key, non-monotonic revision, skipped/incorrect predecessor, same revision fork, rollback, stale/expired at action time, resolver unavailable, and historical action valid at `occurred_at` despite later review expiry.

```python
def test_historical_action_uses_checkpoint_as_of_occurred_at(case) -> None:
    decision = compose_for_time(case, occurred_at=case.checkpoint.effective_at)
    assert decision.decision == "BOUND"
    assert verify_at(case, now=case.checkpoint.expires_at + timedelta(days=1)).historical_valid
```

- [ ] **Step 2: Implement pure chain validation**

Validate namespace/subject identity, signature, monotonic revision, exact predecessor digest, effective/expiry window, and fork detection. Keep trust-root configuration explicit and external.

- [ ] **Step 3: Commit checkpoints append-only**

Use the same transaction and readback rules. Reject a fork before writing. Resolver unavailability is an input status, never an unsigned replacement checkpoint.

- [ ] **Step 4: Integrate high-risk decision rules**

High-risk profiles require `authority_status == "current"` at the action's as-of time. Missing/unavailable → `INDETERMINATE`; stale/fork/rollback with valid evidence → the approved `UNBOUND` classification and reason.

- [ ] **Step 5: Run focused and checkpoint regressions**

```bash
./.venv/bin/python -m pytest \
  tests/test_authority_checkpoint_v04.py \
  tests/test_binding_decision_v04.py \
  tests/test_binding_transactions_v04.py -q
```

- [ ] **Step 6: Record checkpoint and commit**

```bash
git add src/openworkproof/authority.py src/openworkproof/evidence.py \
  src/openworkproof/binding_transactions.py tests/test_authority_checkpoint_v04.py
git commit -m "feat: validate binding authority checkpoints as of action time"
```

## Task 11: Route Acceptance and Settlement Through the v0.4 Dual Gate

**Files:**

- Modify: `src/openworkproof/acceptance.py`
- Modify: `src/openworkproof/settlement.py`
- Modify: `src/openworkproof/delivery_package.py`
- Create: `tests/test_acceptance_binding_v04.py`

- [ ] **Step 1: Add acceptance-gate RED tests**

Create a cross-product for verification (`VERIFIED`, `REFUTED`, `UNKNOWN`), binding (`BOUND`, `UNBOUND`, `INDETERMINATE`, missing), acceptance (`ACTIVE`, other), and checkpoint state. Only the approved complete tuple opens the gate.

- [ ] **Step 2: Add explicit version routing**

Existing v0.1–v0.3 acceptance remains unchanged unless the WorkOrder explicitly activates a v0.4 binding manifest/profile. A metadata-only judgment reference must not activate v0.4.

- [ ] **Step 3: Require exact same-chain identities**

Before acceptance request/commit, match WorkOrder, SubjectClaim, EvaluationScope, JudgmentCommitment, ActionBindingManifest, VerificationDecisionV03, BindingDecision, and optional checkpoint by exact id/digest/currentness.

- [ ] **Step 4: Rename the v0.4 readiness result**

Add `READY_FOR_SETTLEMENT_REVIEW` as the only positive v0.4 settlement-readiness state. It must require `EffectiveAcceptance.ACTIVE` and required commercial evidence references. The summary copy must explicitly say no payment or settlement is proven.

- [ ] **Step 5: Run acceptance regressions**

```bash
./.venv/bin/python -m pytest \
  tests/test_acceptance_binding_v04.py \
  tests/test_acceptance_v03.py \
  tests/test_acceptance.py \
  tests/test_settlement_readiness.py -q
```

- [ ] **Step 6: Commit dual-gate routing**

```bash
git add src/openworkproof/acceptance.py src/openworkproof/settlement.py \
  src/openworkproof/delivery_package.py tests/test_acceptance_binding_v04.py
git commit -m "feat: gate acceptance on verified bound work"
```

## Task 12: Export and Replay v0.4 Packages with Honest Privacy Views

**Files:**

- Modify: `src/openworkproof/delivery_package.py`
- Modify: `tests/evidence-bundles/verify_evidence_bundle.py`
- Create: `tests/test_delivery_package_v04.py`

- [ ] **Step 1: Add package RED tests**

Cover customer-private full replay, diagnostic/public replay unavailability, unsafe paths/symlinks/hardlinks, oversized input, manifest single-byte tamper, object substitution, reordered history, missing adapter input, and v0.1–v0.3 package compatibility.

- [ ] **Step 2: Add version-aware protocol objects and manifest entries**

Customer-private contains commitment, manifest, complete decision history, bound receipts, adapter profile/replay inputs, checkpoint chain when required, verification/scope/acceptance history, and a deterministic replay command.

- [ ] **Step 3: Implement view-specific assertions**

Diagnostic/public packages must serialize:

```json
{"binding_replay":"unavailable_in_this_view"}
```

when private artifacts are absent. They must not expose private Issue text, paths, test names, customer keys, or commercial evidence.

- [ ] **Step 4: Keep Layer 1 and Layer 2 outcomes separate**

Package signature/chain failure returns package verification failure. Only after Layer 1 passes may the binding replay return `BOUND`, `UNBOUND`, or `INDETERMINATE`.

- [ ] **Step 5: Run package regressions**

```bash
./.venv/bin/python -m pytest \
  tests/test_delivery_package_v04.py \
  tests/test_delivery_package_v03.py \
  tests/test_delivery_package_v02.py \
  tests/test_export_evidence_bundles.py -q
```

- [ ] **Step 6: Commit offline replay**

```bash
git add src/openworkproof/delivery_package.py \
  tests/evidence-bundles/verify_evidence_bundle.py \
  tests/test_delivery_package_v04.py
git commit -m "feat: replay judgment binding from private delivery packages"
```

## Task 13: Expose One Service Contract Through Python, CLI, and Read-Only MCP

**Files:**

- Modify: `src/openworkproof/services.py`
- Modify: `src/openworkproof/cli.py`
- Modify: `src/openworkproof/mcp_server.py`
- Modify: `src/openworkproof/mcp_transport.py`
- Modify: `src/openworkproof/__init__.py`
- Modify: `tests/test_cli_transport.py`
- Create: `tests/test_binding_interfaces_v04.py`

- [ ] **Step 1: Write interface-contract RED tests**

Cover exact JSON shape, exit codes, stdout/stderr separation, invalid payload, missing ledger/key context, deterministic ordering, and parity across Python/CLI/MCP.

- [ ] **Step 2: Add one Python service facade**

Expose validate/compose/verify/history/replay operations. CLI and MCP must call this facade rather than reimplement protocol logic.

- [ ] **Step 3: Add the minimum CLI surface**

Implement exactly:

```text
owp judgment validate
owp binding-manifest validate
owp binding compose
owp binding verify
owp binding history
owp package replay --binding
```

Validation without ledger/key authority must report authority as `not_checked`, not “validly authorized”.

- [ ] **Step 4: Add read-only MCP tools**

Implement exactly:

```text
owp_validate_judgment_commitment
owp_validate_action_binding_manifest
owp_get_binding_status
owp_explain_binding_decision
```

Reject any Acceptor/Verifier private-key argument. MCP validation cannot commit or sign.

- [ ] **Step 5: Run interface regressions**

```bash
./.venv/bin/python -m pytest \
  tests/test_binding_interfaces_v04.py \
  tests/test_cli_transport.py \
  tests/test_mcp_server.py \
  tests/test_v02_interfaces.py \
  tests/test_scope_interfaces_v03.py -q
```

- [ ] **Step 6: Commit interfaces**

```bash
git add src/openworkproof/services.py src/openworkproof/cli.py \
  src/openworkproof/mcp_server.py src/openworkproof/mcp_transport.py \
  src/openworkproof/__init__.py tests/test_cli_transport.py \
  tests/test_binding_interfaces_v04.py
git commit -m "feat: expose read only judgment binding interfaces"
```

## Task 14: Close the Registered Attack Matrix, Holdouts, and Real-Issue Demo

**Files:**

- Create: `tests/test_binding_adversarial_v04.py`
- Create: `tests/test_binding_holdout_v04.py`
- Create: `tests/test_binding_demo_v04.py`
- Create: `tests/binding-demo/rich-4196/*`
- Create: `tests/evidence-bundles/rich-4196-binding-v04-delivery-package.json`
- Modify: `tests/test_export_evidence_bundles.py`

- [ ] **Step 1: Freeze C0 and A1–A18 expectations before execution**

Represent every registered case as immutable test data with case id, attacker keys, changed inputs, responsibility layer, and expected result. At least 16 attacks must be runnable; implement all A1–A18 unless one is explicitly documented as pipeline-invalid before first execution.

- [ ] **Step 2: Implement the coherent re-sign equivalent of `250 -> 2500`**

Use a code-delivery analogue where Manager/Agent/Sidecar re-sign a complete internally valid chain for an action outside the Customer Acceptor's signed constraint. Assert Layer 1 passes and the adapter returns `UNBOUND`.

- [ ] **Step 3: Add required negative-control categories**

Include: chain-only tamper, internally coherent binding mismatch, replay-only mismatch, authority-only boundary, scope omission, metadata-only judgment, missing Acceptor signature, and a clean positive control.

- [ ] **Step 4: Pre-register four independent holdouts**

Before running them, commit four fixtures and expectations in `tests/test_binding_holdout_v04.py`. The runner reports `adjudicated`, `divergent`, or `pipeline-invalid`; it must not rewrite expected outcomes after execution.

- [ ] **Step 5: Build the self-owned Rich #4196 v0.4 demo**

Use the real Issue context but an OpenWorkProof-owned task, judgment, clean action, coherent-resign attack, and delivery package. The README and package metadata must say:

```text
upstream_adoption: not_evidenced
customer_use: not_evidenced
payment: not_evidenced
```

- [ ] **Step 6: Run attack, holdout, and offline tamper gates**

```bash
./.venv/bin/python -m pytest \
  tests/test_binding_adversarial_v04.py \
  tests/test_binding_holdout_v04.py \
  tests/test_binding_demo_v04.py -q
./.venv/bin/python tests/evidence-bundles/verify_evidence_bundle.py \
  tests/evidence-bundles/rich-4196-binding-v04-delivery-package.json
```

Expected: C0 is `BOUND`; each registered attack matches its frozen responsibility-layer result; all four holdouts are reported without post-hoc expectation edits; one-byte tamper fails.

- [ ] **Step 7: Record checkpoint and commit**

```bash
git add tests/test_binding_adversarial_v04.py \
  tests/test_binding_holdout_v04.py tests/test_binding_demo_v04.py \
  tests/binding-demo/rich-4196 \
  tests/evidence-bundles/rich-4196-binding-v04-delivery-package.json \
  tests/test_export_evidence_bundles.py
git commit -m "test: challenge judgment binding with registered attacks"
```

## Task 15: Publish Honest Technical and 21-Day Pilot Documentation

**Files:**

- Modify: `README.md`
- Modify: `README_en.md`
- Modify: `MCP_SERVER.md`
- Modify: `docs/offline-verification.md`
- Modify: `docs/status.md`
- Create: `docs/pilot/judgment-action-binding-21-day-offer.md`
- Create: `docs/pilot/judgment-action-binding-sow-template.md`
- Create: `docs/pilot/judgment-action-binding-acceptor-checklist.md`
- Create: `docs/pilot/judgment-action-binding-result-template.md`

- [ ] **Step 1: Add documentation truth-boundary tests/checks**

Use literal scans to require the exact distinctions and forbid unsupported claims:

```bash
rg -n 'BOUND.*(不等于|does not mean).*(真理|付款|payment|settlement)' \
  README.md README_en.md docs/offline-verification.md
! rg -n '已收定金|已有客户采用|自动结算|guarantees correctness|production proven' \
  README.md README_en.md docs/pilot
```

- [ ] **Step 2: Document the protocol in business-first language**

Explain: OWP provides verifiable execution credentials for Agent delivery; it does not become a payment institution, truth oracle, legal adjudicator, or customer acceptance substitute. Include the v0.4 state/gate diagram and external authority boundary.

- [ ] **Step 3: Create falsifiable pilot materials**

The offer/SOW/checklist/result template must identify User, Payer hypothesis, independent Customer Acceptor, one real Issue/repository/baseline/change, RMB 30,000–50,000 price hypothesis, 50% deposit trigger, eight-person-day/RMB 2,000 experiment cap, success evidence, and stop rules.

- [ ] **Step 4: Keep commercial evidence fields external**

Templates may reference SOW/deposit evidence ids, but protocol status must not manufacture them. Mark every unfilled external state `not_evidenced`.

- [ ] **Step 5: Run documentation and packaging regressions**

```bash
./.venv/bin/python -m pytest \
  tests/test_package.py \
  tests/test_binding_interfaces_v04.py \
  tests/test_delivery_package_v04.py -q
./.venv/bin/python -m compileall -q src tests
git diff --check
```

- [ ] **Step 6: Commit documentation**

```bash
git add README.md README_en.md MCP_SERVER.md docs/offline-verification.md \
  docs/status.md docs/pilot/judgment-action-binding-*.md
git commit -m "docs: publish judgment binding pilot boundaries"
```

## Task 16: Bind the Candidate, Run Every Release Gate, and Hand Off

**Files:**

- Modify: `supply-chain/images/trusted-helper/SOURCE_ALLOWLIST`
- Create at execution time: `supply-chain/images/candidates/$REVISION.json`, where `$REVISION` is the verified 40-character implementation commit selected by the existing inventory builder
- Create: immutable candidate archives/build-contexts under the existing supply-chain layout
- Modify: `docs/status.md`

- [ ] **Step 1: Run the focused v0.4 suite**

```bash
./.venv/bin/python -m pytest \
  tests/test_binding_models_v04.py \
  tests/test_binding_schema_v04.py \
  tests/test_judgment_transactions_v04.py \
  tests/test_binding_manifest_transactions_v04.py \
  tests/test_binding_gateway_v04.py \
  tests/test_code_delivery_binding_v04.py \
  tests/test_binding_decision_v04.py \
  tests/test_binding_transactions_v04.py \
  tests/test_authority_checkpoint_v04.py \
  tests/test_acceptance_binding_v04.py \
  tests/test_delivery_package_v04.py \
  tests/test_binding_interfaces_v04.py \
  tests/test_binding_adversarial_v04.py \
  tests/test_binding_holdout_v04.py \
  tests/test_binding_demo_v04.py -q
```

Expected: zero failures. Record exact counts rather than copying historical numbers.

- [ ] **Step 2: Run frozen compatibility and portable full gates**

```bash
./.venv/bin/python -m pytest \
  tests/test_verification_models_v02.py \
  tests/test_verification_transactions_v02.py \
  tests/test_delivery_package_v02.py \
  tests/test_scope_models_v03.py \
  tests/test_scope_transactions_v03.py \
  tests/test_delivery_package_v03.py -q
./.venv/bin/python -m pytest -q
```

Expected: zero failures. v0.1–v0.3 frozen schema and bundle hashes remain identical.

- [ ] **Step 3: Update the trusted-helper allowlist surgically**

Add only v0.4 runtime modules required for offline verification. Run:

```bash
./.venv/bin/python -m pytest tests/test_image_supply_chain.py -q
```

Expected initial RED after source changes: current candidate inventory no longer uniquely binds the revision. Do not edit an old inventory.

- [ ] **Step 4: Build a new immutable candidate inventory**

Use the repository's `supply-chain/images/prepare_context.py`, existing Buildx commands, OCI-to-Docker conversion path, actual `docker load`/RepoDigest observations, and canonical inventory generator. Name the inventory with the implementation revision and recompute every archive/config/manifest hash.

- [ ] **Step 5: Run candidate supply-chain gates**

```bash
./.venv/bin/python -m pytest tests/test_image_supply_chain.py -q
./.venv/bin/python -m pytest tests/test_candidate_supplychain_integration.py -q
```

Expected: exactly one candidate matches the current revision and both candidate suites have zero failures.

- [ ] **Step 6: Run required-live Docker with strict thread warning policy**

Use the existing required-live environment and command recorded in the current candidate inventory/release ledger. Additionally set:

```bash
PYTHONWARNINGS=error::pytest.PytestUnhandledThreadExceptionWarning
```

Expected: zero failures, zero skips, zero unhandled thread exceptions. Record all remaining warnings by category; do not claim zero unless observed.

- [ ] **Step 7: Run non-test release checks**

```bash
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests
git diff --check
git status --short
docker ps -a --filter name=openworkproof --format '{{.ID}} {{.Names}}'
docker volume ls --filter name=openworkproof --format '{{.Name}}'
```

Expected: dependency/compile/diff checks pass, no unexpected worktree changes, and no project container/volume residue.

- [ ] **Step 8: Obtain independent read-only reviews**

Request one specification-coverage review and one code-quality/security-boundary review. Resolve all Critical and Important findings with focused RED/GREEN evidence. Do not let the implementation author self-certify the holdout expectations.

- [ ] **Step 9: Update status truth and commit the candidate**

Write exact fresh counts, warning categories, candidate revision/hash, demo boundaries, and unresolved risks to `docs/status.md`.

```bash
git add supply-chain/images/trusted-helper/SOURCE_ALLOWLIST \
  supply-chain/images/candidates docs/status.md
git commit -m "build: bind judgment action v0.4 release candidate"
```

- [ ] **Step 10: Final branch handoff without unilateral integration**

```bash
git log --oneline --decorate -20
git status --short --branch
base="$(git merge-base main HEAD)"
printf 'main-only=' && git rev-list --count "$base"..main
printf 'head-only=' && git rev-list --count "$base"..HEAD
```

Present three explicit choices: merge locally to `main`, push the feature branch for review/PR, or keep it local for the paid-pilot slice. Do not merge or push without user direction.

## Final Self-Review Checklist

- [ ] Every approved design section maps to at least one task in the Spec Coverage Map.
- [ ] `JudgmentCommitment` is Acceptor-signed before action and is not circularly bound to WorkOrder.
- [ ] `ActionBindingManifest` proves WorkOrder/Commitment/Scope/adapter authority and unique active state.
- [ ] `AgentRequestV04` and receipt signing bytes natively bind commitment and manifest; metadata does not satisfy the gate.
- [ ] The GitHub code-delivery adapter is deterministic and version-pinned, with no LLM truth path.
- [ ] `BOUND`, `UNBOUND`, and `INDETERMINATE` are separated from Layer 1 package validity, Acceptance, payment, and settlement.
- [ ] AuthorityCheckpoint uses as-of semantics and cannot turn resolver failure into `BOUND`.
- [ ] v0.1–v0.3 schema, signatures, ledgers, and bundles remain byte-compatible.
- [ ] C0/A1–A18 and four pre-registered holdouts have immutable expectations and responsibility layers.
- [ ] All new transactions cover pre-COMMIT zero-write, ACK-loss readback, idempotency, conflict, concurrency, and cleanup failure.
- [ ] Customer-private, diagnostic, and public views make different replay claims and leak no forbidden private fields.
- [ ] The commercial pilot remains a hypothesis until SOW/deposit/Acceptor/decision evidence exists.
- [ ] No placeholder, TODO, fake key, unresolved type name, ellipsis implementation, or untestable success criterion remains in this plan.
- [ ] No task adds a dashboard, payment rail, automatic settlement, blockchain, second adapter, or general policy language.
