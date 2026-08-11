# OpenWorkProof Scope-Bound Verification v0.3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a backward-compatible Scope-Bound Verification v0.3 protocol slice that proves an Agent code-delivery claim was evaluated against the precommitted source, test, and artifact population, while preserving every v0.1/v0.2 signed object and commercial evidence boundary.

**Architecture:** Add immutable v0.3 models and schemas beside v0.2, put deterministic scope construction and comparison in a new `scope.py`, and use parallel append-only SQLite tables plus an explicit protocol-version router. Existing v0.2 paths remain byte-for-byte valid. Delivery packages gain version-aware replay and three privacy views. CLI and MCP call one service facade; MCP remains read-only for scope operations. A self-owned Rich #4196-derived demo proves the omission attack without claiming upstream adoption.

**Tech Stack:** Python 3.12, Pydantic 2, RFC 8785 JCS, SHA-256, Ed25519/cryptography, SQLite, argparse, MCP SDK, pytest, Docker Buildx, static HTML.

---

## Execution Rules

- Design authority: `docs/superpowers/specs/2026-08-11-openworkproof-scope-bound-verification-v03-design.md` at the plan commit.
- Compatibility authority: `docs/superpowers/specs/2026-08-09-openworkproof-evidence-lifecycle-v0.2-design.md` and frozen `specs/v0.1`, `specs/v0.2` resources.
- Execute in `/Users/molin/Project/openWorkProof-scope-bound-verification-v03` on branch `codex/scope-bound-verification-v03`; never implement in the dirty original checkout.
- For every behavior: write the named test, run it and observe the named failure, add the minimum implementation, rerun the focused test, then run the task regression set.
- Never modify a frozen v0.1/v0.2 schema file, digest, registry, historical evidence bundle, or candidate inventory.
- Do not refactor v0.2 models into shared bases: a Pydantic schema-shape change would threaten frozen v0.2 schema hashes. Duplicate the stable v0.2 fields into v0.3 models and add only v0.3 fields.
- Do not weaken, skip, xfail, deselect, or delete an existing test to make a gate green.
- Keep v0.3 scope insufficiency as `UNKNOWN`; only a valid surviving negative mutation may produce `REFUTED`.
- Do not add a general selector plugin framework, LLM judge, policy registry, transparency network, dashboard scheduler, payment, custody, clearing, arbitration, or non-code dynamic source.
- Do not claim customer use, payment, acceptance, settlement, upstream adoption, MCP/A2A endorsement, production deployment, or market validation from local technical completion.
- Use `apply_patch` for source/document edits. Commit only after the focused and regression commands in the task are green.
- After Tasks 6, 11, and 15, record a checkpoint containing commits, changed paths, observed RED, focused GREEN, regression result, unresolved risks, and worktree status.

## Resolved Implementation Decisions

1. `scope_id` is the SHA-256 of JCS bytes for domain `openworkproof/evaluation-scope/v0.3` over the manifest payload excluding `scope_id` and the complete signature envelope (`digest`, `signature_alg`, `signer_key_id`, `signature`). `SignedProtocolModel` gains a class-only `_signed_version` defaulting to `0.1`; every v0.3 signed model sets it to `0.3`, preserving old bytes while giving new signatures the approved domain separation.
2. Stable `member_id` excludes `content_digest` and hashes only `member_kind` plus canonical `locator`; content integrity is checked separately.
3. `population_digest` hashes the sorted list of `(member_id, member_kind, locator_digest)` and therefore remains stable across positive/negative mutations of the same logical members.
4. v0.3 uses parallel tables: `evaluation_scopes_v03`, `verification_profiles_v03`, `verification_arm_results_v03`, `verification_decisions_v03`, `verification_decision_parents_v03`, `acceptance_transitions_v03`, and `acceptance_transition_parents_v03`. Existing v0.2 tables and foreign keys remain untouched.
5. Acceptance and settlement resolve a referenced decision by querying v0.2 and v0.3 decision tables; exactly one match is required. Zero matches and ambiguous matches fail closed.
6. The approved conceptual `private` privacy view maps to the existing API name `customer_private`. v0.3 adds `diagnostic`, so accepted API values are `public`, `diagnostic`, and `customer_private`.
7. A v0.3 schema registry contains v0.3 Evaluation Scope/Profile/Arm Result/Decision and byte-equivalent generated schemas for the unchanged SubjectClaim, PolicyAnchor, CommitmentAnchor, and AcceptanceTransition models. Frozen v0.2 registry bytes remain unchanged.
8. Rich #4196 supplies the real open-source issue context only. The new scope-gap task and evidence bundle are owned by OpenWorkProof and must say `upstream_adoption: not_evidenced`.
9. `build_evaluation_scope` returns an immutable `EvaluationScopeDraft` without a signature envelope. The caller signs that payload through the existing key boundary to create `EvaluationScopeManifest`; no blank or fake signature is permitted.
10. `scope-validate` without ledger/key context performs intrinsic canonical and semantic checks and reports authority as `not_checked`. Full Manager role, grant, signature, nonce, and WorkOrder validation occurs in `scope-commit`; the CLI/MCP must not imply otherwise.

## File Map

### Create

- `src/openworkproof/scope.py`
- `src/openworkproof/schemas/v0.3/evaluation-scope.schema.json`
- `src/openworkproof/schemas/v0.3/verification-profile.schema.json`
- `src/openworkproof/schemas/v0.3/verification-arm-result.schema.json`
- `src/openworkproof/schemas/v0.3/verification-decision.schema.json`
- `src/openworkproof/schemas/v0.3/subject-claim.schema.json`
- `src/openworkproof/schemas/v0.3/policy-anchor.schema.json`
- `src/openworkproof/schemas/v0.3/commitment-anchor.schema.json`
- `src/openworkproof/schemas/v0.3/acceptance-transition.schema.json`
- `src/openworkproof/schemas/v0.3/schema-registry.json`
- Matching byte-identical files under `specs/v0.3/`
- `tests/test_scope_models_v03.py`
- `tests/test_scope_building_v03.py`
- `tests/test_scope_transactions_v03.py`
- `tests/test_verification_transactions_v03.py`
- `tests/test_acceptance_v03.py`
- `tests/test_delivery_package_v03.py`
- `tests/test_scope_interfaces_v03.py`
- `tests/test_scope_adversarial_v03.py`
- `tests/test_scope_demo_v03.py`
- `tests/scope-demo/rich-4196/README.md`
- `tests/scope-demo/rich-4196/claim.json`
- `tests/scope-demo/rich-4196/selector-rules.json`
- `tests/scope-demo/rich-4196/required-test.py`
- `tests/evidence-bundles/rich-4196-scope-v03-delivery-package.json`
- `docs/pilot/scope-bound-verification-offer.md`
- `docs/pilot/scope-coverage-report.example.md`

### Modify

- `src/openworkproof/models.py`
- `src/openworkproof/signing.py`
- `src/openworkproof/evidence.py`
- `src/openworkproof/verification.py`
- `src/openworkproof/acceptance.py`
- `src/openworkproof/settlement.py`
- `src/openworkproof/delivery_package.py`
- `src/openworkproof/schema_registry.py`
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
- `supply-chain/images/trusted-helper/SOURCE_ALLOWLIST`
- `README.md`, `README_en.md`, `MCP_SERVER.md`
- `docs/offline-verification.md`, `docs/status.md`

## Spec Coverage Map

| Approved design area | Implementation tasks |
|---|---|
| Scope members, digests, bounds, path safety | Tasks 2 and 3 |
| Explicit, git diff, pytest selectors | Tasks 3 and 4 |
| Requirement bindings and required targets | Tasks 2, 3, and 13 |
| Profile/arm/decision v0.3 semantics | Tasks 5 and 8 |
| v0.1/v0.2 immutable compatibility | Tasks 1, 6, 9, 10, and 15 |
| Append-only storage and recovery | Tasks 7 and 8 |
| Acceptance and settlement version routing | Task 9 |
| Delivery package, coverage report, privacy | Task 10 |
| Python/CLI/MCP interfaces | Task 11 |
| Adversarial matrix | Task 12 |
| Real-Issue self-owned demo | Task 13 |
| Commercial pilot boundary | Task 14 |
| Required-live supply-chain release truth | Task 15 |

## Task 1: Create the Isolated Implementation Worktree and Freeze the Baseline

**Files:** none

- [x] **Step 1: Resolve the approved plan commit**

Run in `/Users/molin/Project/openWorkProof/.worktrees/scope-bound-verification-v03-spec`:

```bash
PLAN=docs/superpowers/plans/2026-08-11-openworkproof-scope-bound-verification-v03-implementation.md
SPEC=docs/superpowers/specs/2026-08-11-openworkproof-scope-bound-verification-v03-design.md
PLAN_COMMIT="$(git log -1 --format=%H -- "$PLAN")"
test -n "$PLAN_COMMIT"
git show "$PLAN_COMMIT:$PLAN" >/dev/null
git show "$PLAN_COMMIT:$SPEC" | rg -F '用户已书面批准'
git status --short
```

Expected: both documents exist in `PLAN_COMMIT`, the approved-state line is present, and only known documentation state is shown.

- [x] **Step 2: Create the execution branch and worktree**

Run from `/Users/molin/Project/openWorkProof`:

```bash
git worktree add \
  /Users/molin/Project/openWorkProof-scope-bound-verification-v03 \
  -b codex/scope-bound-verification-v03 \
  "$PLAN_COMMIT"
```

Expected: a clean new worktree. If either path or branch exists, stop and inspect it; do not delete or reuse it blindly.

- [x] **Step 3: Create the environment and prove package identity**

Run in the new worktree:

```bash
python3.12 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -e '.[dev]'
./.venv/bin/python -m pip check
./.venv/bin/python - <<'PY'
from importlib.metadata import version
import openworkproof
print(openworkproof.__file__)
print(openworkproof.__version__)
print(version("openworkproof"))
assert openworkproof.__version__ == version("openworkproof")
PY
```

Expected: imports resolve inside the new worktree and package/source versions agree.

- [x] **Step 4: Record the untouched baseline**

```bash
./.venv/bin/python -m pytest \
  tests/test_verification_models_v02.py \
  tests/test_verification_transactions_v02.py \
  tests/test_delivery_package_v02.py \
  tests/test_acceptance.py \
  tests/test_settlement_readiness.py -q
./.venv/bin/python -m pytest -q
```

Expected: zero failures. Record exact pass/skip counts and warnings; do not encode historical counts as current truth.

## Task 2: Add Domain-Separated Scope Models and Closed Invariants

**Files:**

- Modify: `src/openworkproof/signing.py`
- Modify: `src/openworkproof/models.py`
- Modify: `tests/conftest.py`
- Create: `tests/test_scope_models_v03.py`

- [x] **Step 1: Write RED tests for canonical scope identities**

Add tests that import the absent helpers/models and assert exact formulas:

```python
def test_scope_member_id_excludes_content_digest(scope_member_payload):
    first = ScopeMember(content_digest="1" * 64, **scope_member_payload)
    second = ScopeMember(content_digest="2" * 64, **scope_member_payload)
    assert first.member_id == second.member_id


def test_population_digest_is_order_independent(scope_members):
    assert population_digest(scope_members) == population_digest(
        tuple(reversed(scope_members))
    )


def test_manifest_rejects_empty_or_oversized_population(scope_manifest_payload):
    with pytest.raises(ValueError, match="1..4096"):
        EvaluationScopeManifest.model_validate(
            {**scope_manifest_payload, "members": [], "member_count": 0}
        )
```

Also cover unsorted/duplicate members, wrong locator digest, wrong population digest, incomplete requirement bindings, missing required targets, excluded-member overlap, wrong `scope_id`, invalid signature, invalid times, and canonical payload above 8 MiB. Manager role/grant/nonce authorization requires WorkOrder and ledger context and is therefore covered by `scope-commit` in Task 7 rather than being implied by intrinsic model validation.

Run:

```bash
./.venv/bin/python -m pytest tests/test_scope_models_v03.py -q
```

Expected RED: import errors for v0.3 scope types/helpers.

- [x] **Step 2: Add the four canonical domains**

In `signing.py`, extend canonical domains with `scope-member`, `scope-requirement`, `scope-population`, and `evaluation-scope`. Add a keyword-only `version: Literal["0.1", "0.3"] = "0.1"` to `canonical_bytes`, `digest_payload`, `sign_payload`, and `verify_payload`; include it in the canonical domain string. Existing callers therefore keep identical `/v0.1` bytes. Preserve the legacy flat `ALLOWED_SIGNED_DOMAINS` boundary used by MCP, and keep only `evaluation-scope` signable through the explicit v0.3 version map:

```python
_UNSIGNED_ONLY_DOMAINS = frozenset(
    {"sidecar-event", "verification-decision", "scope-member",
     "scope-requirement", "scope-population", "evaluation-scope"}
)
ALLOWED_SIGNED_DOMAINS = ALLOWED_CANONICAL_DOMAINS - _UNSIGNED_ONLY_DOMAINS
_V03_SIGNED_DOMAINS = frozenset({"evaluation-scope"})
```

Add tests proving `sign_payload("scope-member", ...)` is rejected, `sign_payload("evaluation-scope", ..., version="0.3")` succeeds, and a known v0.2 signed fixture is byte-identical before and after this change.

- [x] **Step 3: Implement strict v0.3 scope models**

Add closed literals and models in `models.py`:

```python
ScopeMemberKind = Literal["source_file", "test_case", "delivery_artifact"]
ScopeSelectorKind = Literal["explicit", "git_diff_closure", "pytest_collection"]
ScopeRequirementKind = Literal["acceptance_condition", "required_artifact"]


class ScopeMember(ProtocolModel):
    member_id: Digest64
    member_kind: ScopeMemberKind
    locator: ScopeLocator
    locator_digest: Digest64
    content_digest: Digest64
    source_revision: ObjectId40


class ScopeSelectorRule(ProtocolModel):
    rule_id: Digest64
    selector_kind: ScopeSelectorKind
    selector_spec_digest: Digest64
    selector_engine_digest: Digest64
    required_evidence_paths: tuple[CanonicalRoot, ...]


class ScopeRequirementBinding(ProtocolModel):
    requirement_kind: ScopeRequirementKind
    requirement_digest: Digest64
    member_ids: tuple[Digest64, ...]


class EvaluationScopeManifest(SignedProtocolModel):
    _signed_domain = "evaluation-scope"
    _signed_version = "0.3"
    schema_version: Literal["openworkproof-evaluation-scope/0.3"]
    scope_id: Digest64
    work_order_digest: Digest64
    subject_claim_digest: Digest64
    source_revision: ObjectId40
    candidate_commit: ObjectId40
    selector_rules: tuple[ScopeSelectorRule, ...]
    members: tuple[ScopeMember, ...]
    member_count: SafePositiveInt
    population_digest: Digest64
    requirement_bindings: tuple[ScopeRequirementBinding, ...]
    required_target_ids: tuple[Digest64, ...]
    excluded_locator_digests: tuple[Digest64, ...]
    workspace_manifest_digest: Digest64
    freshness_mode: Literal["immutable_git_revision"]
    created_at: CanonicalUTCTime
    expires_at: CanonicalUTCTime
    nonce: Digest64
```

Add an `EvaluationScopeDraft` containing the same business fields but no `digest`, `signature_alg`, `signer_key_id`, or `signature`. Add `_signed_version: ClassVar[str] = "0.1"` to `SignedProtocolModel` and use it when validating its digest. Set `_signed_version = "0.3"` on every v0.3 signed model. Add a strict `ScopeLocator`: source/artifact locators use existing `CanonicalRoot`; test locators use `CanonicalRoot + "::" + bounded pytest node suffix`. Canonical locators must reject absolute paths, `..`, NUL, backslashes, non-NFC text, control characters, and case-fold collisions within one manifest.

- [x] **Step 4: Add deterministic v0.3 fixtures and run GREEN**

Add Manager-signed `scope_members_v03`, `evaluation_scope_v03`, and tamper helpers in `tests/conftest.py`. Do not alter v0.2 fixtures.

Run:

```bash
./.venv/bin/python -m pytest tests/test_scope_models_v03.py -q
./.venv/bin/python -m pytest tests/test_verification_models_v02.py tests/test_package.py -q
```

Expected: all pass and v0.2 model tests remain unchanged.

- [x] **Step 5: Commit**

```bash
git add src/openworkproof/signing.py src/openworkproof/models.py \
  tests/conftest.py tests/test_scope_models_v03.py
git diff --cached --check
git commit -m 'feat: add scope-bound protocol models'
```

## Task 3: Build and Validate Evaluation Scope with the Explicit Selector

**Files:**

- Create: `src/openworkproof/scope.py`
- Create: `tests/test_scope_building_v03.py`

- [x] **Step 1: Write RED tests for build/validate/compare**

Cover the public functions and a typed comparison result:

```python
def test_explicit_scope_builds_required_population(scope_build_request):
    draft = build_evaluation_scope(**scope_build_request)
    validate_evaluation_scope(draft, claim=scope_build_request["claim"])
    assert draft.member_count == len(draft.members)
    assert draft.required_target_ids


def test_missing_required_target_is_unknown(evaluation_scope_v03, observed_scope):
    result = compare_observed_scope(
        evaluation_scope_v03,
        observed_scope.model_copy(
            update={"member_ids": observed_scope.member_ids[:-1]}
        ),
    )
    assert result.scope_status == "indeterminate"
    assert "SCOPE_REQUIRED_TARGET_MISSING" in result.reason_codes
```

Add RED cases for empty selection, excluded locator, workspace drift, source revision drift, selector engine drift, N versus N-1 evidence, and repeat-run determinism.

Run and expect imports to fail:

```bash
./.venv/bin/python -m pytest tests/test_scope_building_v03.py -q
```

- [x] **Step 2: Implement pure digest and validation helpers**

Create these exact single-responsibility functions in `scope.py`:

```python
def scope_member_id(member_kind: str, locator: str) -> str: ...
def requirement_digest(requirement_kind: str, value: object) -> str: ...
def population_digest(members: Sequence[ScopeMember]) -> str: ...
def evaluation_scope_id(payload: Mapping[str, object]) -> str: ...
def validate_evaluation_scope(
    manifest: EvaluationScopeDraft | EvaluationScopeManifest,
    *,
    claim: SubjectClaim,
) -> None: ...
def compare_observed_scope(
    manifest: EvaluationScopeManifest,
    observed: ObservedScope,
) -> ScopeComparisonResult: ...
```

Define the unsigned, immutable `ObservedScope` comparison input and `ScopeComparisonResult` beside these pure helpers so Task 3 has a closed N-versus-N-1 comparison boundary. Task 5 reuses these types in arm results rather than redefining them. Return `satisfied`, `contradicted`, or `indeterminate`; do not map these to final Verification Decisions here.

- [x] **Step 3: Implement only the explicit selector and draft builder**

```python
def build_evaluation_scope(
    *,
    claim: SubjectClaim,
    work_order_digest: str,
    source_revision: str,
    candidate_commit: str,
    workspace_manifest_digest: str,
    selector_rules: Sequence[ScopeSelectorRule],
    explicit_members: Sequence[ScopeMember],
    requirement_bindings: Sequence[ScopeRequirementBinding],
    excluded_locator_digests: Sequence[str],
    repository_root: Path,
    created_at: datetime,
    expires_at: datetime,
    nonce: str,
) -> EvaluationScopeDraft: ...
```

The builder returns `EvaluationScopeDraft`; it must not load a private key, invent blank signature fields, or write a ledger. `repository_root` is required because symlink and path-escape safety cannot be proven from a locator string alone. Tests then sign `draft.model_dump(mode="json")` with `sign_payload("evaluation-scope", ..., version="0.3")` and validate the resulting `EvaluationScopeManifest`.

- [x] **Step 4: Prove symlink and path escape fail closed**

Use a temporary Git repository containing a normal file, a symlink, an absolute locator, and a `../` locator. Expected: only the normal repository-relative POSIX locator validates.

Run:

```bash
./.venv/bin/python -m pytest tests/test_scope_building_v03.py -q
./.venv/bin/python -m pytest tests/test_scope_models_v03.py -q
```

- [x] **Step 5: Commit**

```bash
git add src/openworkproof/scope.py tests/test_scope_building_v03.py
git diff --cached --check
git commit -m 'feat: build and compare explicit evaluation scopes'
```

## Task 4: Add Deterministic Git-Diff and Pytest-Collection Selectors

**Files:**

- Modify: `src/openworkproof/scope.py`
- Modify: `tests/test_scope_building_v03.py`

- [x] **Step 1: Write RED selector tests in frozen temporary repositories**

Add cases proving:

- `git_diff_closure` uses committed Git blobs, not dirty working-tree bytes;
- source and candidate revisions must be full 40-character commits;
- renamed/deleted paths have deterministic identities and no path escape;
- `pytest_collection` invokes a fixed argument vector with plugin autoload disabled;
- output is parsed as canonical full node IDs, sorted and unique;
- collection error, timeout, empty output, engine digest drift, or missing required node produces `indeterminate`.

Run:

```bash
./.venv/bin/python -m pytest tests/test_scope_building_v03.py -q -k 'git_diff or pytest_collection'
```

Expected RED: selector functions are absent.

- [x] **Step 2: Implement the two concrete adapters without a plugin registry**

```python
def select_git_diff_closure(
    repo: Path, *, source_revision: str, candidate_commit: str
) -> ScopeSelectorExecution: ...


def select_pytest_collection(
    repo: Path,
    *,
    source_revision: str,
    candidate_commit: str,
    python_executable: Path,
    timeout_seconds: int,
) -> ScopeSelectorExecution: ...
```

Use `git diff --name-status -z`, `git cat-file`, and a detached temporary tree. Use `python -I -m pytest --collect-only -q` with `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, `LC_ALL=C.UTF-8`, and `TZ=UTC`. Do not accept arbitrary selector commands.

- [x] **Step 3: Bind selector specs and engine bytes as evidence**

Persist no evidence in this task. Return deterministic `ScopeSelectorExecution` data containing canonical selector spec bytes, engine digest, evidence path, members, and status for later transaction/package tasks.

- [x] **Step 4: Run focused and backward regressions**

```bash
./.venv/bin/python -m pytest tests/test_scope_building_v03.py -q
./.venv/bin/python -m pytest tests/test_prepare_image_context.py tests/test_sandbox.py -q
```

- [x] **Step 5: Commit**

```bash
git add src/openworkproof/scope.py tests/test_scope_building_v03.py
git diff --cached --check
git commit -m 'feat: add frozen code scope selectors'
```

## Task 5: Add v0.3 Profile, Arm Result, and Decision Semantics

**Files:**

- Modify: `src/openworkproof/models.py`
- Modify: `src/openworkproof/verification.py`
- Modify: `tests/conftest.py`
- Create: `tests/test_verification_transactions_v03.py`

- [x] **Step 1: Write RED model and pure-composition tests**

Test exact-match Profile binding; scope fields on every Arm Result; recomputed `ScopeAssessment`; and the decision table:

```python
@pytest.mark.parametrize(
    ("scope_status", "negative_survived", "expected"),
    [
        ("satisfied", False, "VERIFIED"),
        ("satisfied", True, "REFUTED"),
        ("indeterminate", False, "UNKNOWN"),
        ("contradicted", False, "UNKNOWN"),
    ],
)
def test_v03_decision_table(...): ...
```

Add cross-arm mismatch, missing required target, caller-forged assessment, v0.2 profile offered to v0.3 composer, and validly re-signed but semantically wrong observed-count cases.

- [x] **Step 2: Add v0.3 models without changing v0.2 schemas**

Add `VerificationProfileV03`, `VerificationArmResultV03`, `ScopeAssessment`, `VerificationDecisionDraftV03`, and `VerificationDecisionV03`, reusing the Task 3 `ObservedScope` type. Copy v0.2 fields verbatim, then add only approved fields. Use closed schema literals ending in `/0.3` and a decision digest domain ending in `/v0.3`.

Extend `VerificationReasonCode` with the ten approved scope codes. Do not remove or rename any v0.2 reason.

- [x] **Step 3: Implement pure v0.3 validation/composition beside v0.2**

Add:

```python
def validate_verification_profile_v03(
    profile: VerificationProfileV03,
    manifest: EvaluationScopeManifest,
) -> None: ...


def compose_verification_decision_v03(
    *,
    profile: VerificationProfileV03,
    manifest: EvaluationScopeManifest,
    arm_results: Sequence[VerificationArmResultV03],
    request: DecisionDraftRequest,
) -> VerificationDecisionDraftV03: ...
```

Compute `ScopeAssessment` internally. Scope failure always adds scope reason codes and yields `UNKNOWN` before ordinary VERIFIED logic; a genuine caught/survived mutation remains governed by v0.2 semantics.

- [x] **Step 4: Run GREEN plus frozen-schema guard**

```bash
./.venv/bin/python -m pytest tests/test_verification_transactions_v03.py -q -k 'model or compose'
./.venv/bin/python -m pytest tests/test_verification_models_v02.py tests/test_schema_registry.py -q
```

Expected: v0.3 tests pass and every frozen v0.2 digest still matches.

- [x] **Step 5: Commit**

```bash
git add src/openworkproof/models.py src/openworkproof/verification.py \
  tests/conftest.py tests/test_verification_transactions_v03.py
git diff --cached --check
git commit -m 'feat: bind verification decisions to exact scope'
```

## Task 6: Freeze and Package the v0.3 Schema Registry

**Files:**

- Modify: `src/openworkproof/schema_registry.py`
- Modify: `pyproject.toml`
- Modify: `tests/test_schema_registry.py`
- Create: `src/openworkproof/schemas/v0.3/*.json`
- Create: `specs/v0.3/*.json`

- [x] **Step 1: Write RED three-version registry tests**

Require `authoritative_schema(..., "0.3")`, exact runtime/public mirror equality, canonical bytes, immutable v0.1/v0.2 digests, rejected cross-version object lookup, atomic generation, and rollback on injected failure.

Run:

```bash
./.venv/bin/python -m pytest tests/test_schema_registry.py -q -k 'v03 or three_versions'
```

Expected RED: unknown protocol version `0.3`.

- [x] **Step 2: Register the closed v0.3 object set**

Add `V03_OBJECT_PATHS`, `V03_SCHEMA_FACTORIES`, `_FROZEN_V03_DIGESTS`, and `_FROZEN_V03_REGISTRY`. Do not reorder v0.1/v0.2 registries or modify their constants.

- [x] **Step 3: Generate canonical resources atomically**

Run the repository's schema writer into a temporary directory, inspect the diff, then copy only the v0.3 outputs into runtime/public directories:

```bash
TMP_ROOT="$(mktemp -d)"
./.venv/bin/python -m openworkproof.schema_registry \
  --version 0.3 \
  --destination "$TMP_ROOT/runtime" \
  --mirror "$TMP_ROOT/public"
cmp "$TMP_ROOT/runtime/schema-registry.json" \
  "$TMP_ROOT/public/schema-registry.json"
./.venv/bin/python -m json.tool \
  "$TMP_ROOT/runtime/schema-registry.json" >/dev/null
```

Use `apply_patch` to add the canonical files; do not write over frozen directories.

- [x] **Step 4: Run all registry and package-data tests**

```bash
./.venv/bin/python -m pytest tests/test_schema_registry.py tests/test_package.py -q
./.venv/bin/python - <<'PY'
from importlib import resources
for version in ("0.1", "0.2", "0.3"):
    root = resources.files("openworkproof").joinpath("schemas", f"v{version}")
    assert root.joinpath("schema-registry.json").is_file()
PY
```

- [x] **Step 5: Commit and checkpoint**

```bash
git add src/openworkproof/schema_registry.py src/openworkproof/schemas/v0.3 \
  specs/v0.3 pyproject.toml tests/test_schema_registry.py
git diff --cached --check
git commit -m 'feat: freeze scope-bound v03 schemas'
git status --short --branch
```

Checkpoint must confirm v0.1/v0.2 schema hashes did not change.

## Task 7: Add Append-Only Scope and Profile Transactions

**Files:**

- Modify: `src/openworkproof/evidence.py`
- Modify: `src/openworkproof/verification.py`
- Create: `tests/test_scope_transactions_v03.py`

- [x] **Step 1: Write RED DDL and transaction tests**

Cover canonical commit/load, Manager signature/role/grant/nonce/expiry checks, SubjectClaim and WorkOrder bindings, exact-byte idempotency, conflicting bytes, PREPARE zero-write, insert failure, COMMIT failure, COMMIT-ACK readback, readback indeterminate, cleanup failure, and two-thread same-scope concurrency.

Snapshot all authoritative tables before each injected failure and assert equality after failure.

- [x] **Step 2: Add parallel v0.3 tables**

In the existing schema initialization transaction, create:

```sql
CREATE TABLE evaluation_scopes_v03 (... canonical_json BLOB NOT NULL ...);
CREATE TABLE verification_profiles_v03 (... scope_digest TEXT NOT NULL ...);
CREATE TABLE verification_arm_results_v03 (...);
CREATE TABLE verification_decisions_v03 (...);
CREATE TABLE verification_decision_parents_v03 (...);
CREATE TABLE acceptance_transitions_v03 (...);
CREATE TABLE acceptance_transition_parents_v03 (...);
```

Use foreign keys only within the v0.3 table family. Do not alter existing v0.2 DDL.

- [x] **Step 3: Implement scope commit/load with existing readback semantics**

```python
def commit_evaluation_scope(
    ledger: Path,
    claim: SubjectClaim,
    manifest: EvaluationScopeManifest,
) -> EvaluationScopeManifest: ...


def load_evaluation_scope(
    ledger: Path,
    scope_id: str,
) -> EvaluationScopeManifest: ...
```

Commit the `SubjectClaim` and Manifest atomically when the claim is not already
present; an already committed claim is accepted only on exact canonical-byte
equality. Reuse `_commit_with_readback`, nonce checks, bounded canonical loaders,
and target lock patterns. Do not retry an indeterminate COMMIT.

- [x] **Step 4: Add v0.3 Profile transaction**

Implement `commit_verification_profile_v03`; it must load the committed scope and claim, recompute static invariants, and reject digest-only or missing scope state.

- [x] **Step 5: Run focused and DDL regressions**

```bash
./.venv/bin/python -m pytest tests/test_scope_transactions_v03.py -q
./.venv/bin/python -m pytest \
  tests/test_verification_transactions_v02.py \
  tests/test_replay.py tests/test_state.py -q
```

- [x] **Step 6: Commit**

```bash
git add src/openworkproof/evidence.py src/openworkproof/verification.py \
  tests/test_scope_transactions_v03.py
git diff --cached --check
git commit -m 'feat: commit scope-bound profiles atomically'
```

## Task 8: Add v0.3 Arm and Decision Transactions with Recovery

**Files:**

- Modify: `src/openworkproof/verification.py`
- Modify: `src/openworkproof/evidence.py`
- Modify: `tests/test_verification_transactions_v03.py`

- [x] **Step 1: Write RED arm and decision transaction tests**

Cover a valid positive/negative chain, missing scope evidence, N versus N-1, different negative-arm population, wrong manifest digest, wrong revision, evidence digest tamper, result signature tamper, decision signature tamper, superseding decision, stale parent, and all transaction failure points.

- [x] **Step 2: Implement v0.3 arm commit**

```python
def commit_verification_arm_result_v03(
    ledger: Path,
    result: VerificationArmResultV03,
) -> VerificationArmResultV03: ...
```

Load Profile, Manifest, receipts, key bindings, and evidence. Recompute the observed scope; never trust caller-supplied count/status alone.

- [x] **Step 3: Implement prepare and commit for v0.3 decisions**

```python
def prepare_verification_decision_v03(
    ledger: Path,
    request: DecisionDraftRequest,
) -> VerificationDecisionDraftV03: ...


def commit_verification_decision_v03(
    ledger: Path,
    decision: VerificationDecisionV03,
) -> VerificationDecisionV03: ...
```

Require exact canonical readback after commit, and preserve committed truth if cleanup fails.

- [x] **Step 4: Prove concurrent composition has one truth**

Use two threads with the same decision ID. Exact bytes must be idempotent; different signed bytes must yield one committed truth and one conflict/committed result, never two rows.

- [x] **Step 5: Run focused and complete verification regressions**

```bash
./.venv/bin/python -m pytest \
  tests/test_scope_transactions_v03.py \
  tests/test_verification_transactions_v03.py -q
./.venv/bin/python -m pytest \
  tests/test_verification_models_v02.py \
  tests/test_verification_transactions_v02.py \
  tests/test_v02_adversarial.py -q
```

- [x] **Step 6: Commit**

```bash
git add src/openworkproof/verification.py src/openworkproof/evidence.py \
  tests/test_verification_transactions_v03.py
git diff --cached --check
git commit -m 'feat: commit scope-bound verification outcomes'
```

## Task 9: Route Acceptance and Settlement Across v0.2 and v0.3

**Files:**

- Modify: `src/openworkproof/acceptance.py`
- Modify: `src/openworkproof/settlement.py`
- Modify: `tests/test_acceptance.py`
- Create: `tests/test_acceptance_v03.py`

- [x] **Step 1: Write RED version-router tests**

Test active v0.3 VERIFIED acceptance, v0.3 UNKNOWN/REFUTED rejection, v0.2 unchanged behavior, missing decision, fabricated cross-version digest, ambiguous dual-table row, withdraw, supersede, and settlement readiness.

- [x] **Step 2: Add a closed decision lookup result**

```python
@dataclass(frozen=True, slots=True)
class CurrentVerificationRecord:
    protocol_version: Literal["0.2", "0.3"]
    decision_id: str
    decision_digest: str
    decision: Literal["VERIFIED", "REFUTED", "UNKNOWN"]
```

Implement one internal resolver that requires exactly one table match. Keep `_require_current_verified_decision_if_v02` behavior as a compatibility wrapper until all current callers use the resolver.

- [x] **Step 3: Route acceptance writes to the matching table family**

The same `AcceptanceTransitionReceipt` model may be used, but v0.3 rows and parent rows must go only to v0.3 tables. Never rebind a v0.2 Acceptance to a v0.3 Decision.

- [x] **Step 4: Route settlement reads without changing business states**

`NOT_READY`, `READY_FOR_ACCEPTANCE`, `ACCEPTED_FOR_SETTLEMENT`, `SUSPENDED`, `WITHDRAWN`, and `SUPERSEDED` remain unchanged. Add `protocol_version` to internal snapshots only if required; do not rename public states.

- [x] **Step 5: Run GREEN and compatibility regressions**

```bash
./.venv/bin/python -m pytest \
  tests/test_acceptance_v03.py tests/test_acceptance.py \
  tests/test_acceptor_rejection.py tests/test_settlement_readiness.py -q
```

- [x] **Step 6: Commit**

```bash
git add src/openworkproof/acceptance.py src/openworkproof/settlement.py \
  tests/test_acceptance.py tests/test_acceptance_v03.py
git diff --cached --check
git commit -m 'feat: route acceptance across protocol versions'
```

## Task 10: Export and Replay v0.3 Delivery Packages with Three Privacy Views

**Files:**

- Modify: `src/openworkproof/delivery_package.py`
- Create: `tests/test_delivery_package_v03.py`
- Modify: `docs/offline-verification.md`

- [x] **Step 1: Write RED package and privacy tests**

Require customer-private full replay, diagnostic redaction, public aggregate-only output, manifest digest preservation, scope report contents, selector-spec evidence, member evidence, v0.3 decision replay, and v0.2 package replay unchanged.

Explicitly assert no locator, pytest node ID, source bytes, customer identity, or selector spec bytes occur anywhere in a public package.

- [x] **Step 2: Extend manifest privacy classes and view rules**

Use:

```python
PrivacyClass = Literal["public", "diagnostic", "customer_private"]
PrivacyView = Literal["public", "diagnostic", "customer_private"]
```

Allowed visibility is monotonic: public sees public; diagnostic sees public+diagnostic; customer-private sees all. A public package contains aggregate scope facts and original Manifest digest but must state `full_offline_replay: false`.

- [x] **Step 3: Add version-aware ledger export and replay**

Load exactly one v0.2/v0.3 decision family. For v0.3 include canonical Evaluation Scope, Profile, Arm Results, Decision, selector evidence, observed-scope evidence, keys, Acceptance, settlement snapshot, and generated Scope Coverage Report.

- [x] **Step 4: Generate the customer-readable report without overclaiming**

The report must show claim, revisions, selector versions, declared/observed counts, required coverage, exclusions, cross-arm consistency, decision/reasons, signature digests, and exact replay command. Render the approved bounded VERIFIED sentence. Never render payment, automatic settlement, absolute correctness, or regulatory-compliance claims.

- [x] **Step 5: Run package and tamper tests**

```bash
./.venv/bin/python -m pytest tests/test_delivery_package_v03.py -q
./.venv/bin/python -m pytest \
  tests/test_delivery_package_v02.py tests/test_v02_bundles.py -q
```

- [x] **Step 6: Commit**

```bash
git add src/openworkproof/delivery_package.py \
  tests/test_delivery_package_v03.py docs/offline-verification.md
git diff --cached --check
git commit -m 'feat: export scope coverage delivery packages'
```

## Task 11: Expose One Service Contract through Python, CLI, and Read-Only MCP

**Files:**

- Modify: `src/openworkproof/services.py`
- Modify: `src/openworkproof/cli.py`
- Modify: `src/openworkproof/mcp_transport.py`
- Modify: `src/openworkproof/__init__.py`
- Modify: `tests/test_cli_transport.py`
- Create: `tests/test_scope_interfaces_v03.py`
- Modify: `MCP_SERVER.md`

- [x] **Step 1: Write RED service/CLI/MCP parity tests**

Cover `scope-build`, `scope-validate`, `scope-commit`, and `scope-compare`; schema-version dispatch for profile/arm/decision; diagnostic delivery; JSON/text output; invalid/unknown/contradicted exit codes; and MCP read-only tools.

Assert no MCP tool accepts private key bytes, signs a Manifest, commits a Scope, or accepts an Acceptance decision.

- [x] **Step 2: Extend the service facade first**

Add type/version dispatch based on closed `schema_version`, never trial-parse multiple signed types. Add service methods:

```python
build_scope(...)
validate_scope(...)
commit_scope(...)
compare_scope(...)
```

CLI and MCP must call these methods; do not duplicate scope semantics.

- [x] **Step 3: Add exact CLI commands and exit semantics**

Implement:

```text
owp scope-build --claim claim.json --source-revision SHA --rules rules.json
owp scope-validate scope.json
owp scope-commit pilot.sqlite3 signed-scope.json
owp scope-compare scope.json observed-scope.json
```

Use exit `0` for satisfied/valid, `1` for invalid input or failed operation, `3` for indeterminate/UNKNOWN, and `4` for contradicted. Include the status and reason codes in JSON on every non-zero comparison.

- [x] **Step 4: Add only two MCP validation tools**

Register `owp_scope_validate` and `owp_scope_compare`. Update `owp_validate_profile` and `owp_run_verification` docs/dispatch for v0.2/v0.3 without adding signing authority.

- [x] **Step 5: Run interface and registration gates**

```bash
./.venv/bin/python -m pytest \
  tests/test_scope_interfaces_v03.py tests/test_cli_transport.py \
  tests/test_v02_interfaces.py -q
./.venv/bin/python - <<'PY'
from typing import get_type_hints
import inspect
import openworkproof.mcp_transport as module
for _, value in vars(module).items():
    if inspect.isfunction(value) and value.__annotations__:
        get_type_hints(value, vars(module), vars(module))
PY
```

- [x] **Step 6: Commit and checkpoint**

```bash
git add src/openworkproof/services.py src/openworkproof/cli.py \
  src/openworkproof/mcp_transport.py src/openworkproof/__init__.py \
  tests/test_cli_transport.py tests/test_scope_interfaces_v03.py MCP_SERVER.md
git diff --cached --check
git commit -m 'feat: expose scope-bound verification interfaces'
git status --short --branch
```

Checkpoint must explicitly confirm MCP has no new signing or commit authority.

## Task 12: Close the v0.3 Adversarial and Recovery Matrix

**Files:**

- Create: `tests/test_scope_adversarial_v03.py`
- Modify only for discovered defects: v0.3 implementation files from Tasks 2–11

- [x] **Step 1: Add the full omission and drift matrix**

Test empty population, required file missing, required test missing, N declared/N-1 observed, positive full/negative reduced, source revision drift, candidate drift, workspace drift, selector engine drift, validly re-signed wrong count, and cross-arm population mismatch.

- [x] **Step 2: Add byte and ledger-row tamper matrix**

For every case, rebuild with `model_dump -> modify -> model_validate`; if testing semantic rejection, re-sign with an authorized test key. Tamper Manifest, selector spec, member evidence, scope evidence, profile row, arm row, decision row, decision-parent row, acceptance row, and package manifest. Every case must fail closed or produce the approved UNKNOWN outcome; bad signatures must not be mislabeled as semantic-scope failures.

- [x] **Step 3: Add transaction fault injection**

Inject PREPARE, insert, state update, COMMIT, COMMIT-ACK, readback, and cleanup faults for Scope/Profile/Arm/Decision. Assert full-table snapshots and committed-truth behavior.

- [x] **Step 4: Run the focused adversarial set three times**

```bash
for run in 1 2 3; do
  ./.venv/bin/python -m pytest tests/test_scope_adversarial_v03.py -q || exit 1
done
./.venv/bin/python -m pytest \
  tests/test_scope_models_v03.py \
  tests/test_scope_building_v03.py \
  tests/test_scope_transactions_v03.py \
  tests/test_verification_transactions_v03.py \
  tests/test_acceptance_v03.py \
  tests/test_delivery_package_v03.py \
  tests/test_scope_interfaces_v03.py \
  tests/test_scope_adversarial_v03.py -q
```

- [x] **Step 5: Commit**

```bash
git add tests/test_scope_adversarial_v03.py \
  src/openworkproof/models.py src/openworkproof/signing.py \
  src/openworkproof/scope.py src/openworkproof/evidence.py \
  src/openworkproof/verification.py src/openworkproof/acceptance.py \
  src/openworkproof/settlement.py src/openworkproof/delivery_package.py \
  src/openworkproof/services.py src/openworkproof/cli.py \
  src/openworkproof/mcp_transport.py
git diff --cached --check
git commit -m 'test: close scope-bound adversarial matrix'
```

Before committing, verify `git diff --cached --name-only` contains no unrelated source file.

## Task 13: Build the Self-Owned Rich #4196 Scope-Gap Demo

**Files:**

- Create: `tests/scope-demo/rich-4196/*`
- Create: `tests/test_scope_demo_v03.py`
- Create: `tests/evidence-bundles/rich-4196-scope-v03-delivery-package.json`
- Modify: `tests/test_export_evidence_bundles.py`
- Modify: `tests/evidence-bundles/verify_evidence_bundle.py`

- [x] **Step 1: Freeze the provenance and non-adoption boundary**

In the demo README record the real source issue URL, captured facts, OpenWorkProof-owned task construction, and exact statements:

```yaml
issue_source: https://github.com/Textualize/rich/issues/4196
demo_owner: OpenWorkProof
upstream_adoption: not_evidenced
customer_case: not_evidenced
```

Do not copy or overwrite the existing v0.2 Rich bundle.

- [x] **Step 2: Write RED old-green/new-UNKNOWN test**

Construct a fixed check that returns green while omitting `required-test.py`. Assert the same evidence under v0.3 yields `UNKNOWN` plus `SCOPE_REQUIRED_TARGET_MISSING`.

- [x] **Step 3: Add repaired range and negative-control paths**

After adding the required test to the selected population, assert the positive arm passes, the registered mutant is caught, all arms share the same population digest, and the decision is VERIFIED with bounded language.

- [x] **Step 4: Export and independently replay the immutable bundle**

```bash
./.venv/bin/python -m pytest tests/test_scope_demo_v03.py -q
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
  ./.venv/bin/python tests/evidence-bundles/verify_evidence_bundle.py \
  tests/evidence-bundles/rich-4196-scope-v03-delivery-package.json
```

Expected: `VERIFICATION PASSED`, v0.3 scope satisfied, and no network/ledger dependency. Tampering one member or scope-evidence byte must fail.

- [x] **Step 5: Commit**

```bash
git add tests/scope-demo/rich-4196 tests/test_scope_demo_v03.py \
  tests/evidence-bundles/rich-4196-scope-v03-delivery-package.json \
  tests/test_export_evidence_bundles.py \
  tests/evidence-bundles/verify_evidence_bundle.py
git diff --cached --check
git commit -m 'test: add real-issue scope omission demo'
```

## Task 14: Publish Honest Technical and Commercial Pilot Documentation

**Files:**

- Modify: `README.md`
- Modify: `README_en.md`
- Modify: `docs/status.md`
- Modify: `docs/offline-verification.md`
- Create: `docs/pilot/scope-bound-verification-offer.md`
- Create: `docs/pilot/scope-coverage-report.example.md`

- [x] **Step 1: Write the v0.3 capability boundary in Chinese and English**

Explain that v0.3 proves exact declared-versus-observed scope for code delivery; it does not prove unencoded business intent, customer acceptance, payment, universal correctness, or regulatory compliance. Keep MCP/A2A positioning complementary rather than dismissive.

- [x] **Step 2: Add the 21-day paid pilot offer**

Record User, payer hypothesis, Customer Acceptor, deliverables, formal quoted amount/retainer fields, five-target outreach limit, eight-person-day/2,000-yuan experiment cap, 21-day deadline, success/stop rules, and all external outcomes as `not evidenced`.

- [x] **Step 3: Add an example Scope Coverage Report**

Use the self-owned Rich demo and label it as a demonstration, not a customer case. Show exactly what a buyer receives and the bounded VERIFIED sentence.

- [x] **Step 4: Scan for overclaims and stale protocol counts**

```bash
rg -n '客户已采用|客户已验收|已经付款|资金已释放|自动结算|上游已采用|官方采纳|100%正确' \
  README.md README_en.md docs/pilot docs/status.md docs/offline-verification.md
rg -n '2283|2,283|2204|2,204' README.md README_en.md docs/status.md
```

Expected: any first scan match is an explicit negation/limitation; historical test counts are not presented as fresh current truth.

- [x] **Step 5: Commit**

```bash
git add README.md README_en.md docs/status.md docs/offline-verification.md \
  docs/pilot/scope-bound-verification-offer.md \
  docs/pilot/scope-coverage-report.example.md
git diff --cached --check
git commit -m 'docs: add scope-bound delivery pilot'
```

## Task 15: Bind the Final Candidate and Run Every Release Gate

**Files:**

- Modify: `supply-chain/images/trusted-helper/SOURCE_ALLOWLIST`
- Create: `supply-chain/images/candidates/${REV}.json`
- Modify: `docs/status.md`

- [ ] **Step 1: Close and commit the trusted-helper source surface**

Add only v0.3 modules imported by offline replay, expected to include `src/openworkproof/scope.py` plus already allowlisted core modules. Do not add CLI, MCP, services, pilot docs, or demo sources.

Run:

```bash
git add supply-chain/images/trusted-helper/SOURCE_ALLOWLIST
git diff --cached --check
git commit -m 'build: include scope replay source'
```

Expected: the new committed HEAD contains the exact allowlist used by `prepare_context.py`; never build a candidate from uncommitted allowlist bytes.

- [ ] **Step 2: Run portable gates before the immutable build**

```bash
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests
./.venv/bin/python -m pytest \
  tests/test_scope_models_v03.py \
  tests/test_scope_building_v03.py \
  tests/test_scope_transactions_v03.py \
  tests/test_verification_transactions_v03.py \
  tests/test_acceptance_v03.py \
  tests/test_delivery_package_v03.py \
  tests/test_scope_interfaces_v03.py \
  tests/test_scope_adversarial_v03.py \
  tests/test_scope_demo_v03.py -q
./.venv/bin/python -m pytest -q \
  --ignore=tests/test_image_supply_chain.py \
  --ignore=tests/test_candidate_supplychain_integration.py
git diff --check
```

Expected: zero failures in the portable suite. The two candidate files are deferred—not waived—to Step 6 because no inventory can bind the new revision before it is built. Record exact counts, skips, warnings, and durations.

- [ ] **Step 3: Build revision-specific contexts**

```bash
REV="$(git rev-parse HEAD)"
ARTIFACT_ROOT=/Users/molin/Project/openWorkProof-delivery
./.venv/bin/python supply-chain/images/prepare_context.py \
  --repo /Users/molin/Project/openWorkProof-scope-bound-verification-v03 \
  --source-revision "$REV" \
  --wheelhouse "$ARTIFACT_ROOT/wheelhouse/linux-arm64-cp312-full" \
  --deb-closure "$ARTIFACT_ROOT/debs/linux-arm64-trixie-git" \
  --output-root "$ARTIFACT_ROOT/build-contexts/$REV"
```

Expected: new atomic revision-specific execution/helper contexts. Do not overwrite an existing directory.

- [ ] **Step 4: Build two OCI and two Docker archives**

```bash
REV="$(git rev-parse HEAD)"
ARTIFACT_ROOT=/Users/molin/Project/openWorkProof-delivery
CONTEXT_ROOT="$ARTIFACT_ROOT/build-contexts/$REV"
ARCHIVE_ROOT="$ARTIFACT_ROOT/oci/$REV"
SOURCE_EPOCH="$(git show -s --format=%ct "$REV")"
OCI_CREATED="$(./.venv/bin/python -c \
  'from datetime import datetime, timezone; import sys; print(datetime.fromtimestamp(int(sys.argv[1]), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))' \
  "$SOURCE_EPOCH")"
mkdir -p "$ARCHIVE_ROOT"

docker buildx build --platform linux/arm64 --network none --pull=false \
  --provenance=false --sbom=false --build-arg "OWP_SOURCE_REVISION=$REV" \
  --annotation "manifest-descriptor:org.opencontainers.image.created=$OCI_CREATED" \
  --output "type=oci,dest=$ARCHIVE_ROOT/openworkproof-execution-test-candidate.oci-archive.tar" \
  "$CONTEXT_ROOT/execution"
docker buildx build --platform linux/arm64 --network none --pull=false \
  --provenance=false --sbom=false --build-arg "OWP_SOURCE_REVISION=$REV" \
  --annotation "manifest-descriptor:org.opencontainers.image.created=$OCI_CREATED" \
  --output "type=oci,dest=$ARCHIVE_ROOT/openworkproof-trusted-helper-candidate.oci-archive.tar" \
  "$CONTEXT_ROOT/trusted-helper"
docker buildx build --platform linux/arm64 --network none --pull=false \
  --provenance=false --sbom=false --build-arg "OWP_SOURCE_REVISION=$REV" \
  --tag "openworkproof/execution-test:$REV" \
  --output "type=docker,dest=$ARCHIVE_ROOT/openworkproof-execution-test-candidate.docker-archive.tar" \
  "$CONTEXT_ROOT/execution"
docker buildx build --platform linux/arm64 --network none --pull=false \
  --provenance=false --sbom=false --build-arg "OWP_SOURCE_REVISION=$REV" \
  --tag "openworkproof/trusted-helper-candidate:$REV" \
  --output "type=docker,dest=$ARCHIVE_ROOT/openworkproof-trusted-helper-candidate.docker-archive.tar" \
  "$CONTEXT_ROOT/trusted-helper"
docker load --input \
  "$ARCHIVE_ROOT/openworkproof-execution-test-candidate.docker-archive.tar"
docker load --input \
  "$ARCHIVE_ROOT/openworkproof-trusted-helper-candidate.docker-archive.tar"
```

Expected: four archives derived from the same immutable revision. Do not hand-edit tar members.

- [ ] **Step 5: Create a new measured candidate inventory**

Use the newest valid `openworkproof-image-candidate-inventory/0.2` file as a structural template only. Recompute every revision, input digest, archive digest, manifest digest, image ID, RepoDigest, label, entrypoint, command, byte size, and path. Write only `supply-chain/images/candidates/$REV.json`.

Generate sums:

```bash
(
  cd "$ARCHIVE_ROOT"
  shasum -a 256 \
    openworkproof-execution-test-candidate.docker-archive.tar \
    openworkproof-execution-test-candidate.oci-archive.tar \
    openworkproof-trusted-helper-candidate.docker-archive.tar \
    openworkproof-trusted-helper-candidate.oci-archive.tar \
    | LC_ALL=C sort > SHA256SUMS
)
```

- [ ] **Step 6: Run required-live gates**

```bash
REV="$(git rev-parse HEAD)"
export OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT=/Users/molin/Project/openWorkProof-delivery
export OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1
export OPENWORKPROOF_DOCKER_TEST_IMAGE="docker.io/openworkproof/execution-test@$(
  jq -r '.images.execution.local_image_id' \
    "supply-chain/images/candidates/$REV.json"
)"
docker image inspect "$OPENWORKPROOF_DOCKER_TEST_IMAGE" >/dev/null
./.venv/bin/python -m pytest tests/test_image_supply_chain.py -q
./.venv/bin/python -m pytest -m supplychain \
  tests/test_candidate_supplychain_integration.py -q
./.venv/bin/python -m pytest -q
```

Expected: every command exits 0 with zero failures and no unapproved required-live skip.

- [ ] **Step 7: Replay v0.1, v0.2, and v0.3 bundles offline**

```bash
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
  ./.venv/bin/python tests/evidence-bundles/verify_evidence_bundle.py \
  tests/evidence-bundles/rich-4196-evidence-bundle.json
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
  ./.venv/bin/python tests/evidence-bundles/verify_evidence_bundle.py \
  tests/evidence-bundles/rich-4196-v02-delivery-package.json
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
  ./.venv/bin/python tests/evidence-bundles/verify_evidence_bundle.py \
  tests/evidence-bundles/rich-4196-scope-v03-delivery-package.json
```

Expected: all three report `VERIFICATION PASSED` without network or live ledger access.

- [ ] **Step 8: Record exact release truth, commit, and checkpoint**

Update `docs/status.md` with exact source revision, package version, protocol versions, environment, pass/fail/skip counts, candidate path, bundle results, timestamps, and boundary `commercial_validation: not_evidenced`.

```bash
REV="$(git rev-parse HEAD)"
git add "supply-chain/images/candidates/$REV.json" docs/status.md
git diff --cached --check
git commit -m 'build: bind scope-bound verification candidate'
git status --short --branch
```

Checkpoint must distinguish local release-candidate completion from push, merge, deployment, customer acceptance, and payment.

## Task 16: Final Independent Review and Branch Handoff

**Files:** none unless review identifies a scoped defect

- [ ] **Step 1: Run final static and focused checks from a clean tree**

```bash
test -z "$(git status --porcelain)"
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests
git diff --check
./.venv/bin/python -m pytest -q
```

Expected: clean tree and zero failures.

- [ ] **Step 2: Review every approved invariant against evidence**

Produce a table mapping each Section 21 acceptance criterion and each Task 12 attack to test names and fresh output. Confirm v0.2 frozen registry digests and historical bundles are byte-identical to the plan base.

- [ ] **Step 3: Inspect the three privacy packages manually**

Open customer-private, diagnostic, and public report outputs. Confirm the public view contains no locator/test-name/source-byte leakage and states it is not a complete offline replay package.

- [ ] **Step 4: Stop at the integration choice**

Report branch name, HEAD, commits, tests, inventory, evidence bundle, unresolved risks, and commercial state. Offer exactly:

1. merge locally to `main` after approval;
2. push `codex/scope-bound-verification-v03` and open a review branch/PR;
3. keep local for further review.

Do not merge or push without a fresh explicit instruction.

## Plan Self-Review Gate

Before implementation begins, run:

```bash
PLAN=docs/superpowers/plans/2026-08-11-openworkproof-scope-bound-verification-v03-implementation.md
SPEC=docs/superpowers/specs/2026-08-11-openworkproof-scope-bound-verification-v03-design.md
./.venv/bin/python - "$PLAN" "$SPEC" <<'PY'
from pathlib import Path
import sys

tokens = ("T" + "BD", "TO" + "DO", "FIX" + "ME", "PLACE" + "HOLDER")
for filename in sys.argv[1:]:
    text = Path(filename).read_text(encoding="utf-8")
    for token in tokens:
        assert token not in text, (filename, token)
    assert "待" + "定：" not in text, filename
    assert "待" + "补：" not in text, filename
PY
git diff --check
git status --short --branch
```

Expected: no unresolved placeholder match, no whitespace errors, and only the intended documentation files are changed before the plan commit.
