# OpenWorkProof Verifiable Delivery Pilot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build one paid-pilot-ready code-Agent delivery loop from a frozen customer claim through positive and negative verification, append-only acceptance lifecycle, deterministic settlement readiness, and a portable offline Delivery Proof Package.

**Architecture:** Extend the approved Evidence Lifecycle v0.2 without changing historical v0.1 bytes. Keep signed protocol models in `models.py`, deterministic verification and transactions in a focused `verification.py`, derived acceptance state in `settlement.py`, portable export/replay in `delivery_package.py`, and one shared `services.py` facade used by CLI and MCP. Preserve the existing SQLite target-lock, `BEGIN IMMEDIATE`, canonical JCS, Ed25519, exact readback, and append-only patterns.

**Tech Stack:** Python 3.12, Pydantic 2, RFC 8785 JCS, Ed25519/cryptography, SQLite, argparse, MCP SDK, pytest, Docker Buildx, static HTML.

---

## Execution Rules

- Design authority:
  `docs/superpowers/specs/2026-08-11-openworkproof-verifiable-delivery-pilot-design.md`
  at commit `69a3a62` plus the plan commit that adds the approved anchor-binding
  clarification.
- Protocol authority:
  `docs/superpowers/specs/2026-08-09-openworkproof-evidence-lifecycle-v0.2-design.md`
  at commit `29c6a84`.
- Execute in an isolated branch named `codex/verifiable-delivery-pilot`; never
  implement on `main` or the dirty `codex/pitch-commercial-model` worktree.
- Preserve all v0.1 signed JSON bytes and schema anchors. Add v0.2 resources;
  do not rewrite v0.1 resources.
- For each behavior: write one focused failing test, run it and observe the
  named failure, implement the minimum code, rerun the focused test, then run
  the task suite.
- Do not invent a customer, payment, external Acceptor, deployment, adoption,
  revenue, or pilot result.
- Do not implement custody, payment, clearing, arbitration, SaaS tenancy,
  blockchain, LLM judging, a Policy Registry, Verifier Marketplace, or broad
  framework adapters.
- Do not overwrite historical candidate inventories or evidence bundles.
  Every new inventory or bundle is a new immutable file.
- Do not lower, skip, xfail, deselect, or delete an existing test to make a gate
  green.
- After each task, update only the checkboxes completed with fresh evidence.
- Default execution handoff is WorkBuddy in the isolated worktree. WorkBuddy
  must return a checkpoint report after Tasks 2, 8, 14, and 16 containing: task
  range, commit IDs, exact changed paths, observed RED failure, focused GREEN
  result, regression result, unresolved risks, and clean/dirty status. These
  reports are implementation evidence for later Codex review; they are not
  customer acceptance or permission to merge.

## File Map

### Create

- `src/openworkproof/verification.py` — v0.2 profile/arm/decision validation,
  deterministic composition, T1–T3 transactions, readback, replay, and
  independence assessment.
- `src/openworkproof/settlement.py` — AcceptanceTransition transaction,
  EffectiveAcceptance, and SettlementReadiness computation.
- `src/openworkproof/delivery_package.py` — closed manifest, privacy checks,
  atomic package export, static summary, and offline package replay.
- `src/openworkproof/services.py` — application facade shared by CLI and MCP.
- `src/openworkproof/schemas/v0.2/*.schema.json` — installed canonical v0.2
  schemas.
- `src/openworkproof/schemas/v0.2/schema-registry.json` — installed v0.2
  registry.
- `specs/v0.2/*.schema.json` — public byte-identical v0.2 schema mirror.
- `specs/v0.2/schema-registry.json` — public v0.2 registry mirror.
- `tests/test_verification_models_v02.py` — SubjectClaim, Profile, ArmResult,
  Decision, transition, and schema model tests.
- `tests/test_verification_transactions_v02.py` — T1–T3 atomicity, readback,
  recovery, concurrency, and replay tests.
- `tests/test_settlement_readiness.py` — T4/T5 lifecycle and deterministic
  read-model tests.
- `tests/test_delivery_package_v02.py` — manifest, privacy, export, replay, and
  tamper tests.
- `tests/test_v02_interfaces.py` — service/CLI/MCP parity tests.
- `tests/test_v02_adversarial.py` — registered mutation, independence, causal,
  signature, and evidence attacks.
- `tests/test_v02_bundles.py` — Rich #4196 and Dify #33013 v0.2 bundle replay.
- `tests/evidence-bundles/rich-4196-v02-delivery-package.json` — immutable v0.2
  public case export.
- `tests/evidence-bundles/dify-33013-v02-delivery-package.json` — immutable v0.2
  public case export.
- `docs/pilot/README.md` — 21-day pilot operator guide.
- `docs/pilot/subject-claim.example.json` — non-customer example claim.
- `docs/pilot/verification-profile.example.json` — matching example profile.
- `docs/pilot/registered-adversarial-study.json` — closed study registration.
- `docs/pilot/pilot-scorecard.md` — technical and commercial evidence sheet.
- `docs/pilot/delivery-room.css` — local static report styling.

### Modify

- `src/openworkproof/models.py` — v0.2 signed models, closed enums, strict
  validators, and no v0.1 reinterpretation.
- `src/openworkproof/signing.py` — canonical/signed v0.2 domains.
- `src/openworkproof/evidence.py` — append-only v0.2 tables, bounded loaders,
  replay integration, and shared ledger schema.
- `src/openworkproof/acceptance.py` — current-decision requirement and v0.2
  offline acceptance binding.
- `src/openworkproof/state.py` — `proof_ready` requires current VERIFIED;
  REFUTED/UNKNOWN remain evidence-incomplete.
- `src/openworkproof/schema_registry.py` — explicit v0.1/v0.2 registry routing.
- `src/openworkproof/cli.py` — profile, verify, delivery, audit, and settlement
  commands through `services.py`.
- `src/openworkproof/mcp_transport.py` — minimal v0.2 tools through
  `services.py`.
- `src/openworkproof/mcp_server.py` — shared transaction hooks only; no
  duplicate decision logic.
- `pyproject.toml` — package v0.2 schema and pilot static resources.
- `supply-chain/images/trusted-helper/SOURCE_ALLOWLIST` — add only modules
  required for trusted offline replay.
- `tests/conftest.py` — deterministic v0.2 roles, keys, claims, profiles, and
  arm fixtures.
- `tests/test_schema_registry.py` — multi-version immutable registry tests.
- `tests/test_state.py`, `tests/test_acceptance.py`,
  `tests/test_acceptor_rejection.py`, `tests/test_replay.py` — v0.2 state and
  backward-compatibility regressions.
- `tests/test_cli_transport.py` — new transport registrations and error parity.
- `tests/test_export_evidence_bundles.py` — append new v0.2 exports without
  overwriting v0.1 cases.
- `tests/evidence-bundles/verify_evidence_bundle.py` — dispatch v0.1 or v0.2
  offline verification by closed schema version.
- `README.md`, `README_en.md`, `MCP_SERVER.md`,
  `docs/offline-verification.md`, `docs/status.md` — current verified behavior
  and honest commercial boundaries.

## Spec Coverage Map

| Approved design area | Implementation tasks |
|---|---|
| Commercial payer, 21-day offer, payment boundary | Tasks 15 and 17 |
| Release truth and current three failures | Tasks 1, 2, and 16 |
| Role and authority separation | Tasks 3, 6, 8, 10, and 11 |
| SubjectClaim, Profile, arms, results, decision | Tasks 3, 4, 6, and 7 |
| PolicyAnchor and CommitmentAnchor | Tasks 3, 7, 8, and 9 |
| VERIFIED, REFUTED, UNKNOWN | Tasks 4, 6, and 13 |
| Append-only decision and acceptance lifecycle | Tasks 7 and 8 |
| SettlementReadiness deterministic mapping | Tasks 8, 10, 11, and 12 |
| T1–T5 atomicity and COMMIT-ACK recovery | Tasks 7, 8, and 13 |
| Failure reason registry and fail-closed behavior | Tasks 4, 6, and 13 |
| Trust levels and cryptographic-cost boundaries | Tasks 3 and 15 |
| Provider, Verifier, Auditor CLI and MCP | Tasks 10 and 11 |
| Delivery Proof Package and Delivery Room | Tasks 9 and 12 |
| Privacy and data minimization | Task 9 |
| Registered Adversarial Study and fault matrix | Task 13 |
| Rich and Dify v0.2 real-Issue cases | Task 14 |
| Versioning, v0.1 compatibility, v0.2 schemas | Tasks 5, 8, and 14 |
| Technical and commercial pilot gates | Tasks 15, 16, and 17 |
| Deferred SaaS, payment, registry, blockchain scope | Execution Rules and Task 17 |

## Task 1: Create the Isolated Execution Worktree

**Files:** none

- [x] **Step 1: Confirm the approved source commit**

Run from `/Users/molin/Project/openWorkProof`:

```bash
PLAN_PATH=docs/superpowers/plans/2026-08-11-openworkproof-verifiable-delivery-pilot-implementation.md
PLAN_COMMIT="$(git log -1 --format=%H -- "$PLAN_PATH")"
test -n "$PLAN_COMMIT"
git merge-base --is-ancestor 69a3a62 "$PLAN_COMMIT"
git show "$PLAN_COMMIT:$PLAN_PATH" >/dev/null
git show "$PLAN_COMMIT:docs/superpowers/specs/2026-08-11-openworkproof-verifiable-delivery-pilot-design.md" >/dev/null
git status --short
```

Expected: `PLAN_COMMIT` is the documentation commit containing this plan and
the approved design clarification, it descends from `69a3a62`, both documents
exist in that commit, and the status output exposes—but does not modify—the
user-owned dirty files in the original worktree.

- [x] **Step 2: Create the isolated branch and worktree**

Run:

```bash
git worktree add \
  /Users/molin/Project/openWorkProof-verifiable-delivery \
  -b codex/verifiable-delivery-pilot \
  "$PLAN_COMMIT"
```

Expected: a new clean worktree on `codex/verifiable-delivery-pilot`. If either
the branch or directory already exists, stop and inspect it; do not delete or
reuse it blindly.

- [x] **Step 3: Create a clean development environment**

Run in the new worktree:

```bash
python3.12 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -e '.[dev]'
./.venv/bin/python -m pip check
```

Expected: installation succeeds and pip reports no broken requirements.

- [x] **Step 4: Record the fresh baseline without changing tests**

Run:

```bash
./.venv/bin/python -m pytest -q
```

Expected at design time: the historical observation was `2282 passed, 3
failed, 7 skipped`; record the actual fresh result. Do not proceed if any new
failure appears beyond package metadata and the two candidate-inventory
bindings.

## Task 2: Restore the M0 Release Truth Gate

**Files:**

- Create: `supply-chain/images/candidates/<40-char-source-revision>.json`
- Modify only if a code defect remains: `pyproject.toml`
- Modify only if a code defect remains: `src/openworkproof/__init__.py`
- Modify: `docs/status.md`
- Test: `tests/test_package.py`
- Test: `tests/test_candidate_supplychain_integration.py`
- Test: `tests/test_image_supply_chain.py`

- [x] **Step 1: Prove package metadata uses the clean worktree**

Run:

```bash
./.venv/bin/python - <<'PY'
from importlib.metadata import version
import openworkproof
print(openworkproof.__file__)
print(openworkproof.__version__)
print(version('openworkproof'))
assert openworkproof.__version__ == version('openworkproof') == '1.1.1'
PY
./.venv/bin/python -m pytest tests/test_package.py -q
```

Expected: the imported path is this worktree and the package test passes. If
it fails while both source version literals are already `1.1.1`, repair the
environment instead of changing product version numbers.

- [x] **Step 2: Reproduce the two candidate selector failures**

Run:

```bash
./.venv/bin/python -m pytest \
  tests/test_candidate_supplychain_integration.py::test_current_candidate_inventory_binds_execution_runner \
  tests/test_candidate_supplychain_integration.py::test_current_candidate_inventory_binds_fixed_test_source \
  -q
```

Expected: FAIL with `matched 0` before the new immutable inventory exists.

- [x] **Step 3: Assemble revision-specific build contexts**

Run:

```bash
REV=$(git rev-parse HEAD)
ARTIFACT_ROOT=/Users/molin/Project/openWorkProof-delivery
./.venv/bin/python supply-chain/images/prepare_context.py \
  --repo /Users/molin/Project/openWorkProof-verifiable-delivery \
  --source-revision "$REV" \
  --wheelhouse "$ARTIFACT_ROOT/wheelhouse/linux-arm64-cp312-full" \
  --deb-closure "$ARTIFACT_ROOT/debs/linux-arm64-trixie-git" \
  --output-root "$ARTIFACT_ROOT/build-contexts/$REV"
```

Expected: exact `execution/` and `trusted-helper/` contexts with verified
`SHA256SUMS`; no historical context changes.

- [x] **Step 4: Build two OCI archives and two Docker archives**

Run:

```bash
REV=$(git rev-parse HEAD)
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
```

Expected: four regular archives. If the Docker archives contain OCI manifest
media types or fail identity-chain checks, stop; do not hand-edit tar members.
Use the repository's previously reviewed OCI-to-Docker conversion path and
rerun the integration tests before continuing.

- [x] **Step 5: Create the immutable inventory and archive sums**

Copy the structure of the newest valid v0.2 inventory, then replace every
revision, input digest, archive digest, manifest digest, RepoDigest, label,
entrypoint, command, byte size, and path with values measured from this build.
Write it only to:

```text
supply-chain/images/candidates/<REV>.json
```

Generate the archive checksum file:

```bash
REV=$(git rev-parse HEAD)
ARCHIVE_ROOT=/Users/molin/Project/openWorkProof-delivery/oci/$REV
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

Expected: the inventory loader and archive checks accept measured values. Never
copy digests from an older revision.

- [x] **Step 6: Run the M0 gates**

Run:

```bash
REV=$(git rev-parse HEAD)
export OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT=/Users/molin/Project/openWorkProof-delivery
export OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1
export OPENWORKPROOF_DOCKER_TEST_IMAGE="docker.io/openworkproof/execution-test@$(
  jq -r '.images.execution.local_image_id' \
    "supply-chain/images/candidates/$REV.json"
)"
docker image inspect "$OPENWORKPROOF_DOCKER_TEST_IMAGE" >/dev/null
./.venv/bin/python -m pytest tests/test_image_supply_chain.py -q
./.venv/bin/python -m pytest -m supplychain tests/test_candidate_supplychain_integration.py -q
./.venv/bin/python -m pytest -q
```

Expected: all three commands exit 0 with zero failures. Record exact pass/skip
counts and elapsed times in `docs/status.md`.

- [x] **Step 7: Commit the release-truth repair**

Run:

```bash
REV=$(git rev-parse HEAD)
git add "supply-chain/images/candidates/$REV.json" docs/status.md
git diff --cached --check
git commit -m 'build: restore verifiable-delivery release truth'
```

Expected: only the new inventory and accurate status text are committed.

## Task 3: Add SubjectClaim and Verification Profile Models

**Files:**

- Modify: `src/openworkproof/models.py`
- Modify: `src/openworkproof/signing.py`
- Modify: `tests/conftest.py`
- Modify: `tests/test_signing.py`
- Create: `tests/test_verification_models_v02.py`

- [x] **Step 1: Write RED SubjectClaim tests**

Add tests that construct a Manager-signed claim, require sorted unique
acceptance conditions and required artifacts, bind the WorkOrder and customer
Acceptor key, and reject any changed claim statement after signing:

```python
def test_subject_claim_binds_customer_acceptor_and_changes_digest(
    signed_subject_claim,
) -> None:
    changed = signed_subject_claim.model_dump(mode="json")
    changed["claim_statement"] = "different delivery claim"

    with pytest.raises(ValueError, match="digest"):
        SubjectClaim.model_validate(changed)
```

Run:

```bash
./.venv/bin/python -m pytest tests/test_verification_models_v02.py -q
```

Expected: collection fails because `SubjectClaim` does not exist.

- [x] **Step 2: Add the strict SubjectClaim model**

In `models.py`, reuse `SignedProtocolModel`, `Digest64`, `Identifier`,
`CanonicalUTCTime`, `KeyId`, and existing bounded-string helpers:

```python
class SubjectClaim(SignedProtocolModel):
    schema_version: Literal["openworkproof-subject-claim/0.1"]
    claim_id: Digest64
    work_order_digest: Digest64
    claim_statement: Annotated[str, _strict_bounded_text(4096, "claim_statement")]
    delivery_target: Annotated[str, _strict_bounded_text(1024, "delivery_target")]
    source_revision: ObjectId40
    acceptance_conditions: tuple[Identifier, ...]
    excluded_scope: tuple[Identifier, ...]
    required_artifacts: tuple[CanonicalRoot, ...]
    customer_acceptor_key_id: KeyId
    created_at: CanonicalUTCTime
    nonce: Digest64

    @model_validator(mode="after")
    def _closed_claim(self) -> "SubjectClaim":
        for values, label in (
            (self.acceptance_conditions, "acceptance_conditions"),
            (self.excluded_scope, "excluded_scope"),
            (self.required_artifacts, "required_artifacts"),
        ):
            if not values or values != tuple(sorted(set(values))):
                raise ValueError(f"{label} must be non-empty sorted and unique")
        return self
```

Add `subject-claim` and `verification-profile` to both canonical and signed
domain sets in `signing.py`. New signed models opt in to canonical digest
validation so stale signed bytes fail at model validation; existing v0.1
signed models retain their current behavior.

Add strict external-reference models in the same task:

```python
class PolicyAnchor(ProtocolModel):
    schema_version: Literal["openworkproof-policy-anchor/0.1"]
    policy_registry_uri: Annotated[str, _strict_bounded_text(2048, "policy_registry_uri")]
    policy_version: Identifier
    policy_digest: Digest64
    effective_at: CanonicalUTCTime
    resolved_at: CanonicalUTCTime
    resolver_identity: Identifier

class CommitmentAnchor(ProtocolModel):
    schema_version: Literal["openworkproof-commitment-anchor/0.1"]
    work_order_digest: Digest64
    subject_claim_digest: Digest64
    anchored_at: CanonicalUTCTime
    anchor_provider: Literal[
        "git_commit", "git_tag", "github_release",
        "customer_signed_document", "enterprise_timestamp"
    ]
    anchor_reference: Annotated[str, _strict_bounded_text(2048, "anchor_reference")]
```

Test that Level 2/3 fixtures require a `CommitmentAnchor` from the
customer-controlled reference selected by the operator. These objects bind
external state; they do not make OWP the Policy Registry or timestamp authority.

- [x] **Step 3: Write RED VerificationProfileV02 tests**

Cover: exactly one positive arm, at least one negative arm, negative arm differs
by pinned mutant, profile binds SubjectClaim/WorkOrder, standard has one
Verifier binding, high-risk has two distinct bindings, and time/order limits.

Run:

```bash
./.venv/bin/python -m pytest \
  tests/test_verification_models_v02.py -k 'profile' -q
```

Expected: FAIL because profile and arm models do not exist.

- [x] **Step 4: Add closed arm and profile models**

Implement these exact public names in `models.py`:

```python
class VerificationArm(ProtocolModel):
    arm_id: Digest64
    arm_kind: Literal["positive", "negative"]
    source_commit: ObjectId40
    candidate_commit: ObjectId40
    mutant_patch_digest: Digest64 | None
    workspace_manifest_digest: Digest64
    command_digest: Digest64
    container_image_digest: ImageDigest
    fixed_test_source_digest: Digest64
    expected_exit_codes: tuple[SafeNonNegativeInt, ...]
    expected_outcome: Literal["pass", "fail"]
    required_evidence_purposes: tuple[Identifier, ...]
    result_artifact_paths: tuple[CanonicalRoot, ...]

class VerifierBinding(ProtocolModel):
    binding_id: Digest64
    verifier_subject_id: Identifier
    verifier_key_id: KeyId
    verifier_public_key_b64url: PublicKeyB64Url
    controller_factors: tuple[Identifier, ...]
    execution_context_factors: tuple[Identifier, ...]
    valid_from: CanonicalUTCTime
    expires_at: CanonicalUTCTime

class VerificationProfileV02(SignedProtocolModel):
    schema_version: Literal["openworkproof-verification-profile/0.2"]
    profile_id: Digest64
    work_order_digest: Digest64
    subject_claim_digest: Digest64
    delivery_trust_level: Literal[1, 2, 3]
    policy_anchor_digest: Digest64 | None
    commitment_anchor_digest: Digest64 | None
    subject_kind: Literal["tests_passed"]
    assurance_level: Literal["standard", "high_risk"]
    verifier_bindings: tuple[VerifierBinding, ...]
    positive_arm: VerificationArm
    negative_arms: tuple[VerificationArm, ...]
    max_evidence_bytes: SafePositiveInt
    max_output_bytes: SafePositiveInt
    created_at: CanonicalUTCTime
    expires_at: CanonicalUTCTime
    nonce: Digest64
```

The Profile validator requires `commitment_anchor_digest` for Level 2/3 and
also requires `assurance_level == "high_risk"` for Level 3. Every present
anchor must reverse-bind the exact WorkOrder and SubjectClaim at T1 and must
never be treated as payment evidence. Reuse existing WorkOrder key-binding
parsing; do not add a seventh role.

- [x] **Step 5: Run model GREEN and commit**

Run:

```bash
./.venv/bin/python -m pytest tests/test_verification_models_v02.py -q
./.venv/bin/python -m pytest tests/test_contract.py tests/test_signing.py -q
git add src/openworkproof/models.py src/openworkproof/signing.py \
  tests/conftest.py tests/test_signing.py tests/test_verification_models_v02.py
git diff --cached --check
git commit -m 'feat: freeze verifiable delivery claims and profiles'
```

Expected: both suites pass and the commit contains only model/signing fixtures.

## Task 4: Add VerificationArmResult and Closed Reason Codes

**Files:**

- Modify: `src/openworkproof/models.py`
- Modify: `src/openworkproof/signing.py`
- Modify: `tests/test_signing.py`
- Modify: `tests/test_verification_models_v02.py`

- [x] **Step 1: Write the RED three-axis result matrix**

Add parameterized tests for positive success, caught mutant, survived mutant,
not-applied mutant, timeout, crash, resource exhaustion, missing evidence, and
illegal cross-axis combinations:

```python
@pytest.mark.parametrize(
    ("mutation", "execution", "expectation"),
    [
        ("applied", "completed", "satisfied"),
        ("applied", "completed", "contradicted"),
        ("not_applied", "completed", "indeterminate"),
        ("applied", "timed_out", "indeterminate"),
    ],
)
def test_negative_arm_result_axes_are_orthogonal(
    mutation, execution, expectation, arm_result_dict
) -> None:
    value = {**arm_result_dict, "mutation_status": mutation,
             "execution_status": execution,
             "expectation_status": expectation}
    assert VerificationArmResult.model_validate(value)
```

Run and expect import/validation failure before implementation.

- [x] **Step 2: Implement the result model and registry**

Add this exact closed `VerificationReasonCode` literal registry; do not accept
free-form status codes:

```python
VerificationReasonCode = Literal[
    "AUTH_SIGNATURE_INVALID",
    "AUTH_GRANT_EXPIRED",
    "AUTH_GRANT_REVOKED",
    "AUTH_ROLE_MISMATCH",
    "AUTH_CAPABILITY_MISSING",
    "AUTH_NONCE_REUSED",
    "AUTH_SUBJECT_MISMATCH",
    "AUTH_POLICY_ANCHOR_UNAVAILABLE",
    "EXEC_COMMAND_FAILED",
    "EXEC_TIMEOUT",
    "EXEC_CRASHED",
    "EXEC_RESOURCE_EXHAUSTED",
    "EXEC_OUTPUT_LIMIT",
    "EXEC_WORKSPACE_DRIFT",
    "EXEC_DEPENDENCY_DRIFT",
    "MUTATION_APPLIED",
    "MUTATION_NOT_APPLIED",
    "MUTATION_SURVIVED",
    "MUTATION_CAUGHT",
    "MUTATION_TARGET_MISMATCH",
    "MUTATION_CLASSIFIER_UNAVAILABLE",
    "EVIDENCE_MISSING",
    "EVIDENCE_DIGEST_MISMATCH",
    "EVIDENCE_SIGNATURE_INVALID",
    "EVIDENCE_CAUSAL_PARENT_MISSING",
    "EVIDENCE_SIZE_LIMIT_EXCEEDED",
    "EVIDENCE_PUBLICATION_INCOMPLETE",
    "EVIDENCE_BUNDLE_REPLAY_FAILED",
    "INDEPENDENCE_KEY_REUSED",
    "INDEPENDENCE_DOMAIN_OVERLAP",
    "INDEPENDENCE_BUILD_NOT_DISTINCT",
    "INDEPENDENCE_CONTEXT_REUSED",
    "INDEPENDENCE_INSUFFICIENT",
    "INDEPENDENCE_UNPROVEN",
    "ACCEPTANCE_DIGEST_MISMATCH",
    "ACCEPTANCE_ACTOR_UNAUTHORIZED",
    "ACCEPTANCE_ALREADY_TERMINAL",
    "ACCEPTANCE_PREDECESSOR_STALE",
    "ACCEPTANCE_WITHDRAWN",
    "ACCEPTANCE_SUPERSEDED",
    "ACCEPTANCE_TRANSITION_INVALID",
]
```

Then implement:

```python
class VerificationArmResult(SignedProtocolModel):
    schema_version: Literal["openworkproof-verification-arm-result/0.2"]
    arm_result_id: Digest64
    profile_digest: Digest64
    arm_id: Digest64
    arm_kind: Literal["positive", "negative"]
    mutation_status: Literal["not_applicable", "applied", "not_applied"]
    execution_status: Literal[
        "completed", "timed_out", "crashed",
        "resource_exhausted", "evidence_unavailable"
    ]
    expectation_status: Literal["satisfied", "contradicted", "indeterminate"]
    reason_codes: tuple[VerificationReasonCode, ...]
    action_receipt_ids: tuple[Digest64, ...]
    evidence_refs: tuple[EvidenceRef, ...]
    verifier_subject_id: Identifier
    verifier_key_id: KeyId
    verifier_build_digest: Digest64
    dependency_lock_digest: Digest64
    controller_factors: tuple[Identifier, ...]
    execution_context_factors: tuple[Identifier, ...]
    created_at: CanonicalUTCTime
```

Enforce: positive uses `not_applicable`; negative uses applied/not-applied;
not-applied and any non-completed execution require `indeterminate`; satisfied
requires all required EvidenceRefs.

Register `verification-arm-result` as a canonical and signed domain, and keep
the exact-domain regression in `tests/test_signing.py` synchronized.

- [x] **Step 3: Add invalid-input tests**

Prove bool-as-int, duplicate reason codes, unsorted receipt IDs, missing
evidence, positive-with-mutant, and crash-with-satisfied fail at model
validation rather than becoming UNKNOWN.

- [x] **Step 4: Run GREEN and commit**

Run:

```bash
./.venv/bin/python -m pytest tests/test_verification_models_v02.py -q
git add src/openworkproof/models.py src/openworkproof/signing.py \
  tests/test_verification_models_v02.py
git diff --cached --check
git commit -m 'feat: model falsifiable verification arm results'
```

Expected: all result-axis and invalid-input tests pass.

## Task 5: Prepare Multi-Version Schema Registry Routing

**Files:**

- Modify: `src/openworkproof/schema_registry.py`
- Modify: `tests/test_schema_registry.py`

- [x] **Step 1: Write RED routing tests without freezing incomplete v0.2 bytes**

Test that v0.1 digests remain byte-identical, an unknown version is rejected,
and a caller can request an explicitly registered version map. Do not generate
v0.2 resources yet because VerificationDecision and AcceptanceTransitionReceipt
are added by later tasks.

Run:

```bash
./.venv/bin/python -m pytest tests/test_schema_registry.py -k 'v02 or v01' -q
```

Expected: FAIL because the registry still assumes one global `_VERSION`.

- [x] **Step 2: Implement explicit version routing**

Replace the single `_VERSION` assumption with closed version maps:

```python
_OBJECT_PATHS_BY_VERSION = {
    "0.1": V01_OBJECT_PATHS,
}
_SCHEMA_FACTORIES_BY_VERSION = {
    "0.1": V01_SCHEMA_FACTORIES,
}
```

Keep `_FROZEN_V01_DIGESTS` and `_FROZEN_V01_REGISTRY` exact. The implementation
must make adding the complete `0.2` map after Task 8 a closed additive change.
Extend the module CLI with a required `--version` choice sourced from the same
closed map; `--destination` and `--mirror` remain explicit paths. An unknown or
unregistered version must fail before any file is written.

- [x] **Step 3: Run v0.1 regression and commit routing only**

Run:

```bash
./.venv/bin/python -m pytest tests/test_schema_registry.py -q
git diff --exit-code -- src/openworkproof/schemas/v0.1 specs/v0.1
git add src/openworkproof/schema_registry.py tests/test_schema_registry.py
git diff --cached --check
git commit -m 'refactor: route immutable protocol schema versions'
```

Expected: v0.1 schema tests pass and no v0.1 byte changes.

## Task 6: Implement Deterministic VerificationDecision Composition

**Files:**

- Create: `src/openworkproof/verification.py`
- Modify: `src/openworkproof/models.py`
- Modify: `src/openworkproof/signing.py`
- Modify: `tests/test_verification_models_v02.py`

- [x] **Step 1: Write RED decision-table tests**

Encode the approved matrix:

```python
@pytest.mark.parametrize(
    ("positive", "negative", "expected"),
    [
        ("satisfied", "satisfied", "VERIFIED"),
        ("contradicted", "satisfied", "REFUTED"),
        ("satisfied", "contradicted", "REFUTED"),
        ("satisfied", "indeterminate", "UNKNOWN"),
    ],
)
def test_compose_verification_decision_matrix(
    positive, negative, expected, decision_case
) -> None:
    assert compose_verification_decision(
        decision_case.with_statuses(positive, negative)
    ).decision == expected
```

Also test no negative arm, missing required evidence, duplicate/reordered arm
results, extra signatures, and current-decision supersession.

- [x] **Step 2: Add decision and independence models**

Implement exact public types in `models.py`:

```python
class VerificationIndependenceAssessment(ProtocolModel):
    distinct_subjects: bool
    distinct_keys: bool
    distinct_controllers: bool
    distinct_execution_contexts: bool
    reason_codes: tuple[VerificationReasonCode, ...]

    @property
    def is_sufficient(self) -> bool:
        return (
            self.distinct_subjects
            and self.distinct_keys
            and self.distinct_controllers
            and self.distinct_execution_contexts
        )

class VerificationArmResultReference(ProtocolModel):
    arm_id: Digest64
    arm_result_id: Digest64
    arm_result_digest: Digest64
    evidence_snapshot_digest: Digest64

class VerificationDecisionSignature(ProtocolModel):
    verifier_subject_id: Identifier
    verifier_key_id: KeyId
    signature_alg: Literal["Ed25519"]
    signature: Signature

class VerificationDecision(ProtocolModel):
    schema_version: Literal["openworkproof-verification-decision/0.2"]
    decision_id: Digest64
    digest: Digest64
    work_order_digest: Digest64
    subject_claim_digest: Digest64
    profile_id: Digest64
    profile_digest: Digest64
    arm_results: tuple[VerificationArmResultReference, ...]
    assurance_level: Literal["standard", "high_risk"]
    decision: Literal["VERIFIED", "REFUTED", "UNKNOWN"]
    independence: VerificationIndependenceAssessment
    reason_codes: tuple[VerificationReasonCode, ...]
    supersedes_decision_id: Digest64 | None
    supersedes_decision_digest: Digest64 | None
    causal_parent_receipt_ids: tuple[Digest64, ...]
    causal_parent_decision_ids: tuple[Digest64, ...]
    decided_at: CanonicalUTCTime
    nonce: Digest64
    verifier_signatures: tuple[VerificationDecisionSignature, ...]

class VerificationDecisionDraft(ProtocolModel):
    decision_id: Digest64
    work_order_digest: Digest64
    subject_claim_digest: Digest64
    profile_id: Digest64
    profile_digest: Digest64
    arm_results: tuple[VerificationArmResultReference, ...]
    assurance_level: Literal["standard", "high_risk"]
    decision: Literal["VERIFIED", "REFUTED", "UNKNOWN"]
    independence: VerificationIndependenceAssessment
    reason_codes: tuple[VerificationReasonCode, ...]
    supersedes_decision_id: Digest64 | None
    supersedes_decision_digest: Digest64 | None
    causal_parent_receipt_ids: tuple[Digest64, ...]
    causal_parent_decision_ids: tuple[Digest64, ...]
    decided_at: CanonicalUTCTime
    nonce: Digest64

class DecisionDraftRequest(ProtocolModel):
    decision_id: Digest64
    decided_at: CanonicalUTCTime
    nonce: Digest64
```

Add `verification-decision` as a canonical signing domain. Model validation
requires one primary Verifier signature for standard assurance and exactly the
primary plus Profile-bound independent Verifier, byte-sorted by key ID, for
high-risk assurance. Missing, extra, duplicate, wrong-key, or payload-divergent
signatures are invalid input and create no decision.

Define the public invalid-input exception in `verification.py` before the
composer:

```python
class VerificationInputError(ValueError):
    """Authenticated protocol input is invalid; no decision may be created."""
```

- [x] **Step 3: Implement a pure composer**

In `verification.py`, implement:

```python
def assess_independence(
    profile: VerificationProfileV02,
    arm_results: tuple[VerificationArmResult, ...],
) -> VerificationIndependenceAssessment:
    required = 2 if profile.assurance_level == "high_risk" else 1
    subjects = {result.verifier_subject_id for result in arm_results}
    keys = {result.verifier_key_id for result in arm_results}
    controllers = {result.controller_factors for result in arm_results}
    contexts = {result.execution_context_factors for result in arm_results}
    checks = {
        "distinct_subjects": len(subjects) >= required,
        "distinct_keys": len(keys) >= required,
        "distinct_controllers": len(controllers) >= required,
        "distinct_execution_contexts": len(contexts) >= required,
    }
    codes = tuple(
        code
        for field, code in (
            ("distinct_subjects", "INDEPENDENCE_INSUFFICIENT"),
            ("distinct_keys", "INDEPENDENCE_KEY_REUSED"),
            ("distinct_controllers", "INDEPENDENCE_DOMAIN_OVERLAP"),
            ("distinct_execution_contexts", "INDEPENDENCE_CONTEXT_REUSED"),
        )
        if not checks[field]
    )
    return VerificationIndependenceAssessment(**checks, reason_codes=codes)

def decision_reason_codes(
    arm_results: tuple[VerificationArmResult, ...],
    independence: VerificationIndependenceAssessment,
) -> tuple[VerificationReasonCode, ...]:
    return tuple(sorted({
        *independence.reason_codes,
        *(code for result in arm_results for code in result.reason_codes),
    }))

def compose_verification_decision(
    *,
    profile: VerificationProfileV02,
    subject_claim: SubjectClaim,
    arm_results: tuple[VerificationArmResult, ...],
    previous_decision: VerificationDecision | None,
    decision_id: str,
    decided_at: datetime,
    nonce: str,
) -> VerificationDecisionDraft:
    ordered_ids = tuple(result.arm_result_id for result in arm_results)
    if ordered_ids != tuple(sorted(set(ordered_ids))):
        raise VerificationInputError("arm results must be sorted and unique")
    if any(result.profile_digest != profile.digest for result in arm_results):
        raise VerificationInputError("arm result profile mismatch")
    positive = tuple(result for result in arm_results if result.arm_kind == "positive")
    negative = tuple(result for result in arm_results if result.arm_kind == "negative")
    if len(positive) != 1 or len(negative) != len(profile.negative_arms):
        raise VerificationInputError("arm result set is incomplete")
    independence = assess_independence(profile, arm_results)
    if positive[0].expectation_status == "contradicted" or any(
        result.expectation_status == "contradicted" for result in negative
    ):
        decision = "REFUTED"
    elif positive[0].expectation_status != "satisfied" or any(
        result.expectation_status != "satisfied" for result in negative
    ) or not independence.is_sufficient:
        decision = "UNKNOWN"
    else:
        decision = "VERIFIED"
    return VerificationDecisionDraft(
        decision_id=decision_id,
        work_order_digest=profile.work_order_digest,
        subject_claim_digest=profile.subject_claim_digest,
        profile_digest=profile.digest,
        profile_id=profile.profile_id,
        decision=decision,
        arm_results=tuple(
            VerificationArmResultReference(
                arm_id=result.arm_id,
                arm_result_id=result.arm_result_id,
                arm_result_digest=result.digest,
                evidence_snapshot_digest=evidence_snapshot_digest(result.evidence_refs),
            )
            for result in arm_results
        ),
        assurance_level=profile.assurance_level,
        independence=independence,
        reason_codes=decision_reason_codes(arm_results, independence),
        supersedes_decision_id=(
            None if previous_decision is None else previous_decision.decision_id
        ),
        supersedes_decision_digest=(
            None if previous_decision is None else previous_decision.digest
        ),
        causal_parent_receipt_ids=tuple(sorted({
            receipt_id for result in arm_results
            for receipt_id in result.action_receipt_ids
        })),
        causal_parent_decision_ids=(
            () if previous_decision is None else (previous_decision.decision_id,)
        ),
        decided_at=decided_at,
        nonce=nonce,
    )
```

The function must have no filesystem, database, clock, network, or LLM access.
Pass `decided_at` and `decision_id` through a deterministic draft request, not
by reading wall time inside the composer. Import and reuse
`openworkproof.acceptance.evidence_snapshot_digest`; do not create a second
snapshot-digest algorithm.

- [x] **Step 4: Separate invalid input from UNKNOWN**

Malformed schema, bad signatures, unordered/duplicate arm IDs, wrong profile,
wrong claim, stale supersedes, or missing causal parents must raise
`VerificationInputError` before a decision object exists. Valid infrastructure
or evidence uncertainty produces signed UNKNOWN with explicit reason codes.

- [x] **Step 5: Run GREEN and commit**

Run:

```bash
./.venv/bin/python -m pytest \
  tests/test_verification_models_v02.py -q
git add src/openworkproof/models.py src/openworkproof/signing.py \
  src/openworkproof/verification.py tests/test_verification_models_v02.py
git diff --cached --check
git commit -m 'feat: compose three-state verification decisions'
```

Expected: the complete matrix and independence tests pass.

## Task 7: Add T1–T3 Append-Only Ledger Transactions

**Files:**

- Modify: `src/openworkproof/evidence.py`
- Modify: `src/openworkproof/verification.py`
- Create: `tests/test_verification_transactions_v02.py`

- [x] **Step 1: Write RED schema and zero-write tests**

Assert exact new tables and snapshot all protocol tables before injecting a
pre-COMMIT failure:

```python
def test_profile_precommit_failure_has_zero_protocol_writes(v02_case) -> None:
    before = snapshot_all_tables(v02_case.ledger_path)
    with pytest.raises(VerificationTransactionError):
        commit_verification_profile(
            v02_case.ledger_path,
            v02_case.claim,
            v02_case.profile,
            fault="before_commit",
        )
    assert snapshot_all_tables(v02_case.ledger_path) == before
```

Run and expect missing-table/function failures.

- [x] **Step 2: Add append-only tables**

Extend the authoritative ledger schema with canonical JSON plus indexed
identifiers:

```sql
CREATE TABLE subject_claims (
  claim_id TEXT PRIMARY KEY,
  claim_json BLOB NOT NULL UNIQUE
);
CREATE TABLE verification_profiles_v02 (
  profile_id TEXT PRIMARY KEY,
  subject_claim_id TEXT NOT NULL UNIQUE,
  profile_json BLOB NOT NULL UNIQUE
);
CREATE TABLE external_anchors (
  anchor_digest TEXT PRIMARY KEY,
  anchor_kind TEXT NOT NULL,
  anchor_json BLOB NOT NULL UNIQUE
);
CREATE TABLE verification_arm_results (
  arm_result_id TEXT PRIMARY KEY,
  profile_id TEXT NOT NULL,
  arm_id TEXT NOT NULL,
  arm_result_json BLOB NOT NULL UNIQUE,
  UNIQUE(profile_id, arm_id, arm_result_id)
);
CREATE TABLE verification_decisions (
  decision_id TEXT PRIMARY KEY,
  predecessor_id TEXT UNIQUE,
  decision_json BLOB NOT NULL UNIQUE
);
CREATE TABLE verification_decision_parents (
  decision_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  arm_result_id TEXT NOT NULL,
  PRIMARY KEY(decision_id, ordinal),
  UNIQUE(decision_id, arm_result_id)
);
```

Canonical bytes remain replay authority; indexed values are revalidated.

- [x] **Step 3: Implement T1 and T2**

Add `commit_verification_profile` and `commit_verification_arm_result` using
the existing target lock and `BEGIN IMMEDIATE`. T1 atomically stores the exact
PolicyAnchor and CommitmentAnchor rows referenced by the profile; Level 2/3
reject a missing customer-domain commitment. Each transaction validates
exact WorkOrder, role, signature, nonce, digest, predecessor, evidence limit,
and replay state inside the transaction.

- [x] **Step 4: Implement T3 and readback**

Add `prepare_verification_decision`, which loads a frozen validated ledger
snapshot and calls the pure composer to return exact signing bytes. Add
`commit_verification_decision`, which recomputes the pure decision from the same
frozen inputs, compares exact canonical bytes, inserts decision plus ordered
parents, commits, then performs exact readback. Expose committed and
indeterminate error types matching existing acceptance transaction behavior.

- [x] **Step 5: Add COMMIT-ACK, concurrency, and tamper tests**

Cover commit-then-raise ACK loss, failed readback, concurrent same predecessor,
duplicate result, stale supersedes, tampered canonical JSON, and cleanup
failure. Expected: committed truth is recoverable, indeterminate blocks blind
retry, and concurrency has one winner.

- [x] **Step 6: Run GREEN and commit**

Run:

```bash
./.venv/bin/python -m pytest \
  tests/test_verification_transactions_v02.py \
  tests/test_receipt_chain.py \
  tests/test_replay.py -q
git add src/openworkproof/evidence.py src/openworkproof/verification.py \
  tests/test_verification_transactions_v02.py
git diff --cached --check
git commit -m 'feat: commit append-only verification transactions'
```

Expected: all focused ledger and replay tests pass.

## Task 8: Add Acceptance Transitions and Settlement Read Models

**Files:**

- Create: `src/openworkproof/settlement.py`
- Modify: `src/openworkproof/models.py`
- Modify: `src/openworkproof/evidence.py`
- Modify: `src/openworkproof/acceptance.py`
- Modify: `src/openworkproof/state.py`
- Modify: `src/openworkproof/schema_registry.py`
- Modify: `pyproject.toml`
- Create: `src/openworkproof/schemas/v0.2/*.json`
- Create: `specs/v0.2/*.json`
- Create: `tests/test_settlement_readiness.py`
- Modify: `tests/test_schema_registry.py`
- Modify: `tests/test_acceptance.py`
- Modify: `tests/test_acceptor_rejection.py`

- [x] **Step 1: Write RED deterministic mapping tests**

Encode the approved priority table for WITHDRAWN, SUPERSEDED, SUSPENDED,
ACCEPTED_FOR_SETTLEMENT, READY_FOR_ACCEPTANCE, rejection, and fallback
NOT_READY. Run and expect missing model/service failures.

- [x] **Step 2: Add the transition model**

Implement:

```python
class AcceptanceTransitionReceipt(SignedProtocolModel):
    schema_version: Literal["openworkproof-acceptance-transition/0.2"]
    protocol_version: Literal["0.2"]
    transition_id: Digest64
    work_order_digest: Digest64
    target_acceptance_id: Digest64
    target_acceptance_digest: Digest64
    verification_decision_id: Digest64
    verification_decision_digest: Digest64
    transition: Literal["withdrawn", "superseded"]
    replacement_acceptance_id: Digest64 | None
    replacement_acceptance_digest: Digest64 | None
    reason_code: Literal[
        "EVIDENCE_REFUTED", "EVIDENCE_UNKNOWN", "SCOPE_CHANGED",
        "REPLACED_DELIVERY", "MANUAL_WITHDRAWAL"
    ]
    causal_parent_ids: tuple[Digest64, ...]
    decided_at: CanonicalUTCTime
    nonce: Digest64
```

Only the WorkOrder-bound Acceptor may sign. Withdrawal forbids replacement;
supersession requires a different replacement acceptance.

- [x] **Step 3: Add T5 storage and commit**

Create `acceptance_transitions` and `acceptance_transition_parents` tables.
Implement `commit_acceptance_transition` with exact current predecessor,
Acceptor signature, COMMIT-ACK readback, zero-write failure, and one-winner
concurrency.

- [x] **Step 4: Implement pure read models**

In `settlement.py`, add:

```python
class EffectiveAcceptance(str, Enum):
    NONE = "NONE"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    WITHDRAWN = "WITHDRAWN"
    SUPERSEDED = "SUPERSEDED"

class SettlementReadiness(str, Enum):
    NOT_READY = "NOT_READY"
    READY_FOR_ACCEPTANCE = "READY_FOR_ACCEPTANCE"
    ACCEPTED_FOR_SETTLEMENT = "ACCEPTED_FOR_SETTLEMENT"
    SUSPENDED = "SUSPENDED"
    WITHDRAWN = "WITHDRAWN"
    SUPERSEDED = "SUPERSEDED"

class AcceptanceHistory(ProtocolModel):
    acceptance: AcceptanceReceipt | None
    rejection: AcceptanceRejectionReceipt | None
    withdrawal: AcceptanceTransitionReceipt | None
    supersession: AcceptanceTransitionReceipt | None
    current_decision: VerificationDecision | None

class SettlementSnapshot(BaseModel):
    current_decision_id: Digest64 | None
    effective_acceptance: EffectiveAcceptance
    settlement_readiness: SettlementReadiness

def effective_acceptance(validated_history: AcceptanceHistory) -> EffectiveAcceptance:
    if validated_history.withdrawal is not None:
        return EffectiveAcceptance.WITHDRAWN
    if validated_history.supersession is not None:
        return EffectiveAcceptance.SUPERSEDED
    if validated_history.acceptance is None:
        return EffectiveAcceptance.NONE
    if validated_history.current_decision is None or (
        validated_history.current_decision.decision != "VERIFIED"
    ):
        return EffectiveAcceptance.SUSPENDED
    return EffectiveAcceptance.ACTIVE

def settlement_readiness(
    *, decision: VerificationDecision | None,
    acceptance: EffectiveAcceptance,
    rejection: AcceptanceRejectionReceipt | None,
) -> SettlementReadiness:
    if acceptance is EffectiveAcceptance.WITHDRAWN:
        return SettlementReadiness.WITHDRAWN
    if acceptance is EffectiveAcceptance.SUPERSEDED:
        return SettlementReadiness.SUPERSEDED
    if acceptance is EffectiveAcceptance.SUSPENDED:
        return SettlementReadiness.SUSPENDED
    if decision is not None and decision.decision == "VERIFIED":
        if acceptance is EffectiveAcceptance.ACTIVE:
            return SettlementReadiness.ACCEPTED_FOR_SETTLEMENT
        if rejection is None:
            return SettlementReadiness.READY_FOR_ACCEPTANCE
    return SettlementReadiness.NOT_READY
```

`SettlementSnapshot` is a frozen, extra-forbid read model rather than a signed
`ProtocolModel`; its enum values must support normal JSON round trips.

No database access inside either function. CLI, MCP, package replay, and
Delivery Room must call these same functions. Add a bounded
`read_settlement_snapshot(ledger: Path) -> SettlementSnapshot` loader that
validates canonical rows, then calls only these pure functions.

- [x] **Step 5: Bind acceptance to current VERIFIED**

Update acceptance request and commit validation so the exact current decision
must be VERIFIED. A later REFUTED or UNKNOWN decision preserves historical
AcceptanceReceipt but derives SUSPENDED.

- [x] **Step 6: Generate and freeze the complete v0.2 schema set**

Now that all v0.2 protocol models exist, register exactly SubjectClaim,
PolicyAnchor, CommitmentAnchor, VerificationProfileV02,
VerificationArmResult, VerificationDecision, and
AcceptanceTransitionReceipt. Generate canonical resources and public mirrors:

```bash
./.venv/bin/python -m openworkproof.schema_registry \
  --version 0.2 \
  --destination src/openworkproof/schemas/v0.2 \
  --mirror specs/v0.2
diff -r src/openworkproof/schemas/v0.2 specs/v0.2
git diff --exit-code -- src/openworkproof/schemas/v0.1 specs/v0.1
WHEEL_OUT="$(mktemp -d)"
./.venv/bin/python -m pip wheel --no-deps -w "$WHEEL_OUT" .
./.venv/bin/python - <<'PY' "$WHEEL_OUT"
from pathlib import Path
import sys
import zipfile

wheels = tuple(Path(sys.argv[1]).glob("openworkproof-*.whl"))
assert len(wheels) == 1, wheels
with zipfile.ZipFile(wheels[0]) as archive:
    names = set(archive.namelist())
assert any("schemas/v0.1" in name for name in names)
assert any("schemas/v0.2" in name for name in names)
PY
./.venv/bin/python -m pytest tests/test_schema_registry.py tests/test_package.py -q
```

Expected: mirrors are byte-identical, v0.1 is unchanged, and the wheel contains
both schema versions.

- [x] **Step 7: Run lifecycle GREEN and commit**

Run:

```bash
./.venv/bin/python -m pytest \
  tests/test_settlement_readiness.py \
  tests/test_acceptance.py \
  tests/test_acceptor_rejection.py \
  tests/test_state.py -q
git add src/openworkproof/models.py src/openworkproof/evidence.py \
  src/openworkproof/acceptance.py src/openworkproof/state.py \
  src/openworkproof/settlement.py src/openworkproof/schema_registry.py \
  src/openworkproof/schemas/v0.2 specs/v0.2 pyproject.toml \
  tests/test_settlement_readiness.py tests/test_schema_registry.py \
  tests/test_acceptance.py tests/test_acceptor_rejection.py
git diff --cached --check
git commit -m 'feat: derive acceptance and settlement readiness'
```

Expected: all mapping, authority, transition, replay, and regression tests pass.

## Task 9: Build the Portable Delivery Proof Package

**Files:**

- Create: `src/openworkproof/delivery_package.py`
- Create: `docs/pilot/delivery-room.css`
- Create: `tests/test_delivery_package_v02.py`
- Modify: `pyproject.toml`

- [x] **Step 1: Write RED closed-manifest tests**

Test exact required paths, including PolicyAnchor and CommitmentAnchor when
referenced; sorted entries, SHA-256, byte size, media type, privacy class, path
traversal, symlink, hardlink, oversized files, secret patterns, duplicate
paths, and missing required files. Reject Delivery Package export for Level 1;
that level produces only its existing offline Evidence Bundle. Permit package
export only for Level 2/3 profiles.

The closed minimum layout is:

```text
manifest.json
subject-claim.json
work-order.json
verification-profile.json
verification-decision.json
execution-ledger/receipts.json
execution-ledger/receipt-parents.json
execution-ledger/evidence-publications.json
evidence/positive/<manifest-bound-files>
evidence/negative/<manifest-bound-files>
public-keys/<key-id>.json
settlement-readiness.json
summary.html
verify.sh
```

`manifest.json` is the signed root object and therefore is not an entry inside
its own `entries` tuple; `digest_manifest()` authenticates it separately. Every
other emitted regular file, including `summary.html` and `verify.sh`, must have
exactly one manifest entry.

Require `acceptance/acceptance-receipt.json`, rejection, withdrawal, or
supersession objects exactly when the derived state references them. Require
`anchors/policy-anchor.json` and `anchors/commitment-anchor.json` exactly when
the signed Profile references their digests. `summary.pdf` is optional and is
never replay authority.

- [x] **Step 2: Implement manifest models and privacy policy**

Add a closed `DeliveryManifest` and `DeliveryManifestEntry` in
`delivery_package.py`. Bind `anchors/policy-anchor.json` and
`anchors/commitment-anchor.json` whenever their digests appear in the signed
profile/claim. Allow only regular files below the package root. Reject private
keys, tokens, `.env`, unbounded stdout/stderr, absolute paths, `..`, symlinks,
and files outside the Evidence allowlist.

Use these result types:

```python
class DeliveryManifestEntry(ProtocolModel):
    path: CanonicalRoot
    sha256: Digest64
    size_bytes: SafeNonNegativeInt
    media_type: Identifier
    privacy_class: Literal["public", "customer_private"]
    required: bool

class DeliveryManifest(ProtocolModel):
    schema_version: Literal["openworkproof-delivery-manifest/0.1"]
    privacy_view: Literal["public", "customer_private"]
    work_order_digest: Digest64
    subject_claim_digest: Digest64
    verification_decision_digest: Digest64
    entries: tuple[DeliveryManifestEntry, ...]

class DeliveryVerificationResult(ProtocolModel):
    current_decision: Literal["VERIFIED", "REFUTED", "UNKNOWN"]
    effective_acceptance: EffectiveAcceptance
    settlement_readiness: SettlementReadiness
    manifest_digest: Digest64
```

- [x] **Step 3: Implement offline package replay**

Implement:

```python
def verify_delivery_package(package_root: Path) -> DeliveryVerificationResult:
    manifest = load_and_verify_manifest(package_root)
    anchors = load_and_verify_anchors(package_root, manifest)
    history = load_signed_history(package_root, manifest, anchors)
    decision = replay_verification(history)
    acceptance = replay_acceptance(history)
    readiness = settlement_readiness(
        decision=decision,
        acceptance=acceptance,
        rejection=history.rejection,
    )
    return DeliveryVerificationResult(
        current_decision=decision.decision,
        effective_acceptance=acceptance,
        settlement_readiness=readiness,
        manifest_digest=digest_manifest(manifest),
    )

def digest_manifest(manifest: DeliveryManifest) -> str:
    payload = rfc8785.dumps(manifest.model_dump(mode="json"))
    return hashlib.sha256(payload).hexdigest()
```

Implement these private helpers with exact signatures and fail-closed behavior:

- `load_and_verify_anchors(package_root: Path, manifest: DeliveryManifest) ->
  tuple[PolicyAnchor | None, CommitmentAnchor | None]` loads only
  manifest-bound anchors and recomputes canonical digests;
- `load_signed_history(package_root: Path, manifest: DeliveryManifest,
  anchors: tuple[PolicyAnchor | None, CommitmentAnchor | None]) ->
  AcceptanceHistory` loads only manifest-bound signed objects and validates the
  complete causal graph;
- `replay_verification(history: AcceptanceHistory) -> VerificationDecision`
  recomputes and returns the unique current decision;
- `replay_acceptance(history: AcceptanceHistory) -> EffectiveAcceptance`
  calls the shared pure acceptance derivation and returns its effective state.

Do not leave docstring-only or placeholder helper bodies; each helper must have
direct negative tests for missing, extra, digest-mismatched, or causally
disconnected inputs.

Implement `export_delivery_package(ledger: Path, output: Path, *,
privacy_view: Literal["public", "customer_private"]) -> DeliveryManifest` as
the only public export entry point. The public view must contain only public
entries; the customer-private view may contain both public and explicitly
allowlisted customer-private entries. Never mutate one view into the other in
place. Construct
`DeliveryVerificationResult` with keyword arguments, including the verified
manifest digest; positional construction is forbidden by the project's strict
model style.

The verifier must not read a live ledger, network, wall-clock policy, or report
HTML.

- [x] **Step 4: Implement atomic export**

Write into a same-parent dot-prefixed temporary directory, generate JSON truth
and HTML from the same read model, verify the completed temporary package, then
use `os.rename` for atomic publication. On any failure, remove only the exact
temporary directory and leave the final path and ledger untouched.

- [x] **Step 5: Add tamper and failed-export tests**

Mutate every required file, manifest entry, public key, arm result, decision,
acceptance, CSS-independent HTML label, and readiness file. Test pre-write,
mid-write, verify, rename, and cleanup failures. Expected: replay fails closed;
ledger snapshot and prior final directory remain byte-identical.

- [x] **Step 6: Run GREEN and commit**

Run:

```bash
./.venv/bin/python -m pytest tests/test_delivery_package_v02.py -q
git add src/openworkproof/delivery_package.py docs/pilot/delivery-room.css \
  tests/test_delivery_package_v02.py pyproject.toml
git diff --cached --check
git commit -m 'feat: export offline verifiable delivery packages'
```

Expected: package export, replay, privacy, and fault suites pass.

## Task 10: Add One Application Service Layer

**Files:**

- Create: `src/openworkproof/services.py`
- Modify: `src/openworkproof/mcp_server.py`
- Create: `tests/test_v02_interfaces.py`

- [x] **Step 1: Write RED facade parity tests**

Test that profile validation, arm commit, decision composition, package export,
audit replay, and settlement status return one closed result shape without
importing CLI or MCP modules.

- [x] **Step 2: Implement the facade**

Expose only:

```python
class OpenWorkProofServices:
    def validate_profile(self, payload: Mapping[str, object]) -> dict:
        profile = VerificationProfileV02.model_validate(payload)
        return profile.model_dump(mode="json")

    def commit_arm_result(self, ledger: Path, payload: Mapping[str, object]) -> dict:
        result = VerificationArmResult.model_validate(payload)
        return commit_verification_arm_result(ledger, result).model_dump(mode="json")

    def prepare_decision(self, ledger: Path, payload: Mapping[str, object]) -> dict:
        request = DecisionDraftRequest.model_validate(payload)
        return prepare_verification_decision(ledger, request).model_dump(mode="json")

    def commit_decision(self, ledger: Path, payload: Mapping[str, object]) -> dict:
        decision = VerificationDecision.model_validate(payload)
        return commit_verification_decision(ledger, decision).model_dump(mode="json")

    def build_delivery(
        self,
        ledger: Path,
        output: Path,
        privacy_view: Literal["public", "customer_private"],
    ) -> dict:
        manifest = export_delivery_package(
            ledger,
            output,
            privacy_view=privacy_view,
        )
        return manifest.model_dump(mode="json")

    def audit_delivery(self, package: Path) -> dict:
        return verify_delivery_package(package).model_dump(mode="json")

    def get_settlement_readiness(self, ledger: Path) -> dict:
        return read_settlement_snapshot(ledger).model_dump(mode="json")
```

Each method calls existing model/transaction/package functions. It must not
duplicate decision, acceptance, or settlement rules.

- [x] **Step 3: Remove v0.2 business decisions from transport code**

If any v0.2 branch was temporarily added to `mcp_server.py`, replace it with a
service call. Preserve all existing v0.1 handler behavior.

Checkpoint: no v0.2 business branch existed in `mcp_server.py`; the audit
therefore required no transport-code edit, and the 70 existing MCP tests pass.

- [x] **Step 4: Run GREEN and commit**

Run:

```bash
./.venv/bin/python -m pytest tests/test_v02_interfaces.py -k services -q
./.venv/bin/python -m pytest tests/test_mcp_server.py -q
git add src/openworkproof/services.py src/openworkproof/mcp_server.py \
  tests/test_v02_interfaces.py
git diff --cached --check
git commit -m 'refactor: share verifiable delivery application services'
```

Expected: facade and all existing MCP server regressions pass.

## Task 11: Add CLI and MCP Surfaces

**Files:**

- Modify: `src/openworkproof/cli.py`
- Modify: `src/openworkproof/mcp_transport.py`
- Modify: `tests/test_v02_interfaces.py`
- Modify: `tests/test_cli_transport.py`
- Modify: `MCP_SERVER.md`

- [x] **Step 1: Write RED CLI parser tests**

Require commands for `profile-validate`, `verify-positive`, `verify-negative`,
`verify-compose`, `delivery-build`, `audit-replay`, `audit-explain`,
`audit-compare`, and `settlement-status`. Test JSON error parity and no private
key arguments for read-only operations.

- [x] **Step 2: Implement thin CLI commands**

Each parser branch loads bounded JSON/path inputs, invokes one
`OpenWorkProofServices` method, and emits sorted JSON. No CLI branch constructs
a VerificationDecision or SettlementReadiness directly. `delivery-build`
requires `--privacy-view public|customer_private`; it has no silent default.

- [x] **Step 3: Write RED MCP registration and parity tests**

Require the approved tool names and compare their result dictionaries with the
equivalent service call for the same fixture. Simulate COMMIT ACK loss and
assert MCP returns committed/indeterminate truth without blind retry.

- [x] **Step 4: Implement minimal MCP tools**

Register only the approved profile, evidence, verification, delivery, and
settlement tools. Acceptor signing remains an external/local-key operation;
MCP must never accept or store an Acceptor private key.

- [x] **Step 5: Run interface GREEN and commit**

Run:

```bash
./.venv/bin/python -m pytest \
  tests/test_v02_interfaces.py \
  tests/test_cli_transport.py \
  tests/test_mcp_server.py -q
git add src/openworkproof/cli.py src/openworkproof/mcp_transport.py \
  tests/test_v02_interfaces.py tests/test_cli_transport.py MCP_SERVER.md
git diff --cached --check
git commit -m 'feat: expose verifiable delivery CLI and MCP tools'
```

Expected: CLI/MCP/service parity and existing transport tests pass.

## Task 12: Build the Static Customer Delivery Room

**Files:**

- Modify: `src/openworkproof/delivery_package.py`
- Modify: `docs/pilot/delivery-room.css`
- Modify: `tests/test_delivery_package_v02.py`

- [x] **Step 1: Write RED customer-language tests**

Parse generated HTML and require exactly five customer questions: authority,
target/version, agreed result, falsification control, and current acceptance
readiness. Require visible UNKNOWN explanation and next action. Reject payment,
escrow, settlement-completed, or customer-adoption claims.

- [x] **Step 2: Implement deterministic HTML rendering**

Render only escaped values from verified JSON read models. Use fixed templates
stored as Python string constants or packaged text resources; do not introduce
a web framework or JavaScript build. The page may link to evidence details but
must not execute signatures or hold private keys.

- [x] **Step 3: Verify JSON/HTML agreement**

For every VERIFIED, REFUTED, UNKNOWN, ACCEPTED_FOR_SETTLEMENT, SUSPENDED,
WITHDRAWN, SUPERSEDED, and rejected fixture, assert visible HTML labels equal
the recomputed JSON states.

- [x] **Step 4: Run GREEN and commit**

Run:

```bash
./.venv/bin/python -m pytest tests/test_delivery_package_v02.py -q
git add src/openworkproof/delivery_package.py docs/pilot/delivery-room.css \
  tests/test_delivery_package_v02.py
git diff --cached --check
git commit -m 'feat: add customer-readable delivery room'
```

Expected: all static report, escaping, boundary, and parity tests pass.

## Task 13: Close the Adversarial and Fault Matrix

**Files:**

- Create: `tests/test_v02_adversarial.py`
- Modify: `tests/test_verification_transactions_v02.py`
- Modify: `tests/test_delivery_package_v02.py`
- Create: `docs/pilot/registered-adversarial-study.json`

- [x] **Step 1: Register the study before adding holdout results**

Create a canonical JSON registration with exact source revision, protocol
schemas, named cases, mutation classes, expected results, verifier bindings,
exclusions, holdout case IDs, and analysis method. Do not record observed
results in the registration object.

- [x] **Step 2: Add the semantic mutation matrix**

Cover correct fix/caught mutant, incorrect fix, survived mutant, not-applied
mutant, verifier timeout, verifier crash, evidence missing, reused Verifier key,
controller overlap, execution-context overlap, stale supersession, and
withdrawn acceptance.

- [x] **Step 3: Add object and causal tamper tests**

Rebuild through `model_dump -> mutate -> model_validate`, re-sign where the
test targets semantic validation, and separately tamper WorkOrder, claim,
profile, arm result, decision, receipt, parent order, EvidenceRef, public key,
and package manifest. Each must fail at the intended layer.

- [x] **Step 4: Add all transaction injection points**

For T1–T5 cover before start, after stage, before commit, commit-ACK loss,
readback unavailable, cleanup failure, retry, and concurrency. Assert exact
table snapshots and committed truth.

- [x] **Step 5: Run adversarial GREEN and commit**

Run:

```bash
./.venv/bin/python -m pytest \
  tests/test_v02_adversarial.py \
  tests/test_verification_transactions_v02.py \
  tests/test_delivery_package_v02.py -q
git add tests/test_v02_adversarial.py \
  tests/test_verification_transactions_v02.py \
  tests/test_delivery_package_v02.py \
  docs/pilot/registered-adversarial-study.json
git diff --cached --check
git commit -m 'test: register verifiable delivery adversarial gates'
```

Expected: every registered non-holdout case has the expected protocol result;
no result is generalized beyond the registered study.

## Task 14: Upgrade Rich and Dify to v0.2 Without Overwriting v0.1

**Files:**

- Modify: `tests/test_export_evidence_bundles.py`
- Modify: `tests/evidence-bundles/verify_evidence_bundle.py`
- Create: `tests/test_v02_bundles.py`
- Create: `tests/evidence-bundles/rich-4196-v02-delivery-package.json`
- Create: `tests/evidence-bundles/dify-33013-v02-delivery-package.json`

- [x] **Step 1: Write RED v0.2 bundle dispatcher tests**

Require exact v0.1/v0.2 schema dispatch, reject unknown versions, and assert
the two historical v0.1 bundle hashes do not change.

- [x] **Step 2: Add fixed positive and negative arms to each case**

For each real Issue, bind source revision, candidate revision, fixed tests,
container, dependency lock, positive expected pass, Manager-pinned mutant, and
negative expected fail. Do not reuse a positive candidate as a fake mutant.

- [x] **Step 3: Export new package objects**

Append v0.2 exporter functions that produce SubjectClaim, Profile, arm results,
VerificationDecision, acceptance history, manifest, public keys, and committed
evidence. Write to the two new filenames only.

- [x] **Step 4: Verify offline and tamper fail-closed**

Run:

```bash
./.venv/bin/python -m pytest tests/test_v02_bundles.py -q
./.venv/bin/python tests/evidence-bundles/verify_evidence_bundle.py \
  tests/evidence-bundles/rich-4196-v02-delivery-package.json
./.venv/bin/python tests/evidence-bundles/verify_evidence_bundle.py \
  tests/evidence-bundles/dify-33013-v02-delivery-package.json
```

Expected: both report `VERIFICATION PASSED`, current decision VERIFIED, and
current readiness matches the included acceptance history. Tamper fixtures
must fail.

- [x] **Step 5: Commit the immutable cases**

Run:

```bash
git add tests/test_export_evidence_bundles.py \
  tests/evidence-bundles/verify_evidence_bundle.py \
  tests/test_v02_bundles.py \
  tests/evidence-bundles/rich-4196-v02-delivery-package.json \
  tests/evidence-bundles/dify-33013-v02-delivery-package.json
git diff --cached --check
git commit -m 'test: publish v0.2 falsifiable delivery cases'
```

Expected: old v0.1 bundle files are absent from the commit diff.

## Task 15: Add the 21-Day Pilot Operator Kit

**Files:**

- Create: `docs/pilot/README.md`
- Create: `docs/pilot/subject-claim.example.json`
- Create: `docs/pilot/verification-profile.example.json`
- Create: `docs/pilot/pilot-scorecard.md`
- Modify: `README.md`
- Modify: `README_en.md`
- Modify: `docs/offline-verification.md`
- Modify: `docs/status.md`

- [x] **Step 1: Write the operator guide**

Document day 1–3 claim freeze, day 4–7 integration, day 8–14 real execution,
day 15–18 customer decision, and day 19–21 commercial review. State that the
first payer is a hypothesis and a deposit is the validation signal. Include the
exact Level 0–3 cost boundary: Level 0 uses ordinary CI; Level 1 produces an
Evidence Bundle but no customer package; Level 2 adds a customer-controlled
CommitmentAnchor, customer acceptance, and Delivery Package; Level 3 adds a
second independent Verifier and stricter retention limits.

- [x] **Step 2: Add byte-valid example objects**

Generate the example SubjectClaim and VerificationProfile from model fixtures,
validate them with the installed v0.2 schemas, and use non-customer identifiers
only. The examples must not contain private keys or imply external acceptance.

- [x] **Step 3: Add the technical/commercial scorecard**

The scorecard must separately capture test counts, registered adversarial
cases, open-source replay cases, paid pilots, customer acceptance decisions,
cycle time, supplement rounds, replay execution, payment evidence, and repeat
project evidence. Default every external outcome to `not evidenced`.

- [x] **Step 4: Update public documentation from fresh behavior**

Document supported v0.2 commands and exact boundaries. Do not reuse historical
test counts; insert only counts from the final gates in Task 16.

- [x] **Step 5: Validate docs and commit**

Run:

```bash
./.venv/bin/python - <<'PY'
import json
from pathlib import Path
from openworkproof.models import SubjectClaim, VerificationProfileV02
SubjectClaim.model_validate(json.loads(Path('docs/pilot/subject-claim.example.json').read_text()))
VerificationProfileV02.model_validate(json.loads(Path('docs/pilot/verification-profile.example.json').read_text()))
PY
rg -n '已付款|资金已释放|客户已采用|正式部署' README.md README_en.md docs/pilot docs/status.md
git diff --check
```

Expected: model validation passes. Any boundary phrase found by `rg` must be a
clearly negated limitation; otherwise revise it.

Run:

```bash
git add docs/pilot README.md README_en.md docs/offline-verification.md docs/status.md
git diff --cached --check
git commit -m 'docs: add verifiable delivery pilot kit'
```

## Task 16: Run Final Supply-Chain and Release Gates

**Files:**

- Modify: `supply-chain/images/trusted-helper/SOURCE_ALLOWLIST`
- Create: `supply-chain/images/candidates/<final-source-revision>.json`
- Modify: `docs/status.md`

- [x] **Step 1: Close the trusted-helper source surface**

Add only `verification.py`, `settlement.py`, and `delivery_package.py` if the
trusted offline verifier imports them. Do not add CLI, MCP, CSS, services, or
pilot documentation to the helper image.

- [x] **Step 2: Run focused and portable gates before building images**

Run:

```bash
./.venv/bin/python -m pip check
./.venv/bin/python -m compileall -q src tests
./.venv/bin/python -m pytest \
  tests/test_verification_models_v02.py \
  tests/test_verification_transactions_v02.py \
  tests/test_settlement_readiness.py \
  tests/test_delivery_package_v02.py \
  tests/test_v02_interfaces.py \
  tests/test_v02_adversarial.py \
  tests/test_v02_bundles.py -q
./.venv/bin/python -m pytest -q
git diff --check
```

Expected: zero failures. Record exact counts; do not prefill them.

- [x] **Step 3: Build a final immutable candidate inventory**

Repeat Task 2 Steps 3–5 against the exact final source revision. Create a new
inventory and final archive directory. Do not edit the M0 or historical
inventories.

- [x] **Step 4: Run required-live gates**

Run:

```bash
export OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT=/Users/molin/Project/openWorkProof-delivery
export OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1
./.venv/bin/python -m pytest tests/test_image_supply_chain.py -q
./.venv/bin/python -m pytest -m supplychain tests/test_candidate_supplychain_integration.py -q
./.venv/bin/python -m pytest -q
```

Expected: every command exits 0 with zero failures and zero unapproved skips.

- [x] **Step 5: Verify both v0.2 packages in a fresh offline process**

Run the two exact verifier commands from Task 14 after clearing network proxy
variables. Expected: both pass without a live ledger or network.

- [x] **Step 6: Record release truth and commit**

Update `docs/status.md` with source revision, package version, protocol schema
versions, environment, exact pass/fail/skip counts, candidate inventory path,
bundle replay results, and build time.

Run:

```bash
REV=$(git rev-parse HEAD)
git add supply-chain/images/trusted-helper/SOURCE_ALLOWLIST \
  "supply-chain/images/candidates/$REV.json" docs/status.md
git diff --cached --check
git commit -m 'build: bind verifiable delivery release candidate'
```

Expected: the final inventory is additive and status claims match fresh output.

## Task 17: Commercial Pilot Handoff Without Fabricated Outcomes

**Files:**

- Modify only after a real event: `docs/pilot/pilot-scorecard.md`

- [x] **Step 1: Prepare but do not invent outreach evidence**

Provide the operator with the validated example package, pilot guide, scorecard,
and exact technical gate report. Leave payer, customer, deposit, acceptance,
payment, repeat project, and deployment fields as `not evidenced`.

- [x] **Step 2: Define the external 21-day gate**

The human operator must obtain a real project, real acceptance criteria, a
Customer Acceptor, and paid deposit. WorkBuddy may record supplied evidence but
must not contact parties, sign for them, or mark the gate complete without
explicit authority and artifacts.

- [ ] **Step 3: Stop at the branch integration choice**

Run:

```bash
git status --short --branch
git log --oneline --decorate 69a3a62..HEAD
git diff --check 69a3a62..HEAD
```

Expected: clean implementation worktree and a reviewable commit series. Report
local implementation, tests, remote branch, release, customer validation, and
payment as separate statuses.

- [ ] **Step 4: Request explicit integration direction**

Offer exactly these options:

1. keep the branch local for audit;
2. push `codex/verifiable-delivery-pilot` and open a review branch/PR;
3. merge locally into `main` after independent review.

Do not merge, push, publish, or open a PR until the user selects one.

## Final Review Checklist

- [x] Every signed v0.1 fixture and schema remains byte-identical.
- [x] Invalid protocol input is rejected before a signed UNKNOWN exists.
- [x] VERIFIED requires a real, applied, caught negative control.
- [x] `MUTATION_NOT_APPLIED`, `MUTATION_SURVIVED`, and verifier crash are
  distinct.
- [x] High-risk verification enforces identity, key, controller, and execution
  context independence.
- [x] VerificationDecision and acceptance histories are append-only.
- [x] Acceptance is bound to the exact current VERIFIED decision.
- [x] SettlementReadiness follows the approved priority mapping everywhere.
- [x] Delivery Package replay requires no network, live ledger, report HTML, or
  OWP-hosted service.
- [x] Delivery Room never holds an Acceptor private key.
- [x] Provider, Verifier, Acceptor, and Auditor authorities remain separate.
- [x] Public/private evidence policy rejects secrets and path escape.
- [x] CLI, MCP, offline replay, and Delivery Room produce the same current
  decision and readiness.
- [x] Rich and Dify v0.2 packages are additive; v0.1 files are unchanged.
- [x] Full, candidate, required-live, and offline gates have fresh zero-failure
  evidence.
- [x] Test counts, adversarial cases, open-source demos, paid pilots, customer
  acceptances, and revenue are disclosed as separate metrics.
- [x] No custody, payment, settlement-completed, customer-adoption, deployment,
  or external-acceptance claim exists without external proof.
