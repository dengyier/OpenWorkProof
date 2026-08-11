from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import rfc8785

import openworkproof.evidence as evidence
from openworkproof.delivery_package import (
    DeliveryPackageError,
    export_delivery_package,
    verify_delivery_package,
)
from openworkproof.models import (
    DecisionDraftRequest,
    ScopeMember,
    SubjectClaim,
    VerificationProfileV03,
)
from openworkproof.scope import (
    ObservedScope,
    compare_observed_scope,
    population_digest,
    scope_member_id,
)
from openworkproof.signing import sign_payload
from openworkproof.verification import (
    commit_evaluation_scope,
    commit_verification_arm_result_v03,
    commit_verification_decision_v03,
    commit_verification_profile_v03,
)
from test_delivery_m2 import RICH_PINNED_COMMIT
from test_export_evidence_bundles import export_v03_delivery_package_envelope
from test_verification_transactions_v03 import (
    _arm_result,
    _insert_transaction_receipt,
    _signed_decision_v03,
    _transaction_manifest,
    _transaction_profile,
    _write_json_evidence,
    verification_profile_v03,
)


DEMO_ROOT = Path(__file__).parent / "scope-demo/rich-4196"
FROZEN_BUNDLE = (
    Path(__file__).parent
    / "evidence-bundles/rich-4196-scope-v03-delivery-package.json"
)
ISSUE_URL = "https://github.com/Textualize/rich/issues/4196"
FROZEN_BUNDLE_SHA256 = (
    "bef58136fbeaed63e91c81c4fdefe8fbfc7257872c98c1151610c3ad449c8bb8"
)


def _run_check(check: str, implementation: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(DEMO_ROOT / check),
            str(DEMO_ROOT / implementation),
        ],
        capture_output=True,
        text=True,
    )


def _member(kind: str, locator: str, source_revision: str) -> dict[str, object]:
    payload = (
        Path(__file__).parent.parent / locator.split("::", 1)[0]
    ).read_bytes()
    return ScopeMember.model_validate(
        {
            "member_id": scope_member_id(kind, locator),
            "member_kind": kind,
            "locator": locator,
            "locator_digest": hashlib.sha256(locator.encode("utf-8")).hexdigest(),
            "content_digest": hashlib.sha256(payload).hexdigest(),
            "source_revision": source_revision,
        }
    ).model_dump(mode="json")


def _observed(manifest, *, include_required_test: bool) -> ObservedScope:
    members = tuple(
        member
        for member in manifest.members
        if include_required_test or member.member_kind != "test_case"
    )
    present = {member.member_id for member in members}
    return ObservedScope.model_validate(
        {
            "member_ids": [member.member_id for member in members],
            "member_count": len(members),
            "population_digest": manifest.population_digest,
            "required_target_ids": [
                target
                for target in manifest.required_target_ids
                if target in present
            ],
            "source_revision": manifest.source_revision,
            "workspace_manifest_digest": manifest.workspace_manifest_digest,
            "selector_engine_digests": sorted(
                rule.selector_engine_digest for rule in manifest.selector_rules
            ),
            "evidence_complete": include_required_test,
        }
    )


def test_rich_4196_old_green_becomes_unknown_then_repaired_verified(
    tmp_path,
    signed_work_order,
    signed_subject_claim,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    verification_profile_v03,
) -> None:
    assert _run_check("legacy_check.py", "candidate.py").returncode == 0
    assert _run_check("legacy_check.py", "mutant.py").returncode == 0
    assert _run_check("required-test.py", "candidate.py").returncode == 0
    assert _run_check("required-test.py", "mutant.py").returncode != 0

    ledger = tmp_path / "rich-4196-v03.sqlite3"
    evidence.initialize_ledger(ledger, signed_work_order)
    claim_raw = signed_subject_claim.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    claim_raw.update(
        {
            "claim_id": hashlib.sha256(b"rich-4196-v03-claim").hexdigest(),
            "claim_statement": (
                "The required Rich #4196 NBSP regression passes within the "
                "declared scope."
            ),
            "delivery_target": "openworkproof-demo/rich-4196",
            "source_revision": RICH_PINNED_COMMIT,
            "acceptance_conditions": ["nbsp_regression_passed"],
            "excluded_scope": [
                "customer_adoption",
                "payment_status",
                "universal_correctness",
            ],
            "required_artifacts": [
                "tests/scope-demo/rich-4196/candidate.py"
            ],
            "nonce": hashlib.sha256(b"rich-4196-v03-claim-nonce").hexdigest(),
        }
    )
    claim = SubjectClaim.model_validate(
        sign_payload(
            "subject-claim",
            claim_raw,
            ephemeral_role_keys["Manager"][0],
        )
    )

    members = sorted(
        (
            _member(
                "source_file",
                "tests/scope-demo/rich-4196/candidate.py",
                claim.source_revision,
            ),
            _member(
                "test_case",
                "tests/scope-demo/rich-4196/required-test.py::test_nbsp_is_not_breakable",
                claim.source_revision,
            ),
        ),
        key=lambda item: (
            item["member_kind"],
            item["locator_digest"],
            item["member_id"],
        ),
    )
    selector_spec = {
        "schema_version": "openworkproof-selector-spec/0.3",
        "selector_kind": "explicit",
        "locators": sorted(member["locator"] for member in members),
    }
    selector_raw = rfc8785.dumps(selector_spec)
    selector_path = tmp_path / "scope/selectors/rich-4196.json"
    selector_path.parent.mkdir(parents=True)
    selector_path.write_bytes(selector_raw)
    scope_payload = {
        "schema_version": "openworkproof-evaluation-scope/0.3",
        "scope_id": "0" * 64,
        "work_order_digest": signed_work_order.digest,
        "subject_claim_digest": claim.digest,
        "source_revision": claim.source_revision,
        "candidate_commit": hashlib.sha1(
            (DEMO_ROOT / "candidate.py").read_bytes(),
            usedforsecurity=False,
        ).hexdigest(),
        "selector_rules": [
            {
                "rule_id": hashlib.sha256(b"rich-4196-selector").hexdigest(),
                "selector_kind": "explicit",
                "selector_spec_digest": hashlib.sha256(selector_raw).hexdigest(),
                "selector_engine_digest": hashlib.sha256(
                    b"openworkproof-explicit-selector-v03"
                ).hexdigest(),
                "required_evidence_paths": [
                    "scope/selectors/rich-4196.json"
                ],
            }
        ],
        "members": members,
        "member_count": len(members),
        "population_digest": population_digest(
            tuple(ScopeMember.model_validate(member) for member in members)
        ),
        "requirement_bindings": [],
        "required_target_ids": [],
        "excluded_locator_digests": [],
        "workspace_manifest_digest": hashlib.sha256(
            b"rich-4196-v03-workspace"
        ).hexdigest(),
        "freshness_mode": "immutable_git_revision",
        "created_at": "2026-01-01T00:00:05Z",
        "expires_at": "2026-01-01T01:00:00Z",
        "nonce": hashlib.sha256(b"rich-4196-v03-scope-nonce").hexdigest(),
    }
    manifest = _transaction_manifest(
        scope_payload,
        work_order=signed_work_order,
        claim=claim,
        manager_key=ephemeral_role_keys["Manager"][0],
    )

    old_observed = _observed(manifest, include_required_test=False)
    old_result = compare_observed_scope(manifest, old_observed)
    assert old_result.scope_status == "indeterminate"
    assert "SCOPE_REQUIRED_TARGET_MISSING" in old_result.reason_codes

    repaired_observed = _observed(manifest, include_required_test=True)
    repaired = compare_observed_scope(manifest, repaired_observed)
    assert repaired.scope_status == "satisfied"
    assert repaired.reason_codes == ()

    profile = _transaction_profile(
        verification_profile_v03,
        manifest=manifest,
        manager_key=ephemeral_role_keys["Manager"][0],
    )
    profile_raw = profile.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    required_test_digest = hashlib.sha256(
        (DEMO_ROOT / "required-test.py").read_bytes()
    ).hexdigest()
    for arm in (profile_raw["positive_arm"], *profile_raw["negative_arms"]):
        arm["fixed_test_source_digest"] = required_test_digest
    profile_raw["negative_arms"][0]["mutant_patch_digest"] = hashlib.sha256(
        (DEMO_ROOT / "mutant.py").read_bytes()
    ).hexdigest()
    profile = VerificationProfileV03.model_validate(
        sign_payload(
            "verification-profile",
            profile_raw,
            ephemeral_role_keys["Manager"][0],
            version="0.3",
        )
    )
    commit_evaluation_scope(ledger, claim, manifest)
    commit_verification_profile_v03(ledger, profile)
    receipt = sidecar_receipt_factory(
        state_before="locally_verified",
        state_after="evidence_incomplete",
        event_type="system_event",
        event_name="proof_composed",
        sequence=1,
    )
    _insert_transaction_receipt(ledger, receipt)

    case = {
        "ledger": ledger,
        "manifest": manifest,
        "profile": profile,
        "keys": ephemeral_role_keys,
        "tmp_path": tmp_path,
    }
    results = []
    for kind, exit_code in (("positive", 0), ("negative", 1)):
        result_ref = _write_json_evidence(
            tmp_path,
            f"results/{kind}.json",
            {
                "issue_source": ISSUE_URL,
                "arm": kind,
                "exit_code": exit_code,
                "required_regression": "passed" if kind == "positive" else "caught",
            },
        )
        scope_ref = _write_json_evidence(
            tmp_path,
            f"scope/{kind}.json",
            repaired_observed.model_dump(mode="json"),
        )
        result = _arm_result(
            profile=profile,
            manifest=manifest,
            ephemeral_role_keys=ephemeral_role_keys,
            arm_kind=kind,
            scope_status="satisfied",
            action_receipt_id=receipt.receipt_id,
            evidence_ref=result_ref,
            scope_evidence_ref=scope_ref,
        )
        commit_verification_arm_result_v03(ledger, result)
        results.append(result)
    case["results"] = tuple(results)
    assert {result.observed_population_digest for result in results} == {
        manifest.population_digest
    }

    decision = _signed_decision_v03(
        case,
        DecisionDraftRequest(
            decision_id=hashlib.sha256(b"rich-4196-v03-decision").hexdigest(),
            decided_at="2026-01-01T00:20:00Z",
            nonce=hashlib.sha256(b"rich-4196-v03-decision-nonce").hexdigest(),
        ),
    )
    assert decision.decision == "VERIFIED"
    assert decision.scope_assessment.scope_status == "satisfied"
    commit_verification_decision_v03(ledger, decision)

    package = tmp_path / "rich-4196-scope-v03-package"
    export_delivery_package(ledger, package, privacy_view="customer_private")
    replay = verify_delivery_package(package)
    assert replay.current_decision == "VERIFIED"
    report = __import__("json").loads(
        (package / "scope-coverage-report.json").read_text(encoding="utf-8")
    )
    assert report["bounded_conclusion"].startswith("VERIFIED within")

    output = (
        FROZEN_BUNDLE
        if os.environ.get("OWP_REFRESH_SCOPE_DEMO_BUNDLE") == "1"
        else tmp_path / FROZEN_BUNDLE.name
    )
    export_v03_delivery_package_envelope(
        package_root=package,
        output_path=output,
        metadata={
            "issue_source": ISSUE_URL,
            "demo_owner": "OpenWorkProof",
            "upstream_adoption": "not_evidenced",
            "customer_case": "not_evidenced",
            "old_green_scope_status": "indeterminate",
            "repaired_scope_status": "satisfied",
            "bounded_conclusion": report["bounded_conclusion"],
        },
    )

    for relative in ("scope/members.json", "evidence/scope/positive/scope/positive.json"):
        tampered = tmp_path / ("tampered-" + relative.replace("/", "-"))
        shutil.copytree(package, tampered)
        target = tampered / relative
        target.write_bytes(target.read_bytes() + b" ")
        with pytest.raises(DeliveryPackageError, match="integrity"):
            verify_delivery_package(tampered)


def test_frozen_rich_scope_bundle_is_immutable_and_offline_verifiable() -> None:
    assert hashlib.sha256(FROZEN_BUNDLE.read_bytes()).hexdigest() == (
        FROZEN_BUNDLE_SHA256
    )
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}
    }
    completed = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).parent / "evidence-bundles/verify_evidence_bundle.py"),
            str(FROZEN_BUNDLE),
        ],
        env=environment,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert "VERIFICATION PASSED" in completed.stdout
    assert "v0.3 scope: satisfied" in completed.stdout
