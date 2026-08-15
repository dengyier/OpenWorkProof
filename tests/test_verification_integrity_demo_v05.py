"""OpenWorkProof self-owned Rich #4196 verification-integrity v0.5 demo.

The demo reuses the committed local fixture under ``tests/scope-demo/rich-4196``
and demonstrates the three v0.5 integrity conclusions: the population blind
spot (UNKNOWN / POPULATION_CAPTURE_FAILED), control rot (UNKNOWN /
CONTROL_FAILURE_SIGNATURE_MISMATCH), and the repaired full chain (VERIFIED)
with an offline-replayable customer-private package. All adoption, customer
and commercial metadata is declared ``not_evidenced``.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

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
    VerificationProfileV05,
)
from openworkproof.scope import (
    ObservedScope,
    population_digest,
    scope_member_id,
)
from openworkproof.signing import sign_payload
from openworkproof.verification import (
    commit_evaluation_scope,
    commit_verification_arm_result_v05,
    commit_verification_decision_v05,
    commit_verification_profile_v05,
    prepare_verification_decision_v05,
)

from test_delivery_m2 import RICH_PINNED_COMMIT
from test_export_evidence_bundles import export_v05_delivery_package_envelope
from test_verification_integrity_transactions_v05 import (
    _insert_transaction_receipt,
    _resign_arm_result_v05,
    _sign_decision_draft_v05,
    _transaction_manifest,
    _transaction_profile_v05,
    _v05_arm_result,
    _v05_control_observation,
    _v05_population_observation,
    _write_json_evidence,
    verification_profile_v03,
)

DEMO_ROOT = Path(__file__).parent / "scope-demo/rich-4196"
FROZEN_BUNDLE = (
    Path(__file__).parent
    / "evidence-bundles/rich-4196-integrity-v05-delivery-package.json"
)
ISSUE_URL = "https://github.com/Textualize/rich/issues/4196"
FROZEN_BUNDLE_SHA256 = (
    "88c39c10761354cc3030c912a98984f10fe06f6b350f03f0f2a632d786dafee0"
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


def _observed(manifest) -> ObservedScope:
    return ObservedScope.model_validate(
        {
            "member_ids": [member.member_id for member in manifest.members],
            "member_count": manifest.member_count,
            "population_digest": manifest.population_digest,
            "required_target_ids": list(manifest.required_target_ids),
            "source_revision": manifest.source_revision,
            "workspace_manifest_digest": manifest.workspace_manifest_digest,
            "selector_engine_digests": sorted(
                rule.selector_engine_digest for rule in manifest.selector_rules
            ),
            "evidence_complete": True,
        }
    )


def _demo_case(
    tmp_path,
    signed_work_order,
    signed_subject_claim,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    verification_profile_v03,
) -> dict:
    ledger = tmp_path / "rich-4196-v05.sqlite3"
    evidence.initialize_ledger(ledger, signed_work_order)
    claim_raw = signed_subject_claim.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    claim_raw.update(
        {
            "claim_id": hashlib.sha256(b"rich-4196-v05-claim").hexdigest(),
            "claim_statement": (
                "The required Rich #4196 NBSP regression passes for the exact "
                "eligible population and the registered negative control fails "
                "for the registered reason."
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
            "nonce": hashlib.sha256(b"rich-4196-v05-claim-nonce").hexdigest(),
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
    source_spec = {
        "schema_version": "openworkproof-selector-spec/0.3",
        "selector_kind": "explicit",
        "locators": ["tests/scope-demo/rich-4196/candidate.py"],
    }
    test_spec = {
        "schema_version": "openworkproof-selector-spec/0.3",
        "selector_kind": "explicit",
        "locators": [
            "tests/scope-demo/rich-4196/"
            "required-test.py::test_nbsp_is_not_breakable"
        ],
    }
    source_raw = rfc8785.dumps(source_spec)
    test_raw = rfc8785.dumps(test_spec)
    selector_parent = tmp_path / "scope/selectors"
    selector_parent.mkdir(parents=True)
    (selector_parent / "source.json").write_bytes(source_raw)
    (selector_parent / "tests.json").write_bytes(test_raw)
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
                "rule_id": "1" * 64,
                "selector_kind": "explicit",
                "selector_spec_digest": hashlib.sha256(
                    source_raw
                ).hexdigest(),
                "selector_engine_digest": hashlib.sha256(
                    b"openworkproof-explicit-selector-v03-source"
                ).hexdigest(),
                "required_evidence_paths": [
                    "scope/selectors/source.json"
                ],
            },
            {
                "rule_id": "2" * 64,
                "selector_kind": "explicit",
                "selector_spec_digest": hashlib.sha256(
                    test_raw
                ).hexdigest(),
                "selector_engine_digest": hashlib.sha256(
                    b"openworkproof-explicit-selector-v03-test"
                ).hexdigest(),
                "required_evidence_paths": [
                    "scope/selectors/tests.json"
                ],
            },
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
            b"rich-4196-v05-workspace"
        ).hexdigest(),
        "freshness_mode": "immutable_git_revision",
        "created_at": "2026-01-01T00:00:05Z",
        "expires_at": "2026-01-01T01:00:00Z",
        "nonce": hashlib.sha256(b"rich-4196-v05-scope-nonce").hexdigest(),
    }
    manifest = _transaction_manifest(
        scope_payload,
        work_order=signed_work_order,
        claim=claim,
        manager_key=ephemeral_role_keys["Manager"][0],
    )
    mutant_digest = hashlib.sha256((DEMO_ROOT / "mutant.py").read_bytes()).hexdigest()
    negative_arm = verification_profile_v03.negative_arms[0].model_copy(
        update={"mutant_patch_digest": mutant_digest}
    )
    base_v03 = verification_profile_v03.model_copy(
        update={"negative_arms": (negative_arm,)}
    )
    profile = _transaction_profile_v05(
        base_v03,
        manifest=manifest,
        manager_key=ephemeral_role_keys["Manager"][0],
    )
    required_test_digest = hashlib.sha256(
        (DEMO_ROOT / "required-test.py").read_bytes()
    ).hexdigest()
    profile_raw = profile.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    for arm in (profile_raw["positive_arm"], *profile_raw["negative_arms"]):
        arm["fixed_test_source_digest"] = required_test_digest
    profile = VerificationProfileV05.model_validate(
        sign_payload(
            "verification-profile",
            profile_raw,
            ephemeral_role_keys["Manager"][0],
            version="0.5",
        )
    )
    commit_evaluation_scope(ledger, claim, manifest)
    commit_verification_profile_v05(ledger, profile)
    receipt = sidecar_receipt_factory(
        state_before="locally_verified",
        state_after="evidence_incomplete",
        event_type="system_event",
        event_name="proof_composed",
        sequence=1,
    )
    _insert_transaction_receipt(ledger, receipt)
    return {
        "ledger": ledger,
        "manifest": manifest,
        "profile": profile,
        "keys": ephemeral_role_keys,
        "tmp_path": tmp_path,
        "receipt_id": receipt.receipt_id,
    }


def _demo_results(
    case,
    *,
    suffix: str,
    created_at: str,
    blind_test_selection: bool,
    control_overrides: dict | None,
    positive_id: str,
    negative_id: str,
) -> tuple:
    root = case["tmp_path"]
    profile = case["profile"]
    results = []
    for kind in ("positive", "negative"):
        observations = []
        for contract in profile.population_contracts:
            if blind_test_selection and contract.member_kind == "test_case":
                observations.append(
                    _v05_population_observation(
                        root,
                        contract,
                        suffix=f"{suffix}-{kind}-{contract.member_kind}",
                        eligible_seen=len(
                            contract.declared_selected_member_ids
                        ) + 1,
                        selected_count=0,
                    )
                )
            else:
                observations.append(
                    _v05_population_observation(
                        root,
                        contract,
                        suffix=f"{suffix}-{kind}-{contract.member_kind}",
                    )
                )
        control = None
        if kind == "negative":
            contract = profile.control_contracts[0]
            control = _v05_control_observation(
                root,
                contract,
                arm_kind="negative",
                **(control_overrides or {}),
            )
        result_ref = _write_json_evidence(
            root,
            f"results/{kind}.json",
            {
                "issue_source": ISSUE_URL,
                "arm": kind,
                "exit_code": 0 if kind == "positive" else 1,
            },
        )
        scope_ref = _write_json_evidence(
            root,
            f"scope/{suffix}-{kind}.json",
            _observed(case["manifest"]).model_dump(mode="json"),
        )
        result = _v05_arm_result(
            profile=profile,
            manifest=case["manifest"],
            keys=case["keys"],
            arm_kind=kind,
            observations=observations,
            control_observation=control,
            action_receipt_id=case["receipt_id"],
            evidence_ref=result_ref,
            scope_evidence_ref=scope_ref,
            created_at=created_at,
        )
        results.append(
            _resign_arm_result_v05(
                case,
                result,
                arm_result_id=positive_id if kind == "positive" else negative_id,
            )
        )
    return tuple(results)


def _request(stage: str, decided_at: str) -> DecisionDraftRequest:
    return DecisionDraftRequest(
        decision_id=hashlib.sha256(f"rich-4196-v05-{stage}".encode()).hexdigest(),
        decided_at=decided_at,
        nonce=hashlib.sha256(
            f"rich-4196-v05-{stage}-nonce".encode()
        ).hexdigest(),
    )


def test_rich_4196_v05_integrity_demo(
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

    case = _demo_case(
        tmp_path,
        signed_work_order,
        signed_subject_claim,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        verification_profile_v03,
    )

    # Step 2: population blind spot — pytest sees two eligible tests, the
    # selector chooses zero. The run finishes cleanly, yet v0.5 derives
    # UNKNOWN / POPULATION_CAPTURE_FAILED, never VERIFIED.
    blind = _demo_results(
        case,
        suffix="blind",
        created_at="2026-01-01T00:10:00Z",
        blind_test_selection=True,
        control_overrides=None,
        positive_id="a" * 64,
        negative_id="b" * 64,
    )
    for result in blind:
        commit_verification_arm_result_v05(case["ledger"], result)
    blind_draft = prepare_verification_decision_v05(
        case["ledger"], _request("blind", "2026-01-01T00:20:00Z")
    )
    assert blind_draft.decision == "UNKNOWN"
    assert blind_draft.integrity_assessment.population_status == "capture_failed"
    assert "POPULATION_CAPTURE_FAILED" in blind_draft.integrity_assessment.reason_codes

    # Step 3: control rot — the registered mutant still fails, but with an
    # altered failure signature. v0.5 derives UNKNOWN /
    # CONTROL_FAILURE_SIGNATURE_MISMATCH. The exact registered signature
    # derives proven (demonstrated by the final chain below).
    contract = case["profile"].control_contracts[0]
    expected = contract.expected_failure_signature.model_dump(mode="json")
    rot = _demo_results(
        case,
        suffix="rot",
        created_at="2026-01-01T00:11:00Z",
        blind_test_selection=False,
        control_overrides={
            "control_status": "mismatched",
            "signature": {
                **expected,
                "exit_codes": [2],
                "reason_codes": ["EXEC_COMMAND_FAILED"],
            },
        },
        positive_id="c" * 64,
        negative_id="d" * 64,
    )
    for result in rot:
        commit_verification_arm_result_v05(case["ledger"], result)
    rot_draft = prepare_verification_decision_v05(
        case["ledger"], _request("rot", "2026-01-01T00:21:00Z")
    )
    assert rot_draft.decision == "UNKNOWN"
    assert rot_draft.integrity_assessment.control_status == "mismatched"
    assert "CONTROL_FAILURE_SIGNATURE_MISMATCH" in rot_draft.integrity_assessment.reason_codes

    # Step 4: repaired full chain — complete selected population and the
    # exact negative control derive VERIFIED.
    repaired = _demo_results(
        case,
        suffix="repaired",
        created_at="2026-01-01T00:12:00Z",
        blind_test_selection=False,
        control_overrides=None,
        positive_id="8" * 64,
        negative_id="9" * 64,
    )
    for result in repaired:
        commit_verification_arm_result_v05(case["ledger"], result)
    final_draft = prepare_verification_decision_v05(
        case["ledger"], _request("repaired", "2026-01-01T00:22:00Z")
    )
    assert final_draft.decision == "VERIFIED"
    assert final_draft.integrity_assessment.population_status == "matched"
    assert final_draft.integrity_assessment.control_status == "proven"
    decision = _sign_decision_draft_v05(case, final_draft)
    commit_verification_decision_v05(case["ledger"], decision)

    package = tmp_path / "rich-4196-integrity-v05-package"
    export_delivery_package(case["ledger"], package, privacy_view="customer_private")
    replay = verify_delivery_package(package)
    assert replay.current_decision == "VERIFIED"
    assert replay.full_offline_replay is True

    output = (
        FROZEN_BUNDLE
        if os.environ.get("OWP_REFRESH_INTEGRITY_DEMO_BUNDLE") == "1"
        else tmp_path / FROZEN_BUNDLE.name
    )
    export_v05_delivery_package_envelope(
        package_root=package,
        output_path=output,
        metadata={
            "issue_source": ISSUE_URL,
            "demo_owner": "OpenWorkProof",
            "upstream_adoption": "not_evidenced",
            "customer_case": "not_evidenced",
            "commercial_validation": "not_evidenced",
            "blind_population_status": "capture_failed",
            "rot_control_status": "mismatched",
            "repaired_decision": "VERIFIED",
        },
    )

    # Step 5: single-byte tamper probes — one population identity, one
    # control fixture byte, and one failure-signature byte all fail closed.
    population_files = [
        path
        for path in package.rglob("*")
        if path.is_file() and "eligible-population" in path.name
    ]
    control_files = [
        path
        for path in package.rglob("*")
        if path.is_file() and "control" in path.relative_to(package).as_posix()
    ]
    arm_files = [
        path
        for path in package.rglob("*")
        if path.is_file() and "evidence/arms/" in path.relative_to(package).as_posix()
    ]
    assert population_files and control_files and arm_files
    for label, target in (
        ("population-identity", population_files[0]),
        ("control-fixture", control_files[0]),
        ("failure-signature", arm_files[0]),
    ):
        tampered = tmp_path / f"tampered-{label}"
        shutil.copytree(package, tampered)
        victim = tampered / target.relative_to(package)
        payload = victim.read_bytes()
        victim.write_bytes(payload[: len(payload) // 2] + bytes([payload[len(payload) // 2] ^ 0x01]) + payload[len(payload) // 2 + 1:])
        with pytest.raises(DeliveryPackageError, match="integrity"):
            verify_delivery_package(tampered)


def test_frozen_integrity_demo_bundle_is_offline_verifiable() -> None:
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
    assert "v0.5 integrity" in completed.stdout


def test_readmes_describe_v05_integrity_and_honest_boundaries() -> None:
    root = Path(__file__).parent.parent
    cases = (
        (
            "README.md",
            "验证完整性",
            (
                "支持自动付款",
                "支持自动结算",
                "保证正确",
                "保证零缺陷",
                "客户已经采用",
                "客户已采用",
                "上游已经采用",
                "已被上游采用",
            ),
        ),
        (
            "README_en.md",
            "Verification Integrity",
            (
                "automatic payment",
                "guaranteed correct",
                "guaranteed correctness",
                "customers have adopted",
                "adopted by customers",
                "upstream has adopted",
            ),
        ),
    )
    for name, section_marker, forbidden in cases:
        text = (root / name).read_text(encoding="utf-8")
        assert section_marker in text
        assert "POPULATION_CAPTURE_FAILED" in text
        assert "CONTROL_FAILURE_SIGNATURE_MISMATCH" in text
        assert "REFUTED" in text
        assert "not evidenced" in text
        for phrase in forbidden:
            assert phrase not in text
