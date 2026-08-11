from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest

import openworkproof.evidence as evidence
import openworkproof.delivery_package as delivery_package
import openworkproof.acceptance as acceptance
from openworkproof.delivery_package import (
    DeliveryManifest,
    DeliveryManifestEntry,
    DeliveryPackageError,
    digest_manifest,
    export_delivery_package,
    verify_delivery_package,
)
from openworkproof.models import (
    CommitmentAnchor,
    SubjectClaim,
    VerificationArmResult,
    VerificationDecision,
    VerificationProfileV02,
)
from openworkproof.signing import key_id, sign_payload
from openworkproof.verification import (
    commit_verification_arm_result,
    commit_verification_decision,
    commit_verification_profile,
    external_anchor_digest,
    prepare_verification_decision,
    verification_decision_signing_bytes,
)
from test_verification_transactions_v02 import (
    _insert_causal_receipt,
    _request,
)


def _canonical(value: object) -> bytes:
    import rfc8785

    return rfc8785.dumps(value)


def _arm_result(
    *,
    profile,
    arm_kind: str,
    result_id: str,
    receipt_id: str,
    private_key,
    payload: bytes,
) -> VerificationArmResult:
    arm = profile.positive_arm if arm_kind == "positive" else profile.negative_arms[0]
    binding = profile.verifier_bindings[0]
    raw = {
        "schema_version": "openworkproof-verification-arm-result/0.2",
        "arm_result_id": result_id,
        "profile_digest": profile.digest,
        "arm_id": arm.arm_id,
        "arm_kind": arm_kind,
        "mutation_status": "not_applicable" if arm_kind == "positive" else "applied",
        "execution_status": "completed",
        "expectation_status": "satisfied",
        "reason_codes": (
            [] if arm_kind == "positive" else ["MUTATION_APPLIED", "MUTATION_CAUGHT"]
        ),
        "action_receipt_ids": [receipt_id],
        "evidence_refs": [
            {
                "path": arm.result_artifact_paths[0],
                "sha256": hashlib.sha256(payload).hexdigest(),
                "media_type": "application/json",
                "size_bytes": len(payload),
            }
        ],
        "verifier_subject_id": binding.verifier_subject_id,
        "verifier_key_id": binding.verifier_key_id,
        "verifier_build_digest": "4" * 64,
        "dependency_lock_digest": "5" * 64,
        "controller_factors": list(binding.controller_factors),
        "execution_context_factors": list(binding.execution_context_factors),
        "created_at": "2026-01-01T00:10:00Z",
    }
    return VerificationArmResult.model_validate(
        sign_payload("verification-arm-result", raw, private_key)
    )


@pytest.fixture
def delivery_case(
    tmp_path,
    signed_work_order,
    signed_subject_claim,
    verification_profile_dict,
    policy_anchor,
    commitment_anchor,
    ephemeral_role_keys,
    sidecar_receipt_factory,
):
    ledger = tmp_path / "delivery-ledger.sqlite3"
    evidence.initialize_ledger(ledger, signed_work_order)
    raw_profile = dict(verification_profile_dict)
    raw_profile["delivery_trust_level"] = 2
    raw_profile["policy_anchor_digest"] = external_anchor_digest(policy_anchor)
    raw_profile["commitment_anchor_digest"] = external_anchor_digest(
        commitment_anchor
    )
    profile = VerificationProfileV02.model_validate(
        sign_payload(
            "verification-profile",
            raw_profile,
            ephemeral_role_keys["Manager"][0],
        )
    )
    commit_verification_profile(
        ledger,
        signed_subject_claim,
        profile,
        policy_anchor=policy_anchor,
        commitment_anchor=commitment_anchor,
    )
    receipt = sidecar_receipt_factory(
        state_before="locally_verified",
        state_after="evidence_incomplete",
        event_type="system_event",
        event_name="proof_composed",
        sequence=1,
    )
    _insert_causal_receipt(ledger, receipt)
    payloads = {
        "positive": _canonical({"exit_code": 0, "tests": "passed"}),
        "negative": _canonical({"exit_code": 1, "mutation": "caught"}),
    }
    for kind, payload in payloads.items():
        path = tmp_path / f"results/{kind}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    results = tuple(
        _arm_result(
            profile=profile,
            arm_kind=kind,
            result_id=("8" if kind == "positive" else "9") * 64,
            receipt_id=receipt.receipt_id,
            private_key=ephemeral_role_keys["Verifier"][0],
            payload=payloads[kind],
        )
        for kind in ("positive", "negative")
    )
    for result in results:
        commit_verification_arm_result(ledger, result)
    request = _request(decision_id="d" * 64)
    draft = prepare_verification_decision(ledger, request)
    encoded = verification_decision_signing_bytes(draft)
    binding = profile.verifier_bindings[0]
    private_key = ephemeral_role_keys["Verifier"][0]
    decision = commit_verification_decision(
        ledger,
        VerificationDecision.model_validate({
            "schema_version": "openworkproof-verification-decision/0.2",
            **draft.model_dump(mode="json"),
            "digest": hashlib.sha256(encoded).hexdigest(),
            "verifier_signatures": [
                {
                    "verifier_subject_id": binding.verifier_subject_id,
                    "verifier_key_id": key_id(private_key.public_key()),
                    "signature_alg": "Ed25519",
                    "signature": base64.urlsafe_b64encode(
                        private_key.sign(encoded)
                    ).decode("ascii").rstrip("="),
                }
            ],
        }),
    )
    return {
        "ledger": ledger,
        "work_order": signed_work_order,
        "claim": signed_subject_claim,
        "profile": profile,
        "decision": decision,
        "verifier_key": ephemeral_role_keys["Verifier"][0],
        "output": tmp_path / "delivery-package",
    }


_CUSTOMER_QUESTIONS = (
    "谁授权了这项工作？",
    "验收的是哪个交付目标和版本？",
    "约定结果是否达成？",
    "反证检查是否通过？",
    "当前能否进入验收或结算准备？",
)


def _render_room(
    delivery_case,
    *,
    decision: str = "VERIFIED",
    acceptance: str = "NONE",
    readiness: str = "READY_FOR_ACCEPTANCE",
    rejected: bool = False,
) -> str:
    return delivery_package._summary_html(
        work_order=delivery_case["work_order"],
        claim=delivery_case["claim"],
        decision=delivery_case["decision"].model_copy(
            update={"decision": decision}
        ),
        effective=delivery_package.EffectiveAcceptance(acceptance),
        readiness=delivery_package.SettlementReadiness(readiness),
        rejected=rejected,
    ).decode("utf-8")


def test_delivery_room_answers_exactly_five_customer_questions(
    delivery_case,
) -> None:
    rendered = _render_room(delivery_case)
    assert rendered.count('class="customer-question"') == 5
    assert all(rendered.count(question) == 1 for question in _CUSTOMER_QUESTIONS)
    assert "下一步：由独立 Acceptor 审阅并签署验收结果。" in rendered
    assert "本页面不作为付款、资金托管或实际结算事实的证明" in rendered


@pytest.mark.parametrize(
    ("decision", "acceptance", "readiness", "rejected"),
    (
        ("VERIFIED", "NONE", "READY_FOR_ACCEPTANCE", False),
        ("REFUTED", "NONE", "NOT_READY", False),
        ("UNKNOWN", "NONE", "NOT_READY", False),
        ("VERIFIED", "ACTIVE", "ACCEPTED_FOR_SETTLEMENT", False),
        ("VERIFIED", "SUSPENDED", "SUSPENDED", False),
        ("VERIFIED", "WITHDRAWN", "WITHDRAWN", False),
        ("VERIFIED", "SUPERSEDED", "SUPERSEDED", False),
        ("VERIFIED", "NONE", "NOT_READY", True),
    ),
)
def test_delivery_room_labels_equal_recomputed_json_states(
    delivery_case, decision, acceptance, readiness, rejected
) -> None:
    rendered = _render_room(
        delivery_case,
        decision=decision,
        acceptance=acceptance,
        readiness=readiness,
        rejected=rejected,
    )
    assert f'data-decision="{decision}"' in rendered
    assert f'data-acceptance="{acceptance}"' in rendered
    assert f'data-readiness="{readiness}"' in rendered
    assert f'<strong>{decision}</strong>' in rendered
    assert f'<strong>{acceptance}</strong>' in rendered
    assert f'<strong>{readiness}</strong>' in rendered


def test_delivery_room_unknown_is_explained_with_next_action(delivery_case) -> None:
    rendered = _render_room(
        delivery_case,
        decision="UNKNOWN",
        readiness="NOT_READY",
    )
    assert "证据缺失、基础设施故障或独立性不足" in rendered
    assert "不能视为通过或失败" in rendered
    assert "下一步：补齐缺失证据或恢复独立执行环境后重新验证。" in rendered


def test_delivery_room_rejected_is_not_presented_as_ready(delivery_case) -> None:
    rendered = _render_room(
        delivery_case,
        readiness="NOT_READY",
        rejected=True,
    )
    assert "客户已拒绝当前交付" in rendered
    assert "下一步：处理拒绝原因，形成新版本后重新验证并提交验收。" in rendered
    for forbidden_claim in ("已付款", "资金已托管", "结算已完成", "客户已采用"):
        assert forbidden_claim not in rendered


def test_delivery_room_escapes_verified_values(delivery_case) -> None:
    claim = delivery_case["claim"].model_copy(
        update={"claim_statement": '<script>alert("x")</script>'}
    )
    rendered = delivery_package._summary_html(
        work_order=delivery_case["work_order"],
        claim=claim,
        decision=delivery_case["decision"],
        effective=delivery_package.EffectiveAcceptance.NONE,
        readiness=delivery_package.SettlementReadiness.READY_FOR_ACCEPTANCE,
        rejected=False,
    ).decode("utf-8")
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered


def test_delivery_room_css_reference_matches_embedded_template() -> None:
    reference = (
        Path(__file__).parents[1] / "docs/pilot/delivery-room.css"
    ).read_text(encoding="utf-8").strip()
    assert reference == delivery_package._DELIVERY_ROOM_CSS


def test_manifest_is_closed_sorted_and_digested() -> None:
    entry = DeliveryManifestEntry(
        path="summary.html",
        sha256="a" * 64,
        size_bytes=12,
        media_type="text/html",
        privacy_class="public",
        required=True,
    )
    manifest = DeliveryManifest.model_validate(
        {
            "schema_version": "openworkproof-delivery-manifest/0.1",
            "privacy_view": "public",
            "work_order_digest": "b" * 64,
            "subject_claim_digest": "c" * 64,
            "verification_decision_digest": "d" * 64,
            "entries": [entry.model_dump(mode="json")],
        }
    )
    assert len(digest_manifest(manifest)) == 64
    with pytest.raises(ValueError):
        DeliveryManifest.model_validate(
            {
                **manifest.model_dump(mode="json"),
                "entries": [entry.model_dump(mode="json"), entry.model_dump(mode="json")],
            }
        )
    with pytest.raises(ValueError):
        DeliveryManifestEntry(
            **{**entry.model_dump(mode="json"), "path": "../secret"}
        )


@pytest.mark.parametrize(
    "path",
    (".env", "config/.env", "keys/customer.pem", "id_rsa", "logs/stdout"),
)
def test_evidence_allowlist_rejects_secret_bearing_paths(path) -> None:
    with pytest.raises(DeliveryPackageError, match="sensitive path"):
        delivery_package._assert_safe_evidence_relative(path)


def test_export_and_offline_verify_level_two_package(delivery_case) -> None:
    manifest = export_delivery_package(
        delivery_case["ledger"], delivery_case["output"], privacy_view="public"
    )
    paths = tuple(entry.path for entry in manifest.entries)
    assert paths == tuple(sorted(paths, key=lambda value: value.encode("utf-8")))
    assert "manifest.json" not in paths
    assert "anchors/commitment-anchor.json" in paths
    assert "anchors/policy-anchor.json" in paths
    assert "evidence/positive/results/positive.json" in paths
    assert "evidence/negative/results/negative.json" in paths
    assert all(entry.privacy_class == "public" for entry in manifest.entries)
    rendered = (delivery_case["output"] / "summary.html").read_text(
        encoding="utf-8"
    )
    assert rendered.count('class="customer-question"') == 5
    assert "<script" not in rendered.lower()
    result = verify_delivery_package(delivery_case["output"])
    assert "full_offline_replay" not in result.model_dump(mode="json")
    assert result.current_decision == "VERIFIED"
    assert result.effective_acceptance == "NONE"
    assert result.settlement_readiness == "READY_FOR_ACCEPTANCE"
    assert result.manifest_digest == digest_manifest(manifest)


def test_public_and_customer_private_views_are_separate_exports(delivery_case) -> None:
    public_output = delivery_case["output"]
    private_output = public_output.parent / "delivery-package-private"
    public_manifest = export_delivery_package(
        delivery_case["ledger"], public_output, privacy_view="public"
    )
    private_manifest = export_delivery_package(
        delivery_case["ledger"], private_output, privacy_view="customer_private"
    )
    assert public_manifest.privacy_view == "public"
    assert private_manifest.privacy_view == "customer_private"
    assert public_output != private_output
    assert verify_delivery_package(public_output).current_decision == "VERIFIED"
    assert verify_delivery_package(private_output).current_decision == "VERIFIED"


def test_customer_private_package_replays_active_acceptance(
    tmp_path,
    signed_work_order,
    signed_subject_claim,
    verification_profile_dict,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from test_acceptance import _request_case, _sign_draft
    from test_mcp_server import _current_run_tests_context
    from openworkproof import repo_tools

    monkeypatch.setattr(
        repo_tools,
        "prepare_candidate_execution_snapshot",
        lambda request: repo_tools.CandidateExecutionSnapshot(
            head_commit=request.expected_head_commit,
            workspace_manifest_digest=request.expected_workspace_manifest_digest,
            plan=repo_tools.ExecutionSnapshotPlan(
                files=(),
                read_only=True,
                owner_uid=65532,
                owner_gid=65532,
                atime_unix_seconds=0,
                mtime_unix_seconds=0,
                clear_extended_attributes=True,
                clear_posix_acls=True,
                clear_file_capabilities=True,
            ),
        ),
    )

    case, context, request, composed, expires_at = _request_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    claim_raw = signed_subject_claim.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    claim_raw.update(
        work_order_digest=case["work_order"].digest,
        source_revision=case["work_order"].source_commit,
        customer_acceptor_key_id=case["work_order"].acceptor_key_ids[0],
    )
    claim = SubjectClaim.model_validate(
        sign_payload("subject-claim", claim_raw, ephemeral_role_keys["Manager"][0])
    )
    commitment = CommitmentAnchor.model_validate(
        {
            "schema_version": "openworkproof-commitment-anchor/0.1",
            "work_order_digest": case["work_order"].digest,
            "subject_claim_digest": claim.digest,
            "anchored_at": "2026-01-01T00:00:04Z",
            "anchor_provider": "customer_signed_document",
            "anchor_reference": "customer://acceptance-criteria/accepted-case",
        }
    )
    profile_raw = dict(verification_profile_dict)
    profile_raw.update(
        work_order_digest=case["work_order"].digest,
        subject_claim_digest=claim.digest,
        delivery_trust_level=2,
        commitment_anchor_digest=external_anchor_digest(commitment),
    )
    profile = VerificationProfileV02.model_validate(
        sign_payload(
            "verification-profile",
            profile_raw,
            ephemeral_role_keys["Manager"][0],
        )
    )
    commit_verification_profile(
        case["ledger_path"], claim, profile, commitment_anchor=commitment
    )
    payloads = {
        "positive": _canonical({"exit_code": 0, "tests": "passed"}),
        "negative": _canonical({"exit_code": 1, "mutation": "caught"}),
    }
    for kind, payload in payloads.items():
        path = case["ledger_path"].parent / f"results/{kind}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    results = tuple(
        _arm_result(
            profile=profile,
            arm_kind=kind,
            result_id=("8" if kind == "positive" else "9") * 64,
            receipt_id=composed.trigger_receipt.receipt_id,
            private_key=ephemeral_role_keys["Verifier"][0],
            payload=payloads[kind],
        )
        for kind in ("positive", "negative")
    )
    for result in results:
        commit_verification_arm_result(case["ledger_path"], result)
    draft = prepare_verification_decision(
        case["ledger_path"], _request(decision_id="d" * 64)
    )
    encoded = verification_decision_signing_bytes(draft)
    verifier = ephemeral_role_keys["Verifier"][0]
    binding = profile.verifier_bindings[0]
    decision = VerificationDecision.model_validate(
        {
            "schema_version": "openworkproof-verification-decision/0.2",
            **draft.model_dump(mode="json"),
            "digest": hashlib.sha256(encoded).hexdigest(),
            "verifier_signatures": [
                {
                    "verifier_subject_id": binding.verifier_subject_id,
                    "verifier_key_id": key_id(verifier.public_key()),
                    "signature_alg": "Ed25519",
                    "signature": base64.urlsafe_b64encode(
                        verifier.sign(encoded)
                    ).decode("ascii").rstrip("="),
                }
            ],
        }
    )
    commit_verification_decision(case["ledger_path"], decision)
    acceptance.request_acceptance_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        request=request,
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        expires_at=expires_at,
        clock=lambda: fixed_now,
    )
    awaiting = _current_run_tests_context(case, fixed_now)
    signed = _sign_draft(
        acceptance.prepare_acceptance(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=awaiting,
            clock=lambda: fixed_now,
        ),
        ephemeral_role_keys,
    )
    acceptance.commit_acceptance(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=awaiting,
        acceptance=signed,
        public_keys=None,
        clock=lambda: fixed_now,
    )
    output = tmp_path / "accepted-delivery-package"
    manifest = export_delivery_package(
        case["ledger_path"], output, privacy_view="customer_private"
    )
    assert "acceptance/acceptance-receipt.json" in {
        entry.path for entry in manifest.entries
    }
    verified = verify_delivery_package(output)
    assert verified.effective_acceptance == "ACTIVE"
    assert verified.settlement_readiness == "ACCEPTED_FOR_SETTLEMENT"
    with pytest.raises(DeliveryPackageError, match="public view"):
        export_delivery_package(
            case["ledger_path"], tmp_path / "public", privacy_view="public"
        )
    acceptance_path = output / "acceptance/acceptance-receipt.json"
    acceptance_raw = json.loads(acceptance_path.read_text(encoding="utf-8"))
    acceptance_raw["accepted_at"] = "2026-01-01T00:00:06Z"
    acceptance_payload = _canonical(acceptance_raw)
    acceptance_path.write_bytes(acceptance_payload)

    def bind_tampered_acceptance(raw):
        entry = next(
            item
            for item in raw["entries"]
            if item["path"] == "acceptance/acceptance-receipt.json"
        )
        entry["sha256"] = hashlib.sha256(acceptance_payload).hexdigest()
        entry["size_bytes"] = len(acceptance_payload)

    _rewrite_manifest(output, bind_tampered_acceptance)
    with pytest.raises(DeliveryPackageError, match="acceptance lifecycle"):
        verify_delivery_package(output)


def test_export_rejects_level_one(
    tmp_path,
    signed_work_order,
    signed_subject_claim,
    signed_verification_profile,
) -> None:
    ledger = tmp_path / "level-one.sqlite3"
    evidence.initialize_ledger(ledger, signed_work_order)
    commit_verification_profile(ledger, signed_subject_claim, signed_verification_profile)
    with pytest.raises(DeliveryPackageError, match="Level 2/3"):
        export_delivery_package(ledger, tmp_path / "package", privacy_view="public")


@pytest.mark.parametrize(
    "target",
    (
        "subject-claim.json",
        "verification-profile.json",
        "verification-decision.json",
        "execution-ledger/receipts.json",
        "evidence/positive/results/positive.json",
        "public-keys/{key}.json",
        "settlement-readiness.json",
        "summary.html",
        "verify.sh",
    ),
)
def test_required_file_tamper_fails_closed(delivery_case, target) -> None:
    manifest = export_delivery_package(
        delivery_case["ledger"], delivery_case["output"], privacy_view="public"
    )
    if "{key}" in target:
        target = next(
            entry.path for entry in manifest.entries if entry.path.startswith("public-keys/")
        )
    path = delivery_case["output"] / target
    path.write_bytes(path.read_bytes() + b"tamper")
    with pytest.raises(DeliveryPackageError):
        verify_delivery_package(delivery_case["output"])


def test_extra_symlink_and_hardlink_fail_closed(delivery_case, tmp_path) -> None:
    export_delivery_package(
        delivery_case["ledger"], delivery_case["output"], privacy_view="public"
    )
    extra = delivery_case["output"] / "extra.txt"
    extra.write_text("extra", encoding="utf-8")
    with pytest.raises(DeliveryPackageError, match="manifest file set"):
        verify_delivery_package(delivery_case["output"])
    extra.unlink()
    os.symlink("summary.html", extra)
    with pytest.raises(DeliveryPackageError, match="regular files"):
        verify_delivery_package(delivery_case["output"])
    extra.unlink()
    os.link(delivery_case["output"] / "summary.html", extra)
    with pytest.raises(DeliveryPackageError, match="hardlink"):
        verify_delivery_package(delivery_case["output"])


def test_atomic_rename_failure_preserves_prior_output(
    delivery_case, monkeypatch
) -> None:
    prior = delivery_case["output"]
    prior.mkdir()
    marker = prior / "prior.txt"
    marker.write_text("unchanged", encoding="utf-8")
    before = marker.read_bytes()
    with pytest.raises(DeliveryPackageError, match="already exists"):
        export_delivery_package(
            delivery_case["ledger"], prior, privacy_view="customer_private"
        )
    assert marker.read_bytes() == before
    assert not tuple(prior.parent.glob(f".{prior.name}.*.tmp"))


def test_manifest_entry_and_missing_file_fail_closed(delivery_case) -> None:
    export_delivery_package(
        delivery_case["ledger"], delivery_case["output"], privacy_view="public"
    )
    manifest_path = delivery_case["output"] / "manifest.json"
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw["entries"][0]["sha256"] = "0" * 64
    manifest_path.write_bytes(_canonical(raw))
    with pytest.raises(DeliveryPackageError):
        verify_delivery_package(delivery_case["output"])


def test_missing_required_file_fails_closed(delivery_case) -> None:
    export_delivery_package(
        delivery_case["ledger"], delivery_case["output"], privacy_view="public"
    )
    (delivery_case["output"] / "work-order.json").unlink()
    with pytest.raises(DeliveryPackageError, match="manifest file set"):
        verify_delivery_package(delivery_case["output"])


def _rewrite_manifest(package: Path, mutate) -> None:
    path = package / "manifest.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    mutate(raw)
    path.write_bytes(_canonical(raw))


def _rewrite_bound_json(package: Path, relative: str, mutate) -> None:
    path = package / relative
    raw = json.loads(path.read_text(encoding="utf-8"))
    mutate(raw)
    payload = _canonical(raw)
    path.write_bytes(payload)

    def update(manifest):
        entry = next(item for item in manifest["entries"] if item["path"] == relative)
        entry["sha256"] = hashlib.sha256(payload).hexdigest()
        entry["size_bytes"] = len(payload)

    _rewrite_manifest(package, update)


@pytest.mark.parametrize(
    ("target", "mutate"),
    (
        (
            "verification-decision.json",
            lambda raw: raw.__setitem__("decided_at", "2026-01-01T00:20:01Z"),
        ),
        (
            "execution-ledger/receipts.json",
            lambda raw: raw[0].__setitem__("occurred_at", "2026-01-01T00:00:04Z"),
        ),
        (
            "settlement-readiness.json",
            lambda raw: raw.__setitem__("settlement_readiness", "NOT_READY"),
        ),
    ),
)
def test_manifest_rewrite_cannot_hide_semantic_tamper(
    delivery_case, target, mutate
) -> None:
    export_delivery_package(
        delivery_case["ledger"], delivery_case["output"], privacy_view="public"
    )
    _rewrite_bound_json(delivery_case["output"], target, mutate)
    with pytest.raises(DeliveryPackageError):
        verify_delivery_package(delivery_case["output"])


def test_manifest_rewrite_cannot_change_media_type(delivery_case) -> None:
    export_delivery_package(
        delivery_case["ledger"], delivery_case["output"], privacy_view="public"
    )

    def mutate(raw):
        target = next(item for item in raw["entries"] if item["path"] == "summary.html")
        target["media_type"] = "application/json"

    _rewrite_manifest(delivery_case["output"], mutate)
    with pytest.raises(DeliveryPackageError, match="media type"):
        verify_delivery_package(delivery_case["output"])


def test_manifest_rebind_cannot_hide_public_key_tamper(delivery_case) -> None:
    manifest = export_delivery_package(
        delivery_case["ledger"], delivery_case["output"], privacy_view="public"
    )
    relative = next(
        entry.path
        for entry in manifest.entries
        if entry.path.startswith("public-keys/")
    )
    _rewrite_bound_json(
        delivery_case["output"],
        relative,
        lambda raw: raw.__setitem__("subject_id", "tampered-subject"),
    )
    with pytest.raises(DeliveryPackageError, match="public key set"):
        verify_delivery_package(delivery_case["output"])


def test_manifest_rebind_cannot_hide_receipt_parent_order_tamper(
    delivery_case,
) -> None:
    export_delivery_package(
        delivery_case["ledger"], delivery_case["output"], privacy_view="public"
    )
    relative = "execution-ledger/receipt-parents.json"

    def reverse_parent_order(raw):
        raw.extend(
            (
                {
                    "child_receipt_id": "2" * 64,
                    "parent_receipt_id": "4" * 64,
                },
                {
                    "child_receipt_id": "2" * 64,
                    "parent_receipt_id": "3" * 64,
                },
            )
        )

    _rewrite_bound_json(
        delivery_case["output"], relative, reverse_parent_order
    )
    with pytest.raises(DeliveryPackageError, match="causal graph"):
        verify_delivery_package(delivery_case["output"])


def test_resigned_evidence_ref_tamper_still_fails_decision_binding(
    delivery_case,
) -> None:
    manifest = export_delivery_package(
        delivery_case["ledger"], delivery_case["output"], privacy_view="public"
    )
    relative = next(
        entry.path
        for entry in manifest.entries
        if entry.path.startswith("evidence/positive/arm-results/")
    )
    path = delivery_case["output"] / relative
    raw = json.loads(path.read_text(encoding="utf-8"))
    for field in ("digest", "signature", "signature_alg", "signer_key_id"):
        raw.pop(field)
    raw["evidence_refs"][0]["sha256"] = "0" * 64
    resigned = sign_payload(
        "verification-arm-result", raw, delivery_case["verifier_key"]
    )
    payload = _canonical(resigned)
    path.write_bytes(payload)

    def bind_resigned_result(manifest_raw):
        entry = next(
            item for item in manifest_raw["entries"] if item["path"] == relative
        )
        entry["sha256"] = hashlib.sha256(payload).hexdigest()
        entry["size_bytes"] = len(payload)

    _rewrite_manifest(delivery_case["output"], bind_resigned_result)
    with pytest.raises(DeliveryPackageError, match="arm result binding"):
        verify_delivery_package(delivery_case["output"])


def test_manifest_bound_unknown_file_is_rejected(delivery_case) -> None:
    export_delivery_package(
        delivery_case["ledger"], delivery_case["output"], privacy_view="public"
    )
    payload = b"unknown"
    unknown = delivery_case["output"] / "evidence/positive/unknown.bin"
    unknown.parent.mkdir(parents=True, exist_ok=True)
    unknown.write_bytes(payload)

    def mutate(raw):
        raw["entries"].append(
            {
                "path": "evidence/positive/unknown.bin",
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size_bytes": len(payload),
                "media_type": "application/octet-stream",
                "privacy_class": "public",
                "required": True,
            }
        )
        raw["entries"].sort(key=lambda item: item["path"].encode("utf-8"))

    _rewrite_manifest(delivery_case["output"], mutate)
    with pytest.raises(DeliveryPackageError, match="allowlist"):
        verify_delivery_package(delivery_case["output"])


@pytest.mark.parametrize("failure", ("write", "verify", "rename"))
def test_failed_export_cleans_exact_temp_and_leaves_ledger_unchanged(
    delivery_case, monkeypatch, failure
) -> None:
    ledger_before = delivery_case["ledger"].read_bytes()
    original_write = delivery_package._write_file
    calls = 0

    if failure == "write":
        def fail_write(root, relative, payload):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError("mid-write")
            return original_write(root, relative, payload)

        monkeypatch.setattr(delivery_package, "_write_file", fail_write)
    elif failure == "verify":
        monkeypatch.setattr(
            delivery_package,
            "verify_delivery_package",
            lambda _: (_ for _ in ()).throw(DeliveryPackageError("verify fault")),
        )
    else:
        monkeypatch.setattr(
            delivery_package.os,
            "rename",
            lambda *_: (_ for _ in ()).throw(OSError("rename fault")),
        )
    with pytest.raises(DeliveryPackageError):
        export_delivery_package(
            delivery_case["ledger"], delivery_case["output"], privacy_view="public"
        )
    assert delivery_case["ledger"].read_bytes() == ledger_before
    assert not delivery_case["output"].exists()
    assert not tuple(
        delivery_case["output"].parent.glob(
            f".{delivery_case['output'].name}.*.tmp"
        )
    )


def test_cleanup_failure_is_reported_without_publishing_output(
    delivery_case, monkeypatch
) -> None:
    monkeypatch.setattr(
        delivery_package.os,
        "rename",
        lambda *_: (_ for _ in ()).throw(OSError("rename fault")),
    )
    monkeypatch.setattr(
        delivery_package.shutil,
        "rmtree",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("cleanup fault")),
    )
    with pytest.raises(DeliveryPackageError, match="cleanup failed"):
        export_delivery_package(
            delivery_case["ledger"], delivery_case["output"], privacy_view="public"
        )
    assert not delivery_case["output"].exists()
