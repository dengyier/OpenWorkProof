"""Acceptance-to-v0.5-decision companion binding tests."""

from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
from datetime import timedelta
from pathlib import Path

import pytest
import rfc8785
from pydantic import ValidationError

import openworkproof.acceptance as acceptance
import openworkproof.evidence as evidence
from openworkproof.signing import key_id, sign_payload, verify_payload


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FROZEN_PROTOCOL_FILES = {
    "src/openworkproof/schemas/v0.1/acceptance-receipt.schema.json": (
        "5436e77e03d64cf131f2273b7527e63aa854f9c3de7b60aeae8751024267ff0e"
    ),
    "src/openworkproof/schemas/v0.1/acceptance-rejection-receipt.schema.json": (
        "cab320167c5af36afcc06506d13cbaa85c3dd9f6b470c4db12d127726fa86ae8"
    ),
    "src/openworkproof/schemas/v0.1/schema-registry.json": (
        "b543abb2d972a84d3fffe97e6f9381f33b5cfe40fe0c8c7c046f91354f849000"
    ),
    "src/openworkproof/schemas/v0.5/verification-decision.schema.json": (
        "682dc06cb5034bc55f93378d5b887e6ef46522ef289ab1aec54debda880128d3"
    ),
    "src/openworkproof/schemas/v0.5/schema-registry.json": (
        "bc3e702340b538529b2d5faff5227991e05c08643d5ebc7af5a5a059c85049e8"
    ),
}


@pytest.fixture(autouse=True)
def _stub_candidate_execution_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    """Use the same deterministic candidate snapshot as acceptance tests."""
    from openworkproof import repo_tools

    def prepare(request):
        return repo_tools.CandidateExecutionSnapshot(
            head_commit=request.expected_head_commit,
            workspace_manifest_digest=(
                request.expected_workspace_manifest_digest
            ),
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
        )

    monkeypatch.setattr(
        repo_tools,
        "prepare_candidate_execution_snapshot",
        prepare,
    )


def test_frozen_acceptance_and_v05_schema_bytes_are_unchanged() -> None:
    for relative, expected in FROZEN_PROTOCOL_FILES.items():
        payload = PROJECT_ROOT.joinpath(relative).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == expected


def test_unbound_cross_version_pair_requires_signed_companion() -> None:
    """Two independently valid proofs must not become one delivery by packaging."""

    from openworkproof.models import AcceptanceDecisionBindingV01

    assert AcceptanceDecisionBindingV01 is not None


def _binding_payload() -> dict[str, object]:
    from openworkproof.models import acceptance_decision_binding_id

    raw: dict[str, object] = {
        "schema_version": "openworkproof-acceptance-decision-binding/0.1",
        "protocol_version": "0.1",
        "work_order_digest": "1" * 64,
        "verification_decision_id": "2" * 64,
        "verification_decision_digest": "3" * 64,
        "composition_report_digest": "4" * 64,
        "acceptance_request_receipt_id": "5" * 64,
        "acceptance_request_receipt_digest": "6" * 64,
        "terminal_kind": "accepted",
        "terminal_receipt_id": "7" * 64,
        "terminal_receipt_digest": "8" * 64,
        "bound_at": "2026-08-21T12:00:00Z",
        "nonce": "9" * 64,
    }
    raw["binding_id"] = acceptance_decision_binding_id(raw)
    return raw


def _signed_binding(ephemeral_role_keys, *, role: str = "Acceptor"):
    from openworkproof.models import AcceptanceDecisionBindingV01

    private_key = ephemeral_role_keys[role][0]
    return AcceptanceDecisionBindingV01.model_validate(
        sign_payload(
            "acceptance-decision-binding",
            _binding_payload(),
            private_key,
        )
    )


def test_binding_id_and_signature_are_deterministic(ephemeral_role_keys) -> None:
    from openworkproof.models import acceptance_decision_binding_id

    first = _signed_binding(ephemeral_role_keys)
    second = _signed_binding(ephemeral_role_keys)
    assert first == second
    assert first.binding_id == acceptance_decision_binding_id(
        first.model_dump(mode="json")
    )
    assert verify_payload(
        "acceptance-decision-binding",
        first.model_dump(mode="json"),
        ephemeral_role_keys["Acceptor"][0].public_key(),
    )


def test_binding_signature_does_not_verify_under_another_role(
    ephemeral_role_keys,
) -> None:
    binding = _signed_binding(ephemeral_role_keys)
    assert binding.signer_key_id == key_id(
        ephemeral_role_keys["Acceptor"][0].public_key()
    )
    assert not verify_payload(
        "acceptance-decision-binding",
        binding.model_dump(mode="json"),
        ephemeral_role_keys["Maintainer"][0].public_key(),
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("schema_version", "openworkproof-acceptance-decision-binding/9.9"),
        ("protocol_version", "0.2"),
        ("verification_decision_digest", "a" * 63),
        ("terminal_kind", "withdrawn"),
        ("bound_at", "2026-08-21T12:00:00+00:00"),
        ("nonce", "A" * 64),
    ),
)
def test_binding_rejects_invalid_closed_fields(
    ephemeral_role_keys,
    field: str,
    value: object,
) -> None:
    from openworkproof.models import AcceptanceDecisionBindingV01

    raw = _binding_payload()
    raw[field] = value
    signed = sign_payload(
        "acceptance-decision-binding",
        raw,
        ephemeral_role_keys["Acceptor"][0],
    )
    with pytest.raises(ValidationError):
        AcceptanceDecisionBindingV01.model_validate(signed)


def test_binding_rejects_unknown_fields(ephemeral_role_keys) -> None:
    from openworkproof.models import AcceptanceDecisionBindingV01

    raw = _binding_payload()
    raw["customer_note"] = "unsigned interpretation"
    signed = sign_payload(
        "acceptance-decision-binding",
        raw,
        ephemeral_role_keys["Acceptor"][0],
    )
    with pytest.raises(ValidationError):
        AcceptanceDecisionBindingV01.model_validate(signed)


def test_binding_rejects_semantic_change_with_stale_id(
    ephemeral_role_keys,
) -> None:
    from openworkproof.models import AcceptanceDecisionBindingV01

    raw = _binding_payload()
    raw["verification_decision_digest"] = "a" * 64
    signed = sign_payload(
        "acceptance-decision-binding",
        raw,
        ephemeral_role_keys["Acceptor"][0],
    )
    with pytest.raises(ValidationError, match="binding ID"):
        AcceptanceDecisionBindingV01.model_validate(signed)


def test_binding_revalidates_malicious_subclass(ephemeral_role_keys) -> None:
    from openworkproof.models import AcceptanceDecisionBindingV01

    binding = _signed_binding(ephemeral_role_keys)

    class Child(AcceptanceDecisionBindingV01):
        pass

    malicious = Child.model_construct(
        **{
            **binding.__dict__,
            "terminal_kind": "withdrawn",
        }
    )
    with pytest.raises(ValidationError):
        AcceptanceDecisionBindingV01.model_validate(malicious)


def _install_v05_decision(
    *,
    case,
    context,
    signed_subject_claim,
    evaluation_scope_payload_v03,
    verification_profile_v03,
    ephemeral_role_keys,
):
    from openworkproof.models import (
        DecisionDraftRequest,
        SubjectClaim,
        VerificationProfileV03,
    )
    from openworkproof.scope import ObservedScope
    from openworkproof.verification import (
        commit_evaluation_scope,
        commit_verification_arm_result_v05,
        commit_verification_decision_v05,
        commit_verification_profile_v05,
    )
    from test_verification_integrity_transactions_v05 import (
        _signed_decision_v05,
        _transaction_manifest,
        _transaction_profile_v05,
        _v05_arm_result,
        _v05_control_observation,
        _v05_population_observation,
        _write_json_evidence,
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
        sign_payload(
            "subject-claim",
            claim_raw,
            ephemeral_role_keys["Manager"][0],
        )
    )
    selector_parent = case["ledger_path"].parent / "scope/selectors"
    selector_parent.mkdir(parents=True, exist_ok=True)
    source_spec = {
        "schema_version": "openworkproof-selector-spec/0.3",
        "selector_kind": "explicit",
        "locators": ["src/widget.py"],
    }
    test_spec = {
        "schema_version": "openworkproof-selector-spec/0.3",
        "selector_kind": "explicit",
        "locators": ["tests/test_widget.py::test_widget[param-\u4e00]"],
    }
    source_raw = rfc8785.dumps(source_spec)
    test_raw = rfc8785.dumps(test_spec)
    (selector_parent / "source.json").write_bytes(source_raw)
    (selector_parent / "tests.json").write_bytes(test_raw)
    scope_payload = copy.deepcopy(evaluation_scope_payload_v03)
    original = scope_payload["selector_rules"][0]
    scope_payload["selector_rules"] = [
        {
            **original,
            "rule_id": "3" * 64,
            "selector_spec_digest": hashlib.sha256(source_raw).hexdigest(),
            "selector_engine_digest": "5" * 64,
            "required_evidence_paths": ["scope/selectors/source.json"],
        },
        {
            **original,
            "rule_id": "6" * 64,
            "selector_spec_digest": hashlib.sha256(test_raw).hexdigest(),
            "selector_engine_digest": "8" * 64,
            "required_evidence_paths": ["scope/selectors/tests.json"],
        },
    ]
    manifest = _transaction_manifest(
        scope_payload,
        work_order=case["work_order"],
        claim=claim,
        manager_key=ephemeral_role_keys["Manager"][0],
    )
    profile_raw = verification_profile_v03.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    verifier = ephemeral_role_keys["Verifier"][1]
    profile_raw["verifier_bindings"] = [
        {
            "binding_id": "a" * 64,
            "verifier_subject_id": verifier["subject_id"],
            "verifier_key_id": verifier["key_id"],
            "verifier_public_key_b64url": verifier["public_key_b64url"],
            "controller_factors": ["customer-independent-verifier"],
            "execution_context_factors": ["isolated-container-a"],
            "valid_from": "2026-01-01T00:00:04Z",
            "expires_at": "2026-01-01T01:00:00Z",
        }
    ]
    rebound_profile_v03 = VerificationProfileV03.model_validate(
        sign_payload(
            "verification-profile",
            profile_raw,
            ephemeral_role_keys["Manager"][0],
            version="0.3",
        )
    )
    profile = _transaction_profile_v05(
        rebound_profile_v03,
        manifest=manifest,
        manager_key=ephemeral_role_keys["Manager"][0],
    )
    commit_evaluation_scope(case["ledger_path"], claim, manifest)
    commit_verification_profile_v05(case["ledger_path"], profile)
    observed = ObservedScope(
        member_ids=tuple(member.member_id for member in manifest.members),
        member_count=manifest.member_count,
        population_digest=manifest.population_digest,
        required_target_ids=manifest.required_target_ids,
        source_revision=manifest.source_revision,
        workspace_manifest_digest=manifest.workspace_manifest_digest,
        selector_engine_digests=tuple(
            sorted(
                rule.selector_engine_digest for rule in manifest.selector_rules
            )
        ),
        evidence_complete=True,
    )
    results = []
    for kind in ("positive", "negative"):
        result_ref = _write_json_evidence(
            case["ledger_path"].parent,
            f"results/{kind}.json",
            {"arm": kind, "passed": True},
        )
        scope_ref = _write_json_evidence(
            case["ledger_path"].parent,
            f"scope/{kind}.json",
            observed.model_dump(mode="json"),
        )
        observations = [
            _v05_population_observation(
                case["ledger_path"].parent,
                contract,
                suffix=f"{kind}-{contract.member_kind}",
            )
            for contract in profile.population_contracts
        ]
        control = (
            _v05_control_observation(
                case["ledger_path"].parent,
                profile.control_contracts[0],
                arm_kind=kind,
            )
            if kind == "negative"
            else None
        )
        results.append(
            _v05_arm_result(
                profile=profile,
                manifest=manifest,
                keys=ephemeral_role_keys,
                arm_kind=kind,
                observations=observations,
                control_observation=control,
                action_receipt_id=context.ledger_prefix.receipts[-1].receipt_id,
                evidence_ref=result_ref,
                scope_evidence_ref=scope_ref,
            )
        )
    for result in results:
        commit_verification_arm_result_v05(case["ledger_path"], result)
    decision_case = {
        "ledger": case["ledger_path"],
        "manifest": manifest,
        "profile": profile,
        "results": tuple(results),
        "keys": ephemeral_role_keys,
    }
    decision = _signed_decision_v05(
        decision_case,
        DecisionDraftRequest(
            decision_id="c" * 64,
            decided_at="2026-01-01T00:20:00Z",
            nonce="d" * 64,
        ),
    )
    commit_verification_decision_v05(case["ledger_path"], decision)
    return {
        "ledger": case["ledger_path"],
        "manifest": manifest,
        "profile": profile,
        "results": tuple(results),
        "keys": ephemeral_role_keys,
        "decision": decision,
    }


def _build_terminal_v05_case(
    tmp_path,
    signed_work_order,
    signed_subject_claim,
    evaluation_scope_payload_v03,
    frozen_verification_profile_v03,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
    *,
    terminal_kind,
):
    from test_acceptance import _request_case, _sign_draft
    from test_mcp_server import _current_run_tests_context

    flow_now = fixed_now + timedelta(minutes=21) - timedelta(seconds=5)
    case, context, _request, composed, expires_at = _request_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    verification_case = _install_v05_decision(
        case=case,
        context=context,
        signed_subject_claim=signed_subject_claim,
        evaluation_scope_payload_v03=evaluation_scope_payload_v03,
        verification_profile_v03=frozen_verification_profile_v03,
        ephemeral_role_keys=ephemeral_role_keys,
    )
    context = _current_run_tests_context(case, flow_now)
    assert context.current_state == "proof_ready"
    from openworkproof.models import AgentRequest, request_arguments_digest
    from test_mcp_server import _grant_id

    manager = ephemeral_role_keys["Manager"][1]
    requested_scope = {
        "work_order_digest": case["work_order"].digest,
        "operation": "submit_final_acceptance",
        "composition_report_digest": acceptance.composition_report_digest(
            composed.report
        ),
    }
    target_action_digest = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/final-acceptance-action/v0.1",
                "requested_scope": requested_scope,
            }
        )
    ).hexdigest()
    arguments = {
        "request_kind": "final_acceptance",
        "target_action_digest": target_action_digest,
        "required_role": "Acceptor",
        "requested_scope": requested_scope,
        "expires_at": "2026-01-01T00:30:00Z",
    }
    request = AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            {
                "claim_type": "agent-request",
                "work_order_digest": case["work_order"].digest,
                "grant_id": case["root"].grant_id,
                "actor_id": manager["subject_id"],
                "actor_key_id": manager["key_id"],
                "tool_name": "owp.request_acceptance",
                "arguments_digest": request_arguments_digest(
                    "owp.request_acceptance", arguments
                ),
                "nonce": _grant_id("acceptance:request:v05-binding"),
                "requested_at": flow_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "authentication_method": "agent_signature",
                "model_id": "model",
                "model_version": "1",
                "prompt_template_digest": "a" * 64,
                "context_source_digest": "b" * 64,
            },
            ephemeral_role_keys["Manager"][0],
        )
    )
    request_receipt = acceptance.request_acceptance_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        request=request,
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        expires_at=expires_at,
        clock=lambda: flow_now,
    )
    awaiting = _current_run_tests_context(case, flow_now)
    if terminal_kind == "accepted":
        draft = acceptance.prepare_acceptance(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=awaiting,
            clock=lambda: flow_now,
        )
        terminal = _sign_draft(draft, ephemeral_role_keys)
        acceptance.commit_acceptance(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=awaiting,
            acceptance=terminal,
            public_keys=None,
            clock=lambda: flow_now,
        )
    else:
        from test_acceptor_rejection import _sign_rejection

        terminal = _sign_rejection(
            case,
            awaiting,
            request_receipt,
            ephemeral_role_keys,
            flow_now,
        )
        acceptance.reject_acceptance_transaction(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=awaiting,
            rejection=terminal,
            public_keys=None,
            clock=lambda: flow_now,
        )
    return {
        **case,
        "decision": verification_case["decision"],
        "verification_case": verification_case,
        "report": composed.report,
        "request": request_receipt,
        "terminal": terminal,
        "binding_now": flow_now + timedelta(minutes=1),
        "keys": ephemeral_role_keys,
    }


@pytest.fixture
def accepted_v05_case(
    tmp_path,
    signed_work_order,
    signed_subject_claim,
    evaluation_scope_payload_v03,
    frozen_verification_profile_v03,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
):
    return _build_terminal_v05_case(
        tmp_path,
        signed_work_order,
        signed_subject_claim,
        evaluation_scope_payload_v03,
        frozen_verification_profile_v03,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
        terminal_kind="accepted",
    )


@pytest.fixture
def rejected_v05_case(
    tmp_path,
    signed_work_order,
    signed_subject_claim,
    evaluation_scope_payload_v03,
    frozen_verification_profile_v03,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
):
    return _build_terminal_v05_case(
        tmp_path,
        signed_work_order,
        signed_subject_claim,
        evaluation_scope_payload_v03,
        frozen_verification_profile_v03,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
        terminal_kind="rejected",
    )


def _sign_binding_draft(draft, keys, *, role="Acceptor"):
    from openworkproof.models import AcceptanceDecisionBindingV01

    return AcceptanceDecisionBindingV01.model_validate(
        sign_payload(
            draft.signing_domain,
            dict(draft.payload),
            keys[role][0],
        )
    )


def _supersede_v05_decision(case):
    from openworkproof.models import DecisionDraftRequest
    from openworkproof.verification import commit_verification_decision_v05
    from test_verification_integrity_transactions_v05 import _signed_decision_v05

    decision = _signed_decision_v05(
        case["verification_case"],
        DecisionDraftRequest(
            decision_id="e" * 64,
            decided_at="2026-01-01T00:23:00Z",
            nonce="f" * 64,
        ),
    )
    commit_verification_decision_v05(case["ledger_path"], decision)
    return decision


def _supersede_with_unknown_v05_decision(case):
    from openworkproof.models import DecisionDraftRequest
    from openworkproof.verification import (
        commit_verification_arm_result_v05,
        commit_verification_decision_v05,
    )
    from test_verification_integrity_transactions_v05 import (
        _resign_arm_result_v05,
        _signed_decision_v05,
        _v05_population_observation,
    )

    verification_case = case["verification_case"]
    replacements = []
    for index, result in enumerate(verification_case["results"]):
        observations = tuple(
            _v05_population_observation(
                case["ledger_path"].parent,
                contract,
                suffix=f"empty-{index}-{contract.member_kind}",
                eligible_seen=0,
                selected_count=0,
            )
            for contract in verification_case["profile"].population_contracts
        )
        replacements.append(
            _resign_arm_result_v05(
                verification_case,
                result,
                arm_result_id=("0" if index == 0 else "1") * 64,
                population_observations=observations,
                created_at="2026-01-01T00:22:30Z",
            )
        )
    for result in replacements:
        commit_verification_arm_result_v05(case["ledger_path"], result)
    decision_case = {**verification_case, "results": tuple(replacements)}
    decision = _signed_decision_v05(
        decision_case,
        DecisionDraftRequest(
            decision_id="e" * 64,
            decided_at="2026-01-01T00:23:00Z",
            nonce="f" * 64,
        ),
    )
    assert decision.decision == "UNKNOWN"
    commit_verification_decision_v05(case["ledger_path"], decision)
    return decision


def test_prepare_and_commit_binding_round_trip(accepted_v05_case) -> None:
    case = accepted_v05_case
    draft = acceptance.prepare_acceptance_decision_binding(
        case["ledger_path"],
        clock=lambda: case["binding_now"],
    )
    assert draft.signing_domain == "acceptance-decision-binding"
    assert draft.verification_decision_id == case["decision"].decision_id
    assert draft.terminal_receipt_id == case["terminal"].acceptance_id
    assert draft.composition_report_digest == acceptance.composition_report_digest(
        case["report"]
    )
    signed = _sign_binding_draft(draft, case["keys"])
    assert acceptance.commit_acceptance_decision_binding(
        case["ledger_path"],
        signed,
        clock=lambda: case["binding_now"],
    ) == signed
    assert acceptance.load_current_acceptance_decision_binding(
        case["ledger_path"]
    ) == signed


def test_rejected_terminal_prepare_and_commit_round_trip(
    rejected_v05_case,
) -> None:
    case = rejected_v05_case
    draft = acceptance.prepare_acceptance_decision_binding(
        case["ledger_path"],
        clock=lambda: case["binding_now"],
    )
    assert draft.terminal_receipt_id == case["terminal"].rejection_id
    signed = _sign_binding_draft(draft, case["keys"])
    assert signed.terminal_kind == "rejected"
    assert acceptance.commit_acceptance_decision_binding(
        case["ledger_path"],
        signed,
        clock=lambda: case["binding_now"],
    ) == signed


def test_binding_commit_rejects_non_acceptor_signature(accepted_v05_case) -> None:
    case = accepted_v05_case
    draft = acceptance.prepare_acceptance_decision_binding(
        case["ledger_path"],
        clock=lambda: case["binding_now"],
    )
    signed = _sign_binding_draft(draft, case["keys"], role="Maintainer")
    with pytest.raises(acceptance.AcceptanceTransactionError, match="Acceptor"):
        acceptance.commit_acceptance_decision_binding(
            case["ledger_path"],
            signed,
            clock=lambda: case["binding_now"],
        )


def test_binding_commit_rejects_bad_acceptor_signature(accepted_v05_case) -> None:
    from openworkproof.models import AcceptanceDecisionBindingV01

    case = accepted_v05_case
    draft = acceptance.prepare_acceptance_decision_binding(
        case["ledger_path"],
        clock=lambda: case["binding_now"],
    )
    signed = _sign_binding_draft(draft, case["keys"])
    raw = signed.model_dump(mode="json")
    raw["signature"] = ("A" if raw["signature"][0] != "A" else "B") + raw[
        "signature"
    ][1:]
    forged = AcceptanceDecisionBindingV01.model_validate(raw)
    with pytest.raises(acceptance.AcceptanceTransactionError, match="signature"):
        acceptance.commit_acceptance_decision_binding(
            case["ledger_path"],
            forged,
            clock=lambda: case["binding_now"],
        )


def test_binding_commit_rejects_unbound_key(accepted_v05_case) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from openworkproof.models import AcceptanceDecisionBindingV01

    case = accepted_v05_case
    draft = acceptance.prepare_acceptance_decision_binding(
        case["ledger_path"], clock=lambda: case["binding_now"]
    )
    signed = AcceptanceDecisionBindingV01.model_validate(
        sign_payload(
            draft.signing_domain,
            dict(draft.payload),
            Ed25519PrivateKey.generate(),
        )
    )
    with pytest.raises(acceptance.AcceptanceTransactionError, match="Acceptor"):
        acceptance.commit_acceptance_decision_binding(
            case["ledger_path"],
            signed,
            clock=lambda: case["binding_now"],
        )


def test_binding_commit_rejects_stale_signature(accepted_v05_case) -> None:
    case = accepted_v05_case
    draft = acceptance.prepare_acceptance_decision_binding(
        case["ledger_path"],
        clock=lambda: case["binding_now"],
    )
    signed = _sign_binding_draft(draft, case["keys"])
    with pytest.raises(acceptance.AcceptanceTransactionError, match="stale"):
        acceptance.commit_acceptance_decision_binding(
            case["ledger_path"],
            signed,
            clock=lambda: case["binding_now"] + timedelta(seconds=301),
        )


def test_uncommitted_binding_to_superseded_decision_is_rejected(
    accepted_v05_case,
) -> None:
    case = accepted_v05_case
    draft = acceptance.prepare_acceptance_decision_binding(
        case["ledger_path"],
        clock=lambda: case["binding_now"],
    )
    signed = _sign_binding_draft(draft, case["keys"])
    _supersede_v05_decision(case)
    with pytest.raises(
        acceptance.AcceptanceTransactionError,
        match="authoritative history",
    ):
        acceptance.commit_acceptance_decision_binding(
            case["ledger_path"],
            signed,
            clock=lambda: case["binding_now"] + timedelta(minutes=2),
        )


def test_prepare_rejects_current_non_verified_decision(accepted_v05_case) -> None:
    case = accepted_v05_case
    _supersede_with_unknown_v05_decision(case)
    with pytest.raises(
        acceptance.AcceptanceTransactionError,
        match="current v0.5 VERIFIED",
    ):
        acceptance.prepare_acceptance_decision_binding(
            case["ledger_path"],
            clock=lambda: case["binding_now"] + timedelta(minutes=2),
        )


def test_non_verified_successor_hides_but_does_not_erase_binding(
    accepted_v05_case,
) -> None:
    case = accepted_v05_case
    draft = acceptance.prepare_acceptance_decision_binding(
        case["ledger_path"], clock=lambda: case["binding_now"]
    )
    signed = _sign_binding_draft(draft, case["keys"])
    acceptance.commit_acceptance_decision_binding(
        case["ledger_path"], signed, clock=lambda: case["binding_now"]
    )
    _supersede_with_unknown_v05_decision(case)
    assert acceptance.load_current_acceptance_decision_binding(
        case["ledger_path"]
    ) is None
    with pytest.raises(acceptance.AcceptanceBindingCommittedError) as captured:
        acceptance.commit_acceptance_decision_binding(
            case["ledger_path"],
            signed,
            clock=lambda: case["binding_now"] + timedelta(minutes=2),
        )
    assert captured.value.committed == signed


@pytest.mark.parametrize(
    "field",
    (
        "verification_decision_digest",
        "composition_report_digest",
        "acceptance_request_receipt_digest",
        "terminal_receipt_digest",
    ),
)
def test_binding_commit_rejects_resigned_authoritative_field_drift(
    accepted_v05_case,
    field,
) -> None:
    from openworkproof.models import (
        AcceptanceDecisionBindingV01,
        acceptance_decision_binding_id,
    )

    case = accepted_v05_case
    draft = acceptance.prepare_acceptance_decision_binding(
        case["ledger_path"], clock=lambda: case["binding_now"]
    )
    payload = dict(draft.payload)
    payload[field] = "0" * 64
    payload["binding_id"] = acceptance_decision_binding_id(payload)
    drifted = AcceptanceDecisionBindingV01.model_validate(
        sign_payload(
            draft.signing_domain,
            payload,
            case["keys"]["Acceptor"][0],
        )
    )
    with pytest.raises(
        acceptance.AcceptanceTransactionError,
        match="authoritative history",
    ):
        acceptance.commit_acceptance_decision_binding(
            case["ledger_path"],
            drifted,
            clock=lambda: case["binding_now"],
        )


def test_binding_exact_replay_reports_committed_truth(accepted_v05_case) -> None:
    case = accepted_v05_case
    draft = acceptance.prepare_acceptance_decision_binding(
        case["ledger_path"],
        clock=lambda: case["binding_now"],
    )
    signed = _sign_binding_draft(draft, case["keys"])
    acceptance.commit_acceptance_decision_binding(
        case["ledger_path"],
        signed,
        clock=lambda: case["binding_now"],
    )
    with pytest.raises(acceptance.AcceptanceBindingCommittedError) as captured:
        acceptance.commit_acceptance_decision_binding(
            case["ledger_path"],
            signed,
            clock=lambda: case["binding_now"] + timedelta(days=2),
        )
    assert captured.value.committed == signed


def test_superseded_binding_remains_historical_but_is_not_current(
    accepted_v05_case,
) -> None:
    case = accepted_v05_case
    draft = acceptance.prepare_acceptance_decision_binding(
        case["ledger_path"],
        clock=lambda: case["binding_now"],
    )
    signed = _sign_binding_draft(draft, case["keys"])
    acceptance.commit_acceptance_decision_binding(
        case["ledger_path"],
        signed,
        clock=lambda: case["binding_now"],
    )
    successor = _supersede_v05_decision(case)
    assert successor.supersedes_decision_id == signed.verification_decision_id
    assert acceptance.load_current_acceptance_decision_binding(
        case["ledger_path"]
    ) is None
    with pytest.raises(acceptance.AcceptanceBindingCommittedError) as captured:
        acceptance.commit_acceptance_decision_binding(
            case["ledger_path"],
            signed,
            clock=lambda: case["binding_now"] + timedelta(minutes=2),
        )
    assert captured.value.committed == signed


def test_binding_tables_are_physically_immutable(accepted_v05_case) -> None:
    case = accepted_v05_case
    draft = acceptance.prepare_acceptance_decision_binding(
        case["ledger_path"],
        clock=lambda: case["binding_now"],
    )
    signed = _sign_binding_draft(draft, case["keys"])
    acceptance.commit_acceptance_decision_binding(
        case["ledger_path"],
        signed,
        clock=lambda: case["binding_now"],
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        with pytest.raises(Exception, match="immutable"):
            connection.execute(
                "UPDATE acceptance_decision_bindings_v01 "
                "SET committed_at = committed_at"
            )
        with pytest.raises(Exception, match="immutable"):
            connection.execute("DELETE FROM acceptance_decision_bindings_v01")
    finally:
        connection.close()


def test_binding_index_set_is_frozen(accepted_v05_case) -> None:
    connection = evidence.connect_ledger(accepted_v05_case["ledger_path"])
    try:
        indexes = tuple(
            sorted(
                (row[1], row[2], row[3])
                for row in connection.execute(
                    "PRAGMA index_list(acceptance_decision_bindings_v01)"
                )
            )
        )
    finally:
        connection.close()
    assert indexes == (
        ("acceptance_decision_bindings_v01_work_order", 0, "c"),
        ("sqlite_autoindex_acceptance_decision_bindings_v01_1", 1, "pk"),
        ("sqlite_autoindex_acceptance_decision_bindings_v01_2", 1, "u"),
        ("sqlite_autoindex_acceptance_decision_bindings_v01_3", 1, "u"),
    )


def test_terminal_can_have_only_one_binding(accepted_v05_case) -> None:
    case = accepted_v05_case
    first_draft = acceptance.prepare_acceptance_decision_binding(
        case["ledger_path"],
        clock=lambda: case["binding_now"],
    )
    second_draft = acceptance.prepare_acceptance_decision_binding(
        case["ledger_path"],
        clock=lambda: case["binding_now"],
    )
    first = _sign_binding_draft(first_draft, case["keys"])
    second = _sign_binding_draft(second_draft, case["keys"])
    assert first.binding_id != second.binding_id
    acceptance.commit_acceptance_decision_binding(
        case["ledger_path"], first, clock=lambda: case["binding_now"]
    )
    with pytest.raises(acceptance.AcceptanceTransactionError, match="terminal"):
        acceptance.commit_acceptance_decision_binding(
            case["ledger_path"], second, clock=lambda: case["binding_now"]
        )


def test_same_binding_id_with_different_bytes_is_rejected(
    accepted_v05_case,
) -> None:
    from openworkproof.models import AcceptanceDecisionBindingV01

    case = accepted_v05_case
    draft = acceptance.prepare_acceptance_decision_binding(
        case["ledger_path"], clock=lambda: case["binding_now"]
    )
    signed = _sign_binding_draft(draft, case["keys"])
    acceptance.commit_acceptance_decision_binding(
        case["ledger_path"], signed, clock=lambda: case["binding_now"]
    )
    raw = signed.model_dump(mode="json")
    raw["signature"] = ("A" if raw["signature"][0] != "A" else "B") + raw[
        "signature"
    ][1:]
    conflicting = AcceptanceDecisionBindingV01.model_validate(raw)
    with pytest.raises(acceptance.AcceptanceTransactionError, match="ID"):
        acceptance.commit_acceptance_decision_binding(
            case["ledger_path"],
            conflicting,
            clock=lambda: case["binding_now"],
        )


@pytest.mark.parametrize(
    ("fault", "error_type", "row_count"),
    (
        ("before_commit", acceptance.AcceptanceTransactionError, 0),
        ("commit_ack_loss", acceptance.AcceptanceBindingCommittedError, 1),
        (
            "readback_failure",
            acceptance.AcceptanceBindingCommitIndeterminateError,
            1,
        ),
        ("cleanup_failure", acceptance.AcceptanceBindingCommittedError, 1),
    ),
)
def test_binding_fault_matrix_is_closed(
    accepted_v05_case,
    fault,
    error_type,
    row_count,
) -> None:
    case = accepted_v05_case
    draft = acceptance.prepare_acceptance_decision_binding(
        case["ledger_path"], clock=lambda: case["binding_now"]
    )
    signed = _sign_binding_draft(draft, case["keys"])
    with pytest.raises(error_type):
        acceptance.commit_acceptance_decision_binding(
            case["ledger_path"],
            signed,
            clock=lambda: case["binding_now"],
            fault=fault,
        )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM acceptance_decision_bindings_v01"
        ).fetchone() == (row_count,)
    finally:
        connection.close()


def test_real_commit_then_raise_is_confirmed_by_readback(
    accepted_v05_case,
    monkeypatch,
) -> None:
    case = accepted_v05_case
    draft = acceptance.prepare_acceptance_decision_binding(
        case["ledger_path"], clock=lambda: case["binding_now"]
    )
    signed = _sign_binding_draft(draft, case["keys"])
    real_connect = evidence.connect_ledger
    calls = 0

    class CommitAckLossConnection:
        def __init__(self, connection):
            self._connection = connection

        def execute(self, statement, parameters=()):
            result = self._connection.execute(statement, parameters)
            if statement == "COMMIT":
                raise OSError("commit acknowledgement lost")
            return result

        def __getattr__(self, name):
            return getattr(self._connection, name)

    def connect_once(path):
        nonlocal calls
        calls += 1
        connection = real_connect(path)
        if calls == 1:
            return CommitAckLossConnection(connection)
        return connection

    monkeypatch.setattr(evidence, "connect_ledger", connect_once)
    with pytest.raises(acceptance.AcceptanceBindingCommittedError) as captured:
        acceptance.commit_acceptance_decision_binding(
            case["ledger_path"],
            signed,
            clock=lambda: case["binding_now"],
        )
    assert captured.value.committed == signed


def test_unavailable_commit_readback_is_indeterminate(
    accepted_v05_case,
    monkeypatch,
) -> None:
    case = accepted_v05_case
    draft = acceptance.prepare_acceptance_decision_binding(
        case["ledger_path"], clock=lambda: case["binding_now"]
    )
    signed = _sign_binding_draft(draft, case["keys"])
    monkeypatch.setattr(
        acceptance,
        "_exact_acceptance_decision_binding_readback",
        lambda *_args, **_kwargs: False,
    )
    with pytest.raises(acceptance.AcceptanceBindingCommitIndeterminateError):
        acceptance.commit_acceptance_decision_binding(
            case["ledger_path"],
            signed,
            clock=lambda: case["binding_now"],
        )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM acceptance_decision_bindings_v01"
        ).fetchone() == (1,)
    finally:
        connection.close()


def test_identical_concurrent_binding_has_one_committer(
    accepted_v05_case,
) -> None:
    case = accepted_v05_case
    draft = acceptance.prepare_acceptance_decision_binding(
        case["ledger_path"], clock=lambda: case["binding_now"]
    )
    signed = _sign_binding_draft(draft, case["keys"])

    def commit_once() -> str:
        try:
            acceptance.commit_acceptance_decision_binding(
                case["ledger_path"],
                signed,
                clock=lambda: case["binding_now"],
            )
            return "committed"
        except acceptance.AcceptanceBindingCommittedError as error:
            assert error.committed == signed
            return "already_committed"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(lambda _: commit_once(), range(2)))
    assert outcomes == ["already_committed", "committed"]


def test_conflicting_concurrent_bindings_leave_one_row(
    accepted_v05_case,
) -> None:
    case = accepted_v05_case
    drafts = tuple(
        acceptance.prepare_acceptance_decision_binding(
            case["ledger_path"], clock=lambda: case["binding_now"]
        )
        for _ in range(2)
    )
    bindings = tuple(_sign_binding_draft(draft, case["keys"]) for draft in drafts)

    def commit_one(binding) -> str:
        try:
            acceptance.commit_acceptance_decision_binding(
                case["ledger_path"],
                binding,
                clock=lambda: case["binding_now"],
            )
            return "committed"
        except acceptance.AcceptanceTransactionError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(commit_one, bindings))
    assert outcomes == ["committed", "rejected"]
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM acceptance_decision_bindings_v01"
        ).fetchone() == (1,)
    finally:
        connection.close()
