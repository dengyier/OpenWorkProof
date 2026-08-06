from __future__ import annotations

import hashlib

import pytest
import rfc8785

from openworkproof.models import (
    ActionReceiptEnvelope,
    AgentRequest,
    CompositionReport,
    EvidenceRef,
)

from conftest import SHA256_A, SHA256_B, SHA256_C, SHA256_D

from openworkproof import acceptance


@pytest.fixture(autouse=True)
def _stub_candidate_execution_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub the filesystem candidate snapshot like test_mcp_server does."""
    from openworkproof import repo_tools  # noqa: PLC0415

    def prepare(
        request,
    ) -> repo_tools.CandidateExecutionSnapshot:
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


def _node(receipt: ActionReceiptEnvelope) -> dict:
    return {
        "receipt_id": receipt.receipt_id,
        "receipt_digest": receipt.digest,
        "parent_receipt_ids": list(receipt.parent_receipt_ids),
    }


def test_causal_graph_root_is_sequence_ordered() -> None:
    receipts = tuple(
        ActionReceiptEnvelope.model_construct(
            receipt_id=f"{index:064x}",
            digest=SHA256_A,
            parent_receipt_ids=(f"{index - 1:064x}",) if index else (),
            sequence=index,
        )
        for index in range(1, 4)
    )
    expected = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/causal-graph-root/0.1",
                "nodes": [
                    _node(receipt)
                    for receipt in sorted(receipts, key=lambda item: item.sequence)
                ],
            }
        )
    ).hexdigest()
    assert acceptance.causal_graph_root(receipts) == expected


def test_causal_graph_root_rejects_duplicate_or_unordered_prefix() -> None:
    receipts = tuple(
        ActionReceiptEnvelope.model_construct(
            receipt_id=f"{index:064x}",
            digest=SHA256_A,
            parent_receipt_ids=(),
            sequence=index,
        )
        for index in range(1, 3)
    )
    with pytest.raises(acceptance.AcceptanceTransactionError):
        acceptance.causal_graph_root(receipts + receipts[:1])
    with pytest.raises(acceptance.AcceptanceTransactionError):
        acceptance.causal_graph_root(tuple(reversed(receipts)))


def _evidence_ref(path: str, digest: str) -> EvidenceRef:
    return EvidenceRef.model_construct(
        path=path,
        sha256=digest,
        media_type="application/json",
        size_bytes=10,
    )


def _no_shared_assessment() -> dict:
    """A satisfied, disclose-only assessment with zero shared factors."""
    return {
        "policy": "disclose_only",
        "developer_reference": {
            "receipt_digest": SHA256_A,
            "factors": {
                "model_id": "dev-model",
                "model_version": "1",
                "prompt_template_digest": SHA256_A,
                "context_source_digest": SHA256_C,
                "toolchain_id": None,
                "execution_context_id": None,
                "container_instance_id_digest": None,
                "controller_id": f"ed25519:{SHA256_A}",
                "fixed_test_source_digest": None,
            },
        },
        "verifier_reference": {
            "receipt_digest": SHA256_B,
            "factors": {
                "model_id": "ver-model",
                "model_version": "1",
                "prompt_template_digest": SHA256_B,
                "context_source_digest": SHA256_D,
                "toolchain_id": None,
                "execution_context_id": None,
                "container_instance_id_digest": None,
                "controller_id": f"ed25519:{SHA256_B}",
                "fixed_test_source_digest": None,
            },
        },
        "shared_factors": [],
        "satisfied": True,
    }


def test_evidence_snapshot_digest_is_path_byte_sorted() -> None:
    refs = (
        _evidence_ref("evidence/patch-input/01.diff", SHA256_C),
        _evidence_ref("evidence/verifier-result/01.json", SHA256_B),
        _evidence_ref("evidence/verifier-result/02.json", SHA256_A),
    )
    expected = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/evidence-snapshot/0.1",
                "refs": [
                    ref.model_dump(mode="json")
                    for ref in sorted(refs, key=lambda item: item.path.encode("utf-8"))
                ],
            }
        )
    ).hexdigest()
    assert acceptance.evidence_snapshot_digest(refs) == expected


def test_evidence_snapshot_digest_rejects_duplicate_paths() -> None:
    refs = (
        _evidence_ref("evidence/x/01.json", SHA256_A),
        _evidence_ref("evidence/x/01.json", SHA256_B),
    )
    with pytest.raises(acceptance.AcceptanceTransactionError):
        acceptance.evidence_snapshot_digest(refs)


def test_composition_report_digest_is_exact_jcs_bytes() -> None:
    report = CompositionReport.model_validate(
        {
            "schema_version": "openworkproof-composition-report/0.1",
            "work_order_digest": SHA256_A,
            "initiator_receipt_id": SHA256_B,
            "initiator_receipt_digest": SHA256_C,
            "final_artifact": {
                "active_patch_receipt_digest": SHA256_A,
                "candidate_commit": "1" * 40,
                "workspace_manifest_digest": SHA256_B,
            },
            "artifact_digests": [],
            "evidence_snapshot_digest": SHA256_C,
            "receipt_digests": [SHA256_A],
            "causal_graph_root": SHA256_B,
            "causal_complete": True,
            "evidence_coverage": {"authority": True, "scope": True, "execution": True, "result": True, "independent_result": True},
            "independence_assessment": _no_shared_assessment(),
            "test_evidence_refs": [],
            "unresolved_failures": [],
            "warnings": [],
            "global_postconditions": [],
            "global_postconditions_satisfied": True,
            "verifier_conclusion": "proof_ready",
            "composed_at": "2026-01-01T00:00:00Z",
        }
    )
    canonical = rfc8785.dumps(report.model_dump(mode="json"))
    expected = hashlib.sha256(canonical).hexdigest()
    assert acceptance.composition_report_digest(report) == expected


def test_composition_report_proof_ready_requires_closed_conditions() -> None:
    def base() -> dict:
        return {
            "schema_version": "openworkproof-composition-report/0.1",
            "work_order_digest": SHA256_A,
            "initiator_receipt_id": SHA256_B,
            "initiator_receipt_digest": SHA256_C,
            "final_artifact": {
                "active_patch_receipt_digest": SHA256_A,
                "candidate_commit": "1" * 40,
                "workspace_manifest_digest": SHA256_B,
            },
            "artifact_digests": [],
            "evidence_snapshot_digest": SHA256_C,
            "receipt_digests": [SHA256_A],
            "causal_graph_root": SHA256_B,
            "causal_complete": True,
            "evidence_coverage": {"authority": True, "scope": True, "execution": True, "result": True, "independent_result": True},
            "independence_assessment": _no_shared_assessment(),
            "test_evidence_refs": [],
            "unresolved_failures": [],
            "warnings": [],
            "global_postconditions": [],
            "global_postconditions_satisfied": True,
            "verifier_conclusion": "proof_ready",
            "composed_at": "2026-01-01T00:00:00Z",
        }

    valid = CompositionReport.model_validate(base())
    assert valid.verifier_conclusion == "proof_ready"

    for path, value in (
        (("causal_complete",), False),
        (("unresolved_failures",), [{"code": "CAUSAL_INCOMPLETE", "subject_ref": SHA256_A}]),
        (("independence_assessment", "satisfied"), False),
        (("global_postconditions_satisfied",), False),
    ):
        candidate = base()
        target: dict = candidate
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value
        with pytest.raises(ValueError, match="proof-ready report is not closed"):
            CompositionReport.model_validate(candidate)

    incomplete = base()
    incomplete["verifier_conclusion"] = "evidence_incomplete"
    incomplete["unresolved_failures"] = [
        {"code": "MISSING_EVIDENCE_DIMENSION", "subject_ref": SHA256_A}
    ]
    parsed = CompositionReport.model_validate(incomplete)
    assert parsed.verifier_conclusion == "evidence_incomplete"

    bad_incomplete = base()
    bad_incomplete["verifier_conclusion"] = "evidence_incomplete"
    with pytest.raises(ValueError, match="closed diagnostics"):
        CompositionReport.model_validate(bad_incomplete)


def test_composition_report_recomputes_shared_factor_warnings() -> None:
    # Make the developer share the model factor with the verifier so the
    # assessment recomputes ("model",) as the shared-factor registry.
    assessment = _no_shared_assessment()
    assessment["developer_reference"]["factors"]["model_id"] = "ver-model"
    assessment["developer_reference"]["factors"]["model_version"] = "1"
    assessment["shared_factors"] = ["model"]
    expected_warning = {
        "code": "SHARED_MODEL",
        "subject_ref": hashlib.sha256(
            rfc8785.dumps(
                {
                    "domain": "openworkproof/shared-factor-ref/v0.1",
                    "factor": "model",
                    "value": {"model_id": "ver-model", "model_version": "1"},
                }
            )
        ).hexdigest(),
    }
    candidate = {
        "schema_version": "openworkproof-composition-report/0.1",
        "work_order_digest": SHA256_A,
        "initiator_receipt_id": SHA256_B,
        "initiator_receipt_digest": SHA256_C,
        "final_artifact": {
            "active_patch_receipt_digest": SHA256_A,
            "candidate_commit": "1" * 40,
            "workspace_manifest_digest": SHA256_B,
        },
        "artifact_digests": [],
        "evidence_snapshot_digest": SHA256_C,
        "receipt_digests": [SHA256_A],
        "causal_graph_root": SHA256_B,
        "causal_complete": True,
        "evidence_coverage": {
            "authority": True,
            "scope": True,
            "execution": True,
            "result": True,
            "independent_result": True,
        },
        "independence_assessment": assessment,
        "test_evidence_refs": [],
        "unresolved_failures": [],
        "warnings": [expected_warning],
        "global_postconditions": [],
        "global_postconditions_satisfied": True,
        "verifier_conclusion": "proof_ready",
        "composed_at": "2026-01-01T00:00:00Z",
    }
    report = CompositionReport.model_validate(candidate)
    assert [item.code for item in report.warnings] == ["SHARED_MODEL"]
    # A report that omits the recomputed warning must fail closed.
    with pytest.raises(ValueError, match="report warnings do not match"):
        CompositionReport.model_validate(
            {**candidate, "warnings": []}
        )


def _compose_case(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    now,
    monkeypatch=None,
):
    from test_mcp_server import (  # noqa: PLC0415
        _FakeRunTestsExecutionDriver,
        _current_run_tests_context,
        _execute_run_tests_case,
        _grant_id,
        _run_tests_case,
    )
    from openworkproof.models import (  # noqa: PLC0415
        ComposeProofArguments,
        request_arguments_digest,
    )
    from openworkproof.signing import sign_payload  # noqa: PLC0415

    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=now,
    )
    _execute_run_tests_case(
        case,
        tmp_path,
        ephemeral_role_keys,
        _FakeRunTestsExecutionDriver(),
    )
    context = _current_run_tests_context(case, now)
    assert context.current_state == "locally_verified"
    manager = ephemeral_role_keys["Manager"][1]
    arguments = ComposeProofArguments(
        expected_state_version=len(context.ledger_prefix.receipts),
        previous_report_digest=None,
    )
    request = AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            {
                "claim_type": "agent-request",
                "work_order_digest": case["work_order"].digest,
                "grant_id": case["root"].grant_id,
                "actor_id": manager["subject_id"],
                "actor_key_id": manager["key_id"],
                "tool_name": "owp.compose_proof",
                "arguments_digest": request_arguments_digest(
                    "owp.compose_proof", arguments
                ),
                "nonce": _grant_id("acceptance:compose-request"),
                "requested_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "authentication_method": "agent_signature",
                "model_id": "model",
                "model_version": "1",
                "prompt_template_digest": "a" * 64,
                "context_source_digest": "b" * 64,
            },
            ephemeral_role_keys["Manager"][0],
        )
    )
    return case, context, request




def _schema_tables(path: str) -> set[str]:
    import sqlite3  # noqa: PLC0415

    connection = sqlite3.connect(path)
    try:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'view')"
        ).fetchall()
        return {row[0] for row in rows}
    finally:
        connection.close()


def test_ledger_schema_includes_composition_reports(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case, _, _ = _compose_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    tables = _schema_tables(str(case["ledger_path"]))
    assert "composition_reports" in tables


def test_composition_report_loader_rejects_tampered_json(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    import sqlite3  # noqa: PLC0415

    from openworkproof import evidence  # noqa: PLC0415

    case, context, request = _compose_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    result = acceptance.compose_proof_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        request=request,
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        clock=lambda: fixed_now,
    )
    connection = sqlite3.connect(case["ledger_path"])
    try:
        row = connection.execute(
            "SELECT report_json FROM composition_reports"
        ).fetchone()
        assert row is not None
        tampered = row[0].replace(
            result.report.work_order_digest, "f" * 64
        )
        connection.execute(
            "UPDATE composition_reports SET report_json = ?",
            (tampered,),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(evidence.ChildGrantIssuanceError):
        evidence._validated_composition_reports(
            evidence.connect_ledger(case["ledger_path"]),
            case["work_order"],
        )


def test_compose_proof_transaction_commits_report_atomically(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case, context, request = _compose_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    result = acceptance.compose_proof_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        request=request,
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        clock=lambda: fixed_now,
    )
    assert result.report.verifier_conclusion == "evidence_incomplete"
    assert result.initiator_receipt.tool_name == "owp.compose_proof"
    assert result.trigger_receipt.system_event_name == "proof_composed"

    from openworkproof import evidence  # noqa: PLC0415

    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        work_order, receipts, _, _ = (
            evidence._replay_receipt_publication_ledger(connection)
        )
        state_row = connection.execute(
            "SELECT current_state, version FROM work_order_state WHERE singleton = 1"
        ).fetchone()
    finally:
        connection.close()
    assert state_row == ("evidence_incomplete", 6)
    assert len(receipts) == len(context.ledger_prefix.receipts) + 2
    assert receipts[-1].receipt_id == result.trigger_receipt.receipt_id
    assert receipts[-2].receipt_id == result.initiator_receipt.receipt_id
    loaded = evidence._validated_composition_reports(
        evidence.connect_ledger(case["ledger_path"]),
        work_order,
    )
    assert len(loaded) == 1
    assert loaded[0].model_dump(mode="json") == result.report.model_dump(mode="json")


def test_compose_pre_commit_failure_leaves_no_protocol_write(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    import sqlite3  # noqa: PLC0415

    case, context, request = _compose_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    from openworkproof import evidence  # noqa: PLC0415

    real_insert = acceptance._insert_compose_rows

    def explode_insert(*args, **kwargs):
        raise acceptance.AcceptanceTransactionError(
            "injected pre-commit failure"
        )

    monkeypatch.setattr(acceptance, "_insert_compose_rows", explode_insert)
    with pytest.raises(acceptance.AcceptanceTransactionError):
        acceptance.compose_proof_transaction(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=context,
            request=request,
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            clock=lambda: fixed_now,
        )
    monkeypatch.undo()

    connection = sqlite3.connect(case["ledger_path"])
    try:
        receipts = connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
        reports = connection.execute(
            "SELECT COUNT(*) FROM composition_reports"
        ).fetchone()[0]
        state = connection.execute(
            "SELECT current_state, version FROM work_order_state WHERE singleton = 1"
        ).fetchone()
    finally:
        connection.close()
    assert receipts == len(context.ledger_prefix.receipts)
    assert reports == 0
    assert state == ("locally_verified", 5)


def test_compose_requires_manager_and_current_context(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case, context, request = _compose_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    # A stale context (clock before the signed snapshot) must fail closed.
    import dataclasses  # noqa: PLC0415
    from datetime import datetime, timezone  # noqa: PLC0415

    stale = dataclasses.replace(
        context,
        transaction_time=datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
    )
    with pytest.raises(acceptance.AcceptanceTransactionError):
        acceptance.compose_proof_transaction(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=stale,
            request=request,
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            clock=lambda: fixed_now,
        )
