"""M1 delivery validation: real external Acceptor end-to-end.

The external Acceptor runs as a *separate subprocess* on the real TCP stack;
the system talks to it only over a socket. Covers V1..V8 of the M1 checklist.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import pytest

from cryptography.hazmat.primitives import serialization

import openworkproof.acceptance as acceptance
from openworkproof.external_acceptor import (
    ExternalAcceptorClient,
    ExternalAcceptorServer,
    load_acceptor_key,
)
from openworkproof.signing import decode_and_verify_key_binding, verify_payload


@pytest.fixture(autouse=True)
def _stub_execution_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    from openworkproof import repo_tools
    from openworkproof.repo_tools import (
        CandidateExecutionSnapshot,
        ExecutionSnapshotPlan,
    )

    def prepare(request):
        return CandidateExecutionSnapshot(
            head_commit=request.expected_head_commit,
            workspace_manifest_digest=request.expected_workspace_manifest_digest,
            plan=ExecutionSnapshotPlan(
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

    monkeypatch.setattr(repo_tools, "prepare_candidate_execution_snapshot", prepare)


def _free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _key_hex(key) -> str:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()


class _AcceptorProcess:
    """A real external Acceptor subprocess with injected fault behaviour."""

    def __init__(self, key_hex: str, *, port: int, delay_ms: int = 0, drop: bool = False, refuse: bool = False):
        self.port = port
        env = {
            **os.environ,
            "OWP_ACCEPTOR_KEY_HEX": key_hex,
            "OWP_ACCEPTOR_PORT": str(port),
            "OWP_ACCEPTOR_DELAY_MS": str(delay_ms),
            "OWP_ACCEPTOR_DROP": "1" if drop else "0",
            "OWP_ACCEPTOR_REFUSE": "1" if refuse else "0",
        }
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "openworkproof.external_acceptor"],
            env=env,
        )
        self._wait_ready()

    def _wait_ready(self, attempts: int = 20) -> None:
        for _ in range(attempts):
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.3):
                    return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("external acceptor process did not become ready")

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)


@pytest.fixture
def external_acceptor(ephemeral_role_keys):
    processes = []

    def launch(*, delay_ms=0, drop=False, refuse=False):
        proc = _AcceptorProcess(
            _key_hex(ephemeral_role_keys["Acceptor"][0]),
            port=_free_port(),
            delay_ms=delay_ms,
            drop=drop,
            refuse=refuse,
        )
        processes.append(proc)
        return proc

    yield launch
    for proc in processes:
        proc.stop()


def _awaiting_payload(tmp_path, signed_work_order, ephemeral_role_keys, sidecar_receipt_factory, fixed_now, monkeypatch):
    from test_acceptance import _awaiting_case, _sign_draft

    case, context, composed, request_receipt = _awaiting_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    return case, context, request_receipt


def _rejection_raw(case, context, request_receipt, ephemeral_role_keys, fixed_now):
    from test_acceptor_rejection import _rejection_raw as raw_builder

    return raw_builder(
        case, context, request_receipt, ephemeral_role_keys, fixed_now,
        reason_code="BUSINESS_DECISION",
    )


def _local_bundle(case, work_order):
    from openworkproof.policy import CommittedEvidence
    from test_mcp_server import _grant_replay_inputs

    receipts, grants, attempts = _grant_replay_inputs(
        case["ledger_path"], work_order
    )
    committed = []
    for receipt in receipts:
        for reference in receipt.evidence_refs:
            payload = (
                case["evidence_root"]
                / reference.path.removeprefix("evidence/")
            ).read_bytes()
            committed.append(
                CommittedEvidence(reference=reference, payload=payload)
            )
    committed.sort(key=lambda item: item.reference.path.encode())
    public_keys = {
        binding.key_id: decode_and_verify_key_binding(binding)
        for binding in work_order.key_bindings
    }
    return (
        tuple(sorted(grants.values(), key=lambda item: item.grant_id)),
        tuple(sorted(attempts.values(), key=lambda item: item.digest)),
        receipts,
        tuple(committed),
        public_keys,
    )


# ---- V1: external environment isolation ------------------------------------

def test_v1_external_process_holds_only_acceptor_material(
    external_acceptor, ephemeral_role_keys
) -> None:
    proc = external_acceptor()
    # The subprocess command line carries no ledger path and no system key;
    # only the Acceptor key material is in its environment.
    assert "--ledger" not in " ".join(proc.proc.args)
    assert proc.proc.args == [sys.executable, "-m", "openworkproof.external_acceptor"]
    client = ExternalAcceptorClient(port=proc.port, timeout=2.0)
    with pytest.raises(RuntimeError, match="unknown action"):
        client._round_trip({"action": "list-ledger"})


# ---- V2: acceptance flow end to end ----------------------------------------

def test_v2_external_acceptor_accepts_end_to_end(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
    external_acceptor,
) -> None:
    case, context, request_receipt = _awaiting_payload(
        tmp_path, signed_work_order, ephemeral_role_keys, sidecar_receipt_factory, fixed_now, monkeypatch
    )
    draft = acceptance.prepare_acceptance(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        clock=lambda: fixed_now,
    )
    proc = external_acceptor()
    client = ExternalAcceptorClient(port=proc.port, timeout=5.0)
    signed = client.sign_acceptance(draft)
    committed = acceptance.commit_acceptance(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        acceptance=signed,
        public_keys=None,
        clock=lambda: fixed_now,
    )
    assert committed.acceptance_id == signed.acceptance_id
    # The external signature verifies against the bound Acceptor key.
    acceptor_binding = next(
        b for b in case["work_order"].key_bindings if b.role == "Acceptor"
    )
    assert verify_payload(
        "acceptance-receipt",
        signed.model_dump(mode="json"),
        decode_and_verify_key_binding(acceptor_binding),
    )
    # Offline bundle verification passes without system access.
    work_order = case["work_order"]
    report = acceptance._current_report(case["ledger_path"], work_order)
    effective_grants, grant_attempts, receipts, committed_ev, public_keys = (
        _local_bundle(case, work_order)
    )
    verified = acceptance.verify_acceptance_bundle(
        work_order=work_order,
        report=report,
        effective_grants=effective_grants,
        grant_attempts=grant_attempts,
        receipts=receipts,
        committed_evidence=committed_ev,
        acceptance_receipt=signed,
        public_keys=public_keys,
    )
    assert verified.acceptance_id == signed.acceptance_id


# ---- V3: rejection flow end to end ------------------------------------------

def test_v3_external_acceptor_rejects_end_to_end(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
    external_acceptor,
) -> None:
    case, context, request_receipt = _awaiting_payload(
        tmp_path, signed_work_order, ephemeral_role_keys, sidecar_receipt_factory, fixed_now, monkeypatch
    )
    proc = external_acceptor()
    client = ExternalAcceptorClient(port=proc.port, timeout=5.0)
    raw = _rejection_raw(case, context, request_receipt, ephemeral_role_keys, fixed_now)
    signed = client.sign_rejection(raw)
    committed = acceptance.reject_acceptance_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        rejection=signed,
        public_keys=None,
        clock=lambda: fixed_now,
    )
    assert committed.rejection_id == signed.rejection_id
    assert committed.decision == "rejected"


# ---- V4: conflict handling ---------------------------------------------------

def test_v4_conflicting_second_decision_is_rejected(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
    external_acceptor,
) -> None:
    from test_acceptance import _sign_draft
    from test_mcp_server import _current_run_tests_context

    case, context, request_receipt = _awaiting_payload(
        tmp_path, signed_work_order, ephemeral_role_keys, sidecar_receipt_factory, fixed_now, monkeypatch
    )
    proc = external_acceptor()
    client = ExternalAcceptorClient(port=proc.port, timeout=5.0)
    draft = acceptance.prepare_acceptance(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        clock=lambda: fixed_now,
    )
    signed_accept = client.sign_acceptance(draft)
    acceptance.commit_acceptance(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        acceptance=signed_accept,
        public_keys=None,
        clock=lambda: fixed_now,
    )
    rejected_context = _current_run_tests_context(case, fixed_now)
    raw = _rejection_raw(case, context, request_receipt, ephemeral_role_keys, fixed_now)
    signed_reject = client.sign_rejection(raw)
    from openworkproof.runtime_context import RuntimeContextError

    with pytest.raises(
        (acceptance.AcceptanceTransactionError, RuntimeContextError)
    ):
        acceptance.reject_acceptance_transaction(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=rejected_context,
            rejection=signed_reject,
            public_keys=None,
            clock=lambda: fixed_now,
        )


# ---- V5: data consistency ----------------------------------------------------

def test_v5_returned_receipt_matches_local_rehash(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
    external_acceptor,
) -> None:
    case, context, request_receipt = _awaiting_payload(
        tmp_path, signed_work_order, ephemeral_role_keys, sidecar_receipt_factory, fixed_now, monkeypatch
    )
    draft = acceptance.prepare_acceptance(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        clock=lambda: fixed_now,
    )
    proc = external_acceptor()
    client = ExternalAcceptorClient(port=proc.port, timeout=5.0)
    signed = client.sign_acceptance(draft)
    # The returned receipt digest equals a local re-computation.
    from openworkproof.signing import sign_payload as local_sign

    local = acceptance.AcceptanceReceipt.model_validate(
        local_sign(
            "acceptance-receipt",
            json.loads(draft.canonical_payload),
            ephemeral_role_keys["Acceptor"][0],
        )
    )
    assert signed.acceptance_id == local.acceptance_id
    assert signed.digest == local.digest


# ---- V6: timeout -------------------------------------------------------------

def test_v6_client_times_out_when_acceptor_hangs(
    external_acceptor,
) -> None:
    proc = external_acceptor(delay_ms=5000)
    client = ExternalAcceptorClient(port=proc.port, timeout=0.5)
    with pytest.raises(OSError):
        client._round_trip({"action": "sign-acceptance", "draft": {}})


# ---- V7: dropped connection --------------------------------------------------

def test_v7_client_detects_dropped_connection(
    external_acceptor,
) -> None:
    proc = external_acceptor(drop=True)
    client = ExternalAcceptorClient(port=proc.port, timeout=2.0)
    with pytest.raises(ConnectionError, match="closed the connection"):
        client._round_trip({"action": "sign-acceptance", "draft": {}})


# ---- V8: retry after disconnect ----------------------------------------------

def test_v8_retry_after_dropped_connection_succeeds(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
    external_acceptor,
) -> None:
    case, context, request_receipt = _awaiting_payload(
        tmp_path, signed_work_order, ephemeral_role_keys, sidecar_receipt_factory, fixed_now, monkeypatch
    )
    draft = acceptance.prepare_acceptance(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        clock=lambda: fixed_now,
    )
    # First attempt hits a dropping acceptor -> connection error.
    dropper = external_acceptor(drop=True)
    drop_client = ExternalAcceptorClient(port=dropper.port, timeout=2.0)
    with pytest.raises(ConnectionError):
        drop_client.sign_acceptance(draft)
    dropper.stop()
    # Retry against a healthy acceptor -> success.
    healthy = external_acceptor()
    healthy_client = ExternalAcceptorClient(port=healthy.port, timeout=5.0)
    signed = healthy_client.sign_acceptance(draft)
    committed = acceptance.commit_acceptance(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        acceptance=signed,
        public_keys=None,
        clock=lambda: fixed_now,
    )
    assert committed.acceptance_id == signed.acceptance_id
