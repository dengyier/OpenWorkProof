"""v0.4 interface contract across Python facade, CLI and read-only MCP (Task 13)."""

from __future__ import annotations

import json

import pytest

from openworkproof.services import OpenWorkProofServices
from test_binding_decision_v04 import (
    _bound_replay,
    _compose,
    _sign_decision,
    _verified_decision,
)
from test_binding_transactions_v04 import (
    _build_signed_decision,
    _seed_verification_row,
    _commit,
)


def _judgment_payload(case) -> dict:
    return case["judgment"].model_dump(mode="json")


def _manifest_payload(case) -> dict:
    return case["manifest"].model_dump(mode="json")


def _compose_payload(case) -> dict:
    verification = _verified_decision(
        work_order=case["work_order"],
        claim=case["claim"],
        scope=case["scope"],
        manifest=case["manifest"],
        keys=case["role_keys"],
    )
    replay = _bound_replay(case["judgment"], case["projection"])
    from openworkproof.binding import BindingDecisionDraftRequest

    request = BindingDecisionDraftRequest(
        decided_at="2026-01-01T00:00:10Z", nonce="a" * 64
    )
    import dataclasses

    request_payload = dataclasses.asdict(request)
    return {
        "judgment": _judgment_payload(case),
        "manifest": _manifest_payload(case),
        "verification": verification.model_dump(mode="json"),
        "receipts": [case["receipt"].model_dump(mode="json")],
        "replay": {
            "outcome": replay.outcome,
            "reason_codes": list(replay.reason_codes),
            "replay_digest": replay.replay_digest,
        },
        "request": request_payload,
    }


def _verify_payload(case, *, decision=None) -> dict:
    decision = decision or _sign_decision(case, _compose(case))
    return {
        "decision": decision.model_dump(mode="json"),
        "work_order": case["work_order"].model_dump(mode="json"),
        "public_keys": {
            key_id(
                case["role_keys"]["Verifier"][0].public_key()
            ): _public_key_b64url(
                case["role_keys"]["Verifier"][0].public_key()
            )
        },
        "expected_signatures": 1,
    }


def _public_key_b64url(public_key) -> str:
    import base64

    from cryptography.hazmat.primitives import serialization

    return (
        base64.urlsafe_b64encode(
            public_key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        )
        .decode("ascii")
        .rstrip("=")
    )


def key_id(public_key) -> str:
    from openworkproof.signing import key_id as _key_id

    return _key_id(public_key)


# ---------------------------------------------------------------------------
# Python facade
# ---------------------------------------------------------------------------


def test_facade_judgment_validate_reports_not_checked(binding_decision_case) -> None:
    result = OpenWorkProofServices().validate_judgment_commitment(
        _judgment_payload(binding_decision_case)
    )
    assert result["valid"] is True
    assert result["authority"] == "not_checked"
    assert result["digest"] == binding_decision_case["judgment"].digest


def test_facade_judgment_validate_invalid_payload() -> None:
    with pytest.raises(ValueError):
        OpenWorkProofServices().validate_judgment_commitment(
            {"schema_version": "openworkproof-judgment-commitment/0.4"}
        )


def test_facade_manifest_validate_reports_not_checked(
    binding_decision_case,
) -> None:
    result = OpenWorkProofServices().validate_action_binding_manifest(
        _manifest_payload(binding_decision_case)
    )
    assert result["valid"] is True
    assert result["authority"] == "not_checked"


def test_facade_compose_binding(binding_decision_case) -> None:
    draft = OpenWorkProofServices().compose_binding(
        _compose_payload(binding_decision_case)
    )
    assert draft["decision"] == "BOUND"
    assert draft["authority_status"] == "not_required"


def test_facade_verify_binding_ok(binding_decision_case) -> None:
    result = OpenWorkProofServices().verify_binding(
        _verify_payload(binding_decision_case)
    )
    assert result["valid"] is True


def test_facade_verify_binding_bad_signature(binding_decision_case) -> None:
    from test_binding_transactions_v04 import _tamper_decision

    case = binding_decision_case
    tampered = _tamper_decision(
        case, _sign_decision(case, _compose(case)), adapter_replay_digest="f" * 64
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    payload = _verify_payload(case, decision=tampered)
    wrong_key = Ed25519PrivateKey.generate().public_key()
    payload["public_keys"] = {
        key_id(wrong_key): _public_key_b64url(wrong_key)
    }
    result = OpenWorkProofServices().verify_binding(payload)
    assert result["valid"] is False


def test_facade_binding_history_requires_ledger(tmp_path) -> None:
    with pytest.raises(ValueError):
        OpenWorkProofServices().binding_history(
            str(tmp_path / "missing-ledger.db")
        )


def test_facade_binding_history_reads_committed_head(
    binding_decision_case,
) -> None:
    case = binding_decision_case
    verification = _verified_decision(
        work_order=case["work_order"],
        claim=case["claim"],
        scope=case["scope"],
        manifest=case["manifest"],
        keys=case["role_keys"],
    )
    _seed_verification_row(case, verification)
    decision = _build_signed_decision(case)
    _commit(case, decision)
    history = OpenWorkProofServices().binding_history(
        str(case["ledger_path"])
    )
    assert history["current"] is not None
    assert history["current"]["binding_decision_id"] == (
        decision.binding_decision_id
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_judgment_validate_parity(binding_decision_case, tmp_path) -> None:
    from openworkproof import cli

    payload_path = tmp_path / "judgment.json"
    payload_path.write_bytes(
        json.dumps(_judgment_payload(binding_decision_case)).encode("utf-8")
    )
    cli_result = cli.cli_judgment_validate(
        _judgment_payload(binding_decision_case)
    )
    assert cli_result["valid"] is True
    assert cli_result["authority"] == "not_checked"
    assert cli.app(["judgment", "validate", str(payload_path)]) == 0


def test_cli_binding_history_missing_ledger(tmp_path) -> None:
    from openworkproof import cli

    with pytest.raises(cli.CliError):
        cli.cli_binding_history(str(tmp_path / "nope.db"))


def test_cli_binding_manifest_validate_invalid_payload(tmp_path) -> None:
    from openworkproof import cli

    bad = tmp_path / "bad.json"
    bad.write_bytes(b"{}")
    assert cli.app(["binding-manifest", "validate", str(bad)]) == 1


def test_cli_binding_compose_parity(binding_decision_case, tmp_path) -> None:
    from openworkproof import cli

    payload_path = tmp_path / "compose.json"
    payload_path.write_bytes(
        json.dumps(_compose_payload(binding_decision_case)).encode("utf-8")
    )
    cli_result = cli.cli_binding_compose(
        _compose_payload(binding_decision_case)
    )
    assert cli_result["decision"] == "BOUND"
    assert cli.app(["binding", "compose", str(payload_path)]) == 0


# ---------------------------------------------------------------------------
# Read-only MCP
# ---------------------------------------------------------------------------


def test_mcp_registers_binding_tools() -> None:
    from openworkproof import mcp_transport

    tools = mcp_transport.mcp._tool_manager._tools
    for name in (
        "owp_validate_judgment_commitment",
        "owp_validate_action_binding_manifest",
        "owp_get_binding_status",
        "owp_explain_binding_decision",
    ):
        assert name in tools


def test_mcp_judgment_validate_parity(binding_decision_case) -> None:
    from openworkproof import mcp_transport

    result = mcp_transport.owp_validate_judgment_commitment(
        json.dumps(_judgment_payload(binding_decision_case))
    )
    assert result["ok"] is True
    assert result["authority"] == "not_checked"


def test_mcp_judgment_validate_rejects_private_key(binding_decision_case) -> None:
    from openworkproof import mcp_transport

    payload = _judgment_payload(binding_decision_case)
    payload["acceptor_private_key"] = "deadbeef"
    result = mcp_transport.owp_validate_judgment_commitment(
        json.dumps(payload)
    )
    assert result["ok"] is False
    assert "private key" in result["error"]


def test_mcp_get_binding_status_missing_ledger(tmp_path) -> None:
    from openworkproof import mcp_transport

    result = mcp_transport.owp_get_binding_status(
        str(tmp_path / "missing.db")
    )
    assert result["ok"] is False


def test_mcp_explain_binding_decision_parity(binding_decision_case) -> None:
    from openworkproof import mcp_transport

    case = binding_decision_case
    decision = _sign_decision(case, _compose(case))
    result = mcp_transport.owp_explain_binding_decision(
        json.dumps(_verify_payload(case, decision=decision))
    )
    assert result["ok"] is True
    assert result["valid"] is True
    assert result["decision"] == "BOUND"


def test_mcp_explain_rejects_private_key(binding_decision_case) -> None:
    from openworkproof import mcp_transport

    payload = _verify_payload(binding_decision_case)
    payload["verifier_private_key_hex"] = "00" * 32
    result = mcp_transport.owp_explain_binding_decision(
        json.dumps(payload)
    )
    assert result["ok"] is False
    assert "private key" in result["error"]


# ---------------------------------------------------------------------------
# deterministic ordering and JSON shape parity
# ---------------------------------------------------------------------------


def test_facade_cli_mcp_report_equivalent_json(
    binding_decision_case, tmp_path
) -> None:
    from openworkproof import cli, mcp_transport

    payload = _judgment_payload(binding_decision_case)
    facade = OpenWorkProofServices().validate_judgment_commitment(payload)
    cli_result = cli.cli_judgment_validate(payload)
    mcp_result = mcp_transport.owp_validate_judgment_commitment(
        json.dumps(payload)
    )
    assert cli_result == facade
    assert mcp_result["ok"] is True
    assert mcp_result["authority"] == facade["authority"]
    assert mcp_result["digest"] == facade["digest"]
