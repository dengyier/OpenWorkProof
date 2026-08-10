from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

import openworkproof.services as services
from openworkproof.services import OpenWorkProofServices


class _Dumpable:
    def __init__(self, value: dict[str, object]) -> None:
        self.value = value

    def model_dump(self, *, mode: str) -> dict[str, object]:
        assert mode == "json"
        return dict(self.value)


def test_services_import_without_cli_or_mcp_modules() -> None:
    code = """
import json
import sys
import openworkproof.services
print(json.dumps({
    'cli': 'openworkproof.cli' in sys.modules,
    'mcp': 'openworkproof.mcp_server' in sys.modules,
}))
"""
    completed = subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(completed.stdout) == {"cli": False, "mcp": False}


def test_services_validate_profile_returns_closed_json_dict(
    signed_verification_profile,
) -> None:
    result = OpenWorkProofServices().validate_profile(
        signed_verification_profile.model_dump(mode="json")
    )
    assert type(result) is dict
    assert result == signed_verification_profile.model_dump(mode="json")


@pytest.mark.parametrize(
    ("method", "dependency", "args", "expected_call"),
    (
        (
            "commit_arm_result",
            "commit_verification_arm_result",
            (Path("ledger.sqlite3"), {"payload": "arm"}),
            (Path("ledger.sqlite3"), "parsed-arm"),
        ),
        (
            "prepare_decision",
            "prepare_verification_decision",
            (Path("ledger.sqlite3"), {"payload": "request"}),
            (Path("ledger.sqlite3"), "parsed-request"),
        ),
        (
            "commit_decision",
            "commit_verification_decision",
            (Path("ledger.sqlite3"), {"payload": "decision"}),
            (Path("ledger.sqlite3"), "parsed-decision"),
        ),
    ),
)
def test_services_parse_then_delegate_once(
    monkeypatch, method, dependency, args, expected_call
) -> None:
    parsed = {
        "commit_arm_result": "parsed-arm",
        "prepare_decision": "parsed-request",
        "commit_decision": "parsed-decision",
    }[method]
    model_name = {
        "commit_arm_result": "VerificationArmResult",
        "prepare_decision": "DecisionDraftRequest",
        "commit_decision": "VerificationDecision",
    }[method]
    model = getattr(services, model_name)
    monkeypatch.setattr(model, "model_validate", lambda payload: parsed)
    calls = []

    def delegate(*values):
        calls.append(values)
        return _Dumpable({"result": method})

    monkeypatch.setattr(services, dependency, delegate)
    result = getattr(OpenWorkProofServices(), method)(*args)
    assert type(result) is dict
    assert result == {"result": method}
    assert calls == [expected_call]


def test_services_build_and_audit_delivery_delegate_without_rules(
    tmp_path, monkeypatch
) -> None:
    ledger = tmp_path / "ledger.sqlite3"
    output = tmp_path / "package"
    calls = []

    def export(ledger_value, output_value, *, privacy_view):
        calls.append(("export", ledger_value, output_value, privacy_view))
        return _Dumpable({"kind": "manifest"})

    def audit(package):
        calls.append(("audit", package))
        return _Dumpable({"kind": "verification"})

    monkeypatch.setattr(services, "export_delivery_package", export)
    monkeypatch.setattr(services, "verify_delivery_package", audit)
    facade = OpenWorkProofServices()
    assert facade.build_delivery(
        ledger, output, "customer_private"
    ) == {"kind": "manifest"}
    assert facade.audit_delivery(output) == {"kind": "verification"}
    assert calls == [
        ("export", ledger, output, "customer_private"),
        ("audit", output),
    ]


def test_services_settlement_status_delegates_without_recomputing(
    tmp_path, monkeypatch
) -> None:
    ledger = tmp_path / "ledger.sqlite3"
    calls = []

    def read(path):
        calls.append(path)
        return _Dumpable({"settlement_readiness": "READY_FOR_ACCEPTANCE"})

    monkeypatch.setattr(services, "read_settlement_snapshot", read)
    result = OpenWorkProofServices().get_settlement_readiness(ledger)
    assert result == {"settlement_readiness": "READY_FOR_ACCEPTANCE"}
    assert calls == [ledger]


def test_v02_mcp_tools_are_registered() -> None:
    from openworkproof import mcp_transport

    names = set(mcp_transport.mcp._tool_manager._tools)
    assert {
        "owp_validate_profile",
        "owp_run_verification",
        "owp_get_decision",
        "owp_build_delivery_package",
        "owp_get_settlement_readiness",
    } <= names


def test_v02_mcp_validate_profile_matches_service(monkeypatch) -> None:
    from openworkproof import mcp_transport

    calls = []

    class FakeServices:
        def validate_profile(self, payload):
            calls.append(payload)
            return {"profile_id": "validated"}

    monkeypatch.setattr(mcp_transport, "OpenWorkProofServices", FakeServices)
    result = mcp_transport.owp_validate_profile('{"profile_id":"candidate"}')
    assert result == {
        "schema_version": "openworkproof/mcp/0.2",
        "ok": True,
        "profile_id": "validated",
    }
    assert calls == [{"profile_id": "candidate"}]


@pytest.mark.parametrize(
    ("operation", "method"),
    (("commit_arm", "commit_arm_result"), ("commit_decision", "commit_decision")),
)
def test_v02_mcp_verification_commit_calls_service_once(
    monkeypatch, operation, method
) -> None:
    from openworkproof import mcp_transport

    calls = []

    class FakeServices:
        def commit_arm_result(self, ledger, payload):
            calls.append(("commit_arm_result", ledger, payload))
            return {"committed": "arm"}

        def commit_decision(self, ledger, payload):
            calls.append(("commit_decision", ledger, payload))
            return {"committed": "decision"}

    monkeypatch.setattr(mcp_transport, "OpenWorkProofServices", FakeServices)
    result = mcp_transport.owp_run_verification(
        "ledger.sqlite3", '{"id":"candidate"}', operation
    )
    assert result["ok"] is True
    assert calls == [(method, Path("ledger.sqlite3"), {"id": "candidate"})]


def test_v02_mcp_commit_ack_loss_returns_committed_truth(monkeypatch) -> None:
    from openworkproof import mcp_transport
    from openworkproof.verification import VerificationCommittedError

    calls = 0

    class FakeServices:
        def commit_decision(self, ledger, payload):
            nonlocal calls
            calls += 1
            raise VerificationCommittedError(
                "ack lost",
                _Dumpable({"decision_id": "committed"}),
            )

    monkeypatch.setattr(mcp_transport, "OpenWorkProofServices", FakeServices)
    result = mcp_transport.owp_run_verification(
        "ledger.sqlite3", '{"id":"candidate"}', "commit_decision"
    )
    assert result["ok"] is True
    assert result["commit_status"] == "committed_after_ack_loss"
    assert result["decision_id"] == "committed"
    assert calls == 1


def test_v02_mcp_indeterminate_commit_blocks_retry(monkeypatch) -> None:
    from openworkproof import mcp_transport
    from openworkproof.verification import VerificationCommitIndeterminateError

    calls = 0

    class FakeServices:
        def commit_arm_result(self, ledger, payload):
            nonlocal calls
            calls += 1
            raise VerificationCommitIndeterminateError("readback unavailable")

    monkeypatch.setattr(mcp_transport, "OpenWorkProofServices", FakeServices)
    result = mcp_transport.owp_run_verification(
        "ledger.sqlite3", '{"id":"candidate"}', "commit_arm"
    )
    assert result["ok"] is False
    assert result["commit_status"] == "indeterminate"
    assert calls == 1
