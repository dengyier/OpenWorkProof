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
