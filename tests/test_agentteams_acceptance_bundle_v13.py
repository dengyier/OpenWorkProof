"""AgentTeams external human-acceptance gate tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import runpy

import pytest

from openworkproof.acceptance_bundle import (
    AcceptanceBundleError,
    AcceptanceBundleVerificationResult,
)


ROOT = Path(__file__).resolve().parents[1]
DEMO_SCRIPT = ROOT / "agentteams/scripts/run_openworkproof_13_demo.py"


def _module() -> dict[str, object]:
    return runpy.run_path(str(DEMO_SCRIPT), run_name="owp_acceptance_gate_test")


def _result(terminal: str) -> AcceptanceBundleVerificationResult:
    return AcceptanceBundleVerificationResult(
        schema_version="openworkproof-acceptance-bundle-result/0.1",
        terminal_decision=terminal,
        work_order_digest="1" * 64,
        surface_manifest_digest="2" * 64,
        verification_decision_digest="3" * 64,
        terminal_receipt_digest="4" * 64,
        acceptance_decision_binding_digest="5" * 64,
        boundary="not payment, settlement, legal audit, or adoption",
    )


def _install_verifier(function, result=None, error=None) -> None:
    def verify(_path):
        if error is not None:
            raise error
        return result

    function.__globals__["verify_acceptance_bundle_directory"] = verify
    function.__globals__["validate_acceptance_bundle_manifest"] = (
        lambda _path: type(
            "Manifest",
            (),
            {"model_dump": lambda self, mode: {"schema_version": "test"}},
        )()
    )


class _Matrix:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.messages = []

    def send_text(self, room_id: str, body: str) -> str:
        self.messages.append((room_id, body))
        if self.fail:
            raise RuntimeError("Matrix unavailable")
        return "$acceptance-event"


def test_demo_parser_replaces_bare_receipt_with_acceptance_bundle() -> None:
    parser = _module()["build_parser"]()
    args = parser.parse_args(
        [
            "--task-file",
            "task.json",
            "--acceptance-bundle",
            "acceptance",
        ]
    )
    assert args.acceptance_bundle == "acceptance"
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "--task-file",
                "task.json",
                "--acceptance-receipt",
                "receipt.json",
            ]
        )


@pytest.mark.parametrize("terminal", ("ACCEPTED", "REJECTED"))
def test_external_acceptance_gate_returns_verified_business_terminal(
    tmp_path: Path,
    terminal: str,
) -> None:
    module = _module()
    wait = module["wait_for_external_acceptance"]
    acceptance = tmp_path / "acceptance"
    acceptance.mkdir()
    provenance = tmp_path / "provenance.json"
    matrix = _Matrix()
    expected = _result(terminal)
    _install_verifier(wait, result=expected)

    actual = wait(
        acceptance_bundle=acceptance,
        timeout_seconds=1,
        provenance_path=provenance,
        matrix=matrix,
        room_id="!team:hs",
    )

    assert actual == expected
    assert len(matrix.messages) == 1
    recorded = json.loads(provenance.read_bytes())
    assert recorded == {
        "schema_version": "openworkproof-agentteams-acceptance-provenance/0.1",
        "bundle_digest": recorded["bundle_digest"],
        "terminal_receipt_digest": "4" * 64,
        "acceptance_decision_binding_digest": "5" * 64,
        "terminal_decision": terminal,
        "announcement_event_id_digest": hashlib.sha256(
            b"$acceptance-event"
        ).hexdigest(),
    }


def test_external_acceptance_gate_closes_invalid_bundle(
    tmp_path: Path,
) -> None:
    module = _module()
    wait = module["wait_for_external_acceptance"]
    acceptance = tmp_path / "invalid"
    acceptance.mkdir()
    _install_verifier(wait, error=AcceptanceBundleError("invalid"))
    with pytest.raises(RuntimeError, match="invalid"):
        wait(
            acceptance_bundle=acceptance,
            timeout_seconds=1,
            provenance_path=None,
            matrix=None,
            room_id=None,
        )


def test_external_acceptance_gate_rejects_manifest_change(
    tmp_path: Path,
) -> None:
    module = _module()
    wait = module["wait_for_external_acceptance"]
    acceptance = tmp_path / "changed"
    acceptance.mkdir()
    _install_verifier(wait, result=_result("ACCEPTED"))
    calls = iter(({"version": 1}, {"version": 2}))

    class Manifest:
        def model_dump(self, mode):
            return next(calls)

    wait.__globals__["validate_acceptance_bundle_manifest"] = (
        lambda _path: Manifest()
    )
    with pytest.raises(RuntimeError, match="invalid"):
        wait(
            acceptance_bundle=acceptance,
            timeout_seconds=1,
            provenance_path=None,
            matrix=None,
            room_id=None,
        )


def test_external_acceptance_gate_times_out_without_directory(
    tmp_path: Path,
) -> None:
    wait = _module()["wait_for_external_acceptance"]
    with pytest.raises(RuntimeError, match="timed out"):
        wait(
            acceptance_bundle=tmp_path / "not-yet-present",
            timeout_seconds=0,
            provenance_path=None,
            matrix=None,
            room_id=None,
        )


@pytest.mark.parametrize("timeout", (-1, float("nan"), float("inf"), True))
def test_external_acceptance_gate_rejects_invalid_timeout(
    tmp_path: Path,
    timeout,
) -> None:
    wait = _module()["wait_for_external_acceptance"]
    with pytest.raises(RuntimeError, match="timeout is invalid"):
        wait(
            acceptance_bundle=tmp_path / "not-yet-present",
            timeout_seconds=timeout,
            provenance_path=None,
            matrix=None,
            room_id=None,
        )


def test_announcement_failure_preserves_verified_provenance(
    tmp_path: Path,
) -> None:
    module = _module()
    wait = module["wait_for_external_acceptance"]
    acceptance = tmp_path / "accepted"
    acceptance.mkdir()
    provenance = tmp_path / "provenance.json"
    expected = _result("ACCEPTED")
    _install_verifier(wait, result=expected)

    with pytest.raises(RuntimeError, match="announcement") as captured:
        wait(
            acceptance_bundle=acceptance,
            timeout_seconds=1,
            provenance_path=provenance,
            matrix=_Matrix(fail=True),
            room_id="!team:hs",
        )
    assert captured.value.verified == expected
    recorded = json.loads(provenance.read_bytes())
    assert recorded["terminal_decision"] == "ACCEPTED"
    assert recorded["announcement_event_id_digest"] is None


def test_demo_source_cannot_generate_human_authority() -> None:
    source = DEMO_SCRIPT.read_text(encoding="utf-8")
    for forbidden in (
        "acceptance-receipt",
        "Ed25519PrivateKey",
        "generate_private_key",
        "private_key",
    ):
        assert forbidden not in source


def test_provenance_contains_no_paths_tokens_or_message_body(
    tmp_path: Path,
) -> None:
    module = _module()
    wait = module["wait_for_external_acceptance"]
    acceptance = tmp_path / "accepted"
    acceptance.mkdir()
    provenance = tmp_path / "provenance.json"
    _install_verifier(wait, result=_result("ACCEPTED"))
    wait(
        acceptance_bundle=acceptance,
        timeout_seconds=1,
        provenance_path=provenance,
        matrix=_Matrix(),
        room_id="!team:hs",
    )
    raw = provenance.read_text(encoding="utf-8")
    assert str(tmp_path) not in raw
    assert "token" not in raw.lower()
    assert "body" not in raw.lower()
    assert "private" not in raw.lower()
