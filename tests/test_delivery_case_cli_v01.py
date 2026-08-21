"""Closed parser, output and exit-code contracts for the delivery-case CLI."""

from __future__ import annotations

import json

import pytest

import openworkproof.cli as cli


def test_delivery_case_parser_exposes_four_actions() -> None:
    parser = cli.build_parser()
    for action in ("init", "inspect", "verify", "export"):
        args = parser.parse_args(["delivery-case", action, "case"] + (
            ["--output-directory", "export"] if action == "export" else []
        ))
        assert args.command == "delivery-case"
        assert args.delivery_case_action == action


@pytest.mark.parametrize(
    ("stage", "exit_code"),
    (
        ("READY_FOR_SETTLEMENT_REVIEW", 0),
        ("EXTERNAL_PAYMENT_EVIDENCED", 0),
        ("REFUTED", 2),
        ("REJECTED", 2),
        ("UNKNOWN", 3),
        ("SCOPE_DRAFTED", 3),
        ("SOW_REFERENCED", 3),
        ("READY_FOR_ACCEPTANCE", 3),
        ("ACCEPTED", 3),
    ),
)
def test_delivery_case_verify_has_closed_exit_codes(
    monkeypatch: pytest.MonkeyPatch, capsys, stage: str, exit_code: int
) -> None:
    monkeypatch.setattr(
        cli, "cli_delivery_case_verify", lambda _directory: {"case_stage": stage}
    )
    assert cli.app(["delivery-case", "verify", "case"]) == exit_code
    assert json.loads(capsys.readouterr().out)["case_stage"] == stage


def test_delivery_case_verify_operational_error_is_four(
    monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    def fail(_directory):
        raise cli.CliError("injected operational failure")

    monkeypatch.setattr(cli, "cli_delivery_case_verify", fail)
    assert cli.app(["delivery-case", "verify", "case"]) == 4
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "openworkproof-delivery-case-result/0.1"
    assert payload["case_stage"] is None
    assert payload["reason_codes"] == ["OPERATIONAL_ERROR"]
    assert (
        payload["boundary"]
        == "not payment, completed settlement, legal audit, or customer adoption"
    )


def test_delivery_case_cli_has_no_private_or_payment_parameters() -> None:
    parser = cli.build_parser()
    actions = (
        ["delivery-case", "init", "case"],
        ["delivery-case", "inspect", "case"],
        ["delivery-case", "verify", "case"],
        ["delivery-case", "export", "case", "--output-directory", "out"],
    )
    for argv in actions:
        args = parser.parse_args(argv)
        namespace = vars(args)
        for key in namespace:
            assert "private" not in key.lower()
            assert "bank" not in key.lower()
            assert "wallet" not in key.lower()
            assert "payment" not in key.lower()


def test_delivery_case_init_command_writes_a_case(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    root = tmp_path / "case"
    assert cli.app(["delivery-case", "init", str(root)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["case_id"]
    assert (root / "case.json").is_file()


def test_delivery_case_error_does_not_leak_absolute_path(
    monkeypatch: pytest.MonkeyPatch, capsys, tmp_path
) -> None:
    def fail(_directory):
        raise cli.CliError(f"failure at {tmp_path / 'secret'}")

    monkeypatch.setattr(cli, "cli_delivery_case_verify", fail)
    assert cli.app(["delivery-case", "verify", "case"]) == 4
    assert str(tmp_path) not in capsys.readouterr().out


def test_delivery_case_public_api_is_lazy_and_exact() -> None:
    import openworkproof
    from openworkproof.delivery_case import (
        DeliveryCaseError,
        DeliveryCaseManifestV01,
        DeliveryCaseResultV01,
        export_delivery_case,
        initialize_delivery_case,
        inspect_delivery_case,
        verify_exported_delivery_case,
    )

    assert openworkproof.DeliveryCaseError is DeliveryCaseError
    assert openworkproof.DeliveryCaseManifestV01 is DeliveryCaseManifestV01
    assert openworkproof.DeliveryCaseResultV01 is DeliveryCaseResultV01
    assert openworkproof.initialize_delivery_case is initialize_delivery_case
    assert openworkproof.inspect_delivery_case is inspect_delivery_case
    assert openworkproof.export_delivery_case is export_delivery_case
    assert openworkproof.verify_exported_delivery_case is verify_exported_delivery_case
