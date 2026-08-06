"""Command-line transport for OpenWorkProof.

The CLI is a thin transport: it parses JSON protocol messages and forwards
them to the coordinator handlers. It does not author policy, sign requests,
or fabricate authority — those live in the protocol layer.

Commands:

- ``owp status <ledger>``        — replay the ledger and print its state
- ``owp run-tests <ledger> <payload.json>``  — forward a run-tests execution
- ``owp repo-read <ledger> <payload.json>``  — forward a repo-read execution

Payload files carry the signed AgentRequest plus the typed arguments, the
execution facts, and the replay checkpoint; see the transport tests for the
exact JSON shape.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from openworkproof import evidence


class CliError(Exception):
    """A transport-level CLI failure with a stable message."""


def cli_status(ledger_path: str | Path) -> dict[str, object]:
    """Replay one ledger and return its authoritative state as JSON data."""
    path = Path(ledger_path)
    if not path.is_file():
        raise CliError(f"ledger does not exist: {path}")
    connection = evidence.connect_ledger(path)
    try:
        work_order, receipts, _, _ = (
            evidence._replay_receipt_publication_ledger(connection)
        )
        state_row = connection.execute(
            "SELECT current_state, version FROM work_order_state "
            "WHERE singleton = 1"
        ).fetchone()
    finally:
        connection.close()
    if state_row is None:
        raise CliError("ledger has no authoritative state row")
    return {
        "schema_version": "openworkproof/cli-status/0.1",
        "work_order_digest": work_order.digest,
        "current_state": state_row[0],
        "version": state_row[1],
        "receipt_count": len(receipts),
    }


def _load_payload(path: str | Path) -> dict[str, object]:
    payload_path = Path(path)
    if not payload_path.is_file():
        raise CliError(f"payload does not exist: {payload_path}")
    try:
        raw = json.loads(payload_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise CliError(f"payload is not valid JSON: {path}") from error
    if type(raw) is not dict:
        raise CliError("payload must be a JSON object")
    return raw


def cli_run_tests(ledger_path: str | Path, payload: dict[str, object]) -> dict:
    """Forward one run-tests execution from a payload dict."""
    from openworkproof import mcp_server

    try:
        receipt = mcp_server._run_tests_from_payload(
            ledger_path, payload
        )
    except KeyError as error:
        raise CliError(f"payload is missing a required field: {error}") from error
    return {
        "schema_version": "openworkproof/cli-result/0.1",
        "receipt_id": receipt.receipt_id,
        "tool_name": receipt.tool_name,
        "execution_status": receipt.execution_status,
        "state_after": receipt.state_after,
        "output_digest": receipt.output_digest,
    }


def cli_repo_read(ledger_path: str | Path, payload: dict[str, object]) -> dict:
    """Forward one repo-read execution from a payload dict."""
    from openworkproof import mcp_server

    try:
        receipt = mcp_server._repo_read_from_payload(
            ledger_path, payload
        )
    except KeyError as error:
        raise CliError(f"payload is missing a required field: {error}") from error
    return {
        "schema_version": "openworkproof/cli-result/0.1",
        "receipt_id": receipt.receipt_id,
        "tool_name": receipt.tool_name,
        "execution_status": receipt.execution_status,
        "state_after": receipt.state_after,
        "output_digest": receipt.output_digest,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="owp")
    parser.add_argument(
        "--output", choices=("json", "text"), default="json",
        help="output format (default: json)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    status = sub.add_parser("status", help="replay a ledger and print its state")
    status.add_argument("ledger", help="path to the SQLite ledger file")

    run_tests = sub.add_parser(
        "run-tests", help="forward one run-tests execution payload"
    )
    run_tests.add_argument("ledger", help="path to the SQLite ledger file")
    run_tests.add_argument("payload", help="path to the run-tests payload JSON")

    repo_read = sub.add_parser(
        "repo-read", help="forward one repo-read execution payload"
    )
    repo_read.add_argument("ledger", help="path to the SQLite ledger file")
    repo_read.add_argument("payload", help="path to the repo-read payload JSON")
    return parser


def app(argv: Sequence[str] | None = None) -> int:
    """Console entry point (``owp``)."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "status":
            result: dict[str, object] = cli_status(args.ledger)
        elif args.command == "run-tests":
            result = cli_run_tests(args.ledger, _load_payload(args.payload))
        elif args.command == "repo-read":
            result = cli_repo_read(args.ledger, _load_payload(args.payload))
        else:
            parser.error(f"unknown command: {args.command}")
            return 2
    except CliError as error:
        print(json.dumps({"error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 1
    if args.output == "text" and args.command == "status":
        print(f"state={result['current_state']} version={result['version']} "
              f"receipts={result['receipt_count']}")
    else:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(app())
