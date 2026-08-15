"""Command-line transport for OpenWorkProof.

The CLI is a thin transport: it parses JSON protocol messages and forwards
them to the coordinator handlers. It does not author policy, sign requests,
or fabricate authority — those live in the protocol layer.

Commands:

- ``owp status <ledger>``        — replay the ledger and print its state
- ``owp run-tests <ledger> <payload.json>``  — forward a run-tests execution
- ``owp repo-read <ledger> <payload.json>``  — forward a repo-read execution
- ``owp profile-validate <payload.json>`` — validate a v0.2 profile
- ``owp verify-positive|verify-negative`` — commit one signed arm result
- ``owp verify-compose``         — explicitly prepare or commit a decision
- ``owp delivery-build``         — export an offline delivery package
- ``owp audit-replay|audit-explain|audit-compare`` — inspect packages offline
- ``owp settlement-status``      — derive readiness without claiming payment
- ``owp scope-build|scope-validate|scope-commit|scope-compare`` — v0.3 scope

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
from openworkproof.services import OpenWorkProofServices
from openworkproof.verification import (
    VerificationCommittedError,
    VerificationCommitIndeterminateError,
)


_MAX_PAYLOAD_BYTES = 8 * 1024 * 1024


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
        if payload_path.stat().st_size > _MAX_PAYLOAD_BYTES:
            raise CliError("payload exceeds 8 MiB")
        raw = json.loads(payload_path.read_bytes())
    except CliError:
        raise
    except (OSError, ValueError, UnicodeDecodeError) as error:
        raise CliError(f"payload is not valid JSON: {path}") from error
    if type(raw) is not dict:
        raise CliError("payload must be a JSON object")
    return raw


def _service_result(callable_, *args) -> dict:
    try:
        return callable_(*args)
    except VerificationCommittedError as error:
        committed = error.committed
        payload = (
            committed.model_dump(mode="json")
            if hasattr(committed, "model_dump")
            else dict(committed)
        )
        return {"commit_status": "committed_after_ack_loss", **payload}
    except VerificationCommitIndeterminateError as error:
        raise CliError(f"commit outcome is indeterminate: {error}") from error
    except Exception as error:
        raise CliError(str(error)) from error


def cli_profile_validate(payload: dict[str, object]) -> dict:
    return _service_result(OpenWorkProofServices().validate_profile, payload)


def cli_scope_build(
    claim: dict[str, object],
    source_revision: str,
    rules: dict[str, object],
) -> dict:
    return _service_result(
        OpenWorkProofServices().build_scope,
        claim,
        source_revision,
        rules,
    )


def cli_scope_validate(payload: dict[str, object]) -> dict:
    return _service_result(OpenWorkProofServices().validate_scope, payload)


def cli_scope_commit(
    ledger_path: str | Path,
    payload: dict[str, object],
) -> dict:
    return _service_result(
        OpenWorkProofServices().commit_scope,
        Path(ledger_path),
        payload,
    )


def cli_scope_compare(
    manifest: dict[str, object],
    observed: dict[str, object],
) -> dict:
    return _service_result(
        OpenWorkProofServices().compare_scope,
        manifest,
        observed,
    )


def cli_verify_arm(
    ledger_path: str | Path,
    payload: dict[str, object],
    *,
    expected_kind: str,
) -> dict:
    if payload.get("arm_kind") != expected_kind:
        raise CliError(f"payload arm_kind must be {expected_kind}")
    return _service_result(
        OpenWorkProofServices().commit_arm_result,
        Path(ledger_path),
        payload,
    )


def cli_verify_compose(
    ledger_path: str | Path,
    payload: dict[str, object],
    *,
    mode: str,
) -> dict:
    service = OpenWorkProofServices()
    if mode == "prepare":
        return _service_result(service.prepare_decision, Path(ledger_path), payload)
    if mode == "commit":
        return _service_result(service.commit_decision, Path(ledger_path), payload)
    raise CliError("verify-compose mode must be prepare or commit")


def cli_delivery_build(
    ledger_path: str | Path,
    output: str | Path,
    privacy_view: str,
) -> dict:
    return _service_result(
        OpenWorkProofServices().build_delivery,
        Path(ledger_path),
        Path(output),
        privacy_view,
    )


def cli_audit_replay(package: str | Path) -> dict:
    return _service_result(OpenWorkProofServices().audit_delivery, Path(package))


def cli_audit_explain(package: str | Path) -> dict:
    result = cli_audit_replay(package)
    explanation: dict[str, object]
    try:
        from openworkproof.delivery_package import (
            DeliveryPackageError,
            explain_integrity_package,
        )

        explanation = explain_integrity_package(Path(package))
    except Exception:
        explanation = {
            "current_decision": result["current_decision"],
            "effective_acceptance": result["effective_acceptance"],
            "settlement_readiness": result["settlement_readiness"],
            "boundary": "readiness is not payment or completed settlement",
        }
    return {**result, "explanation": explanation}


def cli_integrity_observation(payload: dict[str, object]) -> dict:
    return _service_result(
        OpenWorkProofServices().validate_population_observation, payload
    )


def cli_control_observation(payload: dict[str, object]) -> dict:
    return _service_result(
        OpenWorkProofServices().validate_control_observation, payload
    )


def cli_audit_compare(old_package: str | Path, new_package: str | Path) -> dict:
    old = cli_audit_replay(old_package)
    new = cli_audit_replay(new_package)
    comparison: dict[str, object]
    try:
        from openworkproof.delivery_package import (
            DeliveryPackageError,
            compare_integrity_packages,
        )

        comparison = compare_integrity_packages(
            Path(old_package), Path(new_package)
        )
    except Exception:
        changed = tuple(
            key
            for key in sorted(set(old) | set(new))
            if old.get(key) != new.get(key)
        )
        comparison = {"changed_fields": list(changed)}
    return {
        "old": old,
        "new": new,
        "current_decision": new.get("current_decision"),
        **comparison,
    }


def cli_settlement_status(ledger_path: str | Path) -> dict:
    return _service_result(
        OpenWorkProofServices().get_settlement_readiness,
        Path(ledger_path),
    )


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


def cli_judgment_validate(payload: dict[str, object]) -> dict:
    return _service_result(
        OpenWorkProofServices().validate_judgment_commitment, payload
    )


def cli_binding_manifest_validate(payload: dict[str, object]) -> dict:
    return _service_result(
        OpenWorkProofServices().validate_action_binding_manifest, payload
    )


def cli_binding_compose(payload: dict[str, object]) -> dict:
    return _service_result(OpenWorkProofServices().compose_binding, payload)


def cli_binding_verify(payload: dict[str, object]) -> dict:
    return _service_result(OpenWorkProofServices().verify_binding, payload)


def cli_binding_history(ledger_path: str | Path) -> dict:
    return _service_result(
        OpenWorkProofServices().binding_history, str(ledger_path)
    )


def cli_package_replay(package: str | Path) -> dict:
    return _service_result(
        OpenWorkProofServices().replay_binding_package, str(package)
    )


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

    profile_validate = sub.add_parser(
        "profile-validate", help="validate a signed v0.2/v0.3/v0.5 verification profile"
    )
    profile_validate.add_argument("payload", help="path to profile JSON")

    for name, help_text in (
        ("integrity-observation", "assess one population observation set"),
        ("control-observation", "validate one control observation set"),
    ):
        command = sub.add_parser(name, help=help_text)
        command.add_argument(
            "action", choices=("validate",), help="observation action"
        )
        command.add_argument("payload", help="path to observation JSON")

    for name, help_text in (
        ("verify-positive", "commit a positive-arm verification result"),
        ("verify-negative", "commit a negative-arm verification result"),
    ):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("ledger", help="path to the SQLite ledger file")
        command.add_argument("payload", help="path to signed arm result JSON")

    verify_compose = sub.add_parser(
        "verify-compose", help="prepare or commit a versioned verification decision"
    )
    verify_compose.add_argument("ledger", help="path to the SQLite ledger file")
    verify_compose.add_argument("payload", help="path to request or decision JSON")
    verify_compose.add_argument(
        "--mode", choices=("prepare", "commit"), required=True
    )

    delivery_build = sub.add_parser(
        "delivery-build", help="export an offline-verifiable delivery package"
    )
    delivery_build.add_argument("ledger", help="path to the SQLite ledger file")
    delivery_build.add_argument("output_path", help="new delivery package directory")
    delivery_build.add_argument(
        "--privacy-view",
        choices=("public", "diagnostic", "customer_private"),
        required=True,
    )

    scope_build = sub.add_parser(
        "scope-build", help="build an unsigned v0.3 Evaluation Scope draft"
    )
    scope_build.add_argument("--claim", required=True, help="SubjectClaim JSON")
    scope_build.add_argument(
        "--source-revision", required=True, help="full source commit SHA"
    )
    scope_build.add_argument(
        "--rules", required=True, help="closed scope-build input JSON"
    )

    scope_validate = sub.add_parser(
        "scope-validate", help="intrinsically validate a v0.3 scope"
    )
    scope_validate.add_argument("scope", help="scope draft or manifest JSON")

    scope_commit = sub.add_parser(
        "scope-commit", help="commit a Manager-signed scope and claim"
    )
    scope_commit.add_argument("ledger", help="path to SQLite ledger")
    scope_commit.add_argument(
        "signed_scope", help="JSON object containing claim and scope"
    )

    scope_compare = sub.add_parser(
        "scope-compare", help="compare a signed scope with observed scope"
    )
    scope_compare.add_argument("scope", help="signed Evaluation Scope JSON")
    scope_compare.add_argument("observed_scope", help="ObservedScope JSON")

    for name, help_text in (
        ("audit-replay", "offline replay one delivery package"),
        ("audit-explain", "explain one offline replay result"),
    ):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("package", help="path to delivery package")

    audit_compare = sub.add_parser(
        "audit-compare", help="compare two offline replay results"
    )
    audit_compare.add_argument("old_package")
    audit_compare.add_argument("new_package")

    settlement_status = sub.add_parser(
        "settlement-status", help="derive settlement readiness from the ledger"
    )
    settlement_status.add_argument("ledger", help="path to the SQLite ledger file")

    judgment = sub.add_parser(
        "judgment", help="validate one signed JudgmentCommitment"
    )
    judgment_sub = judgment.add_subparsers(dest="binding_action", required=True)
    judgment_validate = judgment_sub.add_parser(
        "validate", help="validate a signed judgment commitment payload"
    )
    judgment_validate.add_argument("payload", help="path to judgment JSON")

    binding_manifest = sub.add_parser(
        "binding-manifest", help="validate one signed ActionBindingManifest"
    )
    bm_sub = binding_manifest.add_subparsers(
        dest="binding_action", required=True
    )
    bm_validate = bm_sub.add_parser(
        "validate", help="validate a signed action binding manifest payload"
    )
    bm_validate.add_argument("payload", help="path to manifest JSON")

    binding = sub.add_parser(
        "binding", help="compose, verify or inspect binding decisions"
    )
    binding_sub = binding.add_subparsers(dest="binding_action", required=True)
    binding_compose = binding_sub.add_parser(
        "compose", help="compose a BindingDecision draft from signed inputs"
    )
    binding_compose.add_argument("payload", help="path to compose inputs JSON")
    binding_verify = binding_sub.add_parser(
        "verify", help="verify a signed BindingDecision against a trust map"
    )
    binding_verify.add_argument("payload", help="path to verify inputs JSON")
    binding_history = binding_sub.add_parser(
        "history", help="read the current binding decision head (read-only)"
    )
    binding_history.add_argument("ledger", help="path to SQLite ledger")

    package = sub.add_parser(
        "package", help="offline delivery package operations"
    )
    package_sub = package.add_subparsers(dest="binding_action", required=True)
    package_replay = package_sub.add_parser(
        "replay", help="offline replay one delivery package"
    )
    package_replay.add_argument("package", help="path to delivery package")
    package_replay.add_argument(
        "--binding", action="store_true", help="binding replay view"
    )
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
        elif args.command == "profile-validate":
            result = cli_profile_validate(_load_payload(args.payload))
        elif args.command == "integrity-observation":
            result = cli_integrity_observation(_load_payload(args.payload))
        elif args.command == "control-observation":
            result = cli_control_observation(_load_payload(args.payload))
        elif args.command == "scope-build":
            result = cli_scope_build(
                _load_payload(args.claim),
                args.source_revision,
                _load_payload(args.rules),
            )
        elif args.command == "scope-validate":
            result = cli_scope_validate(_load_payload(args.scope))
        elif args.command == "scope-commit":
            result = cli_scope_commit(
                args.ledger, _load_payload(args.signed_scope)
            )
        elif args.command == "scope-compare":
            result = cli_scope_compare(
                _load_payload(args.scope),
                _load_payload(args.observed_scope),
            )
        elif args.command == "verify-positive":
            result = cli_verify_arm(
                args.ledger,
                _load_payload(args.payload),
                expected_kind="positive",
            )
        elif args.command == "verify-negative":
            result = cli_verify_arm(
                args.ledger,
                _load_payload(args.payload),
                expected_kind="negative",
            )
        elif args.command == "verify-compose":
            result = cli_verify_compose(
                args.ledger,
                _load_payload(args.payload),
                mode=args.mode,
            )
        elif args.command == "judgment":
            result = cli_judgment_validate(_load_payload(args.payload))
        elif args.command == "binding-manifest":
            result = cli_binding_manifest_validate(
                _load_payload(args.payload)
            )
        elif args.command == "binding":
            if args.binding_action == "compose":
                result = cli_binding_compose(_load_payload(args.payload))
            elif args.binding_action == "verify":
                result = cli_binding_verify(_load_payload(args.payload))
            else:
                result = cli_binding_history(args.ledger)
        elif args.command == "package":
            result = cli_package_replay(args.package)
        elif args.command == "delivery-build":
            result = cli_delivery_build(
                args.ledger,
                args.output_path,
                args.privacy_view,
            )
        elif args.command == "audit-replay":
            result = cli_audit_replay(args.package)
        elif args.command == "audit-explain":
            result = cli_audit_explain(args.package)
        elif args.command == "audit-compare":
            result = cli_audit_compare(args.old_package, args.new_package)
        elif args.command == "settlement-status":
            result = cli_settlement_status(args.ledger)
        else:
            parser.error(f"unknown command: {args.command}")
            return 2
    except CliError as error:
        print(json.dumps({"error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 1
    if args.output == "text" and args.command == "status":
        print(
            f"state={result['current_state']} version={result['version']} "
            f"receipts={result['receipt_count']}"
        )
    elif args.output == "text" and args.command == "scope-compare":
        print(
            f"scope_status={result['scope_status']} reasons="
            f"{','.join(result['reason_codes']) or '-'}"
        )
    elif args.output == "text" and args.command == "scope-validate":
        print(
            f"valid={str(result['valid']).lower()} "
            f"authority={result['authority']} member_count={result['member_count']}"
        )
    else:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    if args.command == "scope-compare":
        return {
            "satisfied": 0,
            "indeterminate": 3,
            "contradicted": 4,
        }[result["scope_status"]]
    if args.command == "control-observation" and "control_status" in result:
        return {
            "proven": 0,
            "survived": 4,
            "mismatched": 3,
            "unavailable": 3,
        }[result["control_status"]]
    if args.command == "integrity-observation" and "population_status" in result:
        return 0 if result["population_status"] == "matched" else 3
    decision_exit = {
        "VERIFIED": 0,
        "UNKNOWN": 3,
        "REFUTED": 4,
        "UNAUTHENTICATED": 3,
    }
    if args.command == "verify-compose" and "decision" in result:
        return decision_exit.get(str(result["decision"]), 3)
    if args.command in {
        "audit-replay",
        "audit-explain",
        "audit-compare",
    } and "current_decision" in result:
        return decision_exit.get(str(result["current_decision"]), 3)
    return 0


if __name__ == "__main__":
    raise SystemExit(app())
