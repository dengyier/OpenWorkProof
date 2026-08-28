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
- ``owp surface-build``          — build a signed-evidence surface bundle
- ``owp surface-verify``         — replay a surface with closed exit codes
- ``owp acceptance-bundle-build`` — export an offline human acceptance proof
- ``owp acceptance-bundle-verify`` — replay acceptance with closed exit codes
- ``owp audit-replay|audit-explain|audit-compare`` — inspect packages offline
- ``owp settlement-status``      — derive readiness without claiming payment
- ``owp scope-build|scope-validate|scope-commit|scope-compare`` — v0.3 scope

Payload files carry the signed AgentRequest plus the typed arguments, the
execution facts, and the replay checkpoint; see the transport tests for the
exact JSON shape.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
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
    from openworkproof.delivery_package import (
        LegacyPackageError,
        explain_integrity_package,
    )

    try:
        explanation = explain_integrity_package(Path(package))
    except LegacyPackageError as error:
        # Only the explicitly supported legacy case may use the controlled
        # fallback; any other v0.5 derived-view failure is operational.
        explanation = {
            "current_decision": result["current_decision"],
            "effective_acceptance": result["effective_acceptance"],
            "settlement_readiness": result["settlement_readiness"],
            "boundary": "readiness is not payment or completed settlement",
            "fallback": "legacy",
        }
    except Exception as error:
        raise CliError(f"explain derived view failed: {error}") from error
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
    from openworkproof.delivery_package import (
        LegacyPackageError,
        compare_integrity_packages,
    )

    try:
        comparison = compare_integrity_packages(
            Path(old_package), Path(new_package)
        )
    except LegacyPackageError as error:
        # Only the explicitly supported legacy case may use the controlled
        # fallback; any other v0.5 derived-view failure is operational. The
        # fallback reports a replay-dict field diff (not a v0.5 derived
        # view) and is explicitly tagged.
        changed = tuple(
            key
            for key in sorted(set(old) | set(new))
            if old.get(key) != new.get(key)
        )
        comparison = {
            "changed_fields": list(changed),
            "fallback": "legacy",
        }
    except Exception as error:
        raise CliError(f"compare derived view failed: {error}") from error
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


def cli_surface_build(
    delivery_package: str | Path,
    fingerprints: Sequence[str | Path],
    output_path: str | Path,
) -> dict:
    return _service_result(
        OpenWorkProofServices().build_surface,
        Path(delivery_package),
        tuple(Path(path) for path in fingerprints),
        Path(output_path),
    )


def cli_surface_verify(package: str | Path) -> dict:
    return _service_result(
        OpenWorkProofServices().verify_surface,
        Path(package),
    )


def cli_acceptance_bundle_build(
    ledger: str | Path,
    surface: str | Path,
    evidence_root: str | Path,
    output: str | Path,
) -> dict:
    return _service_result(
        OpenWorkProofServices().build_acceptance_bundle,
        Path(ledger),
        Path(evidence_root),
        Path(surface),
        Path(output),
    )


def cli_acceptance_bundle_verify(package: str | Path) -> dict:
    return _service_result(
        OpenWorkProofServices().verify_acceptance_bundle,
        Path(package),
    )


def _delivery_case_result(callable_, *args) -> dict:
    try:
        return callable_(*args).model_dump(mode="json")
    except CliError:
        raise
    except Exception as error:
        raise CliError(str(error)) from error


def cli_delivery_case_init(case_directory: str | Path) -> dict:
    from openworkproof.delivery_case import initialize_delivery_case

    return _delivery_case_result(
        initialize_delivery_case, Path(case_directory)
    )


def cli_delivery_case_inspect(case_directory: str | Path) -> dict:
    from openworkproof.delivery_case import inspect_delivery_case

    return _delivery_case_result(
        inspect_delivery_case, Path(case_directory)
    )


def cli_delivery_case_verify(case_directory: str | Path) -> dict:
    from openworkproof.delivery_case import verify_exported_delivery_case

    return _delivery_case_result(
        verify_exported_delivery_case, Path(case_directory)
    )


def cli_delivery_case_export(
    case_directory: str | Path,
    output_directory: str | Path,
) -> dict:
    from openworkproof.delivery_case import export_delivery_case

    return _delivery_case_result(
        export_delivery_case, Path(case_directory), Path(output_directory)
    )


def cli_dsh_case_inspect(case_directory: str | Path) -> dict[str, object]:
    from openworkproof.dsh_case import load_dsh_case

    manifest = load_dsh_case(Path(case_directory))
    return {
        **manifest.model_dump(mode="json"),
        "boundary": (
            "case inspection is not execution, independent verification, "
            "human acceptance, payment, or customer adoption"
        ),
    }


def cli_dsh_case_verify(case_directory: str | Path) -> dict[str, object]:
    from openworkproof.dsh_case import load_dsh_case

    manifest = load_dsh_case(Path(case_directory))
    connection = evidence.connect_ledger(Path(manifest.ledger_path))
    try:
        work_order, receipts, _, _ = (
            evidence._replay_receipt_publication_ledger(connection)
        )
    finally:
        connection.close()
    if work_order.digest != manifest.work_order_digest:
        raise CliError("DSH case WorkOrder binding is invalid")
    return {
        "schema_version": "openworkproof-dsh-case-verification/0.1",
        "case_id": manifest.case_id,
        "status": "VERIFIED",
        "receipt_count": len(receipts),
        "boundary": "case integrity verified; execution and acceptance are separate",
    }


def cli_dsh_acceptance_draft(
    case_directory: str | Path,
    output: str | Path,
    verification_digest: str,
) -> dict[str, object]:
    import os

    from openworkproof.dsh_case import DecisionTokenStore, load_dsh_case
    from openworkproof.dsh_handlers import build_dsh_case_handlers
    from openworkproof.dsh_protocol import DshAcceptanceDraftPayloadV01

    manifest = load_dsh_case(Path(case_directory))
    destination = Path(output)
    if destination.exists() or destination.is_symlink():
        raise CliError("acceptance draft output already exists")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    handlers = build_dsh_case_handlers(
        manifest,
        DecisionTokenStore(clock=lambda: now),
        clock=lambda: now,
    )
    digest = handlers.acceptance_draft(
        DshAcceptanceDraftPayloadV01(
            case_id=manifest.case_id,
            verification_digest=verification_digest,
        )
    )
    source = (
        Path(manifest.evidence_root)
        / "dsh-acceptance-drafts"
        / f"{digest}.json"
    )
    payload = source.read_bytes()
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise CliError("acceptance draft write failed")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {
        "schema_version": "openworkproof-dsh-acceptance-draft-result/0.1",
        "case_id": manifest.case_id,
        "acceptance_draft_digest": digest,
        "output": str(destination),
        "signed": False,
        "boundary": "draft only; no Acceptor private key or acceptance claim",
    }


def cli_dsh_case_export(
    case_directory: str | Path,
    output_directory: str | Path,
    verification_digest: str,
    acceptance_draft_digest: str,
) -> dict[str, object]:
    from openworkproof.dsh_case import load_dsh_case
    from openworkproof.dsh_delivery import build_dsh_delivery

    manifest = load_dsh_case(Path(case_directory))
    digest = build_dsh_delivery(
        case_id=manifest.case_id,
        ledger_path=Path(manifest.ledger_path),
        evidence_root=Path(manifest.evidence_root),
        destination=Path(output_directory),
        verification_digest=verification_digest,
        acceptance_draft_digest=acceptance_draft_digest,
    )
    return {
        "schema_version": "openworkproof-dsh-export-result/0.1",
        "case_id": manifest.case_id,
        "manifest_digest": digest,
        "output_directory": str(output_directory),
        "boundary": "offline package; payment and adoption are separate",
    }


def cli_dsh_delivery_verify(package: str | Path) -> dict[str, object]:
    from openworkproof.dsh_delivery import audit_dsh_delivery

    return audit_dsh_delivery(Path(package))


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

    surface_build = sub.add_parser(
        "surface-build", help="build an offline-verifiable surface bundle"
    )
    surface_build.add_argument("delivery", help="v0.5 delivery package directory")
    surface_build.add_argument(
        "--fingerprint",
        dest="fingerprints",
        action="append",
        required=True,
        help="signed environment fingerprint JSON (repeat at most twice)",
    )
    surface_build.add_argument(
        "--output", dest="output_path", required=True, help="new surface directory"
    )

    surface_verify = sub.add_parser(
        "surface-verify", help="verify and replay one surface bundle offline"
    )
    surface_verify.add_argument("surface", help="surface bundle directory")

    acceptance_build = sub.add_parser(
        "acceptance-bundle-build",
        help="export an offline-verifiable human acceptance bundle",
    )
    acceptance_build.add_argument("ledger", help="path to the SQLite ledger")
    acceptance_build.add_argument("surface", help="verified surface directory")
    acceptance_build.add_argument(
        "--evidence-root",
        required=True,
        help="root containing committed evidence bytes",
    )
    acceptance_build.add_argument(
        "--output",
        dest="output_path",
        required=True,
        help="new acceptance bundle directory",
    )

    acceptance_verify = sub.add_parser(
        "acceptance-bundle-verify",
        help="verify and replay one acceptance bundle offline",
    )
    acceptance_verify.add_argument(
        "acceptance_bundle",
        help="acceptance bundle directory",
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
        ("dsh-delivery-verify", "offline verify one composed DSH delivery"),
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

    delivery_case = sub.add_parser(
        "delivery-case", help="verified delivery case operations"
    )
    delivery_case_sub = delivery_case.add_subparsers(
        dest="delivery_case_action", required=True
    )
    for action in ("init", "inspect", "verify"):
        command = delivery_case_sub.add_parser(action)
        command.add_argument("case_directory")
    export = delivery_case_sub.add_parser("export")
    export.add_argument("case_directory")
    export.add_argument("--output-directory", required=True)

    dsh_bridge = sub.add_parser(
        "dsh-bridge", help="run the DeepSeek Harness JSONL bridge"
    )
    dsh_bridge.add_argument("--stdio", action="store_true", required=True)

    dsh_case = sub.add_parser(
        "dsh-case", help="inspect or export one frozen DSH case"
    )
    dsh_case_sub = dsh_case.add_subparsers(
        dest="dsh_case_action", required=True
    )
    for action in ("inspect", "verify"):
        command = dsh_case_sub.add_parser(action)
        command.add_argument("case_directory")
    acceptance_draft = dsh_case_sub.add_parser("acceptance-draft")
    acceptance_draft.add_argument("case_directory")
    acceptance_draft.add_argument("--verification-digest", required=True)
    acceptance_draft.add_argument("--output", required=True)
    dsh_export = dsh_case_sub.add_parser("export")
    dsh_export.add_argument("case_directory")
    dsh_export.add_argument("--verification-digest", required=True)
    dsh_export.add_argument("--acceptance-draft-digest", required=True)
    dsh_export.add_argument("--output-directory", required=True)
    return parser


def app(argv: Sequence[str] | None = None) -> int:
    """Console entry point (``owp``)."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "dsh-bridge":
            from openworkproof.dsh_bridge import run_stdio_bridge

            return run_stdio_bridge(
                sys.stdin,
                sys.stdout,
                sys.stderr,
                clock=lambda: datetime.now(timezone.utc).replace(microsecond=0),
            )
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
        elif args.command == "surface-build":
            result = cli_surface_build(
                args.delivery,
                args.fingerprints,
                args.output_path,
            )
        elif args.command == "surface-verify":
            result = cli_surface_verify(args.surface)
        elif args.command == "acceptance-bundle-build":
            result = cli_acceptance_bundle_build(
                args.ledger,
                args.surface,
                args.evidence_root,
                args.output_path,
            )
        elif args.command == "acceptance-bundle-verify":
            result = cli_acceptance_bundle_verify(args.acceptance_bundle)
        elif args.command == "audit-replay":
            result = cli_audit_replay(args.package)
        elif args.command == "audit-explain":
            result = cli_audit_explain(args.package)
        elif args.command == "dsh-delivery-verify":
            result = cli_dsh_delivery_verify(args.package)
        elif args.command == "audit-compare":
            result = cli_audit_compare(args.old_package, args.new_package)
        elif args.command == "settlement-status":
            result = cli_settlement_status(args.ledger)
        elif args.command == "delivery-case":
            if args.delivery_case_action == "init":
                result = cli_delivery_case_init(args.case_directory)
            elif args.delivery_case_action == "inspect":
                result = cli_delivery_case_inspect(args.case_directory)
            elif args.delivery_case_action == "verify":
                result = cli_delivery_case_verify(args.case_directory)
            else:
                result = cli_delivery_case_export(
                    args.case_directory, args.output_directory
                )
        elif args.command == "dsh-case":
            if args.dsh_case_action == "inspect":
                result = cli_dsh_case_inspect(args.case_directory)
            elif args.dsh_case_action == "verify":
                result = cli_dsh_case_verify(args.case_directory)
            elif args.dsh_case_action == "acceptance-draft":
                result = cli_dsh_acceptance_draft(
                    args.case_directory,
                    args.output,
                    args.verification_digest,
                )
            else:
                result = cli_dsh_case_export(
                    args.case_directory,
                    args.output_directory,
                    args.verification_digest,
                    args.acceptance_draft_digest,
                )
        else:
            parser.error(f"unknown command: {args.command}")
            return 2
    except CliError as error:
        if args.command == "delivery-case":
            print(
                json.dumps(
                    {
                        "schema_version": (
                            "openworkproof-delivery-case-result/0.1"
                        ),
                        "case_stage": None,
                        "reason_codes": ["OPERATIONAL_ERROR"],
                        "boundary": (
                            "not payment, completed settlement, legal audit, "
                            "or customer adoption"
                        ),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                )
            )
            print(
                json.dumps({"error": str(error)}, ensure_ascii=False),
                file=sys.stderr,
            )
            return 4
        if args.command in {
            "surface-build",
            "surface-verify",
            "acceptance-bundle-build",
            "acceptance-bundle-verify",
        }:
            if args.command.startswith("acceptance-bundle"):
                print(
                    json.dumps(
                        {
                            "schema_version": (
                                "openworkproof-acceptance-bundle-result/0.1"
                            ),
                            "terminal_decision": None,
                            "work_order_digest": None,
                            "surface_manifest_digest": None,
                            "verification_decision_digest": None,
                            "terminal_receipt_digest": None,
                            "acceptance_decision_binding_digest": None,
                            "boundary": (
                                "not payment, settlement, legal audit, or adoption"
                            ),
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                        indent=2,
                    )
                )
                print(
                    json.dumps({"error": str(error)}, ensure_ascii=False),
                    file=sys.stderr,
                )
                return 4
            print(
                json.dumps(
                    {
                        "decision_status": None,
                        "reason_codes": ["OPERATIONAL_ERROR"],
                        "bundle_digest": None,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                )
            )
            print(json.dumps({"error": str(error)}, ensure_ascii=False), file=sys.stderr)
            return 4
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
    elif args.command in {"surface-build", "surface-verify"}:
        print(
            json.dumps(
                {
                    "decision_status": result["decision_status"],
                    "reason_codes": result["reason_codes"],
                    "bundle_digest": result["bundle_digest"],
                },
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
            )
        )
    elif args.command in {
        "acceptance-bundle-build",
        "acceptance-bundle-verify",
    }:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    if args.command in {"surface-build", "surface-verify"}:
        return {"VERIFIED": 0, "REFUTED": 2, "UNKNOWN": 3}[
            str(result["decision_status"])
        ]
    if args.command in {
        "acceptance-bundle-build",
        "acceptance-bundle-verify",
    }:
        return {"ACCEPTED": 0, "REJECTED": 2}[
            str(result["terminal_decision"])
        ]
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
        "dsh-delivery-verify",
    } and "current_decision" in result:
        return decision_exit.get(str(result["current_decision"]), 3)
    if args.command == "delivery-case" and args.delivery_case_action == "verify":
        return {
            "READY_FOR_SETTLEMENT_REVIEW": 0,
            "EXTERNAL_PAYMENT_EVIDENCED": 0,
            "VERIFIED": 0,
            "REFUTED": 2,
            "REJECTED": 2,
            "UNKNOWN": 3,
            "SCOPE_DRAFTED": 3,
            "SOW_REFERENCED": 3,
            "READY_FOR_ACCEPTANCE": 3,
            "ACCEPTED": 3,
        }.get(str(result.get("case_stage")), 4)
    return 0


if __name__ == "__main__":
    raise SystemExit(app())
