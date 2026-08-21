#!/usr/bin/env python3
"""Run the bounded OpenWorkProof 1.3 AgentTeams demonstration."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import time
from typing import Any

import rfc8785

from openworkproof.acceptance_bundle import (
    AcceptanceBundleError,
    AcceptanceBundleVerificationResult,
    validate_acceptance_bundle_manifest,
    verify_acceptance_bundle_directory,
)
from openworkproof.agentteams_controller_client import (
    AgentTeamsControllerClient,
)
from openworkproof.agentteams_matrix_client import AgentTeamsMatrixClient
from openworkproof.agentteams_workflow import AgentTeamsRoleBinding


_DIGEST64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_TASK_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class LivePreflightResult:
    roles: tuple[str, ...]
    matrix_user_ids: tuple[str, ...]
    openworkproof_key_ids: tuple[str, ...]
    room_id: str | None


class AcceptanceAnnouncementError(RuntimeError):
    """An external announcement failed after acceptance was verified."""

    def __init__(
        self,
        message: str,
        *,
        verified: AcceptanceBundleVerificationResult,
    ) -> None:
        super().__init__(message)
        self.verified = verified


def _load_task(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file():
            raise ValueError
        payload = path.read_bytes()
        if not payload or len(payload) > _MAX_TASK_BYTES:
            raise ValueError
        value = json.loads(
            payload,
            object_pairs_hook=_closed_json_object,
        )
    except (OSError, UnicodeError, ValueError, RecursionError) as error:
        raise RuntimeError("demo task file is invalid") from error
    required = {
        "schema_version",
        "task_id",
        "issue_url",
        "objective",
        "manager_resource",
        "developer_resource",
        "verifier_resource",
        "role_bindings",
    }
    if type(value) is not dict or set(value) != required:
        raise RuntimeError("demo task fields are not closed")
    if (
        value["schema_version"]
        != "openworkproof-agentteams-demo-task/0.1"
        or type(value["task_id"]) is not str
        or _DIGEST64.fullmatch(value["task_id"]) is None
        or type(value["role_bindings"]) is not list
        or len(value["role_bindings"]) != 3
    ):
        raise RuntimeError("demo task contract is invalid")
    return value


def _closed_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _resource_by_name(
    resources: list[dict[str, Any]], name: str
) -> dict[str, Any]:
    matches = [item for item in resources if item.get("name") == name]
    if len(matches) != 1:
        raise RuntimeError(f"AgentTeams resource is unavailable: {name}")
    return matches[0]


def run_live_preflight(
    *,
    task_path: Path,
    room: str | None = None,
    controller: AgentTeamsControllerClient | None = None,
    matrix: AgentTeamsMatrixClient | None = None,
) -> LivePreflightResult:
    """Fail closed unless all three live roles and identities are distinct."""

    token = os.environ.get("AGENTTEAMS_MATRIX_TOKEN")
    if not token:
        raise RuntimeError("AGENTTEAMS_MATRIX_TOKEN is required")
    task = _load_task(Path(task_path))
    try:
        bindings = tuple(
            AgentTeamsRoleBinding.model_validate(item)
            for item in task["role_bindings"]
        )
    except Exception as error:
        raise RuntimeError("AgentTeams role bindings are invalid") from error
    roles = tuple(item.role for item in bindings)
    senders = tuple(item.matrix_user_id for item in bindings)
    key_ids = tuple(item.openworkproof_key_id for item in bindings)
    if (
        roles != ("Manager", "Developer", "Verifier")
        or len(set(senders)) != 3
        or len(set(key_ids)) != 3
    ):
        raise RuntimeError("AgentTeams roles, senders, and keys must be distinct")

    controller = controller or AgentTeamsControllerClient()
    matrix = matrix or AgentTeamsMatrixClient(token=token)
    manager = _resource_by_name(
        controller.get_managers(), task["manager_resource"]
    )
    developer = _resource_by_name(
        controller.get_workers(), task["developer_resource"]
    )
    verifier = _resource_by_name(
        controller.get_workers(), task["verifier_resource"]
    )
    resources = (manager, developer, verifier)
    if any(item.get("phase") != "Running" for item in resources):
        raise RuntimeError("all AgentTeams roles must be Running")
    observed_senders = tuple(item.get("matrixUserID") for item in resources)
    if observed_senders != senders:
        raise RuntimeError("live Matrix identities do not match role bindings")

    room_id = None
    if room:
        room_id = (
            matrix.resolve_room_alias(room)
            if room.startswith("#")
            else room
        )
        if room_id not in matrix.joined_rooms():
            raise RuntimeError("Matrix token is not joined to the target room")
    else:
        matrix.joined_rooms()
    return LivePreflightResult(roles, senders, key_ids, room_id)


def _write_provenance(path: Path, record: dict[str, Any]) -> None:
    target = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags, 0o600)
    except OSError as error:
        raise RuntimeError("acceptance provenance cannot be created") from error
    payload = rfc8785.dumps(record) + b"\n"
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("acceptance provenance write made no progress")
            offset += written
        os.fsync(descriptor)
    except OSError as error:
        try:
            target.unlink()
        except OSError:
            pass
        raise RuntimeError("acceptance provenance cannot be written") from error
    finally:
        os.close(descriptor)


def _acceptance_manifest_digest(bundle: Path) -> str:
    manifest = validate_acceptance_bundle_manifest(bundle)
    return hashlib.sha256(
        rfc8785.dumps(manifest.model_dump(mode="json"))
    ).hexdigest()


def wait_for_external_acceptance(
    *,
    acceptance_bundle: Path,
    timeout_seconds: int | float,
    provenance_path: Path | None,
    matrix: AgentTeamsMatrixClient | None,
    room_id: str | None,
) -> AcceptanceBundleVerificationResult:
    """Poll for and verify an external bundle after work is ready to accept."""

    if (
        type(timeout_seconds) not in {int, float}
        or not math.isfinite(timeout_seconds)
        or timeout_seconds < 0
    ):
        raise RuntimeError("acceptance timeout is invalid")
    bundle = Path(acceptance_bundle)
    deadline = time.monotonic() + timeout_seconds
    while not bundle.exists():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("external acceptance timed out")
        time.sleep(min(0.2, remaining))
    if provenance_path is not None and Path(provenance_path).exists():
        raise RuntimeError("acceptance provenance already exists")
    try:
        bundle_digest = _acceptance_manifest_digest(bundle)
        verified = verify_acceptance_bundle_directory(bundle)
        if _acceptance_manifest_digest(bundle) != bundle_digest:
            raise AcceptanceBundleError(
                "acceptance bundle changed during verification"
            )
    except AcceptanceBundleError as error:
        raise RuntimeError("external acceptance bundle is invalid") from error

    event_digest = None
    announcement = {
        "schema_version": "openworkproof-agentteams-acceptance/0.1",
        "terminal_decision": verified.terminal_decision,
        "terminal_receipt_digest": verified.terminal_receipt_digest,
        "acceptance_decision_binding_digest": (
            verified.acceptance_decision_binding_digest
        ),
    }
    announcement_error = None
    if matrix is not None and room_id is not None:
        try:
            event_id = matrix.send_text(
                room_id,
                rfc8785.dumps(announcement).decode("utf-8"),
            )
            event_digest = hashlib.sha256(event_id.encode("utf-8")).hexdigest()
        except Exception as error:
            announcement_error = error

    record = {
        "schema_version": (
            "openworkproof-agentteams-acceptance-provenance/0.1"
        ),
        "bundle_digest": bundle_digest,
        "terminal_receipt_digest": verified.terminal_receipt_digest,
        "acceptance_decision_binding_digest": (
            verified.acceptance_decision_binding_digest
        ),
        "terminal_decision": verified.terminal_decision,
        "announcement_event_id_digest": event_digest,
    }
    if provenance_path is not None:
        _write_provenance(Path(provenance_path), record)
    if announcement_error is not None:
        raise AcceptanceAnnouncementError(
            "acceptance announcement failed",
            verified=verified,
        ) from announcement_error
    return verified


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--room")
    parser.add_argument("--task-file", required=True)
    parser.add_argument("--delivery-package")
    parser.add_argument("--output")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--max-rework", type=int, default=1)
    parser.add_argument("--record-provenance")
    parser.add_argument("--acceptance-bundle")
    parser.add_argument("--preflight-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        preflight = run_live_preflight(
            task_path=Path(args.task_file),
            room=args.room,
        )
        if args.preflight_only:
            print(json.dumps(asdict(preflight), sort_keys=True))
            return 0
        if not args.acceptance_bundle:
            raise RuntimeError(
                "an external acceptance bundle is required after work is ready"
            )
        token = os.environ.get("AGENTTEAMS_MATRIX_TOKEN")
        matrix = (
            AgentTeamsMatrixClient(token=token)
            if preflight.room_id
            else None
        )
        verified = wait_for_external_acceptance(
            acceptance_bundle=Path(args.acceptance_bundle),
            timeout_seconds=args.timeout_seconds,
            provenance_path=(
                Path(args.record_provenance)
                if args.record_provenance
                else None
            ),
            matrix=matrix,
            room_id=preflight.room_id,
        )
        print(
            json.dumps(
                {
                    "preflight": asdict(preflight),
                    "human_acceptance": verified.model_dump(mode="json"),
                },
                sort_keys=True,
            )
        )
        return 0 if verified.terminal_decision == "ACCEPTED" else 2
    except AcceptanceAnnouncementError as error:
        print(
            json.dumps(
                {"human_acceptance": error.verified.model_dump(mode="json")},
                sort_keys=True,
            )
        )
        print(f"OpenWorkProof AgentTeams demo error: {error}", file=os.sys.stderr)
        return 4
    except RuntimeError as error:
        print(f"OpenWorkProof AgentTeams demo error: {error}", file=os.sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
