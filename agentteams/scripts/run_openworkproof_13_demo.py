#!/usr/bin/env python3
"""Run the bounded OpenWorkProof 1.3 AgentTeams demonstration."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
from typing import Any

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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--room")
    parser.add_argument("--task-file", required=True)
    parser.add_argument("--delivery-package")
    parser.add_argument("--output")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--max-rework", type=int, default=1)
    parser.add_argument("--record-provenance")
    parser.add_argument("--acceptance-receipt")
    parser.add_argument("--preflight-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run_live_preflight(
            task_path=Path(args.task_file),
            room=args.room,
        )
        if not args.preflight_only:
            raise RuntimeError(
                "live demo execution is not enabled until all bounded inputs "
                "and the human acceptance receipt are available"
            )
    except RuntimeError as error:
        print(f"OpenWorkProof AgentTeams demo error: {error}", file=os.sys.stderr)
        return 4
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
