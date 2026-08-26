"""Production handler assembly for the DeepSeek Harness bridge."""

from __future__ import annotations

import json
import os
import socket
import stat
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import openworkproof.evidence as evidence
import openworkproof.repo_tools as repo_tools
from openworkproof.binding import canonical_test_profile_digest
from openworkproof.dsh_case import DecisionTokenStore, DshCaseManifestV01
from openworkproof.dsh_execution import (
    DshApplyPatchInputV01,
    DshExecutionCaseV01,
    DshRunTestsInputV01,
    execute_dsh_patch,
    execute_dsh_tests,
)
from openworkproof.dsh_protocol import (
    DshActionExecutePayloadV01,
    DshExecutionIdentityV01,
    dsh_execution_identity_digest,
)
from openworkproof.models import (
    RunTestsArguments,
    TestResultEvidence,
    ToolCallReceipt,
)
from openworkproof.policy import (
    AuthorizationLedgerPrefix,
    CommittedEvidence,
    ProspectiveExecutionFacts,
    derive_authorization_context,
)

if TYPE_CHECKING:
    from openworkproof.dsh_bridge import DshCaseHandlers


_MAX_VERIFIER_MESSAGE_BYTES = 1_048_576
_VERIFIER_TIMEOUT_SECONDS = 5.0


def _strict_canonical_object(raw: bytes) -> dict[str, object]:
    def pairs_hook(pairs):
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate verifier response field")
            value[key] = item
        return value

    try:
        value = json.loads(raw, object_pairs_hook=pairs_hook)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("VERIFIER_RESPONSE_INVALID") from error
    if type(value) is not dict or rfc8785.dumps(value) != raw:
        raise RuntimeError("VERIFIER_RESPONSE_INVALID")
    return value


def _require_private_verifier_socket(path: Path) -> None:
    if (
        not path.is_absolute()
        or path != Path(os.path.abspath(path))
        or path.is_symlink()
    ):
        raise RuntimeError("VERIFIER_TRANSPORT_UNAVAILABLE")
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise RuntimeError("VERIFIER_TRANSPORT_UNAVAILABLE") from error
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.geteuid()
    ):
        raise RuntimeError("VERIFIER_TRANSPORT_UNAVAILABLE")


def _receive_verifier_response(connection: socket.socket) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = connection.recv(min(65_536, _MAX_VERIFIER_MESSAGE_BYTES + 1 - size))
        if not chunk:
            raise RuntimeError("VERIFIER_RESPONSE_INVALID")
        newline = chunk.find(b"\n")
        if newline >= 0:
            if newline != len(chunk) - 1:
                raise RuntimeError("VERIFIER_RESPONSE_INVALID")
            chunks.append(chunk[:newline])
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > _MAX_VERIFIER_MESSAGE_BYTES:
            raise RuntimeError("VERIFIER_RESPONSE_INVALID")
    raw = b"".join(chunks)
    if not raw or len(raw) > _MAX_VERIFIER_MESSAGE_BYTES:
        raise RuntimeError("VERIFIER_RESPONSE_INVALID")
    return raw


def make_external_verifier_executor(
    *,
    socket_path: Path,
    case_id: str,
) -> Callable[
    [
        RunTestsArguments,
        ProspectiveExecutionFacts,
        DshExecutionIdentityV01,
        datetime,
    ],
    ToolCallReceipt,
]:
    """Return a fail-closed client for one case-bound Verifier process."""

    def execute(
        arguments: RunTestsArguments,
        facts: ProspectiveExecutionFacts,
        execution: DshExecutionIdentityV01,
        now: datetime,
    ) -> ToolCallReceipt:
        _require_private_verifier_socket(socket_path)
        if now.tzinfo is None or now.utcoffset() is None or now.microsecond:
            raise RuntimeError("VERIFIER_REQUEST_INVALID")
        execution_digest = dsh_execution_identity_digest(execution)
        request = rfc8785.dumps(
            {
                "schema_version": "openworkproof-dsh-verifier-request/0.1",
                "case_id": case_id,
                "execution_identity_digest": execution_digest,
                "execution": execution.model_dump(mode="json"),
                "arguments": arguments.model_dump(mode="json"),
                "facts": {
                    "execution_context_id": facts.execution_context_id,
                    "container_instance_id_digest": (
                        facts.container_instance_id_digest
                    ),
                    "controller_id": facts.controller_id,
                },
                "requested_at": now.astimezone(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
            }
        )
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(_VERIFIER_TIMEOUT_SECONDS)
                connection.connect(str(socket_path))
                connection.sendall(request + b"\n")
                raw = _receive_verifier_response(connection)
        except RuntimeError:
            raise
        except (OSError, TimeoutError) as error:
            raise RuntimeError("VERIFIER_TRANSPORT_UNAVAILABLE") from error
        response = _strict_canonical_object(raw)
        if (
            set(response)
            != {
                "schema_version",
                "case_id",
                "execution_identity_digest",
                "receipt",
            }
            or response["schema_version"]
            != "openworkproof-dsh-verifier-response/0.1"
            or response["case_id"] != case_id
            or response["execution_identity_digest"] != execution_digest
        ):
            raise RuntimeError("VERIFIER_RESPONSE_INVALID")
        try:
            return ToolCallReceipt.model_validate(response["receipt"])
        except ValueError as error:
            raise RuntimeError("VERIFIER_RESPONSE_INVALID") from error

    return execute


def _load_private_key(path: str) -> Ed25519PrivateKey:
    raw = Path(path).read_bytes()
    if len(raw) != 32:
        raise RuntimeError("CASE_KEY_INVALID")
    return Ed25519PrivateKey.from_private_bytes(raw)


def _case_runtime(
    manifest: DshCaseManifestV01,
    decision_tokens: DecisionTokenStore,
    *,
    now: datetime,
) -> DshExecutionCaseV01:
    ledger_path = Path(manifest.ledger_path)
    evidence_root = Path(manifest.evidence_root)
    connection = evidence.connect_ledger(ledger_path)
    try:
        work_order, receipts, grants, groups = (
            evidence._replay_receipt_publication_ledger(connection)
        )
        attempts = evidence._validated_grant_attempts(
            connection, work_order, receipts
        )
    finally:
        connection.close()
    if (
        work_order.digest != manifest.work_order_digest
        or work_order.source_commit != manifest.source_revision
    ):
        raise RuntimeError("CASE_LEDGER_BINDING_INVALID")
    committed: list[CommittedEvidence] = []
    verified: list[TestResultEvidence] = []
    verifier_paths = {
        f"{work_order.evidence_policy.evidence_root}/{artifact.path}"
        for artifact in work_order.evidence_policy.artifacts
        if artifact.purpose
        in {"verifier_result", "verifier_independent_result"}
    }
    for group in groups:
        for publication in group.publications:
            if publication.state != "COMMITTED":
                continue
            payload = (evidence_root / publication.final_path).read_bytes()
            item = CommittedEvidence(
                reference=publication.reference,
                payload=payload,
            )
            committed.append(item)
            if publication.reference.path in verifier_paths:
                verified.append(TestResultEvidence.model_validate_json(payload))
    workspace = repo_tools.load_candidate_workspace(
        Path(manifest.candidate_runtime_root),
        manifest.candidate_workspace_id,
    )
    if workspace.source_artifact_sha256 != work_order.source_artifact.sha256:
        raise RuntimeError("CASE_WORKSPACE_BINDING_INVALID")
    descriptor = os.open(
        workspace.worktree,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        workspace_manifest = repo_tools.scan_workspace_manifest(
            descriptor, workspace.head_commit
        )
    finally:
        os.close(descriptor)
    workspace_manifest_digest = repo_tools.workspace_manifest_digest(
        workspace_manifest
    )
    if workspace_manifest_digest != workspace.workspace_manifest_digest:
        raise RuntimeError("CASE_WORKSPACE_BINDING_INVALID")
    checkpoint = repo_tools.ReplayCheckpoint(
        files=(),
        head_commit=workspace.head_commit,
        workspace_manifest=workspace_manifest,
        workspace_manifest_digest=workspace_manifest_digest,
        verified_test_results=tuple(verified),
    )
    context = derive_authorization_context(
        work_order,
        AuthorizationLedgerPrefix(
            effective_grants=tuple(
                sorted(grants.values(), key=lambda item: item.grant_id)
            ),
            grant_attempts=tuple(
                sorted(attempts.values(), key=lambda item: item.digest)
            ),
            receipts=receipts,
        ),
        tuple(
            sorted(committed, key=lambda item: item.reference.path.encode())
        ),
        checkpoint,
        now,
    )
    verifier_socket = manifest.verifier_socket_path
    return DshExecutionCaseV01(
        case_id=manifest.case_id,
        ledger_path=ledger_path,
        evidence_root=evidence_root,
        context=context,
        candidate_workspace=workspace,
        sidecar_private_key=_load_private_key(manifest.sidecar_key_path),
        developer_private_key=_load_private_key(manifest.developer_key_path),
        decision_tokens=decision_tokens,
        test_profile_digest=manifest.test_profile_digest,
        run_tests_executor=(
            None
            if verifier_socket is None
            else make_external_verifier_executor(
                socket_path=Path(verifier_socket),
                case_id=manifest.case_id,
            )
        ),
    )


def build_dsh_case_handlers(
    manifest: DshCaseManifestV01,
    decision_tokens: DecisionTokenStore,
    *,
    clock: Callable[[], datetime],
) -> DshCaseHandlers:
    """Assemble one case-scoped handler set from durable protocol truth."""

    from openworkproof.dsh_bridge import DshCaseHandlers

    def action(payload: DshActionExecutePayloadV01) -> str:
        now = clock().astimezone(timezone.utc)
        runtime = _case_runtime(
            manifest,
            decision_tokens,
            now=now,
        )
        if payload.execution.tool_name == "owp_apply_patch":
            result = execute_dsh_patch(
                runtime,
                DshApplyPatchInputV01.model_validate(
                    {
                        "schema_version": (
                            "openworkproof-dsh-apply-patch/0.1"
                        ),
                        "case_id": payload.case_id,
                        "execution": payload.execution.model_dump(mode="json"),
                        "decision_token": payload.decision_token,
                        "patch_utf8": payload.patch_text,
                        "target_paths": list(payload.target_paths or ()),
                    }
                ),
                clock=lambda: now,
            )
            return result.receipt.digest
        receipt = execute_dsh_tests(
            runtime,
            DshRunTestsInputV01.model_validate(
                {
                    "schema_version": "openworkproof-dsh-run-tests/0.1",
                    "case_id": payload.case_id,
                    "execution": payload.execution.model_dump(mode="json"),
                    "decision_token": payload.decision_token,
                    "test_profile_digest": payload.test_profile_digest,
                }
            ),
            clock=lambda: now,
        )
        return receipt.digest

    def unavailable(_payload: object) -> str:
        raise RuntimeError("HANDLER_NOT_IMPLEMENTED")

    return DshCaseHandlers(
        action=action,
        verify=unavailable,
        acceptance_draft=unavailable,
        export=unavailable,
    )


__all__ = ["build_dsh_case_handlers", "make_external_verifier_executor"]
