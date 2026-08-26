"""Production handler assembly for the DeepSeek Harness bridge."""

from __future__ import annotations

import hashlib
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
from openworkproof.acceptance import prepare_acceptance_decision_binding
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
    DshAcceptanceDraftPayloadV01,
    DshActionExecutePayloadV01,
    DshExecutionIdentityV01,
    DshExportRequestPayloadV01,
    DshObservationRecordV01,
    DshVerifyRequestPayloadV01,
    canonical_bytes,
    dsh_execution_identity_digest,
    verify_dsh_observation,
)
from openworkproof.dsh_verifier import (
    DshVerificationCaseV01,
    DshVerificationResultV01,
    verify_dsh_code_change,
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
from openworkproof.services import OpenWorkProofServices

if TYPE_CHECKING:
    from openworkproof.dsh_bridge import DshCaseHandlers


_MAX_VERIFIER_MESSAGE_BYTES = 1_048_576
_VERIFIER_TIMEOUT_SECONDS = 5.0


def _evidence_payload_path(
    evidence_root: Path,
    logical_root: str,
    final_path: str,
) -> Path:
    prefix = f"{logical_root}/"
    if not final_path.startswith(prefix):
        raise RuntimeError("CASE_EVIDENCE_BINDING_INVALID")
    return evidence_root / final_path.removeprefix(prefix)


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
    references = {
        reference.path: reference
        for receipt in receipts
        for reference in receipt.evidence_refs
    }
    for group, state in groups:
        if state != "COMMITTED":
            continue
        for publication in group.publications:
            payload = _evidence_payload_path(
                evidence_root,
                work_order.evidence_policy.evidence_root,
                publication.final_path,
            ).read_bytes()
            reference = references.get(publication.final_path)
            if reference is None:
                raise RuntimeError("CASE_EVIDENCE_BINDING_INVALID")
            item = CommittedEvidence(
                reference=reference,
                payload=payload,
            )
            committed.append(item)
            if reference.path in verifier_paths:
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


def _verified_patch_execution(
    manifest: DshCaseManifestV01,
    receipt_digest: str,
    sidecar_key: Ed25519PrivateKey,
) -> DshExecutionIdentityV01:
    directory = Path(manifest.evidence_root) / "dsh-observations"
    candidates: list[DshExecutionIdentityV01] = []
    if directory.is_dir() and not directory.is_symlink():
        for path in sorted(directory.iterdir(), key=lambda item: item.name):
            if path.is_symlink() or not path.is_file() or path.suffix != ".json":
                continue
            try:
                record = DshObservationRecordV01.model_validate_json(
                    path.read_bytes()
                )
            except (OSError, ValueError):
                continue
            if (
                record.authorization_status == "authorized"
                and record.receipt_digest == receipt_digest
                and not record.evidence_gap_codes
                and record.execution.tool_name == "owp_apply_patch"
                and verify_dsh_observation(
                    record, sidecar_key.public_key()
                )
            ):
                candidates.append(record.execution)
    if len(candidates) != 1:
        raise RuntimeError("PATCH_OBSERVATION_BINDING_UNAVAILABLE")
    return candidates[0]


def _committed_verifier_exit_code(
    manifest: DshCaseManifestV01,
    *,
    candidate_commit: str,
    workspace_manifest_digest: str,
) -> int:
    ledger_path = Path(manifest.ledger_path)
    evidence_root = Path(manifest.evidence_root)
    connection = evidence.connect_ledger(ledger_path)
    try:
        work_order, receipts, _, groups = (
            evidence._replay_receipt_publication_ledger(connection)
        )
    finally:
        connection.close()
    profile = tuple(
        item
        for item in work_order.test_profiles
        if item.test_mode == "verifier"
        and canonical_test_profile_digest(item) == manifest.test_profile_digest
    )
    if len(profile) != 1:
        raise RuntimeError("VERIFIER_PROFILE_BINDING_INVALID")
    selected = profile[0]
    committed_payloads = {
        publication.final_path: _evidence_payload_path(
            evidence_root,
            work_order.evidence_policy.evidence_root,
            publication.final_path,
        ).read_bytes()
        for group, state in groups
        for publication in group.publications
        if state == "COMMITTED"
    }
    results: list[TestResultEvidence] = []
    artifact_purposes = {
        f"{work_order.evidence_policy.evidence_root}/{artifact.path}": (
            artifact.purpose
        )
        for artifact in work_order.evidence_policy.artifacts
    }
    for receipt in receipts:
        if (
            not isinstance(receipt, ToolCallReceipt)
            or receipt.tool_name != "owp.run_tests"
            or receipt.policy_decision != "allow"
            or receipt.execution_status != "succeeded"
            or not isinstance(receipt.request_arguments, RunTestsArguments)
            or receipt.request_arguments.test_mode != "verifier"
            or receipt.request_arguments.command_digest
            != selected.command_digest
            or receipt.request_arguments.container_image_digest
            != selected.container_image_digest
            or receipt.request_arguments.fixed_test_source_digest
            != selected.fixed_test_source_digest
            or receipt.request_arguments.candidate_commit != candidate_commit
            or receipt.request_arguments.workspace_manifest_digest
            != workspace_manifest_digest
        ):
            continue
        references = tuple(
            reference
            for reference in receipt.evidence_refs
            if artifact_purposes.get(reference.path)
            in {"verifier_result", "verifier_independent_result"}
        )
        if len(references) != 1:
            continue
        payload = committed_payloads.get(references[0].path)
        if payload is None:
            continue
        result = TestResultEvidence.model_validate_json(payload)
        if (
            result.test_mode == "verifier"
            and result.command_digest == selected.command_digest
            and result.candidate_commit == candidate_commit
            and result.workspace_manifest_digest == workspace_manifest_digest
            and result.container_image_digest == selected.container_image_digest
            and result.fixed_test_source_digest
            == selected.fixed_test_source_digest
        ):
            results.append(result)
    if len(results) != 1:
        raise RuntimeError("VERIFIER_RESULT_BINDING_UNAVAILABLE")
    return results[0].actual_exit_code


def _store_result(root: Path, kind: str, payload: object) -> str:
    raw = canonical_bytes(payload)
    digest = hashlib.sha256(raw).hexdigest()
    directory = root / kind
    directory.mkdir(mode=0o700, exist_ok=True)
    destination = directory / f"{digest}.json"
    encoded = raw + b"\n"
    if destination.exists():
        if destination.is_symlink() or destination.read_bytes() != encoded:
            raise RuntimeError("IMMUTABLE_RESULT_CONFLICT")
        return digest
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return digest


def _load_verification_result(
    manifest: DshCaseManifestV01,
    digest: str,
) -> DshVerificationResultV01:
    path = (
        Path(manifest.evidence_root)
        / "dsh-verifications"
        / f"{digest}.json"
    )
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("VERIFICATION_RESULT_UNAVAILABLE")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise RuntimeError("VERIFICATION_RESULT_UNAVAILABLE") from error
    if len(raw) > _MAX_VERIFIER_MESSAGE_BYTES or not raw.endswith(b"\n"):
        raise RuntimeError("VERIFICATION_RESULT_INVALID")
    try:
        result = DshVerificationResultV01.model_validate_json(raw)
    except ValueError as error:
        raise RuntimeError("VERIFICATION_RESULT_INVALID") from error
    canonical = canonical_bytes(result)
    if raw != canonical + b"\n" or hashlib.sha256(canonical).hexdigest() != digest:
        raise RuntimeError("VERIFICATION_RESULT_INVALID")
    if (
        result.case_id != manifest.case_id
        or result.status != "VERIFIED"
        or result.work_order_digest != manifest.work_order_digest
        or result.source_revision != manifest.source_revision
        or result.test_profile_digest != manifest.test_profile_digest
    ):
        raise RuntimeError("VERIFICATION_RESULT_BINDING_INVALID")
    return result


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

    def verify(payload: object) -> str:
        request = DshVerifyRequestPayloadV01.model_validate(
            payload.model_dump(mode="json")
            if isinstance(payload, DshVerifyRequestPayloadV01)
            else payload
        )
        if request.case_id != manifest.case_id:
            raise RuntimeError("CASE_ID_MISMATCH")
        now = clock().astimezone(timezone.utc)
        sidecar_key = _load_private_key(manifest.sidecar_key_path)
        execution = _verified_patch_execution(
            manifest,
            request.action_receipt_digest,
            sidecar_key,
        )
        workspace = repo_tools.load_candidate_workspace(
            Path(manifest.candidate_runtime_root),
            manifest.candidate_workspace_id,
        )
        exit_code = _committed_verifier_exit_code(
            manifest,
            candidate_commit=workspace.head_commit,
            workspace_manifest_digest=workspace.workspace_manifest_digest,
        )
        result = verify_dsh_code_change(
            DshVerificationCaseV01(
                case_id=manifest.case_id,
                repository_root=workspace.worktree,
                source_revision=manifest.source_revision,
                allowed_path_roots=manifest.allowed_path_roots,
                denied_path_roots=manifest.denied_path_roots,
                test_profile_digest=manifest.test_profile_digest,
                ledger_path=Path(manifest.ledger_path),
                evidence_root=Path(manifest.evidence_root),
                verification_runner=lambda _repository: exit_code,
                execution=execution,
                action_receipt_digest=request.action_receipt_digest,
                git_dir=workspace.git_dir,
            ),
            clock=lambda: now,
        )
        digest = _store_result(
            Path(manifest.evidence_root),
            "dsh-verifications",
            result,
        )
        if result.status == "VERIFIED":
            return digest
        from openworkproof.dsh_bridge import DshHandlerResult

        return DshHandlerResult(
            status="denied" if result.status == "REFUTED" else "unknown",
            result_digest=digest,
            reason_code=result.reason_codes[0],
        )

    def acceptance_draft(payload: object) -> str:
        request = DshAcceptanceDraftPayloadV01.model_validate(
            payload.model_dump(mode="json")
            if isinstance(payload, DshAcceptanceDraftPayloadV01)
            else payload
        )
        if request.case_id != manifest.case_id:
            raise RuntimeError("CASE_ID_MISMATCH")
        _load_verification_result(manifest, request.verification_digest)
        draft = prepare_acceptance_decision_binding(
            Path(manifest.ledger_path),
            clock=lambda: clock().astimezone(timezone.utc),
        )
        return _store_result(
            Path(manifest.evidence_root),
            "dsh-acceptance-drafts",
            json.loads(draft.canonical_payload),
        )

    def export(payload: object) -> str:
        request = DshExportRequestPayloadV01.model_validate(
            payload.model_dump(mode="json")
            if isinstance(payload, DshExportRequestPayloadV01)
            else payload
        )
        if request.case_id != manifest.case_id:
            raise RuntimeError("CASE_ID_MISMATCH")
        destination = Path(request.destination)
        if (
            not destination.is_absolute()
            or destination != Path(os.path.abspath(destination))
        ):
            raise RuntimeError("EXPORT_DESTINATION_INVALID")
        services = OpenWorkProofServices()
        services.build_delivery(
            Path(manifest.ledger_path),
            destination,
            "customer_private",
        )
        audit = services.audit_delivery(destination)
        manifest_digest = audit.get("manifest_digest")
        if not isinstance(manifest_digest, str) or len(manifest_digest) != 64:
            raise RuntimeError("EXPORT_VERIFICATION_FAILED")
        return manifest_digest

    return DshCaseHandlers(
        action=action,
        verify=verify,
        acceptance_draft=acceptance_draft,
        export=export,
    )


__all__ = ["build_dsh_case_handlers", "make_external_verifier_executor"]
