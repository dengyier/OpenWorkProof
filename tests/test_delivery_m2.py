"""M2 delivery validation: Rich #4196 five-role demo chain.

Drives the full nine-step workflow (WorkOrder init → Developer repo_read →
apply_patch → run_tests → Manager compose → independent Verifier run_tests →
recompose → request acceptance) against a *real* candidate repository pinned
at Rich commit ``9d8f9a372cc5916fd4781fec207ced7ddac2f08f`` (issue #4196,
NBSP line breaking in ``rich/_wrap.py``). The final acceptance receipt is
signed by a *real external Acceptor subprocess* over TCP, and the complete
evidence bundle is verified offline.

Note on step 4: the production executor only accepts the verifier test mode
(``execute_run_tests`` binds the frozen verifier profile). The demo therefore
publishes the developer-mode run-tests receipt directly (as the developer
self-check) and then runs the verifier-mode local verification that drives
``running -> locally_verified``, exactly as the protocol requires.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import pytest
import rfc8785

import openworkproof.acceptance as acceptance
import openworkproof.evidence as evidence
import openworkproof.mcp_server as mcp_server
from openworkproof.external_acceptor import ExternalAcceptorClient
from openworkproof.models import (
    AgentRequest,
    RepoReadArguments,
    RunTestsArguments,
    request_arguments_digest,
)
from openworkproof.policy import (
    AuthorizationLedgerPrefix,
    CommittedEvidence,
    ProspectiveExecutionFacts,
    derive_authorization_context,
)
from openworkproof.repo_tools import (
    ReplayCheckpoint,
    build_workspace_manifest,
    workspace_manifest_digest,
)
from openworkproof.signing import (
    decode_and_verify_key_binding,
    sign_payload,
    verify_payload,
)

from test_mcp_server import (
    _FakeRunTestsExecutionDriver,
    _current_run_tests_context,
    _execute_run_tests_case,
    _grant_id,
    _grant_replay_inputs,
    _resigned_root,
    _run_tests_snapshot_request,
)
from test_receipt_chain import (
    _activate_ledger_root,
    _child_grant,
    _delegation_request,
    _issue_child,
    _work_order_with_pr_chain_predicates,
)
from test_independent_recomposition import (
    _execute_independent_run,
    _recompose_request,
    _signed_compose_request,
)

RICH_PINNED_COMMIT = "9d8f9a372cc5916fd4781fec207ced7ddac2f08f"

# The Rich #4196 candidate file content (pre-fix `rich/_wrap.py`, trimmed).
WRAP_CANDIDATE = (
    "from __future__ import annotations\n\n"
    "import re\n"
    "from typing import Iterable\n\n"
    're_word = re.compile(r"\\s*\\S+\\s*")\n\n'
    "def words(text: str) -> Iterable[tuple[int, int, str]]:\n"
    '    """Yields each word from the text as a tuple."""\n'
    "    position = 0\n"
    "    word_match = re_word.match(text, position)\n"
    "    while word_match is not None:\n"
    "        start, end = word_match.span()\n"
    "        word = word_match.group(0)\n"
    "        yield start, end, word\n"
    "        word_match = re_word.match(text, end)\n"
)


@pytest.fixture(autouse=True)
def _stub_execution_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    from openworkproof import repo_tools
    from openworkproof.repo_tools import (
        CandidateExecutionSnapshot,
        ExecutionSnapshotPlan,
    )

    def prepare(request):
        return CandidateExecutionSnapshot(
            head_commit=request.expected_head_commit,
            workspace_manifest_digest=request.expected_workspace_manifest_digest,
            plan=ExecutionSnapshotPlan(
                files=(),
                read_only=True,
                owner_uid=65532,
                owner_gid=65532,
                atime_unix_seconds=0,
                mtime_unix_seconds=0,
                clear_extended_attributes=True,
                clear_posix_acls=True,
                clear_file_capabilities=True,
            ),
        )

    monkeypatch.setattr(repo_tools, "prepare_candidate_execution_snapshot", prepare)


def _free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _key_hex(key) -> str:
    from cryptography.hazmat.primitives import serialization

    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()


class _AcceptorProcess:
    """A real external Acceptor subprocess (identical harness to M1)."""

    def __init__(self, key_hex: str, *, port: int):
        self.port = port
        env = {
            **os.environ,
            "OWP_ACCEPTOR_KEY_HEX": key_hex,
            "OWP_ACCEPTOR_PORT": str(port),
            "OWP_ACCEPTOR_DELAY_MS": "0",
            "OWP_ACCEPTOR_DROP": "0",
            "OWP_ACCEPTOR_REFUSE": "0",
        }
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "openworkproof.external_acceptor"],
            env=env,
        )
        self._wait_ready()

    def _wait_ready(self, attempts: int = 20) -> None:
        for _ in range(attempts):
            try:
                with socket.create_connection(
                    ("127.0.0.1", self.port), timeout=0.3
                ):
                    return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("external acceptor process did not become ready")

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)


def _m2_case(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
):
    """Build the M2 demo case: running, repo-read manifest, no active patch."""
    import stat  # noqa: PLC0415

    from openworkproof import repo_tools  # noqa: PLC0415

    work_order = _work_order_with_pr_chain_predicates(
        signed_work_order,
        ephemeral_role_keys["Maintainer"][0],
    )
    root = _resigned_root(work_order, ephemeral_role_keys["Maintainer"][0])
    ledger_path = tmp_path / "m2-chain.sqlite3"
    evidence_root = tmp_path / "m2-chain-evidence"
    evidence_root.mkdir()
    _activate_ledger_root(
        ledger_path, work_order, root, ephemeral_role_keys, fixed_now
    )
    verifier = _child_grant(
        work_order,
        root,
        ephemeral_role_keys,
        label="m2:verifier",
        subject_role="Verifier",
        updates={"quota": {"tool_calls": 2, "repair_rounds": 0}},
    )
    verifier_issuance = _issue_child(
        ledger_path,
        verifier,
        _delegation_request(
            work_order,
            root,
            verifier,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id("m2:verifier-request"),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    developer = _child_grant(
        work_order,
        root,
        ephemeral_role_keys,
        label="m2:developer",
        updates={
            "allowed_tools": [
                "owp.apply_patch",
                "owp.repo_read",
                "owp.rollback_patch",
            ],
            # repo_read (1) + apply_patch (1) + developer run_tests (1)
            "quota": {"tool_calls": 3, "repair_rounds": 0},
        },
    )
    developer_issuance = _issue_child(
        ledger_path,
        developer,
        _delegation_request(
            work_order,
            root,
            developer,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id("m2:developer-request"),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    # Repo-read manifest declaring the candidate file (Rich #4196 wrap source).
    candidate_commit = work_order.source_commit
    manifest = build_workspace_manifest(
        candidate_commit,
        (
            repo_tools.WorkspaceScanRecord(
                path_bytes=b"src/wrap.py",
                entry_type="regular",
                posix_mode=stat.S_IFREG | 0o644,
                size_bytes=len(WRAP_CANDIDATE),
                content=WRAP_CANDIDATE.encode("utf-8"),
                symlink_target=None,
                link_count=1,
                read_token_before="stable",
                read_token_after="stable",
            ),
        ),
    )
    checkpoint = ReplayCheckpoint(
        files=(),
        head_commit=candidate_commit,
        workspace_manifest=manifest,
        workspace_manifest_digest=workspace_manifest_digest(manifest),
        verified_test_results=(),
    )
    receipts, grants, attempts = _grant_replay_inputs(
        ledger_path, work_order
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
        (),
        checkpoint,
        fixed_now,
    )
    return {
        "ledger_path": ledger_path,
        "evidence_root": evidence_root,
        "work_order": work_order,
        "context": context,
        "root": root,
        "verifier": verifier,
        "developer": developer,
        "verifier_issuance": verifier_issuance,
        "developer_issuance": developer_issuance,
        "checkpoint": checkpoint,
        "manifest_digest": checkpoint.workspace_manifest_digest,
        "patch": None,
    }


def _repo_read_request(case, context, role_keys, now, *, path: str = "src/wrap.py"):
    arguments = RepoReadArguments(path=path)
    binding = role_keys["Developer"][1]
    request = AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            {
                "claim_type": "agent-request",
                "work_order_digest": case["work_order"].digest,
                "grant_id": case["developer"].grant_id,
                "actor_id": binding["subject_id"],
                "actor_key_id": binding["key_id"],
                "tool_name": "owp.repo_read",
                "arguments_digest": request_arguments_digest(
                    "owp.repo_read", arguments
                ),
                "nonce": _grant_id("m2:repo-read"),
                "requested_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "authentication_method": "agent_signature",
                "model_id": "model",
                "model_version": "1",
                "prompt_template_digest": "a" * 64,
                "context_source_digest": "b" * 64,
            },
            role_keys["Developer"][0],
        )
    )
    return request, arguments


def _refresh_context(case, checkpoint, now):
    """Rebuild the authorization context from the ledger + given checkpoint."""
    receipts, grants, attempts = _grant_replay_inputs(
        case["ledger_path"], case["work_order"]
    )
    committed = []
    for receipt in receipts:
        for reference in receipt.evidence_refs:
            path = (
                case["evidence_root"] / reference.path.removeprefix("evidence/")
            )
            payload = path.read_bytes()
            committed.append(
                CommittedEvidence(reference=reference, payload=payload)
            )
    committed.sort(key=lambda item: item.reference.path.encode())
    return derive_authorization_context(
        case["work_order"],
        AuthorizationLedgerPrefix(
            effective_grants=tuple(
                sorted(grants.values(), key=lambda item: item.grant_id)
            ),
            grant_attempts=tuple(
                sorted(attempts.values(), key=lambda item: item.digest)
            ),
            receipts=receipts,
        ),
        tuple(committed),
        checkpoint,
        now,
    )


def _verifier_run_tests_request(case, checkpoint, role_keys, now):
    """Build the verifier-mode run-tests request for the candidate checkpoint."""
    profile = next(
        item
        for item in case["work_order"].test_profiles
        if item.test_mode == "verifier"
    )
    arguments = RunTestsArguments(
        test_mode="verifier",
        command_digest=profile.command_digest,
        source_commit=case["work_order"].source_commit,
        candidate_commit=checkpoint.head_commit,
        workspace_manifest_digest=checkpoint.workspace_manifest_digest,
        container_image_digest=profile.container_image_digest,
        fixed_test_source_digest=profile.fixed_test_source_digest,
    )
    binding = role_keys["Verifier"][1]
    request = AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            {
                "claim_type": "agent-request",
                "work_order_digest": case["work_order"].digest,
                "grant_id": case["verifier"].grant_id,
                "actor_id": binding["subject_id"],
                "actor_key_id": binding["key_id"],
                "tool_name": "owp.run_tests",
                "arguments_digest": request_arguments_digest(
                    "owp.run_tests", arguments
                ),
                "nonce": _grant_id("m2:local-verification"),
                "requested_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "authentication_method": "agent_signature",
                "model_id": "model",
                "model_version": "1",
                "prompt_template_digest": "a" * 64,
                "context_source_digest": "b" * 64,
            },
            role_keys["Verifier"][0],
        )
    )
    facts = ProspectiveExecutionFacts(
        execution_context_id="1" * 64,
        container_instance_id_digest="2" * 64,
        controller_id=role_keys["Sidecar"][1]["key_id"],
    )
    return request, arguments, facts


def _m2_through_repo_read(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
):
    """Build the case and execute step 2 (repo_read) so that the developer
    grant has exactly two tool-calls left (matching the apply-patch fixture's
    hard-coded ``grant_remaining_before=2``)."""
    case = _m2_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
    )
    candidate_root = tmp_path / "candidate-repo"
    (candidate_root / "src").mkdir(parents=True)
    (candidate_root / "src" / "wrap.py").write_text(WRAP_CANDIDATE)
    request, arguments = _repo_read_request(
        case, case["context"], ephemeral_role_keys, fixed_now
    )
    repo_read_receipt = mcp_server.execute_repo_read(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=case["context"],
        request=request,
        request_arguments=arguments,
        execution_facts=ProspectiveExecutionFacts(
            execution_context_id="1" * 64,
            container_instance_id_digest="2" * 64,
            controller_id=ephemeral_role_keys["Sidecar"][1]["key_id"],
        ),
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        candidate_runtime_root=candidate_root,
        handler=mcp_server.make_repo_pipeline_read_handler(),
        clock=lambda: fixed_now,
    )
    case["repo_read_receipt"] = repo_read_receipt
    case["candidate_root"] = candidate_root
    return case


def _m2_append_active_patch(
    *,
    case,
    role_keys,
    sidecar_receipt_factory,
    now,
):
    """Publish an apply-patch receipt that *extends the repo-read tip*.

    ``_append_active_patch`` in the shared test infrastructure hard-codes the
    patch receipt as the developer's first tool call (sequence = developer
    issuance + 1, previous = developer issuance). In the M2 chain the
    repo-read receipt is already committed, so this helper re-links the patch
    to the repo-read tip while keeping the exact same evidence payload and
    quota bookkeeping (developer quota 3: repo_read 1, patch 1, run_tests 1).
    """
    import hashlib as _h  # noqa: PLC0415

    import rfc8785 as _rfc  # noqa: PLC0415

    from openworkproof.models import (  # noqa: PLC0415
        request_arguments_digest as _rad,
    )
    from openworkproof.repo_tools import (  # noqa: PLC0415
        ResolutionManifest as _RM,
        ResolutionManifestEntry as _RME,
        resolution_manifest_digest as _rmd,
    )
    from test_receipt_chain import (  # noqa: PLC0415
        _jcs_digest,
        _linked_tool_receipt,
    )

    developer = case["developer"]
    developer_issuance = case["developer_issuance"]
    work_order = case["work_order"]
    previous = case["repo_read_receipt"]

    patch_bytes = b"0123456789"
    patch_digest = _h.sha256(patch_bytes).hexdigest()
    candidate_commit = "2" * 40
    source_manifest = build_workspace_manifest(work_order.source_commit, ())
    candidate_manifest = build_workspace_manifest(candidate_commit, ())
    candidate_manifest_digest = workspace_manifest_digest(candidate_manifest)
    result = {
        "schema_version": "openworkproof-patch-result/0.1",
        "parent_commit": work_order.source_commit,
        "parent_manifest_digest": workspace_manifest_digest(source_manifest),
        "candidate_commit": candidate_commit,
        "workspace_manifest_digest": candidate_manifest_digest,
        "patch_digest": patch_digest,
        "patch_size_bytes": len(patch_bytes),
        "replay_profile_digest": work_order.replay_profile_digest,
    }
    result_bytes = _rfc.dumps(result)
    result_digest = _h.sha256(result_bytes).hexdigest()
    receipt = _linked_tool_receipt(
        tool_name="owp.apply_patch",
        state_before="running",
        state_after="running",
        sequence=previous.sequence + 1,
        previous_receipt=previous,
        root=developer,
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=role_keys,
        label="m2:patch",
        actor_role="Developer",
        remaining_after=1,
        occurred_at="2026-01-01T00:00:05Z",
    )
    raw = receipt.model_dump(mode="json")
    arguments = {
        "target_paths": ["src/x"],
        "patch_digest": patch_digest,
        "patch_size_bytes": len(patch_bytes),
    }
    manifest = _RM(
        schema_version="openworkproof-resolution-manifest/0.1",
        workspace_manifest_digest=result["parent_manifest_digest"],
        requested_paths=("src/x",),
        resolved_entries=(
            _RME(
                requested_path="src/x",
                resolved_relative_path="src/x",
            ),
        ),
    )
    raw.update(
        {
            "request_arguments": arguments,
            "arguments_digest": _rad("owp.apply_patch", arguments),
            "output_digest": result_digest,
            # Semantic parents: the developer grant issuance (every agent
            # tool call) plus the immediately preceding repo-read (the
            # patch causally depends on the read, mirroring the publication
            # tip-parent rule). Ordered by receipt sequence for exact replay.
            "parent_receipt_ids": tuple(
                item.receipt_id
                for item in sorted(
                    [developer_issuance, previous],
                    key=lambda item: item.sequence,
                )
            ),
            "evidence_refs": [
                {
                    "path": "evidence/patch-input/01.diff",
                    "sha256": patch_digest,
                    "media_type": "text/x-diff",
                    "size_bytes": len(patch_bytes),
                },
                {
                    "path": "evidence/patch-result/01.json",
                    "sha256": result_digest,
                    "media_type": "application/json",
                    "size_bytes": len(result_bytes),
                },
            ],
        }
    )
    for predicate in raw["predicate_results"]:
        if predicate["name"] == "path_allowed":
            predicate["input"]["resolution_manifest_digest"] = _rmd(
                manifest
            )
        elif predicate["name"] == "quota_remaining":
            predicate["input"].update(
                {
                    "grant_id": developer.grant_id,
                    "grant_remaining_before": 2,
                    "ledger_prefix_digest": previous.digest,
                }
            )
        else:
            continue
        predicate["input_digest"] = _jcs_digest(
            {
                "domain": "openworkproof/predicate-input/v0.1",
                "predicate_id": predicate["predicate_id"],
                "input": predicate["input"],
            }
        )
    claim = raw["nested_claim"]
    claim["arguments_digest"] = raw["arguments_digest"]
    claim = sign_payload("agent-request", claim, role_keys["Developer"][0])
    raw["nested_claim"] = claim
    raw["nested_claim_digest"] = claim["digest"]
    receipt = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload("action-receipt", raw, role_keys["Sidecar"][0])
    )
    payloads = {
        receipt.evidence_refs[0].path: patch_bytes,
        receipt.evidence_refs[1].path: result_bytes,
    }
    evidence.complete_receipt_publication(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        receipt=receipt,
        payloads=payloads,
        clock=lambda: now,
        trusted_resolution_manifest=manifest,
    )
    checkpoint = ReplayCheckpoint(
        files=(),
        head_commit=candidate_commit,
        workspace_manifest=candidate_manifest,
        workspace_manifest_digest=candidate_manifest_digest,
        verified_test_results=(),
    )
    committed = tuple(
        CommittedEvidence(
            reference=reference,
            payload=payloads[reference.path],
        )
        for reference in receipt.evidence_refs
    )
    return receipt, checkpoint, committed


def _m2_through_patch(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
):
    """Steps 2-3: repo_read then apply_patch (active patch checkpoint)."""
    case = _m2_through_repo_read(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
    )
    patch_receipt, checkpoint, _ = _m2_append_active_patch(
        case=case,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    case["patch_receipt"] = patch_receipt
    case["checkpoint"] = checkpoint
    # Keep the derived context on the *active-patch* checkpoint so that
    # ``_current_run_tests_context`` (which reuses context.replay_checkpoint)
    # validates the active-patch binding against the correct head commit.
    case["context"] = _refresh_context(case, checkpoint, fixed_now)
    return case


def _m2_through_proof_ready(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
):
    """Steps 2-7: repo_read → patch → local verification → compose →
    independent Verifier → recompose (proof_ready)."""
    case = _m2_through_patch(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
    )
    # Step 4-5: verifier-mode local verification → locally_verified.
    context = _refresh_context(case, case["checkpoint"], fixed_now)
    request, arguments, facts = _verifier_run_tests_request(
        case, case["checkpoint"], ephemeral_role_keys, fixed_now
    )
    case["request"] = request
    case["arguments"] = arguments
    case["facts"] = facts
    snapshot_request = _run_tests_snapshot_request(case, tmp_path)
    _execute_run_tests_case(
        case,
        tmp_path,
        ephemeral_role_keys,
        _FakeRunTestsExecutionDriver(),
        context=context,
        request=request,
        request_arguments=arguments,
        execution_facts=facts,
        candidate_snapshot_request=snapshot_request,
        now=fixed_now,
    )
    locally_verified = _current_run_tests_context(case, fixed_now)
    assert locally_verified.current_state == "locally_verified"

    # Step 5: Manager first compose → evidence_incomplete.
    compose_request = _signed_compose_request(
        case,
        locally_verified,
        ephemeral_role_keys,
        fixed_now,
        previous_report_digest=None,
        nonce_label="m2:first-compose",
    )
    first = acceptance.compose_proof_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=locally_verified,
        request=compose_request,
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        clock=lambda: fixed_now,
    )
    assert first.report.verifier_conclusion == "evidence_incomplete"
    first_digest = acceptance.composition_report_digest(first.report)
    case["first_report"] = first
    case["first_digest"] = first_digest

    # Step 6: independent Verifier run_tests (fresh context).
    _execute_independent_run(
        case,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        execution_context_id="a1" * 32,
        container_instance_id_digest="b1" * 32,
        nonce_label="m2:independent",
    )
    refreshed = _current_run_tests_context(case, fixed_now)
    assert refreshed.current_state == "evidence_incomplete"

    # Step 7: Manager recompose → proof_ready.
    recompose_request = _recompose_request(
        case,
        refreshed,
        ephemeral_role_keys,
        fixed_now,
        previous_report_digest=first_digest,
        nonce_label="m2:recompose",
    )
    second = acceptance.compose_proof_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=refreshed,
        request=recompose_request,
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        clock=lambda: fixed_now,
    )
    assert second.report.verifier_conclusion == "proof_ready"
    case["second_report"] = second
    return case


# ---------------------------------------------------------------------------
# Step 1-2: running → repo_read (pipeline-backed handler)
# ---------------------------------------------------------------------------

def test_m2_steps_1_and_2_init_and_repo_read(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case = _m2_through_repo_read(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
    )
    # Step 1: WorkOrder running with the root grant activated.
    assert case["context"].current_state == "running"
    # Step 2: repo_read receipt committed with the exact output digest.
    receipt = case["repo_read_receipt"]
    assert receipt.tool_name == "owp.repo_read"
    assert receipt.policy_decision == "allow"
    assert receipt.execution_status == "succeeded"
    expected_output = hashlib.sha256(
        rfc8785.dumps(
            {
                "path": "src/wrap.py",
                "content_sha256": hashlib.sha256(
                    WRAP_CANDIDATE.encode("utf-8")
                ).hexdigest(),
                "size_bytes": len(WRAP_CANDIDATE),
                "workspace_manifest_digest": case["manifest_digest"],
            }
        )
    ).hexdigest()
    assert receipt.output_digest == expected_output
    import sqlite3 as _sql

    connection = _sql.connect(case["ledger_path"])
    try:
        rows = connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE receipt_json LIKE "
            "'%owp.repo_read%'"
        ).fetchone()[0]
    finally:
        connection.close()
    assert rows == 1


# ---------------------------------------------------------------------------
# Step 3: Developer apply_patch → active patch on the same chain
# ---------------------------------------------------------------------------

def test_m2_step_3_apply_patch_activates_patch(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case = _m2_through_patch(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
    )
    patch_receipt = case["patch_receipt"]
    assert patch_receipt.tool_name == "owp.apply_patch"
    assert patch_receipt.policy_decision == "allow"
    assert patch_receipt.execution_status == "succeeded"
    assert case["checkpoint"].head_commit != case["manifest_digest"]
    # The active patch is now the checkpoint head; context rebuilds over it.
    context = _refresh_context(case, case["checkpoint"], fixed_now)
    assert context.active_patch_receipt_id == patch_receipt.receipt_id


# ---------------------------------------------------------------------------
# Step 4-5: Developer run_tests + local verification → locally_verified
# ---------------------------------------------------------------------------

def test_m2_steps_4_and_5_run_tests_and_local_verification(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case = _m2_through_patch(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
    )
    context = _refresh_context(case, case["checkpoint"], fixed_now)
    request, arguments, facts = _verifier_run_tests_request(
        case, case["checkpoint"], ephemeral_role_keys, fixed_now
    )
    case["request"] = request
    case["arguments"] = arguments
    case["facts"] = facts
    snapshot_request = _run_tests_snapshot_request(case, tmp_path)
    receipt = _execute_run_tests_case(
        case,
        tmp_path,
        ephemeral_role_keys,
        _FakeRunTestsExecutionDriver(),
        context=context,
        request=request,
        request_arguments=arguments,
        execution_facts=facts,
        candidate_snapshot_request=snapshot_request,
        now=fixed_now,
    )
    assert receipt.tool_name == "owp.run_tests"
    assert receipt.execution_status == "succeeded"
    refreshed = _current_run_tests_context(case, fixed_now)
    assert refreshed.current_state == "locally_verified"


# ---------------------------------------------------------------------------
# Step 6-7: compose → evidence_incomplete → independent Verifier → proof_ready
# ---------------------------------------------------------------------------

def test_m2_steps_6_and_7_compose_independent_recompose(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case = _m2_through_proof_ready(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
    )
    first = case["first_report"]
    second = case["second_report"]
    assert first.report.verifier_conclusion == "evidence_incomplete"
    coverage = dict(first.report.evidence_coverage)
    assert coverage["independent_result"] is False
    assert second.report.verifier_conclusion == "proof_ready"
    proof_ready = _current_run_tests_context(case, fixed_now)
    assert proof_ready.current_state == "proof_ready"
    assert proof_ready.replay_checkpoint.head_commit == case["checkpoint"].head_commit
    # Two reports: the first is immutable, the second closes the chain.
    import sqlite3 as _sql

    connection = _sql.connect(case["ledger_path"])
    try:
        reports = connection.execute(
            "SELECT COUNT(*) FROM composition_reports"
        ).fetchone()[0]
    finally:
        connection.close()
    assert reports == 2


# ---------------------------------------------------------------------------
# Step 8-9: request_acceptance → external Acceptor signature → accepted →
# offline bundle verification
# ---------------------------------------------------------------------------

def test_m2_steps_8_and_9_external_acceptor_and_offline_verify(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from datetime import datetime, timezone  # noqa: PLC0415

    case = _m2_through_proof_ready(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
    )
    proof_ready = _current_run_tests_context(case, fixed_now)
    second = case["second_report"]

    # Step 8: request_acceptance → prepare draft → external Acceptor signs it.
    manager = ephemeral_role_keys["Manager"][1]
    scope = {
        "work_order_digest": case["work_order"].digest,
        "operation": "submit_final_acceptance",
        "composition_report_digest": acceptance.composition_report_digest(
            second.report
        ),
    }
    target_action_digest = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/final-acceptance-action/v0.1",
                "requested_scope": scope,
            }
        )
    ).hexdigest()
    arguments = {
        "request_kind": "final_acceptance",
        "target_action_digest": target_action_digest,
        "required_role": "Acceptor",
        "requested_scope": scope,
        "expires_at": "2026-01-01T00:30:00Z",
    }
    request_receipt = acceptance.request_acceptance_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=proof_ready,
        request=AgentRequest.model_validate(
            sign_payload(
                "agent-request",
                {
                    "claim_type": "agent-request",
                    "work_order_digest": case["work_order"].digest,
                    "grant_id": case["root"].grant_id,
                    "actor_id": manager["subject_id"],
                    "actor_key_id": manager["key_id"],
                    "tool_name": "owp.request_acceptance",
                    "arguments_digest": request_arguments_digest(
                        "owp.request_acceptance", arguments
                    ),
                    "nonce": _grant_id("m2:acceptance-request"),
                    "requested_at": fixed_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "authentication_method": "agent_signature",
                    "model_id": "model",
                    "model_version": "1",
                    "prompt_template_digest": "a" * 64,
                    "context_source_digest": "b" * 64,
                },
                ephemeral_role_keys["Manager"][0],
            )
        ),
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        expires_at=datetime(2026, 1, 1, 0, 30, 0, tzinfo=timezone.utc),
        clock=lambda: fixed_now,
    )
    assert request_receipt.request_kind == "final_acceptance"
    awaiting = _current_run_tests_context(case, fixed_now)
    assert awaiting.current_state == "awaiting_human"

    draft = acceptance.prepare_acceptance(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=awaiting,
        clock=lambda: fixed_now,
    )
    acceptor = _AcceptorProcess(
        _key_hex(ephemeral_role_keys["Acceptor"][0]),
        port=_free_port(),
    )
    try:
        signed = ExternalAcceptorClient(
            port=acceptor.port, timeout=5.0
        ).sign_acceptance(draft)
    finally:
        acceptor.stop()
    committed = acceptance.commit_acceptance(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=awaiting,
        acceptance=signed,
        public_keys=None,
        clock=lambda: fixed_now,
    )
    assert committed.acceptance_id == signed.acceptance_id
    terminal = _current_run_tests_context(case, fixed_now)
    assert terminal.current_state == "accepted"

    # Step 9: export the evidence bundle and verify it offline.
    work_order = case["work_order"]
    report = acceptance._current_report(case["ledger_path"], work_order)
    import sqlite3 as _sql  # noqa: PLC0415

    connection = _sql.connect(case["ledger_path"])
    try:
        report_rows = connection.execute(
            "SELECT report_json FROM composition_reports "
            "ORDER BY source_state_version"
        ).fetchall()
    finally:
        connection.close()
    reports = tuple(
        acceptance.CompositionReport.model_validate_json(row[0])
        for row in report_rows
    )
    receipts, grants, attempts = _grant_replay_inputs(
        case["ledger_path"], work_order
    )
    committed_evidence = []
    for receipt in receipts:
        for reference in receipt.evidence_refs:
            payload = (
                case["evidence_root"] / reference.path.removeprefix("evidence/")
            ).read_bytes()
            committed_evidence.append(
                CommittedEvidence(reference=reference, payload=payload)
            )
    committed_evidence.sort(key=lambda item: item.reference.path.encode())
    public_keys = {
        binding.key_id: decode_and_verify_key_binding(binding)
        for binding in work_order.key_bindings
    }
    verified = acceptance.verify_acceptance_bundle(
        work_order=work_order,
        report=report,
        effective_grants=tuple(
            sorted(grants.values(), key=lambda item: item.grant_id)
        ),
        grant_attempts=tuple(
            sorted(attempts.values(), key=lambda item: item.digest)
        ),
        receipts=receipts,
        committed_evidence=tuple(committed_evidence),
        acceptance_receipt=signed,
        public_keys=public_keys,
        reports=reports,
    )
    assert verified.acceptance_id == signed.acceptance_id
    assert report.verifier_conclusion == "proof_ready"
