"""M3 delivery validation: Dify #33013 five-role demo chain.

Drives the full nine-step workflow (WorkOrder init → Developer repo_read →
apply_patch → run_tests → Manager compose → independent Verifier run_tests →
recompose → request acceptance) against a *real* application-side issue:
`Dify <https://github.com/langgenius/dify>`_ issue `#33013
<https://github.com/langgenius/dify/issues/33013>`_ — running any workflow
with a Question Classifier node crashed with::

    TypeError: LLMNode.invoke_llm() got an unexpected keyword argument
    'structured_output_enabled'

The v1.14.0-rc1 refactoring replaced the ``structured_output_enabled`` /
``structured_output`` keyword parameters of ``LLMNode.invoke_llm`` with the
unified ``structured_output_schema`` parameter, but the QuestionClassifierNode
caller was not updated. The upstream fix is PR `#32902
<https://github.com/langgenius/dify/pull/32902>`_, commit
``3a04aef82b38ce9063d0404a47df967e448f0311``; this demo pins the pre-fix
parent ``9f7bea37e562e1db3bcb202aa24e68ea120839e0``.

Two layers of validation:

1. **Functional layer** (first two tests): the trimmed candidate source is
   executable; the pre-fix caller genuinely raises ``TypeError`` against the
   post-refactor callee signature, and the genuine upstream patch applies
   cleanly to the candidate content and resolves the crash.
2. **Protocol layer** (remaining five tests): the same nine-step five-role
   evidence chain as M2 (Rich #4196), ending with a real external Acceptor
   subprocess signature over TCP and offline bundle verification.

Dify and its source code remain the property of their respective rights
holders; OpenWorkProof only owns its own protocol and the task packaging.
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
from test_delivery_m2 import (
    _AcceptorProcess,
    _free_port,
    _key_hex,
    _refresh_context,
    _verifier_run_tests_request,
)

# Pre-fix parent of the upstream fix commit 3a04aef82b38 (PR #32902).
DIFY_PINNED_COMMIT = "9f7bea37e562e1db3bcb202aa24e68ea120839e0"
DIFY_FIX_COMMIT = "3a04aef82b38ce9063d0404a47df967e448f0311"

# Repo-relative path of the buggy caller in the pinned Dify tree.
DIFY_PATH = (
    "api/core/workflow/nodes/question_classifier/"
    "question_classifier_node.py"
)

# Path of the trimmed candidate file inside the demo workspace. The
# developer grant authorizes reads/writes under ``src`` only, so the
# trimmed upstream file is packaged there (exactly as M2 packaged
# ``rich/_wrap.py`` as ``src/wrap.py``).
CANDIDATE_PATH = "src/question_classifier_node.py"

# Trimmed, executable candidate content. The keyword-argument block inside
# ``invoke_question_classifier`` is verbatim from the pinned pre-fix source
# (api/core/workflow/nodes/question_classifier/question_classifier_node.py
# @ 9f7bea37e562, the ``LLMNode.invoke_llm(...)`` call in ``_run``). The
# ``LLMNode.invoke_llm`` stub carries the *post-refactor* callee signature
# that landed in v1.14.0-rc1 — the cross-file mismatch between this new
# signature and the un-updated caller is the bug.
DIFY_QCN_CANDIDATE = '''"""Trimmed from langgenius/dify @ 9f7bea37e562 (issue #33013, pre-fix).

Cross-file mismatch captured in one executable module: the callee
(``LLMNode.invoke_llm``, v1.14.0-rc1 post-refactor signature) removed the
``structured_output_enabled`` / ``structured_output`` keyword parameters in
favour of the unified ``structured_output_schema``; the Question Classifier
caller below was not updated, so executing any workflow containing the node
raises ``TypeError: ... unexpected keyword argument
'structured_output_enabled'``.
"""

from __future__ import annotations

from typing import Any, Iterable


class LLMNode:
    """Callee side: post-refactor ``invoke_llm`` signature (v1.14.0-rc1)."""

    @staticmethod
    def invoke_llm(
        *,
        node_data_model: Any,
        model_instance: Any,
        prompt_messages: Any,
        stop: Any,
        user_id: Any,
        structured_output_schema: Any = None,
        file_saver: Any = None,
        file_outputs: Any = None,
        node_id: Any = None,
        node_type: Any = None,
    ) -> Iterable[Any]:
        return iter(())


def invoke_question_classifier(**kwargs: Any) -> Iterable[Any]:
    """Caller side: the pinned pre-fix Question Classifier invocation."""
    return LLMNode.invoke_llm(
        node_data_model=kwargs["node_data_model"],
        model_instance=kwargs["model_instance"],
        prompt_messages=kwargs["prompt_messages"],
        stop=kwargs["stop"],
        user_id=kwargs["user_id"],
        structured_output_enabled=False,
        structured_output=None,
        file_saver=kwargs["file_saver"],
        file_outputs=kwargs["file_outputs"],
        node_id=kwargs["node_id"],
        node_type=kwargs["node_type"],
    )
'''

# The genuine upstream fix (PR #32902, commit 3a04aef82b38): two lines
# deleted, one line added inside the invoke_llm call.
DIFY_FIX_PATCH = f"""--- a/{DIFY_PATH}
+++ b/{DIFY_PATH}
@@ -156,9 +156,8 @@
                 prompt_messages=prompt_messages,
                 stop=stop,
                 user_id=self.user_id,
-                structured_output_enabled=False,
-                structured_output=None,
+                structured_output_schema=None,
                 file_saver=self._llm_file_saver,
                 file_outputs=self._file_outputs,
                 node_id=self._node_id,
"""

# Exact line-level change performed by the upstream fix, used by the
# functional layer to apply the patch to the candidate content.
_PREFIX_LINES = (
    "        structured_output_enabled=False,\n"
    "        structured_output=None,\n"
)
_FIXED_LINE = "        structured_output_schema=None,\n"


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


# ---------------------------------------------------------------------------
# Functional layer: the bug and the upstream fix are real
# ---------------------------------------------------------------------------

_STUB_KWARGS = {
    "node_data_model": object(),
    "model_instance": object(),
    "prompt_messages": (),
    "stop": (),
    "user_id": "tenant-user",
    "file_saver": None,
    "file_outputs": None,
    "node_id": "question-classifier-1",
    "node_type": "question-classifier",
}


def _load_module(source: str, name: str):
    import types  # noqa: PLC0415

    module = types.ModuleType(name)
    exec(compile(source, name, "exec"), module.__dict__)
    return module


def test_dify_33013_bug_reproduces_on_pinned_source() -> None:
    """The pinned pre-fix caller crashes against the refactored callee."""
    module = _load_module(DIFY_QCN_CANDIDATE, "dify_qcn_prefix")
    with pytest.raises(TypeError, match="structured_output_enabled"):
        module.invoke_question_classifier(**_STUB_KWARGS)


def test_dify_33013_upstream_fix_applies_and_resolves() -> None:
    """The genuine upstream patch applies to the candidate and fixes it."""
    # The patch evidence names the exact removed and added lines.
    assert "-                structured_output_enabled=False," in DIFY_FIX_PATCH
    assert "-                structured_output=None," in DIFY_FIX_PATCH
    assert "+                structured_output_schema=None," in DIFY_FIX_PATCH
    # The buggy lines are present verbatim in the pinned candidate content.
    assert _PREFIX_LINES in DIFY_QCN_CANDIDATE
    assert _FIXED_LINE not in DIFY_QCN_CANDIDATE
    # Apply the fix (the same line-level change as the upstream commit).
    fixed_source = DIFY_QCN_CANDIDATE.replace(_PREFIX_LINES, _FIXED_LINE)
    assert _FIXED_LINE in fixed_source
    assert "structured_output_enabled=False," not in fixed_source
    module = _load_module(fixed_source, "dify_qcn_fixed")
    result = module.invoke_question_classifier(**_STUB_KWARGS)
    assert list(result) == []


# ---------------------------------------------------------------------------
# Protocol layer: nine-step five-role evidence chain (mirrors M2)
# ---------------------------------------------------------------------------


def _m3_case(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
):
    """Build the M3 demo case: running, repo-read manifest, no active patch."""
    import stat  # noqa: PLC0415

    from openworkproof import repo_tools  # noqa: PLC0415

    work_order = _work_order_with_pr_chain_predicates(
        signed_work_order,
        ephemeral_role_keys["Maintainer"][0],
    )
    root = _resigned_root(work_order, ephemeral_role_keys["Maintainer"][0])
    ledger_path = tmp_path / "m3-chain.sqlite3"
    evidence_root = tmp_path / "m3-chain-evidence"
    evidence_root.mkdir()
    _activate_ledger_root(
        ledger_path, work_order, root, ephemeral_role_keys, fixed_now
    )
    verifier = _child_grant(
        work_order,
        root,
        ephemeral_role_keys,
        label="m3:verifier",
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
            nonce=_grant_id("m3:verifier-request"),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    developer = _child_grant(
        work_order,
        root,
        ephemeral_role_keys,
        label="m3:developer",
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
            nonce=_grant_id("m3:developer-request"),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    # Repo-read manifest declaring the pinned Dify candidate file.
    candidate_commit = work_order.source_commit
    candidate_bytes = DIFY_QCN_CANDIDATE.encode("utf-8")
    manifest = build_workspace_manifest(
        candidate_commit,
        (
            repo_tools.WorkspaceScanRecord(
                path_bytes=CANDIDATE_PATH.encode("utf-8"),
                entry_type="regular",
                posix_mode=stat.S_IFREG | 0o644,
                size_bytes=len(candidate_bytes),
                content=candidate_bytes,
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


def _m3_repo_read_request(case, context, role_keys, now):
    arguments = RepoReadArguments(path=CANDIDATE_PATH)
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
                "nonce": _grant_id("m3:repo-read"),
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


def _m3_through_repo_read(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
):
    """Build the case and execute step 2 (repo_read of the Dify file)."""
    case = _m3_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
    )
    candidate_root = tmp_path / "candidate-repo"
    target = candidate_root / CANDIDATE_PATH
    target.parent.mkdir(parents=True)
    target.write_text(DIFY_QCN_CANDIDATE)
    request, arguments = _m3_repo_read_request(
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


def _m3_append_active_patch(
    *,
    case,
    role_keys,
    sidecar_receipt_factory,
    now,
):
    """Publish the apply-patch receipt carrying the genuine upstream fix.

    Mirrors ``_m2_append_active_patch`` but binds the real Dify patch bytes
    and the real Dify repo-relative path as the patch target and the
    resolution-manifest entry.
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

    patch_bytes = DIFY_FIX_PATCH.encode("utf-8")
    patch_digest = _h.sha256(patch_bytes).hexdigest()
    candidate_commit = "3" * 40
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
        label="m3:patch",
        actor_role="Developer",
        remaining_after=1,
        occurred_at="2026-01-01T00:00:05Z",
    )
    raw = receipt.model_dump(mode="json")
    arguments = {
        "target_paths": [CANDIDATE_PATH],
        "patch_digest": patch_digest,
        "patch_size_bytes": len(patch_bytes),
    }
    manifest = _RM(
        schema_version="openworkproof-resolution-manifest/0.1",
        workspace_manifest_digest=result["parent_manifest_digest"],
        requested_paths=(CANDIDATE_PATH,),
        resolved_entries=(
            _RME(
                requested_path=CANDIDATE_PATH,
                resolved_relative_path=CANDIDATE_PATH,
            ),
        ),
    )
    raw.update(
        {
            "request_arguments": arguments,
            "arguments_digest": _rad("owp.apply_patch", arguments),
            "output_digest": result_digest,
            # Semantic parents: developer grant issuance + the preceding
            # repo-read (tip-parent rule, as fixed for M2).
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
            predicate["input"]["requested_paths"] = [CANDIDATE_PATH]
            predicate["input"]["resolved_entries"] = [
                {
                    "requested_path": CANDIDATE_PATH,
                    "resolved_relative_path": CANDIDATE_PATH,
                }
            ]
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


def _m3_through_patch(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
):
    """Steps 2-3: repo_read then apply_patch (active patch checkpoint)."""
    case = _m3_through_repo_read(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
    )
    patch_receipt, checkpoint, _ = _m3_append_active_patch(
        case=case,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    case["patch_receipt"] = patch_receipt
    case["checkpoint"] = checkpoint
    case["context"] = _refresh_context(case, checkpoint, fixed_now)
    return case


def _m3_through_proof_ready(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
):
    """Steps 2-7: repo_read → patch → local verification → compose →
    independent Verifier → recompose (proof_ready)."""
    case = _m3_through_patch(
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
        nonce_label="m3:first-compose",
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
        execution_context_id="c3" * 32,
        container_instance_id_digest="d4" * 32,
        nonce_label="m3:independent",
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
        nonce_label="m3:recompose",
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

def test_m3_steps_1_and_2_init_and_repo_read(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case = _m3_through_repo_read(
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
                "path": CANDIDATE_PATH,
                "content_sha256": hashlib.sha256(
                    DIFY_QCN_CANDIDATE.encode("utf-8")
                ).hexdigest(),
                "size_bytes": len(DIFY_QCN_CANDIDATE.encode("utf-8")),
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
# Step 3: Developer apply_patch → active patch carrying the real Dify fix
# ---------------------------------------------------------------------------

def test_m3_step_3_apply_patch_activates_patch(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case = _m3_through_patch(
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
    # The published patch evidence is byte-identical to the upstream fix.
    patch_ref = patch_receipt.evidence_refs[0]
    published = (
        case["evidence_root"] / patch_ref.path.removeprefix("evidence/")
    ).read_bytes()
    assert published == DIFY_FIX_PATCH.encode("utf-8")
    assert patch_ref.sha256 == hashlib.sha256(published).hexdigest()
    # The active patch is now the checkpoint head; context rebuilds over it.
    context = _refresh_context(case, case["checkpoint"], fixed_now)
    assert context.active_patch_receipt_id == patch_receipt.receipt_id


# ---------------------------------------------------------------------------
# Step 4-5: run_tests + local verification → locally_verified
# ---------------------------------------------------------------------------

def test_m3_steps_4_and_5_run_tests_and_local_verification(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case = _m3_through_patch(
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

def test_m3_steps_6_and_7_compose_independent_recompose(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case = _m3_through_proof_ready(
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

def test_m3_steps_8_and_9_external_acceptor_and_offline_verify(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from datetime import datetime, timezone  # noqa: PLC0415

    case = _m3_through_proof_ready(
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
                    "nonce": _grant_id("m3:acceptance-request"),
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
