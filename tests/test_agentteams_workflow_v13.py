"""Three-role AgentTeams workflow contract tests for OpenWorkProof 1.3."""

from __future__ import annotations

import json
import os
from pathlib import Path
import runpy

import pytest

from openworkproof.agentteams_workflow import (
    AgentTeamsCommitAcknowledgementLost,
    AgentTeamsRoleBinding,
    AgentTeamsWorkflow,
    AgentTeamsWorkflowError,
    AgentTeamsWorkflowMessageV01,
)


TASK_ID = "a" * 64
ARTIFACT_DIGEST = "b" * 64
ROOT = Path(__file__).resolve().parents[1]
DEMO_SCRIPT = ROOT / "agentteams/scripts/run_openworkproof_13_demo.py"


def _binding(role: str, sender: str, digit: str) -> AgentTeamsRoleBinding:
    return AgentTeamsRoleBinding(
        role=role,
        matrix_user_id=sender,
        openworkproof_key_id=f"ed25519:{digit * 64}",
    )


@pytest.fixture
def bindings() -> tuple[AgentTeamsRoleBinding, ...]:
    return (
        _binding("Manager", "@manager:hs", "1"),
        _binding("Developer", "@developer:hs", "2"),
        _binding("Verifier", "@verifier:hs", "3"),
    )


@pytest.fixture
def workflow(bindings) -> AgentTeamsWorkflow:
    return AgentTeamsWorkflow(task_id=TASK_ID, bindings=bindings)


def _message(
    *,
    event_id: str,
    sender: str,
    role: str,
    phase: str,
    attempt: int,
    artifact_path: str | None = None,
    artifact_digest: str | None = None,
    decision: str | None = None,
    task_id: str = TASK_ID,
) -> AgentTeamsWorkflowMessageV01:
    return AgentTeamsWorkflowMessageV01(
        schema_version="openworkproof-agentteams-message/0.1",
        task_id=task_id,
        event_id=event_id,
        sender=sender,
        role=role,
        phase=phase,
        attempt=attempt,
        artifact_path=artifact_path,
        artifact_digest=artifact_digest,
        decision=decision,
    )


def _dispatch(event_id: str = "$manager-1") -> AgentTeamsWorkflowMessageV01:
    return _message(
        event_id=event_id,
        sender="@manager:hs",
        role="Manager",
        phase="dispatch",
        attempt=1,
    )


def _development(
    attempt: int,
    *,
    event_id: str | None = None,
    artifact_digest: str = ARTIFACT_DIGEST,
) -> AgentTeamsWorkflowMessageV01:
    return _message(
        event_id=event_id or f"$developer-{attempt}",
        sender="@developer:hs",
        role="Developer",
        phase="development",
        attempt=attempt,
        artifact_path="artifacts/candidate.patch",
        artifact_digest=artifact_digest,
    )


def _verification(
    attempt: int,
    decision: str,
    *,
    event_id: str | None = None,
    sender: str = "@verifier:hs",
    artifact_digest: str = ARTIFACT_DIGEST,
) -> AgentTeamsWorkflowMessageV01:
    return _message(
        event_id=event_id or f"$verifier-{attempt}",
        sender=sender,
        role="Verifier",
        phase="verification",
        attempt=attempt,
        artifact_path="artifacts/candidate.patch",
        artifact_digest=artifact_digest,
        decision=decision,
    )


def test_three_distinct_senders_complete_rework_loop(workflow) -> None:
    workflow.accept(_dispatch())
    workflow.accept(_development(1))
    workflow.accept(_verification(1, "REFUTED"))
    workflow.accept(_development(2))
    outcome = workflow.accept(_verification(2, "VERIFIED"))

    assert outcome.state == "ready_for_acceptance"
    assert outcome.attempt == 2
    assert outcome.openworkproof_key_id == f"ed25519:{'3' * 64}"


def test_role_name_with_same_sender_is_rejected(workflow) -> None:
    workflow.accept(_dispatch())
    workflow.accept(_development(1))
    forged = _verification(1, "VERIFIED", sender="@developer:hs")

    with pytest.raises(AgentTeamsWorkflowError, match="sender binding"):
        workflow.accept(forged)


def test_two_roles_cannot_share_matrix_sender_or_key(bindings) -> None:
    duplicate_sender = (
        bindings[0],
        bindings[1],
        _binding("Verifier", "@developer:hs", "3"),
    )
    duplicate_key = (
        bindings[0],
        bindings[1],
        _binding("Verifier", "@verifier:hs", "2"),
    )

    with pytest.raises(AgentTeamsWorkflowError, match="distinct senders"):
        AgentTeamsWorkflow(task_id=TASK_ID, bindings=duplicate_sender)
    with pytest.raises(AgentTeamsWorkflowError, match="distinct keys"):
        AgentTeamsWorkflow(task_id=TASK_ID, bindings=duplicate_key)


def test_exact_duplicate_event_is_idempotent_but_payload_conflict_fails(
    workflow,
) -> None:
    message = _dispatch()
    first = workflow.accept(message)
    second = workflow.accept(message)
    conflict = _message(
        event_id=message.event_id,
        sender="@developer:hs",
        role="Developer",
        phase="development",
        attempt=1,
        artifact_path="artifacts/candidate.patch",
        artifact_digest=ARTIFACT_DIGEST,
    )

    assert second == first
    with pytest.raises(AgentTeamsWorkflowError, match="event id conflict"):
        workflow.accept(conflict)


def test_out_of_order_and_wrong_task_messages_fail_closed(workflow) -> None:
    with pytest.raises(AgentTeamsWorkflowError, match="transition"):
        workflow.accept(_development(1))
    wrong_task = _message(
        event_id="$wrong-task",
        sender="@manager:hs",
        role="Manager",
        phase="dispatch",
        attempt=1,
        task_id="f" * 64,
    )
    with pytest.raises(AgentTeamsWorkflowError, match="task id"):
        workflow.accept(wrong_task)


def test_verifier_must_bind_the_developer_artifact(workflow) -> None:
    workflow.accept(_dispatch())
    workflow.accept(_development(1))

    with pytest.raises(AgentTeamsWorkflowError, match="artifact digest"):
        workflow.accept(
            _verification(1, "VERIFIED", artifact_digest="c" * 64)
        )


def test_second_non_verified_result_closes_not_ready(workflow) -> None:
    workflow.accept(_dispatch())
    workflow.accept(_development(1))
    workflow.accept(_verification(1, "UNKNOWN"))
    workflow.accept(_development(2))
    outcome = workflow.accept(_verification(2, "REFUTED"))

    assert outcome.state == "not_ready"
    assert outcome.attempt == 2
    with pytest.raises(AgentTeamsWorkflowError, match="terminal"):
        workflow.accept(_development(2, event_id="$developer-3"))


def test_matrix_event_requires_structured_body_and_raw_bindings(
    workflow,
) -> None:
    with pytest.raises(AgentTeamsWorkflowError, match="structured JSON"):
        workflow.accept_matrix_event(
            {
                "event_id": "$manager-1",
                "sender": "@manager:hs",
                "body": "DEV_RESULT token",
            }
        )
    message = _dispatch()
    wire = message.model_dump(mode="json")
    wire.pop("event_id")
    body = json.dumps(wire)
    with pytest.raises(AgentTeamsWorkflowError, match="raw sender"):
        workflow.accept_matrix_event(
            {"event_id": message.event_id, "sender": "@other:hs", "body": body}
        )
    claimed_event = {**wire, "event_id": message.event_id}
    with pytest.raises(AgentTeamsWorkflowError, match="must not claim event id"):
        workflow.accept_matrix_event(
            {
                "event_id": message.event_id,
                "sender": message.sender,
                "body": json.dumps(claimed_event),
            }
        )

    outcome = workflow.accept_matrix_event(
        {
            "event_id": message.event_id,
            "sender": message.sender,
            "body": body,
        }
    )
    assert outcome.event_id == message.event_id


def test_matrix_event_rejects_duplicate_json_keys(workflow) -> None:
    message = _dispatch()
    wire = message.model_dump(mode="json")
    wire.pop("event_id")
    body = json.dumps(wire)
    duplicate = '{"task_id":"' + ("f" * 64) + '",' + body[1:]

    with pytest.raises(AgentTeamsWorkflowError, match="structured JSON"):
        workflow.accept_matrix_event(
            {
                "event_id": message.event_id,
                "sender": message.sender,
                "body": duplicate,
            }
        )


def test_core_commit_failure_prevents_platform_announcement(bindings) -> None:
    announcements: list[object] = []

    def fail_commit(message, state) -> None:
        raise RuntimeError("ledger unavailable")

    workflow = AgentTeamsWorkflow(
        task_id=TASK_ID,
        bindings=bindings,
        commit=fail_commit,
        announce=lambda message, state: announcements.append(state),
    )

    with pytest.raises(AgentTeamsWorkflowError, match="core commit failed"):
        workflow.accept(_dispatch())
    assert workflow.state == "awaiting_dispatch"
    assert announcements == []


def test_commit_ack_loss_reads_committed_truth(bindings) -> None:
    committed = []

    def lose_ack(message, state) -> None:
        committed.append(state)
        raise AgentTeamsCommitAcknowledgementLost(state)

    workflow = AgentTeamsWorkflow(
        task_id=TASK_ID,
        bindings=bindings,
        commit=lose_ack,
    )
    outcome = workflow.accept(_dispatch())

    assert outcome.state == "awaiting_development"
    assert outcome.delivery_status == "committed"
    assert committed[0].state == outcome.state
    assert workflow.state == "awaiting_development"


def test_announcement_failure_does_not_roll_back_core_truth(bindings) -> None:
    commits: list[object] = []

    def fail_announcement(message, state) -> None:
        raise RuntimeError("Matrix ACK lost")

    workflow = AgentTeamsWorkflow(
        task_id=TASK_ID,
        bindings=bindings,
        commit=lambda message, state: commits.append(state),
        announce=fail_announcement,
    )
    outcome = workflow.accept(_dispatch())

    assert outcome.state == "awaiting_development"
    assert outcome.delivery_status == "committed_but_unannounced"
    assert workflow.state == "awaiting_development"
    assert len(commits) == 1


def test_artifact_path_is_relative_and_traversal_free() -> None:
    raw = _development(1).model_dump(mode="json")
    raw["artifact_path"] = "../secret"
    with pytest.raises(ValueError, match="artifact path"):
        AgentTeamsWorkflowMessageV01.model_validate(raw)


def _demo_module() -> dict[str, object]:
    return runpy.run_path(str(DEMO_SCRIPT), run_name="openworkproof_demo_test")


def test_v13_resources_close_three_role_permissions() -> None:
    workers = (ROOT / "agentteams/workers-v13.yaml").read_text(encoding="utf-8")
    team = (ROOT / "agentteams/team-v13.yaml").read_text(encoding="utf-8")

    assert "name: dev-worker" in workers
    assert "name: verifier-worker" in workers
    assert workers.count("runtime: copaw") == 2
    developer, verifier = workers.split("---", 1)
    assert "owp.apply_patch" in developer
    assert "owp.surface_verify" in verifier
    assert "owp.apply_patch" not in verifier
    assert "name: owp-team" in team
    assert "role: team_leader" in team
    assert "name: dev-worker" in team
    assert "name: verifier-worker" in team


def test_demo_preflight_requires_token_and_three_distinct_bindings(
    monkeypatch,
) -> None:
    module = _demo_module()
    run_live_preflight = module["run_live_preflight"]
    task_path = ROOT / "agentteams/fixtures/agentscope-2239-task.json"
    monkeypatch.delenv("AGENTTEAMS_MATRIX_TOKEN", raising=False)

    with pytest.raises(RuntimeError, match="AGENTTEAMS_MATRIX_TOKEN"):
        run_live_preflight(task_path=task_path)


def test_demo_preflight_accepts_exact_live_identity_snapshot(
    monkeypatch,
) -> None:
    module = _demo_module()
    run_live_preflight = module["run_live_preflight"]
    task_path = ROOT / "agentteams/fixtures/agentscope-2239-task.json"
    task = json.loads(task_path.read_text(encoding="utf-8"))
    senders = {
        item["role"]: item["matrix_user_id"]
        for item in task["role_bindings"]
    }

    class Controller:
        def get_managers(self):
            return [
                {
                    "name": "default",
                    "phase": "Running",
                    "matrixUserID": senders["Manager"],
                }
            ]

        def get_workers(self):
            return [
                {
                    "name": "dev-worker",
                    "phase": "Running",
                    "matrixUserID": senders["Developer"],
                },
                {
                    "name": "verifier-worker",
                    "phase": "Running",
                    "matrixUserID": senders["Verifier"],
                },
            ]

    class Matrix:
        def resolve_room_alias(self, alias):
            assert alias == "#team:hs"
            return "!team:hs"

        def joined_rooms(self):
            return ["!team:hs"]

    monkeypatch.setenv("AGENTTEAMS_MATRIX_TOKEN", "in-memory-test-token")
    result = run_live_preflight(
        task_path=task_path,
        room="#team:hs",
        controller=Controller(),
        matrix=Matrix(),
    )

    assert result.roles == ("Manager", "Developer", "Verifier")
    assert result.room_id == "!team:hs"


@pytest.mark.parametrize(
    ("terminal", "expected_exit"),
    (("ACCEPTED", 0), ("REJECTED", 2)),
)
def test_demo_main_uses_closed_human_acceptance_exit_codes(
    tmp_path,
    capsys,
    terminal,
    expected_exit,
) -> None:
    module = _demo_module()
    main = module["main"]
    main.__globals__["run_live_preflight"] = lambda **_kwargs: module[
        "LivePreflightResult"
    ](
        ("Manager", "Developer", "Verifier"),
        ("@manager:hs", "@developer:hs", "@verifier:hs"),
        (
            f"ed25519:{'1' * 64}",
            f"ed25519:{'2' * 64}",
            f"ed25519:{'3' * 64}",
        ),
        None,
    )
    expected = module["AcceptanceBundleVerificationResult"](
        schema_version="openworkproof-acceptance-bundle-result/0.1",
        terminal_decision=terminal,
        work_order_digest="1" * 64,
        surface_manifest_digest="2" * 64,
        verification_decision_digest="3" * 64,
        terminal_receipt_digest="4" * 64,
        acceptance_decision_binding_digest="5" * 64,
        boundary="not payment, settlement, legal audit, or adoption",
    )
    main.__globals__["wait_for_external_acceptance"] = (
        lambda **_kwargs: expected
    )

    exit_code = main(
        [
            "--task-file",
            str(tmp_path / "task.json"),
            "--acceptance-bundle",
            str(tmp_path / "acceptance"),
        ]
    )

    assert exit_code == expected_exit
    output = json.loads(capsys.readouterr().out)
    assert output["human_acceptance"]["terminal_decision"] == terminal
    if terminal == "REJECTED":
        assert "success" not in json.dumps(output).lower()


def test_demo_main_maps_acceptance_gate_failure_to_operational_exit(
    tmp_path,
    capsys,
) -> None:
    module = _demo_module()
    main = module["main"]
    main.__globals__["run_live_preflight"] = lambda **_kwargs: module[
        "LivePreflightResult"
    ](
        ("Manager", "Developer", "Verifier"),
        ("@manager:hs", "@developer:hs", "@verifier:hs"),
        (
            f"ed25519:{'1' * 64}",
            f"ed25519:{'2' * 64}",
            f"ed25519:{'3' * 64}",
        ),
        None,
    )
    main.__globals__["wait_for_external_acceptance"] = (
        lambda **_kwargs: (_ for _ in ()).throw(
            RuntimeError("external acceptance timed out")
        )
    )

    exit_code = main(
        [
            "--task-file",
            str(tmp_path / "task.json"),
            "--acceptance-bundle",
            str(tmp_path / "acceptance"),
        ]
    )

    assert exit_code == 4
    assert "timed out" in capsys.readouterr().err


def test_recording_wrapper_requires_explicit_privacy_attestations() -> None:
    wrapper = (
        ROOT / "agentteams/scripts/record_openworkproof_13_demo.sh"
    ).read_text(encoding="utf-8")

    assert "OWP_SCREEN_RECORD_INPUT" in wrapper
    assert "OWP_ELEMENT_TARGET_ROOM_ONLY" in wrapper
    assert "OWP_DESKTOP_NOTIFICATIONS_OFF" in wrapper
    assert "OWP_NO_VISIBLE_SECRETS" in wrapper
    assert "ffprobe" in wrapper
    assert "printf 'q\\n'" in wrapper


@pytest.mark.agentteams
def test_live_team_has_three_distinct_roles() -> None:
    if os.environ.get("OPENWORKPROOF_AGENTTEAMS_REQUIRED") != "1":
        pytest.skip("live AgentTeams not required")
    module = _demo_module()
    result = module["run_live_preflight"](
        task_path=ROOT / "agentteams/fixtures/agentscope-2239-task.json"
    )

    assert result.roles == ("Manager", "Developer", "Verifier")
    assert len(set(result.matrix_user_ids)) == 3
    assert len(set(result.openworkproof_key_ids)) == 3
