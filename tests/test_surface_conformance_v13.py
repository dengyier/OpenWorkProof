"""Cross-platform conformance tests for the shared Surface evidence core."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openworkproof.adapters.github_surface import GitHubExecutionSourceV01
from openworkproof.adapters.github_surface import project_github_environment
from openworkproof.agentteams_workflow import AgentTeamsExecutionSourceV01
from openworkproof.agentteams_workflow import project_agentteams_environment
from openworkproof.environment_fingerprint import (
    EnvironmentFingerprintPayloadV01,
    core_execution_digest,
    core_execution_projection,
)


def _github_environment(tmp_path: Path) -> dict[str, str]:
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps(
            {
                "repository": {"full_name": "example/openworkproof"},
                "pull_request": {
                    "base": {
                        "repo": {
                            "fork": False,
                            "full_name": "example/openworkproof",
                        }
                    },
                    "head": {
                        "repo": {
                            "fork": False,
                            "full_name": "example/openworkproof",
                        },
                        "sha": "a" * 40,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    return {
        "GITHUB_REPOSITORY": "example/openworkproof",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_EVENT_PATH": str(event),
        "GITHUB_SHA": "b" * 40,
        "GITHUB_WORKFLOW_REF": "example/openworkproof/verify.yml@refs/pull/1/merge",
        "GITHUB_JOB": "verify",
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "1",
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
        "OWP_RUNNER_IMAGE_DIGEST": "1" * 64,
        "OWP_CONTAINER_IMAGE_DIGEST": "2" * 64,
        "OWP_TOOLCHAIN_LOCK_DIGEST": "3" * 64,
        "OWP_COMMAND_DIGEST": "4" * 64,
        "OWP_ARGUMENTS_DIGEST": "5" * 64,
        "OWP_SANDBOX_POLICY_DIGEST": "6" * 64,
        "OWP_COLLECTED_AT": "2026-08-21T00:00:00Z",
        "OWP_COLLECTOR_ACTOR_ID": "github-verifier",
    }


def _agentteams_source(**overrides) -> AgentTeamsExecutionSourceV01:
    payload = {
        "schema_version": "openworkproof-agentteams-execution-source/0.1",
        "task_id": "7" * 64,
        "team_room_id_digest": "8" * 64,
        "message_event_digests": ["9" * 64],
        "source_revision": "a" * 40,
        "runner_os": "Linux",
        "runner_arch": "X64",
        "runner_image_digest": "1" * 64,
        "container_image_digest": "2" * 64,
        "toolchain_lock_digest": "3" * 64,
        "command_digest": "4" * 64,
        "arguments_digest": "5" * 64,
        "sandbox_policy_digest": "6" * 64,
        "collected_at": "2026-08-21T00:00:00Z",
        "collector_actor_id": "agentteams-verifier",
    }
    payload.update(overrides)
    return AgentTeamsExecutionSourceV01.model_validate(payload)


def test_github_and_agentteams_share_core_digest(tmp_path: Path) -> None:
    github_source = GitHubExecutionSourceV01.from_environment(
        _github_environment(tmp_path)
    )
    github = project_github_environment(
        github_source, expected_revision="a" * 40
    )
    agentteams = project_agentteams_environment(_agentteams_source())

    assert github.workflow_identity_digest != agentteams.workflow_identity_digest
    assert core_execution_projection(github) == core_execution_projection(
        agentteams
    )
    assert core_execution_digest(github) == core_execution_digest(agentteams)


def test_platform_metadata_and_unknown_fields_do_not_pollute_core(
    tmp_path: Path,
) -> None:
    github_environment = _github_environment(tmp_path)
    baseline = project_github_environment(
        GitHubExecutionSourceV01.from_environment(github_environment),
        expected_revision="a" * 40,
    )
    github_environment.update(
        {f"UNTRUSTED_GITHUB_FIELD_{index}": str(index) for index in range(100)}
    )
    polluted = project_github_environment(
        GitHubExecutionSourceV01.from_environment(github_environment),
        expected_revision="a" * 40,
    )
    agentteams_mapping = {
        **_agentteams_source().model_dump(mode="json"),
        **{f"untrusted_matrix_field_{index}": index for index in range(100)},
    }
    agentteams = project_agentteams_environment(
        AgentTeamsExecutionSourceV01.from_mapping(agentteams_mapping)
    )

    assert core_execution_digest(baseline) == core_execution_digest(polluted)
    assert core_execution_digest(baseline) == core_execution_digest(agentteams)


@pytest.mark.parametrize(
    "field",
    (
        "source_revision",
        "command_digest",
        "arguments_digest",
        "sandbox_policy_digest",
        "toolchain_lock_digest",
    ),
)
def test_each_core_axis_changes_the_core_digest(field: str) -> None:
    baseline = project_agentteams_environment(_agentteams_source())
    raw = _agentteams_source().model_dump(mode="json")
    raw[field] = ("f" * 40) if field == "source_revision" else ("f" * 64)
    changed = project_agentteams_environment(
        AgentTeamsExecutionSourceV01.model_validate(raw)
    )

    assert core_execution_digest(changed) != core_execution_digest(baseline)


def test_core_digest_excludes_only_platform_provenance() -> None:
    baseline = project_agentteams_environment(_agentteams_source())
    raw = baseline.model_dump(mode="json")
    raw.update(
        {
            "workflow_identity_digest": "f" * 64,
            "collected_at": "2026-08-21T00:00:01Z",
            "collector_actor_id": "another-verifier",
        }
    )
    changed = EnvironmentFingerprintPayloadV01.model_validate(raw)

    assert core_execution_digest(changed) == core_execution_digest(baseline)
