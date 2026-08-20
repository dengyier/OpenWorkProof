"""GitHub platform-source projection tests for Surface Bundle v0.1."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from openworkproof.adapters.github_surface import (
    GitHubExecutionSourceV01,
    GitHubSurfaceError,
    project_github_environment,
)


FIXTURE = Path(__file__).parent / "fixtures/github/pull_request.json"


@pytest.fixture
def fixed_github_env(tmp_path: Path) -> dict[str, str]:
    event = tmp_path / "event.json"
    event.write_bytes(FIXTURE.read_bytes())
    return {
        "GITHUB_REPOSITORY": "example/openworkproof",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_EVENT_PATH": str(event),
        "GITHUB_SHA": "b" * 40,
        "GITHUB_WORKFLOW_REF": (
            "example/openworkproof/.github/workflows/verify.yml@refs/pull/42/merge"
        ),
        "GITHUB_JOB": "verify",
        "GITHUB_RUN_ID": "123456",
        "GITHUB_RUN_ATTEMPT": "1",
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
        "OWP_RUNNER_IMAGE_DIGEST": "1" * 64,
        "OWP_CONTAINER_IMAGE_DIGEST": "2" * 64,
        "OWP_TOOLCHAIN_LOCK_DIGEST": "3" * 64,
        "OWP_SANDBOX_POLICY_DIGEST": "4" * 64,
        "OWP_COMMAND_DIGEST": "5" * 64,
        "OWP_ARGUMENTS_DIGEST": "6" * 64,
        "OWP_COLLECTED_AT": "2026-08-21T00:00:00Z",
        "OWP_COLLECTOR_ACTOR_ID": "github-verifier",
        "GITHUB_TOKEN": "must-not-leak",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "must-not-leak-either",
    }


def test_github_projection_matches_checked_out_pr_head(fixed_github_env) -> None:
    source = GitHubExecutionSourceV01.from_environment(fixed_github_env)
    payload = project_github_environment(source, expected_revision="a" * 40)
    assert source.event_sha == "b" * 40
    assert source.pr_head_sha == "a" * 40
    assert payload.source_revision == "a" * 40
    assert payload.collection_status == "complete"


def test_github_projection_rejects_revision_drift(fixed_github_env) -> None:
    source = GitHubExecutionSourceV01.from_environment(fixed_github_env)
    with pytest.raises(GitHubSurfaceError, match="source revision drift"):
        project_github_environment(source, expected_revision="b" * 40)


def test_github_source_requires_event_sha(fixed_github_env) -> None:
    fixed_github_env.pop("GITHUB_SHA")
    with pytest.raises((GitHubSurfaceError, ValidationError)):
        GitHubExecutionSourceV01.from_environment(fixed_github_env)


def test_github_projection_rejects_fork_source(fixed_github_env) -> None:
    event_path = Path(fixed_github_env["GITHUB_EVENT_PATH"])
    event = json.loads(event_path.read_bytes())
    event["pull_request"]["head"]["repo"] = {
        "fork": True,
        "full_name": "outsider/openworkproof",
    }
    event_path.write_text(json.dumps(event), encoding="utf-8")
    source = GitHubExecutionSourceV01.from_environment(fixed_github_env)
    with pytest.raises(GitHubSurfaceError, match="fork"):
        project_github_environment(source, expected_revision="a" * 40)


def test_missing_immutable_axes_are_reported_without_zero_digest(
    fixed_github_env,
) -> None:
    fixed_github_env.pop("OWP_RUNNER_IMAGE_DIGEST")
    fixed_github_env.pop("OWP_CONTAINER_IMAGE_DIGEST")
    source = GitHubExecutionSourceV01.from_environment(fixed_github_env)
    payload = project_github_environment(source, expected_revision="a" * 40)
    assert payload.collection_status == "partial"
    assert payload.runner_image_digest is None
    assert payload.container_image_digest is None
    assert payload.missing_reason_codes == (
        "CONTAINER_DIGEST_UNAVAILABLE",
        "RUNNER_IMAGE_UNAVAILABLE",
    )
    assert "0" * 64 not in payload.model_dump_json()


def test_mutable_image_tag_cannot_replace_digest(fixed_github_env) -> None:
    fixed_github_env["OWP_RUNNER_IMAGE_DIGEST"] = "ubuntu-24.04"
    with pytest.raises((GitHubSurfaceError, ValidationError)):
        GitHubExecutionSourceV01.from_environment(fixed_github_env)


def test_projection_maps_neutral_model_failure_to_adapter_error(
    fixed_github_env,
) -> None:
    fixed_github_env["RUNNER_OS"] = "x" * 65
    source = GitHubExecutionSourceV01.from_environment(fixed_github_env)
    with pytest.raises(GitHubSurfaceError, match="neutral environment"):
        project_github_environment(source, expected_revision="a" * 40)


def test_platform_secrets_and_raw_identity_do_not_enter_neutral_payload(
    fixed_github_env,
) -> None:
    source = GitHubExecutionSourceV01.from_environment(fixed_github_env)
    source_dump = source.model_dump_json()
    payload = project_github_environment(source, expected_revision="a" * 40)
    neutral_dump = payload.model_dump_json()
    assert "must-not-leak" not in source_dump
    assert "GITHUB_TOKEN" not in source_dump
    assert "example/openworkproof" not in neutral_dump
    assert "123456" not in neutral_dump
    assert "verify.yml" not in neutral_dump
    assert payload.workflow_identity_digest is not None


class _TrackedEnvironment(dict):
    def __iter__(self):
        raise AssertionError("full environment traversal is forbidden")

    def items(self):
        raise AssertionError("full environment traversal is forbidden")

    def keys(self):
        raise AssertionError("full environment traversal is forbidden")


def test_from_environment_reads_only_explicit_allowlist(fixed_github_env) -> None:
    source = GitHubExecutionSourceV01.from_environment(
        _TrackedEnvironment(fixed_github_env)
    )
    assert source.repository == "example/openworkproof"


def test_push_event_binds_expected_revision_to_github_sha(
    fixed_github_env,
) -> None:
    fixed_github_env["GITHUB_EVENT_NAME"] = "push"
    Path(fixed_github_env["GITHUB_EVENT_PATH"]).write_text(
        '{"repository":{"full_name":"example/openworkproof"}}',
        encoding="utf-8",
    )
    source = GitHubExecutionSourceV01.from_environment(fixed_github_env)
    payload = project_github_environment(source, expected_revision="b" * 40)
    assert payload.source_revision == "b" * 40
