"""Deterministic GitHub Actions projection into neutral environment evidence."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
import os
from pathlib import Path
import re
import stat
from typing import Any, Literal

import rfc8785
from pydantic import ConfigDict, model_validator

from openworkproof.environment_fingerprint import (
    EnvironmentFingerprintPayloadV01,
    derive_environment_allowlist_digest,
)
from openworkproof.models import CanonicalUTCTime, Digest64, ProtocolModel


__all__ = [
    "GitHubExecutionSourceV01",
    "GitHubSurfaceError",
    "project_github_environment",
]

_SOURCE_SCHEMA = "openworkproof-github-execution-source/0.1"
_OID40 = re.compile(r"^[0-9a-f]{40}$")
_MAX_EVENT_BYTES = 1024 * 1024
_MAX_TEXT_BYTES = 1024


class GitHubSurfaceError(RuntimeError):
    """GitHub execution metadata cannot be projected safely."""


def _required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name)
    if type(value) is not str or not value:
        raise GitHubSurfaceError(f"required GitHub field is missing: {name}")
    return value


def _optional_digest(environment: Mapping[str, str], name: str) -> str | None:
    value = environment.get(name)
    if value in {None, ""}:
        return None
    if type(value) is not str:
        raise GitHubSurfaceError(f"GitHub digest field is invalid: {name}")
    return value


def _read_event(path_value: str) -> dict[str, Any]:
    path = Path(path_value)
    descriptor = -1
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > _MAX_EVENT_BYTES
        ):
            raise GitHubSurfaceError("GitHub event payload is not a safe regular file")
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        )
        opened = os.fstat(descriptor)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
        )
        if identity != (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
        ):
            raise GitHubSurfaceError("GitHub event payload changed before read")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(payload) != opened.st_size or identity != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise GitHubSurfaceError("GitHub event payload changed while read")
    except GitHubSurfaceError:
        raise
    except OSError as error:
        raise GitHubSurfaceError("GitHub event payload cannot be read") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        event = json.loads(payload)
    except (UnicodeDecodeError, ValueError) as error:
        raise GitHubSurfaceError("GitHub event payload is not valid JSON") from error
    if type(event) is not dict:
        raise GitHubSurfaceError("GitHub event payload must be a JSON object")
    return event


def _repository_name(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value.encode("utf-8")) > _MAX_TEXT_BYTES
        or "\x00" in value
    ):
        raise GitHubSurfaceError(f"{label} is invalid")
    return value


def _pr_facts(
    event_name: str,
    event: dict[str, Any],
    repository: str,
) -> tuple[str | None, str | None, bool]:
    event_repository = event.get("repository")
    if type(event_repository) is not dict:
        raise GitHubSurfaceError("GitHub event repository is missing")
    event_repository_name = _repository_name(
        event_repository.get("full_name"), "GitHub event repository"
    )
    if event_repository_name != repository:
        raise GitHubSurfaceError("GitHub repository identity drift")
    if event_name != "pull_request":
        return None, None, False
    pull_request = event.get("pull_request")
    if type(pull_request) is not dict:
        raise GitHubSurfaceError("pull request payload is missing")
    head = pull_request.get("head")
    base = pull_request.get("base")
    if type(head) is not dict or type(base) is not dict:
        raise GitHubSurfaceError("pull request repository facts are missing")
    head_repository = head.get("repo")
    base_repository = base.get("repo")
    if type(head_repository) is not dict or type(base_repository) is not dict:
        raise GitHubSurfaceError("pull request repository facts are missing")
    head_name = _repository_name(
        head_repository.get("full_name"), "pull request head repository"
    )
    base_name = _repository_name(
        base_repository.get("full_name"), "pull request base repository"
    )
    head_sha = head.get("sha")
    if type(head_sha) is not str or _OID40.fullmatch(head_sha) is None:
        raise GitHubSurfaceError("pull request head revision is invalid")
    fork = head_repository.get("fork") is True or head_name != base_name
    if base_name != repository:
        raise GitHubSurfaceError("pull request base repository drift")
    return head_sha, head_name, fork


class GitHubExecutionSourceV01(ProtocolModel):
    """Allowlisted GitHub source facts; never a platform authority proof."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="subclass-instances",
    )

    schema_version: Literal["openworkproof-github-execution-source/0.1"]
    repository: str
    event_name: Literal["pull_request", "push", "workflow_dispatch"]
    event_sha: str
    pr_head_sha: str | None
    pr_head_repository: str | None
    fork_source: bool
    workflow_ref: str
    job: str
    run_id: str
    run_attempt: str
    runner_os: str
    runner_arch: str
    runner_image_digest: Digest64 | None
    container_image_digest: Digest64 | None
    toolchain_lock_digest: Digest64 | None
    sandbox_policy_digest: Digest64 | None
    command_digest: Digest64
    arguments_digest: Digest64
    environment_allowlist_digest: Digest64
    collected_at: CanonicalUTCTime
    collector_actor_id: str

    @model_validator(mode="after")
    def _closed_source(self) -> GitHubExecutionSourceV01:
        if _OID40.fullmatch(self.event_sha) is None:
            raise ValueError("GitHub event revision is invalid")
        if self.pr_head_sha is not None and _OID40.fullmatch(
            self.pr_head_sha
        ) is None:
            raise ValueError("pull request head revision is invalid")
        for label, value in (
            ("repository", self.repository),
            ("workflow_ref", self.workflow_ref),
            ("job", self.job),
            ("run_id", self.run_id),
            ("run_attempt", self.run_attempt),
            ("runner_os", self.runner_os),
            ("runner_arch", self.runner_arch),
            ("collector_actor_id", self.collector_actor_id),
        ):
            _repository_name(value, label)
        if not self.run_id.isdecimal() or not self.run_attempt.isdecimal():
            raise ValueError("GitHub run identity must use decimal strings")
        if self.event_name == "pull_request" and self.pr_head_sha is None:
            raise ValueError("pull request source requires a head revision")
        if self.event_name != "pull_request" and (
            self.pr_head_sha is not None
            or self.pr_head_repository is not None
            or self.fork_source
        ):
            raise ValueError("non-PR source cannot carry pull request facts")
        return self

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str]
    ) -> GitHubExecutionSourceV01:
        if not isinstance(environment, Mapping):
            raise GitHubSurfaceError("GitHub environment must be a mapping")
        repository = _required(environment, "GITHUB_REPOSITORY")
        event_name = _required(environment, "GITHUB_EVENT_NAME")
        event = _read_event(_required(environment, "GITHUB_EVENT_PATH"))
        pr_head_sha, pr_head_repository, fork_source = _pr_facts(
            event_name, event, repository
        )
        runner_os = _required(environment, "RUNNER_OS")
        runner_arch = _required(environment, "RUNNER_ARCH")
        runner_image_digest = _optional_digest(
            environment, "OWP_RUNNER_IMAGE_DIGEST"
        )
        container_image_digest = _optional_digest(
            environment, "OWP_CONTAINER_IMAGE_DIGEST"
        )
        toolchain_lock_digest = _optional_digest(
            environment, "OWP_TOOLCHAIN_LOCK_DIGEST"
        )
        sandbox_policy_digest = _optional_digest(
            environment, "OWP_SANDBOX_POLICY_DIGEST"
        )
        command_digest = _required(environment, "OWP_COMMAND_DIGEST")
        arguments_digest = _required(environment, "OWP_ARGUMENTS_DIGEST")
        allowlist_digest = derive_environment_allowlist_digest(
            runner_os=runner_os,
            runner_arch=runner_arch,
            runner_image_digest=runner_image_digest,
            container_image_digest=container_image_digest,
            toolchain_lock_digest=toolchain_lock_digest,
            command_digest=command_digest,
            arguments_digest=arguments_digest,
            sandbox_policy_digest=sandbox_policy_digest,
        )
        try:
            return cls(
                schema_version=_SOURCE_SCHEMA,
                repository=repository,
                event_name=event_name,
                event_sha=_required(environment, "GITHUB_SHA"),
                pr_head_sha=pr_head_sha,
                pr_head_repository=pr_head_repository,
                fork_source=fork_source,
                workflow_ref=_required(environment, "GITHUB_WORKFLOW_REF"),
                job=_required(environment, "GITHUB_JOB"),
                run_id=_required(environment, "GITHUB_RUN_ID"),
                run_attempt=_required(environment, "GITHUB_RUN_ATTEMPT"),
                runner_os=runner_os,
                runner_arch=runner_arch,
                runner_image_digest=runner_image_digest,
                container_image_digest=container_image_digest,
                toolchain_lock_digest=toolchain_lock_digest,
                sandbox_policy_digest=sandbox_policy_digest,
                command_digest=command_digest,
                arguments_digest=arguments_digest,
                environment_allowlist_digest=allowlist_digest,
                collected_at=_required(environment, "OWP_COLLECTED_AT"),
                collector_actor_id=_required(
                    environment, "OWP_COLLECTOR_ACTOR_ID"
                ),
            )
        except GitHubSurfaceError:
            raise
        except Exception as error:
            raise GitHubSurfaceError("GitHub execution source is invalid") from error


def project_github_environment(
    source: GitHubExecutionSourceV01,
    *,
    expected_revision: str,
) -> EnvironmentFingerprintPayloadV01:
    """Project allowlisted platform facts into the neutral companion model."""

    try:
        rebuilt = GitHubExecutionSourceV01.model_validate(
            source.model_dump(mode="json", warnings="error")
        )
    except Exception as error:
        raise GitHubSurfaceError("GitHub execution source is invalid") from error
    if type(expected_revision) is not str or _OID40.fullmatch(
        expected_revision
    ) is None:
        raise GitHubSurfaceError("expected source revision is invalid")
    if rebuilt.fork_source:
        raise GitHubSurfaceError("fork source requires an external trusted collector")
    authoritative_revision = (
        rebuilt.pr_head_sha
        if rebuilt.event_name == "pull_request"
        else rebuilt.event_sha
    )
    if authoritative_revision != expected_revision:
        raise GitHubSurfaceError("source revision drift")
    workflow_projection = {
        "repository": rebuilt.repository,
        "event_name": rebuilt.event_name,
        "event_sha": rebuilt.event_sha,
        "pr_head_sha": rebuilt.pr_head_sha,
        "workflow_ref": rebuilt.workflow_ref,
        "job": rebuilt.job,
        "run_id": rebuilt.run_id,
        "run_attempt": rebuilt.run_attempt,
    }
    workflow_identity_digest = hashlib.sha256(
        rfc8785.dumps(workflow_projection)
    ).hexdigest()
    axes = (
        (rebuilt.runner_image_digest, "RUNNER_IMAGE_UNAVAILABLE"),
        (rebuilt.container_image_digest, "CONTAINER_DIGEST_UNAVAILABLE"),
        (rebuilt.toolchain_lock_digest, "TOOLCHAIN_LOCK_UNAVAILABLE"),
        (rebuilt.sandbox_policy_digest, "SANDBOX_POLICY_UNAVAILABLE"),
    )
    missing = tuple(
        sorted(
            (reason for value, reason in axes if value is None),
            key=lambda value: value.encode("utf-8"),
        )
    )
    try:
        return EnvironmentFingerprintPayloadV01.model_validate({
            "schema_version": "openworkproof-execution-environment/0.1",
            "source_revision": authoritative_revision,
            "runner_os": rebuilt.runner_os,
            "runner_arch": rebuilt.runner_arch,
            "runner_image_digest": rebuilt.runner_image_digest,
            "container_image_digest": rebuilt.container_image_digest,
            "toolchain_lock_digest": rebuilt.toolchain_lock_digest,
            "command_digest": rebuilt.command_digest,
            "arguments_digest": rebuilt.arguments_digest,
            "environment_allowlist_digest": rebuilt.environment_allowlist_digest,
            "sandbox_policy_digest": rebuilt.sandbox_policy_digest,
            "workflow_identity_digest": workflow_identity_digest,
            "collection_status": "complete" if not missing else "partial",
            "missing_reason_codes": missing,
            "collected_at": rebuilt.model_dump(mode="json")["collected_at"],
            "collector_actor_id": rebuilt.collector_actor_id,
        })
    except Exception as error:
        raise GitHubSurfaceError("neutral environment projection is invalid") from error
