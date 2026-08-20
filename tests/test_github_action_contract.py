"""GitHub composite action and summary boundary tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

from cryptography.hazmat.primitives import serialization
import pytest

from openworkproof.delivery_package import load_surface_facts
from openworkproof.github_action_cli import build_action_surface
from openworkproof.signing import key_id
from openworkproof.surface_bundle import verify_surface_bundle

from test_surface_bundle_v01 import surface_source
from test_verification_integrity_transactions_v05 import (
    v05_transaction_case,
    verification_profile_v03,
)


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "integrations/github/run.sh"
ACTION = ROOT / "integrations/github/action.yml"
SMOKE = ROOT / ".github/workflows/github-action-smoke.yml"
EXAMPLE = ROOT / "examples/github-action/.github/workflows/openworkproof.yml"


def test_action_never_accepts_private_key_as_cli_argument() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    assert "--private-key" not in script
    assert "OWP_COLLECTOR_PRIVATE_KEY_FILE" in script
    assert '"$GITHUB_STEP_SUMMARY"' in script
    assert '"$GITHUB_OUTPUT"' in script


def test_action_missing_required_input_is_operational_failure(
    tmp_path: Path,
) -> None:
    key = tmp_path / "collector.key"
    key.write_text("11" * 32, encoding="ascii")
    environment = {
        **os.environ,
        "OWP_COLLECTOR_PRIVATE_KEY_FILE": str(key),
        "OWP_EXPECTED_SOURCE_REVISION": "a" * 40,
        "OWP_DELIVERY_PACKAGE": str(tmp_path / "delivery"),
        "OWP_TOOLCHAIN_LOCK_FILE": str(tmp_path / "toolchain.lock"),
        "OWP_SANDBOX_POLICY_FILE": str(tmp_path / "sandbox.json"),
        "OWP_SURFACE_OUTPUT": str(tmp_path / "surface"),
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
        "GITHUB_OUTPUT": str(tmp_path / "outputs.txt"),
    }
    completed = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=tmp_path,
        env=environment,
        text=True,
        capture_output=True,
    )
    assert completed.returncode == 4
    assert "collector actor id" in completed.stderr


@pytest.mark.parametrize(
    ("decision", "expected"),
    (("VERIFIED", 0), ("REFUTED", 2), ("UNKNOWN", 3)),
)
def test_action_preserves_surface_exit_code(
    tmp_path: Path, decision: str, expected: int
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    python = fake_bin / "python"
    python.write_text(
        "#!/bin/sh\n"
        "if [ \"$3\" = build ]; then mkdir -p \"$OWP_SURFACE_OUTPUT\"; exit 0; fi\n"
        "if [ \"$3\" = write-summary ]; then\n"
        "  printf '# fixture summary\\n' >\"$5\"\n"
        "  printf 'decision=%s\\nbundle_digest=%s\\nartifact_path=%s\\n' "
        "\"$OWP_TEST_DECISION\" \"$(printf a%.0s $(seq 1 64))\" "
        "'openworkproof-evidence-bundle.tar.gz' >\"$6\"\n"
        "  exit 0\n"
        "fi\n"
        "exit 1\n",
        encoding="utf-8",
    )
    owp = fake_bin / "owp"
    owp.write_text(
        "#!/bin/sh\n"
        "printf '{\"decision_status\":\"%s\",\"reason_codes\":[],"
        "\"bundle_digest\":\"%s\"}\\n' \"$OWP_TEST_DECISION\" "
        "\"$(printf a%.0s $(seq 1 64))\"\n"
        "case \"$OWP_TEST_DECISION\" in VERIFIED) exit 0;; REFUTED) exit 2;; *) exit 3;; esac\n",
        encoding="utf-8",
    )
    tar = fake_bin / "tar"
    tar.write_text(
        "#!/bin/sh\ntouch openworkproof-evidence-bundle.tar.gz\n",
        encoding="utf-8",
    )
    for executable in (python, owp, tar):
        executable.chmod(0o700)
    key = tmp_path / "collector.key"
    key.write_text("11" * 32, encoding="ascii")
    delivery = tmp_path / "delivery"
    delivery.mkdir()
    toolchain = tmp_path / "toolchain.lock"
    sandbox = tmp_path / "sandbox.json"
    toolchain.write_text("locked", encoding="utf-8")
    sandbox.write_text("{}", encoding="utf-8")
    summary = tmp_path / "summary.md"
    output = tmp_path / "outputs.txt"
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    environment = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "OWP_TEST_DECISION": decision,
        "OWP_COLLECTOR_PRIVATE_KEY_FILE": str(key),
        "OWP_COLLECTOR_ACTOR_ID": "fixture-verifier",
        "OWP_EXPECTED_SOURCE_REVISION": "a" * 40,
        "OWP_DELIVERY_PACKAGE": str(delivery),
        "OWP_TOOLCHAIN_LOCK_FILE": str(toolchain),
        "OWP_SANDBOX_POLICY_FILE": str(sandbox),
        "OWP_SURFACE_OUTPUT": str(tmp_path / "surface"),
        "RUNNER_TEMP": str(runner_temp),
        "GITHUB_STEP_SUMMARY": str(summary),
        "GITHUB_OUTPUT": str(output),
    }
    completed = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=tmp_path,
        env=environment,
        text=True,
        capture_output=True,
    )
    assert completed.returncode == expected, completed.stderr
    assert summary.is_file()
    assert "artifact_path=openworkproof-evidence-bundle.tar.gz" in output.read_text()
    assert (tmp_path / "openworkproof-evidence-bundle.tar.gz").is_file()


def test_write_summary_is_closed_and_does_not_leak_paths(tmp_path: Path) -> None:
    result = tmp_path / "result.json"
    summary = tmp_path / "summary.md"
    outputs = tmp_path / "outputs.txt"
    result.write_text(
        json.dumps(
            {
                "decision_status": "UNKNOWN",
                "reason_codes": ["ENVIRONMENT_INCOMPLETE"],
                "bundle_digest": "a" * 64,
            }
        ),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "openworkproof.github_action_cli",
            "write-summary",
            str(result),
            str(summary),
            str(outputs),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    assert completed.returncode == 0, completed.stderr
    rendered = summary.read_text(encoding="utf-8")
    assert "谁授权" in rendered
    assert "Agent 做了什么" in rendered
    assert "谁验证" in rendered
    assert "当前能否验收" in rendered
    assert "UNKNOWN" in rendered
    assert str(tmp_path) not in rendered
    assert "不代表付款或人工验收" in rendered
    assert outputs.read_text(encoding="utf-8").splitlines() == [
        "decision=UNKNOWN",
        f"bundle_digest={'a' * 64}",
        "artifact_path=openworkproof-evidence-bundle.tar.gz",
    ]


@pytest.mark.parametrize(
    "result_payload",
    (
        {
            "decision_status": "UNKNOWN",
            "reason_codes": ["OPEN_REASON\nforged-summary"],
            "bundle_digest": "a" * 64,
        },
        {
            "decision_status": "VERIFIED",
            "reason_codes": ["ENVIRONMENT_INCOMPLETE"],
            "bundle_digest": "a" * 64,
        },
        {
            "decision_status": "UNKNOWN",
            "reason_codes": [],
            "bundle_digest": "a" * 64,
        },
    ),
)
def test_write_summary_rejects_open_or_incoherent_result_codes(
    tmp_path: Path, result_payload: dict[str, object]
) -> None:
    result = tmp_path / "result.json"
    summary = tmp_path / "summary.md"
    outputs = tmp_path / "outputs.txt"
    result.write_text(json.dumps(result_payload), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "openworkproof.github_action_cli",
            "write-summary",
            str(result),
            str(summary),
            str(outputs),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 4
    assert not summary.exists()
    assert not outputs.exists()


def test_action_helper_builds_a_real_offline_verifiable_surface(
    surface_source, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    case, package_root, _ = surface_source
    facts = load_surface_facts(package_root)
    private_key = case["keys"]["Verifier"][0]
    collector_key_id = key_id(private_key.public_key())
    key_file = tmp_path / "collector.key"
    key_file.write_text(
        private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ).hex(),
        encoding="ascii",
    )
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
                        "sha": facts.source_revision,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    environment = {
        "GITHUB_REPOSITORY": "example/openworkproof",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_EVENT_PATH": str(event),
        "GITHUB_SHA": "f" * 40,
        "GITHUB_WORKFLOW_REF": "example/openworkproof/.github/workflows/owp.yml@refs/pull/42/merge",
        "GITHUB_JOB": "verify-delivery",
        "GITHUB_RUN_ID": "42",
        "GITHUB_RUN_ATTEMPT": "1",
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
        "OWP_RUNNER_IMAGE_DIGEST": "a" * 64,
        "OWP_CONTAINER_IMAGE_DIGEST": "b" * 64,
        "OWP_EXPECTED_SOURCE_REVISION": facts.source_revision,
        "OWP_COLLECTOR_ACTOR_ID": facts.trusted_verifier_subjects[
            collector_key_id
        ],
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    toolchain = tmp_path / "requirements.lock"
    sandbox = tmp_path / "sandbox.json"
    toolchain.write_text("locked", encoding="utf-8")
    sandbox.write_text("{}", encoding="utf-8")
    output = tmp_path / "surface"

    result = build_action_surface(
        package_root,
        key_file,
        toolchain,
        sandbox,
        output,
    )

    assert result["decision_status"] == "VERIFIED"
    assert verify_surface_bundle(output).report.decision_status == "VERIFIED"


def test_action_helper_closes_adapter_errors_without_traceback(
    tmp_path: Path,
) -> None:
    delivery = tmp_path / "delivery"
    delivery.mkdir()
    (delivery / "manifest.json").write_text("{}", encoding="utf-8")
    key = tmp_path / "collector.key"
    key.write_text("11" * 32, encoding="ascii")
    event = tmp_path / "event.json"
    event.write_text("{}", encoding="utf-8")
    toolchain = tmp_path / "requirements.lock"
    sandbox = tmp_path / "sandbox.json"
    toolchain.write_text("locked", encoding="utf-8")
    sandbox.write_text("{}", encoding="utf-8")
    environment = {
        **os.environ,
        "OWP_EXPECTED_SOURCE_REVISION": "a" * 40,
        "OWP_COLLECTOR_ACTOR_ID": "fixture-verifier",
        "GITHUB_REPOSITORY": "example/openworkproof",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_EVENT_PATH": str(event),
        "GITHUB_SHA": "f" * 40,
        "GITHUB_WORKFLOW_REF": "example/openworkproof/fixture.yml@main",
        "GITHUB_JOB": "fixture",
        "GITHUB_RUN_ID": "42",
        "GITHUB_RUN_ATTEMPT": "1",
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
    }
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "openworkproof.github_action_cli",
            "build",
            "--delivery-package",
            str(delivery),
            "--collector-key-file",
            str(key),
            "--toolchain-lock-file",
            str(toolchain),
            "--sandbox-policy-file",
            str(sandbox),
            "--output",
            str(tmp_path / "surface"),
        ],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 4
    assert "GitHub event repository is missing" in completed.stderr
    assert "Traceback" not in completed.stderr
    assert "11" * 32 not in completed.stderr


def test_action_and_examples_mark_fixture_and_secret_boundaries() -> None:
    action = ACTION.read_text(encoding="utf-8")
    smoke = SMOKE.read_text(encoding="utf-8")
    example = EXAMPLE.read_text(encoding="utf-8")
    readme = (ROOT / "examples/github-action/README.md").read_text(
        encoding="utf-8"
    )
    assert "collector-private-key-file" in action
    assert "actions/upload-artifact@v4" in action
    assert "fixture" in smoke.lower()
    assert "fixture" in smoke
    assert "secrets.OPENWORKPROOF_COLLECTOR_PRIVATE_KEY" in example
    assert "temporary" in readme.lower()
    assert "not production" in readme.lower()
