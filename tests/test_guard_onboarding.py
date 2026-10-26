"""Review, native exact trust, and probe identity must agree before a task."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from openworkproof import codex_host, guard_cli, guard_onboarding, guard_probe


@pytest.fixture
def setup(tmp_path, monkeypatch):
    project = tmp_path / "project"
    allowed = project / "preview"
    allowed.mkdir(parents=True)
    state = tmp_path / "state"
    executable = tmp_path / "codex"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    installed = guard_cli._install(project, allowed, state)
    directory = Path(installed["state_directory"])
    behavior = {"override": {}, "duplicate": False, "seen_reviews": [], "probe_calls": 0,
                "version": "0.147.0", "during_probe": None, "bad_probe": False}

    class Host:
        def __init__(self, *, executable, project, reviewed_hook=None):
            self.reviewed = reviewed_hook
            behavior["seen_reviews"].append(reviewed_hook)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def list_hooks(self):
            entry = json.loads((project / ".codex/hooks.json").read_text())["hooks"]["PreToolUse"][-1]
            digest = "sha256:" + hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
            h = {"key": str(project / ".codex/hooks.json") + ":pre_tool_use:0:0",
                 "currentHash": digest, "sourcePath": str(project / ".codex/hooks.json"),
                 "source": "project", "eventName": "preToolUse", "handlerType": "command",
                 "command": entry["hooks"][0]["command"], "matcher": "*", "timeoutSec": 5,
                 "enabled": True, "isManaged": False,
                 "trustStatus": "trusted" if self.reviewed == {"key": str(project / ".codex/hooks.json") + ":pre_tool_use:0:0", "currentHash": digest} else "untrusted"}
            h.update(behavior["override"])
            return {"cwd": str(project), "hooks": [h, dict(h)] if behavior["duplicate"] else [h], "warnings": [], "errors": []}

    def probe(**kwargs):
        behavior["probe_calls"] += 1
        if behavior["during_probe"]:
            behavior["during_probe"]()
        return {"status": "passed", "checks": {} if behavior["bad_probe"] else {key: True for key in guard_probe.REQUIRED_CHECKS},
                "codes": [], "started_at": "2026-10-26T12:00:00+00:00", "finished_at": "2026-10-26T12:00:01+00:00"}

    monkeypatch.setattr(codex_host, "CodexHost", Host)
    monkeypatch.setattr(codex_host, "codex_version", lambda exe: behavior["version"])
    monkeypatch.setattr(guard_probe, "perform_probe", probe)
    return project, allowed, state, executable, directory, behavior


def enable(setup):
    p, _, s, exe, _, _ = setup
    return guard_onboarding.enable(p, s, executable=str(exe), trust_own_hook=True)


def doctor(setup):
    p, _, s, exe, _, _ = setup
    return guard_onboarding.doctor(p, s, executable=str(exe))


def test_installed_and_local_log_are_not_activation(setup):
    _, _, _, _, directory, _ = setup
    (directory / "events.jsonl").write_text('{"decision":"allow"}\n')
    result = doctor(setup)
    assert result["configured"] is True
    assert result["review_status"] == "missing"
    assert result["ready_for_guarded_run"] is False
    assert result["ordinary_startup_verified"] is False


def test_enable_requires_explicit_own_hook_consent(setup):
    p, _, s, exe, directory, behavior = setup
    with pytest.raises(guard_onboarding.OnboardingError):
        guard_onboarding.enable(p, s, executable=str(exe))
    assert not (directory / "review.json").exists()
    assert behavior["probe_calls"] == 0


def test_enable_records_native_key_hash_and_checks_actual_session_trust(setup):
    result = enable(setup)
    assert result["ready_for_guarded_run"] is True
    assert result["host_trust_status"] == "trusted"
    assert result["activation_scope"] == "guarded_codex_invocation"
    assert result["ordinary_startup_verified"] is False
    review = json.loads((setup[4] / "review.json").read_text())
    assert review["identity"]["hook_key"].endswith(":pre_tool_use:0:0")
    assert review["identity"]["hook_hash"].startswith("sha256:")
    assert setup[5]["probe_calls"] == 1
    assert any(x is not None for x in setup[5]["seen_reviews"])


@pytest.mark.parametrize("changed", [
    {"source": "user"}, {"sourcePath": "/another/hooks.json"},
    {"handlerType": "mcpTool"}, {"eventName": "postToolUse"},
    {"isManaged": True}, {"enabled": False}, {"matcher": "Bash"},
    {"timeoutSec": 500}, {"command": "curl attacker.invalid"},
    {"currentHash": "self-reported"}, {"key": "another-key"},
])
def test_nearby_or_unverifiable_hook_cannot_be_authorized(setup, changed):
    setup[5]["override"] = changed
    with pytest.raises(guard_onboarding.OnboardingError):
        enable(setup)
    assert not (setup[4] / "review.json").exists()


def test_ambiguous_native_inventory_is_not_authorized(setup):
    setup[5]["duplicate"] = True
    with pytest.raises(guard_onboarding.OnboardingError):
        enable(setup)
    assert not (setup[4] / "review.json").exists()


def test_reviewed_identity_cannot_change_during_user_confirmation(setup):
    p, _, s, exe, directory, _ = setup
    summary = guard_onboarding.review_summary(p, s, executable=str(exe))
    exe.write_text("#!/bin/sh\n# changed before confirmation\nexit 0\n")
    with pytest.raises(guard_onboarding.OnboardingError):
        guard_onboarding.enable(p, s, executable=str(exe), trust_own_hook=True,
                                reviewed_identity=summary["identity"])
    assert not (directory / "review.json").exists()


@pytest.mark.parametrize("change", ["codex_bytes", "codex_version", "reinstall", "upgrade"])
def test_old_review_and_probe_do_not_survive_identity_changes(setup, monkeypatch, change):
    assert enable(setup)["ready_for_guarded_run"]
    p, allowed, s, exe, _, behavior = setup
    behavior["seen_reviews"].clear()
    if change == "codex_bytes":
        exe.write_text("#!/bin/sh\n# new bytes\nexit 0\n")
    elif change == "codex_version":
        behavior["version"] = "0.148.0"
    elif change == "reinstall":
        guard_cli._uninstall(p, s)
        guard_cli._install(p, allowed, s)
    else:
        source = p.parent / "new_runtime.py"
        source.write_bytes(guard_cli.RUNTIME_SOURCE.read_bytes() + b"\n# upgrade\n")
        monkeypatch.setattr(guard_cli, "RUNTIME_SOURCE", source)
        guard_cli._install(p, allowed, s, upgrade=True)
    result = doctor(setup)
    assert not result["ready_for_guarded_run"]
    assert result["review_status"] == "outdated"
    assert behavior["seen_reviews"] == [None]


def test_empty_probe_checks_cannot_turn_status_green(setup):
    setup[5]["bad_probe"] = True
    result = enable(setup)
    assert not result["ready_for_guarded_run"]
    assert result["probe_status"] != "passed"


def test_drift_during_probe_invalidates_the_record(setup):
    def change():
        config = setup[0] / ".codex/hooks.json"
        d = json.loads(config.read_text())
        d["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] = 6
        config.write_text(json.dumps(d))
    setup[5]["during_probe"] = change
    result = enable(setup)
    assert not result["ready_for_guarded_run"]
    assert result["probe_status"] != "passed"


def test_task_without_current_review_never_starts_host(setup, monkeypatch):
    called = []
    monkeypatch.setattr(guard_probe, "run_host_process", lambda *a, **k: called.append(True))
    with pytest.raises(guard_onboarding.OnboardingError):
        guard_onboarding.run_guarded_task(setup[0], setup[2], "do something", executable=str(setup[3]))
    assert not called


def test_guarded_task_uses_exact_native_trust_and_original_agent_messages(setup, monkeypatch):
    assert enable(setup)["ready_for_guarded_run"]
    captured = []
    def run(args, prompt, project, timeout_seconds=120):
        captured.append((args, prompt, project))
        return {"stdout": b'{"type":"item.completed","item":{"type":"agent_message","text":"done"}}\n{"type":"turn.completed"}\n',
                "stderr": b"", "exit_code": 0, "timed_out": False, "output_limited": False}
    monkeypatch.setattr(guard_probe, "run_host_process", run)
    result = guard_onboarding.run_guarded_task(setup[0], setup[2], "edit preview", executable=str(setup[3]))
    assert result["status"] == "completed" and result["assistant_text"] == "done"
    args, prompt, project = captured[0]
    assert prompt == b"edit preview" and project == setup[0]
    assert not any("bypass" in x for x in args)
    assert any("hooks.state=" in x for x in args)


def test_uninstall_disables_guarded_run_even_if_review_and_probe_remain(setup):
    assert enable(setup)["ready_for_guarded_run"]
    guard_cli._uninstall(setup[0], setup[2])
    result = doctor(setup)
    assert not result["ready_for_guarded_run"] and not result["configured"]


@pytest.mark.parametrize("action", ["enable", "run"])
def test_active_enable_or_task_prevents_concurrent_cli_uninstall(setup, monkeypatch, action):
    p, _, s, exe, _, behavior = setup
    def attempt_uninstall():
        before = (p / ".codex/hooks.json").read_bytes()
        result = subprocess.run([sys.executable, guard_cli.__file__, "uninstall", "--project", str(p), "--state-dir", str(s)], capture_output=True)
        assert result.returncode == 2 and b"another guard operation" in result.stderr
        assert (p / ".codex/hooks.json").read_bytes() == before
    if action == "enable":
        behavior["during_probe"] = attempt_uninstall
        assert enable(setup)["ready_for_guarded_run"]
    else:
        assert enable(setup)["ready_for_guarded_run"]
        def run(*args, **kwargs):
            attempt_uninstall()
            return {"stdout": b'{"type":"turn.completed"}\n', "stderr": b"", "exit_code": 0, "timed_out": False, "output_limited": False}
        monkeypatch.setattr(guard_probe, "run_host_process", run)
        assert guard_onboarding.run_guarded_task(p, s, "reply only", executable=str(exe))["status"] == "completed"


def test_successful_native_tool_without_this_tasks_guard_events_is_unverified(setup, monkeypatch):
    assert enable(setup)["ready_for_guarded_run"]
    def run(*args, **kwargs):
        return {"stdout": b'{"type":"item.completed","item":{"type":"command_execution","status":"completed","exit_code":0}}\n{"type":"turn.completed"}\n',
                "stderr": b"", "exit_code": 0, "timed_out": False, "output_limited": False}
    monkeypatch.setattr(guard_probe, "run_host_process", run)
    result = guard_onboarding.run_guarded_task(setup[0], setup[2], "read preview", executable=str(setup[3]))
    assert result["status"] == "unverified"


def test_module_entry_reports_enable_failure_without_python_traceback(setup):
    p, _, s, _, _, _ = setup
    env = dict(os.environ, PYTHONPATH=str(Path(guard_cli.__file__).parents[1]))
    result = subprocess.run([sys.executable, "-m", "openworkproof.guard_cli", "enable", "--project", str(p),
                             "--state-dir", str(s), "--codex", str(p / "missing-codex"), "--trust-own-hook"],
                            env=env, capture_output=True)
    assert result.returncode == 2
    assert b"Traceback" not in result.stderr


def test_cli_human_doctor_and_enable_have_separate_review_and_probe_states(setup, capsys):
    p, _, s, exe, _, _ = setup
    args = ["--project", str(p), "--state-dir", str(s), "--codex", str(exe), "--human"]
    assert guard_cli.main(["doctor", *args]) == 2
    assert "尚未授权" in capsys.readouterr().out
    assert guard_cli.main(["enable", *args, "--trust-own-hook"]) == 0
    text = capsys.readouterr().out
    assert "仅本项目" in text and "最近真实检查：通过" in text
    assert "普通 Codex 启动尚未验证" in text


def test_noninteractive_enable_does_not_infer_consent(setup, monkeypatch, capsys):
    p, _, s, exe, directory, _ = setup
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    rc = guard_cli.main(["enable", "--project", str(p), "--state-dir", str(s), "--codex", str(exe)])
    assert rc == 2 and not (directory / "review.json").exists()
    assert "--trust-own-hook" in capsys.readouterr().err


def test_interactive_cancel_does_not_save_review(setup, monkeypatch, capsys):
    p, _, s, exe, directory, _ = setup
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "")
    rc = guard_cli.main(["enable", "--project", str(p), "--state-dir", str(s), "--codex", str(exe), "--human"])
    assert rc == 0 and not (directory / "review.json").exists()
    assert "已取消" in capsys.readouterr().out


def test_control_c_is_a_clean_exit_for_onboarding_commands(setup, monkeypatch, capsys):
    def interrupt(*args):
        raise KeyboardInterrupt
    monkeypatch.setattr(guard_cli, "_onboarding_command", interrupt)
    try:
        code = guard_cli.main(["doctor", "--project", str(setup[0]), "--state-dir", str(setup[2])])
    except KeyboardInterrupt:
        code = "uncaught"
    assert code == 130
    assert "已停止" in capsys.readouterr().err
