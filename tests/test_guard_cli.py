"""Installation lifecycle checks use disposable projects, never user settings."""

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from openworkproof import guard_cli


@pytest.fixture
def layout(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    project = root / "project"
    project.mkdir()
    allowed = project / "preview"
    allowed.mkdir()
    source = root / "fixture_runtime.py"
    source.write_text("import sys\nsys.stdin.read()\nprint('{}')\n")
    monkeypatch.setattr(guard_cli, "RUNTIME_SOURCE", source)
    return project, allowed, root / "state", source


def invoke(capsys, command, project, state, *extra):
    rc = guard_cli.main([command, "--project", str(project), "--state-dir", str(state), *extra])
    output = capsys.readouterr()
    return rc, json.loads(output.out) if output.out else None, output.err


def install(capsys, layout, *extra):
    project, allowed, state, _ = layout
    rc, result, err = invoke(capsys, "install", project, state, "--allow-dir", str(allowed), *extra)
    assert rc == 0, err
    return result


def run_hook(config_path, payload=b'{"hook_event_name":"PreToolUse"}'):
    entry = json.loads(config_path.read_text())["hooks"]["PreToolUse"][-1]
    return subprocess.run(entry["hooks"][0]["command"], shell=True, input=payload, capture_output=True)


def test_install_preserves_other_hooks_and_raw_backup(layout, capsys):
    project, _, _, _ = layout
    config = project / ".codex/hooks.json"
    config.parent.mkdir()
    original = b'{\r\n "description":"mine", "hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo mine"}]}],"Stop":[]}\r\n}\r\n'
    config.write_bytes(original)
    result = install(capsys, layout)
    state = Path(result["state_directory"])
    parsed = json.loads(config.read_bytes())
    assert parsed["description"] == "mine"
    assert len(parsed["hooks"]["PreToolUse"]) == 2
    assert parsed["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "echo mine"
    ours = parsed["hooks"]["PreToolUse"][-1]
    assert ours["matcher"] == "*"
    assert ours["hooks"][0]["timeout"] == 5
    assert "async" not in ours["hooks"][0]
    assert (state / "hooks.before").read_bytes() == original
    policy = json.loads((state / "policy.json").read_text())
    assert set(policy) == {"schema_version", "project_root", "allowed_directory", "installation_id"}
    assert policy["allowed_directory"] == str(layout[1])
    assert result["requires_trust"] is True
    assert run_hook(config).stdout.strip() == b"{}"


@pytest.mark.parametrize("failure", ["missing", "crash"])
def test_wrapper_returns_supported_deny_for_failed_python(layout, capsys, failure):
    result = install(capsys, layout)
    runtime = Path(result["state_directory"]) / "runtime.py"
    if failure == "missing":
        runtime.unlink()
    else:
        runtime.write_text("print('not JSON')\nraise RuntimeError('private traceback')\n")
    proc = run_hook(layout[0] / ".codex/hooks.json")
    assert proc.returncode == 0
    output = json.loads(proc.stdout)
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert b"private traceback" not in proc.stderr


def test_install_is_idempotent_and_upgrade_is_explicit(layout, capsys):
    first = install(capsys, layout)
    config = layout[0] / ".codex/hooks.json"
    config_before = config.read_bytes()
    manifest = Path(first["state_directory"]) / "installation.json"
    manifest_before = manifest.read_bytes()
    second = install(capsys, layout)
    assert second["installation_id"] == first["installation_id"]
    assert config.read_bytes() == config_before
    assert manifest.read_bytes() == manifest_before
    layout[3].write_text("print('{}')\n# upgraded snapshot\n")
    rc, _, err = invoke(capsys, "install", layout[0], layout[2], "--allow-dir", str(layout[1]))
    assert rc != 0 and "--upgrade" in err
    assert config.read_bytes() == config_before
    upgraded = install(capsys, layout, "--upgrade")
    assert upgraded["installation_id"] == first["installation_id"]
    assert upgraded["requires_trust"] is True
    assert config.read_bytes() != config_before  # source hash changes hook definition/trust
    assert b"upgraded snapshot" in (manifest.parent / "runtime.py").read_bytes()


def test_status_observes_only_matching_valid_events(layout, capsys):
    installed = install(capsys, layout)
    rc, status, _ = invoke(capsys, "status", layout[0], layout[2])
    assert rc == 0 and status["configured"] is True and status["last_observed"] is None
    assert "trusted" not in status
    good = {"schema_version": "openworkproof/agent-guard-event/0.1", "installation_id": installed["installation_id"], "checked_at": "2026-10-26T01:02:03Z", "tool_name": "Bash", "decision": "allow", "code": "allowed", "action_digest": "a" * 64, "policy_digest": status["policy_digest"]}
    wrong = dict(good, installation_id="not-ours")
    (Path(installed["state_directory"]) / "events.jsonl").write_text(json.dumps(good) + "\n" + json.dumps(wrong) + "\n{broken\n")
    _, status, _ = invoke(capsys, "status", layout[0], layout[2])
    assert status["last_observed"] == good


def test_modified_hook_entry_is_not_removed(layout, capsys):
    installed = install(capsys, layout)
    config = layout[0] / ".codex/hooks.json"
    data = json.loads(config.read_text())
    data["hooks"]["PreToolUse"][-1]["hooks"][0]["timeout"] = 9
    config.write_text(json.dumps(data))
    before = config.read_bytes()
    _, status, _ = invoke(capsys, "status", layout[0], layout[2])
    assert status["configured"] is False and status["drift"]
    rc, _, _ = invoke(capsys, "uninstall", layout[0], layout[2])
    assert rc != 0
    assert config.read_bytes() == before


@pytest.mark.parametrize("target", ["runtime.py", "hook.sh", "policy.json", "hooks.before"])
def test_drifted_state_does_not_trap_uninstall(layout, capsys, target):
    config = layout[0] / ".codex/hooks.json"
    config.parent.mkdir()
    config.write_text('{"description":"original","hooks":{"Stop":[]}}\n')
    installed = install(capsys, layout)
    artifact = Path(installed["state_directory"]) / target
    artifact.write_text("changed bytes remain local\n")
    data = json.loads(config.read_text())
    data["later_change"] = "preserve"
    config.write_text(json.dumps(data))
    _, status, _ = invoke(capsys, "status", layout[0], layout[2])
    assert status["drift"] and status["configured"] is False
    rc, uninstalled, err = invoke(capsys, "uninstall", layout[0], layout[2])
    assert rc == 0, err
    assert uninstalled["configured"] is False
    assert artifact.read_text() == "changed bytes remain local\n"
    kept = json.loads(config.read_text())
    assert kept["description"] == "original" and kept["later_change"] == "preserve"
    assert kept["hooks"]["Stop"] == []
    assert not kept["hooks"].get("PreToolUse")


@pytest.mark.parametrize("backup", ["missing", "changed"])
def test_bad_backup_falls_back_to_removing_exact_entry(layout, capsys, backup):
    config = layout[0] / ".codex/hooks.json"
    config.parent.mkdir()
    config.write_text('{"description":"must survive", "hooks":{"Stop":[]}}')
    installed = install(capsys, layout)
    original = Path(installed["state_directory"]) / "hooks.before"
    if backup == "missing":
        original.unlink()
    else:
        original.write_text('{"description":"never restore me"}')
    rc, _, err = invoke(capsys, "uninstall", layout[0], layout[2])
    assert rc == 0, err
    current = json.loads(config.read_text())
    assert current["description"] == "must survive"
    assert current["hooks"]["Stop"] == []
    assert current["hooks"]["PreToolUse"] == []


@pytest.mark.parametrize("existed", [False, True])
def test_uninstall_restores_original_bytes_or_absence(layout, capsys, existed):
    config = layout[0] / ".codex/hooks.json"
    original = b'{\r\n  "hooks": {}, "description": "keep format"\r\n}\r\n'
    if existed:
        config.parent.mkdir()
        config.write_bytes(original)
    install(capsys, layout)
    rc, result, err = invoke(capsys, "uninstall", layout[0], layout[2])
    assert rc == 0, err
    assert result["configured"] is False
    assert config.read_bytes() == original if existed else not config.exists()


def test_uninstall_preserves_changes_added_after_install_and_upgrade(layout, capsys):
    install(capsys, layout)
    config = layout[0] / ".codex/hooks.json"
    data = json.loads(config.read_text())
    other = {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo new"}]}
    data["hooks"]["PreToolUse"].insert(0, other)
    data["new_setting"] = {"keep": True}
    config.write_text(json.dumps(data))
    layout[3].write_text("print('{}')\n# new version\n")
    install(capsys, layout, "--upgrade")
    rc, _, err = invoke(capsys, "uninstall", layout[0], layout[2])
    assert rc == 0, err
    data = json.loads(config.read_text())
    assert data["hooks"]["PreToolUse"] == [other]
    assert data["new_setting"] == {"keep": True}


@pytest.mark.parametrize("kind", ["project_root", "outside", "hidden", "codex", "symlink", "state_overlap"])
def test_unsafe_allowed_paths_are_rejected(layout, capsys, kind):
    project, allowed, state, _ = layout
    if kind == "project_root":
        allowed = project
    elif kind == "outside":
        allowed = state.parent
    elif kind in {"hidden", "codex"}:
        allowed = project / (".hidden" if kind == "hidden" else ".codex")
        allowed.mkdir()
    elif kind == "symlink":
        linked = project / "linked"
        linked.symlink_to(allowed, target_is_directory=True)
        allowed = linked
    else:
        state = allowed / "state"
    rc, _, _ = invoke(capsys, "install", project, state, "--allow-dir", str(allowed))
    assert rc != 0
    assert not (project / ".codex/hooks.json").exists()


@pytest.mark.parametrize("content", [b"not JSON", b"[]", b'{"hooks": []}', b'{"hooks":{},"hooks":{}}'])
def test_bad_existing_config_is_not_overwritten(layout, capsys, content):
    config = layout[0] / ".codex/hooks.json"
    config.parent.mkdir()
    config.write_bytes(content)
    rc, _, _ = invoke(capsys, "install", layout[0], layout[2], "--allow-dir", str(layout[1]))
    assert rc != 0
    assert config.read_bytes() == content


def test_symlinked_config_is_rejected_without_touching_target(layout, capsys):
    project, _, state, _ = layout
    target = project.parent / "personal.json"
    target.write_text('{"keep":true}')
    config = project / ".codex/hooks.json"
    config.parent.mkdir()
    config.symlink_to(target)
    rc, _, _ = invoke(capsys, "install", project, state, "--allow-dir", str(layout[1]))
    assert rc != 0 and target.read_text() == '{"keep":true}'


def test_uninstalled_status_is_not_a_protection_claim(layout, capsys):
    rc, result, err = invoke(capsys, "status", layout[0], layout[2])
    assert rc == 0, err
    assert result["configured"] is False and result["last_observed"] is None


def test_wrapper_missing_interpreter_returns_valid_deny(layout):
    project = layout[0]
    wrapper = project / "fixture-wrapper.sh"
    wrapper.write_bytes(guard_cli._wrapper(project / "missing-python", project / "runtime.py", project / "policy.json", "fixture-id", "fixture-digest", "fixture-policy-digest"))
    proc = subprocess.run(["/bin/sh", str(wrapper), "fixture-id", "fixture-digest", "fixture-wrapper-digest", "fixture-policy-digest"], input=b"{}", capture_output=True)
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("source", ["pass\n", "print('broken JSON')\n", "print('[]')\n", "print('{\"continue\":false}')\n", "print('{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"ask\"}}')\n", "print('{\"a\":1,\"a\":2}')\n"])
def test_wrapper_rejects_successful_but_invalid_runtime_output(layout, capsys, source):
    layout[3].write_text(source)
    install(capsys, layout)
    proc = run_hook(layout[0] / ".codex/hooks.json")
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_wrapper_times_out_before_host_timeout(layout, capsys):
    layout[3].write_text("import time\ntime.sleep(30)\nprint('{}')\n")
    install(capsys, layout)
    started = time.monotonic()
    proc = run_hook(layout[0] / ".codex/hooks.json")
    assert time.monotonic() - started < 4.5
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_configuration_compare_and_swap_preserves_foreign_writer(layout, capsys, monkeypatch):
    config = layout[0] / ".codex/hooks.json"
    atomic = guard_cli._atomic
    foreign = b'{"description":"concurrent edit"}\n'

    def concurrent_write(path, data, before, mode=0o600):
        if path == config:
            config.write_bytes(foreign)
        return atomic(path, data, before, mode)

    monkeypatch.setattr(guard_cli, "_atomic", concurrent_write)
    rc, _, err = invoke(capsys, "install", layout[0], layout[2], "--allow-dir", str(layout[1]))
    assert rc != 0 and "concurrently" in err
    assert config.read_bytes() == foreign
    assert not list(layout[2].glob("*/installation.json"))


def test_project_lock_refuses_concurrent_guard_operation(layout, capsys):
    with guard_cli._project_lock(layout[0]):
        rc, _, err = invoke(capsys, "status", layout[0], layout[2])
    assert rc != 0 and "another guard operation" in err


def test_nonregular_config_is_rejected_without_blocking(layout, capsys):
    config = layout[0] / ".codex/hooks.json"
    config.parent.mkdir()
    os.mkfifo(config)
    rc, _, err = invoke(capsys, "install", layout[0], layout[2], "--allow-dir", str(layout[1]))
    assert rc != 0 and "regular file" in err
    assert config.is_fifo()


def test_reinstallation_keeps_historical_events_but_does_not_claim_observation(layout, capsys):
    original = install(capsys, layout)
    rc, uninstalled, err = invoke(capsys, "uninstall", layout[0], layout[2])
    assert rc == 0, err
    assert uninstalled["retained_state_directory"] == original["state_directory"]
    historical = Path(original["state_directory"]) / "events.jsonl"
    historical.write_text('{"not":"a current event"}\n')
    new = install(capsys, layout)
    assert new["installation_id"] != original["installation_id"]
    assert new["last_observed"] is None
    assert historical.exists()


def test_wrapper_uses_real_runtime_without_executing_agent_tools(layout, capsys, monkeypatch):
    monkeypatch.setattr(guard_cli, "RUNTIME_SOURCE", Path(guard_cli.__file__).with_name("agent_guard.py"))
    installed = install(capsys, layout)
    (layout[1] / "index.html").write_text("preview")
    config = layout[0] / ".codex/hooks.json"
    event = {"hook_event_name": "PreToolUse", "cwd": str(layout[0]), "session_id": "fixture-only", "tool_name": "Bash", "tool_input": {"command": "/bin/cat preview/index.html"}}
    allowed = run_hook(config, json.dumps(event).encode())
    assert allowed.returncode == 0 and json.loads(allowed.stdout) == {}
    event["tool_input"]["command"] = "/bin/cat ../private.txt"
    denied = run_hook(config, json.dumps(event).encode())
    assert json.loads(denied.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    _, status, _ = invoke(capsys, "status", layout[0], layout[2])
    assert status["last_observed"]["decision"] == "deny"
    assert status["state_directory"] == installed["state_directory"]


def test_wrapper_upgrade_changes_host_trust_definition(layout, capsys, monkeypatch):
    installed = install(capsys, layout)
    config = layout[0] / ".codex/hooks.json"
    before = config.read_bytes()
    build_wrapper = guard_cli._wrapper
    monkeypatch.setattr(guard_cli, "_wrapper", lambda *args: build_wrapper(*args) + b"# updated wrapper\n")
    rc, _, err = invoke(capsys, "install", layout[0], layout[2], "--allow-dir", str(layout[1]))
    assert rc != 0 and "--upgrade" in err
    updated = install(capsys, layout, "--upgrade")
    assert updated["installation_id"] == installed["installation_id"]
    assert config.read_bytes() != before


def test_human_status_never_claims_trusted_or_enabled(layout, capsys):
    install(capsys, layout)
    rc = guard_cli.main(["status", "--project", str(layout[0]), "--state-dir", str(layout[2]), "--human"])
    output = capsys.readouterr()
    assert rc == 0 and "项目接入：已配置" in output.out
    assert "宿主当前是否信任/启用：尚未核实，配置存在不代表生效" in output.out
    assert "最近一次检查：尚未观察到" in output.out
    assert "保护已启用" not in output.out
    rc = guard_cli.main(["uninstall", "--project", str(layout[0]), "--state-dir", str(layout[2]), "--human"])
    output = capsys.readouterr()
    assert rc == 0 and "本地记录保留" in output.out


@pytest.mark.parametrize("artifact", ["runtime", "policy"])
def test_wrapper_checks_installed_bytes_before_trusting_result(layout, capsys, monkeypatch, artifact):
    monkeypatch.setattr(guard_cli, "RUNTIME_SOURCE", Path(guard_cli.__file__).with_name("agent_guard.py"))
    installed = install(capsys, layout)
    directory = Path(installed["state_directory"])
    config = layout[0] / ".codex/hooks.json"
    wider = layout[0] / "wider"
    wider.mkdir()
    (wider / "secret.txt").write_text("not in approved preview")
    event = {"hook_event_name": "PreToolUse", "cwd": str(layout[0]), "tool_name": "Bash", "tool_input": {"command": "/bin/cat wider/secret.txt"}}
    assert json.loads(run_hook(config, json.dumps(event).encode()).stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    if artifact == "runtime":
        (directory / "runtime.py").write_text("print('{}')\n")
    else:
        policy = json.loads((directory / "policy.json").read_text())
        policy["allowed_directory"] = str(wider)
        (directory / "policy.json").write_text(json.dumps(policy))
    proc = run_hook(config, json.dumps(event).encode())
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("control", ["state", "installation", "codex"])
def test_install_refuses_preexisting_writable_control_directories(layout, capsys, control):
    project, _, state, _ = layout
    if control == "installation":
        installed = install(capsys, layout)
        unsafe = Path(installed["state_directory"])
    else:
        unsafe = state if control == "state" else project / ".codex"
        unsafe.mkdir()
    unsafe.chmod(0o777)
    config = project / ".codex/hooks.json"
    before = config.read_bytes() if config.exists() else None
    rc, _, err = invoke(capsys, "install", project, state, "--allow-dir", str(layout[1]))
    assert rc != 0 and "permissions" in err
    assert (config.read_bytes() if config.exists() else None) == before
    assert unsafe.stat().st_mode & 0o777 == 0o777


def test_uninstall_rejects_a_modified_duplicate_of_owned_entry(layout, capsys):
    install(capsys, layout)
    config = layout[0] / ".codex/hooks.json"
    data = json.loads(config.read_text())
    duplicate = json.loads(json.dumps(data["hooks"]["PreToolUse"][0]))
    duplicate["hooks"][0]["timeout"] = 8
    data["hooks"]["PreToolUse"].append(duplicate)
    config.write_text(json.dumps(data))
    before = config.read_bytes()
    rc, _, _ = invoke(capsys, "uninstall", layout[0], layout[2])
    assert rc != 0
    assert config.read_bytes() == before


@pytest.mark.parametrize("artifact", ["runtime.py", "policy.json"])
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_wrapper_rejects_linked_or_nonregular_control_files(layout, capsys, artifact, kind):
    installed = install(capsys, layout)
    target = Path(installed["state_directory"]) / artifact
    original = target.read_bytes()
    replacement = layout[0].parent / ("alternate-" + artifact)
    replacement.write_bytes(original)
    target.unlink()
    if kind == "symlink":
        target.symlink_to(replacement)
    elif kind == "hardlink":
        os.link(replacement, target)
    else:
        os.mkfifo(target)
    proc = run_hook(layout[0] / ".codex/hooks.json")
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_previous_owned_wrapper_can_be_explicitly_upgraded(layout, capsys):
    installed = install(capsys, layout)
    directory = Path(installed["state_directory"])
    manifest_path = directory / "installation.json"
    manifest = json.loads(manifest_path.read_text())
    legacy_wrapper = b"#!/bin/sh\nprintf '{}\\n'\n"
    (directory / "hook.sh").write_bytes(legacy_wrapper)
    manifest["wrapper_digest"] = guard_cli._digest(legacy_wrapper)
    manifest["hook_entry"] = guard_cli._entry(directory, manifest["installation_id"], manifest["runtime_digest"], manifest["wrapper_digest"])
    config_path = layout[0] / ".codex/hooks.json"
    config = json.loads(config_path.read_text())
    config["hooks"]["PreToolUse"] = [manifest["hook_entry"]]
    config_path.write_bytes(guard_cli._json_bytes(config))
    manifest["installed_config_digest"] = guard_cli._digest(config_path.read_bytes())
    manifest_path.write_bytes(guard_cli._json_bytes(manifest))
    rc, _, err = invoke(capsys, "install", layout[0], layout[2], "--allow-dir", str(layout[1]))
    assert rc != 0 and "--upgrade" in err
    updated = install(capsys, layout, "--upgrade")
    assert updated["installation_id"] == installed["installation_id"]
    current_manifest = json.loads(manifest_path.read_text())
    assert current_manifest["policy_file_digest"] in config_path.read_text()
    assert run_hook(config_path).stdout.strip() == b"{}"
