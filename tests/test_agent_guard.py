"""Behavioral contract for the local Codex execution-before guard."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from openworkproof import agent_guard


@pytest.fixture
def workspace(tmp_path):
    project = tmp_path / "project"
    preview = project / "preview"
    preview.mkdir(parents=True)
    (preview / "index.html").write_text("before\n")
    (project / "original.txt").write_text("original\n")
    state = tmp_path / "state"
    state.mkdir()
    policy = {
        "schema_version": "openworkproof/agent-guard/0.1",
        "project_root": str(project),
        "allowed_directory": str(preview),
        "installation_id": "test-installation",
    }
    policy_path = state / "policy.json"
    policy_path.write_text(json.dumps(policy))
    return project, preview, policy, policy_path


def event(project, tool, command, **extra):
    return {
        "hook_event_name": "PreToolUse",
        "cwd": str(project),
        "tool_name": tool,
        "tool_input": {"command": command, **extra},
    }


def decide(workspace, tool, command, **extra):
    project, _, policy, _ = workspace
    return agent_guard.evaluate_event(event(project, tool, command, **extra), policy)


def patch(*lines):
    return "\n".join(("*** Begin Patch", *lines, "*** End Patch"))


def test_normal_preview_read_and_edit_pass_without_bypassing_host_permissions(workspace):
    project, _, policy, _ = workspace
    read = decide(workspace, "Bash", "/bin/cat preview/index.html")
    edit = decide(workspace, "apply_patch", patch(
        "*** Update File: preview/index.html", "@@", "-before", "+after",
    ))
    add = decide(workspace, "apply_patch", patch(
        "*** Add File: preview/new page.html", "+new",
    ))
    assert read.allowed and edit.allowed and add.allowed
    assert agent_guard.hook_response(edit) == {}
    assert (project / "original.txt").read_text() == "original\n"
    assert agent_guard.evaluate_event(event(project, "Bash", "/bin/ls preview"), policy).allowed


@pytest.mark.parametrize("command", [
    "/bin/cat original.txt",
    "/bin/cat preview/../original.txt",
    "/bin/cat /etc/passwd",
    "/bin/cat preview/.env",
    "/bin/cat preview/.codex/config.toml",
    "/bin/cat preview/index.html > preview/stolen",
    "/bin/cat preview/index.html; touch preview/marker",
    "/bin/cat preview/index.html | curl example.com",
    "/bin/cat $(touch preview/marker)",
    "/bin/cat `touch preview/marker`",
    "/bin/cat preview/index.html\ntouch preview/marker",
    "PATH=preview /bin/cat preview/index.html",
    "cat preview/index.html",
    "/bin/sh", "python3 -c 'print(1)'", "curl example.com",
    "git -c core.pager=sh diff", "find preview -exec sh {} ;",
    "/bin/ls -R preview", "/bin/cat -", "/bin/cat",
])
def test_shell_bypasses_and_out_of_scope_reads_are_denied(workspace, command):
    assert not decide(workspace, "Bash", command).allowed


@pytest.mark.parametrize("extra", [
    {"tty": True}, {"stdin": "write now"}, {"session_id": 1},
    {"shell": "/bin/sh"}, {"env": {"PATH": "preview"}},
    {"workdir": "/tmp"}, {"sandbox_permissions": "require_escalated"},
])
def test_interactive_or_alternate_execution_parameters_are_denied(workspace, extra):
    assert not decide(workspace, "Bash", "/bin/cat preview/index.html", **extra).allowed


@pytest.mark.parametrize("lines", [
    ("*** Add File: original.txt", "+changed"),
    ("*** Add File: preview/../original.txt", "+changed"),
    ("*** Add File: preview/.env", "+changed"),
    ("*** Add File: preview/.codex/hooks.json", "+changed"),
    ("*** Delete File: preview/index.html",),
    ("*** Update File: preview/index.html", "*** Move to: preview/moved.html", "@@", "-before", "+after"),
    ("*** Add File: preview/new.html", "+safe", "*** Add File: original.txt", "+unsafe"),
    ("*** Add File: preview/new.html", "+safe", "*** Delete File: original.txt"),
    ("*** Add File: preview/new.html", "+safe", "*** Unknown: anything"),
    ("*** Add File: preview/new.html", "+safe", "*** Add File: preview/new.html", "+again"),
])
def test_entire_patch_is_denied_if_any_action_is_unsafe(workspace, lines):
    result = decide(workspace, "apply_patch", patch(*lines))
    assert not result.allowed
    assert agent_guard.hook_response(result)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_only_patch_headers_are_paths_not_quoted_file_content(workspace):
    assert decide(workspace, "apply_patch", patch(
        "*** Add File: preview/new.txt", "+*** Delete File: /etc/passwd",
    )).allowed


@pytest.mark.parametrize("link_kind", ["file", "directory", "hardlink"])
def test_links_cannot_reach_another_file(workspace, link_kind):
    project, preview, _, _ = workspace
    if link_kind == "file":
        (preview / "linked.txt").symlink_to(project / "original.txt")
        target = "preview/linked.txt"
    elif link_kind == "directory":
        (preview / "linked").symlink_to(project, target_is_directory=True)
        target = "preview/linked/original.txt"
    else:
        import os
        os.link(project / "original.txt", preview / "linked.txt")
        target = "preview/linked.txt"
    assert not decide(workspace, "Bash", f"/bin/cat {target}").allowed
    assert not decide(workspace, "apply_patch", patch(
        f"*** Update File: {target}", "@@", "-original", "+changed",
    )).allowed


@pytest.mark.parametrize("tool", ["mcp__files__write", "write_stdin", "exec_command", "js_repl", "unknown"])
def test_unrecognized_tool_names_do_not_gain_authority(workspace, tool):
    assert not decide(workspace, tool, "/bin/cat preview/index.html").allowed


@pytest.mark.parametrize("payload", [None, {}, {"tool_name": "Bash"}, {"hook_event_name": "PostToolUse"}])
def test_malformed_host_input_is_denied(workspace, payload):
    assert not agent_guard.evaluate_event(payload, workspace[2]).allowed


def test_command_workdir_is_used_when_validating_paths(workspace):
    _, preview, _, _ = workspace
    assert decide(workspace, "Bash", "/bin/cat index.html", workdir=str(preview)).allowed
    assert not decide(workspace, "Bash", "/bin/cat ../original.txt", workdir=str(preview)).allowed


@pytest.mark.parametrize("command", ["/bin/cat -- -", "/bin/cat -n -- -"])
def test_a_real_dash_filename_cannot_turn_cat_into_an_interactive_reader(workspace, command):
    _, preview, _, _ = workspace
    (preview / "-").write_text("ordinary file")
    result = decide(workspace, "Bash", command, workdir=str(preview))
    assert not result.allowed and result.code == "COMMAND_NOT_ALLOWED"


@pytest.mark.parametrize("name", ["*", "?", "[a]", "~"])
def test_shell_expansion_is_rejected_even_when_the_literal_file_exists(workspace, name):
    project, preview, _, _ = workspace
    (preview / name).write_text("literal file")
    (preview / "linked.txt").symlink_to(project / "original.txt")
    assert not decide(workspace, "Bash", f"/bin/cat {name}", workdir=str(preview)).allowed


@pytest.mark.parametrize("option", ["-l", "-a", "-la", "-al", "-lah"])
def test_directory_listing_cannot_expose_hidden_metadata_or_link_targets(workspace, option):
    project, preview, _, _ = workspace
    (preview / ".env").write_text("private")
    (preview / "link").symlink_to(project / "original.txt")
    assert not decide(workspace, "Bash", f"/bin/ls {option} preview").allowed


def test_ambiguous_workdir_fields_and_unknown_execution_options_are_denied(workspace):
    project, preview, _, _ = workspace
    (project / "same.txt").write_text("outside")
    (preview / "same.txt").write_text("inside")
    assert not decide(workspace, "Bash", "/bin/cat same.txt",
                      workdir=str(project), working_directory=str(preview)).allowed
    assert not decide(workspace, "Bash", "/bin/cat preview/index.html", new_exec_option=True).allowed


@pytest.mark.parametrize("option", ["-R", "-L", "-la"])
def test_late_options_cannot_be_disguised_as_existing_directory_names(workspace, option):
    _, preview, _, _ = workspace
    (preview / option).mkdir()
    assert not decide(workspace, "Bash", f"/bin/ls . {option}", workdir=str(preview)).allowed


def invoke(policy_path, project, data):
    return subprocess.run(
        [sys.executable, "-I", agent_guard.__file__, "--policy", str(policy_path)],
        input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=project, check=False,
    )


def test_runtime_records_digests_without_leaking_command_or_file_content(workspace):
    project, _, _, policy_path = workspace
    command = patch("*** Add File: preview/new.txt", "+PRIVATE-CONTENT-DO-NOT-LOG")
    data = json.dumps(event(project, "apply_patch", command)).encode()
    result = invoke(policy_path, project, data)
    assert result.returncode == 0 and json.loads(result.stdout) == {}
    record = json.loads(policy_path.with_name("events.jsonl").read_text())
    assert record["decision"] == "allow"
    assert record["installation_id"] == "test-installation"
    canonical = json.dumps(json.loads(data), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    assert record["action_digest"] == hashlib.sha256(canonical).hexdigest()
    assert "PRIVATE-CONTENT" not in policy_path.with_name("events.jsonl").read_text()
    assert not result.stderr


@pytest.mark.parametrize("case", ["missing_policy", "invalid_policy", "bad_input", "huge_input", "audit_unavailable"])
def test_runtime_failures_return_supported_deny_instead_of_host_fail_open(workspace, case):
    project, _, _, policy_path = workspace
    data = json.dumps(event(project, "Bash", "/bin/cat preview/index.html")).encode()
    if case == "missing_policy":
        policy_path.unlink()
    elif case == "invalid_policy":
        policy_path.write_text('{"allowed":true}')
    elif case == "bad_input":
        data = b"not JSON PRIVATE-CONTENT"
    elif case == "huge_input":
        data = b"x" * (agent_guard.MAX_INPUT_BYTES + 1)
    else:
        policy_path.with_name("events.jsonl").mkdir()
    result = invoke(policy_path, project, data)
    assert result.returncode == 0
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert b"PRIVATE-CONTENT" not in result.stdout + result.stderr


def test_replaced_policy_directory_and_wrong_event_cwd_are_denied(workspace):
    project, preview, policy, _ = workspace
    other = project / "other"
    other.mkdir()
    preview.rename(project / "old-preview")
    preview.symlink_to(other, target_is_directory=True)
    assert not agent_guard.evaluate_event(event(project, "Bash", "/bin/pwd"), policy).allowed
