"""Native-evidence probe tests use local fake executables, never a real model."""

import json
from pathlib import Path
import sys
import time
import types

import pytest

from openworkproof import guard_probe


FAKE_HOST = r'''
import json, os, pathlib, subprocess, sys, time
MODE = __MODE__
LOG = pathlib.Path(__LOG__)
CAPTURE = pathlib.Path(__CAPTURE__)
INSTALLATION = __INSTALLATION__
prompt = sys.stdin.read()
line = next(line for line in prompt.splitlines() if line.startswith("OWP_PROBE_FIXTURES="))
plan = json.loads(line.split("=", 1)[1])
CAPTURE.write_text(json.dumps({"prompt": prompt, "plan": plan}))
if MODE == "outside_then_timeout":
    (pathlib.Path.cwd() / plan["outside_patch_path"]).touch()
    time.sleep(30)
if MODE == "timeout":
    later = str(CAPTURE.with_name("surviving-child.txt"))
    subprocess.Popen([sys.executable, "-c", "import pathlib,time; time.sleep(1.5); pathlib.Path(" + repr(later) + ").write_text('escaped')"])
    CAPTURE.with_name("child-started.txt").write_text("spawned")
    time.sleep(30)
if MODE == "output_limit":
    sys.stdout.write("X" * (2 * 1024 * 1024 + 4096)); sys.stdout.flush(); time.sleep(30)
root = pathlib.Path.cwd()
nonce = (root / plan["read_path"]).read_text().strip()
CAPTURE.write_text(json.dumps({"prompt":prompt, "plan":plan, "nonce":nonce}))
(root / plan["allowed_path"]).write_text(plan["allowed_content"] if MODE != "wrong_file" else "wrong")
if MODE in {"outside_patch", "outside_then_nonzero"}:
    (root / plan["outside_patch_path"]).write_text("forbidden")
if MODE == "outside_command":
    (root / plan["outside_command_path"]).touch()
events = [
    ("Bash", "allow", "WITHIN_PREVIEW"),
    ("apply_patch", "allow", "WITHIN_PREVIEW"),
    ("apply_patch", "deny", "PATH_OUTSIDE_PREVIEW"),
    ("Bash", "deny", "COMMAND_NOT_ALLOWED"),
]
if MODE == "extra_event": events.append(events[-1])
if MODE == "wrong_sequence": events[0], events[1] = events[1], events[0]
if MODE == "no_guard": events = []
LOG.parent.mkdir(parents=True, exist_ok=True)
with LOG.open("a") as handle:
    for name, decision, code in events:
        event = {"schema_version":"openworkproof/agent-guard-event/0.1", "installation_id":INSTALLATION, "checked_at":"2026-10-26T12:00:00Z", "tool_name":name, "decision":decision, "code":code, "action_digest":"a" * 64, "policy_digest":"b" * 64}
        handle.write(json.dumps(event) + "\n")
    if MODE == "unrelated_event":
        event["installation_id"] = "another-installation"
        handle.write(json.dumps(event) + "\n")
    if MODE == "bad_log": handle.write("broken log\n")
native = {"type":"item.completed", "item":{"id":"item_0", "type":"command_execution", "command":plan["read_command"], "status":"completed", "exit_code":0, "aggregated_output":nonce + "\n"}}
if MODE == "wrong_exit": native["item"]["exit_code"] = 1
if MODE == "not_completed": native["item"]["status"] = "in_progress"
if MODE == "wrong_native_command": native["item"]["command"] = "/bin/pwd"
if MODE == "self_report": native = {"type":"item.completed", "item":{"type":"agent_message", "text":"I read and verified " + nonce}}
print(json.dumps({"type":"thread.started", "thread_id":"synthetic"}))
if MODE != "no_native": print(json.dumps(native))
print(json.dumps({"type":"turn.completed", "usage":{"input_tokens":1,"output_tokens":1}}))
if MODE == "bad_stdout": print("broken JSONL")
if MODE != "no_stderr":
    for code in ["PATH_OUTSIDE_PREVIEW", "COMMAND_NOT_ALLOWED"]:
        print("ERROR codex_core::tools::router: Command blocked by PreToolUse hook: OWP [" + code + "]: fixture-only", file=sys.stderr)
if MODE in {"nonzero", "outside_then_nonzero"}: raise SystemExit(7)
'''


@pytest.fixture
def probe_case(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    project = root / "project"
    project.mkdir()
    allowed = project / "preview"
    allowed.mkdir()
    (project / "user-original.txt").write_text("leave untouched")
    event_log = root / "state/events.jsonl"
    capture = root / "capture.json"
    installation_id = "78fc9088-a8ab-4f60-9548-177a0c6e685e"
    executable = root / "fake-host"

    def configure(mode="success"):
        source = FAKE_HOST.replace("__MODE__", repr(mode)).replace("__LOG__", repr(str(event_log))).replace("__CAPTURE__", repr(str(capture))).replace("__INSTALLATION__", repr(installation_id))
        executable.write_text("#!" + str(Path(sys.executable).resolve()) + "\n" + source)
        executable.chmod(0o700)

    configure()
    # Invoke the fake through the known interpreter, avoiding macOS first-run
    # assessment of a newly created executable in short deadline tests.
    monkeypatch.setattr(guard_probe, "_exec_args", lambda executable, project, reviewed: [str(Path(sys.executable).resolve()), executable, "-"])
    return {"project": project, "allowed_directory": allowed, "event_log": event_log, "installation_id": installation_id, "executable": str(executable), "reviewed_hook": {"key": "reviewed-fixture-hook", "currentHash": "c" * 64}}, configure, capture


def assert_fixtures_cleaned(case, capture):
    assert (case["project"] / "user-original.txt").read_text() == "leave untouched"
    assert not list(case["allowed_directory"].glob("owp-probe-*"))
    assert not list(case["project"].glob("owp-probe-outside-*"))
    if capture.exists():
        plan = json.loads(capture.read_text())["plan"]
        assert not (case["project"] / plan["outside_patch_path"]).exists()
        assert not (case["project"] / plan["outside_command_path"]).exists()


def test_pass_requires_native_nonce_file_and_guard_evidence(probe_case):
    case, _, capture = probe_case
    result = guard_probe.perform_probe(**case)
    assert result["status"] == "passed", result
    assert all(result["checks"].values())
    assert set(result["checks"]) == set(guard_probe.REQUIRED_CHECKS)
    assert result["exit_code"] == 0
    assert result["host_stdout"]["bytes"] > 0
    assert set(result["host_stdout"]) == {"sha256", "bytes", "truncated"}
    recorded = json.loads(capture.read_text())
    assert "-I" not in recorded["prompt"]  # probe never proposes an alternate guard path
    assert "不要绕过" in recorded["prompt"]
    assert_fixtures_cleaned(case, capture)
    assert str(case["project"]) not in json.dumps(result)
    assert "leave untouched" not in json.dumps(result)


@pytest.mark.parametrize("mode", ["self_report", "no_native", "wrong_exit", "not_completed", "wrong_native_command", "no_stderr", "no_guard", "extra_event", "wrong_sequence", "bad_stdout", "bad_log", "nonzero"])
def test_incomplete_or_contradictory_evidence_never_passes(probe_case, mode):
    case, configure, capture = probe_case
    configure(mode)
    result = guard_probe.perform_probe(**case)
    assert result["status"] in {"failed", "unknown"}, result
    assert "PROBE_PASSED" not in result["codes"]
    assert_fixtures_cleaned(case, capture)


@pytest.mark.parametrize("mode,check", [("outside_patch", "outside_patch_absent"), ("outside_command", "outside_command_absent"), ("wrong_file", "allowed_file_exact")])
def test_observed_bad_files_fail_before_only_owned_fixtures_are_cleaned(probe_case, mode, check):
    case, configure, capture = probe_case
    configure(mode)
    result = guard_probe.perform_probe(**case)
    assert result["status"] == "failed", result
    assert result["checks"][check] is False
    assert_fixtures_cleaned(case, capture)


def test_prior_and_other_installation_events_do_not_count(probe_case):
    case, configure, capture = probe_case
    case["event_log"].parent.mkdir()
    case["event_log"].write_text("old malformed data must stay before byte offset\n")
    configure("unrelated_event")
    result = guard_probe.perform_probe(**case)
    assert result["status"] == "passed", result
    assert case["event_log"].read_text().startswith("old malformed data")
    assert_fixtures_cleaned(case, capture)


def test_timeout_cleans_owned_process_group_and_fixtures(probe_case):
    case, configure, capture = probe_case
    configure("timeout")
    started = time.monotonic()
    result = guard_probe.perform_probe(**case, timeout_seconds=0.4)
    assert time.monotonic() - started < 3
    assert result["status"] == "unknown" and "TIMEOUT" in result["codes"]
    assert capture.with_name("child-started.txt").exists()
    time.sleep(1.3)
    assert not capture.with_name("surviving-child.txt").exists()
    assert_fixtures_cleaned(case, capture)


def test_output_is_bounded_and_not_returned_raw(probe_case):
    case, configure, capture = probe_case
    configure("output_limit")
    result = guard_probe.perform_probe(**case, timeout_seconds=4)
    assert result["status"] == "unknown" and "OUTPUT_LIMIT" in result["codes"]
    assert result["host_stdout"]["bytes"] + result["host_stderr"]["bytes"] <= 2 * 1024 * 1024
    assert "X" * 100 not in json.dumps(result)
    assert_fixtures_cleaned(case, capture)


def test_native_nonce_is_absent_from_prompt_and_result(probe_case):
    case, _, capture = probe_case
    result = guard_probe.perform_probe(**case)
    assert result["status"] == "passed"
    # The fake's stdout digest is useful, but no transcript/body is persisted by the API.
    assert "stdout" not in result and "stderr" not in result
    assert "prompt" not in result
    captured = json.loads(capture.read_text())
    assert captured["nonce"] not in captured["prompt"]
    assert captured["nonce"] not in json.dumps(result)
    assert_fixtures_cleaned(case, capture)


@pytest.mark.parametrize("mode", ["outside_then_nonzero", "outside_then_timeout"])
def test_negative_marker_is_failed_even_if_host_crashes_or_times_out(probe_case, mode):
    case, configure, capture = probe_case
    configure(mode)
    result = guard_probe.perform_probe(**case, timeout_seconds=1.5)
    assert result["status"] == "failed", result
    assert result["checks"]["outside_patch_absent"] is False
    assert "OUTSIDE_PATCH_CREATED" in result["codes"]
    assert_fixtures_cleaned(case, capture)


def test_symlinked_input_does_not_start_host_or_touch_user_files(probe_case):
    case, _, capture = probe_case
    linked = case["project"] / "linked-preview"
    linked.symlink_to(case["allowed_directory"], target_is_directory=True)
    case["allowed_directory"] = linked
    result = guard_probe.perform_probe(**case)
    assert result["status"] == "unknown"
    assert not capture.exists()
    assert (case["project"] / "user-original.txt").read_text() == "leave untouched"
    assert set(result["checks"]) == set(guard_probe.REQUIRED_CHECKS)


@pytest.mark.parametrize("last_arg", [None, "-"])
def test_host_builder_receives_exact_review_and_stdin_prompt_marker(monkeypatch, tmp_path, last_arg):
    received = []
    host = types.ModuleType("openworkproof.codex_host")

    def build(executable, project, key, current_hash):
        received.append((executable, project, key, current_hash))
        return [executable, "exec", *([last_arg] if last_arg else [])]

    host.build_exec_args = build
    monkeypatch.setitem(sys.modules, "openworkproof.codex_host", host)
    reviewed = {"key": "exact-key", "currentHash": "d" * 64}
    result = guard_probe._exec_args("/fake/codex", tmp_path, reviewed)
    assert result == ["/fake/codex", "exec", "-"]
    assert received == [("/fake/codex", tmp_path, reviewed["key"], reviewed["currentHash"])]


def test_shared_host_runner_handles_large_stdin_and_both_output_pipes(tmp_path):
    prompt = b"synthetic input\n" * 10000
    result = guard_probe.run_host_process([str(Path(sys.executable).resolve()), "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()); sys.stderr.write('done')"], prompt, tmp_path.resolve(), 3)
    assert result == {"stdout": prompt, "stderr": b"done", "exit_code": 0, "timed_out": False, "output_limited": False}
