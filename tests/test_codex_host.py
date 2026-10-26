"""Bounded native Codex inventory and exact session-trust contract."""

import json
import os
import sys
import time

import pytest

from openworkproof import codex_host


HASH = "sha256:" + "a" * 64


@pytest.fixture
def fake_host(tmp_path, monkeypatch):
    project = tmp_path / 'project.with.dot "中文"'
    project.mkdir()
    capture = tmp_path / "requests.jsonl"
    pid_file = tmp_path / "host.pid"
    helper = tmp_path / "fake-codex"
    helper.write_text(
        "#!" + sys.executable + "\n" + r'''
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

mode = os.environ.get("OWP_CODEX_FAKE_MODE", "normal")
capture = Path(os.environ["OWP_CODEX_CAPTURE"])
Path(os.environ["OWP_CODEX_PID_FILE"]).write_text(str(os.getpid()))
capture.with_suffix(".argv.json").write_text(json.dumps(sys.argv[1:]))
if "--version" in sys.argv:
    if mode == "bad-version":
        print("RAW_SECRET is not a version")
    elif mode == "version-timeout":
        time.sleep(30)
    else:
        print("codex-cli 0.147.0")
    raise SystemExit(0)
if mode == "ignore-term":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
if mode == "init-pending-descendant":
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    pid_path = Path(os.environ["OWP_CODEX_PID_FILE"])
    pid_path.with_suffix(".child.pid").write_text(str(child.pid))
    def reap_child(signum, frame):
        child.wait(timeout=1)
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, reap_child)
    pid_path.with_suffix(".ready").touch()
    time.sleep(30)
    raise SystemExit(0)
if mode == "stderr":
    sys.stderr.write("RAW_SECRET" * 100000)
    sys.stderr.flush()
for line in sys.stdin:
    message = json.loads(line)
    with capture.open("a") as output:
        output.write(json.dumps(message) + "\n")
    method = message.get("method")
    if method == "initialized":
        continue
    if method == "initialize":
        result = {"userAgent": "fake", "codexHome": "not-returned"}
    elif method == "hooks/list":
        if mode in ("timeout", "ignore-term"):
            time.sleep(30)
        if mode == "eof":
            raise SystemExit(0)
        if mode == "invalid-json":
            print("RAW_SECRET not json", flush=True)
            continue
        if mode == "oversize":
            print("x" * 10000, flush=True)
            continue
        if mode == "deep-json":
            print("[" * 1001 + "0" + "]" * 1001, flush=True)
            continue
        if mode == "wrong-id":
            print(json.dumps({"id": 999, "result": {}}), flush=True)
            continue
        if mode == "rpc-error":
            print(json.dumps({"id": message["id"], "error": {"message": "RAW_SECRET"}}), flush=True)
            continue
        if mode == "server-request":
            print(json.dumps({"id": 99, "method": "permission/request", "params": {"secret": "RAW_SECRET"}}), flush=True)
            continue
        if mode == "notification":
            print(json.dumps({"method": "config/warning", "params": {"message": "RAW_SECRET"}}), flush=True)
        cwd = message["params"]["cwds"][0]
        hook = {
            "key": cwd + "/.codex/hooks.json:pre_tool_use:0:0",
            "currentHash": "sha256:" + "a" * 64,
            "trustStatus": "untrusted", "enabled": True,
            "isManaged": False, "source": "project",
            "sourcePath": cwd + "/.codex/hooks.json",
            "eventName": "preToolUse", "handlerType": "command",
            "command": "/bin/sh /trusted/owp-hook.sh", "matcher": "*",
            "timeoutSec": 5,
        }
        entry = {"cwd": cwd, "hooks": [hook], "warnings": [], "errors": []}
        if mode == "entry-error":
            entry["errors"] = [{"message": "RAW_SECRET", "path": cwd}]
        if mode == "wrong-cwd":
            entry["cwd"] = "/another/project"
        result = {"data": [entry]}
        if mode == "invalid-result":
            result = {"data": "RAW_SECRET"}
        if mode == "duplicate-cwd":
            result["data"].append(entry)
    else:
        raise SystemExit(3)
    print(json.dumps({"id": message["id"], "result": result}), flush=True)
'''
    )
    helper.chmod(0o700)
    monkeypatch.setenv("OWP_CODEX_CAPTURE", str(capture))
    monkeypatch.setenv("OWP_CODEX_PID_FILE", str(pid_file))
    return helper, project, capture, pid_file


def assert_stopped(pid_file):
    pid = int(pid_file.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_native_inventory_initializes_and_only_lists_hooks(fake_host):
    helper, project, capture, pid_file = fake_host
    with codex_host.CodexHost(executable=str(helper), project=project) as host:
        entry = host.list_hooks()
    assert entry["cwd"] == str(project)
    assert entry["hooks"][0]["currentHash"] == HASH
    messages = [json.loads(line) for line in capture.read_text().splitlines()]
    assert [message["method"] for message in messages] == [
        "initialize", "initialized", "hooks/list",
    ]
    assert messages[0]["params"]["capabilities"]["experimentalApi"] is True
    assert messages[2]["params"] == {"cwds": [str(project)]}
    args = json.loads(capture.with_suffix(".argv.json").read_text())
    assert "app-server" in args
    assert "exec" not in args and "--ignore-user-config" not in args
    assert not any("bypass" in argument for argument in args)
    assert_stopped(pid_file)


@pytest.mark.parametrize("mode", ["notification", "stderr"])
def test_notifications_and_stderr_do_not_leak_or_block_inventory(fake_host, monkeypatch, mode):
    helper, project, _, pid_file = fake_host
    monkeypatch.setenv("OWP_CODEX_FAKE_MODE", mode)
    with codex_host.CodexHost(executable=str(helper), project=project) as host:
        assert host.list_hooks()["hooks"][0]["trustStatus"] == "untrusted"
    assert_stopped(pid_file)


@pytest.mark.parametrize("mode", [
    "eof", "invalid-json", "oversize", "deep-json", "wrong-id", "rpc-error",
    "server-request", "entry-error", "wrong-cwd", "invalid-result", "duplicate-cwd",
])
def test_protocol_failures_are_closed_and_do_not_echo_raw_data(fake_host, monkeypatch, mode):
    helper, project, _, pid_file = fake_host
    monkeypatch.setenv("OWP_CODEX_FAKE_MODE", mode)
    with pytest.raises(codex_host.CodexHostError) as error:
        with codex_host.CodexHost(
            executable=str(helper), project=project, max_message_bytes=2048,
        ) as host:
            host.list_hooks()
    assert "RAW_SECRET" not in str(error.value)
    assert str(error.value)
    assert_stopped(pid_file)


def test_deep_json_is_a_fixed_error_with_a_smaller_recursion_limit(fake_host, monkeypatch):
    helper, project, _, pid_file = fake_host
    monkeypatch.setenv("OWP_CODEX_FAKE_MODE", "deep-json")
    previous_limit = sys.getrecursionlimit()
    try:
        sys.setrecursionlimit(500)
        with pytest.raises(codex_host.CodexHostError):
            with codex_host.CodexHost(executable=str(helper), project=project) as host:
                host.list_hooks()
    finally:
        sys.setrecursionlimit(previous_limit)
    assert_stopped(pid_file)


@pytest.mark.parametrize("mode", ["timeout", "ignore-term"])
def test_stalled_host_is_bounded_and_reaped(fake_host, monkeypatch, mode):
    helper, project, _, pid_file = fake_host
    monkeypatch.setenv("OWP_CODEX_FAKE_MODE", mode)
    started = time.monotonic()
    with pytest.raises(codex_host.CodexHostError) as error:
        with codex_host.CodexHost(
            executable=str(helper), project=project, timeout_seconds=1.0,
        ) as host:
            host.list_hooks()
    assert time.monotonic() - started < 5
    assert "RAW_SECRET" not in str(error.value)
    assert_stopped(pid_file)


def test_context_error_still_cleans_up_host(fake_host):
    helper, project, _, pid_file = fake_host
    with pytest.raises(ValueError, match="caller failure"):
        with codex_host.CodexHost(executable=str(helper), project=project):
            raise ValueError("caller failure")
    assert_stopped(pid_file)


@pytest.mark.skipif(os.name != "posix", reason="owned POSIX process-group contract")
@pytest.mark.parametrize("interruption", [KeyboardInterrupt("init interrupted"), SystemExit(7)])
def test_initialization_interruption_cleans_up_real_parent_and_descendant(
    fake_host, monkeypatch, interruption,
):
    helper, project, _, pid_file = fake_host
    monkeypatch.setenv("OWP_CODEX_FAKE_MODE", "init-pending-descendant")
    host = codex_host.CodexHost(executable=str(helper), project=project)
    child_pid_file = pid_file.with_suffix(".child.pid")

    def interrupt_initialize(self, method, params):
        assert method == "initialize"
        deadline = time.monotonic() + 3
        while not pid_file.with_suffix(".ready").exists():
            assert time.monotonic() < deadline, "fake child did not become ready"
            time.sleep(0.01)
        parent_pid = int(pid_file.read_text())
        child_pid = int(child_pid_file.read_text())
        assert os.getpgid(parent_pid) == parent_pid
        assert os.getpgid(child_pid) == parent_pid
        raise interruption

    monkeypatch.setattr(codex_host.CodexHost, "_request", interrupt_initialize)
    try:
        with pytest.raises(type(interruption)) as error:
            with host:
                pytest.fail("initialization should have been interrupted")
        assert error.value is interruption
        assert_stopped(pid_file)
        assert_stopped(child_pid_file)
    finally:
        # A failing pre-fix regression must not leave its synthetic processes behind.
        host.close()


def test_version_uses_only_version_entrypoint(fake_host):
    helper, _, capture, pid_file = fake_host
    assert codex_host.codex_version(str(helper)) == "0.147.0"
    assert not capture.exists()
    assert_stopped(pid_file)


def test_bad_version_is_not_repeated_in_error(fake_host, monkeypatch):
    helper, _, _, pid_file = fake_host
    monkeypatch.setenv("OWP_CODEX_FAKE_MODE", "bad-version")
    with pytest.raises(codex_host.CodexHostError) as error:
        codex_host.codex_version(str(helper))
    assert "RAW_SECRET" not in str(error.value)
    assert_stopped(pid_file)


def test_missing_executable_is_a_fixed_error(tmp_path):
    with pytest.raises(codex_host.CodexHostError) as error:
        codex_host.codex_version(str(tmp_path / "missing-private-name"))
    assert "missing-private-name" not in str(error.value)


def test_exec_args_encode_whole_tables_and_only_exact_reviewed_hook(tmp_path):
    tomllib = pytest.importorskip("tomllib")
    project = tmp_path / 'project.with.dot "中文"'
    project.mkdir()
    key = str(project / ".codex/hooks.json") + ":pre_tool_use:0:0"
    args = codex_host.build_exec_args("codex", project, key, HASH)
    assert args[-1] == "-"
    assert args[args.index("-C") + 1] == str(project)
    assert {"exec", "--ignore-user-config", "--ephemeral", "--json"}.issubset(args)
    assert not any("bypass" in argument for argument in args)
    assert "-m" not in args and "--model" not in args
    overrides = {}
    for index, argument in enumerate(args):
        if argument == "-c":
            overrides.update(tomllib.loads(args[index + 1]))
    assert overrides["projects"] == {str(project): {"trust_level": "trusted"}}
    assert overrides["hooks"]["state"] == {
        key: {"trusted_hash": HASH, "enabled": True},
    }
    assert overrides["features"] == {
        "hooks": True, "plugins": False, "apps": False,
        "multi_agent": False, "code_mode_host": True,
    }
    assert overrides["web_search"] == "disabled"


@pytest.mark.parametrize("key,current_hash", [
    ("", HASH), ("key", "a" * 64), ("key", "sha256:BAD"),
    ("key\x00bad", HASH), ("key", None),
])
def test_invalid_trust_cannot_generate_exec_args(tmp_path, key, current_hash):
    with pytest.raises(codex_host.CodexHostError):
        codex_host.build_exec_args("codex", tmp_path, key, current_hash)


def test_reviewed_hook_is_passed_as_one_session_state(fake_host):
    tomllib = pytest.importorskip("tomllib")
    helper, project, capture, _ = fake_host
    key = str(project / ".codex/hooks.json") + ":pre_tool_use:0:0"
    host = codex_host.CodexHost(
        executable=str(helper), project=project,
        reviewed_hook={"key": key, "currentHash": HASH},
    )
    with host:
        assert host.list_hooks()["hooks"]
    args = json.loads(capture.with_suffix(".argv.json").read_text())
    state = [tomllib.loads(args[i + 1])["hooks"]["state"]
             for i, value in enumerate(args) if value == "-c"
             and args[i + 1].startswith("hooks.state=")]
    assert state == [{key: {"trusted_hash": HASH, "enabled": True}}]
    assert not any("bypass" in value for value in args)
    assert [json.loads(line)["method"] for line in capture.read_text().splitlines()] == [
        "initialize", "initialized", "hooks/list",
    ]
def test_guarded_execution_keeps_native_workspace_permissions(tmp_path):
    from openworkproof.codex_host import build_exec_args

    args = build_exec_args("codex", tmp_path, "owned-key", "sha256:" + "a" * 64)
    assert args[args.index("-a") + 1] == "never"
    assert args[args.index("-s") + 1] == "workspace-write"
    assert not any("bypass" in argument for argument in args)
