"""Small, local Codex PreToolUse policy. Copied verbatim by the installer.

Standard library only: run with Python -I, without importing project code.
The host must actually load/trust this hook; this is not an OS security boundary.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import sys


MAX_INPUT_BYTES = 1024 * 1024
MAX_POLICY_BYTES = 16 * 1024
SCHEMA = "openworkproof/agent-guard/0.1"
POLICY_FIELDS = {"schema_version", "project_root", "allowed_directory", "installation_id"}


@dataclass(frozen=True)
class GuardDecision:
    allowed: bool
    code: str
    reason: str


def _deny(code: str, reason: str) -> GuardDecision:
    return GuardDecision(False, code, reason)


ALLOW = GuardDecision(True, "WITHIN_PREVIEW", "操作在预览目录允许范围内。")
INVALID = _deny("INVALID_INPUT", "OWP 无法识别这次操作，已拒绝执行。")
UNAVAILABLE = _deny("POLICY_UNAVAILABLE", "OWP 保护设置不可用，已拒绝执行；请先检查保护状态。")
OUTSIDE = _deny("PATH_OUTSIDE_PREVIEW", "本次仅允许访问预览目录；其他文件、隐藏路径和链接不在允许范围内。")
COMMAND = _deny("COMMAND_NOT_ALLOWED", "预览模式仅允许 /bin/cat、/bin/ls、/bin/pwd 的受限只读调用；请用 apply_patch 编辑预览。")
PATCH = _deny("PATCH_NOT_ALLOWED", "本次仅允许在预览目录增加或修改普通文件；不允许删除、移动或格式不明的补丁。")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _plain_text(value: object) -> bool:
    return isinstance(value, str) and bool(value) and all(ord(c) >= 32 and ord(c) != 127 for c in value)


def _policy_paths(policy: object) -> tuple[Path, Path]:
    if type(policy) is not dict or set(policy) != POLICY_FIELDS:
        raise ValueError("invalid policy")
    if policy["schema_version"] != SCHEMA or not _plain_text(policy["installation_id"]):
        raise ValueError("invalid policy")
    roots = []
    for key in ("project_root", "allowed_directory"):
        raw = policy[key]
        if not _plain_text(raw):
            raise ValueError("invalid directory")
        path = Path(raw)
        if not path.is_absolute() or path.resolve(strict=True) != path or not path.is_dir():
            raise ValueError("directory changed")
        roots.append(path)
    project, allowed = roots
    if allowed == project or not _within(allowed, project):
        raise ValueError("preview must be a project subdirectory")
    if any(part.startswith(".") for part in allowed.relative_to(project).parts):
        raise ValueError("hidden preview")
    return project, allowed


def _safe_path(raw: object, cwd: Path, allowed: Path, *, directory: bool = False, existing: bool = False) -> bool:
    if not _plain_text(raw):
        return False
    path = Path(raw)
    if ".." in path.parts:
        return False
    if not path.is_absolute():
        path = cwd / path
    if not _within(path, allowed):
        return False
    relative = path.relative_to(allowed)
    if any(part.startswith(".") for part in relative.parts):
        return False
    # Inspect each existing ancestor instead of silently resolving a link.
    current = allowed
    for part in ("", *relative.parts):
        if part:
            current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            if existing or directory:
                return False
            continue
        if stat.S_ISLNK(info.st_mode):
            return False
        if current != path:
            if not stat.S_ISDIR(info.st_mode):
                return False
        elif directory:
            if not stat.S_ISDIR(info.st_mode):
                return False
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            return False
    return path.resolve(strict=False) == path


def _shell_decision(inputs: dict, cwd: Path, project: Path, allowed: Path) -> GuardDecision:
    # No interactive process is allowed: Codex does not re-hook write_stdin.
    supported = {
        "command", "description", "workdir", "cwd", "working_directory",
        "tty", "login", "yield_time_ms", "max_output_tokens",
        "sandbox_permissions", "justification", "prefix_rule",
    }
    if set(inputs) - supported:
        return COMMAND
    directories = [key for key in ("workdir", "cwd", "working_directory") if inputs.get(key) is not None]
    if len(directories) > 1:
        return COMMAND
    if inputs.get("tty") not in (None, False) or inputs.get("sandbox_permissions") == "require_escalated":
        return COMMAND
    for key in ("workdir", "cwd", "working_directory"):
        if key not in inputs or inputs[key] is None:
            continue
        raw = inputs[key]
        if not _plain_text(raw) or not Path(raw).is_absolute():
            return OUTSIDE
        candidate = Path(raw)
        if candidate.resolve(strict=True) != candidate or not candidate.is_dir() or not _within(candidate, project):
            return OUTSIDE
        cwd = candidate
    command = inputs["command"]
    if not _plain_text(command) or any(c in command for c in ";&|<>$`(){}\\*?[]~!"):
        return COMMAND
    try:
        argv = shlex.split(command, posix=True)
    except ValueError:
        return COMMAND
    if not argv:
        return COMMAND
    executable, *arguments = argv
    if executable == "/bin/pwd":
        return ALLOW if not arguments else COMMAND
    if executable not in ("/bin/cat", "/bin/ls"):
        return COMMAND
    paths = []
    options_done = False
    for argument in arguments:
        if executable == "/bin/cat" and argument == "-":
            return COMMAND  # cat treats '-' as stdin even after '--'.
        if not options_done and argument == "--":
            options_done = True
        elif argument.startswith("-"):
            if options_done:
                return COMMAND  # Some utilities also parse options after paths.
            options = {"-n"} if executable == "/bin/cat" else set()
            if argument not in options:
                return COMMAND
        else:
            paths.append(argument)
            options_done = True
    if not paths:
        if executable == "/bin/cat":
            return COMMAND
        paths = [str(cwd)]
    if len(paths) > 32:
        return COMMAND
    if not all(_safe_path(p, cwd, allowed, directory=executable == "/bin/ls", existing=True) for p in paths):
        return OUTSIDE
    return ALLOW


def _patch_decision(command: str, cwd: Path, allowed: Path) -> GuardDecision:
    if len(command.encode()) > MAX_INPUT_BYTES:
        return PATCH
    lines = command.splitlines()
    if len(lines) < 3 or lines[0] != "*** Begin Patch" or lines[-1] != "*** End Patch":
        return PATCH
    index, seen = 1, set()
    while index < len(lines) - 1:
        header = lines[index]
        if header.startswith("*** Add File: "):
            kind, raw = "add", header[len("*** Add File: "):]
        elif header.startswith("*** Update File: "):
            kind, raw = "update", header[len("*** Update File: "):]
        else:
            return PATCH
        if raw != raw.strip() or not _safe_path(raw, cwd, allowed, existing=kind == "update"):
            return OUTSIDE
        target = str((cwd / raw).absolute())
        if target in seen or len(seen) >= 64:
            return PATCH
        seen.add(target)
        index += 1
        chunks = 0
        while index < len(lines) - 1:
            line = lines[index]
            if line.startswith(("*** Add File: ", "*** Update File: ")):
                break
            if kind == "add":
                if not line.startswith("+"):
                    return PATCH
            elif line == "@@" or line.startswith("@@ "):
                chunks += 1
            elif line == "*** End of File":
                if index + 1 < len(lines) - 1 and not lines[index + 1].startswith(("*** Add File: ", "*** Update File: ")):
                    return PATCH
            elif not chunks or not line.startswith((" ", "+", "-")):
                return PATCH
            index += 1
        if kind == "update" and not chunks:
            return PATCH
    return ALLOW if seen else PATCH


def evaluate_event(event: object, policy: object) -> GuardDecision:
    """Evaluate host-supplied input without executing it or granting authority."""
    try:
        project, allowed = _policy_paths(policy)
    except (OSError, ValueError, TypeError, RuntimeError):
        return UNAVAILABLE
    if type(event) is not dict or event.get("hook_event_name") != "PreToolUse":
        return INVALID
    if event.get("tool_name") not in ("Bash", "apply_patch"):
        return _deny("TOOL_NOT_SUPPORTED", "预览模式未授权这个工具；允许受限只读命令和预览文件补丁。")
    inputs = event.get("tool_input")
    raw_cwd = event.get("cwd")
    if type(inputs) is not dict or not isinstance(inputs.get("command"), str) or not _plain_text(raw_cwd):
        return INVALID
    try:
        cwd = Path(raw_cwd)
        if not cwd.is_absolute() or cwd.resolve(strict=True) != cwd or not cwd.is_dir() or not _within(cwd, project):
            return OUTSIDE
        if event["tool_name"] == "Bash":
            return _shell_decision(inputs, cwd, project, allowed)
        # apply_patch uses the session cwd, not a caller-selected workdir.
        if any(inputs.get(key) is not None for key in ("workdir", "cwd", "working_directory")):
            return INVALID
        return _patch_decision(inputs["command"], cwd, allowed)
    except (OSError, ValueError, TypeError, RuntimeError):
        return INVALID


def hook_response(decision: GuardDecision) -> dict:
    if decision.allowed:
        return {}  # Keep the host's own permissions and approval requirements.
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": f"OWP [{decision.code}]：{decision.reason}",
    }}


def _load_json(raw: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def _append_event(policy_path: Path, policy: dict, event: object, raw: bytes, decision: GuardDecision) -> None:
    tool_name = event.get("tool_name") if type(event) is dict else "invalid"
    if tool_name not in ("Bash", "apply_patch", "invalid"):
        tool_name = "unsupported"
    record = {
        "schema_version": "openworkproof/agent-guard-event/0.1",
        "installation_id": policy["installation_id"],
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "tool_name": tool_name,
        "decision": "allow" if decision.allowed else "deny",
        "code": decision.code,
        "action_digest": hashlib.sha256(raw if event is None else _canonical(event)).hexdigest(),
        "policy_digest": hashlib.sha256(_canonical(policy)).hexdigest(),
    }
    target = policy_path.with_name("events.jsonl")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode) or os.fstat(fd).st_nlink != 1:
            raise ValueError("invalid event log")
        data = _canonical(record) + b"\n"
        if os.write(fd, data) != len(data):
            raise OSError("partial event write")
    finally:
        os.close(fd)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="OWP local Codex execution-before check")
    parser.add_argument("--policy", type=Path, required=True)
    args = parser.parse_args(argv)
    decision = UNAVAILABLE
    try:
        if args.policy.is_symlink() or args.policy.stat().st_size > MAX_POLICY_BYTES:
            raise ValueError("invalid policy file")
        policy = _load_json(args.policy.read_bytes())
        _policy_paths(policy)
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        event = None
        if len(raw) > MAX_INPUT_BYTES:
            decision = INVALID
        else:
            try:
                event = _load_json(raw)
            except (ValueError, UnicodeError):
                decision = INVALID
            else:
                decision = evaluate_event(event, policy)
        _append_event(args.policy, policy, event, raw, decision)
    except Exception:
        # Never echo exception text, paths, input, environment or source content.
        decision = UNAVAILABLE
    sys.stdout.write(json.dumps(hook_response(decision), ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
