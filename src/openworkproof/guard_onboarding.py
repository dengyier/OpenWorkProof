"""Review one installed hook, verify native session trust, then use Codex.

Review/probe files belong to the local OS user. They are not signed protocol
receipts. No user or system Codex configuration is changed here.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat

from openworkproof import codex_host, guard_cli, guard_probe


REVIEW_SCHEMA = "openworkproof/agent-guard-review/0.1"
PROBE_SCHEMA = "openworkproof/agent-guard-host-check/0.1"
_NATIVE_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RECORD_LIMIT = 64 * 1024


class OnboardingError(guard_cli.GuardError):
    """A fixed explanation, without raw host errors or configuration contents."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _executable_identity(executable: str) -> tuple[str, str]:
    try:
        found = shutil.which(executable)
        if not found:
            raise ValueError
        path = Path(found).resolve(strict=True)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or not os.access(path, os.X_OK):
                raise ValueError
            digest = hashlib.sha256()
            with os.fdopen(fd, "rb", closefd=False) as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise ValueError
        finally:
            os.close(fd)
        return str(path), digest.hexdigest()
    except (OSError, ValueError, TypeError):
        raise OnboardingError("无法确认 Codex 程序的路径和文件身份。") from None


def _load_record(path: Path) -> dict | None:
    try:
        info = path.lstat()
        if info.st_size > _RECORD_LIMIT or info.st_uid != os.getuid() or info.st_mode & 0o022:
            return None
        value = guard_cli._parse_json(guard_cli._read(path).data)
        return value
    except (OSError, guard_cli.GuardError):
        return None


def _save_record(path: Path, value: dict) -> None:
    guard_cli._trusted_directory(path.parent)
    before = guard_cli._read(path, optional=True)
    guard_cli._atomic(path, guard_cli._json_bytes(value), before)


def _static_identity(project: Path, state: Path, executable: str):
    status = guard_cli._status(project, state)
    if not status["configured"]:
        raise OnboardingError("项目尚未安装完整的 OWP 检查，或配置已变化；请先安装或修复。")
    directory = guard_cli._installation_dir(project, state)
    manifest, _ = guard_cli._manifest(directory, project)
    config, raw = guard_cli._config(project / ".codex/hooks.json")
    entries = config["hooks"]["PreToolUse"]
    index = entries.index(manifest["hook_entry"])
    binary, binary_digest = _executable_identity(executable)
    version = codex_host.codex_version(binary)
    identity = {
        "project_root": str(project), "allowed_directory": manifest["allowed_directory"],
        "installation_id": manifest["installation_id"],
        "runtime_digest": manifest["runtime_digest"], "wrapper_digest": manifest["wrapper_digest"],
        "policy_file_digest": manifest["policy_file_digest"],
        "policy_digest": manifest["policy_digest"],
        "hooks_file_digest": guard_cli._digest(raw.data),
        "codex_path": binary, "codex_sha256": binary_digest, "codex_version": version,
    }
    expected_key = str(project / ".codex/hooks.json") + f":pre_tool_use:{index}:0"
    return identity, expected_key, directory, manifest, status


def _valid_review(review: dict | None) -> bool:
    if not isinstance(review, dict) or set(review) != {"schema_version", "identity", "reviewed_at", "consent"}:
        return False
    if review["schema_version"] != REVIEW_SCHEMA or type(review["identity"]) is not dict:
        return False
    if review["consent"] not in ("interactive_own_hook", "explicit_own_hook"):
        return False
    try:
        when = datetime.fromisoformat(review["reviewed_at"])
        return when.utcoffset() == timezone.utc.utcoffset(when)
    except (TypeError, ValueError):
        return False


def _select_hook(entry: dict, project: Path, manifest: dict, expected_key: str) -> dict:
    if type(entry) is not dict or entry.get("cwd") != str(project) or entry.get("warnings") or entry.get("errors"):
        raise OnboardingError("宿主未能无歧义地识别本项目检查，请先处理宿主提示。")
    hooks = entry.get("hooks")
    if not isinstance(hooks, list):
        raise OnboardingError("宿主未返回可识别的检查条目。")
    matches = [h for h in hooks if type(h) is dict and h.get("key") == expected_key]
    if len(matches) != 1:
        raise OnboardingError("宿主未找到唯一的本项目 OWP 检查。")
    hook = matches[0]
    expected_command = manifest["hook_entry"]["hooks"][0]["command"]
    required = {
        "eventName": "preToolUse", "handlerType": "command", "source": "project",
        "sourcePath": str(project / ".codex/hooks.json"), "matcher": "*", "command": expected_command,
    }
    if (any(hook.get(k) != v for k, v in required.items())
            or hook.get("isManaged") is not False or hook.get("enabled") is not True
            or type(hook.get("timeoutSec")) is not int or hook["timeoutSec"] != 5
            or not isinstance(hook.get("currentHash"), str)
            or _NATIVE_HASH.fullmatch(hook["currentHash"]) is None
            or hook.get("trustStatus") not in ("trusted", "untrusted", "modified")):
        raise OnboardingError("宿主中的检查与本地安装记录不一致，未授权运行。")
    # Also reject a duplicate claiming the same owned command under a second key.
    if sum(type(h) is dict and h.get("command") == expected_command for h in hooks) != 1:
        raise OnboardingError("宿主中的 OWP 检查归属存在歧义。")
    return hook


def _capture(project: Path, state: Path, executable: str, *, use_review: bool = True) -> dict:
    try:
        base, expected_key, directory, manifest, status = _static_identity(project, state, executable)
        review = _load_record(directory / "review.json")
        eligible = False
        if use_review and _valid_review(review):
            old = review["identity"]
            eligible = (set(old) == set(base) | {"hook_key", "hook_hash"}
                        and all(old.get(k) == v for k, v in base.items())
                        and old.get("hook_key") == expected_key
                        and isinstance(old.get("hook_hash"), str)
                        and _NATIVE_HASH.fullmatch(old["hook_hash"]) is not None)
        selected = {"key": expected_key, "currentHash": review["identity"]["hook_hash"]} if eligible else None
        with codex_host.CodexHost(executable=base["codex_path"], project=project, reviewed_hook=selected) as host:
            native = host.list_hooks()
        hook = _select_hook(native, project, manifest, expected_key)
        identity = dict(base, hook_key=hook["key"], hook_hash=hook["currentHash"])
        current = bool(eligible and review["identity"] == identity)
        return {"identity": identity, "hook": hook, "directory": directory, "static_status": status,
                "review_current": current, "review_status": "current" if current else "outdated" if review else "missing"}
    except (guard_cli.GuardError, codex_host.CodexHostError, OSError, ValueError, TypeError, KeyError):
        raise OnboardingError("无法确认当前安装和宿主检查，请运行状态检查并处理提示。") from None


def _probe_status(snapshot: dict) -> str:
    record = _load_record(snapshot["directory"] / "probe.json")
    if not record:
        return "not_run"
    if (record.get("schema_version") != PROBE_SCHEMA or record.get("identity") != snapshot["identity"]):
        return "outdated"
    report = record.get("report")
    if not isinstance(report, dict) or record.get("identity_unchanged") is not True:
        return "unknown"
    checks = report.get("checks")
    if (report.get("status") == "passed" and type(checks) is dict
            and set(checks) == set(guard_probe.REQUIRED_CHECKS)
            and all(value is True for value in checks.values())):
        return "passed"
    return "failed" if report.get("status") == "failed" else "unknown"


def _doctor_result(snapshot: dict) -> dict:
    probe_status = _probe_status(snapshot)
    trusted = snapshot["review_current"] and snapshot["hook"]["trustStatus"] == "trusted"
    return {"configured": True, "allowed_directory": snapshot["identity"]["allowed_directory"],
            "review_status": snapshot["review_status"], "host_trust_status": snapshot["hook"]["trustStatus"],
            "probe_status": probe_status, "ready_for_guarded_run": trusted and probe_status == "passed",
            "ordinary_startup_verified": False, "activation_scope": "guarded_codex_invocation",
            "codex_path": snapshot["identity"]["codex_path"], "codex_version": snapshot["identity"]["codex_version"],
            "identity": snapshot["identity"]}


def doctor(project: Path, state: Path, *, executable: str = "codex") -> dict:
    try:
        return _doctor_result(_capture(project, state, executable))
    except OnboardingError as error:
        try:
            configured = guard_cli._status(project, state)["configured"]
        except (OSError, guard_cli.GuardError, ValueError):
            configured = False
        return {"configured": configured, "review_status": "unknown", "host_trust_status": "unknown",
                "probe_status": "unknown", "ready_for_guarded_run": False, "ordinary_startup_verified": False,
                "activation_scope": "guarded_codex_invocation", "reason": str(error)}


def review_summary(project: Path, state: Path, *, executable: str = "codex") -> dict:
    snapshot = _capture(project, state, executable, use_review=False)
    return {"identity": snapshot["identity"], "allowed_directory": snapshot["identity"]["allowed_directory"],
            "codex_path": snapshot["identity"]["codex_path"], "codex_version": snapshot["identity"]["codex_version"],
            "hook_hash": snapshot["identity"]["hook_hash"], "scope": "仅在 OWP 受保护启动中授权本项目这一条检查。"}


def _enable(
    project: Path, state: Path, *, executable: str = "codex", trust_own_hook: bool = False,
    reviewed_identity: dict | None = None, consent_method: str = "explicit_own_hook",
) -> dict:
    if not trust_own_hook or consent_method not in ("interactive_own_hook", "explicit_own_hook"):
        raise OnboardingError("尚未授权当前 OWP 检查；请先审阅并确认这一条检查。")
    before = _capture(project, state, executable, use_review=False)
    if reviewed_identity is not None and reviewed_identity != before["identity"]:
        raise OnboardingError("审阅后检查版本发生变化，请重新审阅。")
    _save_record(before["directory"] / "review.json", {
        "schema_version": REVIEW_SCHEMA, "identity": before["identity"], "reviewed_at": _now(), "consent": consent_method,
    })
    trusted = _capture(project, state, executable)
    if not trusted["review_current"] or trusted["hook"]["trustStatus"] != "trusted":
        raise OnboardingError("宿主尚未认可这一版本的授权，未开始真实检查。")
    identity = trusted["identity"]
    report = guard_probe.perform_probe(
        executable=identity["codex_path"], project=project, allowed_directory=Path(identity["allowed_directory"]),
        reviewed_hook={"key": identity["hook_key"], "currentHash": identity["hook_hash"]},
        event_log=trusted["directory"] / "events.jsonl", installation_id=identity["installation_id"],
    )
    unchanged = False
    try:
        after = _capture(project, state, executable)
        unchanged = after["identity"] == identity and after["review_current"] and after["hook"]["trustStatus"] == "trusted"
    except OnboardingError:
        pass
    _save_record(trusted["directory"] / "probe.json", {
        "schema_version": PROBE_SCHEMA, "identity": identity, "identity_unchanged": unchanged, "report": report,
    })
    result = doctor(project, state, executable=executable)
    if not unchanged:
        result["probe_status"] = "unknown"
    return result


def _task_events(path: Path, position, installation_id: str, policy_digest: str) -> list[dict] | None:
    offset, expected_file = position
    try:
        guard_cli._no_links(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return [] if offset == 0 and expected_file is None else None
    except (OSError, guard_cli.GuardError):
        return None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size < offset
                or expected_file is not None and expected_file != (info.st_dev, info.st_ino)):
            return None
        with os.fdopen(fd, "rb", closefd=False) as handle:
            handle.seek(offset)
            raw = handle.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024 or raw and not raw.endswith(b"\n"):
            return None
        rows = []
        for line in raw.splitlines():
            row = guard_cli._parse_json(line)
            if row.get("installation_id") != installation_id:
                return None  # Concurrent activity is not this task's evidence.
            if (row.get("schema_version") != guard_cli.EVENT_SCHEMA
                    or row.get("policy_digest") != policy_digest
                    or row.get("decision") not in ("allow", "deny")
                    or row.get("tool_name") not in ("Bash", "apply_patch", "unsupported", "invalid")
                    or not isinstance(row.get("action_digest"), str)
                    or guard_cli._HEX.fullmatch(row["action_digest"]) is None
                    or not isinstance(row.get("code"), str)
                    or re.fullmatch(r"[A-Z0-9_]{1,80}", row["code"]) is None):
                return None
            rows.append(row)
        return rows
    except (OSError, ValueError, TypeError, guard_cli.GuardError):
        return None
    finally:
        os.close(fd)


def _run_guarded_task(project: Path, state: Path, prompt: str, *, executable: str = "codex") -> dict:
    if not isinstance(prompt, str) or not prompt.strip() or len(prompt.encode()) > 64 * 1024:
        raise OnboardingError("请提供一条不超过 64 KiB 的任务说明。")
    snapshot = _capture(project, state, executable)
    if not _doctor_result(snapshot)["ready_for_guarded_run"]:
        raise OnboardingError("当前版本尚未完成授权和真实检查，请先运行 enable。")
    identity = snapshot["identity"]
    args = codex_host.build_exec_args(identity["codex_path"], project, identity["hook_key"], identity["hook_hash"])
    log = snapshot["directory"] / "events.jsonl"
    try:
        position = guard_probe._log_position(log)
    except (OSError, ValueError):
        raise OnboardingError("无法读取本次检查的起点，未启动任务。") from None
    run = guard_probe.run_host_process(args, prompt.encode(), project, timeout_seconds=300)
    messages, turn_completed, native_tools, unfamiliar_item = [], False, 0, False
    try:
        for line in run["stdout"].splitlines():
            event = json.loads(line)
            if type(event) is not dict:
                raise ValueError
            item = event.get("item", {})
            if type(item) is dict and item.get("type") == "agent_message" and isinstance(item.get("text"), str):
                messages.append(item["text"])
            if event.get("type") == "item.completed" and type(item) is dict:
                if item.get("type") in ("command_execution", "file_change"):
                    native_tools += 1
                elif item.get("type") not in ("agent_message", "reasoning", "plan", "todo_list", "error"):
                    unfamiliar_item = True
            turn_completed |= event.get("type") == "turn.completed"
    except (ValueError, UnicodeError, TypeError):
        turn_completed = False
    unchanged = False
    try:
        after = _capture(project, state, executable)
        unchanged = after["identity"] == identity and after["review_current"] and after["hook"]["trustStatus"] == "trusted"
    except OnboardingError:
        pass
    rows = _task_events(log, position, identity["installation_id"], identity["policy_digest"])
    protection = "unverified"
    if rows is not None and not unfamiliar_item:
        allowed = sum(row["decision"] == "allow" for row in rows)
        denied = [row for row in rows if row["decision"] == "deny"]
        stderr = run["stderr"].decode(errors="replace")
        native_blocks = stderr.count("Command blocked by PreToolUse hook")
        native_failure = bool(re.search(r"hook[^\n]*(?:failed|timed out|untrusted|skipped|modified)", stderr, re.I))
        blocks_match = native_blocks == len(denied) and all("OWP [" + row["code"] + "]" in stderr for row in denied)
        if allowed == native_tools and blocks_match and not native_failure:
            protection = "window_activity_observed" if rows else "no_tool_actions"
    complete = (run["exit_code"] == 0 and not run["timed_out"] and not run["output_limited"]
                and turn_completed and unchanged and protection != "unverified")
    return {"status": "completed" if complete else "unverified", "assistant_text": "\n\n".join(messages),
            "exit_code": run["exit_code"], "activation_scope": "guarded_codex_invocation",
            "identity_unchanged": unchanged, "ordinary_startup_verified": False,
            "protection_observation": protection, "native_tool_count": native_tools,
            "per_tool_session_proof": False}


def enable(
    project: Path, state: Path, *, executable: str = "codex", trust_own_hook: bool = False,
    reviewed_identity: dict | None = None, consent_method: str = "explicit_own_hook",
) -> dict:
    # Do not race our own uninstall/upgrade into Codex's fail-open boundary.
    # The CLI asks for consent before entering here. Ctrl-C ends a running check.
    with guard_cli._project_lock(project):
        return _enable(project, state, executable=executable, trust_own_hook=trust_own_hook,
                       reviewed_identity=reviewed_identity, consent_method=consent_method)


def run_guarded_task(project: Path, state: Path, prompt: str, *, executable: str = "codex") -> dict:
    with guard_cli._project_lock(project):
        return _run_guarded_task(project, state, prompt, executable=executable)
