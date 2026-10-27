"""Install a project-local Codex hook without altering host trust settings."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
from typing import NamedTuple
import uuid


RUNTIME_SOURCE = Path(__file__).with_name("agent_guard.py")
DEFAULT_STATE_DIR = Path.home() / ".local/share/openworkproof/guard"
POLICY_SCHEMA = "openworkproof/agent-guard/0.1"
INSTALL_SCHEMA = "openworkproof/agent-guard-installation/0.1"
EVENT_SCHEMA = "openworkproof/agent-guard-event/0.1"
_HEX = re.compile(r"[0-9a-f]{64}\Z")


class GuardError(Exception):
    """An unsafe or ambiguous installation must not change the configuration."""


class Snapshot(NamedTuple):
    data: bytes
    mode: int
    identity: tuple[int, int, int, int]


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _policy_digest(value: dict) -> str:
    return _digest(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GuardError("duplicate JSON key")
        result[key] = value
    return result


def _parse_json(raw: bytes) -> dict:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError) as exc:
        raise GuardError("invalid JSON") from exc
    if not isinstance(value, dict):
        raise GuardError("JSON must be an object")
    return value


def _no_links(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise GuardError("symbolic links are not accepted")


def _path(value: str | Path, base: Path | None = None, *, directory=False) -> Path:
    path = Path(value).expanduser()
    if ".." in path.parts:
        raise GuardError("parent traversal is not accepted")
    if not path.is_absolute():
        path = (base or Path.cwd()) / path
    _no_links(path)
    path = path.resolve(strict=False)
    if directory and not path.is_dir():
        raise GuardError("directory does not exist")
    return path


def _inside(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _scope(project: Path, allowed: Path, state: Path) -> None:
    if project == Path(project.anchor) or allowed == project or not _inside(allowed, project):
        raise GuardError("allow-dir must be a proper project subdirectory")
    if any(part.startswith(".") for part in allowed.relative_to(project).parts):
        raise GuardError("allow-dir cannot contain hidden paths or .codex")
    if _inside(state, allowed) or _inside(allowed, state):
        raise GuardError("state-dir and allow-dir cannot overlap")


def _trusted_directory(path: Path) -> None:
    """Check only the component's control directories, not all OS ancestors."""
    _no_links(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise GuardError("unsafe control directory permissions or ownership")


def _read(path: Path, *, optional=False) -> Snapshot | None:
    _no_links(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if optional:
            return None
        raise GuardError("required installation file is missing") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise GuardError("expected a regular file with one link")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read()
        return Snapshot(data, stat.S_IMODE(info.st_mode), (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns))
    finally:
        os.close(fd)


def _config(path: Path) -> tuple[dict, Snapshot | None]:
    snapshot = _read(path, optional=True)
    value = _parse_json(snapshot.data) if snapshot else {}
    hooks = value.get("hooks", {})
    if not isinstance(hooks, dict) or not isinstance(hooks.get("PreToolUse", []), list):
        raise GuardError("invalid hooks configuration")
    return value, snapshot


@contextmanager
def _project_lock(project: Path):
    if os.name != "posix":
        raise GuardError("this release supports POSIX hosts only")
    import fcntl

    fd = os.open(project, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise GuardError("another guard operation is using this project") from exc
        yield
    finally:
        os.close(fd)


def _atomic(path: Path, data: bytes | None, before: Snapshot | None, mode=0o600) -> Snapshot | None:
    """Check-and-replace under our project lock; not a hostile-writer OS barrier."""
    _no_links(path)
    if _read(path, optional=True) != before:
        raise GuardError("file changed concurrently; refusing to overwrite")
    if data is None:
        if before is not None:
            path.unlink()
        return None
    temporary = path.with_name(".owp-guard-" + uuid.uuid4().hex + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), mode)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _no_links(path.parent)
        if _read(path, optional=True) != before:
            raise GuardError("file changed concurrently; refusing to overwrite")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return _read(path)


def _transaction(changes):
    completed = []
    try:
        for path, data, before, mode in changes:
            after = _atomic(path, data, before, mode)
            completed.append((path, before, after))
    except (OSError, GuardError):
        for path, before, after in reversed(completed):
            try:
                _atomic(path, before.data if before else None, after, before.mode if before else 0o600)
            except (OSError, GuardError):
                # Never overwrite a concurrent writer just to finish rollback.
                pass
        raise


def _wrapper(python: Path, runtime: Path, policy: Path, installation_id: str, source_digest: str, policy_digest: str) -> bytes:
    denial = json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "OWP guard could not validate this operation."}}, separators=(",", ":"))
    supervisor = '''import hashlib, json, os, pathlib, stat, subprocess, sys
def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate output key")
        result[key] = value
    return result
def check_file(path, expected, limit):
    target = pathlib.Path(path)
    current = pathlib.Path(target.anchor)
    for part in target.parts[1:]:
        current /= part
        if stat.S_ISLNK(current.lstat().st_mode):
            raise ValueError("linked control file")
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("non-regular control file")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read(limit + 1)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("control file changed while reading")
        if len(raw) > limit or hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("control file digest mismatch")
    finally:
        os.close(fd)
try:
    # The child reopens these paths after verification. Same-user replacement
    # races remain outside this hook's boundary; this is not OS isolation.
    check_file(sys.argv[1], sys.argv[3], 1048576)
    check_file(sys.argv[2], sys.argv[4], 16384)
    payload = sys.stdin.buffer.read(1048577)
    if len(payload) > 1048576:
        raise ValueError("oversized input")
    process = subprocess.run([sys.executable, "-I", sys.argv[1], "--policy", sys.argv[2]], input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2)
    if process.returncode != 0 or len(process.stdout) > 16384:
        raise ValueError("runtime failed")
    result = json.loads(process.stdout, object_pairs_hook=unique)
    if not isinstance(result, dict):
        raise ValueError("invalid output")
    if result != {}:
        specific = result.get("hookSpecificOutput")
        if (set(result) != {"hookSpecificOutput"} or not isinstance(specific, dict)
            or set(specific) != {"hookEventName", "permissionDecision", "permissionDecisionReason"}
            or specific["hookEventName"] != "PreToolUse" or specific["permissionDecision"] != "deny"
            or not isinstance(specific["permissionDecisionReason"], str) or not specific["permissionDecisionReason"]):
            raise ValueError("unsupported output")
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
except Exception:
    raise SystemExit(1)
'''
    text = "#!/bin/sh\n# OWP synchronous hook; failures after this wrapper starts deny the operation.\n"
    text += "deny() { printf '%s\\n' " + shlex.quote(denial) + "; exit 0; }\n"
    text += '[ "$#" -eq 4 ] || deny\n'
    text += '[ "$1" = ' + shlex.quote(installation_id) + ' ] || deny\n'
    text += '[ "$2" = ' + shlex.quote(source_digest) + ' ] || deny\n'
    text += '[ "$4" = ' + shlex.quote(policy_digest) + ' ] || deny\n'
    command = " ".join(shlex.quote(str(value)) for value in (python, "-I", "-c", supervisor, runtime, policy, source_digest, policy_digest))
    text += "if result=$(" + command + " 2>/dev/null); then\n  printf '%s\\n' \"$result\"\nelse\n  deny\nfi\n"
    return text.encode()


def _entry(directory: Path, installation_id: str, runtime_digest: str, wrapper_digest: str, policy_digest: str | None = None) -> dict:
    # Include both snapshots in the definition hash so an upgrade needs host trust.
    arguments = ["/bin/sh", directory / "hook.sh", installation_id, runtime_digest, wrapper_digest]
    if policy_digest is not None:
        arguments.append(policy_digest)
    command = " ".join(shlex.quote(str(value)) for value in arguments)
    return {"matcher": "*", "hooks": [{"type": "command", "command": command, "timeout": 5}]}


def _installation_dir(project: Path, state: Path) -> Path:
    return state / _digest(str(project).encode())


def _has_owned_marker(entry: object, installation_id: str, directory: Path) -> bool:
    if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
        return False
    for handler in entry["hooks"]:
        if not isinstance(handler, dict) or not isinstance(handler.get("command"), str):
            continue
        command = handler["command"]
        try:
            arguments = shlex.split(command)
        except ValueError:
            return installation_id in command or str(directory / "hook.sh") in command
        if installation_id in arguments or str(directory / "hook.sh") in arguments:
            return True
    return False


def _manifest(directory: Path, project: Path) -> tuple[dict, Snapshot]:
    info = (directory / "installation.json").lstat()
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise GuardError("unsafe installation ownership record permissions")
    snapshot = _read(directory / "installation.json")
    value = _parse_json(snapshot.data)
    try:
        expected_fields = {"schema_version", "active", "installation_id", "project_root", "allowed_directory", "python_path", "runtime_digest", "wrapper_digest", "policy_file_digest", "policy_digest", "hook_entry", "original_config_exists", "original_config_digest", "original_config_mode", "restore_original", "installed_config_digest", "codex_dir_created"}
        valid_id = str(uuid.UUID(value["installation_id"])) == value["installation_id"]
        valid = set(value) == expected_fields and value["schema_version"] == INSTALL_SCHEMA and value["project_root"] == str(project)
        valid &= type(value["active"]) is bool and type(value["original_config_exists"]) is bool
        valid &= type(value["restore_original"]) is bool and isinstance(value["hook_entry"], dict)
        valid &= type(value["codex_dir_created"]) is bool and isinstance(value["allowed_directory"], str)
        valid &= type(value["original_config_mode"]) is int and 0 <= value["original_config_mode"] <= 0o777
        valid &= all(isinstance(value[k], str) and _HEX.fullmatch(value[k]) for k in ("runtime_digest", "wrapper_digest", "policy_file_digest", "policy_digest", "installed_config_digest"))
        valid &= valid_id and Path(value["python_path"]).is_absolute()
        # Accept the previous owned definition only so an explicit upgrade/uninstall
        # remains possible. New definitions always bind the policy bytes as well.
        valid &= value["hook_entry"] in (
            _entry(directory, value["installation_id"], value["runtime_digest"], value["wrapper_digest"], value["policy_file_digest"]),
            _entry(directory, value["installation_id"], value["runtime_digest"], value["wrapper_digest"]),
        )
        if value["original_config_exists"]:
            valid &= bool(_HEX.fullmatch(value["original_config_digest"]))
    except (ValueError, KeyError, TypeError):
        valid = False
    if not valid:
        raise GuardError("invalid installation ownership record")
    return value, snapshot


def _last_observed(directory: Path, manifest: dict) -> dict | None:
    path = directory / "events.jsonl"
    _no_links(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            return None
        with os.fdopen(fd, "rb", closefd=False) as handle:
            start = max(0, info.st_size - 1024 * 1024)
            handle.seek(start)
            if start:
                handle.readline()
            lines = handle.readlines()
        keys = {"schema_version", "installation_id", "checked_at", "tool_name", "decision", "code", "action_digest", "policy_digest"}
        for raw in reversed(lines):
            try:
                event = _parse_json(raw)
                when = datetime.fromisoformat(event["checked_at"].replace("Z", "+00:00"))
                if (set(event) == keys and event["schema_version"] == EVENT_SCHEMA
                        and event["installation_id"] == manifest["installation_id"]
                        and event["policy_digest"] == manifest["policy_digest"]
                        and event["decision"] in {"allow", "deny"}
                        and event["tool_name"] in {"Bash", "apply_patch", "unsupported", "invalid"}
                        and isinstance(event["code"], str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", event["code"])
                        and isinstance(event["action_digest"], str) and _HEX.fullmatch(event["action_digest"])
                        and when.utcoffset() == timezone.utc.utcoffset(when)):
                    return event
            except (GuardError, KeyError, TypeError, ValueError, AttributeError):
                continue
        return None
    finally:
        os.close(fd)


def _inspect(project: Path, state: Path, manifest: dict) -> tuple[dict, dict | None, Snapshot | None]:
    directory = _installation_dir(project, state)
    drift = []
    try:
        for path in (state, directory, project / ".codex"):
            _trusted_directory(path)
    except (OSError, GuardError):
        drift.append("control_directory_permissions_unsafe")
    for name, key in (("runtime.py", "runtime_digest"), ("hook.sh", "wrapper_digest"), ("policy.json", "policy_file_digest")):
        try:
            snapshot = _read(directory / name)
            if _digest(snapshot.data) != manifest[key]:
                drift.append(name + "_changed")
        except (OSError, GuardError):
            drift.append(name + "_missing_or_unsafe")
    if manifest["original_config_exists"]:
        try:
            backup = _read(directory / "hooks.before")
            if _digest(backup.data) != manifest["original_config_digest"]:
                drift.append("backup_changed")
        except (OSError, GuardError):
            drift.append("backup_missing_or_unsafe")
    try:
        allowed = _path(manifest["allowed_directory"], directory=True)
        _scope(project, allowed, state)
    except (OSError, GuardError):
        drift.append("allowed_directory_missing_or_unsafe")
    if not Path(manifest["python_path"]).is_file() or not os.access(manifest["python_path"], os.X_OK):
        drift.append("python_unavailable")
    config = snapshot = None
    try:
        config, snapshot = _config(project / ".codex/hooks.json")
        entries = config.get("hooks", {}).get("PreToolUse", [])
        expected = 1 if manifest["active"] else 0
        marked = sum(_has_owned_marker(item, manifest["installation_id"], directory) for item in entries)
        if entries.count(manifest["hook_entry"]) != expected or marked != expected:
            drift.append("hook_entry_changed_or_missing")
    except (OSError, GuardError):
        drift.append("hooks_missing_or_invalid")
    try:
        source = _read(RUNTIME_SOURCE)
        desired_python = Path(sys.executable).resolve()
        desired_runtime = _digest(source.data)
        desired_wrapper = _wrapper(desired_python, directory / "runtime.py", directory / "policy.json", manifest["installation_id"], desired_runtime, manifest["policy_file_digest"])
        desired_entry = _entry(directory, manifest["installation_id"], desired_runtime, _digest(desired_wrapper), manifest["policy_file_digest"])
        upgrade_available = desired_runtime != manifest["runtime_digest"] or _digest(desired_wrapper) != manifest["wrapper_digest"] or desired_entry != manifest["hook_entry"]
    except (OSError, GuardError):
        upgrade_available = None
    try:
        observed = _last_observed(directory, manifest)
    except (OSError, GuardError):
        observed = None
        drift.append("events_unsafe")
    result = {"project_root": str(project), "state_directory": str(directory), "installation_id": manifest["installation_id"], "configured": manifest["active"] and not drift, "last_observed": observed, "drift": drift, "upgrade_available": upgrade_available, "policy_digest": manifest["policy_digest"], "allowed_directory": manifest["allowed_directory"], "read_scope": "allowed_directory only", "coverage": "supported local PreToolUse paths only; host trust and activation must be verified separately"}
    return result, config, snapshot


def _install(project: Path, allowed: Path, state: Path, *, upgrade=False) -> dict:
    _scope(project, allowed, state)
    config_path = project / ".codex/hooks.json"
    directory = _installation_dir(project, state)
    for path in (state, directory, config_path.parent):
        _trusted_directory(path)
    config, before = _config(config_path)
    source = _read(RUNTIME_SOURCE)
    if not source.data:
        raise GuardError("runtime source is empty")
    python = Path(sys.executable).resolve()
    source_digest = _digest(source.data)
    previous = previous_snapshot = None
    if directory.exists():
        previous, previous_snapshot = _manifest(directory, project)
        status, config, before = _inspect(project, state, previous)
        if status["drift"]:
            raise GuardError("installation drift detected; refusing to overwrite: " + ", ".join(status["drift"]))
        if previous["active"]:
            if previous["allowed_directory"] != str(allowed):
                raise GuardError("allow-dir differs; uninstall before changing the grant")
            if not status["upgrade_available"]:
                return dict(status, requires_trust=True, changed=False)
            if not upgrade:
                raise GuardError("runtime source changed; use --upgrade and review/retrust the hook")
    active = previous is not None and previous["active"]
    installation_id = previous["installation_id"] if active else str(uuid.uuid4())
    policy = {"schema_version": POLICY_SCHEMA, "project_root": str(project), "allowed_directory": str(allowed), "installation_id": installation_id}
    policy_raw = _json_bytes(policy)
    wrapper = _wrapper(python, directory / "runtime.py", directory / "policy.json", installation_id, source_digest, _digest(policy_raw))
    entry = _entry(directory, installation_id, source_digest, _digest(wrapper), _digest(policy_raw))
    if active:
        config["hooks"]["PreToolUse"] = [entry if item == previous["hook_entry"] else item for item in config["hooks"]["PreToolUse"]]
        original_exists = previous["original_config_exists"]
        original_digest = previous["original_config_digest"]
        original_mode = previous["original_config_mode"]
        restore = previous["restore_original"] and before is not None and _digest(before.data) == previous["installed_config_digest"]
    else:
        config.setdefault("hooks", {}).setdefault("PreToolUse", []).append(entry)
        original_exists = before is not None
        original_digest = _digest(before.data) if before else None
        original_mode = before.mode if before else 0o600
        restore = True
    config_raw = _json_bytes(config)
    manifest = {"schema_version": INSTALL_SCHEMA, "active": True, "installation_id": installation_id, "project_root": str(project), "allowed_directory": str(allowed), "python_path": str(python), "runtime_digest": source_digest, "wrapper_digest": _digest(wrapper), "policy_file_digest": _digest(policy_raw), "policy_digest": _policy_digest(policy), "hook_entry": entry, "original_config_exists": original_exists, "original_config_digest": original_digest, "original_config_mode": original_mode, "restore_original": restore, "installed_config_digest": _digest(config_raw), "codex_dir_created": previous["codex_dir_created"] if active else not config_path.parent.exists()}
    _no_links(state)
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.mkdir(exist_ok=True, mode=0o700)
    _no_links(directory)
    config_path.parent.mkdir(exist_ok=True, mode=0o700)
    _no_links(config_path.parent)
    for path in (state, directory, config_path.parent):
        _trusted_directory(path)
    changes = []
    for name, raw, mode in (("runtime.py", source.data, 0o600), ("hook.sh", wrapper, 0o700), ("policy.json", policy_raw, 0o600)):
        changes.append((directory / name, raw, _read(directory / name, optional=True), mode))
    if not active:
        changes.append((directory / "hooks.before", before.data if before else None, _read(directory / "hooks.before", optional=True), 0o600))
    changes.append((config_path, config_raw, before, before.mode if before else 0o600))
    changes.append((directory / "installation.json", _json_bytes(manifest), previous_snapshot, 0o600))
    try:
        _transaction(changes)
    except (OSError, GuardError):
        if previous is None:
            try:
                directory.rmdir()
            except OSError:
                pass
        raise
    result, _, _ = _inspect(project, state, manifest)
    return dict(result, requires_trust=True, changed=True, next_step="Review this hook in Codex /hooks before relying on it. Upgrades require renewed trust.")


def _status(project: Path, state: Path) -> dict:
    directory = _installation_dir(project, state)
    if not directory.exists():
        return {"project_root": str(project), "state_directory": str(directory), "configured": False, "last_observed": None, "drift": []}
    manifest, _ = _manifest(directory, project)
    result, _, _ = _inspect(project, state, manifest)
    return result


def _uninstall(project: Path, state: Path) -> dict:
    directory = _installation_dir(project, state)
    if not directory.exists():
        return _status(project, state)
    manifest, manifest_before = _manifest(directory, project)
    status, config, before = _inspect(project, state, manifest)
    if config is None or "hook_entry_changed_or_missing" in status["drift"]:
        raise GuardError("cannot identify one intact owned hook entry; refusing to overwrite")
    if not manifest["active"]:
        return dict(status, retained_state_directory=str(directory))
    config_path = project / ".codex/hooks.json"
    backup = original = None
    backup_valid = not manifest["original_config_exists"]
    if manifest["original_config_exists"]:
        try:
            backup = _read(directory / "hooks.before")
            backup_valid = _digest(backup.data) == manifest["original_config_digest"]
            if backup_valid:
                original = _parse_json(backup.data)
        except (OSError, GuardError):
            backup_valid = False
    if backup_valid and manifest["restore_original"] and before and _digest(before.data) == manifest["installed_config_digest"]:
        raw = backup.data if manifest["original_config_exists"] else None
        mode = manifest["original_config_mode"]
    else:
        entries = config["hooks"]["PreToolUse"]
        config["hooks"]["PreToolUse"] = [item for item in entries if item != manifest["hook_entry"]]
        if backup_valid:
            original = original or {}
            if not config["hooks"]["PreToolUse"] and "PreToolUse" not in original.get("hooks", {}):
                del config["hooks"]["PreToolUse"]
            if not config["hooks"] and "hooks" not in original:
                del config["hooks"]
        raw, mode = _json_bytes(config), before.mode
    manifest["active"] = False
    _transaction([(config_path, raw, before, mode), (directory / "installation.json", _json_bytes(manifest), manifest_before, 0o600)])
    if raw is None and manifest["codex_dir_created"]:
        try:
            config_path.parent.rmdir()
        except OSError:
            pass
    result, _, _ = _inspect(project, state, manifest)
    return dict(result, retained_state_directory=str(directory), note="Project hook removed. Local installation records and events are retained; no host trust settings were changed.")


def _print_human(result: dict, command: str) -> None:
    print("项目接入：" + ("已配置" if result["configured"] else "未配置"))
    print("配置与代码漂移：" + ("、".join(result["drift"]) if result["drift"] else "未发现"))
    print("允许访问目录：" + result.get("allowed_directory", "尚未配置"))
    observed = result["last_observed"]
    if observed:
        print("最近一次检查：" + observed["checked_at"] + "，" + ("允许" if observed["decision"] == "allow" else "拒绝") + "，原因码 " + observed["code"])
    else:
        print("最近一次检查：尚未观察到本次安装的有效记录")
    print("宿主当前是否信任/启用：尚未核实，配置存在不代表生效")
    if command == "install":
        print("下一步运行 owp-guard enable，审阅当前版本并完成真实检查；升级后须重新启用。")
    if result.get("retained_state_directory"):
        print("已移除项目接入；本地记录保留：" + result["retained_state_directory"])


def _print_activation(result: dict, command: str) -> None:
    if result.get("cancelled"):
        print("已取消启用，现有授权未更改。")
        return
    if command == "run":
        print(result["assistant_text"] or "本次未取得 Agent 回应。")
        if result.get("protection_observation") == "window_activity_observed":
            print("运行期间观察到 OWP 检查活动；这不是逐项操作的独立证明。")
        elif result.get("protection_observation") == "no_tool_actions":
            print("本次未观察到工具操作。")
        if result["status"] != "completed":
            print("本次运行未能完整核实，请检查宿主状态。")
        return
    print("本项目检查：" + ("已安装完整" if result["configured"] else "尚未确认完整安装"))
    reviews = {"current": "已授权当前版本", "missing": "尚未授权", "outdated": "版本已变化，请重新启用", "unknown": "未核实"}
    probes = {"passed": "通过", "failed": "未通过", "not_run": "尚未运行", "outdated": "已失效", "unknown": "未核实"}
    print("当前版本授权：" + reviews.get(result["review_status"], "未核实"))
    print("宿主对受保护启动的信任核验：" + ("通过" if result["review_status"] == "current" and result["host_trust_status"] == "trusted" else "未通过"))
    print("最近真实检查：" + probes.get(result["probe_status"], "未核实"))
    print("允许访问目录：" + result.get("allowed_directory", "未核实"))
    if result["ready_for_guarded_run"]:
        print("可以通过 owp-guard run 在 Codex 中执行预览任务。")
    else:
        print("当前尚未满足受保护启动条件，请运行 enable 或处理状态提示。")
    print("上述结果适用于 OWP 受保护启动；普通 Codex 启动尚未验证。")
    if result.get("reason"):
        print(result["reason"])


def _onboarding_action(args, project: Path, state: Path) -> dict:
    from openworkproof import guard_onboarding

    if args.command == "doctor":
        return guard_onboarding.doctor(project, state, executable=args.codex)
    if args.command == "run":
        return guard_onboarding.run_guarded_task(project, state, args.prompt, executable=args.codex)
    summary = guard_onboarding.review_summary(project, state, executable=args.codex)
    stream = sys.stdout if args.human else sys.stderr
    print("授权范围：仅本项目当前这条 OWP 检查，供受保护启动使用。", file=stream)
    print("允许访问目录：" + summary["allowed_directory"], file=stream)
    print("允许预览文件读取、增加和修改；越界、删除移动、任意命令及未知工具会拒绝。", file=stream)
    print("Codex：" + summary["codex_version"] + "，程序：" + summary["codex_path"], file=stream)
    print("当前检查版本：" + summary["hook_hash"], file=stream)
    print("受保护模式使用 Codex 默认模型和原有登录；本次不载入个人 MCP/插件配置，在线搜索关闭。", file=stream)
    print("确认后将用 Codex 对新建合成文件执行真实的放行与阻断检查。", file=stream, flush=True)
    consent = "explicit_own_hook"
    if not args.trust_own_hook:
        if not sys.stdin.isatty():
            raise GuardError("请在交互终端审阅确认，或明确使用 --trust-own-hook 仅授权当前 OWP 检查。")
        try:
            answer = input("确认启用并检查？输入“确认”继续，回车取消：").strip()
        except EOFError:
            answer = ""
        if answer not in ("确认", "y", "yes"):
            return {"cancelled": True}
        consent = "interactive_own_hook"
    return guard_onboarding.enable(
        project, state, executable=args.codex, trust_own_hook=True,
        reviewed_identity=summary["identity"], consent_method=consent,
    )


def _onboarding_command(args, project: Path, state: Path) -> dict:
    # With ``python -m``, this transport is __main__ while the service imports
    # its canonical module. Normalize its exception into this transport's type.
    from openworkproof.guard_cli import GuardError as ServiceGuardError

    try:
        return _onboarding_action(args, project, state)
    except ServiceGuardError as error:
        raise GuardError(str(error)) from None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Project-local OWP Guard for Codex (POSIX).")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("install", "status", "uninstall", "enable", "doctor", "run"):
        sub = commands.add_parser(command)
        sub.add_argument("--project", required=True)
        sub.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR))
        sub.add_argument("--human", action="store_true", help="显示简洁中文状态；默认输出JSON。")
        if command == "install":
            sub.add_argument("--allow-dir", required=True)
            sub.add_argument("--upgrade", action="store_true")
        if command in ("enable", "doctor", "run"):
            sub.add_argument("--codex", default="codex", help="Codex 可执行程序，默认使用 PATH 中的 codex。")
        if command == "enable":
            sub.add_argument("--trust-own-hook", action="store_true", help="明确授权当前项目这条 OWP 检查并进行真实检查。")
        if command == "run":
            sub.add_argument("--prompt", required=True, help="交给 Codex 的预览任务。")
    args = parser.parse_args(argv)
    try:
        project = _path(args.project, directory=True)
        state = _path(args.state_dir)
        onboarding = args.command in ("enable", "doctor", "run")
        if onboarding:
            result = _onboarding_command(args, project, state)
        else:
            with _project_lock(project):
                if args.command == "install":
                    allowed = _path(args.allow_dir, project, directory=True)
                    result = _install(project, allowed, state, upgrade=args.upgrade)
                elif args.command == "status":
                    result = _status(project, state)
                else:
                    result = _uninstall(project, state)
        if args.human:
            if onboarding:
                _print_activation(result, args.command)
            else:
                _print_human(result, args.command)
        else:
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        if onboarding and not result.get("cancelled"):
            return 0 if result.get("ready_for_guarded_run", result.get("status") == "completed") else 2
        return 0
    except KeyboardInterrupt:
        print("已停止本次检查或任务。", file=sys.stderr)
        return 130
    except (GuardError, OSError, ValueError) as exc:
        print("owp-guard: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
