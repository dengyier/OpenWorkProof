"""Bounded stdio inventory and exact, invocation-scoped native Codex trust.

This module does not persist trust, approve hooks, or start an AI task. The
caller reviews native inventory and owns any durable review record.
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
import re
import select
import selectors
import signal
import subprocess
import time


_FEATURES = (
    "features={hooks=true,plugins=false,apps=false,"
    "multi_agent=false,code_mode_host=true}"
)
_HASH = re.compile(r"sha256:[0-9a-f]{64}")
_VERSION = re.compile(r"codex-cli\s+(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)")
_MAX_LINE_BYTES = 1_048_576
_TIMEOUT_SECONDS = 10.0


class CodexHostError(RuntimeError):
    """A fixed, user-readable error without raw host or configuration output."""


def _project_path(project: Path) -> Path:
    try:
        path = Path(project)
        if not path.is_absolute() or not path.is_dir():
            raise ValueError
        return path.resolve(strict=True)
    except (OSError, TypeError, ValueError):
        raise CodexHostError("请选择存在的项目目录。") from None


def _executable_name(executable: str) -> str:
    try:
        value = os.fspath(executable)
        if not isinstance(value, str) or not value or "\0" in value:
            raise ValueError
        return value
    except (TypeError, ValueError):
        raise CodexHostError("无法找到可用的 Codex 程序。") from None


def _trust_table(key: str, current_hash: str) -> str:
    if (
        not isinstance(key, str) or not key or "\0" in key or len(key) > 8192
        or not isinstance(current_hash, str)
        or _HASH.fullmatch(current_hash) is None
    ):
        raise CodexHostError("尚未取得有效的单项宿主信任记录。")
    return "hooks.state={" + json.dumps(key, ensure_ascii=False) + "={" + (
        "trusted_hash=" + json.dumps(current_hash) + ",enabled=true}}"
    )


def _session_args(
    executable: str, project: Path, reviewed_hook: dict | None = None,
) -> list[str]:
    project = _project_path(project)
    args = [
        _executable_name(executable), "-c", _FEATURES,
        "-c", 'web_search="disabled"',
        "-c", "projects={" + json.dumps(str(project), ensure_ascii=False)
        + '={trust_level="trusted"}}',
    ]
    if reviewed_hook is not None:
        if not isinstance(reviewed_hook, dict):
            raise CodexHostError("尚未取得有效的单项宿主信任记录。")
        args.extend(["-c", _trust_table(
            reviewed_hook.get("key"), reviewed_hook.get("currentHash"),
        )])
    return args


def build_exec_args(
    executable: str, project: Path, key: str, current_hash: str,
) -> list[str]:
    """Build a stdin-prompt invocation; do not execute or persist anything."""
    path = _project_path(project)
    args = _session_args(executable, path, {
        "key": key, "currentHash": current_hash,
    })
    return [args[0], "-a", "never", "-s", "workspace-write", *args[1:]] + [
        "exec", "--ignore-user-config", "--ephemeral", "--json",
        "-C", str(path), "-",
    ]


def _stop_process(process: subprocess.Popen) -> None:
    if process.stdin is not None:
        try:
            process.stdin.close()
        except OSError:
            pass
    try:
        process.wait(timeout=0.1)
    except subprocess.TimeoutExpired:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                if os.name == "posix":
                    os.killpg(process.pid, sig)
                elif sig == signal.SIGTERM:
                    process.terminate()
                else:
                    process.kill()
            except ProcessLookupError:
                pass
            except OSError:
                raise CodexHostError("宿主连接未能正常关闭。") from None
            try:
                process.wait(timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                continue
        else:
            raise CodexHostError("宿主连接未能正常关闭。")
    finally:
        if process.stdout is not None:
            process.stdout.close()


def _spawn(args: list[str], project: Path | None = None) -> subprocess.Popen:
    try:
        return subprocess.Popen(
            args, cwd=project, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0, close_fds=True,
            start_new_session=(os.name == "posix"),
        )
    except (OSError, ValueError):
        raise CodexHostError("无法启动 Codex 宿主连接。") from None


def _read_line(
    process: subprocess.Popen, selector: selectors.BaseSelector,
    buffer: bytearray, deadline: float, max_bytes: int,
) -> bytes:
    while True:
        newline = buffer.find(b"\n")
        if newline >= 0:
            if newline > max_bytes:
                raise CodexHostError("宿主返回的数据超过安全读取上限。")
            line = bytes(buffer[:newline])
            del buffer[:newline + 1]
            return line
        if len(buffer) > max_bytes:
            raise CodexHostError("宿主返回的数据超过安全读取上限。")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CodexHostError("等待 Codex 宿主响应超时。")
        try:
            ready = selector.select(remaining)
            if not ready:
                raise CodexHostError("等待 Codex 宿主响应超时。")
            chunk = os.read(
                process.stdout.fileno(), min(65536, max_bytes + 1 - len(buffer)),
            )
        except OSError:
            raise CodexHostError("无法读取 Codex 宿主响应。") from None
        if not chunk:
            raise CodexHostError("Codex 宿主提前关闭了连接。")
        buffer.extend(chunk)


def codex_version(executable: str = "codex") -> str:
    """Return the native semantic version, without echoing invalid output."""
    process = _spawn([_executable_name(executable), "--version"])
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + _TIMEOUT_SECONDS
        raw = _read_line(process, selector, bytearray(), deadline, 4096)
        try:
            match = _VERSION.fullmatch(raw.decode("utf-8").strip())
            if match is None:
                raise ValueError
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
            if process.returncode != 0:
                raise ValueError
        except (UnicodeError, ValueError, subprocess.TimeoutExpired):
            raise CodexHostError("无法确认 Codex 的版本。") from None
        return match.group(1)
    finally:
        selector.close()
        _stop_process(process)


class CodexHost:
    """A no-task native app-server connection; use it as a context manager."""

    def __init__(
        self, executable: str = "codex", *, project: Path,
        reviewed_hook: dict | None = None,
        timeout_seconds: float = _TIMEOUT_SECONDS,
        max_message_bytes: int = _MAX_LINE_BYTES,
    ) -> None:
        self.project = _project_path(project)
        self._args = _session_args(executable, self.project, reviewed_hook)
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (float, int))
            or not math.isfinite(timeout_seconds) or timeout_seconds <= 0
            or type(max_message_bytes) is not int or max_message_bytes < 1
        ):
            raise CodexHostError("宿主连接的读取限制无效。")
        self._timeout = float(timeout_seconds)
        self._max_bytes = max_message_bytes
        self._process = None
        self._selector = None
        self._buffer = bytearray()
        self._next_id = 1

    def __enter__(self) -> CodexHost:
        if self._process is not None:
            raise CodexHostError("宿主连接已经打开。")
        try:
            self._process = _spawn(
                self._args + ["app-server", "--listen", "stdio://"], self.project,
            )
            self._selector = selectors.DefaultSelector()
            self._buffer.clear()
            self._next_id = 1
            self._selector.register(self._process.stdout, selectors.EVENT_READ)
            os.set_blocking(self._process.stdin.fileno(), False)
            self._request("initialize", {
                "clientInfo": {"name": "owp-guard", "title": "OWP Guard", "version": "0.1"},
                "capabilities": {"experimentalApi": True, "requestAttestation": False},
            })
            self._send({"method": "initialized"}, time.monotonic() + self._timeout)
        except BaseException:
            try:
                self.close()
            except CodexHostError:
                pass
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        try:
            self.close()
        except CodexHostError:
            if exc_type is None:
                raise

    def close(self) -> None:
        process, self._process = self._process, None
        selector, self._selector = self._selector, None
        if selector is not None:
            selector.close()
        if process is not None:
            _stop_process(process)

    def _send(self, message: dict, deadline: float) -> None:
        if self._process is None:
            raise CodexHostError("宿主连接尚未打开。")
        try:
            data = json.dumps(message, ensure_ascii=False).encode("utf-8") + b"\n"
            offset = 0
            while offset < len(data):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CodexHostError("等待 Codex 宿主响应超时。")
                _, ready, _ = select.select([], [self._process.stdin], [], remaining)
                if not ready:
                    raise CodexHostError("等待 Codex 宿主响应超时。")
                try:
                    offset += os.write(self._process.stdin.fileno(), data[offset:])
                except BlockingIOError:
                    continue
        except (OSError, UnicodeError, ValueError):
            raise CodexHostError("无法向 Codex 宿主发送请求。") from None

    def _request(self, method: str, params: dict) -> dict:
        request_id = self._next_id
        self._next_id += 1
        deadline = time.monotonic() + self._timeout
        self._send({"id": request_id, "method": method, "params": params}, deadline)
        while True:
            raw = _read_line(
                self._process, self._selector, self._buffer, deadline, self._max_bytes,
            )
            try:
                message = json.loads(raw)
            except (UnicodeError, ValueError, RecursionError):
                raise CodexHostError("宿主返回了无法识别的数据。") from None
            if not isinstance(message, dict):
                raise CodexHostError("宿主返回了无法识别的数据。")
            if "method" in message:
                if "id" not in message and isinstance(message["method"], str):
                    continue
                raise CodexHostError("宿主请求了当前不支持的交互。")
            if type(message.get("id")) is not int or message["id"] != request_id:
                raise CodexHostError("宿主响应与当前请求不匹配。")
            if message.get("error") is not None:
                raise CodexHostError("Codex 宿主未能完成此次检查。")
            result = message.get("result")
            if not isinstance(result, dict):
                raise CodexHostError("宿主返回了无法识别的数据。")
            return result

    def list_hooks(self) -> dict:
        result = self._request("hooks/list", {"cwds": [str(self.project)]})
        data = result.get("data")
        if not isinstance(data, list):
            raise CodexHostError("宿主未返回有效的保护组件清单。")
        entries = [
            entry for entry in data
            if isinstance(entry, dict) and entry.get("cwd") == str(self.project)
        ]
        if len(entries) != 1:
            raise CodexHostError("宿主未返回当前项目的唯一保护组件清单。")
        entry = entries[0]
        if (
            not isinstance(entry.get("hooks"), list)
            or not all(isinstance(hook, dict) for hook in entry["hooks"])
            or not isinstance(entry.get("warnings"), list)
            or not all(isinstance(warning, str) for warning in entry["warnings"])
            or not isinstance(entry.get("errors"), list)
        ):
            raise CodexHostError("宿主未返回有效的保护组件清单。")
        if entry["errors"]:
            raise CodexHostError("宿主配置检查未通过，尚不能确认保护已生效。")
        return entry
