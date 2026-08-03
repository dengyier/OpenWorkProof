"""Fixed trusted-helper request dispatcher."""

from __future__ import annotations

import base64
import json
from pathlib import Path
import re
import sys
from typing import BinaryIO, Sequence

import rfc8785

from openworkproof import repo_tools


REQUEST_SCHEMA = "openworkproof-trusted-helper-request/0.1"
RESPONSE_SCHEMA = "openworkproof-trusted-helper-response/0.1"
MAX_REQUEST_BYTES = 8_192
RUNTIME_ROOT = Path("/runtime")
EXIT_BY_CODE = {
    "REQUEST_INVALID": 64,
    "RECOVERY_REQUIRED": 65,
    "PATH_DENIED": 66,
    "FILE_CHANGED": 67,
    "INTERNAL_ERROR": 70,
}

_REQUEST_KEYS = frozenset(
    {
        "schema_version",
        "operation",
        "workspace_id",
        "source_artifact_sha256",
        "expected_head_commit",
        "expected_workspace_manifest_digest",
        "path",
    }
)
_CANDIDATE_ERROR_CODES = (
    "RECOVERY_REQUIRED",
    "PATH_DENIED",
    "FILE_CHANGED",
)
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class _RequestInvalid(ValueError):
    """The request is not the frozen canonical dispatcher representation."""


def _object_without_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise _RequestInvalid
        value[key] = item
    return value


def _parse_request(raw: bytes, runtime_root: Path) -> repo_tools.CandidateReadRequest:
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_REQUEST_BYTES:
        raise _RequestInvalid
    try:
        value = json.loads(raw, object_pairs_hook=_object_without_duplicate_keys)
        if rfc8785.dumps(value) != raw:
            raise _RequestInvalid
    except _RequestInvalid:
        raise
    except Exception:
        raise _RequestInvalid from None
    if type(value) is not dict or frozenset(value) != _REQUEST_KEYS:
        raise _RequestInvalid
    if any(type(value[key]) is not str for key in _REQUEST_KEYS):
        raise _RequestInvalid
    if (
        value["schema_version"] != REQUEST_SCHEMA
        or value["operation"] != "repo_read"
        or _DIGEST_PATTERN.fullmatch(value["workspace_id"]) is None
        or _DIGEST_PATTERN.fullmatch(value["source_artifact_sha256"]) is None
        or _COMMIT_PATTERN.fullmatch(value["expected_head_commit"]) is None
        or _DIGEST_PATTERN.fullmatch(
            value["expected_workspace_manifest_digest"]
        )
        is None
    ):
        raise _RequestInvalid
    try:
        repo_tools.validate_canonical_relative_path(value["path"])
    except repo_tools.PathError:
        raise _RequestInvalid from None
    return repo_tools.CandidateReadRequest(
        runtime_root=runtime_root,
        workspace_id=value["workspace_id"],
        source_artifact_sha256=value["source_artifact_sha256"],
        expected_head_commit=value["expected_head_commit"],
        expected_workspace_manifest_digest=(
            value["expected_workspace_manifest_digest"]
        ),
        path=value["path"],
    )


def _error_response(code: str) -> dict[str, str]:
    return {
        "schema_version": RESPONSE_SCHEMA,
        "status": "error",
        "code": code,
    }


def _closed_candidate_error_code(
    error: repo_tools.CandidateReadError,
) -> str:
    try:
        code = error.code
    except BaseException:
        return "INTERNAL_ERROR"
    if type(code) is str and code in _CANDIDATE_ERROR_CODES:
        return code
    return "INTERNAL_ERROR"


def _write_response(
    stdout: BinaryIO,
    response: dict[str, object],
    exit_code: int,
) -> int:
    try:
        encoded = rfc8785.dumps(response)
        if stdout.write(encoded) != len(encoded):
            return EXIT_BY_CODE["INTERNAL_ERROR"]
    except Exception:
        return EXIT_BY_CODE["INTERNAL_ERROR"]
    return exit_code


def main(
    argv: Sequence[str],
    stdin: BinaryIO,
    stdout: BinaryIO,
    runtime_root: Path,
) -> int:
    try:
        invalid_argv = (
            not isinstance(argv, Sequence)
            or isinstance(argv, (str, bytes, bytearray))
            or len(argv) != 0
        )
    except Exception:
        return _write_response(
            stdout,
            _error_response("INTERNAL_ERROR"),
            EXIT_BY_CODE["INTERNAL_ERROR"],
        )
    if invalid_argv:
        return _write_response(
            stdout,
            _error_response("REQUEST_INVALID"),
            EXIT_BY_CODE["REQUEST_INVALID"],
        )
    try:
        raw = stdin.read(MAX_REQUEST_BYTES + 1)
        request = _parse_request(raw, runtime_root)
        result = repo_tools.read_candidate_file(request)
        response: dict[str, object] = {
            "schema_version": RESPONSE_SCHEMA,
            "status": "ok",
            "result": result.output.model_dump(mode="json"),
            "content_b64url": base64.urlsafe_b64encode(result.content)
            .decode("ascii")
            .rstrip("="),
        }
        return _write_response(stdout, response, 0)
    except _RequestInvalid:
        code = "REQUEST_INVALID"
    except repo_tools.CandidateReadError as error:
        code = _closed_candidate_error_code(error)
    except Exception:
        code = "INTERNAL_ERROR"
    return _write_response(stdout, _error_response(code), EXIT_BY_CODE[code])


if __name__ == "__main__":
    raise SystemExit(
        main(sys.argv[1:], sys.stdin.buffer, sys.stdout.buffer, RUNTIME_ROOT)
    )
