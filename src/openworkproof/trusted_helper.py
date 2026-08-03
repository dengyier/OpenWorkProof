"""Fixed trusted-helper request dispatcher."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import BinaryIO, Sequence

import rfc8785

from openworkproof import repo_tools
from openworkproof.models import RepoReadOutput


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
_INTERNAL_ERROR_BYTES = (
    b'{"code":"INTERNAL_ERROR","schema_version":'
    b'"openworkproof-trusted-helper-response/0.1","status":"error"}'
)

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
_RESULT_KEYS = frozenset(
    {
        "path",
        "content_sha256",
        "size_bytes",
        "workspace_manifest_digest",
    }
)


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


def _reject_json_number(unused: str) -> None:
    raise _RequestInvalid


def _parse_request(raw: bytes, runtime_root: Path) -> repo_tools.CandidateReadRequest:
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_REQUEST_BYTES:
        raise _RequestInvalid
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_float=_reject_json_number,
            parse_int=_reject_json_number,
            parse_constant=_reject_json_number,
        )
        canonical = rfc8785.dumps(value)
        if type(canonical) is not bytes:
            raise TypeError("canonicalizer did not return bytes")
        if canonical != raw:
            raise _RequestInvalid
    except (
        _RequestInvalid,
        json.JSONDecodeError,
        UnicodeDecodeError,
        RecursionError,
        rfc8785.CanonicalizationError,
    ):
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


def _exit_for_code(code: str) -> int:
    if code == "REQUEST_INVALID":
        return 64
    if code == "RECOVERY_REQUIRED":
        return 65
    if code == "PATH_DENIED":
        return 66
    if code == "FILE_CHANGED":
        return 67
    return 70


def _validated_success_response(
    result: object,
    request: repo_tools.CandidateReadRequest,
) -> dict[str, object]:
    if type(result) is not repo_tools.CandidateReadResult:
        raise TypeError("candidate read result is not closed")
    if type(result.content) is not bytes:
        raise TypeError("candidate read content is not closed")
    if type(result.output) is not RepoReadOutput:
        raise TypeError("candidate read output is not closed")
    content_sha256 = hashlib.sha256(result.content).hexdigest()
    if (
        result.output.path != request.path
        or result.output.workspace_manifest_digest
        != request.expected_workspace_manifest_digest
        or result.output.size_bytes != len(result.content)
        or result.output.content_sha256 != content_sha256
    ):
        raise ValueError("candidate read result binding mismatch")
    dumped = result.output.model_dump(mode="json")
    if type(dumped) is not dict or frozenset(dumped) != _RESULT_KEYS:
        raise TypeError("candidate read output dump is not closed")
    if (
        type(dumped["path"]) is not str
        or dumped["path"] != request.path
        or type(dumped["content_sha256"]) is not str
        or dumped["content_sha256"] != content_sha256
        or type(dumped["size_bytes"]) is not int
        or dumped["size_bytes"] != len(result.content)
        or type(dumped["workspace_manifest_digest"]) is not str
        or dumped["workspace_manifest_digest"]
        != request.expected_workspace_manifest_digest
    ):
        raise ValueError("candidate read output dump binding mismatch")
    return {
        "schema_version": RESPONSE_SCHEMA,
        "status": "ok",
        "result": dumped,
        "content_b64url": base64.urlsafe_b64encode(result.content)
        .decode("ascii")
        .rstrip("="),
    }


def _write_response(
    stdout: BinaryIO,
    response: dict[str, object],
    exit_code: int,
) -> int:
    try:
        encoded = rfc8785.dumps(response)
        if type(encoded) is not bytes:
            raise TypeError("response canonicalizer did not return bytes")
    except BaseException:
        encoded = _INTERNAL_ERROR_BYTES
        exit_code = 70
    try:
        if stdout.write(encoded) != len(encoded):
            return 70
    except BaseException:
        return 70
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
        if invalid_argv:
            return _write_response(
                stdout,
                _error_response("REQUEST_INVALID"),
                64,
            )
        raw = stdin.read(MAX_REQUEST_BYTES + 1)
        request = _parse_request(raw, runtime_root)
        result = repo_tools.read_candidate_file(request)
        response = _validated_success_response(result, request)
        return _write_response(stdout, response, 0)
    except _RequestInvalid:
        code = "REQUEST_INVALID"
    except repo_tools.CandidateReadError as error:
        code = _closed_candidate_error_code(error)
    except BaseException:
        code = "INTERNAL_ERROR"
    return _write_response(stdout, _error_response(code), _exit_for_code(code))


if __name__ == "__main__":
    raise SystemExit(
        main(sys.argv[1:], sys.stdin.buffer, sys.stdout.buffer, RUNTIME_ROOT)
    )
