"""File reading: decode a text file with size limits and permission guards.

The reader is intentionally a small dependency-free seam so traversal and
analysis stages can be tested with injected readers.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .errors import DecodeError, PermissionDeniedError, get_logger

MAX_TEXT_BYTES = 1_048_576  # 1 MiB: larger files are skipped by the reader
_logger = get_logger()


def _decode_utf8(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise DecodeError("file is not valid UTF-8 text") from error


def read_text_file(path: Path, *, max_bytes: int = MAX_TEXT_BYTES) -> str:
    """Read one file as UTF-8 text with a size cap and permission guard."""
    try:
        size = path.stat().st_size
    except OSError as error:
        raise PermissionDeniedError(f"cannot stat file: {path}") from error
    if size > max_bytes:
        _logger.warning("skipping oversized file (%.1f KiB): %s", size / 1024, path)
        raise DecodeError(f"file exceeds the {max_bytes}-byte text limit: {path}")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise PermissionDeniedError(f"cannot read file: {path}") from error
    return _decode_utf8(raw)


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())
