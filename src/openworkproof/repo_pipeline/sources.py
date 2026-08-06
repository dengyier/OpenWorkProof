"""Input resolution: turn a local path or a remote repository URL into a
concrete readable repository root.

``resolve_repository_source`` accepts:

- a local absolute or relative path to an existing directory;
- a GitHub URL such as ``https://github.com/owner/repo`` or
  ``https://github.com/owner/repo/tree/<ref>``.

Remote sources are cloned into a caller-managed temporary root when
``clone_enabled`` is true and the ``git`` executable is available; otherwise a
``RemoteCloneError`` is raised so callers can degrade gracefully.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlparse

from .errors import (
    PathNotFoundError,
    PermissionDeniedError,
    RemoteCloneError,
    UnsupportedSourceError,
    get_logger,
)

_GITHUB_URL = re.compile(
    r"^https?://(?:www\.)?github\.com/(?P<owner>[A-Za-z0-9_.-]+)/"
    r"(?P<repo>[A-Za-z0-9_.-]+)(?:/tree/(?P<ref>.+))?$"
)
_KNOWN_REMOTE_HOSTS = frozenset({"github.com"})
_logger = get_logger()


def _looks_like_remote_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and parsed.netloc != ""


def _classify(value: str) -> str:
    if _looks_like_remote_url(value):
        match = _GITHUB_URL.match(value)
        if match is not None:
            return "github"
        host = urlparse(value).netloc
        if host in _KNOWN_REMOTE_HOSTS:
            return "github"
        raise UnsupportedSourceError(f"unsupported remote host: {host}")
    return "local"


def resolve_local_path(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if not path.exists():
        raise PathNotFoundError(f"repository path does not exist: {path}")
    if not path.is_dir():
        raise UnsupportedSourceError(f"repository source is not a directory: {path}")
    if not os.access(path, os.R_OK):
        raise PermissionDeniedError(f"repository path is not readable: {path}")
    return path.resolve()


def _clone_github(owner: str, repo: str, ref: str | None) -> Path:
    git = shutil.which("git")
    if git is None:
        raise RemoteCloneError("git executable is unavailable")
    root = Path(tempfile.mkdtemp(prefix="owp-repo-"))
    url = f"https://github.com/{owner}/{repo}.git"
    try:
        subprocess.run(
            (git, "clone", "--depth", "1", url, str(root)),
            check=True,
            capture_output=True,
            timeout=300,
        )
        if ref is not None and ref != "HEAD":
            subprocess.run(
                (git, "-C", str(root), "checkout", ref),
                check=True,
                capture_output=True,
                timeout=120,
            )
    except (subprocess.CalledProcessError, OSError) as error:
        shutil.rmtree(root, ignore_errors=True)
        raise RemoteCloneError(f"remote clone failed for {owner}/{repo}") from error
    return root


def resolve_repository_source(
    source: str | Path,
    *,
    clone_enabled: bool = True,
) -> Path:
    """Resolve a local path or remote URL to a readable repository root.

    Returns the local repository root. Remote sources are cloned into a
    temporary directory that the caller must clean up.
    """
    if isinstance(source, Path):
        return resolve_local_path(source)
    if not isinstance(source, str) or not source:
        raise UnsupportedSourceError("repository source must be a path or URL")
    kind = _classify(source)
    if kind == "local":
        _logger.debug("resolved local repository source: %s", source)
        return resolve_local_path(source)
    match = _GITHUB_URL.match(source)
    if match is None:
        raise UnsupportedSourceError(f"unsupported repository URL: {source}")
    if not clone_enabled:
        raise RemoteCloneError("remote clone is disabled for this pipeline")
    owner, repo, ref = match.group("owner"), match.group("repo"), match.group("ref")
    _logger.info("cloning remote repository %s/%s", owner, repo)
    return _clone_github(owner, repo, ref)
