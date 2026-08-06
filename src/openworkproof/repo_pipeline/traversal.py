"""Repository traversal: recursively walk a repository, apply directory
filters, recognise code file types, and read each supported file.

The traversal stage is a pure walker over the local repository root. It
accepts an injected ``read_file`` callable so tests and callers can substitute
the reader without touching the walk logic.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable

from .errors import ReadError, get_logger
from .models import RepoFileEntry, RepositoryScan, SkippedDirectory
from .reader import read_text_file, sha256_bytes

_logger = get_logger()

MAX_FILES = 5_000
MAX_DIRECTORY_DEPTH = 32

# Directories never scanned: VCS, dependency installs, build output, caches.
FILTERED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "bower_components",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".idea",
        ".vscode",
        "dist",
        "build",
        "out",
        "target",
        ".next",
        ".nuxt",
        ".cache",
        "coverage",
        ".terraform",
        "Pods",
        "vendor",
    }
)

# Extension -> language. Unknown text files still load with language None.
LANGUAGE_BY_EXTENSION: dict[str, str] = {
    ".py": "Python",
    ".pyi": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".jsx": "JavaScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".kt": "Kotlin",
    ".swift": "Swift",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".hpp": "C++",
    ".cs": "C#",
    ".rb": "Ruby",
    ".php": "PHP",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".fish": "Shell",
    ".ps1": "PowerShell",
    ".sql": "SQL",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".less": "Less",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".toml": "TOML",
    ".xml": "XML",
    ".md": "Markdown",
    ".rst": "RST",
    ".tex": "LaTeX",
    ".proto": "Protocol Buffers",
    ".graphql": "GraphQL",
    ".vue": "Vue",
    ".svelte": "Svelte",
    ".dockerfile": "Dockerfile",
    ".tf": "Terraform",
    ".lua": "Lua",
    ".pl": "Perl",
    ".r": "R",
    ".m": "Objective-C",
    ".dart": "Dart",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".erl": "Erlang",
    ".hs": "Haskell",
    ".clj": "Clojure",
    ".scala": "Scala",
    ".groovy": "Groovy",
    ".fs": "F#",
}

# File names treated as code regardless of extension.
NAME_LANGUAGES: dict[str, str] = {
    "Dockerfile": "Dockerfile",
    "Makefile": "Makefile",
    "CMakeLists.txt": "CMake",
    "Justfile": "Justfile",
    "Jenkinsfile": "Jenkinsfile",
    "Rakefile": "Ruby",
    "Gemfile": "Ruby",
    "Cargo.toml": "TOML",
    "go.mod": "Go",
}


def language_for(path: Path) -> str | None:
    name = path.name
    if name in NAME_LANGUAGES:
        return NAME_LANGUAGES[name]
    return LANGUAGE_BY_EXTENSION.get(path.suffix.lower())


def _walk_relative(
    top: Path,
    current: Path,
    *,
    depth: int,
    filters: frozenset[str],
    max_files: int,
    max_depth: int,
) -> tuple[list[RepoFileEntry], list[SkippedDirectory]]:
    entries: list[RepoFileEntry] = []
    skipped: list[SkippedDirectory] = []
    if depth > max_depth:
        _logger.warning("traversal depth limit reached at %s", current)
        return entries, skipped
    try:
        children = sorted(current.iterdir(), key=lambda item: item.name)
    except OSError as error:
        _logger.error("cannot list directory %s: %s", current, error)
        return entries, skipped
    for child in children:
        if child.is_symlink():
            _logger.debug("skipping symlink: %s", child)
            continue
        if child.is_dir():
            if child.name in filters:
                skipped.append(
                    SkippedDirectory(
                        relative_path=child.relative_to(top).as_posix(),
                        rule="filtered-directory",
                    )
                )
                _logger.debug("filtering directory: %s", child.name)
                continue
            sub_entries, sub_skipped = _walk_relative(
                top,
                child,
                depth=depth + 1,
                filters=filters,
                max_files=max_files,
                max_depth=max_depth,
            )
            entries.extend(sub_entries)
            skipped.extend(sub_skipped)
            continue
        if not child.is_file():
            continue
        if len(entries) >= max_files:
            _logger.warning("file count limit reached (%d files)", max_files)
            break
        language = language_for(child)
        if language is None:
            _logger.debug("skipping unrecognised file type: %s", child.name)
            continue
        entries.append(
            RepoFileEntry(
                relative_path=child.relative_to(top).as_posix(),
                language=language,
                size_bytes=0,
                content="",
                sha256="",
            )
        )
    return entries, skipped


def scan_repository(
    root: Path,
    *,
    filters: frozenset[str] = FILTERED_DIRECTORIES,
    max_files: int = MAX_FILES,
    max_depth: int = MAX_DIRECTORY_DEPTH,
    read_file: Callable[[Path], str] = read_text_file,
) -> RepositoryScan:
    """Walk ``root`` and build a ``RepositoryScan`` of supported text files."""
    placeholder_entries, skipped = _walk_relative(
        root,
        root,
        depth=0,
        filters=filters,
        max_files=max_files,
        max_depth=max_depth,
    )
    entries: list[RepoFileEntry] = []
    total_bytes = 0
    for placeholder in placeholder_entries:
        path = root / placeholder.relative_path
        try:
            content = read_file(path)
        except ReadError as error:
            _logger.warning("skipping unreadable file %s: %s", path, error)
            continue
        raw = content.encode("utf-8")
        total_bytes += len(raw)
        entries.append(
            RepoFileEntry(
                relative_path=placeholder.relative_path,
                language=placeholder.language,
                size_bytes=len(raw),
                content=content,
                sha256=sha256_bytes(raw),
            )
        )
    entries.sort(key=lambda entry: entry.relative_path)
    languages: dict[str, int] = {}
    for entry in entries:
        if entry.language is not None:
            languages[entry.language] = languages.get(entry.language, 0) + 1
    return RepositoryScan(
        root=str(root),
        entries=tuple(entries),
        skipped=tuple(skipped),
        total_files=len(entries),
        total_bytes=total_bytes,
        languages=languages,
    )
