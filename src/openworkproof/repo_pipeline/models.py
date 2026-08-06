"""Unified data models for the repository read-and-analysis pipeline.

Every stage of the pipeline exchanges immutable dataclasses from this module,
so stages stay decoupled: traversal produces ``RepositoryScan``, analyzers
consume it and emit ``AnalysisResult``, and the output layer renders results
to JSON.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import stat
from typing import Mapping


@dataclass(frozen=True, slots=True)
class RepoFileEntry:
    """One file discovered by the traversal stage."""

    relative_path: str
    language: str | None
    size_bytes: int
    content: str
    sha256: str

    @property
    def is_text(self) -> bool:
        return self.language is not None


@dataclass(frozen=True, slots=True)
class SkippedDirectory:
    """One directory skipped by a traversal filter rule."""

    relative_path: str
    rule: str


@dataclass(frozen=True, slots=True)
class RepositoryScan:
    """The complete immutable result of one repository traversal."""

    root: str
    entries: tuple[RepoFileEntry, ...] = ()
    skipped: tuple[SkippedDirectory, ...] = ()
    total_files: int = 0
    total_bytes: int = 0
    languages: Mapping[str, int] = field(default_factory=dict)

    def language_counts(self) -> Mapping[str, int]:
        counts: dict[str, int] = {}
        for entry in self.entries:
            if entry.language is not None:
                counts[entry.language] = counts.get(entry.language, 0) + 1
        return counts


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """One analyzer's structured output for a scan."""

    analyzer: str
    data: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RepositoryAnalysis:
    """The full pipeline output: scan plus every analyzer result."""

    scan: RepositoryScan
    results: tuple[AnalysisResult, ...] = ()


def entry_mode_is_regular(mode: int) -> bool:
    return stat.S_ISREG(mode)


def is_supported_source_path(path: object) -> bool:
    return isinstance(path, (str, Path)) and bool(path)
