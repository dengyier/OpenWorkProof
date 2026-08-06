"""Extensible analysis layer.

Analyzers implement ``RepositoryAnalyzer`` and receive the immutable
``RepositoryScan``; each returns one ``AnalysisResult``. The pipeline runs
analyzers in order and never lets one analyzer's failure abort the others
unless ``fail_fast`` is set.
"""

from __future__ import annotations

from typing import Protocol

from .errors import AnalysisError, get_logger
from .models import AnalysisResult, RepositoryScan

_logger = get_logger()


class RepositoryAnalyzer(Protocol):
    name: str

    def analyze(self, scan: RepositoryScan) -> AnalysisResult: ...


class LanguageStatsAnalyzer:
    """Summarise files and bytes per programming language."""

    name = "language_stats"

    def analyze(self, scan: RepositoryScan) -> AnalysisResult:
        per_language: dict[str, dict[str, int]] = {}
        for entry in scan.entries:
            if entry.language is None:
                continue
            bucket = per_language.setdefault(
                entry.language, {"files": 0, "bytes": 0}
            )
            bucket["files"] += 1
            bucket["bytes"] += entry.size_bytes
        return AnalysisResult(
            analyzer=self.name,
            data={
                "languages": {
                    language: {"files": counts["files"], "bytes": counts["bytes"]}
                    for language, counts in sorted(per_language.items())
                }
            },
        )


class LineCountAnalyzer:
    """Count total source lines and per-language lines."""

    name = "line_counts"

    def analyze(self, scan: RepositoryScan) -> AnalysisResult:
        total_lines = 0
        per_language: dict[str, int] = {}
        for entry in scan.entries:
            lines = entry.content.count("\n")
            total_lines += lines
            if entry.language is not None:
                per_language[entry.language] = (
                    per_language.get(entry.language, 0) + lines
                )
        return AnalysisResult(
            analyzer=self.name,
            data={
                "total_lines": total_lines,
                "lines_by_language": dict(
                    sorted(per_language.items(), key=lambda item: item[0])
                ),
            },
        )


class DependencySnifferAnalyzer:
    """Lightweight dependency-import sniffing for common ecosystems.

    This is intentionally shallow and heuristic: it detects import/require
    statements and package manifests without resolving the dependency graph.
    """

    name = "dependency_sniff"

    def analyze(self, scan: RepositoryScan) -> AnalysisResult:
        imports: dict[str, list[str]] = {}
        for entry in scan.entries:
            if entry.language == "Python":
                kind = "python"
            elif entry.language == "JavaScript":
                kind = "javascript"
            else:
                continue
            names = _sniff_imports(entry.content, kind)
            if names:
                imports.setdefault(kind, []).extend(names)
        return AnalysisResult(
            analyzer=self.name,
            data={
                "imports_by_kind": {
                    kind: sorted(set(names))
                    for kind, names in sorted(imports.items())
                }
            },
        )


def _sniff_imports(content: str, kind: str) -> list[str]:
    names: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "/*", "*")):
            continue
        if kind == "python":
            if stripped.startswith(("import ", "from ")):
                token = stripped.split()[1]
                names.append(token.split(".")[0])
        elif kind == "javascript":
            if stripped.startswith(("import ", "from ", "require(")):
                token = stripped.split()[1].strip("'\"")
                names.append(token.split("/")[0])
    return names


def analyze_scan(
    scan: RepositoryScan,
    analyzers: tuple[RepositoryAnalyzer, ...],
    *,
    fail_fast: bool = False,
) -> tuple[AnalysisResult, ...]:
    """Run every analyzer over the scan, isolating per-analyzer failures."""
    results: list[AnalysisResult] = []
    for analyzer in analyzers:
        try:
            results.append(analyzer.analyze(scan))
        except AnalysisError:
            raise
        except Exception as error:  # noqa: BLE001
            _logger.error("analyzer %s failed: %s", analyzer.name, error)
            if fail_fast:
                raise AnalysisError(
                    f"analyzer {analyzer.name} failed"
                ) from error
    return tuple(results)


DEFAULT_ANALYZERS: tuple[RepositoryAnalyzer, ...] = (
    LanguageStatsAnalyzer(),
    LineCountAnalyzer(),
    DependencySnifferAnalyzer(),
)
