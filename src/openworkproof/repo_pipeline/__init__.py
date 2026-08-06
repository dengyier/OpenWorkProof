"""Repository read-and-analysis pipeline.

Public entry point::

    from openworkproof.repo_pipeline import analyze_repository

    analysis = analyze_repository("/path/to/repo")   # local path
    analysis = analyze_repository(
        "https://github.com/owner/repo", clone_enabled=True
    )

Pipeline stages, each decoupled and independently testable:

1. ``sources``   — resolve a local path or remote URL to a repository root
2. ``traversal`` — recursively walk, filter directories, recognise languages
3. ``reader``    — read and decode each supported file with guards
4. ``analysis``  — run the injected analyzers over the immutable scan
5. ``output``    — render the full result to canonical JSON

Errors are typed (see ``errors``) and logging is graded through
``openworkproof.repo_pipeline``.
"""

from __future__ import annotations

from pathlib import Path

from .analysis import (
    DEFAULT_ANALYZERS,
    RepositoryAnalyzer,
    analyze_scan,
)
from .errors import get_logger
from .models import RepositoryAnalysis
from .output import render_json, to_dict
from .sources import resolve_repository_source
from .traversal import scan_repository

_logger = get_logger()

__all__ = [
    "RepositoryAnalysis",
    "RepositoryAnalyzer",
    "analyze_repository",
    "render_json",
    "resolve_repository_source",
    "scan_repository",
    "to_dict",
]


def analyze_repository(
    source: str | Path,
    *,
    analyzers: tuple[RepositoryAnalyzer, ...] = DEFAULT_ANALYZERS,
    clone_enabled: bool = True,
    fail_fast: bool = False,
) -> RepositoryAnalysis:
    """Run the full pipeline over a local path or remote repository URL.

    Remote sources are cloned into a temporary directory that the caller
    must remove after consuming the result.
    """
    root = resolve_repository_source(source, clone_enabled=clone_enabled)
    _logger.info("scanning repository root: %s", root)
    scan = scan_repository(root)
    results = analyze_scan(scan, analyzers, fail_fast=fail_fast)
    _logger.info(
        "scan complete: %d files, %d bytes, %d skipped dirs",
        scan.total_files,
        scan.total_bytes,
        len(scan.skipped),
    )
    return RepositoryAnalysis(scan=scan, results=results)
