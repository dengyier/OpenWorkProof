"""Structured output: render a ``RepositoryAnalysis`` to canonical JSON.

The output is a single self-describing object so downstream tools can consume
it without extra context:

.. code-block:: json

    {
      "schema_version": "openworkproof/repo-analysis/0.1",
      "root": "/abs/path",
      "totals": {"files": 3, "bytes": 42},
      "files": [{"path": "a.py", "language": "Python", "size_bytes": 42,
                 "sha256": "...", "lines": 2}],
      "results": [{"analyzer": "language_stats", "data": {...}}]
    }
"""

from __future__ import annotations

import json

from .errors import OutputError, get_logger
from .models import RepositoryAnalysis

_logger = get_logger()

SCHEMA_VERSION = "openworkproof/repo-analysis/0.1"


def _file_record(entry) -> dict[str, object]:
    return {
        "path": entry.relative_path,
        "language": entry.language,
        "size_bytes": entry.size_bytes,
        "sha256": entry.sha256,
        "lines": entry.content.count("\n"),
    }


def to_dict(analysis: RepositoryAnalysis) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "root": analysis.scan.root,
        "totals": {
            "files": analysis.scan.total_files,
            "bytes": analysis.scan.total_bytes,
            "skipped_directories": len(analysis.scan.skipped),
        },
        "files": [
            _file_record(entry) for entry in analysis.scan.entries
        ],
        "results": [
            {"analyzer": result.analyzer, "data": dict(result.data)}
            for result in analysis.results
        ],
    }


def render_json(analysis: RepositoryAnalysis, *, indent: int | None = 2) -> str:
    try:
        return json.dumps(
            to_dict(analysis),
            ensure_ascii=False,
            sort_keys=True,
            indent=indent,
        )
    except (TypeError, ValueError) as error:
        raise OutputError("repository analysis cannot be serialized") from error
