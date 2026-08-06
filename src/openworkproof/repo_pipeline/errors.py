"""Typed errors and graded logging for the repository pipeline.

Every failure path raises a ``RepoPipelineError`` subclass so callers can
handle categories (missing path, permission, unsupported source, parse
failure, output failure) without inspecting message strings. Logging uses the
``openworkproof.repo_pipeline`` namespace with severity levels suitable for
operator triage.
"""

from __future__ import annotations

import logging


class RepoPipelineError(Exception):
    """Base class for all repository pipeline failures."""


class SourceError(RepoPipelineError):
    """The input source could not be resolved or reached."""


class PathNotFoundError(SourceError):
    """A local repository path does not exist or is not a directory."""


class PermissionDeniedError(SourceError):
    """The pipeline cannot read the repository path or a file inside it."""


class UnsupportedSourceError(SourceError):
    """The input is neither a local path nor a supported remote URL."""


class RemoteCloneError(SourceError):
    """A remote repository could not be cloned or fetched."""


class TraversalError(RepoPipelineError):
    """The traversal stage failed while walking the repository."""


class ReadError(RepoPipelineError):
    """A file could not be read or decoded."""


class DecodeError(ReadError):
    """A file could not be decoded as UTF-8 text."""


class AnalysisError(RepoPipelineError):
    """An analyzer failed while processing a scan."""


class OutputError(RepoPipelineError):
    """The structured output could not be rendered."""


_logger = logging.getLogger("openworkproof.repo_pipeline")


def get_logger() -> logging.Logger:
    """Return the shared graded logger for the pipeline stages."""
    return _logger
