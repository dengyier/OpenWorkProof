"""Repository pipeline tests: inputs, traversal, models, analysis, output,
error handling, and module decoupling."""

from __future__ import annotations

import json
from pathlib import Path
import stat

import pytest

from openworkproof.repo_pipeline import (
    analyze_repository,
    render_json,
    resolve_repository_source,
    scan_repository,
    to_dict,
)
from openworkproof.repo_pipeline.analysis import (
    LineCountAnalyzer,
    RepositoryAnalyzer,
)
from openworkproof.repo_pipeline.errors import (
    DecodeError,
    PathNotFoundError,
    PermissionDeniedError,
    UnsupportedSourceError,
)
from openworkproof.repo_pipeline.models import AnalysisResult
from openworkproof.repo_pipeline.sources import resolve_local_path
from openworkproof.repo_pipeline.traversal import language_for


def _sample_repo(tmp_path: Path) -> Path:
    root = tmp_path / "sample"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("import os\n\nprint('hi')\n")
    (root / "src" / "lib.ts").write_text("export const x = 1;\n")
    (root / "README.md").write_text("# Sample\n")
    (root / "node_modules").mkdir()
    (root / "node_modules" / "dep.js").write_text("module.exports = 1;\n")
    (root / ".git").mkdir()
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (root / "dist").mkdir()
    (root / "dist" / "bundle.js").write_text("console.log(1);\n")
    return root


def test_resolve_local_path_accepts_str_and_path(tmp_path: Path) -> None:
    root = _sample_repo(tmp_path)
    assert resolve_local_path(str(root)) == root.resolve()
    assert resolve_local_path(root) == root.resolve()


def test_resolve_missing_path_raises(tmp_path: Path) -> None:
    missing = tmp_path / "nope"
    with pytest.raises(PathNotFoundError):
        resolve_local_path(missing)


def test_resolve_unsupported_source_rejected() -> None:
    with pytest.raises(PathNotFoundError):
        resolve_repository_source("not-a-path-or-url")
    with pytest.raises(UnsupportedSourceError):
        resolve_repository_source("https://gitlab.com/owner/repo")


def test_github_url_classification(tmp_path: Path) -> None:
    url = "https://github.com/owner/repo"
    with pytest.raises(Exception) as exc:
        resolve_repository_source(url, clone_enabled=False)
    assert "clone is disabled" in str(exc.value)


def test_traversal_filters_directories_and_recognises_languages(
    tmp_path: Path,
) -> None:
    root = _sample_repo(tmp_path)
    scan = scan_repository(root)
    paths = {entry.relative_path for entry in scan.entries}
    assert "src/app.py" in paths
    assert "src/lib.ts" in paths
    assert "README.md" in paths
    assert "node_modules/dep.js" not in paths
    assert ".git/HEAD" not in paths
    assert "dist/bundle.js" not in paths
    assert scan.total_files == 3
    assert scan.languages == {"Python": 1, "TypeScript": 1, "Markdown": 1}
    by_path = {entry.relative_path: entry for entry in scan.entries}
    assert by_path["src/app.py"].language == "Python"
    assert by_path["src/app.py"].size_bytes == len("import os\n\nprint('hi')\n")
    assert by_path["src/app.py"].sha256


def test_language_recognition() -> None:
    assert language_for(Path("a.py")) == "Python"
    assert language_for(Path("a.tsx")) == "TypeScript"
    assert language_for(Path("Dockerfile")) == "Dockerfile"
    assert language_for(Path("unknown.zzz")) is None


def test_analysis_layer_extensible_with_custom_analyzer(
    tmp_path: Path,
) -> None:
    root = _sample_repo(tmp_path)
    scan = scan_repository(root)

    class UpperAnalyzer:
        name = "upper"

        def analyze(self, scan):
            return AnalysisResult(
                analyzer=self.name,
                data={"count": sum(1 for e in scan.entries if "py" in e.relative_path)},
            )

    results = analyze_repository(
        root,
        analyzers=(LineCountAnalyzer(), UpperAnalyzer()),
    )
    names = [result.analyzer for result in results.results]
    assert names == ["line_counts", "upper"]
    by_name = {result.analyzer: result for result in results.results}
    assert by_name["line_counts"].data["total_lines"] == 5
    assert by_name["upper"].data["count"] == 1


def test_default_analyzers_emit_language_and_lines(tmp_path: Path) -> None:
    root = _sample_repo(tmp_path)
    analysis = analyze_repository(root, clone_enabled=True)
    by_name = {result.analyzer: result for result in analysis.results}
    assert by_name["language_stats"].data["languages"]["Python"]["files"] == 1
    assert by_name["dependency_sniff"].data["imports_by_kind"]["python"] == ["os"]


def test_output_is_canonical_json(tmp_path: Path) -> None:
    root = _sample_repo(tmp_path)
    analysis = analyze_repository(root)
    rendered = render_json(analysis)
    parsed = json.loads(rendered)
    assert parsed["schema_version"] == "openworkproof/repo-analysis/0.1"
    assert parsed["totals"]["files"] == 3
    assert {item["path"] for item in parsed["files"]} == {
        "src/app.py",
        "src/lib.ts",
        "README.md",
    }
    assert any(
        item["analyzer"] == "language_stats"
        for item in parsed["results"]
    )
    assert to_dict(analysis)["root"] == str(root.resolve())


def test_read_error_skips_file_but_keeps_scan(tmp_path: Path) -> None:
    root = _sample_repo(tmp_path)
    broken = root / "src" / "broken.py"
    broken.write_bytes(b"\xff\xfe binary-ish")

    from openworkproof.repo_pipeline.errors import DecodeError as _DecodeError

    def strict_reader(path: Path) -> str:
        raw = path.read_bytes()
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise _DecodeError("not utf-8") from error

    scan = scan_repository(root, read_file=strict_reader)
    paths = {entry.relative_path for entry in scan.entries}
    assert "src/broken.py" not in paths
    assert "src/app.py" in paths


def test_unreadable_directory_is_skipped_gracefully(tmp_path: Path) -> None:
    root = _sample_repo(tmp_path)
    secret = root / "src" / "secret"
    secret.mkdir()
    secret.chmod(0)
    try:
        scan = scan_repository(root)
    finally:
        secret.chmod(stat.S_IRWXU)
    assert all("secret" not in entry.relative_path for entry in scan.entries)


def test_reader_rejects_oversized_and_binary(tmp_path: Path) -> None:
    from openworkproof.repo_pipeline.reader import read_text_file

    big = tmp_path / "big.txt"
    big.write_bytes(b"x" * 2_000_000)
    with pytest.raises(DecodeError):
        read_text_file(big)

    binary = tmp_path / "bin.dat"
    binary.write_bytes(b"\x00\x01\xff")
    with pytest.raises(DecodeError):
        read_text_file(binary, max_bytes=10_000_000)


def test_permission_denied_on_unreadable_file(tmp_path: Path) -> None:
    from openworkproof.repo_pipeline.reader import read_text_file

    locked = tmp_path / "locked.txt"
    locked.write_text("data")
    locked.chmod(0)
    try:
        with pytest.raises(PermissionDeniedError):
            read_text_file(locked)
    finally:
        locked.chmod(stat.S_IRWXU)
