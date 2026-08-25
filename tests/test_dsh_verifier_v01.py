from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path

from openworkproof.dsh_verifier import (
    DshVerificationCaseV01,
    verify_dsh_code_change,
)


NOW = datetime(2026, 8, 26, tzinfo=timezone.utc)


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _verification_case(tmp_path: Path) -> DshVerificationCaseV01:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "OWP Test")
    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "src/app.py")
    _git(repo, "commit", "-m", "base")
    source = _git(repo, "rev-parse", "HEAD")
    return DshVerificationCaseV01(
        case_id="a" * 64,
        repository_root=repo,
        source_revision=source,
        allowed_path_roots=("src",),
        denied_path_roots=("secrets",),
        test_profile_digest="b" * 64,
        ledger_path=None,
        evidence_root=None,
        verification_runner=lambda _repo: 0,
    )


def test_independent_verifier_rejects_out_of_scope_file(tmp_path: Path) -> None:
    case = _verification_case(tmp_path)
    (case.repository_root / "secrets.txt").write_text(
        "drift\n", encoding="utf-8"
    )

    result = verify_dsh_code_change(case, clock=lambda: NOW)

    assert result.status == "REFUTED"
    assert "OUT_OF_SCOPE_CHANGE" in result.reason_codes


def test_valid_signature_wrong_criterion_is_refuted(tmp_path: Path) -> None:
    case = _verification_case(tmp_path)

    result = verify_dsh_code_change(
        case,
        criterion_digest="0" * 64,
        clock=lambda: NOW,
    )

    assert result.status == "REFUTED"
    assert "CRITERION_BINDING_MISMATCH" in result.reason_codes


def test_unavailable_independent_runner_is_unknown(tmp_path: Path) -> None:
    case = _verification_case(tmp_path)
    case = DshVerificationCaseV01(
        case_id=case.case_id,
        repository_root=case.repository_root,
        source_revision=case.source_revision,
        allowed_path_roots=case.allowed_path_roots,
        denied_path_roots=case.denied_path_roots,
        test_profile_digest=case.test_profile_digest,
        ledger_path=None,
        evidence_root=None,
        verification_runner=None,
    )

    result = verify_dsh_code_change(case, clock=lambda: NOW)

    assert result.status == "UNKNOWN"
    assert result.reason_codes == ("VERIFIER_UNAVAILABLE",)
