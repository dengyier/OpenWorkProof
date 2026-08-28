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


def test_artifact_bindings_distinguish_swapped_file_contents(
    tmp_path: Path,
) -> None:
    seed = tmp_path / "seed"
    seed.mkdir()
    _git(seed, "init", "-b", "main")
    _git(seed, "config", "user.email", "test@example.com")
    _git(seed, "config", "user.name", "OWP Test")
    (seed / "src").mkdir()
    (seed / "src" / "a.txt").write_text("base-a\n", encoding="utf-8")
    (seed / "src" / "b.txt").write_text("base-b\n", encoding="utf-8")
    _git(seed, "add", "src/a.txt", "src/b.txt")
    _git(seed, "commit", "-m", "base")
    source = _git(seed, "rev-parse", "HEAD")

    left = tmp_path / "left"
    right = tmp_path / "right"
    subprocess.run(["git", "clone", "-q", str(seed), str(left)], check=True)
    subprocess.run(["git", "clone", "-q", str(seed), str(right)], check=True)
    (left / "src" / "a.txt").write_text("alpha\n", encoding="utf-8")
    (left / "src" / "b.txt").write_text("beta\n", encoding="utf-8")
    (right / "src" / "a.txt").write_text("beta\n", encoding="utf-8")
    (right / "src" / "b.txt").write_text("alpha\n", encoding="utf-8")

    def verification_case(repository_root: Path) -> DshVerificationCaseV01:
        return DshVerificationCaseV01(
            case_id="a" * 64,
            repository_root=repository_root,
            source_revision=source,
            allowed_path_roots=("src",),
            denied_path_roots=("secrets",),
            test_profile_digest="b" * 64,
            ledger_path=None,
            evidence_root=None,
            verification_runner=lambda _repo: 0,
        )

    left_result = verify_dsh_code_change(
        verification_case(left), clock=lambda: NOW
    )
    right_result = verify_dsh_code_change(
        verification_case(right), clock=lambda: NOW
    )

    assert left_result.model_dump(mode="json") != right_result.model_dump(
        mode="json"
    )


def test_verifier_refutes_workspace_bytes_changed_after_frozen_test(
    tmp_path: Path,
) -> None:
    case = _verification_case(tmp_path)
    (case.repository_root / "src" / "app.py").write_text(
        "tested\n", encoding="utf-8"
    )
    calls: list[Path] = []
    case = DshVerificationCaseV01(
        case_id=case.case_id,
        repository_root=case.repository_root,
        source_revision=case.source_revision,
        allowed_path_roots=case.allowed_path_roots,
        denied_path_roots=case.denied_path_roots,
        test_profile_digest=case.test_profile_digest,
        ledger_path=None,
        evidence_root=None,
        verification_runner=lambda root: calls.append(root) or 0,
        tested_workspace_manifest_digest="1" * 64,
        candidate_workspace_manifest_digest="2" * 64,
    )

    result = verify_dsh_code_change(case, clock=lambda: NOW)

    assert result.status == "REFUTED"
    assert result.reason_codes == ("TESTED_WORKSPACE_DRIFT",)
    assert calls == []
