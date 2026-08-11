from __future__ import annotations

import hashlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest
import rfc8785

from openworkproof.models import (
    EvaluationScopeManifest,
    ScopeMember,
    ScopeRequirementBinding,
    ScopeSelectorRule,
    SubjectClaim,
)
from openworkproof.scope import (
    ObservedScope,
    build_evaluation_scope,
    compare_observed_scope,
    evaluation_scope_id,
    population_digest,
    requirement_digest,
    select_git_diff_closure,
    select_pytest_collection,
    scope_member_id,
    validate_evaluation_scope,
)
from openworkproof.signing import sign_payload


def _member(
    kind: str,
    locator: str,
    *,
    revision: str,
    content: bytes = b"content",
) -> ScopeMember:
    return ScopeMember.model_validate(
        {
            "member_id": scope_member_id(kind, locator),
            "member_kind": kind,
            "locator": locator,
            "locator_digest": hashlib.sha256(locator.encode()).hexdigest(),
            "content_digest": hashlib.sha256(content).hexdigest(),
            "source_revision": revision,
        }
    )


@pytest.fixture
def scope_build_request(
    tmp_path: Path,
    signed_subject_claim: SubjectClaim,
) -> dict:
    subprocess.run(
        ["git", "init", "-q", str(tmp_path)],
        check=True,
        capture_output=True,
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src/widget.py").write_text("VALUE = 1\n")
    (tmp_path / "tests/test_widget.py").write_text("def test_widget(): pass\n")

    revision = signed_subject_claim.source_revision
    members = tuple(
        sorted(
            (
                _member("source_file", "src/widget.py", revision=revision),
                _member(
                    "test_case",
                    "tests/test_widget.py::test_widget",
                    revision=revision,
                ),
                _member("delivery_artifact", "evidence", revision=revision),
                _member("delivery_artifact", "results", revision=revision),
            ),
            key=lambda member: (
                member.member_kind,
                member.locator_digest,
                member.member_id,
            ),
        )
    )
    test_id = next(
        member.member_id for member in members if member.member_kind == "test_case"
    )
    by_locator = {member.locator: member.member_id for member in members}
    bindings = tuple(
        sorted(
            (
                *(
                    ScopeRequirementBinding(
                        requirement_kind="acceptance_condition",
                        requirement_digest=requirement_digest(
                            "acceptance_condition", condition
                        ),
                        member_ids=(test_id,),
                    )
                    for condition in signed_subject_claim.acceptance_conditions
                ),
                *(
                    ScopeRequirementBinding(
                        requirement_kind="required_artifact",
                        requirement_digest=requirement_digest(
                            "required_artifact", artifact
                        ),
                        member_ids=(by_locator[artifact],),
                    )
                    for artifact in signed_subject_claim.required_artifacts
                ),
            ),
            key=lambda binding: (
                binding.requirement_kind.encode("utf-8"),
                binding.requirement_digest,
            ),
        )
    )
    return {
        "claim": signed_subject_claim,
        "work_order_digest": signed_subject_claim.work_order_digest,
        "source_revision": revision,
        "candidate_commit": "2" * 40,
        "workspace_manifest_digest": "3" * 64,
        "selector_rules": (
            ScopeSelectorRule(
                rule_id="4" * 64,
                selector_kind="explicit",
                selector_spec_digest="5" * 64,
                selector_engine_digest="6" * 64,
                required_evidence_paths=("scope/selectors/explicit.json",),
            ),
        ),
        "explicit_members": members,
        "requirement_bindings": bindings,
        "excluded_locator_digests": (),
        "repository_root": tmp_path,
        "created_at": datetime(2026, 1, 1, 0, 0, 6, tzinfo=timezone.utc),
        "expires_at": datetime(2026, 1, 1, 1, 0, tzinfo=timezone.utc),
        "nonce": "7" * 64,
    }


def _observed(manifest: EvaluationScopeManifest) -> ObservedScope:
    return ObservedScope(
        member_ids=tuple(member.member_id for member in manifest.members),
        member_count=manifest.member_count,
        population_digest=manifest.population_digest,
        required_target_ids=manifest.required_target_ids,
        source_revision=manifest.source_revision,
        workspace_manifest_digest=manifest.workspace_manifest_digest,
        selector_engine_digests=tuple(
            sorted(rule.selector_engine_digest for rule in manifest.selector_rules)
        ),
        evidence_complete=True,
    )


def test_digest_helpers_match_exact_v03_formulas() -> None:
    locator = "src/widget.py"
    expected_member = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/scope-member/v0.3",
                "payload": {"member_kind": "source_file", "locator": locator},
            }
        )
    ).hexdigest()
    assert scope_member_id("source_file", locator) == expected_member
    assert requirement_digest("required_artifact", locator) == hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/scope-requirement/v0.3",
                "payload": {
                    "requirement_kind": "required_artifact",
                    "value": locator,
                },
            }
        )
    ).hexdigest()


def test_explicit_scope_builds_required_population(scope_build_request: dict) -> None:
    draft = build_evaluation_scope(**scope_build_request)
    validate_evaluation_scope(draft, claim=scope_build_request["claim"])
    assert draft.member_count == len(draft.members)
    assert draft.required_target_ids
    assert draft.population_digest == population_digest(draft.members)
    identity = draft.model_dump(mode="json", exclude={"scope_id"})
    assert draft.scope_id == evaluation_scope_id(identity)
    assert "signature" not in draft.model_dump(mode="json")


def test_explicit_scope_repeat_run_is_deterministic(
    scope_build_request: dict,
) -> None:
    first = build_evaluation_scope(**scope_build_request)
    second = build_evaluation_scope(
        **{
            **scope_build_request,
            "selector_rules": tuple(reversed(scope_build_request["selector_rules"])),
            "explicit_members": tuple(
                reversed(scope_build_request["explicit_members"])
            ),
            "requirement_bindings": tuple(
                reversed(scope_build_request["requirement_bindings"])
            ),
        }
    )
    assert first == second
    assert population_digest(first.members) == population_digest(
        tuple(reversed(first.members))
    )


def test_builder_rejects_empty_selection(scope_build_request: dict) -> None:
    with pytest.raises(ValueError, match="1..4096|empty"):
        build_evaluation_scope(
            **{**scope_build_request, "explicit_members": ()}
        )


def test_builder_rejects_excluded_member(scope_build_request: dict) -> None:
    excluded = scope_build_request["explicit_members"][0].locator_digest
    with pytest.raises(ValueError, match="excluded"):
        build_evaluation_scope(
            **{
                **scope_build_request,
                "excluded_locator_digests": (excluded,),
            }
        )


def test_builder_rejects_wrong_claim_or_revision(scope_build_request: dict) -> None:
    with pytest.raises(ValueError, match="work_order_digest"):
        build_evaluation_scope(
            **{**scope_build_request, "work_order_digest": "f" * 64}
        )
    with pytest.raises(ValueError, match="source_revision"):
        build_evaluation_scope(
            **{**scope_build_request, "source_revision": "f" * 40}
        )


def test_builder_rejects_symlink_and_path_escapes(
    scope_build_request: dict,
) -> None:
    root = scope_build_request["repository_root"]
    (root / "linked.py").symlink_to(root / "src/widget.py")
    revision = scope_build_request["source_revision"]
    linked = _member("source_file", "linked.py", revision=revision)
    with pytest.raises(ValueError, match="symlink"):
        build_evaluation_scope(
            **{**scope_build_request, "explicit_members": (linked,)}
        )
    for locator in ("/src/widget.py", "../src/widget.py"):
        with pytest.raises(ValueError, match="root|locator|path"):
            _member("source_file", locator, revision=revision)


def test_validate_rejects_incomplete_requirement_bindings(
    scope_build_request: dict,
) -> None:
    draft = build_evaluation_scope(**scope_build_request)
    incomplete = draft.model_copy(
        update={"requirement_bindings": draft.requirement_bindings[:-1]}
    )
    with pytest.raises(ValueError, match="requirement_bindings"):
        validate_evaluation_scope(incomplete, claim=scope_build_request["claim"])


def test_compare_exact_scope_is_satisfied(
    scope_build_request: dict,
    scope_manager_private_key_v03,
) -> None:
    draft = build_evaluation_scope(**scope_build_request)
    manifest = EvaluationScopeManifest.model_validate(
        sign_payload(
            "evaluation-scope",
            draft.model_dump(mode="json"),
            scope_manager_private_key_v03,
            version="0.3",
        )
    )
    result = compare_observed_scope(manifest, _observed(manifest))
    assert result.scope_status == "satisfied"
    assert result.reason_codes == ()


def test_missing_required_target_is_indeterminate(evaluation_scope_v03) -> None:
    observed = _observed(evaluation_scope_v03)
    result = compare_observed_scope(
        evaluation_scope_v03,
        observed.model_copy(update={"member_ids": observed.member_ids[:-1]}),
    )
    assert result.scope_status == "indeterminate"
    assert "SCOPE_REQUIRED_TARGET_MISSING" in result.reason_codes


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    (
        ("workspace_manifest_digest", "f" * 64, "SCOPE_WORKSPACE_DRIFT"),
        ("source_revision", "f" * 40, "SCOPE_WORKSPACE_DRIFT"),
        ("selector_engine_digests", ("f" * 64,), "SCOPE_SELECTOR_MISMATCH"),
        ("evidence_complete", False, "SCOPE_EVIDENCE_MISSING"),
    ),
)
def test_observed_scope_drift_is_indeterminate(
    evaluation_scope_v03,
    field: str,
    value: object,
    reason: str,
) -> None:
    observed = _observed(evaluation_scope_v03)
    result = compare_observed_scope(
        evaluation_scope_v03,
        observed.model_copy(update={field: value}),
    )
    assert result.scope_status == "indeterminate"
    assert reason in result.reason_codes


def test_n_minus_one_member_evidence_is_indeterminate(evaluation_scope_v03) -> None:
    observed = _observed(evaluation_scope_v03)
    result = compare_observed_scope(
        evaluation_scope_v03,
        observed.model_copy(
            update={
                "member_ids": observed.member_ids[:-1],
                "member_count": observed.member_count - 1,
                "evidence_complete": False,
            }
        ),
    )
    assert result.scope_status == "indeterminate"
    assert "SCOPE_EVIDENCE_MISSING" in result.reason_codes


def test_complete_but_different_population_is_contradicted(
    evaluation_scope_v03,
) -> None:
    observed = _observed(evaluation_scope_v03)
    result = compare_observed_scope(
        evaluation_scope_v03,
        observed.model_copy(
            update={
                "member_ids": (*observed.member_ids, "f" * 64),
                "member_count": observed.member_count + 1,
                "population_digest": "f" * 64,
            }
        ),
    )
    assert result.scope_status == "contradicted"
    assert result.reason_codes == ("SCOPE_POPULATION_DRIFT",)


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _committed_selector_repo(tmp_path: Path) -> tuple[Path, str, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git("init", "-q", cwd=repo)
    _git("config", "user.name", "Scope Test", cwd=repo)
    _git("config", "user.email", "scope@example.invalid", cwd=repo)
    (repo / "src").mkdir()
    (repo / "tests").mkdir()
    (repo / "src/keep.py").write_text("VALUE = 'source'\n")
    (repo / "src/rename_old.py").write_text("RENAMED = True\n")
    (repo / "src/delete.py").write_text("DELETED = True\n")
    (repo / "tests/test_alpha.py").write_text("def test_alpha(): pass\n")
    _git("add", ".", cwd=repo)
    _git("commit", "-q", "-m", "source", cwd=repo)
    source = _git("rev-parse", "HEAD", cwd=repo)

    (repo / "src/keep.py").write_text("VALUE = 'candidate'\n")
    _git("mv", "src/rename_old.py", "src/rename_new.py", cwd=repo)
    _git("rm", "-q", "src/delete.py", cwd=repo)
    _git("add", ".", cwd=repo)
    _git("commit", "-q", "-m", "candidate", cwd=repo)
    candidate = _git("rev-parse", "HEAD", cwd=repo)
    return repo, source, candidate


def test_git_diff_selector_uses_committed_blobs_and_tracks_renames(
    tmp_path: Path,
) -> None:
    repo, source, candidate = _committed_selector_repo(tmp_path)
    (repo / "src/keep.py").write_text("VALUE = 'dirty'\n")
    execution = select_git_diff_closure(
        repo,
        source_revision=source,
        candidate_commit=candidate,
    )
    assert execution.status == "satisfied"
    assert {member.locator for member in execution.members} == {
        "src/delete.py",
        "src/keep.py",
        "src/rename_new.py",
        "src/rename_old.py",
    }
    assert execution.members == tuple(
        sorted(
            execution.members,
            key=lambda member: (
                member.member_kind,
                member.locator_digest,
                member.member_id,
            ),
        )
    )
    keep = next(member for member in execution.members if member.locator == "src/keep.py")
    assert keep.content_digest == hashlib.sha256(
        b"VALUE = 'candidate'\n"
    ).hexdigest()
    assert execution.evidence_path == "scope/selectors/git-diff-closure.json"
    assert execution.selector_spec_bytes


def test_git_diff_selector_requires_full_commits(tmp_path: Path) -> None:
    repo, source, candidate = _committed_selector_repo(tmp_path)
    with pytest.raises(ValueError, match="40-character"):
        select_git_diff_closure(
            repo,
            source_revision=source[:12],
            candidate_commit=candidate,
        )


def test_git_diff_selector_engine_drift_is_indeterminate(tmp_path: Path) -> None:
    repo, source, candidate = _committed_selector_repo(tmp_path)
    execution = select_git_diff_closure(
        repo,
        source_revision=source,
        candidate_commit=candidate,
        expected_engine_digest="f" * 64,
    )
    assert execution.status == "indeterminate"
    assert execution.reason_codes == ("SCOPE_SELECTOR_MISMATCH",)


def test_git_diff_selector_empty_population_is_indeterminate(tmp_path: Path) -> None:
    repo, _source, candidate = _committed_selector_repo(tmp_path)
    execution = select_git_diff_closure(
        repo,
        source_revision=candidate,
        candidate_commit=candidate,
    )
    assert execution.status == "indeterminate"
    assert execution.reason_codes == ("SCOPE_EMPTY",)


def test_git_diff_selector_rejects_committed_symlink(tmp_path: Path) -> None:
    repo, _source, candidate = _committed_selector_repo(tmp_path)
    (repo / "src/linked.py").symlink_to(repo / "src/keep.py")
    _git("add", "src/linked.py", cwd=repo)
    _git("commit", "-q", "-m", "symlink", cwd=repo)
    symlink_commit = _git("rev-parse", "HEAD", cwd=repo)
    with pytest.raises(ValueError, match="symlink"):
        select_git_diff_closure(
            repo,
            source_revision=candidate,
            candidate_commit=symlink_commit,
        )


def _fake_python(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\nset -eu\n" + body)
    path.chmod(0o755)
    return path


def test_pytest_collection_is_fixed_sorted_and_unique(tmp_path: Path) -> None:
    repo, source, candidate = _committed_selector_repo(tmp_path)
    fake = _fake_python(
        tmp_path / "fake-python",
        """
test "$1" = "-I"
test "$2" = "-m"
test "$3" = "pytest"
test "$4" = "--collect-only"
test "$5" = "-q"
test "$PYTEST_DISABLE_PLUGIN_AUTOLOAD" = "1"
test "$LC_ALL" = "C.UTF-8"
test "$TZ" = "UTC"
printf '%s\n' \
  'tests/test_alpha.py::test_z[param-一]' \
  'tests/test_alpha.py::test_a' \
  'tests/test_alpha.py::test_a'
""",
    )
    execution = select_pytest_collection(
        repo,
        source_revision=source,
        candidate_commit=candidate,
        python_executable=fake,
        timeout_seconds=5,
        required_node_ids=("tests/test_alpha.py::test_a",),
    )
    assert execution.status == "satisfied"
    assert sorted(member.locator for member in execution.members) == [
        "tests/test_alpha.py::test_a",
        "tests/test_alpha.py::test_z[param-一]",
    ]
    assert execution.evidence_path == "scope/selectors/pytest-collection.json"


@pytest.mark.parametrize(
    ("body", "timeout", "reason"),
    (
        ("exit 3\n", 5, "SCOPE_SELECTOR_MISMATCH"),
        ("printf 'no tests collected\\n'\n", 5, "SCOPE_EMPTY"),
        ("sleep 2\n", 1, "SCOPE_SELECTOR_MISMATCH"),
    ),
)
def test_pytest_collection_failures_are_indeterminate(
    tmp_path: Path,
    body: str,
    timeout: int,
    reason: str,
) -> None:
    repo, source, candidate = _committed_selector_repo(tmp_path)
    fake = _fake_python(tmp_path / "fake-python", body)
    execution = select_pytest_collection(
        repo,
        source_revision=source,
        candidate_commit=candidate,
        python_executable=fake,
        timeout_seconds=timeout,
    )
    assert execution.status == "indeterminate"
    assert reason in execution.reason_codes


def test_pytest_collection_missing_required_node_is_indeterminate(
    tmp_path: Path,
) -> None:
    repo, source, candidate = _committed_selector_repo(tmp_path)
    fake = _fake_python(
        tmp_path / "fake-python",
        "printf 'tests/test_alpha.py::test_alpha\\n'\n",
    )
    execution = select_pytest_collection(
        repo,
        source_revision=source,
        candidate_commit=candidate,
        python_executable=fake,
        timeout_seconds=5,
        required_node_ids=("tests/test_alpha.py::test_missing",),
    )
    assert execution.status == "indeterminate"
    assert execution.reason_codes == ("SCOPE_REQUIRED_TARGET_MISSING",)
