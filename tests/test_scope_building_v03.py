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
