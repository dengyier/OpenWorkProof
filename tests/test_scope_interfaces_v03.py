from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

import openworkproof.cli as cli
import openworkproof.services as services
from openworkproof.scope import ObservedScope, requirement_digest
from openworkproof.services import OpenWorkProofServices


def _observed(manifest, **overrides) -> ObservedScope:
    payload = {
        "member_ids": [item.member_id for item in manifest.members],
        "member_count": manifest.member_count,
        "population_digest": manifest.population_digest,
        "required_target_ids": list(manifest.required_target_ids),
        "source_revision": manifest.source_revision,
        "workspace_manifest_digest": manifest.workspace_manifest_digest,
        "selector_engine_digests": sorted(
            rule.selector_engine_digest for rule in manifest.selector_rules
        ),
        "evidence_complete": True,
    }
    payload.update(overrides)
    return ObservedScope.model_validate(payload)


def test_service_scope_validate_is_intrinsic_and_does_not_claim_authority(
    evaluation_scope_v03,
) -> None:
    result = OpenWorkProofServices().validate_scope(
        evaluation_scope_v03.model_dump(mode="json")
    )
    assert result == {
        "valid": True,
        "schema_version": "openworkproof-evaluation-scope/0.3",
        "scope_id": evaluation_scope_v03.scope_id,
        "scope_manifest_digest": evaluation_scope_v03.digest,
        "member_count": evaluation_scope_v03.member_count,
        "authority": "not_checked",
    }


def test_service_scope_build_returns_unsigned_draft(
    tmp_path,
    signed_subject_claim,
    evaluation_scope_payload_v03,
) -> None:
    repository = tmp_path / "repository"
    (repository / "src").mkdir(parents=True)
    (repository / "tests").mkdir()
    (repository / "src/widget.py").write_text("source", encoding="utf-8")
    (repository / "tests/test_widget.py").write_text(
        "test", encoding="utf-8"
    )
    source_member = next(
        member
        for member in evaluation_scope_payload_v03["members"]
        if member["member_kind"] == "source_file"
    )
    test_member = next(
        member
        for member in evaluation_scope_payload_v03["members"]
        if member["member_kind"] == "test_case"
    )
    requirement_bindings = sorted(
        [
            *(
                {
                    "requirement_kind": "acceptance_condition",
                    "requirement_digest": requirement_digest(
                        "acceptance_condition", value
                    ),
                    "member_ids": [test_member["member_id"]],
                }
                for value in signed_subject_claim.acceptance_conditions
            ),
            *(
                {
                    "requirement_kind": "required_artifact",
                    "requirement_digest": requirement_digest(
                        "required_artifact", value
                    ),
                    "member_ids": [source_member["member_id"]],
                }
                for value in signed_subject_claim.required_artifacts
            ),
        ],
        key=lambda item: (
            item["requirement_kind"].encode("utf-8"),
            item["requirement_digest"],
        ),
    )
    rules = {
        "work_order_digest": signed_subject_claim.work_order_digest,
        "candidate_commit": evaluation_scope_payload_v03["candidate_commit"],
        "workspace_manifest_digest": evaluation_scope_payload_v03[
            "workspace_manifest_digest"
        ],
        "selector_rules": evaluation_scope_payload_v03["selector_rules"],
        "explicit_members": evaluation_scope_payload_v03["members"],
        "requirement_bindings": requirement_bindings,
        "excluded_locator_digests": [],
        "repository_root": str(repository),
        "created_at": "2026-01-01T00:00:05Z",
        "expires_at": "2026-01-01T01:00:00Z",
        "nonce": "7" * 64,
    }
    result = OpenWorkProofServices().build_scope(
        signed_subject_claim.model_dump(mode="json"),
        signed_subject_claim.source_revision,
        rules,
    )
    assert result["schema_version"] == "openworkproof-evaluation-scope/0.3"
    assert result["member_count"] == 2
    assert not {
        "digest",
        "signature_alg",
        "signer_key_id",
        "signature",
    }.intersection(result)


def test_service_scope_commit_parses_claim_and_manifest_then_delegates_once(
    evaluation_scope_v03,
    signed_subject_claim,
    monkeypatch,
) -> None:
    calls = []
    monkeypatch.setattr(
        services,
        "commit_evaluation_scope",
        lambda ledger, claim, scope: calls.append((ledger, claim, scope))
        or scope,
    )
    result = OpenWorkProofServices().commit_scope(
        Path("ledger.sqlite3"),
        {
            "claim": signed_subject_claim.model_dump(mode="json"),
            "scope": evaluation_scope_v03.model_dump(mode="json"),
        },
    )
    assert result["scope_id"] == evaluation_scope_v03.scope_id
    assert len(calls) == 1
    assert calls[0][0] == Path("ledger.sqlite3")


@pytest.mark.parametrize(
    ("overrides", "status", "reasons"),
    (
        ({}, "satisfied", []),
        (
            {"evidence_complete": False},
            "indeterminate",
            ["SCOPE_EVIDENCE_MISSING"],
        ),
        (
            {"member_ids": [], "member_count": 0},
            "indeterminate",
            [
                "SCOPE_EMPTY",
                "SCOPE_REQUIRED_TARGET_MISSING",
            ],
        ),
    ),
)
def test_service_scope_compare_returns_closed_diagnostics(
    evaluation_scope_v03,
    overrides,
    status,
    reasons,
) -> None:
    observed = _observed(evaluation_scope_v03, **overrides)
    result = OpenWorkProofServices().compare_scope(
        evaluation_scope_v03.model_dump(mode="json"),
        observed.model_dump(mode="json"),
    )
    assert result["scope_status"] == status
    assert result["reason_codes"] == reasons


def test_service_dispatches_v03_profile_arm_and_decision_by_schema(
    monkeypatch,
) -> None:
    calls = []

    class Parsed:
        def __init__(self, value):
            self.value = value

        def model_dump(self, *, mode):
            assert mode == "json"
            return {"parsed": self.value}

    for name in (
        "VerificationProfileV03",
        "VerificationArmResultV03",
        "VerificationDecisionV03",
    ):
        model = getattr(services, name)
        monkeypatch.setattr(
            model,
            "model_validate",
            lambda payload, name=name: Parsed(name),
        )
    monkeypatch.setattr(
        services,
        "commit_verification_arm_result_v03",
        lambda ledger, value: calls.append(("arm", ledger, value)) or value,
    )
    monkeypatch.setattr(
        services,
        "commit_verification_decision_v03",
        lambda ledger, value: calls.append(("decision", ledger, value)) or value,
    )
    facade = OpenWorkProofServices()
    profile = facade.validate_profile(
        {"schema_version": "openworkproof-verification-profile/0.3"}
    )
    arm = facade.commit_arm_result(
        Path("ledger.sqlite3"),
        {"schema_version": "openworkproof-verification-arm-result/0.3"},
    )
    decision = facade.commit_decision(
        Path("ledger.sqlite3"),
        {"schema_version": "openworkproof-verification-decision/0.3"},
    )
    assert profile == {"parsed": "VerificationProfileV03"}
    assert arm == {"parsed": "VerificationArmResultV03"}
    assert decision == {"parsed": "VerificationDecisionV03"}
    assert [item[0] for item in calls] == ["arm", "decision"]


def test_scope_cli_parser_registers_all_four_commands() -> None:
    parser = cli.build_parser()
    cases = (
        [
            "scope-build",
            "--claim",
            "claim.json",
            "--source-revision",
            "a" * 40,
            "--rules",
            "rules.json",
        ],
        ["scope-validate", "scope.json"],
        ["scope-commit", "pilot.sqlite3", "signed-scope.json"],
        ["scope-compare", "scope.json", "observed-scope.json"],
    )
    assert [parser.parse_args(value).command for value in cases] == [
        "scope-build",
        "scope-validate",
        "scope-commit",
        "scope-compare",
    ]


@pytest.mark.parametrize(
    ("status", "expected"),
    (("satisfied", 0), ("indeterminate", 3), ("contradicted", 4)),
)
def test_scope_compare_cli_exit_codes_and_text_output(
    tmp_path,
    monkeypatch,
    capsys,
    status,
    expected,
) -> None:
    scope_path = tmp_path / "scope.json"
    observed_path = tmp_path / "observed.json"
    scope_path.write_text("{}", encoding="utf-8")
    observed_path.write_text("{}", encoding="utf-8")

    class FakeServices:
        def compare_scope(self, scope, observed):
            return {
                "scope_status": status,
                "reason_codes": ["SCOPE_TEST"],
                "missing_required_target_ids": [],
            }

    monkeypatch.setattr(cli, "OpenWorkProofServices", FakeServices)
    code = cli.app(
        [
            "--output",
            "text",
            "scope-compare",
            str(scope_path),
            str(observed_path),
        ]
    )
    assert code == expected
    assert f"scope_status={status}" in capsys.readouterr().out


def test_scope_mcp_tools_are_read_only_and_match_service(
    evaluation_scope_v03,
    monkeypatch,
) -> None:
    from openworkproof import mcp_transport

    calls = []

    class FakeServices:
        def validate_scope(self, payload):
            calls.append(("validate", payload))
            return {"valid": True, "authority": "not_checked"}

        def compare_scope(self, manifest, observed):
            calls.append(("compare", manifest, observed))
            return {"scope_status": "satisfied", "reason_codes": []}

    monkeypatch.setattr(mcp_transport, "OpenWorkProofServices", FakeServices)
    raw = json.dumps(evaluation_scope_v03.model_dump(mode="json"))
    validated = mcp_transport.owp_scope_validate(raw)
    compared = mcp_transport.owp_scope_compare(raw, "{}")
    assert validated["ok"] is True
    assert validated["authority"] == "not_checked"
    assert compared["scope_status"] == "satisfied"
    assert [item[0] for item in calls] == ["validate", "compare"]

    tools = mcp_transport.mcp._tool_manager._tools
    assert {"owp_scope_validate", "owp_scope_compare"} <= set(tools)
    assert not any(
        token in name
        for name in tools
        for token in ("scope_sign", "scope_commit", "acceptance_decide")
    )
    for function in (
        mcp_transport.owp_scope_validate,
        mcp_transport.owp_scope_compare,
    ):
        parameters = inspect.signature(function).parameters
        assert not any(
            token in name
            for name in parameters
            for token in ("private_key", "ledger", "signature")
        )
