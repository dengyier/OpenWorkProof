from __future__ import annotations

import hashlib
import copy
from datetime import datetime, timedelta, timezone

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from openworkproof.models import (
    EvaluationScopeDraft,
    EvaluationScopeManifest,
    ScopeMember,
    ScopeSelectorRule,
)
from openworkproof.signing import (
    canonical_bytes,
    sign_payload,
    verify_payload,
)


def _domain_digest(domain: str, payload: object) -> str:
    return hashlib.sha256(
        rfc8785.dumps(
            {"domain": f"openworkproof/{domain}/v0.3", "payload": payload}
        )
    ).hexdigest()


def _locator_digest(locator: str) -> str:
    return hashlib.sha256(locator.encode("utf-8")).hexdigest()


def _member(kind: str, locator: str, content: str, revision: str) -> dict:
    return {
        "member_id": _domain_digest(
            "scope-member", {"member_kind": kind, "locator": locator}
        ),
        "member_kind": kind,
        "locator": locator,
        "locator_digest": _locator_digest(locator),
        "content_digest": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        "source_revision": revision,
    }


def _manifest_payload() -> dict:
    source_revision = "a" * 40
    members = sorted(
        (
            _member("source_file", "src/widget.py", "source", source_revision),
            _member(
                "test_case",
                "tests/test_widget.py::test_widget[param-一]",
                "test",
                source_revision,
            ),
        ),
        key=lambda item: (
            item["member_kind"],
            item["locator_digest"],
            item["member_id"],
        ),
    )
    condition_digest = _domain_digest(
        "scope-requirement",
        {"requirement_kind": "acceptance_condition", "value": "tests_passed"},
    )
    artifact_digest = _domain_digest(
        "scope-requirement",
        {"requirement_kind": "required_artifact", "value": "src/widget.py"},
    )
    bindings = sorted(
        (
            {
                "requirement_kind": "acceptance_condition",
                "requirement_digest": condition_digest,
                "member_ids": [members[1]["member_id"]],
            },
            {
                "requirement_kind": "required_artifact",
                "requirement_digest": artifact_digest,
                "member_ids": [members[0]["member_id"]],
            },
        ),
        key=lambda item: (
            item["requirement_kind"].encode("utf-8"),
            item["requirement_digest"],
        ),
    )
    population = [
        {
            "member_id": item["member_id"],
            "member_kind": item["member_kind"],
            "locator_digest": item["locator_digest"],
        }
        for item in members
    ]
    created_at = datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc)
    payload = {
        "schema_version": "openworkproof-evaluation-scope/0.3",
        "scope_id": "0" * 64,
        "work_order_digest": "1" * 64,
        "subject_claim_digest": "2" * 64,
        "source_revision": source_revision,
        "candidate_commit": "b" * 40,
        "selector_rules": [
            {
                "rule_id": "3" * 64,
                "selector_kind": "explicit",
                "selector_spec_digest": "4" * 64,
                "selector_engine_digest": "5" * 64,
                "required_evidence_paths": ["scope/selectors/explicit.json"],
            }
        ],
        "members": members,
        "member_count": len(members),
        "population_digest": _domain_digest("scope-population", population),
        "requirement_bindings": bindings,
        "required_target_ids": sorted(
            {member_id for item in bindings for member_id in item["member_ids"]}
        ),
        "excluded_locator_digests": [_locator_digest("docs/ignored.md")],
        "workspace_manifest_digest": "6" * 64,
        "freshness_mode": "immutable_git_revision",
        "created_at": created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (created_at + timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "nonce": "7" * 64,
    }
    identity = {key: value for key, value in payload.items() if key != "scope_id"}
    payload["scope_id"] = _domain_digest("evaluation-scope", identity)
    return payload


def _signed_manifest(
    payload: dict | None = None,
) -> tuple[EvaluationScopeManifest, Ed25519PrivateKey]:
    key = Ed25519PrivateKey.generate()
    raw = _manifest_payload() if payload is None else payload
    signed = sign_payload("evaluation-scope", raw, key, version="0.3")
    return EvaluationScopeManifest.model_validate(signed), key


def test_v03_canonical_domain_isolated_from_v01() -> None:
    payload = {"value": 1}
    assert canonical_bytes("manifest", payload) == canonical_bytes(
        "manifest", payload, version="0.1"
    )
    assert canonical_bytes(
        "evaluation-scope", payload, version="0.3"
    ) != canonical_bytes("manifest", payload)


def test_scope_member_identity_excludes_content_digest() -> None:
    revision = "a" * 40
    first = ScopeMember.model_validate(
        _member("source_file", "src/widget.py", "first", revision)
    )
    second = ScopeMember.model_validate(
        _member("source_file", "src/widget.py", "second", revision)
    )
    assert first.member_id == second.member_id
    assert first.content_digest != second.content_digest


def test_scope_member_accepts_full_pytest_node_id() -> None:
    member = ScopeMember.model_validate(
        _member(
            "test_case",
            "tests/test_widget.py::TestWidget::test_value[param-一]",
            "test",
            "a" * 40,
        )
    )
    assert "::" in member.locator


@pytest.mark.parametrize(
    "locator",
    (
        "/src/widget.py",
        "../src/widget.py",
        "src\\widget.py",
        "src/widget.py\x00",
        "tests/test_widget.py::test_value\nnext",
    ),
)
def test_scope_member_rejects_unsafe_locator(locator: str) -> None:
    with pytest.raises(ValidationError, match="locator|root|path"):
        ScopeMember.model_validate(
            _member("source_file", locator, "content", "a" * 40)
        )


def test_signed_manifest_round_trips_v03_domain() -> None:
    manifest, key = _signed_manifest()
    assert verify_payload(
        "evaluation-scope",
        manifest.model_dump(mode="json"),
        key.public_key(),
        version="0.3",
    )
    assert not verify_payload(
        "evaluation-scope",
        manifest.model_dump(mode="json"),
        key.public_key(),
    )


def test_manifest_and_draft_share_business_payload() -> None:
    payload = _manifest_payload()
    draft = EvaluationScopeDraft.model_validate(payload)
    manifest, _ = _signed_manifest(payload)
    assert draft.model_dump(mode="json") == manifest.model_dump(
        mode="json", exclude={"digest", "signature_alg", "signer_key_id", "signature"}
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("members", [], "1..4096"),
        ("member_count", 1, "member_count"),
        ("population_digest", "f" * 64, "population_digest"),
        ("required_target_ids", [], "required_target_ids"),
        ("scope_id", "f" * 64, "scope_id"),
    ),
)
def test_manifest_rejects_broken_closed_invariant(
    field: str, value: object, message: str
) -> None:
    payload = _manifest_payload()
    payload[field] = value
    with pytest.raises(ValidationError, match=message):
        _signed_manifest(payload)


def test_manifest_rejects_required_target_outside_population() -> None:
    payload = _manifest_payload()
    payload["required_target_ids"] = ["f" * 64]
    with pytest.raises(ValidationError, match="required_target_ids"):
        _signed_manifest(payload)


def test_manifest_rejects_excluded_member() -> None:
    payload = _manifest_payload()
    payload["excluded_locator_digests"] = [payload["members"][0]["locator_digest"]]
    with pytest.raises(ValidationError, match="excluded"):
        _signed_manifest(payload)


def test_manifest_rejects_cross_revision_member() -> None:
    payload = _manifest_payload()
    payload["members"][0]["source_revision"] = "c" * 40
    with pytest.raises(ValidationError, match="source_revision"):
        _signed_manifest(payload)


def test_scope_only_evaluation_scope_is_signable() -> None:
    key = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="cannot be signed"):
        sign_payload(
            "scope-member", {"member_kind": "source_file"}, key, version="0.3"
        )


def test_deterministic_scope_fixture_is_manager_signed(
    evaluation_scope_v03: EvaluationScopeManifest,
    scope_manager_private_key_v03: Ed25519PrivateKey,
) -> None:
    assert verify_payload(
        "evaluation-scope",
        evaluation_scope_v03.model_dump(mode="json"),
        scope_manager_private_key_v03.public_key(),
        version="0.3",
    )


def test_scope_member_rejects_wrong_locator_digest() -> None:
    payload = _member("source_file", "src/widget.py", "source", "a" * 40)
    payload["locator_digest"] = "f" * 64
    with pytest.raises(ValidationError, match="locator_digest"):
        ScopeMember.model_validate(payload)


def test_manifest_rejects_unsorted_or_duplicate_members() -> None:
    payload = _manifest_payload()
    payload["members"] = list(reversed(payload["members"]))
    with pytest.raises(ValidationError, match="members must be sorted"):
        _signed_manifest(payload)

    payload = _manifest_payload()
    payload["members"].append(copy.deepcopy(payload["members"][0]))
    payload["member_count"] = 3
    with pytest.raises(ValidationError, match="members must be sorted"):
        _signed_manifest(payload)


def test_selector_rejects_unsorted_or_empty_evidence_paths() -> None:
    base = {
        "rule_id": "1" * 64,
        "selector_kind": "explicit",
        "selector_spec_digest": "2" * 64,
        "selector_engine_digest": "3" * 64,
    }
    for paths in ([], ["z.json", "a.json"]):
        with pytest.raises(ValidationError, match="required_evidence_paths"):
            ScopeSelectorRule.model_validate(
                {**base, "required_evidence_paths": paths}
            )


def test_manifest_rejects_invalid_times() -> None:
    payload = _manifest_payload()
    payload["expires_at"] = payload["created_at"]
    with pytest.raises(ValidationError, match="times"):
        _signed_manifest(payload)


def test_manifest_rejects_casefold_locator_collision() -> None:
    payload = _manifest_payload()
    revision = payload["source_revision"]
    payload["members"] = sorted(
        (
            _member("source_file", "src/Widget.py", "first", revision),
            _member("source_file", "src/widget.py", "second", revision),
        ),
        key=lambda item: (
            item["member_kind"],
            item["locator_digest"],
            item["member_id"],
        ),
    )
    payload["member_count"] = 2
    with pytest.raises(ValidationError, match="case-fold"):
        _signed_manifest(payload)


def test_manifest_rejects_more_than_4096_members() -> None:
    payload = _manifest_payload()
    payload["members"] = [payload["members"][0]] * 4097
    payload["member_count"] = 4097
    with pytest.raises(ValidationError, match="1..4096"):
        EvaluationScopeDraft.model_validate(payload)


def test_manifest_rejects_canonical_payload_above_8_mib() -> None:
    payload = _manifest_payload()
    revision = payload["source_revision"]
    padding = "x" * 1900
    members = sorted(
        (
            _member(
                "test_case",
                f"tests/test_widget.py::test_{padding}[{index:04d}]",
                "test",
                revision,
            )
            for index in range(4096)
        ),
        key=lambda item: (
            item["member_kind"],
            item["locator_digest"],
            item["member_id"],
        ),
    )
    member_ids = sorted(member["member_id"] for member in members)
    payload["members"] = members
    payload["member_count"] = len(members)
    payload["population_digest"] = _domain_digest(
        "scope-population",
        [
            {
                "member_id": member["member_id"],
                "member_kind": member["member_kind"],
                "locator_digest": member["locator_digest"],
            }
            for member in members
        ],
    )
    payload["requirement_bindings"] = [
        {
            "requirement_kind": "acceptance_condition",
            "requirement_digest": "8" * 64,
            "member_ids": member_ids,
        }
    ]
    payload["required_target_ids"] = member_ids
    identity = {
        key: value for key, value in payload.items() if key != "scope_id"
    }
    payload["scope_id"] = _domain_digest("evaluation-scope", identity)
    with pytest.raises(ValidationError, match="8 MiB"):
        EvaluationScopeDraft.model_validate(payload)


def test_signing_rejects_unknown_version_or_cross_version_domain() -> None:
    key = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="version|domain"):
        canonical_bytes("manifest", {}, version="9.9")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="cannot be signed"):
        sign_payload("work-order", {}, key, version="0.3")
