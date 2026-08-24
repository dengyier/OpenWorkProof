"""Independent human agency (0.1) schema contract constraint tests.

These RED tests validate instance payloads with ``jsonschema.Draft202012Validator``
directly -- never Pydantic -- against the *hardened* generated schemas. They prove
that obviously malformed agency objects (bad digest/key/signature/time, revoked
transitions that name a replacement, superseded transitions missing one, empty or
over-large reserved sets, wrong appeal roles, and expressible duplicates) are now
rejected at the JSON Schema layer, while legitimate packaged instances still pass.

The final test documents the honest boundary: a payload can be structurally valid
yet semantically invalid (content-derived id mismatch), so OpenWorkProof semantic
validation remains mandatory after JSON Schema validation.
"""

from __future__ import annotations

import copy
import json
from importlib import resources
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from openworkproof.agency import human_agency_profile_id


_OBJECT_PATHS = {
    "human-agency-profile": "human-agency-profile.schema.json",
    "agency-profile-transition": "agency-profile-transition.schema.json",
    "agency-appeal": "agency-appeal.schema.json",
}


def _hex64(marker: str) -> str:
    return marker * 64


def _schema(object_type: str) -> dict[str, Any]:
    raw = resources.files("openworkproof").joinpath(
        "schemas", "agency-v0.1", _OBJECT_PATHS[object_type]
    ).read_bytes()
    return json.loads(raw)


def _errors(object_type: str, instance: dict[str, Any]) -> list[Any]:
    validator = Draft202012Validator(_schema(object_type))
    return list(validator.iter_errors(instance))


def _valid_profile() -> dict[str, Any]:
    return {
        "schema_version": "openworkproof-human-agency-profile/0.1",
        "digest": _hex64("a"),
        "signature_alg": "Ed25519",
        "signer_key_id": f"ed25519:{_hex64('b')}",
        "signature": "A" * 86,
        "profile_id": _hex64("c"),
        "work_order_digest": _hex64("d"),
        "delegated_actions": [
            {
                "action_id": _hex64("e"),
                "tool_name": "owp.repo_read",
                "autonomy": "delegated",
            }
        ],
        "reserved_decisions": [],
        "escalation_conditions": [],
        "revocation_and_appeal": {
            "revocation_mode": "acceptor_signed_transition",
            "appeal_mode": "signed_request_then_acceptor_decision",
            "appeal_roles": ["Developer", "Manager", "Verifier"],
        },
        "valid_from": "2026-01-01T00:00:01Z",
        "expires_at": "2026-01-01T23:59:59Z",
        "issued_at": "2026-01-01T00:00:00Z",
        "nonce": _hex64("f"),
    }


def _valid_reserved_only_profile() -> dict[str, Any]:
    profile = _valid_profile()
    profile["delegated_actions"] = []
    profile["reserved_decisions"] = [
        {
            "decision_id": _hex64("1"),
            "decision_kind": "acceptance",
            "blocked_tools": ["owp.apply_patch"],
            "required_role": "Acceptor",
        }
    ]
    return profile


def _valid_revoked_transition() -> dict[str, Any]:
    return {
        "schema_version": "openworkproof-agency-profile-transition/0.1",
        "digest": _hex64("a"),
        "signature_alg": "Ed25519",
        "signer_key_id": f"ed25519:{_hex64('b')}",
        "signature": "A" * 86,
        "transition_id": _hex64("c"),
        "work_order_digest": _hex64("d"),
        "target_profile_id": _hex64("e"),
        "target_profile_digest": _hex64("f"),
        "transition": "revoked",
        "replacement_profile_id": None,
        "replacement_profile_digest": None,
        "reason_code": "human_withdrawal",
        "transitioned_at": "2026-01-01T01:00:00Z",
        "nonce": _hex64("0"),
    }


def _valid_superseded_transition() -> dict[str, Any]:
    transition = _valid_revoked_transition()
    transition["transition"] = "superseded"
    transition["replacement_profile_id"] = _hex64("1")
    transition["replacement_profile_digest"] = _hex64("2")
    return transition


def _valid_appeal() -> dict[str, Any]:
    return {
        "schema_version": "openworkproof-agency-appeal/0.1",
        "digest": _hex64("a"),
        "signature_alg": "Ed25519",
        "signer_key_id": f"ed25519:{_hex64('b')}",
        "signature": "A" * 86,
        "appeal_id": _hex64("c"),
        "work_order_digest": _hex64("d"),
        "profile_id": _hex64("e"),
        "profile_digest": _hex64("f"),
        "appellant_role": "Manager",
        "appellant_subject_id": "manager",
        "requested_change_digest": _hex64("0"),
        "reason_code": "task_blocked",
        "created_at": "2026-01-01T01:05:00Z",
        "nonce": _hex64("1"),
    }


def _mutate(instance: dict[str, Any], field: str, value: Any) -> dict[str, Any]:
    out = copy.deepcopy(instance)
    out[field] = value
    return out


# --------------------------------------------------------------------------- #
# 1. the hardened schemas are themselves valid Draft 2020-12 schemas
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("object_type", sorted(_OBJECT_PATHS))
def test_hardened_schemas_are_valid_draft202012(object_type: str) -> None:
    Draft202012Validator.check_schema(_schema(object_type))


# --------------------------------------------------------------------------- #
# 2. legitimate instances still validate
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("object_type", "instance"),
    [
        ("human-agency-profile", _valid_profile()),
        ("human-agency-profile", _valid_reserved_only_profile()),
        ("agency-profile-transition", _valid_revoked_transition()),
        ("agency-profile-transition", _valid_superseded_transition()),
        ("agency-appeal", _valid_appeal()),
    ],
)
def test_legitimate_instances_pass(object_type: str, instance: dict) -> None:
    assert _errors(object_type, instance) == []


# --------------------------------------------------------------------------- #
# 3. malicious transition fields produce structural errors
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("digest", "not-a-digest"),
        ("signer_key_id", "not-a-key-id"),
        ("signature", "short"),
        ("signature", "A" * 85),
        ("transitioned_at", "2026-01-01T01:00:00+00:00"),
        ("replacement_profile_id", "not-a-digest"),
    ],
)
def test_malicious_transition_fields_are_rejected(
    field: str, value: Any
) -> None:
    instance = _mutate(_valid_superseded_transition(), field, value)
    assert _errors("agency-profile-transition", instance) != []


def test_revoked_transition_with_replacement_is_rejected() -> None:
    instance = _valid_revoked_transition()
    instance["replacement_profile_id"] = _hex64("3")
    instance["replacement_profile_digest"] = _hex64("4")
    assert _errors("agency-profile-transition", instance) != []


def test_superseded_transition_without_replacement_is_rejected() -> None:
    instance = _valid_superseded_transition()
    instance["replacement_profile_id"] = None
    instance["replacement_profile_digest"] = None
    assert _errors("agency-profile-transition", instance) != []


# --------------------------------------------------------------------------- #
# 4. bad digest / key / signature / time are rejected category by category
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("object_type", "instance", "field", "value"),
    [
        ("human-agency-profile", _valid_profile(), "digest", "not-a-digest"),
        ("agency-profile-transition", _valid_superseded_transition(),
         "digest", "not-a-digest"),
        ("agency-appeal", _valid_appeal(), "digest", "not-a-digest"),
        ("human-agency-profile", _valid_profile(), "signer_key_id", "bad-key"),
        ("agency-profile-transition", _valid_superseded_transition(),
         "signer_key_id", "bad-key"),
        ("agency-appeal", _valid_appeal(), "signer_key_id", "bad-key"),
        ("human-agency-profile", _valid_profile(), "signature", "A" * 84),
        ("agency-profile-transition", _valid_superseded_transition(),
         "signature", "not base64url!!"),
        ("agency-appeal", _valid_appeal(), "signature", "A" * 86 + "="),
        ("human-agency-profile", _valid_profile(), "valid_from",
         "2026-01-01T00:00:01Z "),
        ("agency-profile-transition", _valid_superseded_transition(),
         "transitioned_at", "2026/01/01T01:00:00Z"),
        ("agency-appeal", _valid_appeal(), "created_at",
         "2026-01-01T01:05:00.000Z"),
    ],
)
def test_bad_digest_key_signature_time_rejected(
    object_type: str, instance: dict, field: str, value: Any
) -> None:
    assert _errors(object_type, _mutate(instance, field, value)) != []


# --------------------------------------------------------------------------- #
# 5. profile structural invariants
# --------------------------------------------------------------------------- #


def test_profile_with_both_actions_and_decisions_empty_is_rejected() -> None:
    instance = _valid_profile()
    instance["delegated_actions"] = []
    instance["reserved_decisions"] = []
    assert _errors("human-agency-profile", instance) != []


def test_reserved_decisions_over_five_is_rejected() -> None:
    instance = _valid_profile()
    instance["delegated_actions"] = []
    tools = [
        "owp.activate_root_grant",
        "owp.apply_patch",
        "owp.compose_proof",
        "owp.create_pr_proposal",
        "owp.delegate_grant",
        "owp.repo_read",
    ]
    kinds = [
        "scope_or_criteria_change",
        "external_publication",
        "external_communication",
        "acceptance",
        "payment_or_settlement",
        "scope_or_criteria_change",
    ]
    instance["reserved_decisions"] = [
        {
            "decision_id": _hex64(str(index)),
            "decision_kind": kind,
            "blocked_tools": [tool],
            "required_role": "Acceptor",
        }
        for index, (kind, tool) in enumerate(zip(kinds, tools))
    ]
    assert _errors("human-agency-profile", instance) != []


@pytest.mark.parametrize(
    "appeal_roles",
    [
        ["Developer", "Manager", "Acceptor"],
        ["Manager", "Developer", "Verifier"],
        ["Developer", "Manager"],
        ["Developer", "Manager", "Verifier", "Developer"],
    ],
)
def test_appeal_roles_wrong_role_or_order_rejected(
    appeal_roles: list[str],
) -> None:
    instance = _valid_profile()
    instance["revocation_and_appeal"]["appeal_roles"] = appeal_roles
    assert _errors("human-agency-profile", instance) != []


# --------------------------------------------------------------------------- #
# 6. expressible duplicate items are rejected
# --------------------------------------------------------------------------- #


def test_duplicate_escalation_conditions_rejected() -> None:
    instance = _valid_profile()
    instance["escalation_conditions"] = [
        {"condition_code": "reserved_decision_requested"},
        {"condition_code": "reserved_decision_requested"},
    ]
    assert _errors("human-agency-profile", instance) != []


def test_duplicate_blocked_tools_rejected() -> None:
    instance = _valid_profile()
    instance["delegated_actions"] = []
    instance["reserved_decisions"] = [
        {
            "decision_id": _hex64("1"),
            "decision_kind": "acceptance",
            "blocked_tools": ["owp.apply_patch", "owp.apply_patch"],
            "required_role": "Acceptor",
        }
    ]
    assert _errors("human-agency-profile", instance) != []


# --------------------------------------------------------------------------- #
# 7. structural pass does not imply semantic validity
# --------------------------------------------------------------------------- #


def test_schema_passes_but_semantic_validation_rejects() -> None:
    """A content-derived id mismatch is invisible to JSON Schema.

    The instance keeps a well-formed (64-hex) ``profile_id`` but it no longer
    equals the canonical content-derived id, so the JSON Schema accepts it while
    OpenWorkProof semantic validation must still reject it.
    """

    instance = _valid_profile()
    instance["profile_id"] = _hex64("9")
    assert _errors("human-agency-profile", instance) == []
    assert human_agency_profile_id(instance) != instance["profile_id"]
