#!/usr/bin/env python3
"""Minimal in-process Human Agency Profile v0.1 demonstration.

This example builds, entirely in memory, the smallest realistic agency flow:

1. a signed WorkOrder with the six fixed role key bindings;
2. a WorkOrder-bound HumanAgencyProfileV01 signed by the WorkOrder Acceptor;
3. signature verification and deterministic current-profile resolution;
4. the reserved-vs-delegated determination for one delegated tool
   (`owp.repo_read`) and one reserved tool (`owp.apply_patch`).

It uses only ephemeral Ed25519 keys generated for this run. It never writes a
private-key file, never touches the network, and never writes to a ledger or a
filesystem. It is a protocol example, not a production deployment guide: the
profile expresses an authorization boundary, and is not employee scoring,
performance monitoring, legal-liability transfer, automatic accountability,
fund custody, or compliance certification.

Run:  ./.venv/bin/python examples/human_agency_profile_v01.py
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openworkproof.agency import (
    HumanAgencyProfileV01,
    delegated_action_id,
    human_agency_profile_id,
    reserved_decision_id,
    resolve_current_human_agency_profile,
    verify_human_agency_profile,
)
from openworkproof.agency_policy import (
    AGENCY_ACTION_NOT_DELEGATED,
    AGENCY_HUMAN_DECISION_REQUIRED,
)
from openworkproof.models import WorkOrder
from openworkproof.signing import key_id, sign_payload

# Synthetic, test-only constants. These are NOT real keys, source artifacts, or
# contract identifiers.
_ROLES = ("Maintainer", "Manager", "Developer", "Verifier", "Sidecar", "Acceptor")
_ALL_TOOLS = sorted(
    [
        "owp.activate_root_grant",
        "owp.apply_patch",
        "owp.compose_proof",
        "owp.create_pr_proposal",
        "owp.delegate_grant",
        "owp.repo_read",
        "owp.request_acceptance",
        "owp.request_pr_proposal",
        "owp.revoke_grant",
        "owp.rollback_patch",
        "owp.run_tests",
        "owp.start_retry",
    ],
    key=lambda value: value.encode("utf-8"),
)
_VERIFIER_ARGV = [
    "/opt/venv/bin/python",
    "-I",
    "-m",
    "pytest",
    "-q",
    "-c",
    "/dev/null",
    "--rootdir=/fixed-tests",
    "--confcutdir=/fixed-tests",
    "/fixed-tests/verifier_test.py",
]
_FIXED_ENV = {
    "HOME": "/nonexistent",
    "LC_ALL": "C.UTF-8",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    "TZ": "UTC",
}
_SHA256_A = "a" * 64
_SHA256_B = "b" * 64
_IMAGE_A = f"sha256:{_SHA256_A}"
_IMAGE_B = f"sha256:{_SHA256_B}"

# Profile and WorkOrder time windows (UTC).
_PROFILE_ISSUED_AT = "2026-01-01T00:00:00Z"
_PROFILE_VALID_FROM = "2026-01-01T00:00:01Z"
_PROFILE_EXPIRES_AT = "2026-01-01T23:59:59Z"
_WORK_ORDER_ISSUED_AT = "2026-01-01T00:00:00Z"
_WORK_ORDER_DEADLINE = "2026-01-02T00:00:00Z"


def _jcs_digest(value: object) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _generate_ephemeral_keys() -> dict[str, tuple[Ed25519PrivateKey, dict[str, str]]]:
    """Generate fresh, per-run Ed25519 keys for the six fixed roles (no files)."""

    result: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]] = {}
    for role in _ROLES:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        raw = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        result[role] = (
            private_key,
            {
                "role": role,
                "subject_id": role.lower(),
                "key_id": key_id(public_key),
                "public_key_b64url": _b64url(raw),
            },
        )
    return result


def _evidence_artifact(
    purpose: str,
    ordinal: int,
    media_type: str,
    dimension: str,
    suffix: str,
) -> dict[str, object]:
    stem = purpose.replace("_", "-")
    return {
        "name": f"{stem}-{ordinal}",
        "path": f"{stem}/{ordinal:02d}.{suffix}",
        "media_type": media_type,
        "max_size_bytes": 65536,
        "evidence_dimension": dimension,
        "purpose": purpose,
        "ordinal": ordinal,
    }


def _make_test_profile(mode: str, *, fixed: bool) -> dict[str, object]:
    command = {
        "argv": _VERIFIER_ARGV,
        "working_directory": "/workspace",
        "env": dict(_FIXED_ENV),
    }
    fixed_source = (
        {
            "path": "fixed-tests/verifier_test.py",
            "media_type": "text/x-python",
            "sha256": _SHA256_B,
            "size_bytes": 1024,
        }
        if fixed
        else None
    )
    return {
        "test_mode": mode,
        "command": command,
        "command_digest": _jcs_digest(
            {"domain": "openworkproof/test-command/v0.1", "command": command}
        ),
        "expected_exit_code": 0,
        "container_image_digest": _IMAGE_A,
        "fixed_test_source": fixed_source,
        "fixed_test_source_digest": _SHA256_B if fixed else None,
    }


def _tests_passed_predicate(verifier_profile: dict[str, object]) -> dict[str, object]:
    arguments = {
        "test_mode": "verifier",
        "command_digest": verifier_profile["command_digest"],
        "expected_exit_code": verifier_profile["expected_exit_code"],
        "fixed_test_source_digest": verifier_profile["fixed_test_source_digest"],
    }
    body = {
        "name": "tests_passed",
        "version": "0.1",
        "applies_to_tools": ["owp.run_tests"],
        "arguments": arguments,
    }
    return {
        "predicate_id": _jcs_digest(
            {"domain": "openworkproof/predicate-id/v0.1", **body}
        ),
        **body,
    }


def _build_signed_work_order(
    keys: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> WorkOrder:
    """Build and sign a minimal valid WorkOrder with the six fixed roles."""

    bindings = [dict(keys[role][1]) for role in _ROLES]
    maintainer = bindings[0]
    manager = bindings[1]
    acceptor = bindings[5]

    verifier_profile = _make_test_profile("verifier", fixed=True)
    replay_profile = {
        "schema_version": "openworkproof-replay-profile/0.1",
        "patch_profile_id": "openworkproof/canonical-text-patch/0.1",
        "object_format": "sha1",
        "source_artifact_sha256": _SHA256_A,
        "trusted_helper_image_digest": _IMAGE_B,
        "author_name": "OpenWorkProof Sidecar",
        "author_email": "sidecar@openworkproof.invalid",
        "commit_message_prefix": "OpenWorkProof patch ",
        "timestamp_rule": "receipt-occurred-at-utc-seconds",
        "worktree_profile": "linux-posix-case-sensitive-v0.1",
    }
    gate_body = {
        "tool_name": "owp.create_pr_proposal",
        "required_role": "Maintainer",
        "max_validity_seconds": 3600,
        "scope_schema": "openworkproof/pr-proposal-scope/0.1",
    }
    candidate = {
        "work_order_id": "0" * 64,
        "protocol_version": "0.1",
        "issuer_id": maintainer["subject_id"],
        "acceptor_key_ids": [acceptor["key_id"]],
        "objective": "Demonstrate a human agency authorization boundary.",
        "preconditions": [],
        "invariants": [],
        "repository": "example/openworkproof",
        "branch": "main",
        "allowed_read_roots": ["src", "tests"],
        "allowed_write_roots": ["src"],
        "source_commit": "1" * 40,
        "source_artifact": {
            "path": "source/base.owpsrc",
            "media_type": "application/vnd.openworkproof.source+zip",
            "sha256": _SHA256_A,
            "size_bytes": 1024,
        },
        "patch_profile_id": "openworkproof/canonical-text-patch/0.1",
        "replay_profile": replay_profile,
        "replay_profile_digest": _jcs_digest(
            {"domain": "openworkproof/replay-profile/v0.1", "profile": replay_profile}
        ),
        "test_profiles": [verifier_profile],
        "allowed_tools": list(_ALL_TOOLS),
        "quota_ceiling": {"tool_calls": 100, "repair_rounds": 1},
        "deadline": _WORK_ORDER_DEADLINE,
        "retention_until": "2026-01-02T01:00:00Z",
        "acceptance_criteria": "The verifier test exits with status zero.",
        "postconditions": [_tests_passed_predicate(verifier_profile)],
        "approval_gates": [
            {
                "gate_id": _jcs_digest(
                    {"domain": "openworkproof/approval-gate-id/v0.1", **gate_body}
                ),
                **gate_body,
            }
        ],
        "required_evidence_dimensions": [
            "authority",
            "scope",
            "execution",
            "result",
        ],
        "independence_policy": "disclose_only",
        "evidence_policy": {
            "evidence_root": "evidence",
            "redaction_policy_id": "owp-public-evidence-v0.1",
            "artifacts": [
                _evidence_artifact(
                    "patch_input", 1, "text/x-diff", "scope", "diff"
                ),
                _evidence_artifact(
                    "patch_result", 1, "application/json", "execution", "json"
                ),
                _evidence_artifact(
                    "patch_denial_audit", 1, "text/x-diff", "none", "diff"
                ),
                _evidence_artifact(
                    "patch_denial_audit", 2, "text/x-diff", "none", "diff"
                ),
                _evidence_artifact(
                    "verifier_result", 1, "application/json", "result", "json"
                ),
            ],
        },
        "root_grant_template": {
            "grant_id": "e" * 64,
            "parent_grant_id": None,
            "issuer_key_id": maintainer["key_id"],
            "subject_agent_id": manager["subject_id"],
            "subject_key_id": manager["key_id"],
            "allowed_tools": list(_ALL_TOOLS),
            "allowed_read_roots": ["src", "tests"],
            "allowed_write_roots": ["src"],
            "usage_mode": "metered",
            "quota": {"tool_calls": 50, "repair_rounds": 1},
            "valid_from": _PROFILE_VALID_FROM,
            "expires_at": _WORK_ORDER_DEADLINE,
            "may_delegate": True,
            "issued_at": _WORK_ORDER_ISSUED_AT,
        },
        "key_bindings": bindings,
        "issued_at": _WORK_ORDER_ISSUED_AT,
    }
    return WorkOrder.model_validate(
        sign_payload("work-order", candidate, keys["Maintainer"][0])
    )


def _delegated(tool: str) -> dict[str, str]:
    body = {"tool_name": tool, "autonomy": "delegated"}
    return {"action_id": delegated_action_id(body), **body}


def _reserved(kind: str, blocked: tuple[str, ...]) -> dict[str, object]:
    body = {
        "decision_kind": kind,
        "blocked_tools": list(blocked),
        "required_role": "Acceptor",
    }
    return {"decision_id": reserved_decision_id(body), **body}


def _build_signed_profile(
    work_order: WorkOrder,
    acceptor_private_key: Ed25519PrivateKey,
) -> HumanAgencyProfileV01:
    """Build an Acceptor-signed profile: repo_read delegated, apply_patch reserved."""

    payload = {
        "schema_version": "openworkproof-human-agency-profile/0.1",
        "work_order_digest": work_order.digest,
        "delegated_actions": [_delegated("owp.repo_read")],
        "reserved_decisions": [
            _reserved("scope_or_criteria_change", ("owp.apply_patch",))
        ],
        "escalation_conditions": [{"condition_code": "reserved_decision_requested"}],
        "revocation_and_appeal": {
            "revocation_mode": "acceptor_signed_transition",
            "appeal_mode": "signed_request_then_acceptor_decision",
            "appeal_roles": ["Developer", "Manager", "Verifier"],
        },
        "valid_from": _PROFILE_VALID_FROM,
        "expires_at": _PROFILE_EXPIRES_AT,
        "issued_at": _PROFILE_ISSUED_AT,
        "nonce": "f" * 64,
    }
    payload["profile_id"] = human_agency_profile_id(payload)
    return HumanAgencyProfileV01.model_validate(
        sign_payload("human-agency-profile", payload, acceptor_private_key)
    )


def _classify(
    profile: HumanAgencyProfileV01, tool_name: str
) -> tuple[str, str | None]:
    """Return (decision, error_code) using the same boundary as the policy layer."""

    delegated = {action.tool_name for action in profile.delegated_actions}
    reserved = {
        tool
        for decision in profile.reserved_decisions
        for tool in decision.blocked_tools
    }
    if tool_name in reserved:
        return ("reserved", AGENCY_HUMAN_DECISION_REQUIRED)
    if tool_name in delegated:
        return ("delegated", None)
    return ("not_delegated", AGENCY_ACTION_NOT_DELEGATED)


def main() -> int:
    keys = _generate_ephemeral_keys()
    work_order = _build_signed_work_order(keys)
    profile = _build_signed_profile(work_order, keys["Acceptor"][0])

    # Signature verification binds the profile to the exact WorkOrder Acceptor.
    verified = verify_human_agency_profile(profile, work_order)

    # Deterministic current-profile resolution (single genesis, no transitions).
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    resolved = resolve_current_human_agency_profile(
        work_order, (profile,), (), now=now
    )

    delegated_decision = _classify(profile, "owp.repo_read")
    reserved_decision = _classify(profile, "owp.apply_patch")

    # Self-check: the demonstration must actually hold before it prints.
    assert verified is True
    assert resolved.status == "active"
    assert resolved.current_profile is not None
    assert delegated_decision == ("delegated", None)
    assert reserved_decision == ("reserved", AGENCY_HUMAN_DECISION_REQUIRED)

    print("Human Agency Profile v0.1 — in-process demonstration")
    print("=" * 60)
    print(f"work_order_digest : {work_order.digest}")
    print(f"profile_id        : {profile.profile_id}")
    print(f"profile verified  : {verified}")
    print(f"resolved status   : {resolved.status}")
    print("-" * 60)
    print(
        f"owp.repo_read     : {delegated_decision[0]} -> "
        f"{delegated_decision[1] or 'allowed'}"
    )
    print(
        f"owp.apply_patch   : {reserved_decision[0]} -> "
        f"{reserved_decision[1]}"
    )
    print("-" * 60)
    print(
        "boundary: verifiable authorization / reserved-decision boundary; "
        "not employee scoring, performance monitoring, legal-liability transfer, "
        "automatic accountability, fund custody, or compliance certification."
    )
    print(
        "boundary: this example writes no private-key file, touches no network, "
        "and performs no ledger side effects."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
