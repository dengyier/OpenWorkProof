"""Deterministic protocol fixtures.

All constants in this module are test-only values.  They are deliberately
synthetic and MUST NOT be used as real OpenWorkProof keys, signatures, source
artifacts, or contract identifiers.
"""

from __future__ import annotations

import base64
import copy
import hashlib
from datetime import datetime, timezone
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from openworkproof.models import (
    ACTION_RECEIPT_ADAPTER,
    ActionReceipt,
    AcceptanceReceipt,
    ActionBindingManifest,
    AgentRequestV04,
    AuthorityCheckpoint,
    BindingDecision,
    CapabilityGrant,
    CommitmentAnchor,
    EvaluationScopeManifest,
    JudgmentCommitment,
    PolicyAnchor,
    ScopeMember,
    SubjectClaim,
    VerificationProfileV02,
    WorkOrder,
)
from openworkproof.signing import canonical_bytes, key_id, sign_payload


WORK_ORDER_ID = "0" * 64
SOURCE_COMMIT = "1" * 40
SHA256_A = "a" * 64
SHA256_B = "b" * 64
SHA256_C = "c" * 64
SHA256_D = "d" * 64
SHA256_E = "e" * 64
IMAGE_A = f"sha256:{SHA256_A}"
IMAGE_B = f"sha256:{SHA256_B}"
SIGNATURE = base64.urlsafe_b64encode(b"\x00" * 64).decode("ascii").rstrip("=")

VERIFIER_ARGV = [
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

FIXED_ENV = {
    "HOME": "/nonexistent",
    "LC_ALL": "C.UTF-8",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    "TZ": "UTC",
}

ALL_TOOLS = sorted(
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


def jcs_digest(value: Any) -> str:
    """Return the test-side RFC 8785 SHA-256 digest."""

    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def deterministic_key_binding(role: str, subject_id: str, byte: int) -> dict[str, str]:
    raw = bytes([byte]) * 32
    public_key = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return {
        "role": role,
        "subject_id": subject_id,
        "key_id": f"ed25519:{hashlib.sha256(raw).hexdigest()}",
        "public_key_b64url": public_key,
    }


@pytest.fixture
def key_bindings() -> list[dict[str, str]]:
    return [
        deterministic_key_binding("Maintainer", "maintainer", 1),
        deterministic_key_binding("Manager", "manager", 2),
        deterministic_key_binding("Developer", "developer", 3),
        deterministic_key_binding("Verifier", "verifier", 4),
        deterministic_key_binding("Sidecar", "sidecar", 5),
        deterministic_key_binding("Acceptor", "acceptor-local", 6),
    ]


def predicate(
    name: str,
    applies_to_tools: list[str],
    arguments: dict[str, Any],
    *,
    version: str = "0.1",
) -> dict[str, Any]:
    body = {
        "name": name,
        "version": version,
        "applies_to_tools": applies_to_tools,
        "arguments": arguments,
    }
    return {
        "predicate_id": jcs_digest(
            {"domain": "openworkproof/predicate-id/v0.1", **body}
        ),
        **body,
    }


def make_test_command(argv: list[str]) -> dict[str, Any]:
    return {
        "argv": argv,
        "working_directory": "/workspace",
        "env": copy.deepcopy(FIXED_ENV),
    }


def make_test_profile(
    mode: str,
    *,
    fixed: bool,
    argv: list[str] | None = None,
) -> dict[str, Any]:
    command = make_test_command(argv or VERIFIER_ARGV)
    fixed_source = (
        {
            "path": "fixed-tests/verifier_test.py",
            "media_type": "text/x-python",
            "sha256": SHA256_B,
            "size_bytes": 1024,
        }
        if fixed
        else None
    )
    return {
        "test_mode": mode,
        "command": command,
        "command_digest": jcs_digest(
            {"domain": "openworkproof/test-command/v0.1", "command": command}
        ),
        "expected_exit_code": 0,
        "container_image_digest": IMAGE_A,
        "fixed_test_source": fixed_source,
        "fixed_test_source_digest": SHA256_B if fixed else None,
    }


def evidence_artifact(
    purpose: str,
    ordinal: int,
    *,
    media_type: str,
    dimension: str,
    suffix: str,
    max_size_bytes: int = 65536,
) -> dict[str, Any]:
    stem = purpose.replace("_", "-")
    return {
        "name": f"{stem}-{ordinal}",
        "path": f"{stem}/{ordinal:02d}.{suffix}",
        "media_type": media_type,
        "max_size_bytes": max_size_bytes,
        "evidence_dimension": dimension,
        "purpose": purpose,
        "ordinal": ordinal,
    }


@pytest.fixture
def demo_evidence_artifacts() -> list[dict[str, Any]]:
    # Exact nine-slot first-Demo inventory from the frozen preliminary design.
    return [
        evidence_artifact(
            "patch_input",
            1,
            media_type="text/x-diff",
            dimension="scope",
            suffix="diff",
        ),
        evidence_artifact(
            "patch_input",
            2,
            media_type="text/x-diff",
            dimension="scope",
            suffix="diff",
        ),
        evidence_artifact(
            "patch_result",
            1,
            media_type="application/json",
            dimension="execution",
            suffix="json",
        ),
        evidence_artifact(
            "patch_result",
            2,
            media_type="application/json",
            dimension="execution",
            suffix="json",
        ),
        evidence_artifact(
            "patch_denial_audit",
            1,
            media_type="text/x-diff",
            dimension="none",
            suffix="diff",
        ),
        evidence_artifact(
            "patch_denial_audit",
            2,
            media_type="text/x-diff",
            dimension="none",
            suffix="diff",
        ),
        evidence_artifact(
            "verifier_result",
            1,
            media_type="application/json",
            dimension="result",
            suffix="json",
        ),
        evidence_artifact(
            "verifier_result",
            2,
            media_type="application/json",
            dimension="result",
            suffix="json",
        ),
        evidence_artifact(
            "verifier_independent_result",
            1,
            media_type="application/json",
            dimension="independent_result",
            suffix="json",
        ),
    ]


@pytest.fixture
def work_order_dict(
    key_bindings: list[dict[str, str]],
    demo_evidence_artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    verifier_profile = make_test_profile("verifier", fixed=True)

    preconditions = [
        predicate(
            "path_allowed",
            ["owp.apply_patch", "owp.repo_read"],
            {"allowed_roots": ["src", "tests"]},
        ),
        predicate(
            "quota_remaining",
            ["owp.apply_patch", "owp.run_tests"],
            {"metric": "tool_calls", "amount": 1},
        ),
        predicate(
            "tool_allowed",
            [
                "owp.apply_patch",
                "owp.compose_proof",
                "owp.create_pr_proposal",
                "owp.repo_read",
                "owp.run_tests",
            ],
            {
                "allowed_tools": [
                    "owp.apply_patch",
                    "owp.compose_proof",
                    "owp.create_pr_proposal",
                    "owp.repo_read",
                    "owp.run_tests",
                ],
                "tool_name": "owp.run_tests",
            },
        ),
    ]
    invariants = [
        predicate(
            "path_allowed",
            ["owp.apply_patch"],
            {"allowed_roots": ["src"]},
        )
    ]
    postconditions = [
        predicate(
            "tests_passed",
            ["owp.run_tests"],
            {
                "test_mode": "verifier",
                "command_digest": verifier_profile["command_digest"],
                "expected_exit_code": verifier_profile["expected_exit_code"],
                "fixed_test_source_digest": verifier_profile[
                    "fixed_test_source_digest"
                ],
            },
        )
    ]
    for conditions in (preconditions, invariants, postconditions):
        conditions.sort(key=lambda item: item["predicate_id"])

    replay_profile = {
        "schema_version": "openworkproof-replay-profile/0.1",
        "patch_profile_id": "openworkproof/canonical-text-patch/0.1",
        "object_format": "sha1",
        "source_artifact_sha256": SHA256_A,
        "trusted_helper_image_digest": IMAGE_B,
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
    root_grant_template = {
        "grant_id": SHA256_E,
        "parent_grant_id": None,
        "issuer_key_id": key_bindings[0]["key_id"],
        "subject_agent_id": key_bindings[1]["subject_id"],
        "subject_key_id": key_bindings[1]["key_id"],
        "allowed_tools": copy.deepcopy(ALL_TOOLS),
        "allowed_read_roots": ["src", "tests"],
        "allowed_write_roots": ["src"],
        "usage_mode": "metered",
        "quota": {"tool_calls": 50, "repair_rounds": 1},
        "valid_from": "2026-01-01T00:00:01Z",
        "expires_at": "2026-01-02T00:00:00Z",
        "may_delegate": True,
        "issued_at": "2026-01-01T00:00:00Z",
    }
    return {
        "work_order_id": WORK_ORDER_ID,
        "protocol_version": "0.1",
        "issuer_id": key_bindings[0]["subject_id"],
        "signer_key_id": key_bindings[0]["key_id"],
        "acceptor_key_ids": [key_bindings[5]["key_id"]],
        "objective": "Apply a deterministic patch and verify it.",
        "preconditions": preconditions,
        "invariants": invariants,
        "repository": "example/openworkproof",
        "branch": "main",
        "allowed_read_roots": ["src", "tests"],
        "allowed_write_roots": ["src"],
        "source_commit": SOURCE_COMMIT,
        "source_artifact": {
            "path": "source/base.owpsrc",
            "media_type": "application/vnd.openworkproof.source+zip",
            "sha256": SHA256_A,
            "size_bytes": 1024,
        },
        "patch_profile_id": "openworkproof/canonical-text-patch/0.1",
        "replay_profile": replay_profile,
        "replay_profile_digest": jcs_digest(
            {
                "domain": "openworkproof/replay-profile/v0.1",
                "profile": replay_profile,
            }
        ),
        "test_profiles": [verifier_profile],
        "allowed_tools": copy.deepcopy(ALL_TOOLS),
        "quota_ceiling": {"tool_calls": 100, "repair_rounds": 1},
        "deadline": "2026-01-02T00:00:00Z",
        "retention_until": "2026-01-02T01:00:00Z",
        "acceptance_criteria": "The fixed verifier exits with status zero.",
        "postconditions": postconditions,
        "approval_gates": [
            {
                "gate_id": jcs_digest(
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
            "independent_result",
        ],
        "independence_policy": "independent_test_source_required",
        "evidence_policy": {
            "evidence_root": "evidence",
            "redaction_policy_id": "owp-public-evidence-v0.1",
            "artifacts": copy.deepcopy(demo_evidence_artifacts),
        },
        "root_grant_template": root_grant_template,
        "key_bindings": copy.deepcopy(key_bindings),
        "issued_at": "2026-01-01T00:00:00Z",
        "digest": SHA256_C,
        "signature_alg": "Ed25519",
        "signature": SIGNATURE,
    }


@pytest.fixture
def root_grant_dict(
    work_order_dict: dict[str, Any],
) -> dict[str, Any]:
    template = copy.deepcopy(work_order_dict["root_grant_template"])
    return {
        "grant_id": template["grant_id"],
        "work_order_digest": work_order_dict["digest"],
        "parent_grant_id": template["parent_grant_id"],
        "issuer_key_id": template["issuer_key_id"],
        "subject_agent_id": template["subject_agent_id"],
        "subject_key_id": template["subject_key_id"],
        "allowed_tools": template["allowed_tools"],
        "allowed_read_roots": template["allowed_read_roots"],
        "allowed_write_roots": template["allowed_write_roots"],
        "usage_mode": template["usage_mode"],
        "quota": template["quota"],
        "valid_from": template["valid_from"],
        "expires_at": template["expires_at"],
        "may_delegate": template["may_delegate"],
        "issued_at": template["issued_at"],
        "digest": SHA256_D,
        "signature_alg": "Ed25519",
        "signer_key_id": template["issuer_key_id"],
        "signature": SIGNATURE,
    }


@pytest.fixture
def child_grant_dict(
    key_bindings: list[dict[str, str]],
    work_order_dict: dict[str, Any],
    root_grant_dict: dict[str, Any],
) -> dict[str, Any]:
    return {
        "grant_id": "f" * 64,
        "work_order_digest": work_order_dict["digest"],
        "parent_grant_id": root_grant_dict["grant_id"],
        "issuer_key_id": key_bindings[1]["key_id"],
        "subject_agent_id": key_bindings[2]["subject_id"],
        "subject_key_id": key_bindings[2]["key_id"],
        "allowed_tools": sorted(
            [
                "owp.apply_patch",
                "owp.repo_read",
                "owp.rollback_patch",
                "owp.run_tests",
            ]
        ),
        "allowed_read_roots": ["src", "tests"],
        "allowed_write_roots": ["src"],
        "usage_mode": "metered",
        "quota": {"tool_calls": 10, "repair_rounds": 0},
        "valid_from": "2026-01-01T00:00:02Z",
        "expires_at": "2026-01-02T00:00:00Z",
        "may_delegate": False,
        "issued_at": "2026-01-01T00:00:01Z",
        "digest": "9" * 64,
        "signature_alg": "Ed25519",
        "signer_key_id": key_bindings[1]["key_id"],
        "signature": SIGNATURE,
    }


EPHEMERAL_ROLES = (
    "Maintainer",
    "Manager",
    "Developer",
    "Verifier",
    "Sidecar",
    "Acceptor",
)


def _public_key_b64url(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


@pytest.fixture
def ephemeral_role_keys(
) -> dict[str, tuple[Ed25519PrivateKey, dict[str, str]]]:
    result: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]] = {}
    for role in EPHEMERAL_ROLES:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        result[role] = (
            private_key,
            {
                "role": role,
                "subject_id": role.lower(),
                "key_id": key_id(public_key),
                "public_key_b64url": _public_key_b64url(public_key),
            },
        )
    return result


@pytest.fixture
def signed_work_order(
    work_order_dict: dict[str, Any],
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> WorkOrder:
    candidate = copy.deepcopy(work_order_dict)
    bindings = [
        copy.deepcopy(ephemeral_role_keys[role][1])
        for role in EPHEMERAL_ROLES
    ]
    maintainer = bindings[0]
    manager = bindings[1]
    acceptor = bindings[5]
    candidate["key_bindings"] = bindings
    candidate["issuer_id"] = maintainer["subject_id"]
    candidate["signer_key_id"] = maintainer["key_id"]
    candidate["acceptor_key_ids"] = [acceptor["key_id"]]
    candidate["root_grant_template"]["issuer_key_id"] = maintainer["key_id"]
    candidate["root_grant_template"]["subject_agent_id"] = manager["subject_id"]
    candidate["root_grant_template"]["subject_key_id"] = manager["key_id"]
    candidate["test_profiles"].insert(
        0,
        make_test_profile("developer", fixed=False),
    )
    candidate["evidence_policy"]["artifacts"].insert(
        6,
        evidence_artifact(
            "developer_test_result",
            1,
            media_type="application/json",
            dimension="execution",
            suffix="json",
        ),
    )
    return WorkOrder.model_validate(
        sign_payload(
            "work-order",
            candidate,
            ephemeral_role_keys["Maintainer"][0],
        )
    )


@pytest.fixture
def signed_root_grant(
    signed_work_order: WorkOrder,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> CapabilityGrant:
    candidate = signed_work_order.root_grant_template.model_dump(mode="json")
    candidate["work_order_digest"] = signed_work_order.digest
    return CapabilityGrant.model_validate(
        sign_payload(
            "capability-grant",
            candidate,
            ephemeral_role_keys["Maintainer"][0],
        )
    )


@pytest.fixture
def public_keys(
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> dict[str, Ed25519PublicKey]:
    return {
        binding["key_id"]: private_key.public_key()
        for private_key, binding in ephemeral_role_keys.values()
    }


@pytest.fixture
def fixed_now() -> datetime:
    return datetime(2026, 1, 1, 0, 0, 5, tzinfo=timezone.utc)


def _v03_digest(domain: str, payload: Any) -> str:
    return jcs_digest(
        {"domain": f"openworkproof/{domain}/v0.3", "payload": payload}
    )


def _v04_digest(domain: str, payload: Any) -> str:
    return hashlib.sha256(
        canonical_bytes(domain, payload, version="0.4")
    ).hexdigest()


@pytest.fixture
def binding_acceptor_private_key_v04() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([43]) * 32)


@pytest.fixture
def binding_manager_private_key_v04() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([44]) * 32)


@pytest.fixture
def binding_developer_private_key_v04() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([45]) * 32)


@pytest.fixture
def binding_verifier_private_key_v04() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([46]) * 32)


@pytest.fixture
def binding_authority_private_key_v04() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([47]) * 32)


@pytest.fixture
def binding_secondary_verifier_private_key_v04() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([48]) * 32)


@pytest.fixture
def judgment_commitment_v04_dict(
    binding_acceptor_private_key_v04: Ed25519PrivateKey,
) -> dict[str, Any]:
    return sign_payload(
        "judgment-commitment",
        {
            "schema_version": "openworkproof-judgment-commitment/0.4",
            "commitment_id": SHA256_A,
            "authority_namespace": "customer.example",
            "subject_id": "issue-123",
            "judgment_kind": "code-delivery",
            "judgment_artifact_uri": "evidence/judgment.json",
            "judgment_artifact_digest": SHA256_B,
            "normalized_facts_digest": SHA256_C,
            "disposition_digest": SHA256_D,
            "action_constraint_digest": SHA256_E,
            "adapter_id": "openworkproof/code-delivery-github/0.1",
            "adapter_version": "0.1",
            "adapter_profile_digest": "1" * 64,
            "repository": "https://github.com/example/project",
            "source_revision": SOURCE_COMMIT,
            "target_branch": "main",
            "acceptance_condition_digests": ["2" * 64],
            "excluded_scope_digests": ["3" * 64],
            "required_artifact_digests": ["4" * 64],
            "valid_from": "2026-01-01T00:00:01Z",
            "expires_at": "2026-01-02T00:00:00Z",
            "created_at": "2026-01-01T00:00:00Z",
            "nonce": "5" * 64,
        },
        binding_acceptor_private_key_v04,
        version="0.4",
    )


@pytest.fixture
def judgment_commitment_v04(
    judgment_commitment_v04_dict: dict[str, Any],
) -> JudgmentCommitment:
    return JudgmentCommitment.model_validate(judgment_commitment_v04_dict)


@pytest.fixture
def action_binding_manifest_v04_dict(
    binding_manager_private_key_v04: Ed25519PrivateKey,
    judgment_commitment_v04: JudgmentCommitment,
) -> dict[str, Any]:
    return sign_payload(
        "action-binding-manifest",
        {
            "schema_version": "openworkproof-action-binding-manifest/0.4",
            "binding_manifest_id": "6" * 64,
            "work_order_digest": SHA256_A,
            "judgment_commitment_id": judgment_commitment_v04.commitment_id,
            "judgment_commitment_digest": judgment_commitment_v04.digest,
            "evaluation_scope_id": "7" * 64,
            "evaluation_scope_digest": "8" * 64,
            "adapter_id": judgment_commitment_v04.adapter_id,
            "adapter_version": judgment_commitment_v04.adapter_version,
            "adapter_profile_digest": judgment_commitment_v04.adapter_profile_digest,
            "allowed_tool_names": ["owp.apply_patch", "owp.run_tests"],
            "allowed_action_kinds": ["patch", "test"],
            "allowed_path_roots": ["src", "tests"],
            "required_test_profile_digests": ["9" * 64],
            "source_revision": SOURCE_COMMIT,
            "supersedes_binding_manifest_id": None,
            "supersedes_binding_manifest_digest": None,
            "causal_parent_manifest_ids": [],
            "created_at": "2026-01-01T00:00:02Z",
            "expires_at": "2026-01-01T23:59:59Z",
            "nonce": "0" * 64,
        },
        binding_manager_private_key_v04,
        version="0.4",
    )


@pytest.fixture
def action_binding_manifest_v04(
    action_binding_manifest_v04_dict: dict[str, Any],
) -> ActionBindingManifest:
    return ActionBindingManifest.model_validate(action_binding_manifest_v04_dict)


@pytest.fixture
def authority_checkpoint_v04_dict(
    binding_authority_private_key_v04: Ed25519PrivateKey,
    judgment_commitment_v04: JudgmentCommitment,
) -> dict[str, Any]:
    payload = {
        "schema_version": "openworkproof-authority-checkpoint/0.4",
        "checkpoint_id": "1" * 64,
        "authority_namespace": judgment_commitment_v04.authority_namespace,
        "subject_id": judgment_commitment_v04.subject_id,
        "monotonic_revision": 1,
        "current_judgment_commitment_digest": judgment_commitment_v04.digest,
        "predecessor_checkpoint_digest": None,
        "effective_at": "2026-01-01T00:00:02Z",
        "expires_at": "2026-01-02T00:00:00Z",
        "authority_key_id": key_id(binding_authority_private_key_v04.public_key()),
        "signature_alg": "Ed25519",
    }
    encoded = canonical_bytes("authority-checkpoint", payload, version="0.4")
    return {
        **payload,
        "signature": base64.urlsafe_b64encode(
            binding_authority_private_key_v04.sign(encoded)
        ).decode("ascii").rstrip("="),
        "digest": hashlib.sha256(encoded).hexdigest(),
    }


@pytest.fixture
def authority_checkpoint_v04(
    authority_checkpoint_v04_dict: dict[str, Any],
) -> AuthorityCheckpoint:
    return AuthorityCheckpoint.model_validate(authority_checkpoint_v04_dict)


@pytest.fixture
def binding_decision_v04_dict(
    binding_verifier_private_key_v04: Ed25519PrivateKey,
    action_binding_manifest_v04: ActionBindingManifest,
    authority_checkpoint_v04: AuthorityCheckpoint,
) -> dict[str, Any]:
    payload = {
        "schema_version": "openworkproof-binding-decision/0.4",
        "binding_decision_id": "2" * 64,
        "work_order_digest": action_binding_manifest_v04.work_order_digest,
        "judgment_commitment_digest": (
            action_binding_manifest_v04.judgment_commitment_digest
        ),
        "action_binding_manifest_digest": action_binding_manifest_v04.digest,
        "verification_decision_id": "3" * 64,
        "verification_decision_digest": "4" * 64,
        "action_receipt_ids": ["5" * 64, "6" * 64],
        "action_receipt_digests": ["7" * 64, "8" * 64],
        "adapter_replay_digest": "9" * 64,
        "authority_checkpoint_digest": authority_checkpoint_v04.digest,
        "decision": "BOUND",
        "reason_codes": [],
        "authority_status": "current",
        "causal_parent_decision_ids": [],
        "supersedes_binding_decision_id": None,
        "supersedes_binding_decision_digest": None,
        "decided_at": "2026-01-01T00:00:04Z",
        "nonce": "a" * 64,
    }
    encoded = canonical_bytes("binding-decision", payload, version="0.4")
    return {
        **payload,
        "verifier_signatures": [
            {
                "verifier_subject_id": "verifier",
                "verifier_key_id": key_id(
                    binding_verifier_private_key_v04.public_key()
                ),
                "signature_alg": "Ed25519",
                "signature": base64.urlsafe_b64encode(
                    binding_verifier_private_key_v04.sign(encoded)
                ).decode("ascii").rstrip("="),
            }
        ],
        "digest": hashlib.sha256(encoded).hexdigest(),
    }


@pytest.fixture
def binding_decision_v04(
    binding_decision_v04_dict: dict[str, Any],
) -> BindingDecision:
    return BindingDecision.model_validate(binding_decision_v04_dict)


@pytest.fixture
def agent_request_v04_dict(
    binding_developer_private_key_v04: Ed25519PrivateKey,
    action_binding_manifest_v04: ActionBindingManifest,
) -> dict[str, Any]:
    actor_key_id = key_id(binding_developer_private_key_v04.public_key())
    return sign_payload(
        "agent-request",
        {
            "schema_version": "openworkproof-agent-request/0.4",
            "claim_type": "agent-request",
            "work_order_digest": action_binding_manifest_v04.work_order_digest,
            "grant_id": SHA256_A,
            "actor_id": "developer",
            "actor_key_id": actor_key_id,
            "tool_name": "owp.apply_patch",
            "arguments_digest": SHA256_B,
            "nonce": SHA256_C,
            "requested_at": "2026-01-01T00:00:03Z",
            "authentication_method": "agent_signature",
            "model_id": "model",
            "model_version": "1",
            "prompt_template_digest": SHA256_D,
            "context_source_digest": SHA256_E,
            "judgment_commitment_id": (
                action_binding_manifest_v04.judgment_commitment_id
            ),
            "judgment_commitment_digest": (
                action_binding_manifest_v04.judgment_commitment_digest
            ),
            "action_binding_manifest_id": (
                action_binding_manifest_v04.binding_manifest_id
            ),
            "action_binding_manifest_digest": action_binding_manifest_v04.digest,
        },
        binding_developer_private_key_v04,
        version="0.4",
    )


@pytest.fixture
def agent_request_v04(
    agent_request_v04_dict: dict[str, Any],
) -> AgentRequestV04:
    return AgentRequestV04.model_validate(agent_request_v04_dict)


def _scope_member_v03(
    member_kind: str,
    locator: str,
    content: bytes,
) -> dict[str, Any]:
    return {
        "member_id": _v03_digest(
            "scope-member",
            {"member_kind": member_kind, "locator": locator},
        ),
        "member_kind": member_kind,
        "locator": locator,
        "locator_digest": hashlib.sha256(locator.encode("utf-8")).hexdigest(),
        "content_digest": hashlib.sha256(content).hexdigest(),
        "source_revision": SOURCE_COMMIT,
    }


@pytest.fixture
def scope_manager_private_key_v03() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([42]) * 32)


@pytest.fixture
def scope_members_v03() -> tuple[ScopeMember, ...]:
    raw = sorted(
        (
            _scope_member_v03("source_file", "src/widget.py", b"source"),
            _scope_member_v03(
                "test_case",
                "tests/test_widget.py::test_widget[param-\u4e00]",
                b"test",
            ),
        ),
        key=lambda item: (
            item["member_kind"],
            item["locator_digest"],
            item["member_id"],
        ),
    )
    return tuple(ScopeMember.model_validate(item) for item in raw)


@pytest.fixture
def evaluation_scope_payload_v03(
    scope_members_v03: tuple[ScopeMember, ...],
) -> dict[str, Any]:
    members = [member.model_dump(mode="json") for member in scope_members_v03]
    bindings = sorted(
        (
            {
                "requirement_kind": "acceptance_condition",
                "requirement_digest": _v03_digest(
                    "scope-requirement",
                    {
                        "requirement_kind": "acceptance_condition",
                        "value": "tests_passed",
                    },
                ),
                "member_ids": [members[1]["member_id"]],
            },
            {
                "requirement_kind": "required_artifact",
                "requirement_digest": _v03_digest(
                    "scope-requirement",
                    {
                        "requirement_kind": "required_artifact",
                        "value": "src/widget.py",
                    },
                ),
                "member_ids": [members[0]["member_id"]],
            },
        ),
        key=lambda item: (
            item["requirement_kind"].encode("utf-8"),
            item["requirement_digest"],
        ),
    )
    payload: dict[str, Any] = {
        "schema_version": "openworkproof-evaluation-scope/0.3",
        "scope_id": "0" * 64,
        "work_order_digest": SHA256_A,
        "subject_claim_digest": SHA256_B,
        "source_revision": SOURCE_COMMIT,
        "candidate_commit": "2" * 40,
        "selector_rules": [
            {
                "rule_id": SHA256_C,
                "selector_kind": "explicit",
                "selector_spec_digest": SHA256_D,
                "selector_engine_digest": SHA256_E,
                "required_evidence_paths": ["scope/selectors/explicit.json"],
            }
        ],
        "members": members,
        "member_count": len(members),
        "population_digest": _v03_digest(
            "scope-population",
            [
                {
                    "member_id": member["member_id"],
                    "member_kind": member["member_kind"],
                    "locator_digest": member["locator_digest"],
                }
                for member in members
            ],
        ),
        "requirement_bindings": bindings,
        "required_target_ids": sorted(
            {
                member_id
                for binding in bindings
                for member_id in binding["member_ids"]
            }
        ),
        "excluded_locator_digests": [],
        "workspace_manifest_digest": "6" * 64,
        "freshness_mode": "immutable_git_revision",
        "created_at": "2026-01-01T00:00:05Z",
        "expires_at": "2026-01-01T01:00:00Z",
        "nonce": "7" * 64,
    }
    payload["scope_id"] = _v03_digest(
        "evaluation-scope",
        {key: value for key, value in payload.items() if key != "scope_id"},
    )
    return payload


@pytest.fixture
def evaluation_scope_v03(
    evaluation_scope_payload_v03: dict[str, Any],
    scope_manager_private_key_v03: Ed25519PrivateKey,
) -> EvaluationScopeManifest:
    return EvaluationScopeManifest.model_validate(
        sign_payload(
            "evaluation-scope",
            evaluation_scope_payload_v03,
            scope_manager_private_key_v03,
            version="0.3",
        )
    )


@pytest.fixture
def tamper_scope_v03():
    def tamper(payload: dict[str, Any], field: str, value: Any) -> dict[str, Any]:
        candidate = copy.deepcopy(payload)
        candidate[field] = value
        return candidate

    return tamper


@pytest.fixture
def signed_subject_claim(
    signed_work_order: WorkOrder,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> SubjectClaim:
    candidate = {
        "schema_version": "openworkproof-subject-claim/0.1",
        "claim_id": "7" * 64,
        "work_order_digest": signed_work_order.digest,
        "claim_statement": "The frozen verifier tests pass for this delivery.",
        "delivery_target": "customer/release-candidate",
        "source_revision": signed_work_order.source_commit,
        "acceptance_conditions": ["artifact_digest_matches", "tests_passed"],
        "excluded_scope": ["payment_status"],
        "required_artifacts": ["evidence", "results"],
        "customer_acceptor_key_id": signed_work_order.acceptor_key_ids[0],
        "created_at": "2026-01-01T00:00:05Z",
        "nonce": "8" * 64,
    }
    return SubjectClaim.model_validate(
        sign_payload(
            "subject-claim",
            candidate,
            ephemeral_role_keys["Manager"][0],
        )
    )


@pytest.fixture
def policy_anchor() -> PolicyAnchor:
    return PolicyAnchor.model_validate(
        {
            "schema_version": "openworkproof-policy-anchor/0.1",
            "policy_registry_uri": "https://policy.example.invalid/agent-delivery",
            "policy_version": "customer-policy-v1",
            "policy_digest": "9" * 64,
            "effective_at": "2026-01-01T00:00:00Z",
            "resolved_at": "2026-01-01T00:00:04Z",
            "resolver_identity": "customer-policy-resolver",
        }
    )


@pytest.fixture
def commitment_anchor(
    signed_work_order: WorkOrder,
    signed_subject_claim: SubjectClaim,
) -> CommitmentAnchor:
    return CommitmentAnchor.model_validate(
        {
            "schema_version": "openworkproof-commitment-anchor/0.1",
            "work_order_digest": signed_work_order.digest,
            "subject_claim_digest": signed_subject_claim.digest,
            "anchored_at": "2026-01-01T00:00:04Z",
            "anchor_provider": "customer_signed_document",
            "anchor_reference": "customer://acceptance-criteria/2026-001",
        }
    )


@pytest.fixture
def verification_profile_dict(
    signed_work_order: WorkOrder,
    signed_subject_claim: SubjectClaim,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> dict[str, Any]:
    verifier = ephemeral_role_keys["Verifier"][1]
    positive_arm = {
        "arm_id": "1" * 64,
        "arm_kind": "positive",
        "source_commit": signed_work_order.source_commit,
        "candidate_commit": "2" * 40,
        "mutant_patch_digest": None,
        "workspace_manifest_digest": "3" * 64,
        "command_digest": "4" * 64,
        "container_image_digest": IMAGE_A,
        "fixed_test_source_digest": SHA256_B,
        "expected_exit_codes": [0],
        "expected_outcome": "pass",
        "required_evidence_purposes": ["verifier_result"],
        "result_artifact_paths": ["results/positive.json"],
    }
    negative_arm = {
        **positive_arm,
        "arm_id": "2" * 64,
        "arm_kind": "negative",
        "mutant_patch_digest": "5" * 64,
        "expected_exit_codes": [1],
        "expected_outcome": "fail",
        "result_artifact_paths": ["results/negative.json"],
    }
    return {
        "schema_version": "openworkproof-verification-profile/0.2",
        "profile_id": "6" * 64,
        "work_order_digest": signed_work_order.digest,
        "subject_claim_digest": signed_subject_claim.digest,
        "delivery_trust_level": 1,
        "policy_anchor_digest": None,
        "commitment_anchor_digest": None,
        "subject_kind": "tests_passed",
        "assurance_level": "standard",
        "verifier_bindings": [
            {
                "binding_id": "a" * 64,
                "verifier_subject_id": verifier["subject_id"],
                "verifier_key_id": verifier["key_id"],
                "verifier_public_key_b64url": verifier["public_key_b64url"],
                "controller_factors": ["customer-independent-verifier"],
                "execution_context_factors": ["isolated-container-a"],
                "valid_from": "2026-01-01T00:00:04Z",
                "expires_at": "2026-01-01T01:00:00Z",
            }
        ],
        "positive_arm": positive_arm,
        "negative_arms": [negative_arm],
        "max_evidence_bytes": 1048576,
        "max_output_bytes": 65536,
        "created_at": "2026-01-01T00:00:05Z",
        "expires_at": "2026-01-01T01:00:00Z",
        "nonce": "b" * 64,
    }


@pytest.fixture
def signed_verification_profile(
    verification_profile_dict: dict[str, Any],
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> VerificationProfileV02:
    return VerificationProfileV02.model_validate(
        sign_payload(
            "verification-profile",
            verification_profile_dict,
            ephemeral_role_keys["Manager"][0],
        )
    )


def _bind_and_sign_nested_claim(
    raw: dict[str, Any],
    *,
    work_order: WorkOrder,
    actor_role: str,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> None:
    binding = ephemeral_role_keys[actor_role][1]
    raw["actor_id"] = binding["subject_id"]
    raw["actor_key_id"] = binding["key_id"]
    claim = copy.deepcopy(raw["nested_claim"])
    claim["work_order_digest"] = work_order.digest
    claim["actor_id"] = binding["subject_id"]
    claim["actor_key_id"] = binding["key_id"]
    if raw["actor_type"] == "agent":
        signed = sign_payload(
            "agent-request",
            claim,
            ephemeral_role_keys[actor_role][0],
        )
        raw["nonce"] = signed["nonce"]
    elif raw["actor_type"] == "human":
        signed = sign_payload(
            "human-decision",
            claim,
            ephemeral_role_keys[actor_role][0],
        )
    else:
        raise AssertionError("Sidecar claims are digest-only")
    raw["nested_claim"] = signed
    raw["nested_claim_digest"] = signed["digest"]


def _set_predicate_result_input(
    result: dict[str, Any],
    input_value: dict[str, Any],
) -> None:
    result["input"] = input_value
    result["input_digest"] = jcs_digest(
        {
            "domain": "openworkproof/predicate-input/v0.1",
            "predicate_id": result["predicate_id"],
            "input": input_value,
        }
    )


@pytest.fixture
def sidecar_receipt_factory(
    signed_work_order: WorkOrder,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
):
    bindings = [
        copy.deepcopy(ephemeral_role_keys[role][1])
        for role in EPHEMERAL_ROLES
    ]

    def make_receipt(
        *,
        state_before: str,
        state_after: str,
        event_type: str,
        event_name: str | None = None,
        actor_role: str | None = None,
        policy_decision: str = "allow",
        execution_status: str = "succeeded",
        parent_receipt_ids: tuple[str, ...] = (),
        sequence: int = 1,
        previous_receipt_digest: str | None = None,
        occurred_at: str = "2026-01-01T00:00:03Z",
        test_passed: bool = True,
        final_request: bool = False,
    ) -> ActionReceipt:
        from test_contract import (  # noqa: PLC0415
            agent_arguments_digest,
            predicate_result_data,
            receipt_data,
            run_tests_receipt_data,
            system_input_digest,
        )

        if event_type == "tool_call" and actor_role in {
            "Developer",
            "Verifier",
        }:
            test_mode = (
                "verifier" if actor_role == "Verifier" else "developer"
            )
            raw, _ = run_tests_receipt_data(
                bindings,
                signed_work_order,
                test_mode=test_mode,
                evidence_path=(
                    "verifier-result/01.json"
                    if test_mode == "verifier"
                    else "developer-test-result/01.json"
                ),
            )
        else:
            raw = receipt_data(
                event_type,
                bindings,
                policy_decision=policy_decision,
                execution_status=execution_status,
            )

        raw.update(
            {
                "work_order_digest": signed_work_order.digest,
                "state_before": state_before,
                "state_after": state_after,
                "parent_receipt_ids": list(parent_receipt_ids),
                "sequence": sequence,
                "previous_receipt_digest": previous_receipt_digest,
                "occurred_at": occurred_at,
            }
        )

        if event_type == "grant_issued" and state_before == "issued":
            grant_id = signed_work_order.root_grant_template.grant_id
            raw.update(
                {
                    "authorizing_grant_id": grant_id,
                    "candidate_grant_digest": SHA256_B,
                    "parent_grant_id": None,
                    "issued_grant_id": grant_id,
                }
            )
            arguments = {
                "operation": "activate_root",
                "authorizing_grant_id": grant_id,
                "candidate_grant_digest": SHA256_B,
            }
            raw["nested_claim"]["grant_id"] = grant_id
            raw["nested_claim"]["tool_name"] = "owp.activate_root_grant"
            raw["nested_claim"]["arguments_digest"] = agent_arguments_digest(
                "owp.activate_root_grant",
                arguments,
            )

        if event_type == "tool_call" and actor_role in {
            "Developer",
            "Verifier",
        }:
            include_postconditions = actor_role == "Verifier"
            applicable = sorted(
                (
                    spec
                    for spec in (
                        signed_work_order.preconditions
                        + signed_work_order.invariants
                        + (
                            signed_work_order.postconditions
                            if include_postconditions
                            else ()
                        )
                    )
                    if "owp.run_tests" in spec.applies_to_tools
                ),
                key=lambda spec: spec.predicate_id,
            )
            results = []
            for spec in applicable:
                spec_data = spec.model_dump(mode="json")
                passed = test_passed or spec.name != "tests_passed"
                result = predicate_result_data(
                    spec_data,
                    passed=passed,
                    error_code=None if passed else "PREDICATE_FALSE",
                )
                if spec.name == "quota_remaining":
                    _set_predicate_result_input(
                        result,
                        {
                            "grant_id": raw["grant_id"],
                            "metric": "tool_calls",
                            "amount": 1,
                            "grant_remaining_before": 1,
                            "ledger_prefix_digest": SHA256_B,
                        },
                    )
                elif spec.name == "tool_allowed":
                    _set_predicate_result_input(
                        result,
                        {"actual_tool_name": "owp.run_tests"},
                    )
                elif spec.name == "tests_passed":
                    input_value = copy.deepcopy(result["input"])
                    input_value.update(
                        {
                            "command_digest": signed_work_order.postconditions[
                                0
                            ].arguments["command_digest"],
                            "expected_exit_code": 0,
                            "actual_exit_code": 0 if test_passed else 1,
                            "fixed_test_source_digest": (
                                signed_work_order.postconditions[0].arguments[
                                    "fixed_test_source_digest"
                                ]
                            ),
                        }
                    )
                    _set_predicate_result_input(result, input_value)
                results.append(result)
            raw["predicate_results"] = results

        if event_type == "tool_call" and raw["tool_name"] == "owp.repo_read":
            applicable = sorted(
                (
                    spec
                    for spec in (
                        signed_work_order.preconditions
                        + signed_work_order.invariants
                    )
                    if "owp.repo_read" in spec.applies_to_tools
                ),
                key=lambda spec: spec.predicate_id,
            )
            results = []
            for spec in applicable:
                result = predicate_result_data(spec.model_dump(mode="json"))
                if spec.name == "tool_allowed":
                    _set_predicate_result_input(
                        result,
                        {"actual_tool_name": "owp.repo_read"},
                    )
                results.append(result)
            raw["predicate_results"] = results

        if event_type == "system_event":
            name = event_name or "proof_composed"
            if name == "contract_expired":
                cause = {
                    "deadline": signed_work_order.model_dump(mode="json")[
                        "deadline"
                    ],
                    "observed_at": occurred_at,
                    "tip_receipt_digest": previous_receipt_digest,
                }
            else:
                cause = {
                    "initiator_receipt_digest": SHA256_B,
                    "composition_report_digest": SHA256_C,
                    "state_version_before": 0,
                }
            input_digest = system_input_digest(
                name,
                signed_work_order.digest,
                cause,
            )
            raw.update(
                {
                    "system_event_name": name,
                    "cause": cause,
                    "input_digest": input_digest,
                    "error_code": (
                        "CONTRACT_EXPIRED"
                        if name == "contract_expired"
                        else "SECURITY_VIOLATION"
                        if name == "security_violation"
                        else None
                    ),
                    "nested_claim_digest": input_digest,
                    "nested_claim": {
                        "claim_type": "sidecar-event",
                        "work_order_digest": signed_work_order.digest,
                        "event_name": name,
                        "cause": cause,
                        "input_digest": input_digest,
                        "occurred_at": occurred_at,
                    },
                }
            )

        if event_type == "approval_requested":
            if final_request:
                scope = {
                    "work_order_digest": signed_work_order.digest,
                    "operation": "submit_final_acceptance",
                    "composition_report_digest": SHA256_B,
                }
                target_domain = (
                    "openworkproof/final-acceptance-action/v0.1"
                )
                tool_name = "owp.request_acceptance"
                request_kind = "final_acceptance"
                required_role = "Acceptor"
            else:
                scope = {
                    "work_order_digest": signed_work_order.digest,
                    "operation": "create_local_pr_proposal",
                    "target_patch_digest": SHA256_B,
                }
                target_domain = "openworkproof/high-risk-action/v0.1"
                tool_name = "owp.request_pr_proposal"
                request_kind = "high_risk_action"
                required_role = "Maintainer"
            target_payload = {
                "domain": target_domain,
                "requested_scope": scope,
            }
            if not final_request:
                target_payload["tool_name"] = "owp.create_pr_proposal"
            target_action_digest = jcs_digest(target_payload)
            raw.update(
                {
                    "request_kind": request_kind,
                    "target_action_digest": target_action_digest,
                    "required_role": required_role,
                    "requested_scope": scope,
                }
            )
            arguments = {
                "request_kind": request_kind,
                "target_action_digest": target_action_digest,
                "required_role": required_role,
                "requested_scope": scope,
                "expires_at": raw["expires_at"],
            }
            raw["nested_claim"]["tool_name"] = tool_name
            raw["nested_claim"]["arguments_digest"] = agent_arguments_digest(
                tool_name,
                arguments,
            )

        if event_type == "termination_decision":
            raw["target_work_order_digest"] = signed_work_order.digest
            raw["nested_claim"]["target_work_order_digest"] = (
                signed_work_order.digest
            )

        if event_type == "approval_decision":
            scope = {
                "work_order_digest": signed_work_order.digest,
                "operation": "create_local_pr_proposal",
                "target_patch_digest": SHA256_E,
            }
            raw["approved_scope"] = scope
            raw["nested_claim"]["approved_scope"] = scope

        if raw["actor_type"] == "agent":
            role = actor_role or "Manager"
            _bind_and_sign_nested_claim(
                raw,
                work_order=signed_work_order,
                actor_role=role,
                ephemeral_role_keys=ephemeral_role_keys,
            )
        elif raw["actor_type"] == "human":
            _bind_and_sign_nested_claim(
                raw,
                work_order=signed_work_order,
                actor_role=actor_role or "Maintainer",
                ephemeral_role_keys=ephemeral_role_keys,
            )
        else:
            sidecar = ephemeral_role_keys["Sidecar"][1]
            raw["actor_id"] = sidecar["subject_id"]
            raw["actor_key_id"] = sidecar["key_id"]
            raw["nested_claim_digest"] = raw["input_digest"]

        signed = sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
        return ACTION_RECEIPT_ADAPTER.validate_python(signed)

    return make_receipt


@pytest.fixture
def signed_acceptance_receipt(
    signed_work_order: WorkOrder,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> AcceptanceReceipt:
    from test_contract import acceptance_data  # noqa: PLC0415

    bindings = [
        copy.deepcopy(ephemeral_role_keys[role][1])
        for role in EPHEMERAL_ROLES
    ]
    raw = acceptance_data(
        bindings,
        signed_work_order.model_dump(mode="json"),
    )
    raw["work_order_digest"] = signed_work_order.digest
    return AcceptanceReceipt.model_validate(
        sign_payload(
            "acceptance-receipt",
            raw,
            ephemeral_role_keys["Acceptor"][0],
        )
    )
