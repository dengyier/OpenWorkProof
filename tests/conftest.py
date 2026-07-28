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
    CapabilityGrant,
    WorkOrder,
)
from openworkproof.signing import key_id, sign_payload


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
        "acceptor_key_ids": [key_bindings[0]["key_id"]],
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
    candidate["key_bindings"] = bindings
    candidate["issuer_id"] = maintainer["subject_id"]
    candidate["signer_key_id"] = maintainer["key_id"]
    candidate["acceptor_key_ids"] = [maintainer["key_id"]]
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
            else:
                scope = {
                    "work_order_digest": signed_work_order.digest,
                    "operation": "create_local_pr_proposal",
                    "target_patch_digest": SHA256_B,
                }
                target_domain = "openworkproof/high-risk-action/v0.1"
                tool_name = "owp.request_pr_proposal"
                request_kind = "high_risk_action"
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
                    "requested_scope": scope,
                }
            )
            arguments = {
                "request_kind": request_kind,
                "target_action_digest": target_action_digest,
                "required_role": raw["required_role"],
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
            ephemeral_role_keys["Maintainer"][0],
        )
    )
