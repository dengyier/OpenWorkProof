"""v0.4 delivery package export and replay with honest privacy views (Task 12)."""

from __future__ import annotations

import hashlib
import json
import os

import pytest
import rfc8785

from openworkproof.adapters import (
    ADAPTER_ID,
    ADAPTER_VERSION,
    CodeDeliveryAdapterProfile,
    CodeDeliveryJudgmentInput,
    CodeDeliveryReplayInput,
    ObservedAction,
    replay_code_delivery_binding,
)
from openworkproof.delivery_package import (
    DeliveryManifest,
    DeliveryManifestEntry,
    DeliveryPackageError,
    verify_delivery_package,
)

_JUDGMENT_DIGEST = "a" * 64
_MANIFEST_DIGEST = "b" * 64
_DECISION_DIGEST = "c" * 64


def _canonical(value: object) -> bytes:
    return rfc8785.dumps(value)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _media_type(path: str) -> str:
    if path.endswith(".json"):
        return "application/json"
    if path.endswith(".html"):
        return "text/html"
    return "application/octet-stream"


def _replay_inputs(case) -> dict:
    judgment = case["judgment"]
    projection = case["projection"]
    return {
        "judgment": {
            "adapter_id": ADAPTER_ID,
            "adapter_version": ADAPTER_VERSION,
            "adapter_profile_digest": judgment.adapter_profile_digest,
            "issue_snapshot_digest": judgment.judgment_artifact_digest,
            "repository_identity": judgment.repository,
            "source_revision": judgment.source_revision,
            "target_branch": judgment.target_branch,
            "acceptance_condition_digests": list(
                judgment.acceptance_condition_digests
            ),
            "excluded_scope_digests": list(judgment.excluded_scope_digests),
            "excluded_path_roots": [],
            "required_artifact_digests": list(
                judgment.required_artifact_digests
            ),
            "allowed_path_roots": list(projection.allowed_path_roots),
            "allowed_action_kinds": list(projection.allowed_action_kinds),
            "required_test_profile_digests": list(
                projection.required_test_profile_digests
            ),
        },
        "profile": {
            "adapter_id": ADAPTER_ID,
            "adapter_version": ADAPTER_VERSION,
            "adapter_profile_digest": judgment.adapter_profile_digest,
            "allowed_tool_names": list(projection.allowed_tool_names),
            "allowed_action_kinds": list(projection.allowed_action_kinds),
            "allowed_path_roots": list(projection.allowed_path_roots),
            "required_test_profile_digests": list(
                projection.required_test_profile_digests
            ),
        },
        "observed": {
            "tool_name": "owp.run_tests",
            "action_kind": "test",
            "changed_paths": [],
            "patch_digest": None,
            "candidate_commit_digest": None,
            "workspace_digest": None,
            "artifact_digests": list(judgment.required_artifact_digests),
            "covered_condition_digests": list(
                judgment.acceptance_condition_digests
            ),
            "undeclared_side_effects": [],
        },
    }


def _expected_replay(inputs: dict) -> str:
    result = replay_code_delivery_binding(
        CodeDeliveryReplayInput(
            judgment=CodeDeliveryJudgmentInput(**inputs["judgment"]),
            profile=CodeDeliveryAdapterProfile(**inputs["profile"]),
            observed=ObservedAction(**inputs["observed"]),
        )
    )
    return result.outcome


def _build_package(
    tmp_path,
    *,
    privacy_view: str,
    binding_replay: str,
    reason_codes=(),
    inputs: dict | None = None,
    verification_decision="VERIFIED",
    effective_acceptance="ACTIVE",
    settlement_readiness="READY_FOR_SETTLEMENT_REVIEW",
) -> "tuple":
    root = tmp_path / "package"
    root.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": "openworkproof-binding-report/0.4",
        "privacy_view": privacy_view,
        "judgment_commitment_digest": _JUDGMENT_DIGEST,
        "action_binding_manifest_digest": _MANIFEST_DIGEST,
        "binding_decision_digest": _DECISION_DIGEST,
        "verification_decision": verification_decision,
        "effective_acceptance": effective_acceptance,
        "settlement_readiness": settlement_readiness,
        "binding_replay": binding_replay,
        "binding_reason_codes": list(reason_codes),
    }
    files = {
        "binding-report.json": _canonical(report),
    }
    if privacy_view == "customer_private":
        if inputs is not None:
            files["binding-replay-inputs.json"] = _canonical(inputs)
    if privacy_view != "public":
        html = (
            "<html><body><h1>Judgment-to-Action Binding Report</h1>"
            f"<p>binding_replay: <code>{binding_replay}</code></p>"
            f"<p>binding_reason_codes: <code>{', '.join(reason_codes)}</code></p>"
            "<p>本结果不证明付款或结算已发生。</p></body></html>"
        ).encode("utf-8")
        files["binding-report.html"] = html

    entries = []
    for path, data in sorted(files.items()):
        (root / path).write_bytes(data)
        entries.append(
            {
                "path": path,
                "sha256": _sha256(data),
                "size_bytes": len(data),
                "media_type": _media_type(path),
                "privacy_class": privacy_view,
                "required": True,
            }
        )
    manifest = DeliveryManifest.model_validate(
        {
            "schema_version": "openworkproof-delivery-manifest/0.1",
            "privacy_view": privacy_view,
            "work_order_digest": "1" * 64,
            "subject_claim_digest": "2" * 64,
            "verification_decision_digest": "3" * 64,
            "binding_protocol_version": "0.4",
            "judgment_commitment_digest": _JUDGMENT_DIGEST,
            "action_binding_manifest_digest": _MANIFEST_DIGEST,
            "binding_decision_digest": _DECISION_DIGEST,
            "binding_replay": binding_replay,
            "entries": entries,
        }
    )
    manifest_bytes = _canonical(manifest.model_dump(mode="json"))
    (root / "manifest.json").write_bytes(manifest_bytes)
    return root, manifest


def _write_manifest_only(root, manifest) -> None:
    (root / "manifest.json").write_bytes(
        _canonical(manifest.model_dump(mode="json"))
    )


# ---------------------------------------------------------------------------
# Step 1: package replay and view behavior
# ---------------------------------------------------------------------------


def test_customer_private_full_replay(binding_decision_case, tmp_path) -> None:
    inputs = _replay_inputs(binding_decision_case)
    expected = _expected_replay(inputs)
    assert expected == "BOUND"
    root, _ = _build_package(
        tmp_path,
        privacy_view="customer_private",
        binding_replay="BOUND",
        inputs=inputs,
    )
    result = verify_delivery_package(root)
    assert result.binding_replay == "BOUND"
    assert result.binding_reason_codes == ()


def test_customer_private_unbound_replay(
    binding_decision_case, tmp_path,
) -> None:
    inputs = _replay_inputs(binding_decision_case)
    inputs["observed"]["changed_paths"] = ["docs/outside.md"]
    expected = _expected_replay(inputs)
    assert expected == "UNBOUND"
    assert replay_code_delivery_binding(
        CodeDeliveryReplayInput(
            judgment=CodeDeliveryJudgmentInput(**inputs["judgment"]),
            profile=CodeDeliveryAdapterProfile(**inputs["profile"]),
            observed=ObservedAction(**inputs["observed"]),
        )
    ).reason_codes == ("ACTION_OUTSIDE_APPROVED_SCOPE",)
    root, _ = _build_package(
        tmp_path,
        privacy_view="customer_private",
        binding_replay="UNBOUND",
        reason_codes=("ACTION_OUTSIDE_APPROVED_SCOPE",),
        inputs=inputs,
    )
    result = verify_delivery_package(root)
    assert result.binding_replay == "UNBOUND"
    assert result.binding_reason_codes == ("ACTION_OUTSIDE_APPROVED_SCOPE",)


def test_diagnostic_view_replay_unavailable(tmp_path) -> None:
    root, _ = _build_package(
        tmp_path,
        privacy_view="diagnostic",
        binding_replay="unavailable_in_this_view",
    )
    result = verify_delivery_package(root)
    assert result.binding_replay == "unavailable_in_this_view"
    assert not (root / "binding-replay-inputs.json").exists()


def test_public_view_replay_unavailable(tmp_path) -> None:
    root, _ = _build_package(
        tmp_path,
        privacy_view="public",
        binding_replay="unavailable_in_this_view",
    )
    result = verify_delivery_package(root)
    assert result.binding_replay == "unavailable_in_this_view"


def test_manifest_single_byte_tamper(tmp_path) -> None:
    root, _ = _build_package(
        tmp_path,
        privacy_view="diagnostic",
        binding_replay="unavailable_in_this_view",
    )
    raw = (root / "manifest.json").read_bytes()
    (root / "manifest.json").write_bytes(
        raw[:5] + b"X" + raw[6:]
    )
    with pytest.raises(DeliveryPackageError):
        verify_delivery_package(root)


def test_report_object_substitution(tmp_path) -> None:
    root, manifest = _build_package(
        tmp_path,
        privacy_view="diagnostic",
        binding_replay="unavailable_in_this_view",
    )
    # Replace the report with a different digest; manifest still references
    # the original digests so the report binding must fail.
    report = json.loads(
        (root / "binding-report.json").read_bytes()
    )
    report["binding_decision_digest"] = "f" * 64
    (root / "binding-report.json").write_bytes(_canonical(report))
    with pytest.raises(DeliveryPackageError):
        verify_delivery_package(root)


def test_replay_derived_truth_mismatch(binding_decision_case, tmp_path) -> None:
    inputs = _replay_inputs(binding_decision_case)
    inputs["observed"]["changed_paths"] = ["docs/outside.md"]
    root, _ = _build_package(
        tmp_path,
        privacy_view="customer_private",
        binding_replay="BOUND",  # declared BOUND but inputs replay UNBOUND
        inputs=inputs,
    )
    with pytest.raises(DeliveryPackageError):
        verify_delivery_package(root)


def test_missing_adapter_input_is_package_failure(tmp_path) -> None:
    root, _ = _build_package(
        tmp_path,
        privacy_view="customer_private",
        binding_replay="BOUND",
        inputs=None,  # customer-private without replay inputs
    )
    with pytest.raises(DeliveryPackageError):
        verify_delivery_package(root)


def test_oversized_package_rejected(tmp_path) -> None:
    root, manifest = _build_package(
        tmp_path,
        privacy_view="diagnostic",
        binding_replay="unavailable_in_this_view",
    )
    # Rewrite one entry with a payload exceeding the total package bound.
    payload = b"0" * (32 * 1024 * 1024 + 1)
    (root / "binding-report.json").write_bytes(payload)
    bad_manifest_payload = manifest.model_dump(mode="json")
    bad_manifest_payload["entries"] = [
        {
            **entry,
            "sha256": _sha256(payload),
            "size_bytes": len(payload),
        }
        if entry["path"] == "binding-report.json"
        else entry
        for entry in bad_manifest_payload["entries"]
    ]
    with pytest.raises(Exception):
        DeliveryManifest.model_validate(bad_manifest_payload)


def test_symlink_entry_rejected(tmp_path) -> None:
    root, manifest = _build_package(
        tmp_path,
        privacy_view="diagnostic",
        binding_replay="unavailable_in_this_view",
    )
    target = tmp_path / "outside-secret.txt"
    target.write_bytes(b"secret")
    (root / "binding-report.html").unlink()
    os.symlink(target, root / "binding-report.html")
    with pytest.raises(DeliveryPackageError):
        verify_delivery_package(root)


# ---------------------------------------------------------------------------
# Step 4: Layer 1 / Layer 2 separation
# ---------------------------------------------------------------------------


def test_structure_failure_is_package_failure_not_unbound(tmp_path) -> None:
    # A Layer 1 failure (report missing required fields) must surface as a
    # package verification failure, never as a UNBOUND replay result.
    root, manifest = _build_package(
        tmp_path,
        privacy_view="diagnostic",
        binding_replay="unavailable_in_this_view",
    )
    report = json.loads((root / "binding-report.json").read_bytes())
    del report["schema_version"]
    (root / "binding-report.json").write_bytes(_canonical(report))
    with pytest.raises(DeliveryPackageError):
        verify_delivery_package(root)
