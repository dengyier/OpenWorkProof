"""Thin application facade for versioned OpenWorkProof operations."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Literal

from openworkproof import evidence
from openworkproof.delivery_package import (
    export_delivery_package,
    verify_delivery_package,
)
from openworkproof.models import (
    DecisionDraftRequest,
    EvaluationScopeDraft,
    EvaluationScopeManifest,
    ScopeMember,
    ScopeRequirementBinding,
    ScopeSelectorRule,
    SubjectClaim,
    VerificationArmResult,
    VerificationArmResultV03,
    VerificationDecision,
    VerificationDecisionV03,
    VerificationProfileV02,
    VerificationProfileV03,
)
from openworkproof.scope import (
    ObservedScope,
    build_evaluation_scope,
    compare_observed_scope,
)
from openworkproof.settlement import read_settlement_snapshot
from openworkproof.verification import (
    commit_evaluation_scope,
    commit_verification_arm_result,
    commit_verification_arm_result_v03,
    commit_verification_decision,
    commit_verification_decision_v03,
    prepare_verification_decision,
    prepare_verification_decision_v03,
)


class OpenWorkProofServices:
    """Parse inputs, invoke one domain operation, and return JSON data."""

    def validate_profile(self, payload: Mapping[str, object]) -> dict:
        schema = payload.get("schema_version")
        if schema == "openworkproof-verification-profile/0.2":
            model = VerificationProfileV02
        elif schema == "openworkproof-verification-profile/0.3":
            model = VerificationProfileV03
        else:
            raise ValueError("verification profile schema_version is unsupported")
        profile = model.model_validate(payload)
        return profile.model_dump(mode="json")

    def build_scope(
        self,
        claim_payload: Mapping[str, object],
        source_revision: str,
        rules_payload: Mapping[str, object],
    ) -> dict:
        claim = SubjectClaim.model_validate(claim_payload)
        required = {
            "work_order_digest",
            "candidate_commit",
            "workspace_manifest_digest",
            "selector_rules",
            "explicit_members",
            "requirement_bindings",
            "excluded_locator_digests",
            "repository_root",
            "created_at",
            "expires_at",
            "nonce",
        }
        if set(rules_payload) != required:
            raise ValueError("scope build rules have an invalid field set")
        draft = build_evaluation_scope(
            claim=claim,
            work_order_digest=str(rules_payload["work_order_digest"]),
            source_revision=source_revision,
            candidate_commit=str(rules_payload["candidate_commit"]),
            workspace_manifest_digest=str(
                rules_payload["workspace_manifest_digest"]
            ),
            selector_rules=tuple(
                ScopeSelectorRule.model_validate(item)
                for item in rules_payload["selector_rules"]
            ),
            explicit_members=tuple(
                ScopeMember.model_validate(item)
                for item in rules_payload["explicit_members"]
            ),
            requirement_bindings=tuple(
                ScopeRequirementBinding.model_validate(item)
                for item in rules_payload["requirement_bindings"]
            ),
            excluded_locator_digests=tuple(
                rules_payload["excluded_locator_digests"]
            ),
            repository_root=Path(str(rules_payload["repository_root"])),
            created_at=datetime.fromisoformat(
                str(rules_payload["created_at"]).replace("Z", "+00:00")
            ),
            expires_at=datetime.fromisoformat(
                str(rules_payload["expires_at"]).replace("Z", "+00:00")
            ),
            nonce=str(rules_payload["nonce"]),
        )
        return draft.model_dump(mode="json")

    def validate_scope(self, payload: Mapping[str, object]) -> dict:
        if payload.get("schema_version") != "openworkproof-evaluation-scope/0.3":
            raise ValueError("evaluation scope schema_version is unsupported")
        signature_fields = {
            "digest",
            "signature_alg",
            "signer_key_id",
            "signature",
        }
        present = signature_fields.intersection(payload)
        if present and present != signature_fields:
            raise ValueError("evaluation scope signature envelope is incomplete")
        model = EvaluationScopeManifest if present else EvaluationScopeDraft
        scope = model.model_validate(payload)
        result = {
            "valid": True,
            "schema_version": scope.schema_version,
            "scope_id": scope.scope_id,
            "member_count": scope.member_count,
            "authority": "not_checked",
        }
        if isinstance(scope, EvaluationScopeManifest):
            result["scope_manifest_digest"] = scope.digest
        else:
            result["scope_manifest_digest"] = None
        return result

    def commit_scope(
        self,
        ledger: Path,
        payload: Mapping[str, object],
    ) -> dict:
        if set(payload) != {"claim", "scope"}:
            raise ValueError("scope commit payload must contain claim and scope")
        claim = SubjectClaim.model_validate(payload["claim"])
        manifest = EvaluationScopeManifest.model_validate(payload["scope"])
        return commit_evaluation_scope(ledger, claim, manifest).model_dump(
            mode="json"
        )

    def compare_scope(
        self,
        manifest_payload: Mapping[str, object],
        observed_payload: Mapping[str, object],
    ) -> dict:
        manifest = EvaluationScopeManifest.model_validate(manifest_payload)
        observed = ObservedScope.model_validate(observed_payload)
        return compare_observed_scope(manifest, observed).model_dump(mode="json")

    def commit_arm_result(
        self,
        ledger: Path,
        payload: Mapping[str, object],
    ) -> dict:
        schema = payload.get("schema_version")
        if schema == "openworkproof-verification-arm-result/0.2":
            result = VerificationArmResult.model_validate(payload)
            committed = commit_verification_arm_result(ledger, result)
        elif schema == "openworkproof-verification-arm-result/0.3":
            result = VerificationArmResultV03.model_validate(payload)
            committed = commit_verification_arm_result_v03(ledger, result)
        else:
            raise ValueError("verification arm result schema_version is unsupported")
        return committed.model_dump(mode="json")

    def prepare_decision(
        self,
        ledger: Path,
        payload: Mapping[str, object],
    ) -> dict:
        request = DecisionDraftRequest.model_validate(payload)
        connection = evidence.connect_ledger(ledger)
        try:
            v02 = connection.execute(
                "SELECT COUNT(*) FROM verification_profiles_v02"
            ).fetchone()[0]
            v03 = connection.execute(
                "SELECT COUNT(*) FROM verification_profiles_v03"
            ).fetchone()[0]
        finally:
            connection.close()
        if (v02, v03) == (1, 0):
            draft = prepare_verification_decision(ledger, request)
        elif (v02, v03) == (0, 1):
            draft = prepare_verification_decision_v03(ledger, request)
        else:
            raise ValueError("verification protocol is ambiguous")
        return draft.model_dump(mode="json")

    def commit_decision(
        self,
        ledger: Path,
        payload: Mapping[str, object],
    ) -> dict:
        schema = payload.get("schema_version")
        if schema == "openworkproof-verification-decision/0.2":
            decision = VerificationDecision.model_validate(payload)
            committed = commit_verification_decision(ledger, decision)
        elif schema == "openworkproof-verification-decision/0.3":
            decision = VerificationDecisionV03.model_validate(payload)
            committed = commit_verification_decision_v03(ledger, decision)
        else:
            raise ValueError("verification decision schema_version is unsupported")
        return committed.model_dump(mode="json")

    def build_delivery(
        self,
        ledger: Path,
        output: Path,
        privacy_view: Literal["public", "diagnostic", "customer_private"],
    ) -> dict:
        manifest = export_delivery_package(
            ledger,
            output,
            privacy_view=privacy_view,
        )
        return manifest.model_dump(mode="json")

    def audit_delivery(self, package: Path) -> dict:
        return verify_delivery_package(package).model_dump(mode="json")

    def get_settlement_readiness(self, ledger: Path) -> dict:
        return read_settlement_snapshot(ledger).model_dump(mode="json")


__all__ = ["OpenWorkProofServices"]
