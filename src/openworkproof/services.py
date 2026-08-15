"""Thin application facade for versioned OpenWorkProof operations."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Literal

from openworkproof import evidence, integrity
from openworkproof.delivery_package import (
    export_delivery_package,
    verify_delivery_package,
)
from openworkproof.models import (
    WorkOrder,
    DecisionDraftRequest,
    EvaluationScopeDraft,
    EvaluationScopeManifest,
    ScopeMember,
    ScopeRequirementBinding,
    ScopeSelectorRule,
    SubjectClaim,
    VerificationArmResult,
    VerificationArmResultV03,
    VerificationArmResultV05,
    VerificationDecision,
    VerificationDecisionV03,
    VerificationDecisionV05,
    VerificationProfileV02,
    VerificationProfileV03,
    VerificationProfileV05,
)
from openworkproof.binding import (
    BindingDecisionDraftRequest,
    compose_binding_decision,
    verify_binding_decision,
)
from openworkproof.binding_transactions import (
    BindingTransactionError,
    load_current_binding_decision,
)
from openworkproof.delivery_package import (
    DeliveryPackageError,
    verify_delivery_package,
)
from openworkproof.models import (
    ActionBindingManifest,
    AuthorityCheckpoint,
    BindingDecision,
    JudgmentCommitment,
    ToolCallReceiptV04,
    RollbackReceiptV04,
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
    commit_verification_arm_result_v05,
    commit_verification_decision,
    commit_verification_decision_v03,
    commit_verification_decision_v05,
    prepare_verification_decision,
    prepare_verification_decision_v03,
    prepare_verification_decision_v05,
)




class _ReplayView:
    """Minimal replay view for the service facade (Task 13)."""

    def __init__(self, *, outcome: str, reason_codes: tuple[str, ...], replay_digest: str) -> None:
        self.outcome = outcome
        self.reason_codes = reason_codes
        self.replay_digest = replay_digest


def _decode_public_key(value: object):
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("authority_key must be a base64url string")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )
    import base64 as _b64

    raw = _b64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    return Ed25519PublicKey.from_public_bytes(raw)


def _b64url_decode(value: object) -> bytes:
    import base64 as _b64m

    if type(value) is not str:
        raise ValueError("evidence inventory value is not unpadded base64url")
    padded = value + "=" * (-len(value) % 4)
    try:
        raw = _b64m.urlsafe_b64decode(padded)
    except (ValueError, _b64m.binascii.Error) as error:
        raise ValueError("evidence inventory value is not valid base64url") from error
    if _b64m.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise ValueError("evidence inventory value is not unpadded base64url")
    return raw


def _require(payload: Mapping[str, object], key: str) -> object:
    try:
        return payload[key]
    except (KeyError, TypeError):
        raise ValueError(f"payload is missing a required field: {key}") from None


class OpenWorkProofServices:
    """Parse inputs, invoke one domain operation, and return JSON data."""

    def validate_profile(self, payload: Mapping[str, object]) -> dict:
        schema = payload.get("schema_version")
        if schema == "openworkproof-verification-profile/0.2":
            model = VerificationProfileV02
        elif schema == "openworkproof-verification-profile/0.3":
            model = VerificationProfileV03
        elif schema == "openworkproof-verification-profile/0.5":
            model = VerificationProfileV05
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
        elif schema == "openworkproof-verification-arm-result/0.5":
            result = VerificationArmResultV05.model_validate(payload)
            committed = commit_verification_arm_result_v05(ledger, result)
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
            v05 = connection.execute(
                "SELECT COUNT(*) FROM verification_profiles_v05"
            ).fetchone()[0]
        finally:
            connection.close()
        if (v02, v03, v05) == (1, 0, 0):
            draft = prepare_verification_decision(ledger, request)
        elif (v02, v03, v05) == (0, 1, 0):
            draft = prepare_verification_decision_v03(ledger, request)
        elif (v02, v03, v05) == (0, 0, 1):
            draft = prepare_verification_decision_v05(ledger, request)
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
        elif schema == "openworkproof-verification-decision/0.5":
            decision = VerificationDecisionV05.model_validate(payload)
            committed = commit_verification_decision_v05(ledger, decision)
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

    def validate_population_observation(
        self, payload: Mapping[str, object]
    ) -> dict:
        """Assess v0.5 population observations without checking authority.

        The population status is derived from the signed inputs and replayed
        evidence only; signer authority is reported as ``not_checked``, never
        as validly authorized.
        """
        profile = VerificationProfileV05.model_validate(
            _require(payload, "profile")
        )
        manifest = EvaluationScopeManifest.model_validate(
            _require(payload, "manifest")
        )
        raw_results = _require(payload, "results")
        if not isinstance(raw_results, list):
            raise ValueError("results must be a JSON array of v0.5 arm results")
        results = tuple(
            VerificationArmResultV05.model_validate(item)
            for item in raw_results
        )
        raw_outputs = payload.get("rule_outputs")
        rule_outputs: dict[str, tuple[str, ...]] | None = None
        if raw_outputs is not None:
            if not isinstance(raw_outputs, Mapping):
                raise ValueError("rule_outputs must be a JSON object")
            rule_outputs = {}
            for key, value in raw_outputs.items():
                if type(value) not in {list, tuple}:
                    raise ValueError("rule output entries must be arrays")
                if any(type(item) is not str for item in value):
                    raise ValueError("rule output entries must be strings")
                rule_outputs[str(key)] = tuple(value)
        raw_inventory = payload.get("evidence_inventory")
        inventory: dict[str, bytes] | None = None
        if raw_inventory is not None:
            if not isinstance(raw_inventory, Mapping):
                raise ValueError("evidence_inventory must be a JSON object")
            inventory = {
                str(key): _b64url_decode(value)
                for key, value in raw_inventory.items()
            }
        assessment = integrity.assess_population_integrity(
            profile,
            manifest,
            results,
            rule_outputs=rule_outputs,
            evidence_inventory=inventory,
        )
        return {
            "valid": True,
            "authority": "not_checked",
            "population_status": assessment.status,
            "reason_codes": list(assessment.reason_codes),
        }

    def validate_control_observation(
        self, payload: Mapping[str, object]
    ) -> dict:
        """Assess v0.5 control observations without checking authority.

        The control status is derived from the signed inputs; signer
        authority is reported as ``not_checked``, never as validly
        authorized. ``proven`` additionally requires the evidence content
        to resolve through the supplied evidence inventory (canonical
        bytes, closed resolver, and the facts == observation == expected
        closure); without an inventory the status is never proven and
        ``evidence`` is reported as ``not_checked``.
        """
        profile = VerificationProfileV05.model_validate(
            _require(payload, "profile")
        )
        raw_results = _require(payload, "results")
        if not isinstance(raw_results, list):
            raise ValueError("results must be a JSON array of v0.5 arm results")
        results = tuple(
            VerificationArmResultV05.model_validate(item)
            for item in raw_results
        )
        raw_inventory = payload.get("evidence_inventory")
        inventory: dict[str, bytes] | None = None
        if raw_inventory is not None:
            if not isinstance(raw_inventory, Mapping):
                raise ValueError("evidence_inventory must be a JSON object")
            inventory = {
                str(key): _b64url_decode(value)
                for key, value in raw_inventory.items()
            }
        assessment = integrity.assess_control_integrity(
            profile,
            results,
            evidence_inventory=inventory,
        )
        return {
            "valid": True,
            "authority": "not_checked",
            "control_status": assessment.status,
            "reason_codes": list(assessment.reason_codes),
            "evidence": "checked" if inventory is not None else "not_checked",
        }

    def explain_integrity_package(self, package: Path) -> dict:
        """Derive the v0.5 integrity explanation from package bytes."""
        from openworkproof.delivery_package import explain_integrity_package

        return explain_integrity_package(package)

    def get_settlement_readiness(self, ledger: Path) -> dict:
        return read_settlement_snapshot(ledger).model_dump(mode="json")



    # ------------------------------------------------------------------
    # v0.4 judgment-to-action binding interfaces (Task 13)
    # ------------------------------------------------------------------

    def validate_judgment_commitment(
        self, payload: Mapping[str, object]
    ) -> dict:
        """Validate one signed JudgmentCommitment without any authority.

        Without a ledger or trusted key context the authority is reported
        as ``not_checked``, never as validly authorized.
        """
        judgment = JudgmentCommitment.model_validate(dict(payload))
        return {
            "valid": True,
            "object_type": "judgment_commitment",
            "schema_version": judgment.schema_version,
            "digest": judgment.digest,
            "authority": "not_checked",
        }

    def validate_action_binding_manifest(
        self, payload: Mapping[str, object]
    ) -> dict:
        """Validate one signed ActionBindingManifest without any authority."""
        manifest = ActionBindingManifest.model_validate(dict(payload))
        return {
            "valid": True,
            "object_type": "action_binding_manifest",
            "schema_version": manifest.schema_version,
            "digest": manifest.digest,
            "authority": "not_checked",
        }

    def compose_binding(self, payload: Mapping[str, object]) -> dict:
        """Compose a BindingDecision draft from signed inputs."""
        request_payload = payload["request"]
        draft = compose_binding_decision(
            judgment=JudgmentCommitment.model_validate(
                dict(payload["judgment"])
            ),
            manifest=ActionBindingManifest.model_validate(
                dict(payload["manifest"])
            ),
            verification=VerificationDecisionV03.model_validate(
                dict(payload["verification"])
            ),
            receipts=tuple(
                ToolCallReceiptV04.model_validate(receipt)
                if receipt.get("event_type") == "tool_call"
                else RollbackReceiptV04.model_validate(receipt)
                for receipt in payload["receipts"]
            ),
            replay=_ReplayView(
                outcome=str(payload["replay"]["outcome"]),
                reason_codes=tuple(payload["replay"]["reason_codes"]),
                replay_digest=str(payload["replay"]["replay_digest"]),
            ),
            checkpoint=(
                AuthorityCheckpoint.model_validate(dict(payload["checkpoint"]))
                if payload.get("checkpoint") is not None
                else None
            ),
            request=BindingDecisionDraftRequest(
                **dict(request_payload)
            ),
            checkpoint_chain=tuple(
                AuthorityCheckpoint.model_validate(checkpoint)
                for checkpoint in payload.get("checkpoint_chain", ())
            ),
            authority_key=_decode_public_key(payload.get("authority_key")),
            resolver_unavailable=bool(
                payload.get("resolver_unavailable", False)
            ),
        )
        return draft.model_dump(mode="json")

    def verify_binding(self, payload: Mapping[str, object]) -> dict:
        """Verify a signed BindingDecision against an external trust map."""
        decision = BindingDecision.model_validate(dict(payload["decision"]))
        work_order = WorkOrder.model_validate(dict(payload["work_order"]))
        public_keys = {
            str(key_id): _decode_public_key(value)
            for key_id, value in payload["public_keys"].items()
        }
        ok = verify_binding_decision(
            decision,
            work_order=work_order,
            public_keys=public_keys,
            expected_signatures=int(payload["expected_signatures"]),
        )
        return {"valid": bool(ok)}

    def binding_history(self, ledger_path: str) -> dict:
        """Read the current binding decision head for the authoritative
        WorkOrder (read-only; never commits)."""
        path = Path(ledger_path)
        connection = evidence.connect_ledger(path)
        try:
            work_order = evidence.load_authoritative_work_order(connection)
        except Exception as error:
            raise ValueError("binding ledger is unavailable") from error
        finally:
            connection.close()
        try:
            current = load_current_binding_decision(
                path, work_order.digest
            )
        except BindingTransactionError as error:
            raise ValueError("binding history is not readable") from error
        if current is None:
            return {"current": None}
        return {
            "current": current.model_dump(mode="json"),
            "work_order_digest": work_order.digest,
        }

    def replay_binding_package(self, package_path: str) -> dict:
        """Replay one v0.4 delivery package offline (read-only)."""
        try:
            result = verify_delivery_package(Path(package_path))
        except DeliveryPackageError as error:
            raise ValueError("binding package replay failed") from error
        return result.model_dump(mode="json")


__all__ = ["OpenWorkProofServices"]
