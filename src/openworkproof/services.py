"""Thin application facade for Evidence Lifecycle v0.2 operations."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from openworkproof.delivery_package import (
    export_delivery_package,
    verify_delivery_package,
)
from openworkproof.models import (
    DecisionDraftRequest,
    VerificationArmResult,
    VerificationDecision,
    VerificationProfileV02,
)
from openworkproof.settlement import read_settlement_snapshot
from openworkproof.verification import (
    commit_verification_arm_result,
    commit_verification_decision,
    prepare_verification_decision,
)


class OpenWorkProofServices:
    """Parse inputs, invoke one domain operation, and return JSON data."""

    def validate_profile(self, payload: Mapping[str, object]) -> dict:
        profile = VerificationProfileV02.model_validate(payload)
        return profile.model_dump(mode="json")

    def commit_arm_result(
        self,
        ledger: Path,
        payload: Mapping[str, object],
    ) -> dict:
        result = VerificationArmResult.model_validate(payload)
        return commit_verification_arm_result(ledger, result).model_dump(
            mode="json"
        )

    def prepare_decision(
        self,
        ledger: Path,
        payload: Mapping[str, object],
    ) -> dict:
        request = DecisionDraftRequest.model_validate(payload)
        return prepare_verification_decision(ledger, request).model_dump(
            mode="json"
        )

    def commit_decision(
        self,
        ledger: Path,
        payload: Mapping[str, object],
    ) -> dict:
        decision = VerificationDecision.model_validate(payload)
        return commit_verification_decision(ledger, decision).model_dump(
            mode="json"
        )

    def build_delivery(
        self,
        ledger: Path,
        output: Path,
        privacy_view: Literal["public", "customer_private"],
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
