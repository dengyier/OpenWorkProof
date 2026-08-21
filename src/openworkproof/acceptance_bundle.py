"""Offline-verifiable OpenWorkProof acceptance bundles (0.1)."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BeforeValidator, ConfigDict, model_validator

from openworkproof.models import Digest64, ProtocolModel, SafeNonNegativeInt


__all__ = [
    "AcceptanceBundleVerificationResult",
    "AcceptanceManifestEntry",
    "AcceptanceManifestV01",
]


def _acceptance_relative_path(value: Any) -> str:
    if type(value) is not str:
        raise ValueError("acceptance bundle path must be a strict string")
    if not value or len(value.encode("utf-8")) > 512:
        raise ValueError("acceptance bundle path length is invalid")
    if (
        value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or "//" in value
    ):
        raise ValueError("acceptance bundle path is not canonical relative POSIX")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("acceptance bundle path contains an unsafe segment")
    return value


AcceptanceRelativePath = Annotated[
    str,
    BeforeValidator(_acceptance_relative_path),
]

_ACCEPTANCE_BUNDLE_CONFIG = ConfigDict(
    extra="forbid",
    frozen=True,
    strict=True,
    validate_assignment=True,
    revalidate_instances="subclass-instances",
)


class AcceptanceManifestEntry(ProtocolModel):
    model_config = _ACCEPTANCE_BUNDLE_CONFIG

    path: AcceptanceRelativePath
    sha256: Digest64
    size_bytes: SafeNonNegativeInt


class AcceptanceManifestV01(ProtocolModel):
    model_config = _ACCEPTANCE_BUNDLE_CONFIG

    schema_version: Literal["openworkproof-acceptance-bundle/0.1"]
    surface_manifest_digest: Digest64
    delivery_manifest_digest: Digest64
    work_order_digest: Digest64
    verification_decision_digest: Digest64
    composition_report_digest: Digest64
    terminal_decision: Literal["accepted", "rejected"]
    terminal_receipt_digest: Digest64
    acceptance_decision_binding_digest: Digest64
    entries: tuple[AcceptanceManifestEntry, ...]

    @model_validator(mode="after")
    def _closed_manifest(self) -> AcceptanceManifestV01:
        paths = tuple(entry.path for entry in self.entries)
        if not paths or paths != tuple(
            sorted(set(paths), key=lambda item: item.encode("utf-8"))
        ):
            raise ValueError(
                "acceptance bundle entries must be non-empty, sorted, and unique"
            )
        return self


class AcceptanceBundleVerificationResult(ProtocolModel):
    model_config = _ACCEPTANCE_BUNDLE_CONFIG

    schema_version: Literal["openworkproof-acceptance-bundle-result/0.1"]
    terminal_decision: Literal["ACCEPTED", "REJECTED"]
    work_order_digest: Digest64
    surface_manifest_digest: Digest64
    verification_decision_digest: Digest64
    terminal_receipt_digest: Digest64
    acceptance_decision_binding_digest: Digest64
    boundary: Literal[
        "not payment, settlement, legal audit, or adoption"
    ]
