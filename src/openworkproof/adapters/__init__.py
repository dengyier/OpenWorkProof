"""Deterministic domain adapters for judgment-to-action binding."""

from openworkproof.adapters.code_delivery_github import (
    ADAPTER_ID,
    ADAPTER_VERSION,
    BindingReplayResult,
    CodeDeliveryAdapterProfile,
    CodeDeliveryJudgmentInput,
    CodeDeliveryReplayInput,
    NormalizedJudgment,
    ObservedAction,
    action_constraint_digest,
    normalize_code_delivery_judgment,
    replay_code_delivery_binding,
)

__all__ = [
    "ADAPTER_ID",
    "ADAPTER_VERSION",
    "BindingReplayResult",
    "CodeDeliveryAdapterProfile",
    "CodeDeliveryJudgmentInput",
    "CodeDeliveryReplayInput",
    "NormalizedJudgment",
    "ObservedAction",
    "action_constraint_digest",
    "normalize_code_delivery_judgment",
    "replay_code_delivery_binding",
]
