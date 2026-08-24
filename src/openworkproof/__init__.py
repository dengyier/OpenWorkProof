__version__ = "1.3.0"

from importlib import import_module


_LAZY_EXPORTS = {
    "build_evaluation_scope": ("openworkproof.scope", "build_evaluation_scope"),
    "compare_observed_scope": ("openworkproof.scope", "compare_observed_scope"),
    "validate_evaluation_scope": (
        "openworkproof.scope",
        "validate_evaluation_scope",
    ),
    "commit_evaluation_scope": (
        "openworkproof.verification",
        "commit_evaluation_scope",
    ),
    "load_evaluation_scope": (
        "openworkproof.verification",
        "load_evaluation_scope",
    ),
    "build_surface_bundle": (
        "openworkproof.surface_bundle",
        "build_surface_bundle",
    ),
    "verify_surface_bundle": (
        "openworkproof.surface_bundle",
        "verify_surface_bundle",
    ),
    "export_acceptance_bundle": (
        "openworkproof.acceptance_bundle",
        "export_acceptance_bundle",
    ),
    "verify_acceptance_bundle_directory": (
        "openworkproof.acceptance_bundle",
        "verify_acceptance_bundle_directory",
    ),
    "DeliveryCaseError": ("openworkproof.delivery_case", "DeliveryCaseError"),
    "DeliveryCaseManifestV01": (
        "openworkproof.delivery_case",
        "DeliveryCaseManifestV01",
    ),
    "DeliveryCaseResultV01": (
        "openworkproof.delivery_case",
        "DeliveryCaseResultV01",
    ),
    "initialize_delivery_case": (
        "openworkproof.delivery_case",
        "initialize_delivery_case",
    ),
    "inspect_delivery_case": (
        "openworkproof.delivery_case",
        "inspect_delivery_case",
    ),
    "export_delivery_case": (
        "openworkproof.delivery_case",
        "export_delivery_case",
    ),
    "verify_exported_delivery_case": (
        "openworkproof.delivery_case",
        "verify_exported_delivery_case",
    ),
    "HumanAgencyProfileV01": (
        "openworkproof.agency",
        "HumanAgencyProfileV01",
    ),
    "AgencyProfileTransitionV01": (
        "openworkproof.agency",
        "AgencyProfileTransitionV01",
    ),
    "AgencyAppealV01": ("openworkproof.agency", "AgencyAppealV01"),
    "commit_human_agency_profile": (
        "openworkproof.agency_ledger",
        "commit_human_agency_profile",
    ),
    "commit_agency_profile_transition": (
        "openworkproof.agency_ledger",
        "commit_agency_profile_transition",
    ),
    "commit_agency_appeal": (
        "openworkproof.agency_ledger",
        "commit_agency_appeal",
    ),
    "load_agency_history": (
        "openworkproof.agency_ledger",
        "load_agency_history",
    ),
    "load_current_human_agency_profile": (
        "openworkproof.agency_ledger",
        "load_current_human_agency_profile",
    ),
    "load_agency_appeals": (
        "openworkproof.agency_ledger",
        "load_agency_appeals",
    ),
    "authorize_tool_call_with_agency_profile": (
        "openworkproof.agency_policy",
        "authorize_tool_call_with_agency_profile",
    ),
    "dispatch_protected_agent_action": (
        "openworkproof.mcp_server",
        "dispatch_protected_agent_action",
    ),
    "export_agency_bundle": (
        "openworkproof.agency_bundle",
        "export_agency_bundle",
    ),
    "verify_agency_bundle_directory": (
        "openworkproof.agency_bundle",
        "verify_agency_bundle_directory",
    ),
    "AgencyBundleManifestV01": (
        "openworkproof.agency_bundle",
        "AgencyBundleManifestV01",
    ),
    "AgencyBundleVerificationResultV01": (
        "openworkproof.agency_bundle",
        "AgencyBundleVerificationResultV01",
    ),
}


def __getattr__(name: str):
    try:
        module_name, attribute = _LAZY_EXPORTS[name]
    except KeyError as error:
        raise AttributeError(name) from error
    value = getattr(import_module(module_name), attribute)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    # Side-effect-free: list the lazy public names from ``__all__`` without
    # importing any lazy module or triggering ``__getattr__``.
    return sorted(set(globals()) | set(__all__))


__all__ = [
    "__version__",
    "build_evaluation_scope",
    "commit_evaluation_scope",
    "compare_observed_scope",
    "load_evaluation_scope",
    "build_surface_bundle",
    "export_acceptance_bundle",
    "verify_surface_bundle",
    "verify_acceptance_bundle_directory",
    "validate_evaluation_scope",
    "DeliveryCaseError",
    "DeliveryCaseManifestV01",
    "DeliveryCaseResultV01",
    "initialize_delivery_case",
    "inspect_delivery_case",
    "export_delivery_case",
    "verify_exported_delivery_case",
    "HumanAgencyProfileV01",
    "AgencyProfileTransitionV01",
    "AgencyAppealV01",
    "commit_human_agency_profile",
    "commit_agency_profile_transition",
    "commit_agency_appeal",
    "load_agency_history",
    "load_current_human_agency_profile",
    "load_agency_appeals",
    "authorize_tool_call_with_agency_profile",
    "dispatch_protected_agent_action",
    "export_agency_bundle",
    "verify_agency_bundle_directory",
    "AgencyBundleManifestV01",
    "AgencyBundleVerificationResultV01",
]
