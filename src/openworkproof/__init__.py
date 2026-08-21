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
}


def __getattr__(name: str):
    try:
        module_name, attribute = _LAZY_EXPORTS[name]
    except KeyError as error:
        raise AttributeError(name) from error
    value = getattr(import_module(module_name), attribute)
    globals()[name] = value
    return value

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
]
