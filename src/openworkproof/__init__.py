__version__ = "1.1.1"

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
    "validate_evaluation_scope",
]
