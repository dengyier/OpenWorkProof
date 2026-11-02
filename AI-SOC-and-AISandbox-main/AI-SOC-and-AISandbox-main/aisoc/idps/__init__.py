"""AI-IDPS: dual_model detection (known-pattern branch + normality branch)."""

from .dual_model import MODEL_FILE_SCHEMA, CaseDecision, CaseStatus, DualModel, ExternalAnomaly, ExternalKnown
from .features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, FlowRecord, featurize
from .known_model import BENIGN, KnownModel
from .normality_model import NormalityModel
from .release import MODEL_RELEASE_ROLE, ModelReleaseError, load_verified_model, release_model

__all__ = [
    "BENIGN",
    "CaseDecision",
    "CaseStatus",
    "DualModel",
    "ExternalAnomaly",
    "ExternalKnown",
    "FEATURE_NAMES",
    "FEATURE_SCHEMA_VERSION",
    "FlowRecord",
    "KnownModel",
    "MODEL_FILE_SCHEMA",
    "MODEL_RELEASE_ROLE",
    "ModelReleaseError",
    "NormalityModel",
    "featurize",
    "load_verified_model",
    "release_model",
]
