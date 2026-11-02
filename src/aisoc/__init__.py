"""aisoc: AI-IDPS (dual_model) + constrained Agent sandbox + OpenWorkProof-aligned evidence chain.

Reference implementation of the architecture described in
"AI Security and Ethical Governance: dual_model, Agent impact limitation and
OpenWorkProof for a verifiable AI SOC". Synthetic data and stub agents only.
"""

from .soc import AISOC, CaseResult, conservative_human

__all__ = ["AISOC", "CaseResult", "conservative_human"]
__version__ = "0.1.0"
