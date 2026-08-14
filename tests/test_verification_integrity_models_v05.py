from __future__ import annotations

import hashlib

from openworkproof.models import (
    ActionBindingManifest,
    EvaluationScopeManifest,
    VerificationArmResultV03,
    VerificationDecisionV03,
    VerificationProfileV02,
    VerificationProfileV03,
)
from openworkproof.signing import canonical_bytes
from openworkproof.verification import verification_decision_signing_bytes_v03


def test_frozen_pre_v05_canonical_bytes_and_signatures(
    frozen_verification_profile_v02: VerificationProfileV02,
    evaluation_scope_v03: EvaluationScopeManifest,
    frozen_verification_profile_v03: VerificationProfileV03,
    frozen_verification_arm_result_v03: VerificationArmResultV03,
    frozen_verification_decision_v03: VerificationDecisionV03,
    action_binding_manifest_v04: ActionBindingManifest,
) -> None:
    actual = {
        "v02_profile_digest": hashlib.sha256(
            canonical_bytes(
                "verification-profile",
                frozen_verification_profile_v02.model_dump(mode="json"),
            )
        ).hexdigest(),
        "v02_profile_signature": frozen_verification_profile_v02.signature,
        "v03_scope_digest": hashlib.sha256(
            canonical_bytes(
                "evaluation-scope",
                evaluation_scope_v03.model_dump(mode="json"),
                version="0.3",
            )
        ).hexdigest(),
        "v03_scope_signature": evaluation_scope_v03.signature,
        "v03_profile_digest": hashlib.sha256(
            canonical_bytes(
                "verification-profile",
                frozen_verification_profile_v03.model_dump(mode="json"),
                version="0.3",
            )
        ).hexdigest(),
        "v03_profile_signature": frozen_verification_profile_v03.signature,
        "v03_arm_result_digest": hashlib.sha256(
            canonical_bytes(
                "verification-arm-result",
                frozen_verification_arm_result_v03.model_dump(mode="json"),
                version="0.3",
            )
        ).hexdigest(),
        "v03_arm_result_signature": frozen_verification_arm_result_v03.signature,
        "v03_decision_digest": hashlib.sha256(
            verification_decision_signing_bytes_v03(frozen_verification_decision_v03)
        ).hexdigest(),
        "v03_decision_signature": (
            frozen_verification_decision_v03.verifier_signatures[0].signature
        ),
        "v04_binding_digest": hashlib.sha256(
            canonical_bytes(
                "action-binding-manifest",
                action_binding_manifest_v04.model_dump(mode="json"),
                version="0.4",
            )
        ).hexdigest(),
        "v04_binding_signature": action_binding_manifest_v04.signature,
    }

    assert actual == {
        "v02_profile_digest": "38a8cb8c9a415980d8f3c9df4b7b5d08f8245b2ea124271cafed178d73315245",
        "v02_profile_signature": "fqv9pL7SPmGgYclR4NzEjTnP5SPqAxwjbfOslM6_kbfrBm3bllDy_U-bP9Pr6eoQlRKdZsDRqlL-T8wj8NAaAw",
        "v03_scope_digest": "13365cbb1a2af3a4951fc838ab07e58f63387e0cd79ca61c8635981626fa1f83",
        "v03_scope_signature": "ktEnletSX2ROHAiOeYUlX2XCg6U1b7xKEkf07TV2_zBhlhRHTg27OprAqhFrCFVyarCJ5S6oCQtxcIQpG_htAA",
        "v03_profile_digest": "4f254e559a556a3fc86cc98f5ab03bd25dbb6867f0584cc0e8dfc7c64a224ca2",
        "v03_profile_signature": "5G_YOMtMU45QiyI6nq5FCx4MyNHaARMTBNmAWngu1YZjvVZXiuhZ1TX_LKmMF-W5xqlWehPzxyLd5k6JIdLhBA",
        "v03_arm_result_digest": "62b43fa1134d7f68f51e0e7153ab43fabb9966534d338c61f6f2e112784805ef",
        "v03_arm_result_signature": "MVMhXvzqhgaiysA4Qqcv9jfY0AQqR2sDjqfHdri7dDhg4HeoICIb08FOu4whi183VmBw1AhVPnkNrvX26QXIAA",
        "v03_decision_digest": "db0c57be0f83c38b585c39f3c631b1efee83d7f87308d5c97bd5869360ccf73b",
        "v03_decision_signature": "7TS6R1-oBNStohQhx_Ce6LGdV0ucyGMhzGfeUF2IhLHoQfNYWvc2WwtGWMccicvp1c66SAZqDbYQlTIp7LSXCQ",
        "v04_binding_digest": "34b81680b9e1e5af65de11420a19154981d9f7b45ff9c8429139086e2fa253c2",
        "v04_binding_signature": "EBGSKn-kzOLdLB06vIRxr9Qrydj6jCA-xeUhRcyLx5rrTdnNWKp_uC3Co2w7Dg1xSe0Vg5gxIFtFT3b5tNUYAQ",
    }
