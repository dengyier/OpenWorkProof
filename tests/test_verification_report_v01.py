"""Deterministic verification report (0.1) tests.

The VerificationReportV01 is a derived offline-replay view, not a new
authorization or acceptance truth.  This module exercises the fail-closed
three-state combination rules, the canonical replay digest, and the static
no-script HTML renderer.  All keys, digests and revisions below are synthetic
test-only constants and MUST NOT be used as real OpenWorkProof credentials.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from openworkproof.delivery_package import DeliverySurfaceFacts
from openworkproof.delivery_package import (
    export_delivery_package,
    load_surface_facts,
)
from openworkproof.environment_fingerprint import (
    EnvironmentFingerprintPayloadV01,
    SignedEnvironmentFingerprintV01,
    sign_environment_fingerprint,
    verify_environment_fingerprint,
)
from openworkproof.signing import key_id
from openworkproof.verification_report import (
    VerificationReportV01,
    compose_verification_report,
    render_report_html,
)

from test_acceptance_v05 import _commit_v05_decision
from test_verification_integrity_transactions_v05 import (
    v05_transaction_case,
    verification_profile_v03,
)


REPORT_SCHEMA_VERSION = "openworkproof-verification-report/0.1"
RENDERER_VERSION = "openworkproof-report-renderer/0.1"
SOURCE_REVISION = "0" * 40
BUNDLE_DIGEST = "3" * 64
WORK_ORDER_DIGEST = "1" * 64
DECISION_DIGEST = "2" * 64
EVIDENCE_CLOSED_AT = "2026-01-01T00:20:00Z"

_KEY_A = Ed25519PrivateKey.from_private_bytes(bytes([0x42]) * 32)
_KEY_B = Ed25519PrivateKey.from_private_bytes(bytes([0x99]) * 32)
_KEY_UNTRUSTED = Ed25519PrivateKey.from_private_bytes(bytes([0x33]) * 32)


def _actor_id(key: Ed25519PrivateKey) -> str:
    if key is _KEY_A:
        return "verifier-a"
    if key is _KEY_B:
        return "verifier-b"
    return "verifier-untrusted"


def _complete_payload(
    source_revision: str = SOURCE_REVISION, **overrides: Any
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "openworkproof-execution-environment/0.1",
        "source_revision": source_revision,
        "runner_os": "linux",
        "runner_arch": "amd64",
        "runner_image_digest": "a" * 64,
        "container_image_digest": "b" * 64,
        "toolchain_lock_digest": "c" * 64,
        "command_digest": "d" * 64,
        "arguments_digest": "e" * 64,
        "environment_allowlist_digest": "f" * 64,
        "sandbox_policy_digest": "0" * 64,
        "workflow_identity_digest": "1" * 64,
        "collection_status": "complete",
        "missing_reason_codes": [],
        "collected_at": "2026-01-01T00:00:00Z",
        "collector_actor_id": "verifier",
    }
    payload.update(overrides)
    return payload


def _partial_payload(source_revision: str = SOURCE_REVISION) -> dict[str, Any]:
    return _complete_payload(
        source_revision=source_revision,
        collection_status="partial",
        runner_image_digest=None,
        toolchain_lock_digest=None,
        missing_reason_codes=[
            "RUNNER_IMAGE_UNAVAILABLE",
            "TOOLCHAIN_LOCK_UNAVAILABLE",
        ],
    )


def _unavailable_payload(source_revision: str = SOURCE_REVISION) -> dict[str, Any]:
    return _complete_payload(
        source_revision=source_revision,
        collection_status="unavailable",
        runner_image_digest=None,
        container_image_digest=None,
        toolchain_lock_digest=None,
        sandbox_policy_digest=None,
        workflow_identity_digest=None,
        missing_reason_codes=[
            "CONTAINER_DIGEST_UNAVAILABLE",
            "RUNNER_IMAGE_UNAVAILABLE",
            "SANDBOX_POLICY_UNAVAILABLE",
            "TOOLCHAIN_LOCK_UNAVAILABLE",
            "WORKFLOW_IDENTITY_UNVERIFIED",
        ],
    )


def _complete(
    key: Ed25519PrivateKey,
    source_revision: str = SOURCE_REVISION,
) -> SignedEnvironmentFingerprintV01:
    payload = EnvironmentFingerprintPayloadV01.model_validate(
        _complete_payload(
            source_revision=source_revision,
            collector_actor_id=_actor_id(key),
        )
    )
    return sign_environment_fingerprint(payload, key)


def _partial(key: Ed25519PrivateKey) -> SignedEnvironmentFingerprintV01:
    payload = EnvironmentFingerprintPayloadV01.model_validate(
        _partial_payload() | {"collector_actor_id": _actor_id(key)}
    )
    return sign_environment_fingerprint(payload, key)


def _unavailable(key: Ed25519PrivateKey) -> SignedEnvironmentFingerprintV01:
    payload = EnvironmentFingerprintPayloadV01.model_validate(
        _unavailable_payload() | {"collector_actor_id": _actor_id(key)}
    )
    return sign_environment_fingerprint(payload, key)


def _facts(
    *,
    decision: str = "VERIFIED",
    risk_class: str = "standard",
    keys: tuple[Ed25519PrivateKey, ...] = (_KEY_A,),
    source_revision: str = SOURCE_REVISION,
) -> DeliverySurfaceFacts:
    trusted = {key_id(key.public_key()): key.public_key() for key in keys}
    trusted_subjects = {
        key_id(key.public_key()): _actor_id(key)
        for key in keys
    }
    return DeliverySurfaceFacts(
        decision=decision,  # type: ignore[arg-type]
        reason_codes=(),
        work_order_digest=WORK_ORDER_DIGEST,
        source_revision=source_revision,
        risk_class=risk_class,  # type: ignore[arg-type]
        decision_digests=(DECISION_DIGEST,),
        acceptance_receipt_digest=None,
        evidence_closed_at=EVIDENCE_CLOSED_AT,
        trusted_verifier_keys=trusted,
        trusted_verifier_subjects=trusted_subjects,
    )


COMPLETE_A = _complete(_KEY_A)
COMPLETE_B = _complete(_KEY_B)
PARTIAL_A = _partial(_KEY_A)
UNAVAILABLE_A = _unavailable(_KEY_A)


# --------------------------------------------------------------------------- #
# 1. fail-closed three-state combination
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("facts", "fingerprints", "expected"),
    [
        (_facts(decision="REFUTED"), (), "REFUTED"),
        (_facts(decision="UNKNOWN"), (), "UNKNOWN"),
        (_facts(decision="VERIFIED", risk_class="standard"), (COMPLETE_A,), "VERIFIED"),
        (
            _facts(decision="VERIFIED", risk_class="high_risk"),
            (COMPLETE_A,),
            "UNKNOWN",
        ),
        (
            _facts(decision="VERIFIED", risk_class="high_risk", keys=(_KEY_A, _KEY_B)),
            (COMPLETE_A, COMPLETE_B),
            "VERIFIED",
        ),
        (_facts(decision="VERIFIED", risk_class="standard"), (PARTIAL_A,), "UNKNOWN"),
    ],
)
def test_report_status_is_fail_closed(facts, fingerprints, expected) -> None:
    report = compose_verification_report(
        facts, fingerprints, bundle_digest=BUNDLE_DIGEST
    )
    assert report.decision_status == expected


def test_verified_standard_has_no_reason_codes() -> None:
    report = compose_verification_report(
        _facts(decision="VERIFIED", risk_class="standard"),
        (COMPLETE_A,),
        bundle_digest=BUNDLE_DIGEST,
    )
    assert report.decision_status == "VERIFIED"
    assert report.reason_codes == ()


def test_report_composes_from_verified_private_package(
    v05_transaction_case,
) -> None:
    case = dict(v05_transaction_case)
    _commit_v05_decision(case)
    package_root = case["tmp_path"] / "report-source-package"
    export_delivery_package(
        case["ledger"], package_root, privacy_view="customer_private"
    )
    facts = load_surface_facts(package_root)
    verifier_key = case["keys"]["Verifier"][0]
    verifier_key_id = key_id(verifier_key.public_key())
    payload = EnvironmentFingerprintPayloadV01.model_validate(
        _complete_payload(
            source_revision=facts.source_revision,
            collector_actor_id=facts.trusted_verifier_subjects[verifier_key_id],
        )
    )
    fingerprint = sign_environment_fingerprint(payload, verifier_key)
    report = compose_verification_report(
        facts,
        (fingerprint,),
        bundle_digest=hashlib.sha256(
            (package_root / "manifest.json").read_bytes()
        ).hexdigest(),
    )
    assert report.decision_status == "VERIFIED"
    assert report.work_order_digest == facts.work_order_digest
    assert report.environment_fingerprint_digests == (fingerprint.digest,)


def test_high_risk_single_fingerprint_is_count_insufficient() -> None:
    report = compose_verification_report(
        _facts(decision="VERIFIED", risk_class="high_risk"),
        (COMPLETE_A,),
        bundle_digest=BUNDLE_DIGEST,
    )
    assert report.decision_status == "UNKNOWN"
    assert report.reason_codes == ("ENVIRONMENT_COUNT_INSUFFICIENT",)


def test_high_risk_two_distinct_verified_fingerprints() -> None:
    report = compose_verification_report(
        _facts(
            decision="VERIFIED",
            risk_class="high_risk",
            keys=(_KEY_A, _KEY_B),
        ),
        (COMPLETE_A, COMPLETE_B),
        bundle_digest=BUNDLE_DIGEST,
    )
    assert report.decision_status == "VERIFIED"
    assert report.reason_codes == ()


def test_duplicate_same_key_does_not_satisfy_high_risk() -> None:
    report = compose_verification_report(
        _facts(
            decision="VERIFIED",
            risk_class="high_risk",
            keys=(_KEY_A, _KEY_B),
        ),
        (COMPLETE_A, COMPLETE_A),
        bundle_digest=BUNDLE_DIGEST,
    )
    assert report.decision_status == "UNKNOWN"
    assert report.reason_codes == ("ENVIRONMENT_COUNT_INSUFFICIENT",)


def test_partial_and_unavailable_are_always_unknown() -> None:
    for fingerprint in (PARTIAL_A, UNAVAILABLE_A):
        report = compose_verification_report(
            _facts(decision="VERIFIED", risk_class="standard"),
            (fingerprint,),
            bundle_digest=BUNDLE_DIGEST,
        )
        assert report.decision_status == "UNKNOWN"
        assert report.reason_codes == (
            "ENVIRONMENT_COUNT_INSUFFICIENT",
            "ENVIRONMENT_INCOMPLETE",
        )


# --------------------------------------------------------------------------- #
# 2. source revision, signature and trust failures
# --------------------------------------------------------------------------- #


def test_source_revision_mismatch_is_unknown() -> None:
    other = _complete(_KEY_A, source_revision="1" * 40)
    report = compose_verification_report(
        _facts(decision="VERIFIED", risk_class="standard"),
        (other,),
        bundle_digest=BUNDLE_DIGEST,
    )
    assert report.decision_status == "UNKNOWN"
    assert report.reason_codes == (
        "ENVIRONMENT_COUNT_INSUFFICIENT",
        "ENVIRONMENT_SOURCE_MISMATCH",
    )


def test_two_fingerprints_with_inconsistent_source_revision_is_unknown() -> None:
    first = _complete(_KEY_A, source_revision=SOURCE_REVISION)
    second = _complete(_KEY_B, source_revision="1" * 40)
    report = compose_verification_report(
        _facts(
            decision="VERIFIED",
            risk_class="high_risk",
            keys=(_KEY_A, _KEY_B),
        ),
        (first, second),
        bundle_digest=BUNDLE_DIGEST,
    )
    assert report.decision_status == "UNKNOWN"
    assert "ENVIRONMENT_SOURCE_MISMATCH" in report.reason_codes


def test_bad_signature_is_unknown() -> None:
    signed = _complete(_KEY_A)
    tampered = signed.model_copy(
        update={"signature": "A" * 86}
    )
    report = compose_verification_report(
        _facts(decision="VERIFIED", risk_class="standard"),
        (tampered,),
        bundle_digest=BUNDLE_DIGEST,
    )
    assert report.decision_status == "UNKNOWN"
    assert report.reason_codes == (
        "ENVIRONMENT_COUNT_INSUFFICIENT",
        "ENVIRONMENT_SIGNATURE_INVALID",
    )


def test_untrusted_key_is_unknown() -> None:
    signed = _complete(_KEY_UNTRUSTED)
    report = compose_verification_report(
        _facts(decision="VERIFIED", risk_class="standard", keys=(_KEY_A,)),
        (signed,),
        bundle_digest=BUNDLE_DIGEST,
    )
    assert report.decision_status == "UNKNOWN"
    assert report.reason_codes == (
        "ENVIRONMENT_COUNT_INSUFFICIENT",
        "ENVIRONMENT_SIGNATURE_INVALID",
    )


def test_refuted_and_unknown_priorities_ignore_environment() -> None:
    for decision, code in (
        ("REFUTED", "DELIVERY_REFUTED"),
        ("UNKNOWN", "DELIVERY_UNKNOWN"),
    ):
        report = compose_verification_report(
            _facts(decision=decision, risk_class="standard"),
            (COMPLETE_A,),
            bundle_digest=BUNDLE_DIGEST,
        )
        assert report.decision_status == decision
        assert report.reason_codes == (code,)


def test_refuted_still_audits_supplied_environment_signature() -> None:
    tampered = COMPLETE_A.model_copy(update={"signature": "A" * 86})
    report = compose_verification_report(
        _facts(decision="REFUTED"),
        (tampered,),
        bundle_digest=BUNDLE_DIGEST,
    )
    assert report.decision_status == "REFUTED"
    assert report.reason_codes == (
        "DELIVERY_REFUTED",
        "ENVIRONMENT_SIGNATURE_INVALID",
    )


def test_collector_actor_must_match_signed_profile_subject() -> None:
    payload = EnvironmentFingerprintPayloadV01.model_validate(
        _complete_payload(collector_actor_id="forged-verifier")
    )
    signed = sign_environment_fingerprint(payload, _KEY_A)
    report = compose_verification_report(
        _facts(decision="VERIFIED", risk_class="standard"),
        (signed,),
        bundle_digest=BUNDLE_DIGEST,
    )
    assert report.decision_status == "UNKNOWN"
    assert "ENVIRONMENT_SUBJECT_MISMATCH" in report.reason_codes


def test_hostile_subject_mapping_fails_closed() -> None:
    class HostileSubjects(dict):
        def get(self, key, default=None):
            raise RuntimeError("hostile mapping")

    facts = replace(
        _facts(decision="VERIFIED", risk_class="standard"),
        trusted_verifier_subjects=HostileSubjects(),
    )
    report = compose_verification_report(
        facts,
        (COMPLETE_A,),
        bundle_digest=BUNDLE_DIGEST,
    )
    assert report.decision_status == "UNKNOWN"
    assert "ENVIRONMENT_SUBJECT_MISMATCH" in report.reason_codes


# --------------------------------------------------------------------------- #
# 3. canonical replay digest and determinism
# --------------------------------------------------------------------------- #


def test_replay_result_digest_excludes_itself() -> None:
    report = compose_verification_report(
        _facts(decision="VERIFIED", risk_class="standard"),
        (COMPLETE_A,),
        bundle_digest=BUNDLE_DIGEST,
    )
    payload = report.model_dump(mode="json", exclude={"replay_result_digest"})
    expected = hashlib.sha256(rfc8785.dumps(payload)).hexdigest()
    assert report.replay_result_digest == expected


def test_compose_is_deterministic() -> None:
    facts = _facts(decision="VERIFIED", risk_class="high_risk", keys=(_KEY_A, _KEY_B))
    first = compose_verification_report(
        facts, (COMPLETE_A, COMPLETE_B), bundle_digest=BUNDLE_DIGEST
    )
    second = compose_verification_report(
        facts, (COMPLETE_A, COMPLETE_B), bundle_digest=BUNDLE_DIGEST
    )
    assert first == second
    assert first.replay_result_digest == second.replay_result_digest


def test_evidence_closed_at_comes_from_facts_not_wall_clock() -> None:
    report = compose_verification_report(
        _facts(decision="VERIFIED", risk_class="standard"),
        (COMPLETE_A,),
        bundle_digest=BUNDLE_DIGEST,
    )
    assert report.model_dump(mode="json")["evidence_closed_at"] == EVIDENCE_CLOSED_AT


def test_bundle_digest_changes_replay_result_digest() -> None:
    facts = _facts(decision="VERIFIED", risk_class="standard")
    first = compose_verification_report(
        facts, (COMPLETE_A,), bundle_digest=BUNDLE_DIGEST
    )
    second = compose_verification_report(
        facts, (COMPLETE_A,), bundle_digest="4" * 64
    )
    assert first.bundle_digest != second.bundle_digest
    assert first.replay_result_digest != second.replay_result_digest


def test_report_rejects_inconsistent_replay_digest() -> None:
    report = compose_verification_report(
        _facts(decision="VERIFIED", risk_class="standard"),
        (COMPLETE_A,),
        bundle_digest=BUNDLE_DIGEST,
    )
    bad = report.model_dump(mode="json")
    bad["replay_result_digest"] = "9" * 64
    with pytest.raises(ValidationError):
        VerificationReportV01.model_validate(bad)


@pytest.mark.parametrize(
    ("decision_status", "reason_codes"),
    [
        ("VERIFIED", ["ENVIRONMENT_INCOMPLETE"]),
        ("REFUTED", []),
        ("UNKNOWN", []),
    ],
)
def test_report_model_rejects_semantically_inconsistent_status(
    decision_status, reason_codes
) -> None:
    report = _verified_report()
    raw = report.model_dump(mode="json")
    raw.update(decision_status=decision_status, reason_codes=reason_codes)
    unsigned = {key: value for key, value in raw.items() if key != "replay_result_digest"}
    raw["replay_result_digest"] = hashlib.sha256(
        rfc8785.dumps(unsigned)
    ).hexdigest()
    with pytest.raises(ValidationError):
        VerificationReportV01.model_validate(raw)


# --------------------------------------------------------------------------- #
# 4. closed model shape and input validation
# --------------------------------------------------------------------------- #


def test_report_model_json_roundtrip() -> None:
    report = compose_verification_report(
        _facts(decision="VERIFIED", risk_class="standard"),
        (COMPLETE_A,),
        bundle_digest=BUNDLE_DIGEST,
    )
    rebuilt = VerificationReportV01.model_validate_json(report.model_dump_json())
    assert rebuilt == report


def test_report_model_rejects_extra_field_and_is_frozen() -> None:
    report = compose_verification_report(
        _facts(decision="VERIFIED", risk_class="standard"),
        (COMPLETE_A,),
        bundle_digest=BUNDLE_DIGEST,
    )
    data = report.model_dump(mode="json")
    data["unexpected"] = "boom"
    with pytest.raises(ValidationError):
        VerificationReportV01.model_validate(data)

    with pytest.raises(ValidationError, match="frozen"):
        report.decision_status = "REFUTED"  # type: ignore[misc]


def test_compose_rejects_non_model_fingerprint() -> None:
    with pytest.raises(ValueError):
        compose_verification_report(
            _facts(decision="VERIFIED", risk_class="standard"),
            ({"not": "a fingerprint"},),  # type: ignore[arg-type]
            bundle_digest=BUNDLE_DIGEST,
        )


def test_compose_rejects_hostile_sequence_without_traversal() -> None:
    class HostileSequence:
        def __iter__(self):
            raise AssertionError("must not traverse hostile sequence")

    with pytest.raises(ValueError, match="tuple or list"):
        compose_verification_report(
            _facts(decision="VERIFIED", risk_class="standard"),
            HostileSequence(),  # type: ignore[arg-type]
            bundle_digest=BUNDLE_DIGEST,
        )


def test_compose_rejects_malformed_bundle_digest() -> None:
    with pytest.raises(ValidationError):
        compose_verification_report(
            _facts(decision="VERIFIED", risk_class="standard"),
            (COMPLETE_A,),
            bundle_digest="not-a-digest",
        )


def test_compose_rejects_malicious_model_construct_fingerprint() -> None:
    valid = COMPLETE_A
    malicious_type = type(
        "_MaliciousSignedEnvironmentFingerprintV01",
        (SignedEnvironmentFingerprintV01,),
        {},
    )
    data = valid.model_dump(mode="python")
    data["signature"] = "A" * 86
    malicious = malicious_type.model_construct(**data)
    report = compose_verification_report(
        _facts(decision="VERIFIED", risk_class="standard"),
        (malicious,),
        bundle_digest=BUNDLE_DIGEST,
    )
    assert report.decision_status == "UNKNOWN"
    assert "ENVIRONMENT_SIGNATURE_INVALID" in report.reason_codes


# --------------------------------------------------------------------------- #
# 5. static no-script HTML renderer
# --------------------------------------------------------------------------- #

FORBIDDEN_HTML = (
    "<script",
    "javascript:",
    "vbscript:",
    "<link",
    "<img",
    "<iframe",
    "<svg",
    "<form",
    "<object",
    "<embed",
    "onload",
    "onerror",
    "onclick",
    "src=",
    "href=",
    "http://",
    "https://",
    "@import",
    "url(",
)


def _verified_report() -> VerificationReportV01:
    return compose_verification_report(
        _facts(decision="VERIFIED", risk_class="standard"),
        (COMPLETE_A,),
        bundle_digest=BUNDLE_DIGEST,
    )


def test_html_renderer_is_deterministic() -> None:
    report = _verified_report()
    assert render_report_html(report) == render_report_html(report)


def test_html_renderer_contains_no_scripts_or_external_resources() -> None:
    report = _verified_report()
    output = render_report_html(report).decode("utf-8").lower()
    for marker in FORBIDDEN_HTML:
        assert marker not in output


def test_html_renderer_escapes_every_rendered_field(monkeypatch) -> None:
    import openworkproof.verification_report as vr_module

    report = _verified_report()
    seen: list[str] = []
    real_escape = vr_module.html.escape

    def spy(value: Any, quote: bool = True) -> str:
        seen.append(str(value))
        return real_escape(value, quote=quote)

    monkeypatch.setattr(vr_module.html, "escape", spy)
    output = render_report_html(report).decode("utf-8")

    assert report.decision_status in seen
    assert report.source_revision in seen
    assert report.work_order_digest in seen
    assert report.bundle_digest in seen
    assert report.replay_result_digest in seen
    assert report.renderer_version in seen
    assert EVIDENCE_CLOSED_AT in seen
    for digest in report.environment_fingerprint_digests:
        assert digest in seen
    assert "VERIFIED" in output
