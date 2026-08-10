from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import sys

import pytest

from openworkproof.delivery_package import DeliveryPackageError


BUNDLE_DIR = Path(__file__).parent / "evidence-bundles"
sys.path.insert(0, str(BUNDLE_DIR))
from verify_evidence_bundle import bundle_schema, verify_bundle  # noqa: E402
V01_HASHES = {
    "rich-4196-evidence-bundle.json": (
        "e9aee9f43aef013d4af5f67c4d75df810affb36fa3553449e416dcaaf5447fa0"
    ),
    "dify-33013-evidence-bundle.json": (
        "7f1bfadb618d5ae0c8e5350355ddc40708835f0832341c6f2ca69292a20af3c8"
    ),
}
V02_FILES = (
    "rich-4196-v02-delivery-package.json",
    "dify-33013-v02-delivery-package.json",
)
V02_HASHES = {
    "rich-4196-v02-delivery-package.json": (
        "a03e21c1ff1cb4d5d64b70194362ab329a44e507c249fa09783b83b446aa3726"
    ),
    "dify-33013-v02-delivery-package.json": (
        "2c99e6accb89e941084cb529cf3eaf2f39af04fdde3775807826d7b056f6be2f"
    ),
}
V02_METADATA_FIELDS = {
    "bug_id",
    "bug_url",
    "pinned_source_commit",
    "positive_candidate_commit",
    "candidate_revision_type",
    "fixed_test_source_digest",
    "negative_mutant_patch_digest",
    "container_image_digest",
    "dependency_lock_digest",
    "fix_description",
    "current_decision",
    "current_readiness",
}


def test_historical_v01_bundle_hashes_are_unchanged() -> None:
    for name, expected in V01_HASHES.items():
        assert hashlib.sha256((BUNDLE_DIR / name).read_bytes()).hexdigest() == expected
        assert bundle_schema(BUNDLE_DIR / name) == "openworkproof/evidence-bundle/v0.1"


def test_v02_delivery_package_hashes_are_frozen() -> None:
    for name, expected in V02_HASHES.items():
        assert hashlib.sha256((BUNDLE_DIR / name).read_bytes()).hexdigest() == expected


def test_unknown_bundle_schema_is_rejected(tmp_path) -> None:
    unknown = tmp_path / "unknown.json"
    unknown.write_text('{"schema_version":"openworkproof/unknown/9.9"}')
    with pytest.raises(ValueError, match="unsupported bundle schema"):
        verify_bundle(str(unknown))


@pytest.mark.parametrize("name", V02_FILES)
def test_v02_delivery_package_envelope_is_closed_and_offline_verifiable(name) -> None:
    path = BUNDLE_DIR / name
    envelope = json.loads(path.read_text(encoding="utf-8"))
    assert bundle_schema(path) == "openworkproof/delivery-package-envelope/0.2"
    assert set(envelope) == {"schema_version", "metadata", "files"}
    assert set(envelope["metadata"]) == V02_METADATA_FIELDS
    assert envelope["metadata"]["positive_candidate_commit"] != envelope[
        "metadata"
    ]["negative_mutant_patch_digest"][:40]
    paths = tuple(item["path"] for item in envelope["files"])
    assert paths == tuple(sorted(set(paths), key=lambda value: value.encode("utf-8")))
    assert "manifest.json" in paths
    for item in envelope["files"]:
        payload = base64.b64decode(item["payload_b64"], validate=True)
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
    by_path = {item["path"]: item for item in envelope["files"]}
    readiness = json.loads(
        base64.b64decode(
            by_path["settlement-readiness.json"]["payload_b64"], validate=True
        )
    )
    profile = json.loads(
        base64.b64decode(
            by_path["verification-profile.json"]["payload_b64"], validate=True
        )
    )
    positive = profile["positive_arm"]
    negative = profile["negative_arms"][0]
    assert positive["source_commit"] == envelope["metadata"]["pinned_source_commit"]
    assert positive["candidate_commit"] == envelope["metadata"][
        "positive_candidate_commit"
    ]
    assert negative["candidate_commit"] == positive["candidate_commit"]
    assert negative["mutant_patch_digest"] == envelope["metadata"][
        "negative_mutant_patch_digest"
    ]
    assert negative["mutant_patch_digest"] is not None
    assert positive["fixed_test_source_digest"] == envelope["metadata"][
        "fixed_test_source_digest"
    ]
    assert negative["fixed_test_source_digest"] == positive[
        "fixed_test_source_digest"
    ]
    assert positive["expected_outcome"] == "pass"
    assert negative["expected_outcome"] == "fail"
    assert readiness["effective_acceptance"] == "NONE"
    assert readiness["settlement_readiness"] == "READY_FOR_ACCEPTANCE"
    assert envelope["metadata"]["current_decision"] == "VERIFIED"
    assert envelope["metadata"]["current_readiness"] == "READY_FOR_ACCEPTANCE"
    assert verify_bundle(str(path)) is True


@pytest.mark.parametrize("name", V02_FILES)
def test_v02_delivery_package_tamper_fails_closed(name, tmp_path) -> None:
    envelope = json.loads((BUNDLE_DIR / name).read_text(encoding="utf-8"))
    target = next(item for item in envelope["files"] if item["path"] == "manifest.json")
    payload = bytearray(base64.b64decode(target["payload_b64"]))
    payload[-2] ^= 1
    target["payload_b64"] = base64.b64encode(payload).decode("ascii")
    tampered = tmp_path / name
    tampered.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(DeliveryPackageError, match="envelope file hash"):
        verify_bundle(str(tampered))
