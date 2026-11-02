import json

import pytest

from aisoc.canonical import CanonicalizationError, canonical_bytes, digest
from aisoc.crypto import Ed25519Signer, TrustedKeys


def test_canonical_is_key_sorted_and_compact():
    assert canonical_bytes({"b": 1, "a": [1.0, "x"]}) == b'{"a":[1,"x"],"b":1}'


def test_canonical_rejects_nan_and_non_string_keys():
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"a": float("nan")})
    with pytest.raises(CanonicalizationError):
        canonical_bytes({1: "a"})


def test_digest_stable_across_ordering():
    assert digest({"a": 1, "b": 2}) == digest(json.loads('{"b": 2, "a": 1}'))


def test_signature_roundtrip_and_role_check():
    s = Ed25519Signer("authorizer")
    t = TrustedKeys()
    t.trust(s)
    payload = {"x": 1}
    sig = s.sign_payload(payload)
    assert t.verify(payload, sig, expected_role="authorizer")
    assert not t.verify(payload, sig, expected_role="executor")
    assert not t.verify({"x": 2}, sig)
    assert not TrustedKeys().verify(payload, sig)
