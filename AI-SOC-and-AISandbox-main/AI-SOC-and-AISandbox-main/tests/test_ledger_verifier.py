import pytest

from aisoc.crypto import Clock, Ed25519Signer, TrustedKeys
from aisoc.owp import EncryptedEvidenceStore, ExternalWitness, HashChainLedger, Verifier, merkle_root
from aisoc.owp.ledger import GENESIS


@pytest.fixture
def ledger(tmp_path):
    clock = Clock(start=Clock().now())
    signer = Ed25519Signer("ledger")
    trusted = TrustedKeys()
    trusted.trust(signer)
    witness = ExternalWitness(tmp_path / "witness.jsonl")
    led = HashChainLedger(signer, clock, witness)
    for i in range(5):
        led.append("detection", f"case-{i}", {"i": i})
    led.checkpoint()
    return led, trusted, clock


def test_chain_and_witness_ok(ledger):
    led, trusted, _ = ledger
    assert led.verify_chain() == []
    assert led.verify_against_witness(trusted) == []


def test_witness_file_is_append_only_jsonl(ledger, tmp_path):
    led, _, _ = ledger
    led.checkpoint()
    lines = (tmp_path / "witness.jsonl").read_text().splitlines()
    assert len(lines) == 2
    reopened = ExternalWitness(tmp_path / "witness.jsonl")
    assert len(reopened.checkpoints()) == 2


def test_modification_detected(ledger):
    led, trusted, _ = ledger
    led.entries[2].object_digest = "sha256:" + "a" * 64
    assert any("entry_hash" in p for p in led.verify_chain())
    led.entries[2].entry_hash = led.entries[2].compute_hash()  # attacker re-hashes
    assert any("prev_hash" in p for p in led.verify_chain())
    # attacker re-hashes the whole suffix: local chain looks fine, witness catches it
    for i in range(3, len(led.entries)):
        led.entries[i].prev_hash = led.entries[i - 1].entry_hash
        led.entries[i].entry_hash = led.entries[i].compute_hash()
    assert led.verify_chain() == []
    assert any("merkle" in p for p in led.verify_against_witness(trusted))


def test_truncation_and_fork_detected(ledger):
    led, trusted, _ = ledger
    led.entries = led.entries[:3]
    assert any("truncated" in p for p in led.verify_against_witness(trusted))


def test_witness_signature_from_wrong_role_rejected(ledger):
    led, trusted, clock = ledger
    rogue = Ed25519Signer("executor")
    trusted.trust(rogue)
    cp = led.witness.checkpoints()[0]
    cp["signatures"] = [rogue.sign_payload(cp["payload"])]
    assert any("signature" in p for p in led.verify_against_witness(trusted))


def test_merkle_root_edge_cases():
    assert merkle_root([]) == GENESIS
    h = "sha256:" + "1" * 64
    assert merkle_root([h]) == h
    assert merkle_root([h, h, h]) == merkle_root([h, h, h, h])


def test_evidence_store_separation_and_deletion():
    store = EncryptedEvidenceStore()
    d = store.put({"pii": "alice", "flow": 1})
    assert store.get(d, "verifier", "audit") == {"pii": "alice", "flow": 1}
    assert store.access_log[0]["accessor"] == "verifier"
    assert store.delete(d)
    assert store.get(d, "verifier", "audit") is None
    assert d.startswith("sha256:")  # commitment survives deletion of the plaintext


def test_verifier_unknown_without_witness():
    clock = Clock(start=Clock().now())
    signer = Ed25519Signer("ledger")
    vsig = Ed25519Signer("verifier")
    trusted = TrustedKeys()
    trusted.trust(signer)
    trusted.trust(vsig)
    led = HashChainLedger(signer, clock, witness=None)
    led.append("detection", "c", {"a": 1})
    vd = Verifier(vsig, trusted, clock).verify_case("c", led, [])
    assert vd.payload["status"] == "UNKNOWN"
