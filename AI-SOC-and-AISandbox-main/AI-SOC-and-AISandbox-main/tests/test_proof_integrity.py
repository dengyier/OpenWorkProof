"""Regression coverage for signed authorization and exported proof integrity."""
import argparse
import copy
import json
from datetime import timedelta

import pytest

from aisoc.canonical import digest
from aisoc.cli import cmd_verify
from aisoc.crypto import Clock, Ed25519Signer, TrustedKeys, utc_iso
from aisoc.idps import DualModel
from aisoc.owp import ActionRequest, CapabilityGrant, ExternalWitness, HashChainLedger, Verifier, WorkOrder
from aisoc.sandbox import ACTION_TAG_CASE, AuthorizationSigner, BoundedExecutor, PolicyEnforcementPoint, PolicyEngine, ToolSideLog
from aisoc.scenarios import _first_authorized, _soc
from aisoc.simulate import generate
from aisoc.owp.verifier import verify_bundle
from aisoc.owp.ledger import GENESIS, merkle_root


@pytest.fixture
def world():
    clock = Clock(start=Clock().now())
    keys = {r: Ed25519Signer(r) for r in ("ledger", "authorizer", "executor", "verifier")}
    trusted = TrustedKeys()
    for key in keys.values():
        trusted.trust(key)
    ledger = HashChainLedger(keys["ledger"], clock, ExternalWitness())
    tool_log = ToolSideLog()
    pep = PolicyEnforcementPoint(trusted, BoundedExecutor(keys["executor"], clock), tool_log, clock)
    order = WorkOrder("c", "t", "tag", [ACTION_TAG_CASE], ["f"], digest({"f": 1}), "KNOWN_SUSPICIOUS", "m", clock.iso())
    grant = CapabilityGrant("g", "c", "t", order.digest(), [ACTION_TAG_CASE], ["case:c"], 3, "bounded", clock.iso(), utc_iso(clock.now() + timedelta(hours=1)))
    req = ActionRequest("r", "c", "t", ACTION_TAG_CASE, "case:c", None, {"tag": "reviewed"}, ["f"], "i", clock.iso())
    pd = PolicyEngine(clock).decide(req, order, grant)
    auth = AuthorizationSigner(keys["authorizer"], trusted, clock).issue(req, order, pd)
    ledger.append("work_order", "c", order.to_dict())
    ledger.append("capability_grant", "c", grant.to_dict())
    ledger.append("agent_egress", "c", {"request": req.to_dict()}, {"msg_digest": req.digest()})
    ledger.append("action_request", "c", req.to_dict())
    ledger.append("policy_decision", "c", pd.to_dict(), {"request_digest": req.digest()})
    return dict(clock=clock, keys=keys, trusted=trusted, ledger=ledger, tool_log=tool_log, pep=pep,
                verifier=Verifier(keys["verifier"], trusted, clock), req=req, auth=auth)


def execute(w, *, late=False, unsigned=False):
    led, req, auth = w["ledger"], w["req"], w["auth"]
    if not late:
        led.append("authorization", "c", {"unsigned": True} if unsigned else auth.payload, {"request_digest": req.digest()})
    result = w["pep"].execute(req, auth)
    assert result.executed
    led.append("action_receipt", "c", result.receipt.payload)
    if late:
        led.append("authorization", "c", auth.payload, {"request_digest": req.digest()})
    led.checkpoint()


def export(w, tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    w["ledger"].export(run / "ledger.json")
    data = {"trusted-keys.json": w["trusted"].export(), "witness-checkpoints.json": w["ledger"].witness.checkpoints(),
            "tool-side-receipts.json": [r.to_dict() for r in w["tool_log"].receipts], "authorizations.json": [w["auth"].to_dict()]}
    for name, value in data.items():
        (run / name).write_text(json.dumps(value))
    keys = tmp_path / "pinned-keys.json"
    cps = tmp_path / "pinned-checkpoints.json"
    keys.write_text(json.dumps(data["trusted-keys.json"]))
    cps.write_text(json.dumps(data["witness-checkpoints.json"]))
    return run, keys, cps


def cli(run, keys, cps, capsys):
    code = cmd_verify(argparse.Namespace(dir=str(run), trusted_keys=str(keys) if keys else None,
                                         trusted_checkpoints=str(cps) if cps else None))
    return code, json.loads(capsys.readouterr().out)


def test_cli_rejects_missing_tool_receipt(world, tmp_path, capsys):
    execute(world)
    run, keys, cps = export(world, tmp_path)
    (run / "tool-side-receipts.json").write_text("[]")
    code, result = cli(run, keys, cps, capsys)
    assert result["status"] == "FAILED" and code == 1


def test_cli_rejects_authorization_recorded_after_execution(world, tmp_path, capsys):
    execute(world, late=True)
    run, keys, cps = export(world, tmp_path)
    code, result = cli(run, keys, cps, capsys)
    assert result["status"] == "FAILED" and code == 1
    assert any("after execution" in p for p in result["problems"])


def test_internal_rejects_unsigned_authorization_reference(world):
    execute(world, unsigned=True)
    decision = world["verifier"].verify_case("c", world["ledger"], world["tool_log"].receipts)
    assert decision.payload["status"] == "FAILED"


def test_bundle_keys_alone_cannot_establish_identity(world, tmp_path, capsys):
    execute(world)
    run, _, _ = export(world, tmp_path)
    code, result = cli(run, None, None, capsys)
    assert result["status"] == "UNKNOWN" and code == 1


def test_old_witness_does_not_cover_new_case(world):
    world["ledger"].checkpoint()
    world["ledger"].append("detection", "new-case", {"event": 1})
    decision = world["verifier"].verify_case("new-case", world["ledger"], [])
    assert decision.payload["status"] == "UNKNOWN"


def test_export_witness_covers_final_decisions(tmp_path):
    data = generate(n=1200, seed=2)
    soc = _soc(DualModel.train(data.train, data.val))
    _first_authorized(soc)
    soc.export(tmp_path)
    entries = json.loads((tmp_path / "ledger.json").read_text())
    cps = json.loads((tmp_path / "witness-checkpoints.json").read_text())
    assert cps[-1]["payload"]["length"] == len(entries)
    assert (tmp_path / "authorizations.json").is_file()


def proof(w):
    return {"ledger.json": [e.to_dict() for e in w["ledger"].entries],
            "trusted-keys.json": w["trusted"].export(),
            "witness-checkpoints.json": copy.deepcopy(w["ledger"].witness.checkpoints()),
            "tool-side-receipts.json": [r.to_dict() for r in w["tool_log"].receipts],
            "authorizations.json": [w["auth"].to_dict()]}


def verify_pinned(bundle, keys=None, cps=None):
    return verify_bundle(bundle, bundle["trusted-keys.json"] if keys is None else keys,
                         bundle["witness-checkpoints.json"] if cps is None else cps)


def test_valid_signed_evidence_requires_both_caller_pins(world):
    execute(world)
    bundle = proof(world)
    assert verify_pinned(bundle)["status"] == "VERIFIED"
    assert verify_bundle(bundle)["status"] == "UNKNOWN"
    assert verify_bundle(bundle, world["trusted"].export())["status"] == "UNKNOWN"
    assert verify_bundle(bundle, trusted_checkpoints=bundle["witness-checkpoints.json"])["status"] == "UNKNOWN"
    internal = world["verifier"].verify_case("c", world["ledger"], world["tool_log"].receipts, [world["auth"]])
    assert internal.payload["status"] == verify_pinned(bundle)["status"]


@pytest.mark.parametrize("kind", ["delete", "duplicate", "signature", "identity", "extra"])
def test_receipts_match_one_to_one_and_authenticate_executor(world, kind):
    execute(world)
    bundle = proof(world)
    receipts = bundle["tool-side-receipts.json"]
    if kind == "delete":
        receipts.clear()
    elif kind == "duplicate":
        receipts.append(copy.deepcopy(receipts[0]))
    elif kind == "signature":
        receipts[0]["signatures"][0]["sig"] = "00" * 64
    elif kind == "identity":
        # A valid executor signature cannot claim a different executor identity.
        receipts[0]["payload"] = dict(receipts[0]["payload"], executor_identity="someone-else")
        receipts[0]["signatures"] = [world["keys"]["executor"].sign_payload(receipts[0]["payload"])]
    else:
        extra = copy.deepcopy(receipts[0])
        extra["payload"] = dict(extra["payload"], receipt_id="unrecorded")
        extra["signatures"] = [world["keys"]["executor"].sign_payload(extra["payload"])]
        receipts.append(extra)
    assert verify_pinned(bundle)["status"] == "FAILED"


@pytest.mark.parametrize("kind", ["delete", "duplicate", "signature", "wrong-envelope", "wrong-case"])
def test_executed_receipt_requires_exact_signed_authorization(world, kind):
    execute(world)
    bundle = proof(world)
    auths = bundle["authorizations.json"]
    if kind == "delete":
        auths.clear()
    elif kind == "duplicate":
        auths.append(copy.deepcopy(auths[0]))
    elif kind == "signature":
        auths[0]["signatures"][0]["sig"] = "00" * 64
    else:
        receipt = bundle["tool-side-receipts.json"][0]
        receipt["payload"] = dict(receipt["payload"], **({"envelope_digest": digest({"fake": 1})} if kind == "wrong-envelope" else {"case_id": "other"}))
        receipt["signatures"] = [world["keys"]["executor"].sign_payload(receipt["payload"])]
        # Re-record and witness the executor's mismatched receipt, so the failure
        # must include authorization binding, rather than an invalid chain.
        entry = world["ledger"].entries[-1]
        entry.object_digest = digest(receipt["payload"])
        entry.case_id = receipt["payload"]["case_id"]
        entry.entry_hash = entry.compute_hash()
        world["ledger"].witness = ExternalWitness()
        world["ledger"].checkpoint()
        bundle["ledger.json"] = [e.to_dict() for e in world["ledger"].entries]
        bundle["witness-checkpoints.json"] = world["ledger"].witness.checkpoints()
    result = verify_pinned(bundle)
    assert result["status"] == "FAILED"
    if kind in {"wrong-envelope", "wrong-case"}:
        assert any("matching signed authorization" in p for p in result["problems"])


def test_external_checkpoint_detects_removal_of_bundled_final_checkpoint(world):
    execute(world)
    bundle = proof(world)
    pinned = copy.deepcopy(bundle["witness-checkpoints.json"])
    bundle["ledger.json"].pop()
    bundle["witness-checkpoints.json"] = []
    assert verify_pinned(bundle, cps=pinned)["status"] == "FAILED"


def test_external_key_pin_rejects_producer_key_replacement(world):
    execute(world)
    bundle = proof(world)
    keys = copy.deepcopy(bundle["trusted-keys.json"])
    rogue = Ed25519Signer("ledger")
    replacement = TrustedKeys()
    replacement.trust(rogue)
    bundle["trusted-keys.json"] = replacement.export()
    for cp in bundle["witness-checkpoints.json"]:
        cp["signatures"] = [rogue.sign_payload(cp["payload"])]
    assert verify_pinned(bundle, keys=keys)["status"] == "FAILED"


def test_cli_rejects_pins_inside_the_bundle(world, tmp_path, capsys):
    execute(world)
    run, _, _ = export(world, tmp_path)
    code, result = cli(run, run / "trusted-keys.json", run / "witness-checkpoints.json", capsys)
    assert code == 1 and result["status"] == "FAILED"
    assert any("outside" in p for p in result["problems"])


def test_malformed_bundle_fails_instead_of_raising(world):
    execute(world)
    bundle = proof(world)
    bundle["witness-checkpoints.json"][0]["payload"]["length"] = -1
    assert verify_pinned(bundle)["status"] == "FAILED"
    assert verify_bundle({"ledger.json": None})["status"] == "FAILED"


@pytest.mark.parametrize("entry_type", ["work_order", "policy_decision"])
@pytest.mark.parametrize("change", ["missing", "wrong-case", "different-digest", "after-authorization"])
def test_signed_authorization_requires_prior_same_case_task_and_policy(world, entry_type, change):
    execute(world)
    bundle = proof(world)
    entries = bundle["ledger.json"]
    target = next(e for e in entries if e["entry_type"] == entry_type)
    if change == "missing":
        entries.remove(target)
    elif change == "wrong-case":
        target["case_id"] = "other-case"
    elif change == "different-digest":
        target["object_digest"] = digest({"replaced": entry_type})
    else:
        entries.remove(target)
        auth_index = next(i for i, e in enumerate(entries) if e["entry_type"] == "authorization")
        entries.insert(auth_index + 1, target)
    prev = GENESIS
    for index, entry in enumerate(entries):
        entry["index"], entry["prev_hash"] = index, prev
        entry["entry_hash"] = digest({k: v for k, v in entry.items() if k != "entry_hash"})
        prev = entry["entry_hash"]
    cp = bundle["witness-checkpoints.json"][-1]
    cp["payload"].update(length=len(entries), head_hash=prev,
                         merkle_root=merkle_root([e["entry_hash"] for e in entries]))
    cp["signatures"] = [world["keys"]["ledger"].sign_payload(cp["payload"])]
    result = verify_pinned(bundle)
    assert result["status"] == "FAILED"
    assert any(f"prior {entry_type}" in p for p in result["problems"])


def test_authorization_must_be_recorded_before_signed_execution_time(world):
    outcome = world["pep"].execute(world["req"], world["auth"])
    assert outcome.executed
    world["clock"].advance(60)
    world["ledger"].append("authorization", "c", world["auth"].payload,
                           {"request_digest": world["req"].digest()})
    world["ledger"].append("action_receipt", "c", outcome.receipt.payload)
    world["ledger"].checkpoint()
    result = verify_pinned(proof(world))
    assert result["status"] == "FAILED"
    assert any("recorded after signed execution time" in p for p in result["problems"])
