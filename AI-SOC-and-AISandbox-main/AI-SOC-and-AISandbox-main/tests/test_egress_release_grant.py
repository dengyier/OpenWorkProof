"""Ported controls: model serialisation + signed release gate, egress proxy, grant attenuation, CLI."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from aisoc.crypto import Clock, Ed25519Signer, TrustedKeys
from aisoc.idps import (
    MODEL_RELEASE_ROLE,
    DualModel,
    ExternalAnomaly,
    ExternalKnown,
    ModelReleaseError,
    load_verified_model,
    release_model,
)
from aisoc.owp.objects import CapabilityGrant
from aisoc.sandbox import (
    MSG_ACTION_REQUEST,
    MSG_INVESTIGATION_REPORT,
    ControlledEgressProxy,
    EgressConfig,
    FailingAudit,
    HeuristicStubAgent,
)
from aisoc.scenarios import _malicious_flow, _seed_ioc, _soc
from aisoc.simulate import generate
from aisoc.soc import AISOC

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def trained():
    ds = generate(n=800, seed=5)
    return DualModel.train(ds.train, ds.val, model_version="dual_model/test"), ds


# ----------------------------------------------------------------------------- model files
def test_model_round_trips_through_bytes_with_identical_decisions(trained):
    model, ds = trained
    clone = DualModel.from_bytes(model.to_bytes())
    assert clone.model_version == model.model_version
    for f in ds.test[:60]:
        a, b = model.decide(f), clone.decide(f)
        assert a.status == b.status and a.known_score == b.known_score and a.anomaly_score == b.anomaly_score
    assert DualModel.from_bytes(clone.to_bytes()).to_bytes() == model.to_bytes()


def test_model_file_schema_is_checked(trained):
    model, _ = trained
    d = json.loads(model.to_bytes())
    d["schema"] = "something-else"
    with pytest.raises(ValueError):
        DualModel.from_params(d)
    d2 = json.loads(model.to_bytes())
    d2["feature_schema"] = "aisoc/features/v0"
    with pytest.raises(ValueError):
        DualModel.from_params(d2)


def test_release_gate_accepts_only_exact_signed_artefact(trained):
    model, _ = trained
    clock = Clock(start=Clock().now())
    rel = Ed25519Signer(MODEL_RELEASE_ROLE)
    trust = TrustedKeys()
    trust.trust(rel)
    blob = model.to_bytes()
    manifest = release_model(model, "sha256:" + "00" * 32, rel, clock, approved_by="board")
    assert manifest.payload["model_version"] == "dual_model/test"
    loaded = load_verified_model(blob, manifest, trust)
    assert loaded.model_version == model.model_version
    with pytest.raises(ModelReleaseError, match="hash"):
        load_verified_model(blob.replace(b"dual_model/test", b"dual_model/tesT"), manifest, trust)
    other = Ed25519Signer(MODEL_RELEASE_ROLE)  # right role, not trusted
    with pytest.raises(ModelReleaseError, match="signature"):
        load_verified_model(blob, release_model(model, "x", other, clock), trust)
    with pytest.raises(ModelReleaseError, match="role"):
        release_model(model, "x", Ed25519Signer("ledger"), clock)
    with pytest.raises(ModelReleaseError, match="schema"):
        load_verified_model(blob, type(manifest)(payload=dict(manifest.payload, schema_version="nope"), signatures=manifest.signatures), trust)


def test_soc_from_release_records_verified_manifest_and_plain_init_records_unverified(trained):
    model, _ = trained
    clock = Clock(start=Clock().now())
    rel = Ed25519Signer(MODEL_RELEASE_ROLE)
    trust = TrustedKeys()
    trust.trust(rel)
    manifest = release_model(model, "ds", rel, clock)
    soc = AISOC.from_release(model.to_bytes(), manifest, trust, HeuristicStubAgent(clock), clock=clock)
    first = soc.ledger.entries[0]
    assert first.entry_type == "model_release" and first.refs["model_version"] == "dual_model/test"
    plain = AISOC(model, HeuristicStubAgent(clock), clock=clock)
    assert plain.ledger.entries[0].entry_type == "model_release"
    with pytest.raises(ModelReleaseError):
        AISOC.from_release(model.to_bytes(), manifest, TrustedKeys(), HeuristicStubAgent(clock), clock=clock)


# ----------------------------------------------------------------------------- external branches
def test_decide_external_combinations(trained):
    model, ds = trained
    flow = ds.test[0]
    k_conf = ExternalKnown("c2", 0.9, False, "slips/x", "T1071", ["e1"])
    k_rej = ExternalKnown("unclassified", 0.3, True, "slips/x")
    anomaly = ExternalAnomaly(0.8, True, "slips/ml")
    assert model.decide_external(flow, k_conf).status.value == "KNOWN_SUSPICIOUS"
    assert model.decide_external(flow, k_conf, anomaly).status.value == "KNOWN_SUSPICIOUS"
    d = model.decide_external(flow, k_rej, anomaly)
    assert d.status.value == "SUSPECTED_UNKNOWN" and d.requires_human_review
    d = model.decide_external(flow, k_rej)
    assert d.status.value == "UNKNOWN" and d.requires_human_review and not d.requires_agent_investigation
    d = model.decide_external(flow, k_rej, ExternalAnomaly(0.1, False, "slips/ml"))
    assert d.status.value in ("INSUFFICIENT_EVIDENCE", "LOW_RISK_OBSERVE")
    assert d.model_version.endswith("+slips/x")


# ----------------------------------------------------------------------------- egress proxy
class _Sink:
    def __init__(self):
        self.rows = []

    def append(self, entry_type, case_id, obj, refs=None):
        self.rows.append((entry_type, case_id, obj, refs or {}))


def test_egress_proxy_logs_before_forwarding_and_binds_identity():
    sink = _Sink()
    clock = Clock(start=Clock().now())
    proxy = ControlledEgressProxy(sink, "agent-A", clock, EgressConfig(max_msg_bytes=200, max_per_minute=2))
    r = proxy.forward(MSG_INVESTIGATION_REPORT, {"agent_id": "human-admin", "verdict": "benign"}, "c1")
    assert r.ok and r.agent_id == "agent-A" and sink.rows[-1][0] == "agent_egress" and sink.rows[-1][3]["agent_id"] == "agent-A"
    assert proxy.forward("shell_exec", {"cmd": "rm -rf /"}, "c1").code == "REJECTED_BY_PROXY"
    assert proxy.forward(MSG_ACTION_REQUEST, {"x": "y" * 500}, "c1").code == "REJECTED_BY_PROXY"
    assert proxy.forward(MSG_ACTION_REQUEST, {"n": 1}, "c1").ok
    assert proxy.forward(MSG_ACTION_REQUEST, {"n": 2}, "c1").code == "RATE_LIMITED"
    clock.advance(61)
    assert proxy.forward(MSG_ACTION_REQUEST, {"n": 3}, "c1").ok
    assert proxy.forward(MSG_ACTION_REQUEST, {"bad": float("nan")}, "c1").code == "MALFORMED"
    assert len(proxy.dropped) == 4


def test_egress_proxy_fail_closed_vs_fail_open():
    clock = Clock(start=Clock().now())
    closed = ControlledEgressProxy(FailingAudit(), "a", clock)
    assert closed.forward(MSG_ACTION_REQUEST, {"n": 1}, "c").code == "AUDIT_UNAVAILABLE"
    opened = ControlledEgressProxy(FailingAudit(), "a", clock, EgressConfig(fail_open_on_audit_error=True))
    assert opened.forward(MSG_ACTION_REQUEST, {"n": 1}, "c").ok


def test_soc_with_audit_down_produces_no_side_effects(trained):
    model, _ = trained
    soc = _soc(model)
    soc.egress.audit = FailingAudit()
    flow = _malicious_flow()
    _seed_ioc(soc, flow)
    res = soc.ingest(flow)
    assert res.egress_dropped == ["investigation_report:AUDIT_UNAVAILABLE"]
    assert res.report is None and res.requests == [] and not soc.executor.blocked_hosts
    assert res.verification_status == "VERIFIED"  # nothing happened, and that is provable


def test_verifier_flags_action_request_without_egress_record(trained):
    model, _ = trained
    soc = _soc(model)
    flow = _malicious_flow()
    _seed_ioc(soc, flow)
    res = soc.ingest(flow)
    # Drop the egress record of the request -> chain still valid after re-hash? No: we only re-point refs,
    # so simulate an insider who wrote the request directly instead of through the proxy.
    case = soc.ledger.entries_for_case(res.case_id)
    req_entry = next(e for e in case if e.entry_type == "action_request")
    soc.ledger.append("action_request", res.case_id, {"request_id": "direct", "digest_differs": True})
    vd = soc.verifier.verify_case(res.case_id, soc.ledger, soc.tool_log.receipts)
    assert vd.payload["status"] == "FAILED"
    assert any("egress" in f for f in vd.payload["findings"])
    assert req_entry.object_digest != soc.ledger.entries[-1].object_digest


# ----------------------------------------------------------------------------- grants
def _grant():
    return CapabilityGrant(grant_id="g1", case_id="c", tenant="t", task_digest="sha256:" + "a" * 64,
                           allowed_actions=["tag_case", "add_watchlist", "block_host"], resource_patterns=["host:h1", "case:c"],
                           max_uses=3, usage_mode="bounded", issued_at="2026-11-01T00:00:00Z", expires_at="2026-11-01T01:00:00Z")


def test_attenuate_narrows_only():
    g = _grant()
    child = g.attenuate(allowed_actions=["tag_case"], resource_patterns=["case:c"], max_uses=1, expires_at="2026-11-01T00:30:00Z")
    assert child.grant_id != g.grant_id and child.parent_grant_id == "g1"
    assert child.allowed_actions == ["tag_case"] and child.resource_patterns == ["case:c"] and child.max_uses == 1
    assert child.task_digest == g.task_digest and child.tenant == g.tenant
    for bad in (dict(allowed_actions=["egress_connect"]), dict(resource_patterns=["host:*"]), dict(max_uses=4),
                dict(expires_at="2026-11-01T02:00:00Z")):
        with pytest.raises(ValueError):
            g.attenuate(**bad)
    grandchild = child.attenuate(max_uses=1)
    assert grandchild.parent_grant_id == child.grant_id


# ----------------------------------------------------------------------------- CLI
def test_cli_slips_ingest_verify_bundle_and_push_dry_run(tmp_path):
    out = tmp_path / "run"
    fx = ROOT / "tests" / "fixtures"
    env = {"PYTHONPATH": str(ROOT)}
    r = subprocess.run([sys.executable, "-m", "aisoc", "slips-ingest", str(fx / "slips" / "alerts.json"), "--conn-log",
                        str(fx / "slips" / "conn.log"), "--out", str(out), "--seed", "3"], cwd=ROOT, env={**env, "PATH": ""},
                       capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stderr
    summary = json.loads((out / "slips-summary.json").read_text())
    assert summary["cases"] == 5 and len(summary["case_results"]) == 5 and summary["model_release"]["approved_by"]
    v = subprocess.run([sys.executable, "-m", "aisoc", "verify", str(out)], cwd=ROOT, env={**env, "PATH": ""}, capture_output=True, text=True)
    assert v.returncode == 0 and json.loads(v.stdout)["status"] == "VERIFIED"
    p = subprocess.run([sys.executable, "-m", "aisoc", "aisoc-push", str(out), "--dry-run"], cwd=ROOT, env={**env, "PATH": ""},
                       capture_output=True, text=True)
    assert p.returncode == 0
    events = json.loads(p.stdout)["events"]
    assert len(events) == 5 and any(e["mitre_techniques"] == ["T1071"] for e in events)
    b = subprocess.run([sys.executable, "-m", "aisoc", "aisoc-bundle-verify", str(fx / "aisoc" / "investigation-bundle.json"),
                        "--hmac-key", "test-key"], cwd=ROOT, env={**env, "PATH": ""}, capture_output=True, text=True)
    assert b.returncode == 0 and json.loads(b.stdout)["ok"] is True
    bad = subprocess.run([sys.executable, "-m", "aisoc", "aisoc-bundle-verify", str(fx / "aisoc" / "investigation-bundle.json"),
                         "--hmac-key", "wrong"], cwd=ROOT, env={**env, "PATH": ""}, capture_output=True, text=True)
    assert bad.returncode == 1
