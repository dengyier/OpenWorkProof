"""End-to-end: detection -> agent -> policy -> approval -> PEP -> ledger -> verification."""

import pytest

from aisoc.idps import DualModel
from aisoc.scenarios import ALL_SCENARIOS, _malicious_flow, _seed_ioc, _soc
from aisoc.sandbox import InjectionFollowingStubAgent
from aisoc.simulate import generate, injection_flow


@pytest.fixture(scope="module")
def model():
    ds = generate(n=1200, seed=2)
    return DualModel.train(ds.train, ds.val)


def test_happy_path_is_fully_recorded_and_verified(model):
    soc = _soc(model)
    flow = _malicious_flow()
    _seed_ioc(soc, flow)
    res = soc.ingest(flow)
    assert res.investigated
    assert any(q.executed for q in res.requests)
    types = [e.entry_type for e in soc.ledger.entries_for_case(res.case_id)]
    for t in ("detection", "work_order", "capability_grant", "investigation_report", "action_request",
              "policy_decision", "human_approval", "authorization", "action_receipt", "verification_decision",
              "acceptance_decision"):
        assert t in types, t
    assert types.index("authorization") < types.index("action_receipt")
    assert res.verification_status == "VERIFIED"
    assert res.acceptance_status == "ACCEPTED"


def test_compromised_agent_cannot_cause_side_effects(model):
    soc = _soc(model, InjectionFollowingStubAgent)
    res = soc.ingest(injection_flow())
    assert len(res.requests) >= 3
    assert all(q.policy_status == "denied" for q in res.requests)
    assert not soc.executor.egress_log and not soc.executor.blocked_hosts
    assert res.report["injection_flags_seen"]


def test_dedup_suppresses_repeat_within_window(model):
    soc = _soc(model)
    f1 = _malicious_flow(seed=1)
    f2 = _malicious_flow(seed=1)
    f2.flow_id = "flow-malicious-2"
    r1 = soc.ingest(f1)
    r2 = soc.ingest(f2)
    assert r1.investigated and r2.deduplicated and not r2.investigated


@pytest.mark.parametrize("scenario", ALL_SCENARIOS, ids=lambda f: f.__name__)
def test_scenarios_behave_as_specified(model, scenario):
    result = scenario(model)
    assert result["passed"], result
