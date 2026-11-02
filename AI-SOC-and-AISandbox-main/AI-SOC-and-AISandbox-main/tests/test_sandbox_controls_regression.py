"""Regression coverage for bound investigation tools and capability limits."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from aisoc.canonical import digest
from aisoc.crypto import Clock, Ed25519Signer, TrustedKeys, parse_iso, utc_iso
from aisoc.idps import CaseDecision, CaseStatus, FlowRecord
from aisoc.owp.objects import ActionRequest, CapabilityGrant, WorkOrder
from aisoc.sandbox import (
    AuthorizationError, AuthorizationSigner, BoundedExecutor, HumanApprover,
    InvestigationReport, PolicyEnforcementPoint, PolicyEngine, ReadOnlyTools, RuntimeConstraints,
    TelemetryStore, ToolError, ToolSideLog,
)
from aisoc.soc import AISOC


@pytest.fixture
def world():
    clock = Clock(datetime(2026, 11, 2, tzinfo=timezone.utc))
    keys = {role: Ed25519Signer(role) for role in ("authorizer", "executor", "approver")}
    trusted = TrustedKeys()
    for key in keys.values():
        trusted.trust(key)
    order = WorkOrder(
        "case-a", "tenant-a", "Investigate a single host", ["tag_case", "block_host", "egress_connect"],
        ["flow-a", "hostwin:host-a", "ioc:192.0.2.1"], digest({"fixture": True}),
        "KNOWN_SUSPICIOUS", "fixture", clock.iso(),
    )
    grant = CapabilityGrant(
        "grant-a", order.case_id, order.tenant, order.digest(), list(order.allowed_action_types),
        ["case:case-a", "host:host-a"], 3, "bounded", clock.iso(),
        utc_iso(clock.now() + timedelta(hours=1)),
    )
    executor = BoundedExecutor(keys["executor"], clock)
    return dict(
        clock=clock, order=order, grant=grant, keys=keys, trusted=trusted, executor=executor,
        policy=PolicyEngine(clock, RuntimeConstraints(max_requests_per_case=20)),
        signer=AuthorizationSigner(keys["authorizer"], trusted, clock),
        approver=HumanApprover("analyst", keys["approver"], clock),
        pep=PolicyEnforcementPoint(trusted, executor, ToolSideLog(), clock),
    )


def request(w, index=0, action="tag_case", params=None, destination=None):
    return ActionRequest(
        f"req-{index}", w["order"].case_id, w["order"].tenant, action,
        "case:case-a" if action == "tag_case" else "host:host-a", destination,
        {"tag": f"tag-{index}"} if params is None else params,
        ["flow-a"], f"unique-{index}", w["clock"].iso(),
    )


def authorize(w, req):
    decision = w["policy"].decide(req, w["order"], w["grant"])
    approval = w["approver"].decide(req, w["order"], decision, True, "fixture") if decision.status == "reserved" else None
    return w["signer"].issue(req, w["order"], decision, approval)


@pytest.mark.parametrize("case,tenant", [("case-a", "tenant-b"), ("invented-case", "tenant-a")])
def test_agent_tool_view_rejects_self_claimed_scope(world, case, tenant):
    store = TelemetryStore()
    store.host_windows["tenant-b/host-a"] = {"secret": "other-tenant"}
    store.host_windows["tenant-a/host-a"] = {"own": True}
    tools = ReadOnlyTools(store, ToolSideLog(), world["clock"])
    view = tools.for_order(world["order"])
    with pytest.raises(ToolError):
        view.call(case, tenant, "get_host_window", host="host-a")
    assert not hasattr(view, "store") and not hasattr(view, "log")


def test_agent_tool_view_enforces_frozen_resources_and_budget(world):
    store = TelemetryStore()
    store.host_windows["tenant-a/host-a"] = {"own": True}
    store.host_windows["tenant-a/unrelated"] = {"secret": "same-tenant-other-case"}
    tools = ReadOnlyTools(store, ToolSideLog(), world["clock"], max_calls_per_case=1)
    view = tools.for_order(world["order"])
    world["order"].evidence_ids.append("hostwin:unrelated")
    with pytest.raises(ToolError):
        view.call("case-a", "tenant-a", "get_host_window", host="unrelated")
    assert view.call("case-a", "tenant-a", "get_host_window", host="host-a").content == {"own": True}
    with pytest.raises(ToolError):
        view.call("new-case", "tenant-a", "get_host_window", host="host-a")
    with pytest.raises(ToolError, match="budget"):
        view.call("case-a", "tenant-a", "get_host_window", host="host-a")


def test_grant_budget_limits_distinct_execution_authorizations(world):
    requests = [request(world, index) for index in range(5)]
    authorizations = [authorize(world, req) for req in requests]
    outcomes = [world["pep"].execute(req, auth) for req, auth in zip(requests, authorizations)]
    assert sum(outcome.executed for outcome in outcomes) == 3
    assert len(world["executor"].tags["case:case-a"]) == 3
    assert all("grant" in outcome.reason for outcome in outcomes[3:])


def test_grant_budget_is_atomic_for_concurrent_envelopes(world):
    requests = [request(world, index) for index in range(8)]
    authorizations = [authorize(world, req) for req in requests]
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda pair: world["pep"].execute(*pair), zip(requests, authorizations)))
    assert sum(outcome.executed for outcome in outcomes) == 3
    assert len(world["executor"].tags["case:case-a"]) == 3


def test_single_use_grant_and_idempotent_retry(world):
    world["grant"].usage_mode = "single_use"
    first, second = request(world), request(world, 1)
    first_auth, second_auth = authorize(world, first), authorize(world, second)
    assert world["pep"].execute(first, first_auth).executed
    assert "idempotent" in world["pep"].execute(first, first_auth).reason
    assert not world["pep"].execute(second, second_auth).executed
    assert len(world["executor"].tags["case:case-a"]) == 1


def test_empty_grant_budget_is_denied(world):
    world["grant"].max_uses = 0
    assert world["policy"].decide(request(world), world["order"], world["grant"]).status == "denied"


def test_authorization_cannot_outlive_grant(world):
    world["grant"].expires_at = utc_iso(world["clock"].now() + timedelta(seconds=1))
    req = request(world)
    auth = authorize(world, req)
    assert parse_iso(auth.payload["expires_at"]) <= parse_iso(world["grant"].expires_at)
    world["clock"].advance(2)
    assert not world["pep"].execute(req, auth).executed


def test_signer_refuses_policy_decided_before_grant_expired(world):
    world["grant"].expires_at = utc_iso(world["clock"].now() + timedelta(seconds=1))
    req = request(world)
    decision = world["policy"].decide(req, world["order"], world["grant"])
    world["clock"].advance(2)
    with pytest.raises(AuthorizationError, match="expired"):
        world["signer"].issue(req, world["order"], decision)


def test_authorization_cannot_outlive_human_approval(world):
    world["approver"].ttl_s = 1
    req = request(world, action="block_host", params={"ttl_s": 60})
    auth = authorize(world, req)
    assert parse_iso(auth.payload["expires_at"]) <= world["clock"].now() + timedelta(seconds=1)
    world["clock"].advance(2)
    assert not world["pep"].execute(req, auth).executed


@pytest.mark.parametrize("ttl", ["not-an-integer", None, {}, [], True, 1.5, -1, 0])
def test_malformed_block_ttl_is_a_policy_denial(world, ttl):
    req = request(world, action="block_host", params={"ttl_s": ttl})
    decision = world["policy"].decide(req, world["order"], world["grant"])
    assert decision.status == "denied"
    assert any("ttl" in reason for reason in decision.reasons)


@pytest.mark.parametrize("ttl", ["invalid", {}, [], True, -1, 0, 3601])
def test_malformed_egress_ttl_is_a_policy_denial(world, ttl):
    req = request(world, action="egress_connect", params={}, destination={
        "ip": "8.8.8.8", "port": 443, "scope": "public", "ttl_s": ttl,
    })
    assert world["policy"].decide(req, world["order"], world["grant"]).status == "denied"


def test_non_object_action_parameters_are_a_policy_denial(world):
    req = request(world)
    req.params = []
    assert world["policy"].decide(req, world["order"], world["grant"]).status == "denied"


class FixedDetector:
    model_version = "sandbox-regression-fixture"

    def decide(self, flow):
        return CaseDecision(
            flow.flow_id, flow.tenant, CaseStatus.KNOWN_SUSPICIOUS, "fixture", 1.0,
            False, 1.0, 0.5, True, False, True, model_version=self.model_version,
        )


def synthetic_flow():
    return FlowRecord("flow-a", "tenant-a", "host-a", "192.0.2.1", 443,
                      100, 100, 10, 10, 1, 100, 0, 1, 1, 0)


class AdversarialAgent:
    name = "sandbox-regression-agent"

    def __init__(self, clock, mode):
        self.clock, self.mode = clock, mode

    def investigate(self, order, decision, tools):
        requests, narrative = [], "fixture"
        if self.mode == "cross_tenant":
            try:
                narrative = str(tools.call(order.case_id, "tenant-b", "get_host_window", host="host-a").content)
            except ToolError:
                narrative = "cross-tenant read rejected"
        else:
            for index in range(5 if self.mode == "budget" else 1):
                malformed = self.mode == "malformed"
                requests.append(ActionRequest(
                    f"req-{index}", order.case_id, order.tenant,
                    "block_host" if malformed else "tag_case",
                    "host:host-a" if malformed else f"case:{order.case_id}", None,
                    {"ttl_s": "not-an-integer"} if malformed else {"tag": str(index)},
                    ["flow-a"], f"unique-{index}", self.clock.iso(),
                ))
        return InvestigationReport(order.case_id, "suspicious", ["flow-a"], [], "none", 0.5,
                                   narrative, proposed_requests=requests)


def test_soc_binds_agent_read_tools_to_actual_tenant(world):
    soc = AISOC(FixedDetector(), AdversarialAgent(world["clock"], "cross_tenant"), clock=world["clock"])
    soc.telemetry.host_windows["tenant-b/host-a"] = {"secret": "TENANT_B_SECRET"}
    result = soc.ingest(synthetic_flow())
    assert result.report["narrative"] == "cross-tenant read rejected"
    assert "TENANT_B_SECRET" not in str(result.report)


def test_soc_enforces_grant_budget_for_compromised_agent(world):
    soc = AISOC(FixedDetector(), AdversarialAgent(world["clock"], "budget"), clock=world["clock"])
    result = soc.ingest(synthetic_flow())
    assert sum(req.executed for req in result.requests) == 3
    assert len(soc.executor.tags[f"case:{result.case_id}"]) == 3


def test_soc_records_malformed_agent_ttl_as_denial_and_finishes_case(world):
    soc = AISOC(FixedDetector(), AdversarialAgent(world["clock"], "malformed"), clock=world["clock"])
    result = soc.ingest(synthetic_flow())
    assert result.requests[0].policy_status == "denied"
    assert not result.requests[0].executed
    assert soc.witness.checkpoints() and soc.results == [result]


@pytest.mark.parametrize("field,value", [
    ("action", []), ("resource", []), ("evidence_ids", None),
    ("evidence_ids", [{}]), ("case_id", []), ("tenant", []),
    ("request_id", None), ("idempotency_key", []),
])
def test_request_structure_is_denied_before_policy_set_operations(world, field, value):
    req = request(world)
    setattr(req, field, value)
    decision = world["policy"].decide(req, world["order"], world["grant"])
    assert decision.status == "denied"
    assert any(field in reason for reason in decision.reasons)


@pytest.mark.parametrize("field,value", [("action", []), ("resource", []), ("evidence_ids", None)])
def test_soc_records_malformed_request_structure_and_finishes_case(world, field, value):
    class MalformedStructureAgent(AdversarialAgent):
        def investigate(self, order, decision, tools):
            report = super().investigate(order, decision, tools)
            setattr(report.proposed_requests[0], field, value)
            return report

    soc = AISOC(FixedDetector(), MalformedStructureAgent(world["clock"], "malformed"), clock=world["clock"])
    result = soc.ingest(synthetic_flow())
    assert result.requests[0].policy_status == "denied"
    assert not result.requests[0].executed
    assert soc.witness.checkpoints() and soc.results == [result]
