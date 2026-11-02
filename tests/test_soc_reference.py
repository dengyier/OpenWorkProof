import json

import pytest

from openworkproof.soc_reference import analyze_slips, sample_alerts, verify_soc_bundle


def test_supplied_alerts_produce_reference_cases_and_untrusted_offline_bundle():
    result = analyze_slips(sample_alerts()["alerts_jsonl"], "trial-tenant")
    assert result["summary"]["cases"] > 0
    assert result["mode"] == "reference_only"
    assert result["real_host_actions"] is False
    assert all(case["human_acceptance_obtained"] is False for case in result["cases"])
    assert all("acceptance_status" not in case for case in result["cases"])
    bundle = result["bundle"]
    checked = verify_soc_bundle(json.dumps(bundle))
    assert checked["status"] == "UNKNOWN"
    pinned = verify_soc_bundle(
        json.dumps(bundle), json.dumps(bundle["trusted-keys.json"]),
        json.dumps(bundle["witness-checkpoints.json"]),
    )
    assert pinned["status"] == "VERIFIED"
    assert "caller" in pinned["trust_scope"].lower()


def test_reference_bundle_rejects_deleted_receipts_with_pinned_trust():
    bundle = analyze_slips(sample_alerts()["alerts_jsonl"], "trial")["bundle"]
    assert bundle["tool-side-receipts.json"]
    bundle["tool-side-receipts.json"] = []
    checked = verify_soc_bundle(json.dumps(bundle), json.dumps(bundle["trusted-keys.json"]),
                                json.dumps(bundle["witness-checkpoints.json"]))
    assert checked["status"] == "FAILED"


@pytest.mark.parametrize("text", ["", "{}", "x" * (128 * 1024 + 1), "{}\n" * 501])
def test_alert_input_requires_supported_nonempty_bounded_content(text):
    with pytest.raises(ValueError):
        analyze_slips(text, "trial")


@pytest.mark.parametrize("tenant", ["", "a" * 129])
def test_tenant_identifier_is_required_and_bounded(tenant):
    with pytest.raises(ValueError):
        analyze_slips(sample_alerts()["alerts_jsonl"], tenant)


def test_mcp_exposes_callable_reference_tools():
    from openworkproof import mcp_transport as transport
    example = transport.owp_soc_sample_alerts()
    assert example["ok"]
    result = transport.owp_soc_analyze_slips(example["alerts_jsonl"], "trial")
    assert result["ok"] and result["summary"]["cases"] > 0
    checked = transport.owp_soc_verify_bundle(json.dumps(result["bundle"]))
    assert checked["ok"] and checked["status"] == "UNKNOWN"
    assert transport.owp_soc_analyze_slips("", "trial")["ok"] is False
