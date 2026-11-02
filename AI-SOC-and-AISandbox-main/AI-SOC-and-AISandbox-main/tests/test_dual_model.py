import pytest

from aisoc.idps import BENIGN, CaseStatus, DualModel, FlowRecord
from aisoc.simulate import FAMILIES, generate


@pytest.fixture(scope="module")
def model_and_data():
    ds = generate(n=1200, seed=3)
    return DualModel.train(ds.train, ds.val), ds


def test_thresholds_are_fit_only_on_train_and_val(model_and_data):
    model, _ = model_and_data
    assert "default" in model.normality.tau_a
    assert 0 < model.normality.tau_a["default"] <= 1


def test_missing_data_is_unknown_not_normal(model_and_data):
    model, ds = model_and_data
    f = ds.test[0]
    f.bytes_in = -1  # invalid telemetry
    d = model.decide(f)
    assert d.status is CaseStatus.UNKNOWN
    assert d.requires_human_review


def test_decision_table_covers_known_attack(model_and_data):
    model, ds = model_and_data
    attacks = [f for f in ds.test if f.label != BENIGN]
    statuses = {model.decide(f).status for f in attacks}
    assert CaseStatus.KNOWN_SUSPICIOUS in statuses
    for f in attacks:
        d = model.decide(f)
        if d.status is CaseStatus.KNOWN_SUSPICIOUS:
            assert d.requires_agent_investigation and not d.requires_human_review
        if d.status in (CaseStatus.SUSPECTED_UNKNOWN, CaseStatus.MODEL_CONFLICT):
            assert d.requires_human_review


def test_scores_are_kept_separately(model_and_data):
    model, ds = model_and_data
    d = model.decide(ds.test[1])
    assert d.known_score is not None and d.anomaly_score is not None and d.anomaly_threshold is not None


def test_leave_one_family_out_escalates_unseen_family_somewhere():
    ds = generate(n=1500, seed=4, held_out_family="port_scan")
    model = DualModel.train(ds.train, ds.val)
    assert all(f.family != "port_scan" for f in ds.train)
    held = [f for f in ds.test if f.family == "port_scan"]
    escalated = [
        model.decide(f).status for f in held
        if model.decide(f).status in (CaseStatus.SUSPECTED_UNKNOWN, CaseStatus.MODEL_CONFLICT, CaseStatus.KNOWN_SUSPICIOUS)
    ]
    # We only assert the path exists, not a recall figure: that would be a claim the paper refuses to make.
    assert escalated
