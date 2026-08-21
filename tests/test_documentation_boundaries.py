"""Documentation truth-boundary scans (Task 15, Step 1).

Literal scans that require the exact truth distinctions in the published
documentation and forbid unsupported commercial or correctness claims.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DOCS = (
    "README.md",
    "README_en.md",
    "docs/offline-verification.md",
    "docs/status.md",
)
PILOT_DIR = ROOT / "docs/pilot"


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_docs_assert_truth_boundaries() -> None:
    for relative in DOCS:
        text = _text(relative)
        # The docs must separate BOUND from business truth.
        assert ("BOUND" in text and "付款" in text) or (
            "BOUND" in text and "payment" in text
        ), f"{relative} must state the BOUND/payment boundary"


def test_docs_forbid_unsupported_claims() -> None:
    # The plan scans README (both languages) and the pilot materials for
    # affirmative unsupported claims. "自动结算" appears only inside
    # negation boundaries ("不证明…自动结算已发生"), which is the correct
    # statement, so it is checked with a negation-aware pattern here.
    forbidden_affirmative = (
        "已收定金",
        "已有客户采用",
        "guarantees correctness",
        "production proven",
    )
    scanned = ("README.md", "README_en.md")
    for relative in scanned:
        text = _text(relative)
        for phrase in forbidden_affirmative:
            assert phrase not in text, (
                f"{relative} must not claim: {phrase}"
            )
        # 自动结算 must only appear in a negation boundary, never
        # affirmatively.
        for match in ("自动结算", "auto-settlement"):
            if match in text:
                lines = text.splitlines()
                index = next(
                    index
                    for index, line in enumerate(lines)
                    if match in line
                )
                window = "\n".join(
                    lines[max(0, index - 1): index + 2]
                )
                assert any(
                    token in window
                    for token in ("不", "未", "没有", "never", "does not", "not")
                ), f"{relative} must not affirm auto-settlement"


def test_pilot_materials_are_falsifiable() -> None:
    offer = (PILOT_DIR / "judgment-action-binding-21-day-offer.md").read_text(
        encoding="utf-8"
    )
    for requirement in (
        "30,000–50,000",
        "50%",
        "8 人日",
        "2,000",
        "not_evidenced",
        "停止",
    ):
        assert requirement in offer, f"offer missing: {requirement}"


def test_pilot_commercial_fields_are_external() -> None:
    for name in ("result-template", "21-day-offer"):
        text = (
            PILOT_DIR / f"judgment-action-binding-{name}.md"
        ).read_text(encoding="utf-8")
        assert "not_evidenced" in text
        assert "协议状态绝不制造商业事实" in text or (
            "协议不证明收到定金" in text
        )


def test_v13_docs_expose_both_surfaces_without_unearned_claims() -> None:
    chinese = _text("README.md")
    english = _text("README_en.md")
    status = _text("docs/status.md")
    pilot = _text("docs/pilot/README.md")

    assert "GitHub Action" in chinese
    assert "AgentTeams" in chinese
    assert "四问" in chinese
    assert "GitHub Action" in english
    assert "AgentTeams" in english
    assert "four-question" in english

    combined = "\n".join((chinese, english, status, pilot))
    for boundary in (
        "customer_adoption: not_evidenced",
        "paid_sow: not_evidenced",
        "deposit: not_evidenced",
        "upstream_adoption: not_evidenced",
        "agentteams_live_execution: not_evidenced",
        "human_acceptance: not_evidenced",
    ):
        assert boundary in combined


def test_v13_pilot_has_bounded_inputs_deliverables_and_exclusions() -> None:
    pilot = _text("docs/pilot/README.md")
    normalized = " ".join(pilot.split())
    for requirement in (
        "真实私有仓库或脱敏仓库",
        "一个 Agent PR 流程",
        "客户 Verifier 密钥绑定",
        "客户 Acceptor",
        "三个 Surface Bundle",
        "差异报告",
        "人工验收 SOP",
        "不包含代开发",
        "不提供付款担保",
        "不构成法律审计",
        "不包含无限期运维",
    ):
        assert requirement in normalized, f"pilot missing: {requirement}"


def test_portable_ci_runs_tests_and_frozen_compatibility() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "python -m pytest -q" in workflow
    assert "tests/test_schema_registry.py" in workflow
    assert "python -m pip check" in workflow
    assert "python -m compileall -q src tests" in workflow
    assert "OPENWORKPROOF_REQUIRE_LIVE" not in workflow


def test_acceptance_bundle_workflow_and_boundaries_are_documented() -> None:
    chinese = _text("README.md")
    english = _text("README_en.md")
    status = _text("docs/status.md")

    for text in (chinese, english):
        for literal in (
            "AcceptanceDecisionBindingV01",
            "prepare → sign → commit",
            "owp acceptance-bundle-build",
            "owp acceptance-bundle-verify",
            "ACCEPTED=0",
            "REJECTED=2",
            "operational=4",
            "--acceptance-bundle",
            "VERIFIED != ACCEPTED != PAID/SETTLED/LEGAL AUDIT/ADOPTION",
        ):
            assert literal in text, f"acceptance docs missing: {literal}"
    assert "双签" in chinese
    assert "缺失 binding" in chinese
    assert "dual signature" in english
    assert "missing binding" in english
    assert "外部人工验收" in chinese
    assert "external human acceptance" in english
    for boundary in (
        "agentteams_live_execution: not_evidenced",
        "human_acceptance: not_evidenced",
        "customer_adoption: not_evidenced",
        "paid_sow: not_evidenced",
        "deposit: not_evidenced",
        "upstream_adoption: not_evidenced",
    ):
        assert boundary in status


def test_verified_delivery_docs_close_commercial_boundaries() -> None:
    root = ROOT / "docs/commercial/verified-agent-delivery"
    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(root.iterdir())
    )
    for literal in (
        "Delivery Provider",
        "Customer Acceptor",
        "not_evidenced",
        "READY_FOR_SETTLEMENT_REVIEW",
        "不托管资金",
        "不等于付款",
        "停止条件",
    ):
        assert literal in combined, f"verified delivery docs missing: {literal}"
    for forbidden in ("保证回款", "自动付款", "法律公证", "已有客户采用"):
        assert forbidden not in combined, f"forbidden claim present: {forbidden}"


def test_verified_delivery_example_json_is_strictly_closed() -> None:
    from openworkproof.delivery_case import ExternalEvidenceReferenceV01

    root = ROOT / "docs/commercial/verified-agent-delivery"
    for name in ("sow-reference.example.json", "payer-status.example.json"):
        payload = (root / name).read_bytes()
        import json as _json

        import rfc8785 as _rfc8785

        raw = _json.loads(payload)
        reference = ExternalEvidenceReferenceV01.model_validate(raw)
        assert reference.status == "not_evidenced"
        assert reference.reference_digest is None
        assert reference.observed_at is None
        assert _rfc8785.dumps(reference.model_dump(mode="json")) == payload
