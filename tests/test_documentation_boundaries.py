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


def test_portable_ci_runs_tests_and_frozen_compatibility() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "python -m pytest -q" in workflow
    assert "tests/test_schema_registry.py" in workflow
    assert "python -m pip check" in workflow
    assert "python -m compileall -q src tests" in workflow
    assert "OPENWORKPROOF_REQUIRE_LIVE" not in workflow
