"""Documentation truth-boundary scans (Task 15, Step 1).

Literal scans that require the exact truth distinctions in the published
documentation and forbid unsupported commercial or correctness claims.
"""

from __future__ import annotations

import re
import subprocess
import sys
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


def test_deepseek_harness_docs_state_exact_security_and_claim_boundaries() -> None:
    combined = "\n".join(
        _text(relative)
        for relative in (
            "README.md",
            "README_en.md",
            "docs/status.md",
            "docs/integrations/deepseek-harness.md",
        )
    )
    for literal in (
        "DeepSeek Harness 0.1.1-rc.2",
        "Audit emits ObservationRecord",
        "Disabled means NOT_CONFIGURED",
        "Enforce denies native write/edit/bash/pwsh/str_replace_editor/cordis_define/cordis_run/cordis_stop/cordis_undefine",
        "HOST_VERSION_INCOMPATIBLE",
        "VERIFIED != ACCEPTED",
        "Manager and Acceptor private keys remain outside Harness",
        "customer_adoption: not_evidenced",
        "deepseek_endorsement: not_evidenced",
    ):
        assert literal in combined, f"DeepSeek Harness docs missing: {literal}"


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


# --- Human Agency Profile v0.1 (Task 8) truth boundaries ---

AGENCY_PROTOCOL_DOC = "docs/protocol/human-agency-profile-v0.1.md"


def test_human_agency_readmes_are_authorization_boundaries_not_surveillance() -> None:
    """Both READMEs state the boundary and deny surveillance/compliance meaning."""

    chinese = _text("README.md")
    english = _text("README_en.md")

    # Chinese: WorkOrder-bound, Acceptor-signed, machine-verifiable.
    for literal in ("Human Agency Profile", "WorkOrder 绑定", "Acceptor 签名", "机器可验证"):
        assert literal in chinese, f"README.md missing: {literal}"
    # Chinese negation of unsupported meanings.
    assert "不是员工评分、绩效监控、法律责任转移、自动担责、资金托管或合规认证" in chinese

    # English: same three facts.
    for literal in ("Human Agency Profile", "WorkOrder-bound", "Acceptor-signed", "machine-verifiable"):
        assert literal in english, f"README_en.md missing: {literal}"
    assert (
        "not employee scoring, performance monitoring, legal-liability transfer, "
        "automatic accountability, fund custody, or compliance certification"
    ) in english

    # Both languages link the protocol doc and the runnable example.
    for text in (chinese, english):
        assert "docs/protocol/human-agency-profile-v0.1.md" in text
        assert "examples/human_agency_profile_v01.py" in text


def test_human_agency_appeal_records_but_never_restores() -> None:
    """Appeal is a signed request, not a permission change; only Acceptor transitions."""

    chinese = _text("README.md")
    english = _text("README_en.md")
    protocol = _text(AGENCY_PROTOCOL_DOC)

    assert "不恢复或扩大权限" in chinese
    assert (
        "只有 Acceptor 签名的 transition 才能撤销当前 profile "
        "或将其替换为另一个 Acceptor 签名的 profile"
    ) in chinese

    assert "never restores or expands permission" in english
    assert (
        "only an Acceptor-signed transition can revoke the active profile "
        "or supersede it with another Acceptor-signed profile"
    ) in english

    # The protocol doc must make the same precise claim, not a grant-mutation one.
    assert "revoke or replace the grant" not in protocol
    assert (
        "Only an Acceptor-signed transition can revoke the active profile "
        "or supersede it with another Acceptor-signed profile"
    ) in protocol


def test_human_agency_protocol_doc_names_three_objects_and_roles() -> None:
    text = _text(AGENCY_PROTOCOL_DOC)
    for name in (
        "HumanAgencyProfileV01",
        "AgencyProfileTransitionV01",
        "AgencyAppealV01",
    ):
        assert name in text, f"protocol doc missing object: {name}"
    for role in ("Acceptor", "Manager", "Developer", "Verifier"):
        assert role in text, f"protocol doc missing role: {role}"


def test_human_agency_protocol_doc_genesis_is_signature_verified() -> None:
    """The genesis profile is signature-verified, never 'unsigned'; all three objects are signed."""

    text = _text(AGENCY_PROTOCOL_DOC)
    assert "unsigned genesis" not in text
    assert (
        "signature-verified genesis profile with no incoming transition" in text
    )
    assert "All three objects are closed, immutable, signed protocol objects" in text


def test_human_agency_protocol_doc_protected_dispatcher_four_tools() -> None:
    text = _text(AGENCY_PROTOCOL_DOC)
    for tool in (
        "owp.repo_read",
        "owp.apply_patch",
        "owp.run_tests",
        "owp.rollback_patch",
    ):
        assert tool in text, f"protocol doc missing protected tool: {tool}"


def test_human_agency_protocol_doc_schema_is_structural_gate_only() -> None:
    text = _text(AGENCY_PROTOCOL_DOC)
    assert "JSON Schema" in text
    assert "structural" in text
    # Semantic facts are NOT expressed by the schema and still need OWP verifier.
    for literal in (
        "content-derived",
        "WorkOrder binding",
        "Ed25519",
        "causal",
    ):
        assert literal in text, f"protocol doc missing semantic boundary: {literal}"


def test_human_agency_protocol_doc_offline_bundle_freshness_boundary() -> None:
    text = _text(AGENCY_PROTOCOL_DOC)
    assert "snapshot" in text
    assert "TSA" in text
    assert "freshness" in text


def test_human_agency_protocol_doc_offline_bundle_layout_matches_implementation() -> None:
    """The offline layout names every enforced file, including the pinned verify.sh."""

    text = _text(AGENCY_PROTOCOL_DOC)

    # The verifier requires these exact files and allowlists these directory
    # patterns (agency_bundle._REQUIRED_AGENCY_FILES + _path_is_allowed).
    for literal in (
        "agency-manifest.json",
        "agency/work-order.json",
        "verify.sh",
        "agency/profiles/",
        "agency/transitions/",
        "agency/appeals/",
    ):
        assert literal in text, f"protocol doc missing offline layout: {literal}"

    # "key-free" is misleading: the signed WorkOrder carries the verification
    # public key, so the bundle is private-key-free / self-contained, not key-free.
    assert "key-free offline bundle" not in text
    for literal in ("private-key-free", "self-contained"):
        assert literal in text, f"protocol doc missing bundle term: {literal}"

    # verify.sh is itself manifest-entry covered and pinned to the exact
    # production bytes. Derive the expected content from the production constant
    # so the doc cannot silently drift from the implementation.
    from openworkproof.agency_bundle import AGENCY_VERIFY_SCRIPT

    assert isinstance(AGENCY_VERIFY_SCRIPT, bytes) and AGENCY_VERIFY_SCRIPT
    assert AGENCY_VERIFY_SCRIPT.decode("utf-8") in text, (
        "protocol doc must show the exact pinned verify.sh content"
    )
    assert "covered by the manifest entries" in text


def test_human_agency_protocol_doc_denies_unsupported_meanings() -> None:
    text = _text(AGENCY_PROTOCOL_DOC)
    assert (
        "not employee scoring, performance monitoring, legal-liability transfer, "
        "automatic accountability, fund custody, or compliance certification"
    ) in text


def test_human_agency_protocol_doc_authorization_ordering_and_threat_model() -> None:
    text = _text(AGENCY_PROTOCOL_DOC)
    assert "target lock" in text
    assert "fail closed" in text or "fail-closed" in text
    assert "threat model" in text
    # Base authorization runs before the agency layer.
    assert "base authorization" in text


def test_status_keeps_agency_commercial_fields_not_evidenced() -> None:
    status = _text("docs/status.md")
    lines = {line.strip() for line in status.splitlines()}
    for boundary in (
        "customer_adoption: not_evidenced",
        "payment: not_evidenced",
        "upstream_adoption: not_evidenced",
    ):
        assert boundary in lines, f"status.md missing: {boundary}"


def _run_human_agency_example() -> tuple[int, bytes, bytes]:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "examples" / "human_agency_profile_v01.py")],
        capture_output=True,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def test_human_agency_example_output_is_byte_stable_and_secret_free() -> None:
    """Two consecutive runs print identical bytes, exit 0, and leak no random id/digest/key."""

    first_rc, first_out, _ = _run_human_agency_example()
    second_rc, second_out, _ = _run_human_agency_example()

    assert first_rc == 0
    assert second_rc == 0
    assert first_out == second_out, (
        "example stdout must be byte-identical across runs"
    )

    text = first_out.decode("utf-8")
    # The stable facts the example is allowed to print.
    assert "profile verified  : True" in text
    assert "resolved status   : active" in text
    assert "owp.repo_read     : delegated -> allowed" in text
    assert "owp.apply_patch   : reserved -> AGENCY_HUMAN_DECISION_REQUIRED" in text
    # Ephemeral keys may exist, but no random digest/id or private key may print.
    assert "work_order_digest" not in text
    assert "profile_id" not in text
    assert "ed25519:" not in text
    assert "PRIVATE KEY" not in text
    assert re.search(r"[0-9a-f]{64}", text) is None


def test_human_agency_example_describes_application_side_effects_precisely() -> None:
    """The example must not confuse interpreter bytecode caches with protocol writes."""

    source = _text("examples/human_agency_profile_v01.py")
    normalized = " ".join(source.split())
    assert "never writes to a ledger or a filesystem" not in normalized
    assert "no application-level filesystem or ledger writes" in normalized
    assert "never writes a private-key file" in normalized


# --- Human-centered README narrative ---


def test_readmes_lead_with_human_purpose_and_judgment() -> None:
    chinese = _text("README.md")
    english = _text("README_en.md")

    chinese_lead = "\n".join(chinese.splitlines()[:60])
    english_lead = "\n".join(english.splitlines()[:60])

    assert "让智能依人的目的而行动，让每一次行动经得起人的判断。" in chinese_lead
    assert "OpenWorkProof 是 AI Agent 工作契约与可验证执行协议。" in chinese_lead
    assert (
        "Let intelligence act toward human purposes, and let every action "
        "stand up to human judgment."
    ) in english_lead
    assert (
        "OpenWorkProof is an open work contract and verifiable execution "
        "protocol for AI agents."
    ) in english_lead


def test_readmes_preserve_purpose_authority_evidence_and_human_judgment() -> None:
    chinese = _text("README.md")
    english = _text("README_en.md")

    for literal in (
        "人的目的",
        "签名授权",
        "独立验证",
        "接受、拒绝、撤销和申诉",
        "最终判断",
    ):
        assert literal in chinese, f"README.md missing: {literal}"

    for literal in (
        "human purposes",
        "signed authority",
        "independent verification",
        "accept, reject, revoke, and appeal",
        "final judgment",
    ):
        assert literal in english, f"README_en.md missing: {literal}"


def test_readmes_keep_current_release_and_test_boundaries_aligned() -> None:
    chinese = _text("README.md")
    english = _text("README_en.md")

    for text in (chinese, english):
        for literal in (
            "1.4.0",
            "97 passed",
            "80 passed",
            "186 passed",
            "4373 passed",
            "0 failed",
            "0 skipped",
        ):
            assert literal in text, f"README release boundary missing: {literal}"

    assert "本地候选" in chinese
    assert "尚未发布" in chinese
    assert "外部发布 READY" in chinese
    assert "local candidate" in english
    assert "not released" in english
    assert "external-release READY" in english


def test_readmes_do_not_turn_the_homepage_into_fundraising_or_market_copy() -> None:
    forbidden = (
        "Gartner",
        "$48M",
        "$65M",
        "融资",
        "funding",
        "百亿美元市场",
        "$10B+ market",
    )
    for relative in ("README.md", "README_en.md"):
        text = _text(relative)
        for literal in forbidden:
            assert literal not in text, f"{relative} contains market copy: {literal}"


def test_readmes_place_openworkproof_beyond_connection_protocols() -> None:
    chinese = _text("README.md")
    english = _text("README_en.md")

    assert "MCP 连接 Agent 与工具，A2A 连接 Agent 与 Agent。" in chinese
    assert "MCP connects agents to tools. A2A connects agents to agents." in english
