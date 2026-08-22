# OpenWorkProof README Live Status Refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refresh the Chinese and English READMEs with the implemented Verified Agent Delivery surface, the live AgentTeams three-role preflight, and the fresh `3987 passed / 0 failed / 0 skipped` required-live result without overstating business execution or acceptance.

**Architecture:** Treat `README.md` and `README_en.md` as two language views of one evidence statement. Update the same four semantic areas in both files, then use repository documentation tests and literal searches to prevent stale or asymmetric claims.

**Tech Stack:** Markdown, pytest documentation-boundary tests, ripgrep, and Git.

---

### Task 1: Refresh the Chinese README

**Files:**
- Modify: `README.md:58-60`
- Modify: `README.md:720-740`

- [x] **Step 1: Replace the AgentTeams evidence paragraph**

Replace the paragraph that says the real three-Agent environment is not evidenced with a four-level status statement:

```text
agentteams_live_environment: evidenced
agentteams_three_role_preflight: evidenced
agentteams_end_to_end_business_execution: not_evidenced
human_acceptance: not_evidenced
```

Explain that the live preflight observed Manager, Developer, and Verifier as three distinct roles with distinct Matrix identities and OpenWorkProof key IDs. State explicitly that this does not prove a fresh Manager → Developer → Verifier business execution or a human Acceptor terminal decision.

- [x] **Step 2: Add Verified Agent Delivery to the implemented list**

Add one bullet describing the implemented delivery-case model, CLI, deterministic export, GitHub Action, commercial intake templates, and fail-closed derivation from Surface / Acceptance / Settlement evidence. Keep `READY_FOR_SETTLEMENT_REVIEW` distinct from payment or settlement.

- [x] **Step 3: Replace the stale current gate snapshot**

Replace the current `3773 passed / 1 skipped` paragraph with:

```text
required-live 全量：3987 passed、0 failed、0 skipped
```

State that `OPENWORKPROOF_AGENTTEAMS_REQUIRED=1` was enabled and the live three-role preflight passed. Do not change the historical 1.2.0 snapshot.

- [x] **Step 4: Narrow the unfinished boundary**

Remove “AgentTeams 真实三 Agent 环境未启用” from the unfinished list. Retain fresh end-to-end business execution, external human acceptance, customer adoption/payment/settlement, remaining handler/evidence closures, and formal competition submission as unfinished or not evidenced.

### Task 2: Mirror the same evidence in the English README

**Files:**
- Modify: `README_en.md:63-66`
- Modify: `README_en.md:745-766`

- [x] **Step 1: Translate the AgentTeams evidence levels without changing meaning**

Use these exact evidence keys:

```text
agentteams_live_environment: evidenced
agentteams_three_role_preflight: evidenced
agentteams_end_to_end_business_execution: not_evidenced
human_acceptance: not_evidenced
```

Describe the same three distinct roles, Matrix identities, and OpenWorkProof key IDs as the Chinese README. Preserve the distinction between live preflight and an end-to-end business run.

- [x] **Step 2: Mirror the Verified Agent Delivery capability bullet**

Mention the same model, CLI, deterministic export, GitHub Action, commercial templates, and evidence-derived status. Preserve `READY_FOR_SETTLEMENT_REVIEW != payment or completed settlement`.

- [x] **Step 3: Mirror the fresh gate result and unfinished boundary**

Use `3987 passed, 0 failed, 0 skipped`, state that the live three-role preflight was required and passed, and retain the same unfinished business evidence and implementation boundaries as the Chinese README.

### Task 3: Verify documentation truth and language parity

**Files:**
- Test: `tests/test_documentation_boundaries.py`
- Test: `tests/test_github_action_contract.py`
- Test: `tests/test_delivery_case_cli_v01.py`

- [x] **Step 1: Run focused documentation and commercial-surface tests**

Run:

```bash
./.venv/bin/python -m pytest -q \
  tests/test_documentation_boundaries.py \
  tests/test_github_action_contract.py \
  tests/test_delivery_case_cli_v01.py
```

Expected: exit code 0 and no failed tests.

- [x] **Step 2: Reject stale current-state wording**

Run:

```bash
! rg -n '3773 passed / 1 skipped|3773 passed、1 skipped|真实三 Agent 环境，因此严格发布门尚未闭合|only required-live skip is the unenabled live three-Agent' README.md README_en.md
```

Expected: exit code 0 because none of the stale phrases remain.

- [x] **Step 3: Confirm paired evidence keys and result counts**

Run:

```bash
for file in README.md README_en.md; do
  rg -q 'agentteams_live_environment: evidenced' "$file"
  rg -q 'agentteams_three_role_preflight: evidenced' "$file"
  rg -q 'agentteams_end_to_end_business_execution: not_evidenced' "$file"
  rg -q 'human_acceptance: not_evidenced' "$file"
  rg -q '3987 passed' "$file"
done
```

Expected: exit code 0.

- [x] **Step 4: Check the patch and commit**

Run:

```bash
git diff --check
git diff -- README.md README_en.md
git add README.md README_en.md \
  docs/superpowers/plans/2026-08-22-openworkproof-readme-live-status-refresh.md
git commit -m "docs: refresh live delivery status"
```

Expected: a documentation-only commit with no source, test, schema, version, or release-state changes.
