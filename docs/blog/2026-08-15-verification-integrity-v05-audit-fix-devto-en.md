---
title: "Verifying the Verifier: How an Independent Audit Hardened OpenWorkProof v0.5"
published: false
description: "Agents now do engineering work. But who verifies what the verifying agent actually verified? OpenWorkProof v0.5 freezes authorization, scope, population completeness, and negative-control semantics into a signed, replayable evidence chain — and this update is the story of an external audit that attacked it and how every finding was closed."
tags: security, python, opensource, testing
---

# Verifying the Verifier: How an Independent Audit Hardened OpenWorkProof v0.5

> Repo: [github.com/dengyier/OpenWorkProof](https://github.com/dengyier/OpenWorkProof)
> This update: `af00586..39369db` (15 commits; final candidate inventory `d460c876a7f3…`)

## What this is for (the 30-second version for everyone)

Increasingly, the person "doing the work" is an agent, and the person "checking the work" is also an agent. The moment you pay, merge, deploy, or ship on an agent's say-so, you have a new question: **who verifies the verifier?**

OpenWorkProof is a Python protocol layer that answers that question with evidence instead of vibes. It takes one unit of agent work — a task, a git change, a test run — and freezes four things into a signed, append-only, **offline-replayable** chain:

1. **Authorization** — who was allowed to do this work, signed by keys.
2. **Scope** — exactly which files and which tests were claimed, and what was actually observed; the two must be byte-identical.
3. **Population completeness** — if the engine saw *N* eligible tests but the selector picked *zero*, that run does not pass. (Call this the "tested nothing, reported green" blind spot.)
4. **Negative-control semantics** — a deliberately injected mutation must not merely *fail*; it must fail *for the registered reason* (error code / predicate signature). "Failed by accident" ≠ "failed as designed".

The verdict is deliberately three-valued and monotonic: `VERIFIED`, `REFUTED`, `UNKNOWN` — where `UNKNOWN` is a safe conclusion, not a crash. The CLI is fail-closed: `VERIFIED=0`, `UNKNOWN=3`, `REFUTED=4`.

For business readers: this is **not** a payment rail, not an auto-settlement system, and not a claim that any customer adopted it. It is a protocol capability, demonstrated on our own work item (Rich #4196). What it buys you is a concrete answer to "what exactly was verified, by whom, against which inputs — and can I replay that myself without trusting anyone's server?"

## Why v0.5 is designed this way

v0.3 proved "claimed scope == observed scope, exactly." The design of v0.5 follows from two attacks v0.3 could not see:

- **The population blind spot.** An executor sees many eligible tests; a selector may legally choose a subset — or zero. A run that selects nothing ends successfully and, under older semantics, looked green. v0.5 therefore binds *what was eligible, what was excluded, and why* into the signed selector spec, and requires a positive match before `VERIFIED` is reachable.
- **Negative-control corruption.** A registered mutation "failing" is meaningless unless the *failure signature* matches the registered one. v0.5 stores the signature and requires `observed == signed == expected` before a control arm is `proven`.

Two engineering principles carry the rest of the design:

- **Never trust the agent's self-report.** Every decision is recomposed from canonical signed rows and re-signed; a plain JSON report with a self-hash is treated as untrusted input, not truth.
- **Evidence must survive offline.** Deliveries are bundles you can re-verify with no network and no original ledger, against an **immutable candidate inventory** — a supply-chain record bound to exact source bytes and fully-qualified image digests. Any source change invalidates the old inventory by construction.

## The audit: we invited someone to break it

After the implementation was "done," we commissioned an independent external review — and it declined to take our word for anything. It reproduced attacks by hand and returned **2 Critical + 5 Important + minors**:

- **Critical 1 — offline package authenticity.** The `scope-coverage-report.json` was self-hashed JSON. The customer-private view replayed the signed objects and then **threw away the recomputed decision**, returning fields from the report instead; the public/diagnostic views had no signed objects at all yet could still return `READY_FOR_ACCEPTANCE`. Reproduction: tamper the report's decision, re-sync the manifest hash/size — signature verification still passes; a public package can be forged into `VERIFIED` from zero.
- **Critical 2 — selector inputs not frozen.** The git selector's spec digest omitted allowlist/excluded/required locators; pytest's omitted `selector_args`/`required_node_ids`; the pytest adapter treated *any stdout line containing `::`* as an authoritative node id. Reproduction: two different allowlists (or argument sets) with identical output produced byte-identical observations and evidence — both satisfied.
- **Important 1** — decision loading checked only the Decision ↔ parent ID link; it never loaded or validated Arm Results, never recomposed, never checked `committed_at`. Deleting every Arm Result row still loaded `VERIFIED`.
- **Important 2** — control evidence `PROVEN` required only non-empty refs + a self-reported matching signature: any `{"arm": "negative"}` JSON could be proven.
- **Important 3** — `Path.resolve()` dereferenced `.venv/bin/python` into the base interpreter; `-m pytest` lost site-packages and died with ModuleNotFoundError.
- **Important 4** — the CLI could exit 0 on `UNKNOWN`/`REFUTED`, and audit-explain/compare bypassed the v0.5 derived functions.
- **Important 5** — several matrix entries "existed as test names" without covering what they claimed; the plan referenced phantom test filenames.

## How we closed it: attack tests first (RED → minimal fix → dual review)

Every finding was handled the same way: write an **attack-shaped test**, confirm it is RED against the old code, apply the smallest fix, commit, then have two independent sub-agents review — one against the spec, one for quality/security. Critical and Important findings blocked progress until closed.

- **Batch A — offline packages trust only replayed signed truth.** The customer-private verdict now comes solely from the recomposed, signature-verified `Decision`; the report is compared field-by-field against the replay and any divergence fails closed. Public/diagnostic views — which carry no signed redacted attestation — return `UNAUTHENTICATED` / `NOT_READY`. Attack tests: forged report decision + synced manifest; from-zero forgery of a public package.
- **Batch B — freeze every selector input into the digest.** Allow/exclude/require parameters are canonicalized into `selector_spec_digest` for both selectors; node ids come only from a **controlled canonical collector** (a closed JSON file written at `pytest_collection_finish`); stdout is never parsed. Reviewers then demonstrated two further bypasses — a nested `conftest.py` (trylast hook) and a root-level `pytest.py` shadowing the real pytest — closed with **conftest-free refusal** and **`-I` isolation**, each with its own regression test.
- **Batch C — decision history is fully replayed at every entry point.** `_load_current_decision_v05` now loads canonical Arm Results by parent chain, validates each row (id/digest/authority/signature/evidence), recomposes every chain link from its predecessor requiring identical signing bytes, and enforces canonical `committed_at` plus causal/monotonic ordering (leap seconds rejected). Attack tests: deleted parent rows, row swaps, timestamp tampering, relation drift.
- **Batch D — a closed control-evidence resolver.** A 9-key canonical document (`openworkproof-control-evidence/0.5`) is now the only accepted shape; ledger and offline package share one resolver; `proven` requires `evidence fact == signed observation == registered expectation`. Attack tests: legacy blob shapes, contradictory facts, missing evidence.
- **Batch E — respect the venv launcher.** Keep the absolute invocation path (no final-symlink dereference), bind the real target, `pyvenv.cfg`, and executable digest separately; a real `.venv` regression test drives a real pytest collection.
- **Batch F — CLI parity.** Unified exit map (`VERIFIED=0 / UNKNOWN=3 / REFUTED=4`, unrecognized values fail closed to 3); audit-explain/compare reuse the v0.5 derived functions; end-to-end CLI tests cover all three verdicts.
- **Batch G — matrix, supply chain, and plan truth.** Added fault injection (insert / before-COMMIT / readback) and same-id concurrency for Profile/Arm/Decision, physical tampering across all six v0.5 table families; the archive converter rejects duplicate tar members, absolute paths, and `..`, and derives platform from the real config; eliminated pytest tmpdir cleanup noise; corrected phantom test filenames and the `_ledger_delivery_protocol` text in the plan.

## Re-freezing the release: immutable inventory + five gates

Because any source change invalidates the old inventory (by design), we rebuilt the candidate after the minors closed:

- Candidate inventory: `supply-chain/images/candidates/d460c876a7f3046fd1d338951d964bce6d1a6be1.json` (fully qualified `docker.io/openworkproof/execution-test@sha256:2acf4820…`)
- focused v0.5: **370 passed**
- frozen v0.2–v0.4 compatibility: **216 passed**
- portable full suite: **3348 passed / 0 failed / 6 skipped**
- candidate live-Docker suites: **173 passed**
- **required-live full run: 3456 passed / 0 failed / 0 skipped, zero warnings**
- Rich #4196 offline delivery bundle: **VERIFICATION PASSED** (no network, no original ledger)

## What this does not claim

Green tests and offline replays do **not** equal customer adoption, paid SOW, deposits, upstream adoption, or commercial validation — those states remain `not_evidenced`. OpenWorkProof is a complementary layer: it freezes authorization, scope evidence, population completeness, and negative-control semantics for one unit of work. It does not replace MCP/A2A interoperability or identity, and it does not execute payment or settlement.

If you have been burned by "the agent said it verified it," we'd like to hear from you — and we invite independent reproduction of both the attack tests and the candidate supply chain.
