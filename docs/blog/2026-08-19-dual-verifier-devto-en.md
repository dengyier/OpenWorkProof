---
title: "Two Verifiers, One Verdict: Closing the 'Self-Reported Exit Code' Hole"
published: false
description: "An agent says 'tests all green'. Another agent says 'I reviewed it — it's fine.' Two independent executions, two keys, one verdict — or no decision at all. OpenWorkProof v0.5's dual-verifier cross-validation, built in 7 review rounds against adversarial probes."
tags: security, python, opensource, aiagents
---

# Two Verifiers, One Verdict: Closing the "Self-Reported Exit Code" Hole

> Repo: [github.com/dengyier/OpenWorkProof](https://github.com/dengyier/OpenWorkProof)
> This update: `04e62d5..ec0e72e` (29 commits across three phases; candidate inventory `837dbb10a3fdc4…`)

## The problem: "two sub-agents reviewed it" is not independence

In public code reviews of agent tooling, two objections keep coming back:

1. **"Two sub-agents reviewing the same work is not independence."** If both reviewers read the same log written by the same actor, they are two signatures on one story — not two executions of that story.
2. **"The exit code is self-reported."** An agent says `tests all green`. The report says so. The log says so. But nothing binds that claim to what actually ran. Nothing stops the agent from editing the test instead of the bug and then reporting green with a straight face.

OpenWorkProof v0.5 now answers both with the same mechanism: **two independent verifiers must each execute the work and each sign their own result — and their conclusion-bearing fields must agree field by field, or no decision is formed at all.**

## What "dual verifier" means here

A high-risk decision (e.g. the kind you'd pay for) requires:

- **Two distinct verifier bindings** — different keys, different subjects, different controllers, different execution contexts (all enforced at profile construction).
- **Each verifier covers every arm** — positive arm, negative controls, population observations, scope evidence. One verifier doing the positive arm and another doing the negative arm is rejected ("split coverage").
- **Every conclusion-bearing field must converge**: `expectation_status`, `execution_status`, `mutation_status`, `reason_codes`, `action_receipt_ids`, observed member count / population digest / required target ids, `scope_expectation_status`, population observations, control observation, and the evidence snapshot digest.
- **The decision references the full dual set.** Commit, chain replay, and the offline delivery package all recompose from the decision's own references — so an appended later run can never break an already-committed decision, and a verifier can never cite its own older passing run to hide a newer failing one (the commit's stale gate requires the referenced set to equal exactly what prepare would load).

If the two verifiers disagree on any conclusion field, the decision **cannot be formed** — this is a documented temporary compromise (the frozen v0.5 decision model holds one reference per arm; a formal on-ledger divergence state is the v0.6 path).

## Why this closes the "self-reported exit code" hole

The naive design compares the *evidence snapshot digests* the two verifiers cite. But evidence refs are self-signed metadata — a lying verifier can copy the honest one's refs verbatim and flip `expectation_status`. That was the hole. The fix is to compare **every field that carries a conclusion**, not just the pointer to evidence:

- A verifier that fabricates an exit code now produces different conclusion fields from the honest verifier → divergence → no decision.
- A verifier that cites its own old run to suppress a newer failing one is stopped at commit: the referenced set must equal the set prepare would load (newest per (arm, verifier)).
- A verifier that signs but never produces results cannot turn a single-verifier UNKNOWN into a VERIFIED.

Each of these was demonstrated by an adversarial probe first (RED), then fixed minimally (GREEN), then re-attacked by an independent reviewer for seven rounds.

## The 7-round audit

Both a specification reviewer and a quality/security reviewer (separate agents) attacked the implementation across seven rounds each. Every round was either a probe that reproduced an attack, or a confirmation that a previous attack now fails. Representative probes:

| Probe | Attack | Result after fix |
|---|---|---|
| Copy refs + flip `expectation_status` | Lying verifier fabricates exit code | `VerificationInputError: high-risk verifiers diverged` |
| Cite old PASS + newest other-verifier | Suppress own newer FAILING run | Commit blocked: `references arm results that are not the current set` |
| Second verifier co-signs only | Single verifier + co-sign → VERIFIED | Commit rejected (recompose → UNKNOWN ≠ signature) |
| Append a newer converged round | Break replay of committed decision | Old decision replays from its own references; new decision supersedes |
| Same key twice | Impersonate dual verifiers | Shape gate rejects duplicate (arm, verifier) rows |

Final state: **required-live full gate 3543 passed / 0 failed / 0 skipped**, candidate inventory rebuilt and bound, v0.1–v0.5 frozen schemas untouched.

## Honest boundaries (kept)

- This proves the *protocol requires* dual-verifier convergence. It does not prove any actual delivery went through dual verification, that verifiers are honest, or that no collusion happened (the trust model assumes at least one honest verifier).
- Divergence currently means "no decision" (combination failure), not an on-ledger UNKNOWN — the frozen decision model can't hold two references per arm. This is a documented temporary compromise; a formal `DUAL_VERIFIER_DIVERGENCE` state is the v0.6 path.
- No customer adoption, no paid work, no upstream adoption (all `not_evidenced`).

## Try it (5 minutes, offline)

```bash
git clone https://github.com/dengyier/OpenWorkProof
cd OpenWorkProof
python -m pip install -e .
python tests/evidence-bundles/verify_evidence_bundle.py \
  tests/evidence-bundles/rich-4196-integrity-v05-delivery-package.json
```

Then break it: change one byte anywhere in the evidence chain and watch the verdict stop being VERIFIED.

---

*OpenWorkProof is a Python protocol layer that makes agent work authorizable, verifiable, and offline-replayable. Apache-2.0. [Sponsors welcome](https://github.com/sponsors/dengyier).*
