# OpenWorkProof README v0.5 Evidence Sync Design

Date: 2026-08-16
Status: approved for implementation planning

## Goal

Synchronize `README.md` and `README_en.md` with the final locally and remotely
published Verification Integrity v0.5 release evidence without restructuring
the existing README narrative.

## Scope

- Preserve the existing section order, product positioning, installation
  instructions, CLI/MCP/Python entry points, and market narrative.
- Keep the Chinese and English READMEs structurally and factually aligned.
- Replace stale v0.2 release-candidate evidence with the final v0.5 evidence:
  - v0.5 focused: `401 passed, 0 failed`;
  - candidate live suites: `175 passed, 0 failed`;
  - required-live full suite: `3492 passed, 0 failed, 0 skipped`;
  - current candidate source revision:
    `a305f7204053f08312613dddb3a0ce7533ce4806`;
  - current immutable candidate inventory:
    `supply-chain/images/candidates/a305f7204053f08312613dddb3a0ce7533ce4806.json`;
  - execution image identity:
    `docker.io/openworkproof/execution-test@sha256:bc35711b843e6e2c479c52d486a1b2ed401cc90c7b15edb52b948206e9157abb`;
  - Rich #4196 offline delivery bundle:
    `VERIFICATION PASSED / VERIFIED / READY_FOR_ACCEPTANCE`.
- State that protocol schemas cover v0.1 through v0.5 and retain the current
  21-tool MCP surface.
- Preserve the explicit boundary that customer adoption, paid SOW, deposit,
  upstream adoption, production deployment, payment, and settlement remain
  `not_evidenced` unless independently proven.

## Non-Goals

- No README-wide rewrite or section reordering.
- No version bump, code, test, schema, candidate inventory, or supply-chain
  modification.
- No financing, customer, regulatory-compliance, upstream-adoption, payment,
  or settlement claim beyond existing evidence.
- No new market-sizing or competitor assertions.

## Consistency Rules

1. Each changed factual claim must have the same meaning in Chinese and English.
2. The final v0.5 snapshot must not coexist with stale `2491 passed`, the old
   `64f6ba65...` candidate link, or a label that calls v0.2 the final release
   gate.
3. Historical protocol descriptions may remain when clearly labeled as
   historical or version-specific; they must not be presented as the current
   release snapshot.
4. `READY_FOR_ACCEPTANCE` describes protocol readiness only and must not be
   translated into customer acceptance or commercial validation.

## Verification

- Inspect the diff to confirm only `README.md` and `README_en.md` change during
  implementation.
- Search both files for stale release evidence and contradictory commercial
  claims.
- Verify the current candidate inventory path exists.
- Check Chinese/English release evidence for exact parity.
- Run `git diff --check`.
