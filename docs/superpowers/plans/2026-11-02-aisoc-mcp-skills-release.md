# AI-SOC MCP and Skill Release Implementation Plan

**Goal:** Repair the reviewed AI-SOC correctness defects, distribute a bounded reference integration through the existing OpenWorkProof MCP package and an installable Agent Skill, and verify public releases.

**Architecture:** Keep the existing Core/Guard behavior. Ship the `aisoc` Python package in the same wheel and add read-only/reference MCP tools for supplied Slips alerts and signed export review. No MCP tool calls the real AiSOC HTTP push or host enforcement interfaces. The detector remains synthetic-trained and investigation remains a deterministic stub. Local proof consistency does not establish externally trusted identity.

**Acceptance:** F01-F13 receive focused regressions; nested tests enter default CI; root regression passes or every environment-only skip is explicit; fresh wheel performs MCP discovery, supplied-alert analysis, normal offline verification with independent trust input, and tamper rejection. Skill invocation leads to this actual flow without implying active desktop protection. Public artifacts must match the tested release and each listing status is independently read back.

## Work ownership and steps

- [ ] Sandbox owner: bind tools to the frozen order, enforce signed grant budgets atomically at PEP, bound envelope expiry, reject invalid TTL with recorded refusal. Files: nested `aisoc/sandbox/{tools,policy,authorization,pep}.py`, regression tests. Verify first-failing focused tests and existing policy/egress tests.
- [ ] Proof owner: preserve signed authorization objects; reconcile exact request/envelope/receipt and ordering; cover final ledger records with checkpoints; make CLI and runtime use shared checks; require bundle-external trust for independent verification. Files: nested `aisoc/{soc,cli}.py`, `aisoc/owp/verifier.py`, related ledger/objects if necessary, regression tests. Also attach the order-bound tools interface and external source-window dedup identity.
- [ ] Adapter owner: select evidence meeting both confidence and severity; use source-window dedup identities; isolate malformed Note records; normalize connection/time-out failures to signed refusal. Files: nested `aisoc/adapters`, corresponding regression tests.
- [ ] Integrator: place package under `src/aisoc`; preserve uploaded documentation and nested tests; root test discovery includes those tests. Add `owp-aisoc` console entry and explicit reference-only tools in `openworkproof/mcp_transport.py`, with behavior in `openworkproof/soc_reference.py`. Supplied content only, bounded sizes/case counts, generated temporary output only, no user-selected filesystem writes or network side effects.
- [ ] Add a genuine `skills/openworkproof-soc-review/SKILL.md`, install/invocation documentation, release scope and exact command examples. Validate frontmatter and independently exercise its workflow from an installed wheel.
- [ ] Repair the existing schema-registry concurrent-start race if reproduced; keep the fix narrow and include the existing subprocess concurrency regression.
- [ ] Run complete root/new tests, packaging and clean-install MCP roundtrip, then independent code review. Resolve actionable regressions before release.
- [ ] Commit only scoped changes, push a release PR, follow CI, merge once green, tag the additive release, publish PyPI/GitHub/official MCP Registry, then synchronize existing editable catalogues. Treat automatic catalogue refresh as pending until observed; do not claim an Agent Skills directory entry is an installed Skill.

**Excluded claims:** Live SOC deployment, production detection rates, real HSM/OS isolation, whole-computer protection, real host remediation, customer adoption or payment. Existing canceled contact automation remains canceled.
