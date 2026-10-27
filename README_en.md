# OpenWorkProof

<!-- mcp-name: io.github.dengyier/OpenWorkProof -->

<div align="center">
  <a href="README.md">中文</a> | <strong>English</strong>
</div>

> Let intelligence act toward human purposes, and let every action stand up to human judgment.

OpenWorkProof is an open work contract and verifiable execution protocol for AI agents.

It records who authorized a job, what the agent actually did, whether it stayed within scope,
what the verifier concluded, and whether the acceptor accepted or rejected the delivery. Each
job can be exported as a signed evidence bundle. A third party can verify the work chain with
the bundle and public keys, without connecting to the original system.

OpenWorkProof does not guarantee that an agent is correct, and it does not make the acceptance
decision for the customer. It gives authority a source, gives execution evidence, keeps
verification separate from acceptance, and preserves the human ability to accept, reject, revoke, and appeal.

[Install](#five-minute-start) · [How it works](#how-it-works) ·
[OWP Guard (experimental)](docs/integrations/agent-guard-onboarding.md) ·
[Human Agency](#human-agency-more-capability-must-not-mean-less-human-choice) ·
[DeepSeek Harness](docs/integrations/deepseek-harness.md) ·
[Community records](#community-contributions-and-external-records) ·
[Protocol](docs/protocol/human-agency-profile-v0.1.md) · [中文](README.md)

[![OpenWorkProof MCP on MCPRush](https://mcprush.com/badge/openworkproof-mcp/card.svg)](https://mcprush.com/to/openworkproof-mcp?ref=badge)

Live MCPRush listing card; click for scoring details and scan scope.

```text
Core package version: 1.5.0
DeepSeek Harness plugin candidate: 0.1.0, not published to npm
core focused: 97 passed / 0 failed / 0 skipped
plugin: 80 passed / 0 failed / 0 skipped
candidate: 186 passed / 0 failed / 0 skipped
required-live: 4373 passed / 0 failed / 0 skipped
License: Apache-2.0
```

The test figures above describe the existing 1.4.0 protocol baseline. Version 1.4.1 adds MCP startup compatibility; 1.4.2 clarifies tool descriptions. Version 1.5.0 adds the separately activated experimental Codex Guard. Read the release notes and GitHub Actions for current release checks.

Read public release state directly from [PyPI](https://pypi.org/project/openworkproof/),
the [GitHub Release](https://github.com/dengyier/OpenWorkProof/releases/tag/v1.5.0), and
the [MCP Registry](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.dengyier%2FOpenWorkProof/versions/1.5.0).
Core `1.5.0` includes the `owp-guard` command and retains existing MCP startup and tool descriptions; read back the links above for publication status. The DeepSeek
Harness plugin `0.1.0` remains a local candidate and is not published to npm or a plugin
marketplace. These are separate release facts.

## Community contributions and external records

The following public records concern OpenWorkProof and its maintainer,
[dengyier](https://github.com/dengyier). Status was checked on **2026-10-26**;
follow the original records for later changes.

| Category | Verifiable achievements and participation |
|---|---|
| Community directories | [awesome-mcp-servers PR #11702](https://github.com/punkpeye/awesome-mcp-servers/pull/11702) was merged by its maintainer on 2026-08-29. [awesome-a2a](https://github.com/ai-boost/awesome-a2a) and the [DeepSeek Harness community plugin directory](https://github.com/dshworks/awesome-dsh-plugins/blob/main/lists/observability-evidence.md) also currently list OWP entries. |
| External research | Judgment Pack's [Study 014](https://github.com/Judgment-Pack/judgment-pack-evaluator-experiments/blob/main/studies/014-openworkproof-binding/ANALYSIS.md) investigates judgment-to-execution binding, offline replay and detection boundaries against pinned OWP commit `8eeca6f`. The study and adapter are the external authors' work. |
| Cross-project integration experiment | AgentGuard's [OWP integration PR #4](https://github.com/Brodin2001/Agentguard/pull/4) remains open. Its maintainer's [execution-boundary fix PR #5](https://github.com/Brodin2001/Agentguard/pull/5) was merged into `integration/openworkproof-v1.4.0` on 2026-09-11. This is not a merge into its main branch or a completed integration release. |
| Protocol community discussions | The maintainer contributed to the [AutoGen GuardrailProvider discussion](https://github.com/microsoft/autogen/issues/7405#issuecomment-5226759945) and opened [MCP work-contract discussion #3215](https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/3215), now closed, to discuss signed authorization, execution receipts and tool-call boundaries. |
| DEV technical writing | The maintainer published a [protocol introduction](https://dev.to/dengyier/when-ai-agents-ship-code-a-protocol-for-verifiable-execution-29m3), a [community-feedback retrospective](https://dev.to/dengyier/i-asked-do-you-trust-an-agent-that-says-the-tests-passed-68-comments-later-heres-what-i-40an), and an article on [verifiable human authority](https://dev.to/dengyier/agent-autonomy-has-a-missing-layer-verifiable-human-authority-358f), with public discussions about evidence scope, freshness and judgment binding. |
| Public discovery and checks | [Glama](https://glama.ai/mcp/servers/dengyier/OpenWorkProof), [MCPRush](https://mcprush.com/dengyier/openworkproof-mcp), and [VerifyMCP](https://verifymcp.io/servers/dengyier-openworkproof/openworkproof) provide OWP pages. Read each platform's details for its current score, scanned version and check scope. |

Directory listings, discussions, integration experiments and automated scores have distinct meanings.
Study 014 explicitly disclaims an OWP security audit or endorsement; its scope is 39 locked test
cells and 8 holdout cells, not "47 attacks passed." These records do not establish institutional
adoption, comprehensive security certification, customer production deployment or paid use.

<details>
<summary>Other maintainer proposals and pending directory submissions</summary>

| Record | Current status |
|---|---|
| OpenClaw channel-diagnostics proposals: [PR #54244](https://github.com/openclaw/openclaw/pull/54244) and [earlier PR #54231](https://github.com/openclaw/openclaw/pull/54231) | Both closed without merging. These record community participation, not accepted upstream contributions. |
| [awesome-ai-sdks PR #316](https://github.com/e2b-dev/awesome-ai-sdks/pull/316) | Submitted and still open; not merged or listed through this PR. |
| [awesome-ai-agents PR #5](https://github.com/GopalGB/awesome-ai-agents/pull/5) | Submitted and still open; not merged or listed through this PR. |

</details>

## OWP Guard: Codex preview-directory protection (experimental)

Version 1.5.0 includes `owp-guard` for project-scoped preview editing. The supported
launch path checks tool requests before execution: it permits reads and text additions
or edits inside the designated preview directory, while rejecting out-of-scope paths,
deletes, moves, arbitrary commands, and unsupported tools.

Installing or connecting the MCP server does not activate Guard. Use the separate
`install -> enable -> doctor -> run` flow to review the current definition, complete a
live probe, and launch a guarded task with exact native session trust. Ordinary Codex
windows are not automatically protected. Guard is POSIX-only; the live host evidence
covers macOS, Python 3.12 and Codex CLI 0.147.0. Builds, deployment, personal MCP/plugin
configuration, and online search are outside this bounded launch path. It is not
whole-computer isolation or a cryptographic proof of every tool call.

See [first-time activation](docs/integrations/agent-guard-onboarding.md) and the
[scope and limitations](docs/integrations/agent-guard-codex.md). WorkBuddy integration
and enterprise controls remain unverified.

## What is missing when an agent says `done`

MCP connects agents to tools. A2A connects agents to agents. They define connection and
communication, but do not by themselves prove that a job was authorized, executed as agreed,
or accepted by the designated party.

Imagine an AI service provider asking an agent to modify a customer's repository. The agent
submits a patch and says the tests passed. The customer still needs answers:

1. Who authorized the agent to modify this repository?
2. Did it stay within the allowed tools, paths, quota, and deadline?
3. Did the patch, tests, and report come from the same execution?
4. Has a verification result been misrepresented as customer acceptance?
5. Can a third party review the facts without connecting to either party's system?

Logs show what a system printed. By themselves, they do not independently prove authority,
causality, or final acceptance. A platform should not be the only party able to verify its own
claims.

OpenWorkProof turns one agent job into a chain that can be carried, stored, and checked:

```text
The customer freezes the job and acceptance criteria
        ↓
The designated actor signs authority
        ↓
The agent executes and leaves signed receipts for important actions
        ↓
An independent Verifier checks the evidence and causal chain
        ↓
The Acceptor accepts or rejects
        ↓
A third party replays the complete result offline
```

OpenWorkProof does not make an agent smarter. It makes the agent's work safer to delegate.

## What OpenWorkProof is

OpenWorkProof is an open protocol layer that fits into existing agents, CI systems, MCP tools,
and multi-agent orchestrators. It connects six facts:

| Fact | Question answered |
|---|---|
| Purpose and scope | What was the agent asked to complete? |
| Signed authority | Who allowed the agent to do it? |
| Pre-execution decision | May this action run now? |
| Action receipt | What did the agent actually do? |
| Independent verification | Is the evidence complete, and what does it support? |
| Human acceptance | Who finally accepted or rejected the delivery? |

The result is not a log that only the originating platform can read. It is an offline-verifiable
signed evidence bundle for independent verification. A holder of the bundle and public keys can
review the source of authority, execution scope, evidence digests, verification result, and
acceptance decision.

### What it is not

OpenWorkProof is not an Agent OS, a model, or an orchestration framework. It does not plan work
for the agent, and it does not claim to judge every business outcome correctly.

Human Agency Profile is an authorization boundary. It is not employee scoring, performance monitoring, legal-liability transfer, automatic accountability, fund custody, or compliance certification.

OpenWorkProof does not hold money, execute payment, or replace legal arbitration. Protocol
state can prove that evidence reached a defined stage. It cannot create an external business
fact.

## How it works

A complete work chain uses these objects:

```text
WorkOrder -> CapabilityGrant -> PolicyDecision -> ActionReceipt
          -> VerificationDecision -> AcceptanceDecision
```

| Object | Purpose |
|---|---|
| `WorkOrder` | Freezes the target, source revision, paths, tools, deadline, and acceptance criteria |
| `CapabilityGrant` | Carries signed authority that can be reduced or consumed but never expanded |
| `PolicyDecision` | Allows or denies an action before the tool runs |
| `ActionReceipt` | Binds the request, authority decision, execution result, and evidence digest |
| `VerificationDecision` | Records an independent Verifier's decision against frozen scope and evidence |
| `AcceptanceDecision` | Records the WorkOrder-bound Acceptor's acceptance or rejection |

The protocol uses Ed25519 signatures, canonical JSON, an append-only ledger, and content
digests. If someone changes the WorkOrder, grant, receipt, evidence, public key, or causal
parents, offline replay fails closed.

Schemas live in [specs](specs/). Current implementation status and dated historical snapshots
live in [docs/status.md](docs/status.md).

## Six roles with separate authority

| Role | Responsibility |
|---|---|
| Maintainer | Initializes the WorkOrder and issues root authority |
| Manager | Delegates reduced authority and starts work and proof composition |
| Developer | Reads, modifies, and tests within authorized boundaries |
| Verifier | Checks results and evidence with an independent key |
| Sidecar | Supplies trusted execution facts and checkpoints |
| Acceptor | Independently signs acceptance, rejection, or profile changes |

Role separation does not add management ceremony. It prevents one agent from acting as the
executor, verifier, and final acceptor at the same time. A system may automate the workflow,
but it must not erase authority boundaries.

## Human Agency: more capability must not mean less human choice

`CapabilityGrant` describes what the system may give an agent. `Human Agency Profile`
describes which part of that capability a person is willing to let the agent use autonomously.
Effective permission is the intersection of three boundaries:

```text
What the WorkOrder permits
∩ What the CapabilityGrant delegates
∩ What the active HumanAgencyProfile allows
```

Human Agency Profile has three concrete properties:

- **WorkOrder-bound**: a profile cannot be moved to another job;
- **Acceptor-signed**: only the designated human authority can change the active profile;
- **machine-verifiable**: the dispatcher can resolve an action as allowed, reserved, or denied
  before execution.

A `reserved` action does not run first and ask later. It returns
`AGENCY_HUMAN_DECISION_REQUIRED` before execution. An appeal is a signed request for review. It
never restores or expands permission. Under this rule, only an Acceptor-signed transition can revoke the active profile or supersede it with another Acceptor-signed profile.

Read [Human Agency Profile v0.1](docs/protocol/human-agency-profile-v0.1.md) or run
[examples/human_agency_profile_v01.py](examples/human_agency_profile_v01.py).

## Verification and acceptance are separate decisions

`VERIFIED` means that a Verifier reached a result against frozen scope and evidence. The
customer's acceptance remains an independent decision by the WorkOrder-bound Acceptor.

OpenWorkProof uses a dual signature. The Verifier signs the verification result. The Acceptor
then signs `AcceptanceDecisionBindingV01`. This binding connects the WorkOrder, Decision,
CompositionReport, acceptance request, and terminal receipt. A missing binding is rejected, so
two valid but unrelated signatures cannot be spliced into one delivery.

The Acceptor's private key never enters AgentTeams or the exporter. The external human acceptance
flow uses `prepare → sign → commit`:

1. The system prepares a draft without a private key.
2. The external Acceptor signs it independently.
3. An append-only transaction commits the signed object.
4. The system exports an Acceptance Bundle.
5. A third party verifies the bundle offline.

```bash
owp acceptance-bundle-build LEDGER SURFACE \
  --evidence-root PATH --output DIRECTORY

owp acceptance-bundle-verify DIRECTORY
```

Exit codes are closed: `ACCEPTED=0`, `REJECTED=2`, and `operational=4`.
The AgentTeams entry point uses `--acceptance-bundle DIRECTORY`. It reads an external directory
and calls the same verifier. It does not generate a key, receipt, or binding.

```text
VERIFIED != ACCEPTED != PAID/SETTLED/LEGAL AUDIT/ADOPTION
```

`REJECTED` is a verified terminal state. It is not an operational error and must not be
reported as delivery success.

## Verification Integrity: the verification result must also be checked

"Tests passed" does not by itself make a verification trustworthy. If the selector missed
eligible targets, or a negative control failed for a different reason than expected, the result
must not become `VERIFIED`.

Verification Integrity v0.5 freezes the eligible population and the expected failure signatures
of negative controls:

- `POPULATION_CAPTURE_FAILED` means the selected set did not cover the contracted eligible
  population, so the result closes as `UNKNOWN`;
- `CONTROL_FAILURE_SIGNATURE_MISMATCH` means a negative control failed for the wrong reason and
  cannot support the claim;
- only when population capture and control evidence hold can the protocol derive `VERIFIED`,
  `REFUTED`, or `UNKNOWN` from the evidence.

This proves that a conclusion is supported by evidence from the contracted scope. It does not
prove that every business outcome is correct. Customer use, payment, legal effect, and upstream
adoption remain separate external facts; without separate evidence, their status is
`not evidenced`.

## Five-minute start

### 1. Install the public package

For MCP clients, use `uvx --from openworkproof owp-mcp`. Starting with 1.4.1,
`uvx openworkproof` starts the same server. Refresh an existing uv cache with
`uvx --refresh openworkproof`. See [MCP_SERVER.md](MCP_SERVER.md) for client configurations.

Read the current public version from PyPI:

```bash
python -m pip install openworkproof
owp --help
```

### 2. Develop from source

Install the current `main` from source when changing the protocol or an integration adapter:

```bash
git clone https://github.com/dengyier/OpenWorkProof.git
cd OpenWorkProof
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
owp --help
```

### 3. Run the minimal Human Agency example

```bash
python examples/human_agency_profile_v01.py
```

Expected output includes:

```text
profile verified  : True
resolved status   : active
owp.repo_read     : delegated -> allowed
owp.apply_patch   : reserved -> AGENCY_HUMAN_DECISION_REQUIRED
```

The example performs no application-level filesystem or ledger writes and never writes a
private-key file.

### 4. Verify an offline bundle

With a Surface Bundle:

```bash
owp surface-verify PATH
```

With an Acceptance Bundle:

```bash
owp acceptance-bundle-verify DIRECTORY
```

See [docs/offline-verification.md](docs/offline-verification.md) for the complete offline model.

## Integration paths

| Entry point | Best for | Start here |
|---|---|---|
| GitHub Action | Teams with an existing PR delivery flow | [integrations/github/action.yml](integrations/github/action.yml) |
| CLI | Local verification, CI, and automation | `owp --help` |
| MCP | Teams exposing OpenWorkProof as agent tools | [MCP_SERVER.md](MCP_SERVER.md) |
| AgentTeams | Manager, Developer, and Verifier collaboration | [agentteams/README.md](agentteams/README.md) |
| DeepSeek Harness | Code changes needing prior authority, independent rechecking, and external acceptance | [integration guide](docs/integrations/deepseek-harness.md) |
| Python API | Platforms embedding the protocol | [src/openworkproof](src/openworkproof/) |

The GitHub Action produces a four-question report:

1. What claim was verified?
2. What evidence was observed?
3. What constrained the execution?
4. What can be concluded now?

The result is `VERIFIED`, `REFUTED`, or `UNKNOWN`, and states whether the work has only reached
`READY_FOR_ACCEPTANCE`. It does not report protocol verification as customer acceptance or
payment.

The DeepSeek Harness adapter is currently an external-release READY local candidate pinned to
`DeepSeek Harness 0.1.1-rc.2`. Audit records observations only. Enforce authorizes before
execution and blocks the native `write`, `edit`, `bash`, `pwsh`, `str_replace_editor`,
`cordis_define`, `cordis_run`, `cordis_stop`, and `cordis_undefine` mutation surfaces. The
installed bundle is disabled and is `NOT_CONFIGURED` until an operator explicitly enables it with
a private case; no Audit evidence is recorded before that point. `/owp-verify` consumes only
the exact causally correlated patch receipt. Real CLI processes now read committed truth back,
verify independently, prepare a keyless acceptance draft, export for offline replay, and recover
the same committed receipt after process restart. These local checks are not npm publication,
external reproduction, customer adoption, or DeepSeek endorsement.

Host detection resolves the actual executable, including the symlink layout used by global
installations. The closed observation protocol and real-host preflight also cover the `read`,
`glob`, `grep`, and `web_search` read-only tools, so an ordinary read-only call cannot terminate
the evidence bridge.

## Evidence you can verify

The following facts describe the local candidate. They do not prove customer adoption:

| Gate | Current result |
|---|---|
| core focused | `97 passed / 0 failed / 0 skipped` |
| plugin | `80 passed / 0 failed / 0 skipped` |
| candidate | `186 passed / 0 failed / 0 skipped` |
| required-live | `4373 passed / 0 failed / 0 skipped` |
| AgentTeams | Manager, Developer, and Verifier live preflight passed (`http://127.0.0.1:18080`) |
| Offline verification | Surface, Acceptance, and Human Agency bundles replay independently |
| Supply chain | Candidate inventory, OCI/Docker artifacts, and hashes passed their binding gate |

The required-live full gate passes with `0 failed / 0 skipped` under
`OPENWORKPROOF_AGENTTEAMS_REQUIRED=1` and
`AGENTTEAMS_HOMESERVER=http://127.0.0.1:18080`. The Matrix token is read from the
local `agentteams-manager` container and is never printed or written to disk.

Rich #4196, Dify #33013, and AgentScope #2239 are project-owned demos and reproductions used to
exercise the protocol across different project types. They are not customer case studies and
do not show upstream adoption.

```text
agentteams_live_environment: evidenced
agentteams_three_role_preflight: evidenced
agentteams_end_to_end_business_execution: not_evidenced
human_acceptance: not_evidenced
customer_adoption: not_evidenced
paid_sow: not_evidenced
deposit: not_evidenced
upstream_adoption: not_evidenced
```

## Verified Agent Delivery

`OpenWorkProof Verified Agent Delivery` is the first application slice above the protocol. It
organizes one agent job into a delivery fact that can be independently verified and accepted or
rejected by the customer.

```bash
owp delivery-case init CASE_DIR
owp delivery-case inspect CASE_DIR
owp delivery-case verify CASE_DIR
owp delivery-case export CASE_DIR --output-directory OUTPUT_DIR
```

`inspect` derives state from real Surface, Acceptance, and Settlement evidence instead of
trusting a prewritten result on disk. `export` creates a third-party review package with a
deterministic summary and integrity manifest.

`READY_FOR_SETTLEMENT_REVIEW` means the evidence can be handed to an external payer for review.
It is not completed payment or settlement. `BOUND` means protocol objects have a determinate
binding. It does not mean payment, customer adoption, or legal recognition.

Commercial templates and admission boundaries live in
[docs/commercial/verified-agent-delivery](docs/commercial/verified-agent-delivery/).

## Open protocol and long-term direction

OpenWorkProof begins with one small, concrete result: one agent job can be independently
verified and accepted. If different organizations accumulate enough portable performance
facts, those facts may later support comparison, transactions, dispute review, and settlement
for agent services.

```text
One job can be verified
        ↓
Cross-organization delivery can be accepted
        ↓
Performance facts become portable
        ↓
Agent services can be compared, transacted, and settled
```

The final step is a long-term direction, not a current capability. OpenWorkProof does not now
provide a marketplace, wallet, payment rail, escrow, insurance, notarization, or statutory
arbitration.

The next protocol priorities are:

- reproduction by more agent frameworks and orchestrators;
- broader Human Agency profile, transition, and appeal interoperability;
- cross-organization execution and an external Acceptor reproduction;
- open interoperability based on reviewable facts instead of platform lock-in.

## Contributing and security

You can start by:

- running the minimal example and reporting what cannot be reproduced;
- integrating the protocol with an existing agent, CI system, or MCP tool;
- reviewing a schema, threat model, or truth boundary;
- contributing an adapter, test, or documentation fix;
- bringing a real but sanitized agent-delivery problem to the discussion.

Read [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues privately through
[GitHub Security Advisories](https://github.com/dengyier/OpenWorkProof/security/advisories/new).
The project is licensed under [Apache-2.0](LICENSE).

## Why we keep building

Capability tells us what an agent can do. A work contract records why it was allowed to do it.
Evidence makes the action open to review. Machines can apply verification rules, but final judgment about acceptance, rejection, and consequences still belongs to people.

We want agents to take on more work. As capability grows, actions should remain bound to the
human purposes stated in the WorkOrder. As systems automate more decisions, authority,
evidence, and appeal must remain visible.

OpenWorkProof has a simple aim. When people delegate work to AI, they should still know what
they authorized, what happened, and when they can say no.

**Let intelligence act toward human purposes, and let every action stand up to final human judgment.**
