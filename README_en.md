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
[Human Agency](#human-agency-more-capability-must-not-mean-less-human-choice) ·
[Protocol](docs/protocol/human-agency-profile-v0.1.md) · [中文](README.md)

```text
Local candidate: 1.3.0, not released
required-live: 4265 passed / 0 failed / 0 skipped
candidate: 183 passed / 0 failed / 0 skipped
License: Apache-2.0
```

Read public release state directly from [PyPI](https://pypi.org/project/openworkproof/) and
the [MCP Registry](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.dengyier%2FOpenWorkProof/versions/1.2.0).
The local candidate and the public release are different facts.

## What is missing when an agent says `done`

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

## Five-minute start

### 1. Install the public package

Read the current public version from PyPI:

```bash
python -m pip install openworkproof
owp --help
```

### 2. Run the local candidate

The repository's `1.3.0` version is a local candidate and is not released. Install it from
source for development:

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
| Python API | Platforms embedding the protocol | [src/openworkproof](src/openworkproof/) |

The GitHub Action produces a four-question report:

1. What claim was verified?
2. What evidence was observed?
3. What constrained the execution?
4. What can be concluded now?

The result is `VERIFIED`, `REFUTED`, or `UNKNOWN`, and states whether the work has only reached
`READY_FOR_ACCEPTANCE`. It does not report protocol verification as customer acceptance or
payment.

## Evidence you can verify

The following facts describe the local candidate. They do not prove customer adoption:

| Gate | Current result |
|---|---|
| required-live | `4265 passed / 0 failed / 0 skipped` |
| candidate | `183 passed / 0 failed / 0 skipped` |
| AgentTeams | Manager, Developer, and Verifier live preflight passed |
| Offline verification | Surface, Acceptance, and Human Agency bundles replay independently |
| Supply chain | Candidate inventory, OCI/Docker artifacts, and hashes passed their binding gate |

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
