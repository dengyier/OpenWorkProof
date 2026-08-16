# OpenWorkProof

<!-- mcp-name: io.github.dengyier/OpenWorkProof -->

> Agents can generate results — but on what authority do we accept delivery?
> Agent Work Contracts and Verifiable Execution Protocol

<div align="center">
  <strong>English</strong> | <a href="README.md">中文</a>
</div>

---

Project: https://github.com/dengyier/OpenWorkProof
Version: 1.2.0
License: Apache-2.0
PyPI: [openworkproof](https://pypi.org/project/openworkproof/)
MCP Registry: [io.github.dengyier/OpenWorkProof](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.dengyier%2FOpenWorkProof/versions/1.2.0)

---

## 30-Second Overview

MCP connects agents to tools. A2A connects agents to agents. AgentTeams orchestrates agent collaboration.

But when an agent says "I'm done," no existing layer answers:

- What authorization backs this work?
- Did every step stay within scope and quota?
- Do tests, patches, and reports form a complete causal chain?
- Who has the authority to accept or reject the outcome?
- In a dispute, can a third party verify all the facts offline, without connecting to any party's system?

**OpenWorkProof fills this gap: contracts, authorization, evidence, and acceptance for agent work.**

It doesn't try to make agents smarter. It makes their work authorizable, constrainable,
verifiable, and acceptable — and rejectable when the evidence falls short.

A contrarian thesis: the primary bottleneck for multi-agent systems isn't model capability
— it's accountability, authority, evidence, and acceptance. Without these, agents can
generate results, but they can't become delegatable, auditable, billable production actors.

---

## Why OpenWorkProof

### Who Needs It

| Role | Pain Point | What OpenWorkProof Provides |
|------|------------|----------------------------|
| **Agent platform / framework builders** | Agents can call tools, but can't prove "this call was authorized" | Signed AgentRequest + PolicyDecision pre-authorization — every call carries machine-checkable authorization evidence |
| **Enterprise IT / compliance teams** | EU AI Act high-risk provisions require proof that agents are authorized, constrained, and auditable | Complete signed authorization chain, quota tracking, offline third-party verification for audit requirements |
| **Multi-agent orchestrators** | Delegated permissions can't decay or be held accountable | CapabilityGrant with atomic attenuation — child grants can only shrink, never expand |
| **Delivery reviewers / acceptors** | Agent claims completion but the causal link between tests, patches, and reports is opaque | Causal replay layer + policy replay layer + five-input offline verifier — the full evidence chain is reproducible |
| **Dispute arbitrators** | Need to review facts without connecting to any party's system | `validate_grant_chain` — pure offline signature verification, only needs the evidence bundle + public keys |

### Why Now

**The market has turned.** Gartner predicts 40% of enterprise software will embed AI agents
by end of 2026 (below 5% in 2025). The EU AI Act's high-risk provisions are already in effect
— organizations that can't prove their agents are "authorized, constrained, and auditable"
face real legal risk.

**The space is being validated by capital.** In H1 2026, over $65M was publicly raised in
the agent trust infrastructure category:

| Project | Funding | Layer |
|---------|---------|-------|
| Catena Labs | $48M (a16z-led) | Agent identity + payment protocol |
| GenLayer | $7.5M | Verifiable judgment + on-chain identity |
| OpenBox AI | $5M | Runtime governance (identity/authorization) |
| t54 Labs | $5M (Franklin Templeton / Ripple) | Agent financial trust layer |

These projects solve "who is acting" and "how money moves" — the identity and payment layers.

**OpenWorkProof solves the layer they all leave untouched: what authority backs this work,
why the process is trustworthy, and what makes the outcome acceptable — the work-contract layer.**
The two are complementary, not competitive.

An analogy: OAuth defined "how humans authorize apps," spawning a $10B+ market
(Okta / Auth0). OpenWorkProof defines "how humans authorize agent work and accept results."

### Core Principles

- **Proof-Carrying Work**: actions must carry machine-checkable authorization and result evidence
- **No-Cloning Authority**: child grants can only attenuate or consume — never replicate equivalent or greater permissions
- **Multi-Scale Proof Composition**: local credentials can only form an acceptable global proof when causality, evidence dimensions, correlation disclosure, and global conditions are simultaneously satisfied
- **Fail Closed**: unverifiable permissions, signatures, history, state, or evidence must never resolve as success
- **Offline Third-Party Verification**: `validate_grant_chain` enables third parties to verify the entire signed authorization history without connecting to any party's system

---

## How It Works

Four protocol objects form the complete work-level proof chain:

```
WorkOrder            CapabilityGrant        ActionReceipt          AcceptanceReceipt
Work contract        Capability grant       Action credential      Acceptance credential
Freezes target/path/ Signable, attenuable,  Binds authorization,   Evidence coverage +
tool/quota/          non-expanding          quota delta, and       causal completeness +
acceptance criteria  → authority         →  evidence refs     →   independence disclosure
                                                                   + human decision
```

Six-role identity binding:

| Role | Responsibility | Key |
|------|---------------|-----|
| Maintainer | Initialize WorkOrder, issue Root Grant | Ed25519 |
| Manager | Issue child grants, invoke compose_proof | Ed25519 |
| Developer | Execute repo_read / apply_patch / run_tests | Ed25519 |
| Verifier | Independently run tests, form independent evidence | Ed25519 |
| Sidecar | Assign trusted execution facts (ReplayCheckpoint) | Ed25519 |
| Acceptor | Human acceptance (accept / reject), independent key | Ed25519 (independent of system) |

State machine:

```
running → locally_verified → proof_ready → awaiting_human → accepted
                                                        ↘ rejected
```

Detailed protocol schemas are in [specs](specs/) (currently v0.1-v0.5).

---

## Quick Start

### Prerequisites

- Python ≥ 3.10 (supports 3.10 / 3.11 / 3.12 / 3.13)
- Git
- macOS or Linux

### Installation

**Direct use (recommended):**

```bash
pip install openworkproof
```

After installation, the `owp` CLI command, `owp-mcp` MCP Server command, and full Python API are available.

**Local development:**

```bash
git clone https://github.com/dengyier/OpenWorkProof.git
cd OpenWorkProof
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements-lock.txt
./.venv/bin/python -m pip install -e .          # editable install, picks up code changes
```

### Verify Installation

```bash
# Check if CLI is available
owp status

# Run full test suite (~5 minutes, requires local dev environment)
./.venv/bin/python -m pytest -q

# Use the command's current output; the fresh release-candidate snapshot is below
```

### Scope-Bound Verification v0.3 and the 21-Day Paid Pilot

v0.3 makes “which files, tests, and delivery objects were actually verified”
part of the signed protocol. A Manager freezes an `EvaluationScopeManifest`;
Verifiers submit Observed Scope evidence for positive and negative arms; and
the composer can return bounded `VERIFIED` only when both populations match,
required targets are covered, and the registered negative control is caught.
Omission, selector drift, or missing evidence resolves to `UNKNOWN`, never a
full-delivery claim based on a local green check.

```bash
owp scope-build --claim claim.json --source-revision COMMIT_SHA --rules rules.json
owp scope-validate scope.json
owp scope-commit pilot.sqlite3 signed-scope-envelope.json
owp scope-compare scope.json observed-scope.json
owp delivery-build --privacy-view customer_private pilot.sqlite3 delivery-package/
owp audit-replay delivery-package/
```

v0.3 proves exact declared-versus-observed scope for a code delivery. It does
not prove unencoded business intent, customer acceptance, payment, fund
release, automatic settlement, universal correctness, or regulatory
compliance. MCP and A2A continue to provide interoperability, identity,
security, task, and messaging capabilities; OpenWorkProof complements them by
freezing work authorization, scope evidence, and the basis for acceptance.

See the [21-day scope-bound paid pilot](docs/pilot/scope-bound-verification-offer.md)
and the buyer-facing [Scope Coverage Report example](docs/pilot/scope-coverage-report.example.md).
External payment, customer acceptance, upstream adoption, and production
deployment are currently `not evidenced`.

### Verification Integrity v0.5

v0.5 extends v0.3's declared-versus-observed scope with two facts frozen into
the signed protocol: the **eligible population before selection** and the
**reason a negative control failed**. v0.3 proves that what was selected was
verified; v0.5 additionally proves what was eligible before selection, what
the selector actually chose, and whether a negative control failed for the
registered reason. It closes two blind spots earlier versions could not see:

- **Population blind spot**: the execution engine can see multiple eligible
  tests, but the selector chooses zero of them. The run itself finishes
  cleanly, yet v0.5 derives `UNKNOWN / POPULATION_CAPTURE_FAILED` — never a
  full-delivery claim from a local green check.
- **Control rot**: the registered mutant still fails, but the failure cause
  (error codes / predicate signature) does not match the registered
  signature. v0.5 derives `UNKNOWN / CONTROL_FAILURE_SIGNATURE_MISMATCH` —
  "failed by coincidence" never counts as "failed as intended".

The three-state boundary stays monotonic: `VERIFIED` (population matched +
control proven + positive arm satisfied), `REFUTED` (control survived),
`UNKNOWN` (population empty/capture_failed/drifted/unavailable or control
mismatched/unavailable). `UNKNOWN` is a safe outcome, not a crash and not a
failure.

```bash
owp integrity-observation validate population.json
owp control-observation validate control.json
owp delivery-build --privacy-view customer_private pilot.sqlite3 delivery-package/
owp audit-replay delivery-package/
```

Exit codes: population `matched` → `0`, every other population status → `3`;
control `proven` → `0`, `survived` → `4`, `mismatched/unavailable` → `3`;
malformed input → `1`.

See [offline verification](docs/offline-verification.md) for the replay
commands, reason-code table, and recovery boundaries, and
`tests/integrity-demo/rich-4196/README.md` for the self-owned Rich #4196 demo.
That demo declares `upstream_adoption`, `customer_case`, and
`commercial_validation` as `not_evidenced`; it is not evidence of customer
adoption, payment, fund release, automatic settlement, universal correctness,
or regulatory compliance.

### Evidence Lifecycle v0.2 Compatibility Entry Points

The current 1.2.0 release retains v0.2 profile validation, positive and
negative evidence commits, verification decisions, Delivery Packages, offline
audits, and settlement-readiness derivation:

```bash
owp profile-validate signed-profile.json
owp verify-positive pilot.sqlite3 signed-positive-result.json
owp verify-negative pilot.sqlite3 signed-negative-result.json
owp verify-compose --mode prepare pilot.sqlite3 decision-request.json
owp verify-compose --mode commit pilot.sqlite3 signed-decision.json
owp delivery-build --privacy-view public pilot.sqlite3 delivery-package/
owp audit-replay delivery-package/
owp settlement-status pilot.sqlite3
```

See the [v0.2 verifiable-delivery pilot kit](docs/pilot/README.md) for the
operator sequence, assurance-level cost boundaries, and a technical/commercial
scorecard. The examples are local integration fixtures; they do not evidence a
real customer, customer acceptance, payment, fund release, or production
deployment.

The local 1.2.0 release candidate completed its gates on source revision
`d0bec9d2f2c3cf12568fa866d16be1a56de4aa9c` and added an immutable
[candidate inventory](supply-chain/images/candidates/d0bec9d2f2c3cf12568fa866d16be1a56de4aa9c.json):

- v0.5 focused: `401 passed, 0 failed`;
- candidate live: `176 passed, 0 failed`;
- required-live full suite: `3494 passed, 0 failed, 0 skipped`;
- frozen execution image:
  `docker.io/openworkproof/execution-test@sha256:6d0dadec750eb498ed4d2260b4de65f33ed1c146adda6e64ec8ba588f7a88097`;
- the Rich #4196 v0.5 delivery bundle replayed offline as
  `VERIFICATION PASSED / VERIFIED / READY_FOR_ACCEPTANCE`.

`READY_FOR_ACCEPTANCE` means that the evidence package meets
the protocol conditions for entering acceptance. It does not mean that a
customer accepted, paid for, or deployed it. See [docs/status.md](docs/status.md)
for the environment, timings, and full claim boundaries.

### End-to-End Demos

OpenWorkProof provides two independent end-to-end demos, covering different project types:

#### M2 — Rich #4196 (Developer Tooling)

A complete five-role workflow demo (~9s) based on the real open-source issue
[Textualize/Rich #4196](https://github.com/Textualize/rich/issues/4196):

```bash
./.venv/bin/python -m pytest tests/test_delivery_m2.py -q

# Expected: exit code 0; use the command's current count
```

Covers a 9-step evidence chain:

```
1. Initialize WorkOrder (five roles + root grant)    → running
2. Developer repo_read (pipeline read of candidate)  → receipt + output_digest
3. Developer apply_patch (publish fix for #4196)     → active patch binding
4. Developer run_tests (self-check)                  → test receipt
5. Manager compose_proof (first report)              → evidence_incomplete
6. Independent Verifier run_tests (fresh context)    → independent result receipt
7. Manager recompose_proof (five-dimension closure)  → proof_ready
8. request_acceptance + Acceptor signing            → accepted
9. Export evidence bundle + offline verification    → verify_acceptance_bundle passes
```

Full log: [docs/superpowers/2026-08-07-rich-4196-demo-log.md](docs/superpowers/2026-08-07-rich-4196-demo-log.md).

#### M3 — Dify #33013 (AI Application Platform)

A complete five-role workflow demo (~6s) based on the real open-source issue
[langgenius/dify #33013](https://github.com/langgenius/dify/issues/33013):

```bash
./.venv/bin/python -m pytest tests/test_delivery_m3_dify.py -q

# Expected: exit code 0; use the command's current count
```

This bug occurs in Dify's QuestionClassifierNode — when a user adds a question
classifier node to their workflow, execution throws a `TypeError`: the `invoke_llm()`
call passes `structured_output_schema` which gets unexpectedly converted to a
dict. The upstream fix updates the parameter to `json_schema` — a one-line change.

Dify is an AI workflow platform where end users directly compose agent workflows —
a completely different context from Rich (a developer tool). This demo proves the
OpenWorkProof protocol's **cross-project-type generality**.

Covers the same 9-step evidence chain as M2, plus two functional-layer assertions:
- The pinned source code reproduces the `TypeError` (confirming the bug is real)
- The upstream fix applies line-level precision (confirming the fix is effective)

Full log: [docs/superpowers/2026-08-07-dify-33013-demo-log.md](docs/superpowers/2026-08-07-dify-33013-demo-log.md).

---

## Usage

OpenWorkProof provides three entry points: CLI, MCP transport, and Python API.

### 1. CLI

```bash
# View ledger status (replays all receipts, outputs current state)
owp status path/to/ledger.db

# Example output:
# {
#   "schema_version": "openworkproof/cli-status/0.1",
#   "work_order_digest": "sha256:...",
#   "current_state": "accepted",
#   "version": 42,
#   "receipt_count": 15
# }

# Forward a run-tests execution request
owp run-tests path/to/ledger.db payload.json

# Forward a repo-read execution request
owp repo-read path/to/ledger.db payload.json

# Text output mode
owp --output text status path/to/ledger.db
# state=accepted version=42 receipts=15
```

Example payload.json (run-tests):

```json
{
  "request": {
    "schema_version": "openworkproof/agent-request/0.1",
    "work_order_digest": "sha256:abc123...",
    "grant_id": "grant-uuid-here",
    "role": "verifier",
    "tool_name": "owp.run_tests",
    "nonce": "unique-nonce-string",
    "arguments": { "mode": "verifier", "test_filter": "test_basic" },
    "signature": { "key_id": "verifier-key-1", "sig": "..." }
  },
  "arguments": { "mode": "verifier", "test_filter": "test_basic" },
  "execution_facts": { ... },
  "replay_checkpoint": { ... }
}
```

### 2. MCP Server (stdio)

OpenWorkProof is registered on the official MCP Registry (`io.github.dengyier/OpenWorkProof`),
providing 21 MCP tools callable by any MCP client (Claude Desktop, Cursor, VS Code, etc.):

```bash
# Start the MCP Server (available after pip install)
owp-mcp

# Or via Python module
python -m openworkproof.mcp_transport
```

Provided MCP tools (21):

**Standalone verification tools (no ledger required):**

| Tool | Function |
|------|----------|
| `owp_generate_keypair` | Generate an Ed25519 key pair |
| `owp_compute_key_id` | Derive key_id from a public key |
| `owp_sign_payload` | Sign a canonical payload |
| `owp_verify_signature` | Verify a signed payload |
| `owp_compute_digest` | Compute JCS canonical SHA-256 digest |
| `owp_verify_work_order` | Verify WorkOrder identity bindings |
| `owp_verify_nested_claim` | Verify AgentRequest / HumanDecision nested claims |
| `owp_list_domains` | List all canonical domains |

**Ledger coordinator tools:**

| Tool | Function |
|------|----------|
| `owp_status(ledger)` | Replay ledger and return authoritative state |
| `owp_run_tests(ledger, payload)` | Forward run-tests execution |
| `owp_repo_read(ledger, payload)` | Forward repo-read execution |

**Utility tools:**

| Tool | Function |
|------|----------|
| `owp_get_schema` | Get an authoritative JSON Schema |
| `owp_get_schema_digest` | Get the frozen digest of a schema |
| `owp_analyze_repo` | Analyze a repository structure |

Add to your MCP client configuration:

**Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "openworkproof": {
      "command": "owp-mcp"
    }
  }
}
```

**Cursor / VS Code** (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "openworkproof": {
      "command": "uvx",
      "args": ["--from", "openworkproof", "owp-mcp"]
    }
  }
}
```

See [MCP_SERVER.md](MCP_SERVER.md) for more configuration options.

### 3. Python API

```python
from openworkproof import evidence, mcp_server, policy
from openworkproof.models import WorkOrder, CapabilityGrant, AgentRequest
from openworkproof.signing import sign_payload, verify_payload
from openworkproof.acceptance import verify_acceptance_bundle

# 1. Initialize ledger (create WorkOrder + Root Grant)
evidence.init_ledger("ledger.db", work_order, root_grant)

# 2. Pre-authorization check (pure function, no execution, no ledger writes)
auth_ctx = policy.derive_authorization_context(
    work_order=work_order,
    grants=grant_prefix,
    receipts=receipts,
    request=signed_request,
    arguments=typed_args,
    execution_facts=facts,
    checkpoint=checkpoint,
)
decision = policy.authorize_tool_call(auth_ctx)
if not decision.allowed:
    # Deny path: audit trace but no execution
    mcp_server.produce_deny_receipt("ledger.db", request, decision)
    return

# 3. Execute tool and commit receipt
receipt = mcp_server.complete_receipt_publication(
    "ledger.db", request, decision, execution_result, evidence_list
)

# 4. Offline verification (by a third party, no live ledger needed)
result = verify_acceptance_bundle(
    work_order=work_order,
    report=report,
    effective_grants=grants,
    grant_attempts=attempts,
    receipts=receipts,
    committed_evidence=evidence,
    acceptance_receipt=signed_receipt,
    public_keys=public_keys,
    reports=all_reports,
)
```

### 4. External Acceptor Service

The Acceptor runs as a standalone process, holding only the Acceptor private key,
receiving signature requests over TCP:

```bash
# Start external Acceptor (default 127.0.0.1:18741)
./.venv/bin/python -c "
from openworkproof.external_acceptor import ExternalAcceptorService
svc = ExternalAcceptorService(host='127.0.0.1', port=18741, key_hex='...')
svc.serve()
"

# Client sends a signing request
./.venv/bin/python -c "
from openworkproof.external_acceptor import ExternalAcceptorClient
client = ExternalAcceptorClient(host='127.0.0.1', port=18741)
result = client.sign_acceptance(draft_receipt)
print(result)
"
```

### 5. AgentTeams Network Transport

Connect to the AgentTeams execution layer via TCP:

```bash
# Environment variables
export OWP_TEAM_ENDPOINT=127.0.0.1:18742
export OWP_TEAM_TOKEN=shared-secret
export OWP_TEAM_TIMEOUT=5.0
```

---

## Offline Verification

A core design goal: third parties verify all facts offline, using only the evidence
bundle, without connecting to any party's system.

```python
from openworkproof.acceptance import verify_acceptance_bundle

# Only needs the evidence bundle + public keys — no live ledger
result = verify_acceptance_bundle(
    work_order=work_order,           # WorkOrder (with six-role public key bindings)
    report=report,                   # CompositionReport (authoritative ledger artifact)
    effective_grants=grants,         # Normalized grant prefix
    grant_attempts=attempts,          # Issuance attempts
    receipts=receipts,               # ActionReceipt envelope sequence
    committed_evidence=evidence,      # (CommittedEvidence, ...)
    acceptance_receipt=signed,       # Terminal acceptance receipt
    public_keys=public_keys,         # {key_id: Ed25519PublicKey}
    reports=reports,                 # All CompositionReports
)
```

What the verifier checks:
1. **Signed authorization history**: rebuilds deterministic indexes, verifies Ed25519
   signatures on every receipt
2. **Policy replay**: recomputes grant attenuation, balance, revocation, single-use,
   quota, and denial precedence
3. **Evidence references**: validates EvidenceRef path, sha256, and publication closure
4. **Causal completeness**: precise parent sets, single genesis, active patch / rework /
   approval semantics
5. **Terminal decision**: acceptance or rejection — exactly one of the two, bound to the request tip

See [docs/offline-verification.md](docs/offline-verification.md) for details.

---

## Project Structure

```
OpenWorkProof/
├── src/openworkproof/
│   ├── models.py              # Four protocol object models (WorkOrder/Grant/Receipt/Acceptance)
│   ├── policy.py              # Pre-authorization: authorize_tool_call / validate_human_decision / validate_rollback
│   ├── evidence.py            # SQLite authoritative ledger, atomic commit, evidence staging & publication
│   ├── composition.py         # Causal replay layer + deterministic CompositionReport
│   ├── acceptance.py          # Terminal acceptance + offline verifier (verify_acceptance_bundle)
│   ├── mcp_server.py          # Coordinator: complete_receipt_publication / compose_proof etc.
│   ├── mcp_transport.py       # MCP Server (existing tools + v0.2/v0.3 interfaces)
│   ├── cli.py                 # CLI transport layer (owp command)
│   ├── execution_adapter.py   # AgentTeams execution adapter
│   ├── team_network_client.py # TCP network client
│   ├── external_acceptor.py   # Standalone Acceptor service
│   ├── signing.py             # Ed25519 signing + RFC 8785 JCS canonicalization
│   ├── schema_registry.py     # JSON Schema registry
│   ├── predicates.py          # Predicate registry
│   ├── repo_tools.py          # Repository pipeline tools
│   ├── runtime_context.py     # Runtime context
│   ├── trusted_helper.py      # Trusted helper request dispatch
│   └── schemas/v0.1..v0.5/    # Multi-version JSON Schema files
├── specs/v0.1..v0.5/          # Public protocol schemas
├── tests/                     # Protocol, fault-injection, and end-to-end tests
├── docs/                      # Documentation (status, demo logs, offline verification guide)
├── supply-chain/              # Trusted build images + candidate inventory
├── pyproject.toml             # Packaging metadata
└── requirements-lock.txt      # Locked dependencies
```

---

## Current Status

**Implemented and verified (public snapshot):**

- Four protocol object models, RFC 8785 JCS + Ed25519 signing, six-role identity binding
- SQLite authoritative ledger, root/child Grant atomic issuance & revocation, quota replay
- Pure pre-authorization: tool-call / human-decision / rollback PolicyDecision
- Causal replay layer + policy replay layer + five-input offline verifier
- Group-aware evidence staging, atomic commit, no-replace publication, crash recovery
- First Verifier `run_tests` trusted coordinator slice (with real subprocess crash injection tests)
- Deterministic CompositionReport and `owp.compose_proof` atomic composition transaction
- Atomic final-acceptance request, keyless external signature draft, and Acceptor-signed acceptance commit
- Acceptor rejection path: AcceptanceRejectionReceipt signed by the same authoritative Acceptor
- Independent Verifier results and deterministic recomposition
- Deny receipt entry point (`produce_deny_receipt`)
- CLI (existing execution entry points plus v0.2/v0.3 scope verification, package, audit,
  and settlement-readiness commands)
- MCP Server (lifecycle aggregate interfaces plus two read-only Scope tools; registered
  on MCP Registry as `io.github.dengyier/OpenWorkProof`)
- AgentTeams TCP network client + execution adapter
- Docker production executor (STARTED_UNCONFIRMED recovery)
- Rich #4196 full five-role E2E demo (Acceptor TCP signing + offline verification)
- Dify #33013 full five-role E2E demo (AI application platform, cross-project-type generality)
- **v0.5 focused: 401 passed, 0 failed; candidate live: 176 passed, 0 failed**
- **Local 1.2.0 required-live gate: 3494 passed, 0 failed, 0 skipped**

**Not yet complete:** remaining ToolCall handler closures, event submission.

> We state "what's not yet done" as clearly as "what is done."
> This isn't modesty — it's the standard of evidence a protocol project demands.

See [docs/status.md](docs/status.md) for the detailed implementation checklist and boundary declarations.

---

## Demos

### M2: Rich #4196 (Developer Tooling)

Based on the real open-source issue [Textualize/Rich #4196](https://github.com/Textualize/rich/issues/4196),
pinned to upstream commit `9d8f9a372cc5916fd4781fec207ced7ddac2f08f`, demonstrating a complete
five-role workflow:

Manager issues minimal permissions → Developer modifies code in a constrained workspace
(repo_read + apply_patch) → out-of-scope paths are denied pre-execution → Verifier runs
pinned tests forming independent evidence → local test pass does not automatically equal
final acceptance → independent Verifier results and recomposition → Acceptor makes a
human acceptance decision based on the complete evidence chain (Acceptor subprocess TCP signing)
→ offline bundle verification.

Rich and its source code remain the property of the original rightsholders;
OpenWorkProof owns only its protocol and task packaging.

### M3: Dify #33013 (AI Application Platform)

Based on the real open-source issue [langgenius/dify #33013](https://github.com/langgenius/dify/issues/33013),
pinned to upstream commit `9f7bea37e`. The bug occurs in Dify's QuestionClassifierNode:
when a user adds a question classifier node to their workflow, execution crashes with
a `TypeError` — a one-line fix updates the parameter from `structured_output_schema`
to `json_schema`.

Dify is an AI workflow platform for end users — completely different from Rich's
developer-tooling context. This demo proves **cross-project-type generality**: the same
9-step, five-role evidence chain works equally well for user-product-level fixes,
with additional functional-layer verification confirming both bug reproduction
and fix effectiveness.

---

## Roadmap

1. ~~Stable execution IDs and start/result receipts for real sandboxed executors~~ (done)
2. ~~Human decision, rollback, and termination policy APIs~~ (done)
3. ~~Independent result execution episode and five-dimension recomposition → proof_ready~~ (done)
4. ~~CLI, MCP Sidecar, and AgentTeams integration~~ (done)
5. ~~Rich #4196 self-contained demo with external independent acceptance~~ (done)
6. ~~Acceptor rejection path and real external Acceptor reproduction~~ (done)
7. ~~Deny receipt entry point~~ (done)
8. ~~Dify #33013 self-contained demo with cross-project-type generality validation~~ (done)
9. ~~MCP Server registered on official MCP Registry~~ (`io.github.dengyier/OpenWorkProof` v1.2.0 metadata ready; remote publication requires Registry readback)
10. Remaining: other ToolCall handler closures, event submission.

---

## Contributing

The project is still in its protocol and MVP phase. Current directions suitable for contribution include:

- Protocol object and conformance tests
- Authorization attenuation and quota replay
- Verifiable builds and evidence bundles
- MCP / agent framework adapters
- Task packaging for real open-source issues
- Security, privacy, and data governance review

The repository is Apache-2.0 licensed. The PyPI package is published at
[pypi.org/project/openworkproof](https://pypi.org/project/openworkproof/),
and the MCP Server is registered on the
[MCP Registry](https://registry.modelcontextprotocol.io/).
Contribution processes and contributor agreements are still being defined —
please start with a GitHub Issue to propose ideas.

## Project Ownership

- Technical Owner: dengyier (currently serving as Maintainer, Manager, and Acceptor)
- Rights Holder: 成都星火领航科技有限公司 (Chengdu Spark Navigation Technology Co., Ltd.)

---

## Vision

OpenWorkProof aims to take agent work from "can generate results" to:

> Authorizable, constrainable, verifiable, acceptable —
> and rejectable when the evidence falls short.

OpenWorkProof doesn't make agents smarter. It gives them the accountability
structure needed to participate in social coordination.

---

## Judgment-to-Action Binding v0.4

v0.4 adds **judgment-to-action binding** to agent delivery: verifiable
execution credentials that answer whether the action the agent actually took
still corresponds to the business judgment the customer originally approved.

### Business-First Language

OpenWorkProof provides **verifiable execution credentials for agent
delivery**. It:

- ✅ proves which authorization the execution relied on, what it did, and
  whether the verifier can actually catch a lie;
- ❌ does not become a payment institution, a truth oracle, a legal
  adjudicator, or a substitute for customer acceptance.

### v0.4 State Chain and Gates

```text
Customer Acceptor signs JudgmentCommitment (before execution)
      ↓
Manager commits ActionBindingManifest (judgment ↔ execution binding)
      ↓
Agent v0.4 request + ActionReceipt (natively bound to the same Manifest)
      ↓
Independent Verifier composes BindingDecision (BOUND / UNBOUND / INDETERMINATE)
      ↓
Dual gate: VerificationDecision=VERIFIED ∧ BindingDecision=BOUND ∧ Acceptance=ACTIVE
      ↓
READY_FOR_SETTLEMENT_REVIEW (does not prove payment or settlement)
```

### External Authority Boundary

High-risk profiles may attach an external **AuthorityCheckpoint** (an
independent key in the customer's control domain). OWP only verifies the
checkpoint's format, signature, chain and binding; it **does not own the
external governance or trust root**. Authority is judged as-of the action
time, and resolver unavailability never fabricates a checkpoint.

### Truth Boundaries

- `BOUND` only means "the action matches the recorded judgment". It does
  **not mean** the judgment is correct, the code has no defects, the
  customer accepted, or payment/settlement occurred.
- Unobtained commercial states are always marked `not_evidenced`
  (upstream adoption, customer use, payment).

### Interfaces

```text
owp judgment validate
owp binding-manifest validate
owp binding compose
owp binding verify
owp binding history
owp package replay --binding
```

Read-only MCP tools: `owp_validate_judgment_commitment`,
`owp_validate_action_binding_manifest`, `owp_get_binding_status`,
`owp_explain_binding_decision`. MCP validation **rejects any
Acceptor/Verifier private-key argument** and never signs or commits.

See [docs/status.md](docs/status.md) for the full implementation state and
[docs/pilot/](docs/pilot/) for the 21-day paid pilot materials.
