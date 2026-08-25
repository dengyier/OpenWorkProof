# OpenWorkProof for DeepSeek Harness V0.1 Design

**Date:** 2026-08-26
**Status:** Approved revised design; implementation not started
**Product:** OpenWorkProof for DeepSeek Harness / OpenWorkProof｜DeepSeek Harness 可验证执行插件

## 1. First-principles purpose

The product is not a dashboard, a generic host abstraction, or a claim that an Agent is trustworthy.

Its V0.1 job is narrower:

> Let another party determine whether one consequential code change was authorized before execution, stayed within scope, produced independently rechecked evidence, and was accepted or rejected by the authorized human.

The first complete loop is:

```text
human-signed WorkOrder and CapabilityGrant
  -> exact DeepSeek Harness tool authorization
  -> observed tool execution through the Harness pipeline
  -> durable event and artifact binding
  -> independent repository readback and test rerun
  -> external human acceptance or rejection
  -> offline-verifiable delivery export
```

The plugin does not prove hidden model reasoning, unobserved processes, or every side effect inside a tool. It proves only the facts inside its declared observation and enforcement boundary. Independent readback is required before a semantic verification claim.

OpenWorkProof remains host-independent. V0.1 ships only a DeepSeek Harness adapter. Codex, ChatGPT, and Claude Code are future integration targets, not current support claims.

## 2. Evidence and upstream status

The design relies on these current DeepSeek Harness extension points:

- the official repository describes DeepSeek Harness as “Everything is a Plugin” and marks it as Developer Preview with compatibility-breaking changes expected;
- profile bundles are out-of-tree packages declaring `dsh.bundle.patch`;
- `dsh plugin --profile <name> add <spec>` installs npm, GitHub, tarball, or local bundle dependencies;
- `tools/pre-execute` supports asynchronous allow, deny, and ask decisions;
- `tools.guard()` is a synchronous monotonic final denial layer after the extensible pre-execution waterfall;
- `tools/result` exposes the frozen live result;
- `session/event` exposes append-only durable session events such as `tool/call` and `tool/result`;
- the official community path is a public plugin repository with the `dsh-plugin` GitHub topic and a post in DeepSeek Harness Discussions.

Primary sources:

- <https://github.com/deepseek-ai/deepseek-harness>
- <https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/user/develop/basic/publish.md>
- <https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/subsystems/tools.md>
- <https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/subsystems/session.md>
- <https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/user/develop/framework/events.md>
- <https://github.com/deepseek-ai/deepseek-harness/blob/master/CONTRIBUTING.md>

Observed on 2026-08-26:

- the installed local `dsh` is `0.1.0-rc.6`;
- npm metadata reports `@deepseek-ai/dsh` latest as `0.1.1-rc.2`;
- no official centralized plugin marketplace is evidenced;
- directory inclusion is discoverability, not endorsement, adoption, or security certification.

Implementation must recheck upstream version, APIs, and distribution rules before release.

## 3. V0.1 user and job

### 3.1 Primary user

A developer or small team using DeepSeek Harness to modify a Git repository and run tests, where another human must be able to review and accept the change.

### 3.2 Current failure

The Agent can report that it changed files and passed tests, but the recipient cannot cheaply establish:

- whether the change was authorized before execution;
- whether the Agent touched only allowed files and tools;
- whether the reported result matches the durable Harness record;
- whether the repository and tests independently confirm the claim;
- who accepted or rejected delivery.

### 3.3 Smallest observable improvement

For one repository and one WorkOrder, the plugin must block an unauthorized write, permit one authorized change, export a complete evidence bundle, fail verification after tampering, and keep human acceptance separate.

### 3.4 Stop condition

If DeepSeek Harness cannot provide a stable pre-execution denial path, durable tool identity, and result correlation for the supported version, V0.1 stops at an observation-only compatibility report. It must not ship Enforce mode with an unproved fail-closed claim.

## 4. Goals

V0.1 must:

1. install as a native DeepSeek Harness profile bundle;
2. complete one `Verified Code Change` loop for one Git repository;
3. provide bilingual Chinese and English status and documentation surfaces;
4. default to non-blocking `audit` mode that emits observation facts only;
5. provide explicit `enforce` mode through an `owp-verified` profile;
6. expose OWP-owned patch and test tools instead of post-hoc wrapping native mutations;
7. combine asynchronous authorization with a monotonic final guard;
8. use the existing Python OpenWorkProof implementation as the sole protocol authority;
9. keep Manager and Acceptor private keys outside Harness and the Agent;
10. bind live tool results to durable Harness events and declared artifacts;
11. perform independent repository readback and test rerun before VerificationDecision;
12. keep verification distinct from acceptance;
13. export a delivery case that another environment can verify offline;
14. package prebuilt plugin artifacts suitable for npm installation;
15. provide compatibility, privacy, threat, and supply-chain evidence proportional to a public developer preview.

## 5. Non-goals

V0.1 does not:

- modify DeepSeek Harness core;
- reimplement OpenWorkProof signing or verification in TypeScript;
- support arbitrary business workflows or every Harness tool;
- support parallel tool execution, multiple Agents, or cross-session workflow composition;
- build a custom web dashboard or full Acceptance UI;
- freeze or publish a universal Host Adapter Protocol based on one implementation;
- implement Codex, ChatGPT, or Claude Code adapters;
- build an OpenWorkProof SaaS, Agent OS, plugin marketplace, wallet, payment, custody, or settlement service;
- inspect or claim access to hidden model reasoning;
- treat a natural-language prompt as signed authorization automatically;
- accept work on behalf of a human;
- claim legal audit, absolute security, customer adoption, payment, production use, or DeepSeek endorsement.

## 6. Product positioning

### 6.1 Market name

**English:** OpenWorkProof for DeepSeek Harness

**Chinese:** OpenWorkProof｜DeepSeek Harness 可验证执行插件

### 6.2 One-line descriptions

**Chinese**

> 为 DeepSeek Harness 的代码变更增加事前授权、执行证据、独立复核与人工验收。

**English**

> Add prior authorization, execution evidence, independent rechecking, and human acceptance to DeepSeek Harness code changes.

### 6.3 Claim boundary

The plugin helps a user determine:

- who requested and authorized the declared change;
- what repository, paths, tools, and tests were in scope;
- which calls passed through the observed Harness tool pipeline;
- whether live results match durable session events;
- whether independent repository readback and test rerun support the claim;
- whether the WorkOrder-bound Acceptor accepted or rejected delivery.

It does not prove unobserved execution, hidden tool-internal behavior, remote-system state without readback, or semantic correctness beyond the frozen verification criteria.

## 7. Trust model and authority

| Role | Authority | V0.1 key boundary |
|---|---|---|
| Manager | defines WorkOrder, scope, tools, tests, and acceptance criteria | private key remains outside Harness |
| Developer Agent | performs the authorized change | receives no Manager or Acceptor private key |
| Adapter/Sidecar | witnesses Harness facts and commits gateway-bound receipts | holds only a dedicated limited witness key |
| Verifier | reads final repository state and reruns frozen checks | separate process or environment and distinct key |
| Acceptor | accepts or rejects the verified delivery | private key remains outside Harness and plugin |

Required disclosures:

- role separation does not imply organizational independence;
- if one person controls multiple keys, the export must state that independence is not evidenced;
- compromise of the Harness or adapter may falsify observed host facts unless independent readback detects the mismatch;
- a signature proves integrity and key possession under verified rules, not that a judgment criterion was correct;
- the Acceptor decision is never generated or signed by the Agent.

## 8. Distribution architecture

The authoritative protocol remains in the existing Python project. The DeepSeek Harness bundle is distributed separately:

```text
github.com/dengyier/OpenWorkProof
  protocol models, policy, signing, replay, delivery export, DSH bridge

github.com/dengyier/openworkproof-dsh-plugin
  DeepSeek Harness bundle, adapter, install docs, compatibility evidence
```

Recommended package name:

```text
@openworkproof/dsh-plugin
```

If the npm scope is unavailable, choose one unscoped fallback before implementation. Do not publish synonymous packages.

The plugin must not duplicate canonical protocol rules. Cross-repository compatibility is pinned by exact version ranges and tested artifact pairs.

## 9. Minimal runtime architecture

```text
DeepSeek Harness profile
  |
  +-- OWP DSH Bundle (TypeScript)
  |     +-- Contract Loader
  |     +-- OWP Tool Registrar
  |     +-- Async Authorization Hook
  |     +-- Monotonic Policy Guard
  |     +-- Live/Durable Evidence Correlator
  |     +-- Status and Export Commands
  |     `-- Bridge Client
  |
  `-- OWP Bridge (Python child process over stdio)
        +-- canonical models and validation
        +-- policy decisions and exact execution tokens
        +-- observation and receipt construction
        +-- independent verification orchestration
        +-- acceptance draft preparation
        `-- delivery-case export and replay

External human tools
  +-- Manager signs WorkOrder and CapabilityGrant
  +-- Verifier worker reruns frozen checks and commits its own receipt
  `-- Acceptor signs accept or reject outside Harness
```

The TypeScript bundle owns host integration. The Python bridge owns protocol
truth. External human keys do not cross into the Harness process. In
particular, the bridge does not hold a Verifier private key: `owp_run_tests`
delegates to a separate Verifier worker, then validates and reads back the
worker's already committed OWP receipt. It never downgrades the existing
Verifier-only `execute_run_tests()` boundary to Developer authority.

### 9.1 Internal adapter boundary

V0.1 may define a private typed interface for the facts needed by the bridge:

```text
session_opened
authorization_requested
tool_result_observed
durable_tool_event_observed
artifact_observed
session_closed
```

This interface is an implementation seam, not a public standard. Vendor-native data may be retained as non-authoritative extension data but cannot silently change canonical signing inputs.

A public cross-host protocol may be designed only after a second adapter exposes real commonalities and differences.

## 10. Verified Code Change contract

Each V0.1 case freezes before execution:

- one repository root and current revision;
- allowed path prefixes;
- denied path prefixes;
- allowed OWP tool names;
- maximum tool-call count and deadline;
- exact verification commands;
- expected exit-code policy;
- required evidence artifacts;
- Acceptor key binding;
- stop and rejection conditions.

The first sample case uses a disposable Git fixture. It authorizes one bounded text or source change through `owp_apply_patch` and one frozen test through `owp_run_tests`. It rejects writes outside the allowed path and rejects any export whose final repository state differs from the independently read state.

## 11. Enforcement pipeline

### 11.1 OWP-owned execution tools

The plugin registers two V0.1 tools:

```text
owp_apply_patch
owp_run_tests
```

Their tool bodies call the Python bridge, which invokes the existing OpenWorkProof authorization, execution, evidence-publication, and receipt transactions. Enforce mode does not run a native DSH write and then manufacture an OWP receipt afterward.

The `owp-verified` profile denies native consequential tools including `write`, `edit`, and unrestricted `bash`. Read-only tools remain available only within the frozen repository boundary. Audit mode may observe native tools but produces ObservationRecords rather than ActionReceipts.

### 11.2 Pre-execution authorization

For every consequential tool call:

1. the async `tools/pre-execute` listener sends the immutable execution identity, tool name, canonical arguments digest, repository target, session, and WorkOrder context to the bridge;
2. the bridge returns allow, deny, or human-confirmation-required plus a one-use decision token bound to that exact execution;
3. the adapter stores only the short-lived decision token in memory;
4. the listener never rewrites tool arguments.

### 11.3 Monotonic final guard

The synchronous `tools.guard()` denies native consequential tools in Enforce mode and checks that each OWP-owned execution has a current allow token. Missing, mismatched, expired, replayed, or already-consumed tokens produce a denial reason.

This guard is mandatory because another pre-execution listener may short-circuit the waterfall. No later listener can turn a guard denial into permission.

### 11.4 Result and durable-event correlation

The adapter observes the frozen live `tools/result` and separately observes append-only `session/event` records. It correlates by Harness execution identity, call ID, session ID, and sequence.

- live result without matching durable events: `UNKNOWN / DURABLE_EVENT_MISSING`;
- durable result without a witnessed authorized execution: `UNKNOWN / AUTHORIZATION_BINDING_MISSING`;
- duplicated, reordered, or conflicting identities: fail closed in Enforce mode;
- out-of-band work: outside evidence scope.

## 12. ObservationRecord and ActionReceipt

Audit and Enforce artifacts are not interchangeable.

### 12.1 ObservationRecord

Audit mode emits a non-authoritative adapter envelope stating what the plugin observed. It may contain hashes, versions, event identifiers, and explicit evidence gaps.

An ObservationRecord does not assert that the action was authorized, policy-approved, semantically correct, verified, or accepted.

### 12.2 ActionReceipt

An ActionReceipt may be constructed only when all required WorkOrder, CapabilityGrant, PolicyDecision, exact execution identity, result, durable event, and artifact bindings are present and valid.

Missing authorization never upgrades an ObservationRecord into an ActionReceipt after execution.

## 13. Independent verification and acceptance

### 13.1 Verification

The Verifier runs outside the Harness and bridge credential boundary. It
receives no claim from the Agent as authoritative. It independently:

1. reads the final Git revision and working-tree state;
2. checks changed paths against the frozen scope;
3. hashes declared artifacts from disk;
4. reruns the exact WorkOrder-bound verification commands;
5. compares exit codes and outputs against the frozen criterion;
6. checks the complete causal and signature chain;
7. returns verified, rejected, or unknown with machine-readable reasons.

Integrity verification and semantic verification remain separate fields. A correct signature cannot compensate for a wrong criterion.

### 13.2 Acceptance

The plugin may display `VERIFIED — AWAITING HUMAN ACCEPTANCE` and prepare an acceptance draft. It cannot sign it.

The external Acceptor reviews the scope, diff, verification result, evidence gaps, and known limitations, then signs accept or reject outside Harness. The final export binds that decision to the exact WorkOrder and verification result.

## 14. Modes and user surface

### 14.1 Audit mode

Audit is the default installation behavior:

- it does not block the existing Harness workflow;
- it emits ObservationRecords only;
- it shows `EXECUTION OBSERVED / AUTHORIZATION NOT EVIDENCED` when no prior authorization exists;
- missing bridge or event continuity remains an explicit evidence gap;
- it never displays `AUTHORIZED`, `VERIFIED`, or `ACCEPTED` without the corresponding protocol facts.

### 14.2 Enforce mode

The `owp-verified` profile enables Enforce mode:

- every consequential call requires an exact current allow token;
- expired, revoked, replayed, wrong-target, and over-scope authority is denied;
- bridge failure, missing decision state, or evidence discontinuity fails closed;
- verification must complete before an acceptance draft exists;
- acceptance remains external and human-controlled.

### 14.3 V0.1 surfaces

V0.1 provides lightweight bilingual status and export commands rather than a custom dashboard:

```text
/owp-status   current task, authorization, execution, verification, acceptance
/owp-evidence evidence coverage and gaps
/owp-export   prepare an offline-verifiable delivery export
```

If slash-command integration is not stable in the supported Harness version, the same functions ship as documented local CLI commands. This substitution does not weaken protocol semantics.

## 15. Bridge protocol

The plugin starts one local process:

```bash
owp dsh-bridge --stdio
```

Transport rules:

- stdout is JSON Lines protocol only;
- stderr is diagnostics only;
- every request has `schema_version`, `request_id`, `session_id`, `message_type`, `sequence`, `timestamp`, and `payload`;
- startup negotiates exact OWP, bridge, adapter, and Harness versions;
- requests are idempotent by `request_id` where replay is safe;
- decision tokens are one-use and bound to an exact execution identity;
- timeouts and process exits have stable operational error codes;
- no private key is passed in command-line arguments;
- committed truth is recovered by readback after lost acknowledgements.

Minimum messages:

```text
hello / ready
case_open / case_status
authorization_check / authorization_result
observation_commit / observation_result
action_execute / action_result
verify_request / verify_result
acceptance_draft / acceptance_draft_result
export_request / export_result
shutdown
error
```

Exact schemas, canonical bytes, recovery semantics, and exit codes must be frozen in the implementation plan before code.

## 16. Installation and first run

V0.1 accepts a two-step developer-preview installation:

```bash
pipx install openworkproof
dsh plugin --profile web add @openworkproof/dsh-plugin
dsh web
```

Preflight checks:

- supported exact `dsh` compatibility range;
- compatible `openworkproof` bridge version;
- bridge executable availability;
- writable private case directory;
- repository root and Git state;
- plugin bundle present in the effective profile;
- no Manager or Acceptor private key in plugin configuration;
- Audit or Enforce mode displayed explicitly.

The five-minute sample must:

1. create a disposable Git fixture;
2. show an unauthorized out-of-scope write being denied in Enforce mode;
3. authorize and complete one in-scope change;
4. independently rerun one frozen test;
5. export the case;
6. show offline verification passing;
7. modify one exported artifact and show verification failing.

## 17. Failure semantics

| Failure | Audit mode | Enforce mode |
|---|---|---|
| OWP Core absent | configuration error; no verified claim | unavailable |
| incompatible Harness version | observation disabled or explicitly degraded | unavailable |
| bridge startup or version negotiation failure | no verified claim | fail closed |
| bridge disconnect | explicit evidence gap | block consequential calls |
| pre-execution hook bypassed | outside evidence scope | guard denies |
| allow token missing or mismatched | observation only | guard denies |
| live result lacks durable event | `UNKNOWN` | fail closed |
| event loss, duplicate, or reordering | `UNKNOWN` | fail closed |
| repository readback differs | `UNKNOWN` or rejected | rejected |
| verifier unavailable | observed/executed, not verified | no acceptance draft |
| user has not accepted | verified, awaiting acceptance | verified, awaiting acceptance |
| export fails | preserve committed truth | preserve committed truth |
| plugin bypassed or out-of-band work | outside evidence scope | no complete-chain claim |

Operational failures and protocol denials use distinct stable codes. No exception path fabricates a successful receipt.

## 18. Privacy, keys, and security

Default evidence excludes:

- API keys, tokens, passwords, and private keys;
- complete environment-variable sets;
- hidden model reasoning;
- source-code bodies not selected as evidence;
- raw tool output beyond the frozen evidence need.

Default evidence includes:

- plugin, Harness, OWP, profile, and schema versions;
- session, execution, call, and event identifiers;
- tool name and canonical argument/result digests;
- declared artifact digests, sizes, media types, and repository-relative paths;
- timestamps and causal links;
- policy, verification, and acceptance identifiers;
- independence disclosure and evidence gaps.

The plugin documents filesystem locations, spawned processes, network behavior, collected fields, redaction, required permissions, key locations, uninstall, and evidence retention.

## 19. Package and supply-chain requirements

The npm package must:

- declare `dsh.bundle.patch`;
- include prebuilt JavaScript and `cordis.patch.yml`;
- avoid install-time build scripts where practical;
- pin a tested Harness compatibility range;
- contain license and third-party notices;
- pass packed-tarball install and load tests;
- publish checksums and immutable release tags;
- disclose that plugin execution is trusted local code;
- avoid downloading unpinned executables at runtime.

Exact peer dependency ranges come from compatibility tests, not examples.

## 20. Verification matrix

### 20.1 Authorization and enforcement

- an ordinary prompt does not create authorization;
- native `write`, `edit`, and unrestricted `bash` cannot bypass OWP-owned tools in Enforce mode;
- out-of-scope write is denied by the monotonic guard;
- expired, revoked, replayed, wrong-target, and over-scope grants are denied;
- another pre-execution listener cannot bypass the final guard;
- an authorized execution proceeds exactly once;
- bridge crash and policy timeout fail closed.

### 20.2 Observation and receipt boundary

- Audit emits ObservationRecord and never ActionReceipt without prior authorization;
- live and durable event identities must match;
- missing, duplicate, reordered, and substituted events return `UNKNOWN` or fail closed;
- unobserved and out-of-band work remains outside scope.

### 20.3 Semantic verification

- changed paths outside scope are rejected;
- changed tool arguments, results, or artifact bytes fail verification;
- substituted keys and mismatched case/session bindings fail;
- a valid signature bound to the wrong test criterion is rejected;
- independent test rerun failure rejects the delivery;
- export replays offline in a clean environment;
- all fail-closed paths leave no fabricated receipt or acceptance.

### 20.4 Human authority

- Manager and Acceptor private keys are absent from Harness configuration and process arguments;
- the Agent cannot invoke acceptance signing;
- verified without human decision remains `AWAITING HUMAN ACCEPTANCE`;
- accept and reject signatures bind to the exact WorkOrder and verification result.

### 20.5 Product and distribution

- Chinese and English status text renders correctly;
- npm tarball installs into a clean profile;
- bundle appears in `dsh --profile <profile> --dump-config`;
- supported versions run the exact sample;
- unsupported versions fail with an actionable message;
- uninstall does not silently delete evidence.

## 21. Staged release plan

### Gate A: local technical alpha

- exact supported Harness version;
- focused and adversarial tests pass;
- five-minute fixture loop passes;
- no public package or adoption claim.

### Gate B: externally reproducible preview

- prebuilt tarball and bilingual README;
- another clean environment reproduces install, denial, authorized execution, verification, tamper failure, and export;
- exact artifact checksums and compatibility evidence recorded.

### Gate C: ecosystem distribution

- public plugin repository;
- prebuilt npm package;
- `dsh-plugin` GitHub topic;
- bilingual DeepSeek Harness Discussions post;
- optional independent directories clearly labeled as discovery metadata only.

Directory ingestion is not a technical release gate. Publication, installation, external reproduction, real use, and adoption remain separate states.

## 22. Success criteria

V0.1 is technically releasable only when:

1. a new user completes the documented two-step installation;
2. the exact five-minute fixture demonstrates deny, allow, verify, export, and tamper failure;
3. Audit records a real Harness call without claiming authorization;
4. Enforce blocks an unauthorized out-of-scope write through the final guard;
5. one authorized code change produces a valid ActionReceipt;
6. an independent repository readback and test rerun produce VerificationDecision;
7. the Agent cannot sign human acceptance;
8. a clean environment verifies the accepted or rejected export offline;
9. the npm artifact and tested compatibility evidence belong to the exact published revision.

Customer adoption, willingness to pay, production use, organizationally independent verification, and DeepSeek endorsement remain `not_evidenced` until direct evidence exists.

## 23. Later versions

Potential follow-up work, explicitly outside V0.1:

- single-command installer or bundled sidecar;
- a second host adapter, followed by evidence-based extraction of a public Host Adapter Protocol;
- Codex, ChatGPT, and Claude Code integrations;
- parallel execution and multi-Agent cases;
- organization policy profiles and team key management;
- richer evidence visualization;
- remote verifier federation;
- externally governed plugin security metadata.

Later work requires new evidence and a separately approved design.
