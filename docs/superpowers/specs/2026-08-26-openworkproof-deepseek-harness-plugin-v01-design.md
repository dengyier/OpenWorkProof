# OpenWorkProof for DeepSeek Harness V0.1 Design

**Date:** 2026-08-26
**Status:** Approved design; implementation not started
**Product:** OpenWorkProof for DeepSeek Harness / OpenWorkProof｜DeepSeek Harness 可验证执行插件

## 1. Purpose

DeepSeek Harness can execute useful Agent work, but an Agent saying “done” is not proof that the work was authorized, executed within scope, independently verified, or accepted by the responsible human.

V0.1 adds an installable DeepSeek Harness bundle that converts one Harness session into evidence-bound OpenWorkProof facts:

```text
task request
  -> authorization boundary
  -> observed tool execution
  -> signed receipts and evidence
  -> independent verification
  -> explicit human acceptance or rejection
```

The plugin does not make the Harness more intelligent. It makes consequential work easier to authorize, inspect, verify, and accept.

OpenWorkProof remains host-independent. Codex, ChatGPT, Claude Code, and DeepSeek Harness are different execution surfaces around one protocol core. This design freezes the common Host Adapter Protocol while delivering only the DeepSeek Harness adapter in V0.1.

## 2. Evidence and upstream status

The design relies on these current DeepSeek Harness extension points:

- the official repository describes DeepSeek Harness as “Everything is a Plugin” and marks it as Developer Preview with compatibility-breaking changes expected;
- profile bundles are out-of-tree packages declaring `dsh.bundle.patch`;
- `dsh plugin --profile <name> add <spec>` installs npm, GitHub, tarball, or local bundle dependencies;
- `tools/pre-execute`, `tools/post-execute`, `tools/result`, and `session/event` expose the authorization, observation, and durable-session seams required by this design;
- the official community path is a public plugin repository with the `dsh-plugin` GitHub topic and a post in DeepSeek Harness Discussions.

Primary sources:

- <https://github.com/deepseek-ai/deepseek-harness>
- <https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/user/develop/basic/publish.md>
- <https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/subsystems/tools.md>
- <https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/user/develop/framework/events.md>
- <https://github.com/deepseek-ai/deepseek-harness/blob/master/CONTRIBUTING.md>

Observed on 2026-08-26:

- the installed local `dsh` is `0.1.0-rc.6`;
- npm metadata reports `@deepseek-ai/dsh` latest as `0.1.1-rc.2`;
- no official centralized plugin marketplace is evidenced;
- several independent community directories and marketplace plugins exist, but listing is not official endorsement or security certification.

Implementation must recheck upstream version, APIs, and distribution rules before release.

## 3. Goals

V0.1 must:

1. install as a native DeepSeek Harness profile bundle;
2. provide bilingual Chinese and English product surfaces;
3. default to a non-blocking `audit` mode;
4. provide an explicit `enforce` mode through an `owp-verified` profile;
5. use the existing Python OpenWorkProof implementation as the sole protocol authority;
6. bind Harness tool execution and artifacts to OWP evidence without fabricating missing facts;
7. keep verification distinct from acceptance;
8. export a delivery case that another environment can verify offline;
9. package prebuilt plugin artifacts suitable for npm installation;
10. provide enough compatibility, privacy, and threat evidence for responsible community distribution;
11. define a host-neutral adapter contract that later Codex, ChatGPT, and Claude Code adapters can implement without changing core protocol truth.

## 4. Non-goals

V0.1 does not:

- modify DeepSeek Harness core;
- reimplement OpenWorkProof signing or verification in TypeScript;
- build an OpenWorkProof SaaS, Agent OS, plugin marketplace, wallet, payment, custody, or settlement service;
- inspect or claim access to hidden model reasoning;
- treat a natural-language prompt as a signed authorization automatically;
- accept work on behalf of a human;
- implement Codex, ChatGPT, or Claude Code adapters in the same release;
- advertise those future adapters as supported before their own implementation and verification gates pass;
- claim legal audit, absolute security, customer adoption, payment, or production use.

## 5. Product positioning

### 5.1 Market name

**English:** OpenWorkProof for DeepSeek Harness
**Chinese:** OpenWorkProof｜DeepSeek Harness 可验证执行插件

### 5.2 One-line descriptions

**Chinese**

> 为 DeepSeek Harness 的 Agent 工作增加可验证授权、执行回执、独立验证与人工验收。

**English**

> Add verifiable authorization, execution receipts, independent verification, and human acceptance to DeepSeek Harness agents.

### 5.3 User promise

An Agent saying “done” is not proof of delivery. The plugin helps a user determine:

- who requested and authorized the work;
- what authority and tool scope were granted;
- what the Harness actually executed;
- what evidence and artifacts support the result;
- whether an independent verifier approved the evidence;
- whether an authorized human accepted or rejected delivery.

## 6. Distribution architecture

The authoritative OpenWorkProof protocol remains in the existing Python project. A separate plugin repository is the recommended distribution surface:

```text
github.com/dengyier/OpenWorkProof          authoritative protocol and Python package
github.com/dengyier/openworkproof-dsh-plugin  DeepSeek Harness bundle and market surface
```

The plugin repository may be developed from a temporary integration workspace, but its published artifact must not duplicate protocol rules.

Future host adapters remain separate distribution packages around the same core:

```text
Codex Adapter -----------\
ChatGPT Adapter ----------+--> OWP Host Adapter Protocol --> OpenWorkProof Core
Claude Code Adapter ------+
DeepSeek Harness Plugin --/
```

Only the DeepSeek Harness path is a V0.1 deliverable. The other paths establish architectural intent, not present support.

Recommended package name:

```text
@openworkproof/dsh-plugin
```

If the npm scope is unavailable, use a single unscoped fallback selected before implementation. Do not publish multiple synonymous packages.

## 7. Runtime architecture

```text
DeepSeek Harness Web or Headless Profile
  |
  +-- OpenWorkProof DSH Bundle (TypeScript)
  |     +-- Session Contract Plugin
  |     +-- Tool Policy Gate
  |     +-- Evidence Collector
  |     +-- Acceptance UI Provider
  |     `-- Bridge Client
  |
  `-- OpenWorkProof Bridge (Python child process over stdio)
        +-- canonical models and validation
        +-- signing and key binding
        +-- policy decisions
        +-- receipt construction
        +-- verification and replay
        `-- delivery-case export
```

The TypeScript bundle owns Harness integration. The Python bridge owns protocol truth.

### 7.1 Host Adapter Protocol

The host-neutral contract sits above existing OWP models and below vendor-specific event APIs. It must not alter frozen WorkOrder, CapabilityGrant, PolicyDecision, ActionReceipt, VerificationDecision, or AcceptanceDecision semantics.

Every adapter declares its observable and enforceable capabilities before opening a case:

```json
{
  "schema_version": "openworkproof-host-capabilities/0.1",
  "host": "deepseek-harness",
  "host_version": "<observed-version>",
  "adapter_version": "<observed-version>",
  "capabilities": {
    "observe_tool_calls": true,
    "block_before_execute": true,
    "observe_results": true,
    "collect_artifacts": true,
    "show_acceptance_ui": true
  }
}
```

The common event vocabulary is:

```text
session_started
task_requested
authorization_requested
tool_started
tool_finished
artifact_observed
verification_requested
acceptance_recorded
session_ended
```

Vendor-native payloads may be retained as non-authoritative extension data. They must not silently change canonical OWP signing inputs.

Capability negotiation controls the strongest claim an adapter may make:

- `block_before_execute=true` is required for `enforce`;
- observation without pre-execution control permits `audit` only;
- missing event continuity produces `UNKNOWN` or an evidence gap;
- no acceptor identity binding means no formal AcceptanceDecision;
- a bypassed adapter cannot claim a complete execution chain.

The first implementation may place the adapter protocol in the existing Python repository as a small model, validation, and bridge surface. Host-specific TypeScript remains in the plugin repository.

## 8. Components

### 8.1 Session Contract Plugin

Responsibilities:

- create a stable binding between a Harness session and an OWP case;
- capture the task request separately from authorization;
- expose the current contract, evidence state, and acceptance state to the UI;
- never infer a CapabilityGrant from an ordinary user prompt.

### 8.2 Tool Policy Gate

Responsibilities:

- participate in `tools/pre-execute`;
- normalize tool name, arguments digest, target, session, and task context;
- in `audit`, observe without changing the Harness result;
- in `enforce`, request an OWP policy decision before consequential execution;
- map allow, deny, and human-confirmation outcomes without silently falling back.

### 8.3 Evidence Collector

Responsibilities:

- observe canonical tool results and durable session events;
- bind tool calls, results, artifacts, versions, timestamps, and event identifiers;
- store hashes and minimal required metadata by default;
- mark missing or discontinuous evidence explicitly;
- never convert incomplete observation into a successful receipt.

### 8.4 Bridge Client and Python Bridge

The plugin starts one local bridge process:

```bash
owp dsh-bridge --stdio
```

The bridge uses JSON Lines. Every message includes:

- `schema_version`;
- `request_id`;
- `session_id`;
- `message_type`;
- `timestamp`;
- `payload`.

Minimum message types:

```text
hello / ready
session_open / session_status
authorization_check / authorization_result
tool_started / tool_finished
artifact_observed
verify_request / verify_result
acceptance_request / acceptance_result
export_request / export_result
shutdown
error
```

The implementation plan must freeze exact schemas, canonical bytes, exit behavior, and replay semantics before production code.

### 8.5 Acceptance UI Provider

The UI follows the active Harness language while retaining stable English protocol identifiers.

It must display:

```text
Task / 任务
Authorization / 授权
Execution / 执行
Verification / 验证
Acceptance / 验收
Evidence / 证据
```

The user can:

- review the active scope and evidence;
- explicitly authorize when permitted by the current protocol context;
- accept delivery;
- reject delivery with a reason;
- request more evidence;
- export the case.

The UI must never label `VERIFIED` as `ACCEPTED`.

## 9. Modes

### 9.1 Audit mode

Audit mode is the default public-install behavior.

- It does not block the existing Harness workflow.
- It records observable task, tool, result, and artifact facts.
- It may verify integrity and evidence completeness.
- Without a valid prior authorization, it displays:

```text
EXECUTION OBSERVED
AUTHORIZATION NOT EVIDENCED
```

- Missing bridge or events create an explicit evidence gap.
- Audit mode must not imply that observed work was authorized or accepted.

### 9.2 Enforce mode

The `owp-verified` profile enables enforce mode by default.

- Consequential tool calls require a current, scope-matching authorization.
- Expired, revoked, replayed, wrong-target, or over-scope authority is denied.
- The gate may request explicit human confirmation when the protocol permits it.
- A bridge failure or evidence discontinuity fails closed.
- Verification must complete before the result can be presented for acceptance.
- Human acceptance remains a separate signed or otherwise protocol-bound decision.

## 10. Protocol mapping

| DeepSeek Harness fact | OpenWorkProof meaning | Boundary |
|---|---|---|
| user prompt or task | task request / WorkOrder input | not automatically authorization |
| session identity | case/session correlation | not human identity by itself |
| `tools/pre-execute` | PolicyDecision input | enforce may allow, deny, or request confirmation |
| canonical tool call | ActionReceipt action input | arguments require canonical digest binding |
| tool result | ActionReceipt result input | successful transport is not semantic success |
| `session/event` sequence | causal evidence | gaps must remain visible |
| artifact path/content | EvidenceRef | bind digest, size, and declared scope; avoid secret capture |
| verifier result | VerificationDecision | verification is not acceptance |
| user acceptance action | AcceptanceDecision | requires authorized acceptor context |

Existing OpenWorkProof schemas remain authoritative. The plugin may introduce adapter-envelope schemas, but must not fork or weaken frozen core semantics.

The DeepSeek Harness mapping is the first conformance implementation of the Host Adapter Protocol. Later adapters require their own capability mapping, threat model, compatibility matrix, tests, and release evidence.

## 11. Installation and first-run flow

V0.1 accepts a two-step installation to reach the market quickly:

```bash
pipx install openworkproof
dsh plugin --profile web add @openworkproof/dsh-plugin
dsh web
```

The first-run preflight checks:

- compatible `dsh` version and profile;
- compatible `openworkproof` version;
- bridge executable availability;
- writable private case directory;
- no unexpected secret capture configuration;
- plugin bundle loaded in the effective profile.

The onboarding offers:

1. Audit Mode / 审计模式;
2. Verified Profile / 强制验证配置;
3. a five-minute real sample task;
4. evidence timeline review;
5. delivery-case export and offline verification.

## 12. Failure semantics

| Failure | Audit mode | Enforce mode |
|---|---|---|
| OWP Core absent | configuration error; no verified claim | enforce unavailable |
| incompatible Harness version | observation disabled or explicitly degraded | enforce unavailable |
| bridge startup failure | no verified claim | fail closed |
| bridge disconnect | continue only with visible evidence gap | block later consequential calls |
| event loss or sequence gap | `UNKNOWN / EVIDENCE GAP` | fail closed |
| policy timeout | record unavailable decision | deny or require authorized human decision |
| verifier unavailable | executed, not verified | cannot proceed to accepted state |
| user has not accepted | verified, awaiting acceptance | verified, awaiting acceptance |
| export fails | preserve committed truth; report export failure | preserve committed truth; report export failure |
| plugin bypassed | outside evidence scope | no complete-chain claim |

Operational failures and protocol denials must have distinct stable codes. No exception path may fabricate a successful receipt.

## 13. Privacy and security

Default evidence excludes:

- API keys, tokens, passwords, and private keys;
- complete environment-variable sets;
- hidden model reasoning;
- source-code bodies not selected as evidence;
- raw tool output beyond the minimum declared evidence need.

Default evidence includes:

- plugin, Harness, OWP, profile, and schema versions;
- session and event identifiers;
- tool name and canonical argument/result digests;
- declared artifact digests, sizes, and media types;
- timestamps and causal links;
- policy, verification, and acceptance identifiers.

The plugin must document:

- filesystem locations;
- spawned processes;
- network behavior;
- collected fields;
- redaction behavior;
- permissions required;
- uninstall and evidence-retention behavior.

## 14. Package and supply-chain requirements

The npm package must:

- declare `dsh.bundle.patch`;
- include prebuilt JavaScript and `cordis.patch.yml`;
- avoid install-time build scripts where practical;
- pin and publish a tested DeepSeek Harness compatibility range;
- contain license and third-party notices;
- pass packed-tarball install and load tests;
- publish a checksum and immutable release tag;
- disclose that plugin execution is trusted local code;
- avoid downloading unpinned executables at runtime.

Initial manifest shape:

```json
{
  "name": "@openworkproof/dsh-plugin",
  "version": "0.1.0",
  "type": "module",
  "main": "lib/index.js",
  "files": ["lib", "cordis.patch.yml"],
  "dsh": {
    "bundle": {
      "patch": "./cordis.patch.yml"
    }
  }
}
```

Exact peer dependency ranges must come from the implementation compatibility tests, not from this example.

## 15. Verification matrix

Release requires evidence for at least:

### Audit behavior

- ordinary Harness execution remains unblocked;
- observed tool calls produce a deterministic evidence timeline;
- absent authorization is displayed as absent;
- missing events produce `UNKNOWN`, not success.

### Enforce behavior

- unauthorized file write is denied;
- unauthorized shell or external action is denied;
- expired, revoked, replayed, wrong-target, and over-scope grants are denied;
- authorized execution proceeds exactly once;
- bridge crash and policy timeout fail closed;
- a human-confirmation path cannot be replayed for another action.

### Evidence integrity

- changed tool arguments fail verification;
- changed tool results fail verification;
- changed artifact bytes fail verification;
- missing, duplicated, or reordered events fail or return `UNKNOWN` as specified;
- substituted keys and mismatched case/session bindings fail;
- export can be replayed offline in a clean environment.

### Product and distribution

- Chinese and English surfaces render correctly;
- npm tarball installs into a clean profile;
- bundle appears in `dsh --profile <profile> --dump-config`;
- supported Harness versions load and run the sample;
- unsupported versions fail with an actionable message;
- uninstall removes the bundle without deleting user evidence silently.

## 16. Market release plan

### 16.1 Official ecosystem discovery

1. publish the public GitHub plugin repository;
2. add `dsh-plugin`, `deepseek-harness`, `openworkproof`, `verifiable-execution`, and `ai-agent-security` topics;
3. publish the prebuilt npm package;
4. post a bilingual “Show Your Plugin” entry in DeepSeek Harness Discussions;
5. provide an exact install command, compatibility matrix, demo, threat model, and evidence boundary.

### 16.2 Community directories

After the official discovery path is live:

- verify whether topic-based community indexes ingest the repository;
- submit structured metadata to relevant independent registries;
- state that inclusion is discovery metadata, not official endorsement or security certification;
- correct stale compatibility records when upstream changes.

### 16.3 Launch assets

- bilingual README;
- 60–90 second installation and first-case video;
- Audit versus Enforce comparison GIF;
- sample WorkOrder and exported evidence bundle;
- one tamper demonstration showing offline verification failure;
- privacy and permissions page;
- compatibility badge tied to a dated test result;
- public issue template for compatibility and security reports.

## 17. Success criteria

V0.1 is technically releasable only when:

1. a new user can complete the documented two-step installation;
2. the five-minute sample produces an understandable bilingual timeline;
3. Audit records a real task without blocking it;
4. Enforce blocks at least one unauthorized consequential action;
5. an authorized action produces a valid receipt;
6. a tampered export fails offline verification;
7. verification and human acceptance remain visibly distinct;
8. the npm package installs and loads from a clean profile;
9. compatibility evidence belongs to the exact published artifacts.

Market distribution is complete only when the public repository, npm package, official Discussions post, and at least one independently reachable directory entry are verified. These states must be reported separately.

Customer adoption, willingness to pay, production use, and DeepSeek endorsement remain `not_evidenced` until direct evidence exists.

## 18. Later versions

Potential follow-up work, explicitly outside V0.1:

- single-command installer or bundled OWP sidecar;
- Codex, ChatGPT, and Claude Code adapters sharing the same Host Adapter Protocol;
- organization policy profiles and team key management;
- richer evidence visualization;
- remote verifier federation;
- externally governed plugin registry security metadata.

Later work requires new evidence and a separately approved design.
