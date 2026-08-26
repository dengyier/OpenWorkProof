# OpenWorkProof for DeepSeek Harness V0.1 Review Remediation Design

**Date:** 2026-08-26
**Status:** Approved remediation scope
**Supersedes:** Only the conflicting implementation details in
`2026-08-26-openworkproof-deepseek-harness-plugin-v01-design.md`

## 1. Why remediation is required

Two independent read-only reviews found that the locally green test suites did
not prove the advertised packaged integration. The candidate is therefore
**not ready for integration**. The blocking facts are:

1. the packed plugin requires OpenWorkProof `1.3.0`, while the real bridge
   advertises `1.4.0`;
2. Enforce blocks `write`, `edit`, and `bash`, but the pinned host also exposes
   writable `str_replace_editor` and `pwsh` tools;
3. the default CLI bridge has no production case-handler assembler;
4. verification does not bind a VERIFIED result to one exact ActionReceipt,
   execution identity, and path-to-digest mapping;
5. a default Audit installation with no case directory registers no evidence
   surfaces and must not be described as active observation;
6. the current live preflight loads the tarball but tests imported classes,
   mocks, and a separate Python fixture rather than one real packaged chain.
7. a clean profile can compose the packed YAML but cannot import the plugin
   when the package emits runtime imports of Harness API packages that the
   profile intentionally does not install as third-party dependencies.

Passing focused, candidate, and required-live tests remains useful regression
evidence, but it does not override these direct integration failures.

## 2. First-principles success condition

V0.1 is ready only when one disposable repository can demonstrate this exact
chain through the packed artifact and pinned host:

```text
signed case -> packed DSH plugin -> real DSH tool pipeline
  -> real `owp dsh-bridge --stdio` -> authorized action receipt
  -> durable host observation -> independently bound verification
  -> export whose advertised verifier succeeds -> tamper rejection
```

No mocked bridge, directly imported policy object, or separate fixture may be
counted as the real-chain proof.

## 3. Considered approaches

### A. Patch only the two P0 literals

Fast, but leaves a package that installs and handshakes while its ordinary
commands still cannot execute a real case. Rejected because it optimizes the
appearance of readiness rather than the user outcome.

### B. Build a new standalone Verified Harness distribution now

Could hide missing integration behind a controlled host distribution. Rejected
because it duplicates host responsibility, expands the attack surface, and
delays entry into the existing DeepSeek Harness ecosystem.

### C. Repair the existing plugin and prove one closed real chain

Chosen. It preserves the separate-plugin strategy, keeps Python as the sole
protocol authority, and produces the smallest result a third party can
reproduce.

## 4. P0 contract corrections

### 4.1 One version compatibility source

The plugin compatibility module owns the exact tuple:

```text
bridge protocol 0.1.0
OpenWorkProof 1.4.0
DeepSeek Harness 0.1.1-rc.2
plugin 0.1.0
```

`bridge-client`, fake fixtures, unit tests, package evidence, and live preflight
must import or derive from this single source. A real child-process handshake
against the current core is a required regression test.

### 4.2 Pinned-host consequential tool closure

For the pinned host, Enforce denies these model-facing native tools:

```text
write
edit
bash
pwsh
str_replace_editor
```

The rule denies the whole `str_replace_editor` tool in Enforce, including its
read-only `view` command, because the monotonic guard receives the execution
only after the model has selected a multi-capability tool. V0.1 prefers a small
functional loss over a mutating bypass. Audit does not deny them.

The compatibility test must inspect the pinned host package set and fail when a
new known consequential model-facing tool is introduced without classification.

### 4.3 Clean-profile runtime loading

Harness API packages remain exact dev-time type dependencies. The emitted
plugin JavaScript must not import a second runtime copy of the host services.
OWP tool definitions therefore use the public `ToolDefinition` shape and closed
JSON Schemas directly. A clean-profile pack/install/import test is mandatory;
`--dump-config` alone is not a runtime-load test.

## 5. Production bridge assembly

`owp dsh-bridge --stdio` must create a production `handler_factory`. Opening a
validated case assembles handlers from that case only:

- action handler consumes the exact one-use decision token and calls the
  existing OpenWorkProof patch/test transaction adapters;
- verify handler constructs an independent verification case from frozen
  manifest values and committed receipt bindings;
- acceptance-draft handler prepares data for an external Acceptor but never
  signs acceptance;
- export handler emits the one documented package type and returns its digest.

The factory may reuse existing deterministic fixture helpers only after their
test-only key and clock assumptions are removed. No fallback handler may turn
an unavailable case into success.

The current `openworkproof-dsh-case/0.1` object is insufficient for this
factory: it identifies a clean source checkout, but not the controlled
candidate runtime needed by `execute_dsh_patch`, and it contains no closed
transport contract for an external Verifier. Before the factory is wired, the
case initialization contract must add those two bindings and prove that they
can be reconstructed after process restart. A lambda built from test fixtures
or a direct host-process test runner is not an acceptable substitute.

The minimal v0.1 transport is a case-bound local Unix socket. A case that
allows `owp_run_tests` must declare an absolute `verifier_socket_path`. The
address may live outside the case because macOS imposes a short Unix-socket
path limit; connection time therefore requires a non-symlink socket owned by
the current user with exact mode `0600`. The separate Verifier process owns
its private key outside the case and returns an already committed
`ToolCallReceipt`; the bridge validates
the typed receipt and reads the exact digest back from the authoritative
ledger. The socket is a transport address, not authority. Handler startup
must reject an absent, non-socket, symlinked, non-owned, or overly permissive
endpoint. Messages are one bounded canonical JSON request and one bounded
canonical JSON response per connection; transport failure remains UNKNOWN and
does not fall back to an in-process Verifier.

## 6. Verification binding

A VERIFIED result must bind all of the following:

- `case_id` and WorkOrder digest;
- exact Developer execution identity;
- exact ActionReceipt digest committed for that execution;
- source revision;
- candidate tree digest, not merely `HEAD`;
- UTF-8 sorted `(path, sha256)` artifact bindings;
- frozen test-profile digest and exit code;
- causal ledger replay result.

Paths and digests are a list of pairs, never two independently sorted lists.
Swapping the contents of two paths must change the verification object and
cannot collide. Missing or ambiguous receipt binding returns UNKNOWN, not
VERIFIED.

For v0.1, `candidate_tree_digest` is the RFC 8785 SHA-256 of the frozen source
revision plus the complete UTF-8 sorted changed-artifact bindings. Deleted,
symlinked, or otherwise unreadable changed paths fail closed; the field is not
the unchanged Git `HEAD` commit id and must not be described as one.

## 7. Honest Audit activation

Both Audit and Enforce require an explicit case directory before the plugin is
active. The shipped base profile may remain installable without a case, but it
must set `enabled: false` or equivalent and state `NOT_CONFIGURED`; it must not
claim that evidence is being recorded.

Once enabled with a valid case, Audit registers correlation and command
surfaces, signs only ObservationRecord facts, never authorizes or synthesizes an
ActionReceipt, and drains incomplete live/durable states to UNKNOWN during
shutdown.

## 8. Export, key custody, and recovery

- The command hint and produced artifact must name the same verifier. V0.1 will
  use the existing `delivery-case` export format only if the DSH handler can
  produce that exact format; otherwise the command must invoke a dedicated
  `dsh-case verify` path that verifies the actual DSH export.
- Case loading rejects Manager, Acceptor, and Verifier private-key names and
  fields. A separate Verifier process receives its key outside the Harness
  case directory.
- ACK recovery must survive a bridge-process restart. Committed responses are
  resolved from durable case truth by execution/request identity; an in-memory
  response cache remains only an optimization. If durable truth cannot
  distinguish committed from uncommitted, the client reports UNKNOWN and does
  not retry the consequential action.

## 9. Release evidence

The release candidate must contain a machine-readable composed manifest binding:

- core Git commit and package version;
- core wheel SHA-256;
- plugin Git commit and package version;
- plugin tarball SHA-256;
- pinned DSH, Node, Python, and bridge-protocol versions;
- exact real-chain command and result.

Metadata is committed only after the exact artifacts and real-chain gate pass.
A fresh immutable candidate inventory is required after source changes.

## 10. Acceptance gates

The remediation is complete only when:

1. real bridge handshake succeeds and wrong versions fail closed;
2. all five pinned native consequential tools are denied in Enforce;
3. the ordinary CLI bridge executes a real authorized case;
4. receipt/path/content swapping and key-placement adversarial tests fail closed;
5. Audit is either explicitly not configured or produces signed observations;
6. the advertised offline verification command succeeds on clean export and
   fails after tampering;
7. ACK-loss restart does not duplicate a consequential action;
8. packed-artifact real-chain preflight passes without mocks;
9. focused, plugin, candidate, and required-live gates pass;
10. two independent reviewers return READY.

Merge, push, npm/PyPI publication, marketplace submission, announcement, real
usage, and adoption remain separate states requiring separate authorization and
evidence.
