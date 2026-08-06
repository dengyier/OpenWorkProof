# OpenWorkProof Production Docker Executor Integration

Date: 2026-08-07

Branch: `codex/acceptor-rejection` (continues on the same feature line)

Spec: `docs/superpowers/specs/2026-08-04-openworkproof-run-tests-execution-recovery-design.md`

## 1. Objective

The recovery design and the `DockerRunTestsExecutor` production driver already
exist and are unit-tested in `tests/test_sandbox.py`, but `execute_run_tests`
in `mcp_server.py` has no production caller and no factory that constructs the
Docker executor. This slice connects the production path:

```text
test_sandbox covers:  DockerRunTestsExecutor + plan/reconcile/cleanup pure logic
gap:                  mcp_server.execute_run_tests is only invoked by tests with
                      fake drivers; no production entry point constructs and runs
                      the Docker executor end-to-end
this slice:           production driver factory + execute_run_tests production
                      entry + required-live integration test + 08-04 plan close-out
```

## 2. Approved Decisions

- **E1:** Reuse the existing `DockerRunTestsExecutor`; do not re-implement the
  driver. The gap is wiring, not driver logic.
- **E2:** Add a production factory `build_docker_run_tests_driver(...)` in
  `repo_tools.py` (or `mcp_server.py`) that constructs the executor from an
  immutable image reference, an absolute docker binary, and an absolute
  candidate runtime root; validation mirrors the executor constructor.
- **E3:** Add a production entry `execute_run_tests_production(...)` in
  `mcp_server.py` that constructs the driver, builds the candidate snapshot
  request, and calls the existing `execute_run_tests`. Tests keep injecting
  fake drivers through `execute_run_tests` unchanged.
- **E4:** The required-live integration test uses the frozen repository image
  reference and the day0 artifact root; it must not invent or retag an image.
- **E5:** The 08-04 plan checkboxes are updated only to the true
  implementation state revealed by the audit; no step is checked without
  evidence.

## 3. Task 1: Audit 08-04 Implementation State

- [ ] Read the 54-step 08-04 plan and map each step to
  `repo_tools.py` / `mcp_server.py` / `tests/test_sandbox.py` symbols.
- [ ] Produce an audit table (step -> symbol -> implemented? -> test?) and
  record which steps remain genuinely unimplemented after this slice.
- [ ] Commit the audit as part of the plan document update.

## 4. Task 2: Production Driver Factory and Entry

- [ ] Add `build_docker_run_tests_driver(*, docker_binary, image_reference,
  candidate_runtime_root)` returning a validated `DockerRunTestsExecutor`;
  raise a coordination error on invalid configuration.
- [ ] Add `execute_run_tests_production(ledger_path, *, evidence_root,
  context, request, request_arguments, execution_facts,
  candidate_snapshot_request, sidecar_private_key, clock)` that builds the
  driver from the frozen environment configuration and calls
  `execute_run_tests`.
- [ ] Unit tests: factory rejects invalid config; production entry
  delegates to `execute_run_tests` with the Docker driver (mock `run`).

## 5. Task 3: Required-Live Docker Integration Test

- [ ] Add a `required-live` marked test that:
  - constructs the Docker executor from the frozen image reference
    `docker.io/openworkproof/execution-test@sha256:677cfa...`;
  - drives one full `execute_run_tests` chain on a verifier work order;
  - asserts a committed verifier result receipt with evidence on disk;
  - asserts container and volume cleanup after the run.
- [ ] Run with `OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1` and the day0 root.

## 6. Task 4: Close-Out and Verification

- [ ] Update the 08-04 plan checkboxes to the audited state; add a note for
  any remaining boundary.
- [ ] Update `docs/status.md` and `README.md`: real Docker executor is wired
  into the production path and verified required-live; remove the stale
  "real executor not connected" boundary claims.
- [ ] Run focused suites, the candidate full gate, and full required-live to
  exit code 0; run pip/compileall/diff checks; require zero owned
  containers/volumes after the suite.
- [ ] Record the branch state and present the standard integration choices;
  do not merge or push without explicit user selection.
