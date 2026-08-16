# OpenWorkProof 1.2.0 Release and README Evidence Sync Design

Date: 2026-08-16
Status: approved for implementation planning

## Goal

Release the completed Verification Integrity v0.5 work as OpenWorkProof Python
package and MCP Server version `1.2.0`, while synchronizing the Chinese and
English READMEs with the final measured evidence and preserving explicit
commercial-evidence boundaries.

## Release Interpretation

- `1.2.0` is the software-distribution version for the cumulative product
  release after `1.1.1`.
- `0.5` is the newest protocol-schema family. Package version and protocol
  version are related but are not the same namespace.
- The release is a minor version because it adds substantial backward-compatible
  verification-integrity capabilities and public schema/MCP surfaces.
- The repository `LICENSE` file is authoritative: Apache-2.0. Existing MIT
  values in Python package metadata and `mcp.json` are stale metadata and will
  be corrected; this does not change the project license.

## Files and Metadata

The following release identities must equal `1.2.0`:

- `pyproject.toml` project version;
- `src/openworkproof/__init__.py` module version;
- `server.json` server version and PyPI package version;
- `mcp.json` server version and PyPI package version;
- the visible version and MCP Registry version links in `README.md` and
  `README_en.md`.

The following license metadata must equal `Apache-2.0`:

- `LICENSE` contents;
- `pyproject.toml` project license and classifier;
- `server.json` license;
- `mcp.json` license;
- both README license labels.

## README Scope

- Preserve the existing section order, product positioning, installation
  instructions, CLI/MCP/Python entry points, and market narrative.
- Keep the Chinese and English READMEs structurally and factually aligned.
- Replace stale v0.2 release-candidate evidence with the final v0.5 evidence:
  - v0.5 focused: `401 passed, 0 failed`;
  - candidate live suites: `176 passed, 0 failed`;
  - required-live full suite: `3494 passed, 0 failed, 0 skipped`;
  - candidate source revision:
    `d0bec9d2f2c3cf12568fa866d16be1a56de4aa9c`;
  - immutable candidate inventory:
    `supply-chain/images/candidates/d0bec9d2f2c3cf12568fa866d16be1a56de4aa9c.json`;
  - execution image identity:
    `docker.io/openworkproof/execution-test@sha256:6d0dadec750eb498ed4d2260b4de65f33ed1c146adda6e64ec8ba588f7a88097`;
  - Rich #4196 offline delivery bundle:
    `VERIFICATION PASSED / VERIFIED / READY_FOR_ACCEPTANCE`.
- State that protocol schemas cover v0.1 through v0.5 and retain the current
  21-tool MCP surface.
- Preserve the boundary that customer adoption, paid SOW, deposit, upstream
  adoption, production deployment, payment, and settlement remain
  `not_evidenced` unless independently proven.

## Local Release Verification

Before any external side effect:

1. Add a metadata-synchronization regression covering the Python module,
   installed distribution, `server.json`, and `mcp.json`.
2. Refresh the editable environment only after changing project metadata.
3. Run package tests, README stale-evidence searches, `pip check`,
   `compileall`, and `git diff --check`.
4. Build wheel and sdist with `python -m build` in a clean output directory.
5. Run `twine check` and inspect both artifacts to prove version, README,
   license, package data, and v0.5 schemas are present.
6. Commit the release preparation without creating a tag or publishing.

## External Publication Boundary

The release is externally published only after a separate action-time user
confirmation. That final step consists of:

1. push the release-preparation commit to `origin/main`;
2. create and push annotated tag `v1.2.0`;
3. observe `.github/workflows/publish.yml` publish the immutable PyPI artifacts
   and GitHub Release assets;
4. verify PyPI `1.2.0`, GitHub Release `v1.2.0`, and artifact hashes directly;
5. publish `server.json` version `1.2.0` to MCP Registry using its official
   publisher flow;
6. read back the MCP Registry `1.2.0` record directly.

The workflow must stop and report evidence if any external publication fails.
It must not overwrite a PyPI version, force a tag, force-push Git history, or
claim MCP Registry publication from a local file alone.

## Non-Goals

- No README-wide rewrite or section reordering.
- No protocol/schema behavior change or new candidate inventory.
- No financing, customer, regulatory-compliance, upstream-adoption, payment,
  or settlement claim beyond existing evidence.
- No new market-sizing or competitor assertions.
- No external upload during local preparation.

## Consistency Rules

1. Each changed factual claim has the same meaning in Chinese and English.
2. The final v0.5 snapshot must not coexist with stale `2491 passed`, the old
   `64f6ba65...` candidate link, or a label calling v0.2 the final release gate.
3. Historical protocol descriptions may remain only when explicitly historical
   or version-specific.
4. `READY_FOR_ACCEPTANCE` means protocol readiness, not customer acceptance or
   commercial validation.
5. Package `1.2.0`, protocol `0.5`, and MCP Registry server `1.2.0` must be
   presented as separate version namespaces.

## Acceptance Criteria

- All five version-bearing release surfaces report `1.2.0` consistently.
- All license-bearing release surfaces report Apache-2.0 consistently.
- Both READMEs carry the exact v0.5 evidence and no stale release snapshot.
- Wheel and sdist pass `twine check`; installed artifact reports `1.2.0` and
  contains schemas v0.1-v0.5.
- Local release-preparation commit is clean and reproducible.
- External publication remains pending until the action-time confirmation and
  is reported separately from local readiness.
