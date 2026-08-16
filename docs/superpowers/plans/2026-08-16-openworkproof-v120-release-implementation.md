# OpenWorkProof 1.2.0 Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prepare, verify, and—only after action-time confirmation—publish OpenWorkProof package and MCP Server version 1.2.0 with bilingual v0.5 release evidence.

**Architecture:** Treat package version `1.2.0`, protocol schema version `0.5`, and release-candidate revision as separate identities. Freeze all local release metadata with one regression test, validate wheel/sdist contents, then use the existing tag-triggered GitHub Actions workflow for PyPI/GitHub and the official `mcp-publisher` CLI for MCP Registry.

**Tech Stack:** Python 3.12, setuptools, Pydantic, pytest, build, twine, GitHub Actions, GitHub CLI, official MCP Registry `mcp-publisher`.

---

## File Map

- Modify `pyproject.toml`: distribution version and Apache-2.0 package metadata.
- Modify `src/openworkproof/__init__.py`: runtime module version.
- Modify `server.json`: authoritative MCP Registry 1.2.0 metadata.
- Modify `mcp.json`: compatibility metadata mirror.
- Modify `README.md`: Chinese version links and final v0.5 evidence.
- Modify `README_en.md`: English parity.
- Modify `tests/test_package.py`: release-metadata identity regression.
- Create `docs/releases/v1.2.0.md`: factual release notes and evidence boundary.

### Task 1: Freeze the 1.2.0 metadata contract

**Files:**
- Modify: `tests/test_package.py`

- [ ] **Step 1: Add the failing release identity test**

Add a test that loads `pyproject.toml`, `server.json`, and `mcp.json` from the
repository root and asserts:

```python
expected = "1.2.0"
assert openworkproof.__version__ == expected
assert version("openworkproof") == expected
assert pyproject["project"]["version"] == expected
for metadata in (server, legacy_mcp):
    assert metadata["version"] == expected
    assert metadata["packages"][0]["version"] == expected
    assert metadata["license"] == "Apache-2.0"
assert pyproject["project"]["license"] == {"text": "Apache-2.0"}
assert "License :: OSI Approved :: Apache Software License" in pyproject["project"]["classifiers"]
```

- [ ] **Step 2: Run the test to observe RED**

Run:

```bash
.venv/bin/python -m pytest tests/test_package.py -q
```

Expected: failure because current release metadata is `1.1.1` and two surfaces
still declare MIT.

- [ ] **Step 3: Commit only after the metadata implementation in Task 2**

The RED test remains uncommitted until the corresponding metadata is green.

### Task 2: Synchronize package and MCP metadata

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/openworkproof/__init__.py`
- Modify: `server.json`
- Modify: `mcp.json`
- Test: `tests/test_package.py`

- [ ] **Step 1: Apply the minimal metadata changes**

Set all package/server/package-reference versions to `1.2.0`. Change only stale
license metadata in `pyproject.toml` and `mcp.json` to Apache-2.0; do not edit
the authoritative `LICENSE` text.

- [ ] **Step 2: Refresh the editable install and run GREEN**

```bash
.venv/bin/python -m pip install -e .
.venv/bin/python -m pytest tests/test_package.py -q
.venv/bin/python -m pip check
```

Expected: all package tests pass and no broken requirements are reported.

- [ ] **Step 3: Commit the metadata contract**

```bash
git add pyproject.toml src/openworkproof/__init__.py server.json mcp.json tests/test_package.py
git commit -m "build: prepare OpenWorkProof 1.2.0 metadata"
```

### Task 3: Synchronize bilingual README release truth

**Files:**
- Modify: `README.md`
- Modify: `README_en.md`
- Create: `docs/releases/v1.2.0.md`

- [ ] **Step 1: Update visible distribution metadata**

Change visible software version and MCP Registry version URLs from `1.1.1` to
`1.2.0`. Keep protocol references at `0.5` where they describe schema versions.

- [ ] **Step 2: Replace stale release-candidate evidence**

Both languages must contain the same values:

```text
v0.5 focused: 401 passed, 0 failed
candidate live: 175 passed, 0 failed
required-live: 3492 passed, 0 failed, 0 skipped
source revision: a305f7204053f08312613dddb3a0ce7533ce4806
inventory: supply-chain/images/candidates/a305f7204053f08312613dddb3a0ce7533ce4806.json
execution image: docker.io/openworkproof/execution-test@sha256:bc35711b843e6e2c479c52d486a1b2ed401cc90c7b15edb52b948206e9157abb
Rich #4196: VERIFICATION PASSED / VERIFIED / READY_FOR_ACCEPTANCE
```

State schemas v0.1-v0.5, 21 MCP tools, and the `not_evidenced`
customer/payment/upstream boundaries.

- [ ] **Step 3: Add factual release notes**

Create `docs/releases/v1.2.0.md` with:

- distribution/protocol distinction;
- Verification Integrity v0.5 highlights;
- final measured gates above;
- upgrade command `python -m pip install --upgrade openworkproof==1.2.0`;
- no-customer/no-payment/no-upstream-adoption boundary.

- [ ] **Step 4: Verify parity and stale-value removal**

```bash
rg -n '2491 passed|64f6ba65|Final v0\.2|required-live.*2491|versions/1\.1\.1|当前版本：1\.1\.1|Version: 1\.1\.1' README.md README_en.md
rg -n '401 passed|175 passed|3492 passed|a305f720|READY_FOR_ACCEPTANCE|21.*MCP|v0\.1.*v0\.5|1\.2\.0' README.md README_en.md docs/releases/v1.2.0.md
git diff --check
```

Expected: the first command has no matches; the second proves bilingual release
facts are present.

- [ ] **Step 5: Commit README and release notes**

```bash
git add README.md README_en.md docs/releases/v1.2.0.md
git commit -m "docs: publish OpenWorkProof 1.2.0 release notes"
```

### Task 4: Build and inspect local release artifacts

**Files:**
- Verify: `dist/openworkproof-1.2.0-py3-none-any.whl`
- Verify: `dist/openworkproof-1.2.0.tar.gz`

- [ ] **Step 1: Build from a clean output directory**

```bash
rm -rf dist
.venv/bin/python -m build
.venv/bin/python -m twine check dist/*
```

Expected: exactly one wheel and one sdist, both passing `twine check`.

- [ ] **Step 2: Verify package identity and contents**

Run an inspection script using `zipfile`, `tarfile`, and `email.parser` to assert
both artifact names contain `1.2.0`, METADATA declares `Version: 1.2.0` and
`License: Apache-2.0`, and the wheel contains each
`openworkproof/schemas/v0.{1,2,3,4,5}/schema-registry.json`.

```bash
.venv/bin/python - <<'PY'
from email.parser import Parser
from pathlib import Path
import tarfile
import zipfile

dist = Path("dist")
wheel, = dist.glob("openworkproof-1.2.0-*.whl")
sdist, = dist.glob("openworkproof-1.2.0.tar.gz")
with zipfile.ZipFile(wheel) as archive:
    names = set(archive.namelist())
    metadata_name, = [name for name in names if name.endswith(".dist-info/METADATA")]
    metadata = Parser().parsestr(archive.read(metadata_name).decode())
    assert metadata["Version"] == "1.2.0"
    assert metadata["License"] == "Apache-2.0"
    for version_number in range(1, 6):
        assert f"openworkproof/schemas/v0.{version_number}/schema-registry.json" in names
with tarfile.open(sdist, "r:gz") as archive:
    names = set(archive.getnames())
    assert any(name.endswith("/PKG-INFO") for name in names)
print(wheel, sdist)
PY
```

- [ ] **Step 3: Run local release gates**

```bash
.venv/bin/python -m pytest tests/test_package.py tests/test_schema_registry.py -q
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q src tests
git diff --check
git status --short --branch
```

Expected: tests and static checks pass; only ignored `dist/` artifacts may be
present; no source changes remain uncommitted.

### Task 5: Action-time publication gate

**Files:**
- External: `origin/main`, Git tag `v1.2.0`, PyPI, GitHub Release, MCP Registry.

- [ ] **Step 1: Request final user confirmation immediately before publication**

Report local commit hashes, artifact filenames/hashes, tests, Git status, and
the exact side effects. Do not continue without a fresh approval.

- [ ] **Step 2: Push source and tag without rewriting history**

```bash
git push origin main
git tag -a v1.2.0 -m "OpenWorkProof 1.2.0"
git push origin v1.2.0
```

Expected: normal fast-forward push; the tag triggers `.github/workflows/publish.yml`.

- [ ] **Step 3: Wait for and verify PyPI/GitHub publication**

```bash
run_id=$(gh run list --workflow publish.yml --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch --exit-status "$run_id"
gh release view v1.2.0 --json tagName,name,publishedAt,url,assets
curl -fsSL https://pypi.org/pypi/openworkproof/1.2.0/json
```

Verify the remote asset hashes against the locally built artifacts.

- [ ] **Step 4: Publish and read back MCP Registry**

Using the official publisher described by the MCP Registry quickstart:

```bash
brew install mcp-publisher
mcp-publisher --help
mcp-publisher login github
mcp-publisher publish
curl -fsSL 'https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.dengyier/OpenWorkProof'
```

Expected: the readback contains server and PyPI package version `1.2.0`. A local
`server.json` or successful login alone is not publication evidence.

- [ ] **Step 5: Report exact external state**

Report local/remote commit equality, tag, workflow result, PyPI URL and version,
GitHub Release URL/assets/hashes, and MCP Registry readback. Keep adoption,
payment, deployment, and commercial validation explicitly `not_evidenced`.
