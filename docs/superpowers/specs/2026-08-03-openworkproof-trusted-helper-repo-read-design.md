# OpenWorkProof Trusted Helper `repo_read` Design

Date: 2026-08-03

Status: user-approved design; implementation has not started

## 1. Purpose

This slice replaces the candidate image's generic Python argument surface with
a fixed internal dispatcher and implements only the read-only repository action
needed by `owp.repo_read`.

The dispatcher is an internal controller-to-helper boundary. It is not an MCP
tool, a signed protocol object, a second authorization layer, or a replacement
for the Sidecar policy and ledger. The Sidecar must authorize the Agent request
before starting this helper.

## 2. Scope

The slice provides exactly one operation:

```text
repo_read
```

It does not provide initialization, patch application, rollback, rebuild,
destruction, shell execution, generic Git execution, Docker control, signing,
evidence publication, or network access.

The image remains named and labelled `trusted-helper-candidate`. Completing this
slice does not establish the final trusted helper, the D8 gate, delivery signoff, Acceptor
reproduction, or contest delivery.

## 3. Fixed Runtime Boundary

The image entrypoint is fixed to:

```json
["/opt/venv/bin/python", "-I", "-m", "openworkproof.trusted_helper"]
```

The image has no default command arguments. Any argument after the module name
is rejected. The dispatcher reads one request from standard input and writes one
response to standard output. Standard error remains empty for both success and
failure.

The trusted controller mounts one WorkOrder-specific candidate runtime root
read-only at:

```text
/runtime
```

The request cannot provide or override that path. It cannot provide a Git
executable, command, environment variable, candidate root, worktree path, Git
directory path, output path, or host path.

The mounted runtime root must preserve the existing candidate layout:

```text
/runtime/<workspace_id>/control.json
/runtime/<workspace_id>/git/
/runtime/<workspace_id>/worktree/
```

All existing ownership, mode, inode, no-symlink, control-record, Git, and full
workspace-manifest checks remain authoritative. The helper runs as
`65532:65532`; the controller is responsible for mounting a candidate runtime
whose trusted files are owned and readable by that identity.

## 4. Request Contract

The dispatcher reads at most 8193 bytes once. A request is valid only when EOF
is reached within 8192 bytes and the exact input bytes are RFC 8785 canonical
JSON with no byte-order mark, trailing newline, trailing whitespace, duplicate
key, or second frame.

The top-level value is an object with exactly these seven fields:

```json
{
  "schema_version": "openworkproof-trusted-helper-request/0.1",
  "operation": "repo_read",
  "workspace_id": "<64 lowercase hex>",
  "source_artifact_sha256": "<64 lowercase hex>",
  "expected_head_commit": "<40 lowercase hex>",
  "expected_workspace_manifest_digest": "<64 lowercase hex>",
  "path": "<canonical relative path>"
}
```

The exact serialized key order is whatever RFC 8785 produces; callers do not
choose an alternative order. Unknown, missing, aliased, coerced, or incorrectly
typed fields are rejected. `path` uses the existing OpenWorkProof canonical
relative-path rules and is at most 512 ASCII bytes.

The dispatcher derives all paths from `/runtime` and `workspace_id`, then
constructs the existing internal `CandidateWorkspace` binding from the request's
expected immutable identifiers. No request field is treated as observed truth;
all expected values are checked against the mounted candidate state.

## 5. Read-Only Checkpoint Verification

Before opening the requested file, the helper:

1. opens `/runtime` and the candidate directories with directory and no-follow
   flags;
2. verifies the private directory layout, ownership, modes, and exact child set;
3. reads and canonicalizes `control.json`, then checks every request binding;
4. verifies the separate Git directory is bare and bound to the recorded inode;
5. verifies `HEAD` equals `expected_head_commit` and the commit/tree objects are
   reachable;
6. verifies the index represents the expected HEAD without refreshing or
   writing the index;
7. scans the complete worktree through its directory descriptor and recomputes
   the WorkspaceManifest using `expected_head_commit`;
8. requires the recomputed manifest digest to equal
   `expected_workspace_manifest_digest`.

The read-only Git verification must set `GIT_OPTIONAL_LOCKS=0` and may use only
fixed Git arguments selected by the helper. It must not use `git status` or
`git write-tree` on the read-only mount, because either command may attempt to
refresh or create Git state. No Agent-controlled bytes enter a Git argument.

Any checkpoint mismatch is `RECOVERY_REQUIRED`; it is not converted into a
policy denial or partial read.

## 6. File Read

After checkpoint verification, the helper walks `path` from the already-opened
worktree directory descriptor. Every ancestor is opened as a directory with
`O_NOFOLLOW`; the leaf is opened read-only with `O_NOFOLLOW`.

The leaf must:

- be the exact path represented in the verified WorkspaceManifest;
- be a regular file;
- have a link count of one;
- be no larger than 65,536 bytes;
- retain the same device, inode, mode, size, modification time, change time, and
  content digest across manifest scan, open, read, and final stat.

Directories, symlinks, hardlinks, FIFOs, sockets, devices, missing paths,
non-canonical paths, and files larger than 65,536 bytes are rejected. The helper
never follows a symlink and never returns a bounded prefix of an oversized file.

## 7. Response Contract

A successful response is RFC 8785 canonical JSON with exactly four fields:

```json
{
  "schema_version": "openworkproof-trusted-helper-response/0.1",
  "status": "ok",
  "result": {
    "path": "<canonical relative path>",
    "content_sha256": "<64 lowercase hex>",
    "size_bytes": 0,
    "workspace_manifest_digest": "<64 lowercase hex>"
  },
  "content_b64url": "<strict unpadded base64url>"
}
```

`result` is validated as the existing `RepoReadOutput` model. Decoding
`content_b64url` must yield exactly `size_bytes` bytes and reproduce
`content_sha256`. The content is transport-only; the signed receipt output
continues to bind the closed `RepoReadOutput`, not this internal response
envelope.

The helper writes no trailing newline. Success exits with status 0.

An error response has exactly three fields:

```json
{
  "schema_version": "openworkproof-trusted-helper-response/0.1",
  "status": "error",
  "code": "REQUEST_INVALID"
}
```

The fixed error and process-exit mapping is:

| Code | Exit | Meaning |
| --- | ---: | --- |
| `REQUEST_INVALID` | 64 | argv, framing, canonical JSON, schema, type, or operation failure |
| `RECOVERY_REQUIRED` | 65 | candidate layout, control, Git, HEAD, index, object, or manifest mismatch |
| `PATH_DENIED` | 66 | path is absent, unsafe, wrong type, hardlinked, or oversized |
| `FILE_CHANGED` | 67 | file or ancestor identity changed during the verified read |
| `INTERNAL_ERROR` | 70 | closed fallback for an unexpected internal exception |

Error responses never contain the submitted path, request bytes, host path,
file bytes, partial content, Git output, exception class, exception message, or
stack trace. Standard error remains empty.

## 8. Code Structure

The implementation changes only the following product surfaces:

- create `src/openworkproof/trusted_helper.py` for framing, dispatch, response,
  and process exits;
- add package-private read-only checkpoint/file helpers to
  `src/openworkproof/repo_tools.py`, reusing the existing candidate validators
  and manifest engine;
- create `tests/test_trusted_helper.py`;
- modify `supply-chain/images/trusted-helper/Dockerfile`;
- modify `supply-chain/images/trusted-helper/SOURCE_ALLOWLIST`;
- modify the minimum affected supply-chain tests and documentation.

The dispatcher does not parse WorkOrder, Grant, AgentRequest, Receipt, policy,
or ledger data. Those remain Sidecar responsibilities. It does not add a second
authorization decision or a second workspace truth source.

## 9. Test Strategy

Implementation follows RED, GREEN, then refactor.

Focused tests cover:

- one exact successful request and byte-for-byte response verification;
- zero-byte and 65,536-byte files;
- argv rejection;
- empty input, 8193-byte input, multiple frames, BOM, newline, whitespace,
  duplicate keys, non-canonical JSON, wrong top-level type, unknown/missing
  fields, wrong types, invalid digests, unknown operation, and path violations;
- wrong workspace ID, source artifact digest, HEAD, manifest digest, control
  record, Git object, index, directory identity, ownership, mode, or child set;
- directory, symlink, ancestor symlink, hardlink, FIFO, socket, missing file,
  and 65,537-byte file rejection;
- replacement, truncation, metadata, ancestor, and content races between scan,
  open, read, and final stat;
- no partial content and no diagnostic leakage for every failure class;
- exact process exit codes and empty stderr;
- Dockerfile entrypoint, empty command, source allowlist, offline build, UID/GID,
  provenance labels, and absence of `mcp_server.py`/`cli.py`;
- the existing portable candidate inventory remains historical and valid for
  its recorded source revision.

After the code/definition commit, the supply-chain phase rebuilds external
contexts and the helper candidate from that exact commit. It generates a new
candidate inventory that binds the new source revision, allowlist, Dockerfile,
context manifests, image ID, Docker archive, OCI archive, and all hashes.

Required verification includes focused tests, candidate supply-chain tests,
required-live Docker tests, the full pytest suite, `pip check`, `compileall`,
archive sidecar checks, recomputation of every local artifact hash from its
actual bytes, and a final check that no owned container or volume remains.

Because this slice does not expose initialization, a live image can prove the
fixed entrypoint and failure-closed request handling, while a successful
`repo_read` is exercised against a real candidate layout in the package test
environment. A live end-to-end candidate lifecycle remains blocked until a
separately designed initialization operation exists.

## 10. Commit and Evidence Boundaries

The work uses two evidence stages:

1. a code/definition commit containing the dispatcher, read boundary, tests,
   Dockerfile, allowlist, and documentation;
2. a later inventory commit created only after rebuilding artifacts from the
   exact first commit.

The second commit may record a new local candidate inventory, but all claims for
registry push, Acceptor access, clean-cache reacquisition, final trusted helper,
D8, and delivery signoff remain false unless separately evidenced.

Neither commit is automatically merged or pushed. Merge, push, Acceptor review,
delivery signoff approval, and contest delivery remain distinct user-controlled steps.

## 11. Non-Goals

This slice does not:

- expose `apply_patch`, rollback, initialize, rebuild, or destroy;
- implement MCP transport or AgentTeams integration;
- publish evidence or commit a Receipt;
- provide a general-purpose repository browser;
- add a shell, general Git, Python expression, module, or script execution API;
- add a LICENSE or change the existing `PENDING/NOASSERTION` rights state;
- claim D8, delivery signoff, independent acceptance, public release completion, contest
  submission, award status, or commercial validation.
