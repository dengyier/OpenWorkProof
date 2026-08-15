# MCP Server Configuration Examples

## Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

### Option A: Pre-installed (recommended)

```json
{
  "mcpServers": {
    "openworkproof": {
      "command": "owp-mcp"
    }
  }
}
```

### Option B: Using uvx (no install needed)

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

### Option C: Using Python module

```json
{
  "mcpServers": {
    "openworkproof": {
      "command": "python",
      "args": ["-m", "openworkproof.mcp_transport"]
    }
  }
}
```

## Cursor / VS Code

Add to `.cursor/mcp.json` or VS Code MCP settings:

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

## Verification

After adding the server, verify it's running:

```bash
# Quick smoke test — should list 27 tools
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | owp-mcp
```

## Available Tools

| Tool | Description |
|------|-------------|
| `owp_generate_keypair` | Generate an Ed25519 key pair |
| `owp_compute_key_id` | Derive key_id from a public key |
| `owp_sign_payload` | Sign a canonical payload |
| `owp_verify_signature` | Verify a signed payload |
| `owp_compute_digest` | Compute canonical SHA-256 digest |
| `owp_verify_work_order` | Verify WorkOrder identity bindings |
| `owp_verify_nested_claim` | Verify AgentRequest / HumanDecision |
| `owp_list_domains` | List all canonical domains |
| `owp_status` | Replay a ledger and return its state |
| `owp_run_tests` | Forward a run-tests execution |
| `owp_repo_read` | Forward a repo-read execution |
| `owp_validate_profile` | Validate a signed Evidence Lifecycle v0.2, v0.3, or v0.5 profile |
| `owp_integrity_observation_validate` | Replay one v0.5 population observation against its contract (read-only) |
| `owp_control_observation_validate` | Replay one v0.5 control observation set against its contracts (read-only) |
| `owp_scope_validate` | Intrinsically validate a v0.3 scope without asserting signer authority |
| `owp_scope_compare` | Compare a signed v0.3 scope with observed coverage |
| `owp_run_verification` | Dispatch a v0.2/v0.3/v0.5 arm or decision operation by closed schema version |
| `owp_get_decision` | Prepare an unsigned v0.2/v0.3/v0.5 verification decision draft from the ledger family |
| `owp_build_delivery_package` | Export a public, diagnostic, or customer-private offline delivery package |
| `owp_get_settlement_readiness` | Derive the current acceptance and settlement-readiness snapshot |
| `owp_get_schema` | Get an authoritative JSON Schema |
| `owp_get_schema_digest` | Get the frozen digest of a schema |
| `owp_analyze_repo` | Analyse a repository structure |

## Evidence Lifecycle v0.2/v0.3 Boundary

The lifecycle tools are thin transports over the shared application service.
`owp_run_verification` requires an explicit operation:
`commit_arm`, `prepare_decision`, or `commit_decision`. It never blindly retries
an indeterminate commit. `owp_build_delivery_package` likewise requires an
explicit `privacy_view` of `public`, `diagnostic`, or `customer_private`.

`owp_scope_validate` and `owp_scope_compare` are read-only. Intrinsic scope
validation returns `authority: not_checked`: it proves canonical structure and
digest closure, not that the signer was authorized. Neither tool accepts a
ledger, private key, signature override, Acceptance decision, or commit
instruction. Manager signing and scope commitment remain external to MCP.

These tools never accept or store an Acceptor private key. Signing and custody
remain external operations. Settlement readiness is an evidence-derived state;
it is not proof that payment, escrow, or settlement has occurred.

Equivalent CLI commands are available through `owp`:

```bash
owp profile-validate profile.json
owp scope-build --claim claim.json --source-revision COMMIT_SHA --rules rules.json
owp scope-validate scope.json
owp scope-commit pilot.sqlite3 signed-scope-envelope.json
owp scope-compare scope.json observed-scope.json
owp verify-positive ledger.sqlite3 positive-result.json
owp verify-negative ledger.sqlite3 negative-result.json
owp verify-compose ledger.sqlite3 request-or-decision.json --mode prepare
owp verify-compose ledger.sqlite3 signed-decision.json --mode commit
owp integrity-observation validate population.json
owp control-observation validate control.json
owp delivery-build ledger.sqlite3 delivery-package --privacy-view public
owp audit-replay delivery-package
owp audit-explain delivery-package
owp audit-compare old-package new-package
owp settlement-status ledger.sqlite3
```

`scope-build` emits an unsigned draft. Its closed rules file contains the
candidate/workspace identity, selector rules, explicit members, requirement
bindings, repository root, and validity window. `scope-commit` accepts a JSON
envelope with exactly two keys, `claim` and `scope`; the scope must already be
Manager-signed. CLI comparison exits `0` when satisfied, `3` when
indeterminate, `4` when contradicted, and `1` for invalid input or another
failed operation. Non-zero comparison output retains the status and reason
codes.

`integrity-observation` and `control-observation` are read-only assessments:
they derive a status from signed inputs and replayed evidence and report
signer authority as `not_checked`, never as authorized. Population assessment
exits `0` for `matched` and `3` for `empty`, `capture_failed`, `drifted`, or
`unavailable`. Control assessment exits `0` for `proven`, `4` for `survived`,
`3` for `mismatched` or `unavailable`, and `1` for malformed input. `UNKNOWN`
is a safe outcome, not a system crash.

## v0.4 只读绑定工具

v0.4 增加 4 个**只读**绑定验证工具。它们拒绝任何 Acceptor/Verifier
私钥参数，只读不签名、不提交：

| 工具 | 说明 |
|---|---|
| `owp_validate_judgment_commitment` | 验证签名 JudgmentCommitment；无权威上下文时 authority=not_checked |
| `owp_validate_action_binding_manifest` | 验证签名 ActionBindingManifest（同上） |
| `owp_get_binding_status` | 读取账本当前 BindingDecision head（只读） |
| `owp_explain_binding_decision` | 验证并解释 BindingDecision（BOUND/UNBOUND/INDETERMINATE + reason codes） |

MCP 验证**不能**充当 Acceptor/Verifier 签名者；签名必须通过外部服务或
离线导入完成。
