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
# Quick smoke test — should list 19 tools
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
| `owp_validate_profile` | Validate a signed Evidence Lifecycle v0.2 profile |
| `owp_run_verification` | Commit one arm result, prepare a decision, or commit a decision |
| `owp_get_decision` | Prepare an unsigned v0.2 verification decision draft |
| `owp_build_delivery_package` | Export a public or customer-private offline delivery package |
| `owp_get_settlement_readiness` | Derive the current acceptance and settlement-readiness snapshot |
| `owp_get_schema` | Get an authoritative JSON Schema |
| `owp_get_schema_digest` | Get the frozen digest of a schema |
| `owp_analyze_repo` | Analyse a repository structure |

## Evidence Lifecycle v0.2 Boundary

The five v0.2 tools are thin transports over the shared application service.
`owp_run_verification` requires an explicit operation:
`commit_arm`, `prepare_decision`, or `commit_decision`. It never blindly retries
an indeterminate commit. `owp_build_delivery_package` likewise requires an
explicit `privacy_view` of `public` or `customer_private`.

These tools never accept or store an Acceptor private key. Signing and custody
remain external operations. Settlement readiness is an evidence-derived state;
it is not proof that payment, escrow, or settlement has occurred.

Equivalent CLI commands are available through `owp`:

```bash
owp profile-validate profile.json
owp verify-positive ledger.sqlite3 positive-result.json
owp verify-negative ledger.sqlite3 negative-result.json
owp verify-compose ledger.sqlite3 request-or-decision.json --mode prepare
owp verify-compose ledger.sqlite3 signed-decision.json --mode commit
owp delivery-build ledger.sqlite3 delivery-package --privacy-view public
owp audit-replay delivery-package
owp audit-explain delivery-package
owp audit-compare old-package new-package
owp settlement-status ledger.sqlite3
```
