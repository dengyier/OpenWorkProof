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
# Quick smoke test — should list 14 tools
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
| `owp_get_schema` | Get an authoritative JSON Schema |
| `owp_get_schema_digest` | Get the frozen digest of a schema |
| `owp_analyze_repo` | Analyse a repository structure |
