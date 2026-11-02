# AI-SOC reference integration (OpenWorkProof 1.6.1)

This is an experimental reference workflow for **reviewing supplied Slips alerts and checking exported evidence**. It uses a synthetic-trained model release gate, deterministic investigation stub and simulated in-memory execution. It does not install an IDS, protect the whole computer, connect to a real AiSOC service, provide OS isolation/HSM, or perform real host remediation. Installing MCP or this Skill does not activate OWP Guard.

The `aisoc` package originates from Tim / alphatin123's MIT-licensed contribution. Its original reference documents remain under `AI-SOC-and-AISandbox-main/AI-SOC-and-AISandbox-main`; executable source is maintained in `src/aisoc`. These are SOC-specific extension objects, not a declaration of new frozen Core schemas.

## Install and connect

```sh
uv tool install 'openworkproof==1.6.1'
```

An MCP client can start the existing stdio server with:

```json
{
  "mcpServers": {
    "openworkproof": {
      "command": "uvx",
      "args": ["openworkproof==1.6.1"]
    }
  }
}
```

Introduced in 1.6.0, the three reference tools below remain available alongside the original 29 MCP tools:

| Tool | Input and result |
| --- | --- |
| `owp_soc_sample_alerts` | Returns synthetic Slips JSONL and the current scope. |
| `owp_soc_analyze_slips` | Supplied `alerts_jsonl` and a local `tenant` label → source-window cases, refusals/simulated results and signed evidence bundle. No live host or HTTP operations. |
| `owp_soc_verify_bundle` | `bundle_json`, optional separately acquired `trusted_keys_json` and `trusted_checkpoints_json` → `VERIFIED`, `UNKNOWN`, or `FAILED` with findings. No writes. |

Alert input is limited to 128 KiB, 500 lines and 50 source windows per call. The tenant label is not login or production isolation. Do not silently split a source window. Internal synthetic normality scoring is disabled for supplied alerts. Slips confidence values are not calibrated attack probabilities.

Suggested prompt after connecting:

> Use the OpenWorkProof SOC sample, analyze it, then verify the returned evidence bundle. Explain the source windows, malformed records, refusals and simulated actions. Do not operate a real host. If independent trust pins are missing, retain UNKNOWN and tell me what is missing.

Actual alert data stays in the local server process but becomes part of the MCP conversation/result and can contain sensitive material. Use only data authorized for the selected client; there is no automatic telemetry upload or background collection by these three tools.

## Install the Agent Skill

The actual Skill is [`skills/openworkproof-soc-review/SKILL.md`](../../skills/openworkproof-soc-review/SKILL.md), also available through the [AgentSkills.in Skill listing](https://www.agentskills.in/marketplace/@dengyier/openworkproof-soc-review). The site's separate MCP directory entry is a different listing.

```sh
npx skills add dengyier/OpenWorkProof --skill openworkproof-soc-review
```

Select the target Agent and install scope in the installer. This publishes instructions for using the existing MCP tools; it does not automatically configure MCP, enable Guard, or grant host permissions. For manual installation, copy the `openworkproof-soc-review` folder into your Agent's documented skill directory. The release also supplies a ZIP of that folder.

## CLI and independent verification

`owp-aisoc` and `python -m aisoc` run the same reference CLI. To import a Slips file into a new output directory:

```sh
owp-aisoc slips-ingest /path/to/alerts.json --out /path/to/new-review
owp-aisoc verify /path/to/new-review
```

The second command intentionally returns **UNKNOWN / nonzero** without external trust. A receiver must obtain expected public keys/roles and a witnessed checkpoint through a separate trusted channel, then use paths **outside the supplied bundle directory**:

```sh
owp-aisoc verify /path/to/new-review \
  --trusted-keys /path/to/recipient-trust/keys.json \
  --trusted-checkpoints /path/to/recipient-trust/checkpoints.json
```

Do not copy `trusted-keys.json` and `witness-checkpoints.json` out of the bundle and call that independent trust. Such copying is useful only for an explicitly labeled local consistency demonstration. Caller pins do not prove distinct administrators or organizations. `VERIFIED` is evidence verification under those pins, not a human acceptance decision or proof that the detection label is correct. The all-in-one reference process's role separation is logical only.

## Validation and remaining boundaries

Regression checks cover order-bound investigation tools, signed grant limits/expiry, structured parameter refusal, signed authorizations and exact receipt reconciliation, final checkpoint coverage, external trust requirements, source-window deduplication, malformed alerts and approval transport failure. Default repository CI includes both Core and the contributed SOC tests.

Real Slips/AiSOC deployment, real model quality, isolated signing and enforcement services, durable distributed budgets/revocation and organizational trust bootstrap remain deployment work. The independent `aisoc-push` adapter is not exposed through these MCP tools or the Skill.

The SOC verifier checks signed authorization/receipt links and that their task/policy digests point to earlier same-case ledger records. Its returned `verification_scope` explicitly excludes reconstructing the original work-order/policy payload, recomputing the underlying evidence meaning, proving wall-clock truth, and replaying frozen OWP Core semantics. Do not describe the reference verifier as complete Core protocol verification.

MCP case summaries label prototype statuses as `simulated_acceptance_status` and `internal_reference_verification_status`, with `human_acceptance_obtained=false`. The raw `cases.json` artifact keeps the prototype field names, whose ACCEPTED/VERIFIED values are simulated/internal results. They do not override a human-review requirement or an independent verifier's UNKNOWN.

### Trust input formats

`trusted_keys_json` uses the same public mapping format as `TrustedKeys.export()`:
keys are expected Ed25519 key IDs, each value is an object with `role` (for example
`ledger`, `authorizer`, or `executor`) and `public_raw_hex` (the 32-byte public key
encoded as 64 hex characters). `trusted_checkpoints_json` is a JSON array of
signed checkpoint objects with `payload` and `signatures`; the payload contains
`length`, `merkle_root`, `head_hash` and its recorded timestamp. Obtain these
exact values from the expected signers/witness through a separate trusted route.
These are public verification materials; private keys are never needed.

The bundle's similarly named files show the data shape, but remain untrusted
candidates. Do not promote them to trusted configuration just to make a green
status appear. CLI takes file paths to the same mapping and array; MCP takes
serialized JSON strings.

### Core pytest collector compatibility

The existing Core pytest-population verifier uses a frozen private collection
layout supported through pytest 9.1.x. Pytest 9.2 removes that layout; the Core
collector therefore returns an indeterminate selector result rather than trusting
a changed report. Development/test installations are constrained to `pytest>=8,<9.2`.
This limitation is in the separate Core pytest-collection workflow, not the three
SOC reference tools. A future collector update requires its own protocol/evidence
review; this release preserves the frozen collector.
