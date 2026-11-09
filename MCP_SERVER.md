# Use OpenWorkProof through MCP

Contributors: dengyier & Tim Shing（成孝添）

[English overview](README.md) · [中文说明](README_zh-CN.md) · [SOC guide](docs/integrations/soc-reference.md) · [Guard guide](docs/integrations/agent-guard-onboarding.en.md)

OpenWorkProof exposes **32 local MCP tools in version 1.6.1**. Connect them to an existing Agent when you want to inspect signed work records, review supplied security alerts, or check an exported evidence bundle.

You can start with the synthetic alert example below without creating signing keys or connecting a production system. Developers integrating a work-contract workflow can then use the schema, signing, execution and verification tools.

## What you can do

| Your task | What OWP returns | Starting point |
| --- | --- | --- |
| Understand a set of Slips alerts | Cases grouped by source window, review findings and a signed reference evidence bundle | The three `owp_soc_*` tools |
| Recheck a received evidence bundle | A verification result with reasons and explicit trust requirements | `owp_soc_verify_bundle` for SOC bundles; `owp_verify_surface_bundle` for Core surface bundles |
| Record and inspect Agent work | Signed request/receipt checks, ledger state, verification drafts and delivery packages | Core tools and the [protocol guide](docs/offline-verification.md) |

The SOC workflow uses a deterministic investigation stub and simulated actions. It does not scan or remediate real hosts. MCP installation does not activate OWP Guard or protect other tools in your Agent.

## 1. Connect the local server

You need a local MCP client that can launch a **stdio** command, `uv`/`uvx`, and Python 3.10 or newer for the package. The client starts and manages the server process; there is no hosted OWP endpoint or API key in this setup.

For a client that accepts an `mcpServers` configuration, add:

```json
{
  "mcpServers": {
    "openworkproof": {
      "command": "uvx",
      "args": ["--from", "openworkproof==1.6.1", "owp-mcp"]
    }
  }
}
```

Restart or reconnect the MCP client as its own settings require. Its tool list should contain 32 OWP tools, including `owp_soc_sample_alerts`, `owp_soc_analyze_slips` and `owp_soc_verify_bundle`.

The configuration location and JSON shape depend on the host. For example, VS Code's `.vscode/mcp.json` uses a top-level `servers` key; the `mcpServers` example above is not a drop-in VS Code file. Follow the [VS Code MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration) or your client's own documentation. An MCP connection is separate from whether that client supports Agent Skills or the experimental Guard integration.

### Other launch options

If you prefer to install the command first:

```sh
uv tool install 'openworkproof==1.6.1'
```

Then configure the MCP client to launch `owp-mcp`, using its absolute executable path if the client's environment cannot find it. An equivalent entry point in an environment where the package is installed is:

```sh
python -m openworkproof.mcp_transport
```

`uvx openworkproof==1.6.1` also starts the MCP server. The explicit `owp-mcp` entry point avoids confusing it with `owp`, which is the separate CLI. A manually started stdio server waits for MCP messages; it does not open a web page or a network port.

## 2. Try one complete alert-review example

After connecting, give your Agent this prompt:

> Use OpenWorkProof to run this installation check. Call `owp_soc_sample_alerts`, pass its returned `alerts_jsonl` to `owp_soc_analyze_slips` with a local label such as `sample-review`, and then pass the returned bundle as serialized `bundle_json` to `owp_soc_verify_bundle`. Explain the cases, refusals and simulated actions. Do not operate a real host. Do not use keys or checkpoints from the same bundle as independent trust pins. If external trust pins are missing, keep `UNKNOWN` and explain what is missing.

Expected observations:

- The first tool returns **synthetic Slips alerts**; these are not incidents found on your computer.
- The review returns cases and an evidence bundle. Case-level acceptance/verification labels describe the simulated reference workflow, not a person's acceptance decision.
- Independent verification without separately obtained expected keys and witnessed checkpoints returns **`UNKNOWN`**. This is the intended result when the trust inputs are missing.

For your own alerts, replace the synthetic input with an authorized Slips JSONL export. Each review accepts at most 128 KiB, 500 lines and 50 source windows. Alert text becomes part of the MCP conversation and may be sent to your chosen model provider by the client; use data approved for that client. The SOC tools do not automatically upload telemetry or operate a live SOC service.

See the [SOC guide](docs/integrations/soc-reference.md) for trust input formats, CLI verification and remaining limits. Copying a bundle's own keys/checkpoints only demonstrates internal consistency; it does not establish independent trust or that a detection label is correct.

## 3. Add the optional SOC Review Skill

The Skill gives a compatible Agent the procedure for the same three tools:

```sh
npx skills add dengyier/OpenWorkProof --skill openworkproof-soc-review
```

Choose the target Agent and installation scope in the installer. The Skill does not configure MCP, grant host permissions or activate Guard. [Read the procedure](skills/openworkproof-soc-review/SKILL.md) before installing it.

## All 32 tools

Tool permissions differ. Some Core tools create keys, write receipts or ledger records, export files, execute configured tests, or clone a repository. Inspect the individual input schema and description before calling them; the SOC tools' read-only scope is not a claim about the whole MCP server.

### Reference SOC review — 3 tools

| Tool | What it does |
| --- | --- |
| `owp_soc_sample_alerts` | Return synthetic Slips JSONL for a first-run check. |
| `owp_soc_analyze_slips` | Review supplied alerts and return cases plus a signed reference bundle; actions are simulated. |
| `owp_soc_verify_bundle` | Check a SOC bundle using separately obtained public trust pins; missing pins returns `UNKNOWN`. |

### Keys, signatures and digests — 5 tools

| Tool | What it does |
| --- | --- |
| `owp_generate_keypair` | Generate an Ed25519 keypair; the result includes the private key. No input parameters. |
| `owp_compute_key_id` | Derive a key ID from an Ed25519 public key. |
| `owp_sign_payload` | Sign a canonical payload using the supplied private key. |
| `owp_verify_signature` | Check a signed payload against a supplied public key. |
| `owp_compute_digest` | Compute a canonical SHA-256 payload digest. |

### Contracts, domains and schemas — 5 tools

| Tool | What it does |
| --- | --- |
| `owp_verify_work_order` | Check WorkOrder identity bindings and its maintainer signature. |
| `owp_verify_nested_claim` | Check an AgentRequest or HumanDecision against its parent WorkOrder. |
| `owp_list_domains` | List canonical/signed domains. No input parameters. |
| `owp_get_schema` | Return an authoritative object schema. |
| `owp_get_schema_digest` | Return a frozen schema digest. |

### Profiles, scope and verification observations — 5 tools

| Tool | What it does |
| --- | --- |
| `owp_validate_profile` | Validate a signed Evidence Lifecycle v0.2/v0.3/v0.5 profile. |
| `owp_scope_validate` | Validate a scope's structure and digest without asserting signer authority. |
| `owp_scope_compare` | Compare a signed scope with a verifier observation. |
| `owp_integrity_observation_validate` | Assess a v0.5 population observation against its contracts; read-only. |
| `owp_control_observation_validate` | Assess v0.5 control observations against their contracts; read-only. |

### Ledger, execution and verification — 6 tools

| Tool | What it does |
| --- | --- |
| `owp_status` | Replay a SQLite ledger and return its authoritative state. |
| `owp_run_tests` | Check a signed request, run configured tests, write a receipt and save evidence files. |
| `owp_repo_read` | Forward a signed repo-read execution to the ledger coordinator. |
| `owp_run_verification` | Commit a verification arm/decision or prepare an unsigned decision, according to the explicit operation. |
| `owp_get_decision` | Prepare an unsigned decision draft without committing it. |
| `owp_analyze_repo` | Inspect repository structure; a remote URL can be cloned to a temporary directory. |

### Bundles, reports and readiness — 4 tools

| Tool | What it does |
| --- | --- |
| `owp_build_delivery_package` | Export a public, diagnostic or customer-private package using an explicit privacy view. |
| `owp_verify_surface_bundle` | Verify and replay a Core surface bundle without signing or writing. |
| `owp_render_surface_report` | Return the verified derived report, not acceptance or payment evidence. |
| `owp_get_settlement_readiness` | Derive readiness from evidence; this is not proof of payment or settlement. |

### Judgment/action binding — 4 tools

| Tool | What it does |
| --- | --- |
| `owp_validate_judgment_commitment` | Read-only validation of a signed JudgmentCommitment, without asserting authority. |
| `owp_validate_action_binding_manifest` | Read-only validation of a signed ActionBindingManifest. |
| `owp_get_binding_status` | Read the current BindingDecision head from a ledger. |
| `owp_explain_binding_decision` | Verify and explain `BOUND`, `UNBOUND` or `INDETERMINATE` with reason codes. |

## Signing, authority and acceptance boundaries

A valid signature alone does not establish who was authorized to sign. Intrinsic scope and observation checks report signer authority as `not_checked`; they do not turn it into authorization. Scope commitment and final signing require their separately reviewed authority context.

The lifecycle and binding verification tools do not accept Acceptor/Verifier private-key parameters. The generic key-generation and signing tools **do handle private-key material**, so do not paste production Acceptor or Verifier keys into an Agent conversation. Keep production signing in an independently controlled process. The alert-review sample needs no private key input.

`owp_run_verification` requires `commit_arm`, `prepare_decision` or `commit_decision`. It never blindly retries an indeterminate commit. `owp_build_delivery_package` requires `privacy_view` to be `public`, `diagnostic` or `customer_private`.

`VERIFIED` is a verification conclusion under stated evidence and trust inputs. It is not human acceptance, customer adoption, payment, escrow, settlement or a legal audit. Core surface bundles and SOC reference bundles have different verifiers and scope; do not treat SOC verification as a replay of all frozen Core semantics.

## Guard is a separate integration

For bounded Codex preview-directory editing, follow the [Guard onboarding guide](docs/integrations/agent-guard-onboarding.en.md). It requires project installation, current-version scope review, a live probe, `doctor` and a guarded launch. Its initial live checks used macOS, Python 3.12 and Codex CLI 0.147.0; this is separate from the package's Python requirement and generic MCP connection.

Guard does not provide whole-computer isolation. WorkBuddy, Windows Guard, arbitrary commands, build/deploy tasks and enterprise-system controls are not established by this MCP configuration.

## Protocol and CLI references

The CLI remains available through `owp`. Commands such as `scope-build` prepare an unsigned draft; `scope-commit` consumes an already signed scope. Observation assessment is read-only and may safely return an indeterminate result. See the complete [offline verification guide](docs/offline-verification.md), [Human Agency protocol](docs/protocol/human-agency-profile-v0.1.md) and [SOC reference guide](docs/integrations/soc-reference.md) for schemas, required signer context, exit codes and examples.
