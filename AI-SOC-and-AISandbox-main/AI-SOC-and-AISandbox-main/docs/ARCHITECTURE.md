# Architecture: AI-IDPS + Agent Sandbox + OpenWorkProof

This document maps the paper *AI 安全與道德治理：結合 dual_model、Agent 影響限制與
OpenWorkProof 的可驗證 AI SOC 架構* to the code in `aisoc/`. Section numbers
refer to the paper.

## 1. Separation of responsibilities (§I, §VI-C, §IX-A)

```
 telemetry ──► dual_model (idps/) ──► CaseDecision
 Slips alerts.json ─► adapters/slips ─┘  (external known / anomaly branches)
                                          │  requires_agent_investigation
                                          ▼
                       WorkOrder (frozen task + evidence digest)
                       CapabilityGrant (tenant / actions / resources / ttl / uses; attenuate() narrows only)
                                          │
                                          ▼
             ┌───────────── inner execution domain A (can be lost) ─────────────┐
             │  InvestigationAgent ── read-only tools ── Untrusted[...] results  │
             │  output: InvestigationReport + ActionRequest(s)   (no authority)  │
             └──────────────────────────────┬───────────────────────────────────┘
                                            ▼
             ───────────── ControlledEgressProxy: the only way out of A ──────────
               allow-listed message types, size / rate limits, canonical form,
               record in ledger FIRST, forward SECOND; audit down ⇒ drop
                                            ▼
             ┌───────────── external service domain C ──────────────────────────┐
             │ PolicyEngine  → allowed | reserved | denied   (C_eff intersection) │
             │ HumanApprover → HumanApproval bound to request/evidence/params     │
             │   (local stub, or AiSOCApprovalBridge over the AiSOC approval API)  │
             │ AuthorizationSigner → Ed25519 envelope (only after policy check)   │
             │ PolicyEnforcementPoint → sig, binding, expiry, revocation,         │
             │   approval, atomic nonce, idempotency → BoundedExecutor            │
             │   → ActionReceipt signed by *executor* key                         │
             └──────────────────────────────┬───────────────────────────────────┘
                                            ▼
             ┌───────────── independent audit domain B ─────────────────────────┐
             │ HashChainLedger (digests only) → Merkle checkpoint → ExternalWitness│
             │ EncryptedEvidenceStore (originals, separately keyed, deletable)    │
             │ ExternalEvidenceRef (e.g. AiSOC HMAC bundle re-derived + anchored) │
             │ Verifier: chain + witness + tool-side reconciliation + egress check │
             │ AcceptanceDecision by a human                                       │
             └────────────────────────────────────────────────────────────────────┘

             ┌───────────── training domain (offline) ─────────────────────────┐
             │ DualModel.train → to_bytes() → ModelReleaseManifest signed by     │
             │ the model_release key → AISOC.from_release verifies hash + sig    │
             │ before loading and writes a model_release ledger entry           │
             └──────────────────────────────────────────────────────────────────┘
```

Five keys exist in the SOC (`ledger`, `authorizer`, `executor`, `verifier`,
`approver`); a sixth, `model_release`, belongs to the training domain — the
SOC receives only its public key (`release_trust`) and never the private half.
`TrustedKeys.verify(..., expected_role=...)` means a key trusted for one role
cannot sign for another. In this reference implementation all of them live in
one process; the paper's assumptions (§IV-B) require them to be in separately
administered domains with no reachable path from A to the private keys.

## 2. dual_model (§V–§VI) — `aisoc/idps/`

| Paper element | Code |
|---|---|
| shared, versioned features; scaler fit on train only | `features.py` (`FEATURE_SCHEMA_VERSION`, `StandardScaler`) |
| known branch f_k with calibrated score and reject option | `known_model.py` (OvR logistic regression, temperature scaling on validation, `tau_k`) |
| normality branch f_a on vetted normal windows, per-service-group τ_a | `normality_model.py` (Isolation Forest, quantile threshold on validation-normal) |
| Table III multi-path decision incl. conflict and insufficient-evidence branches; missing data ⇒ UNKNOWN | `dual_model.py` (`CaseStatus`, `DualModel.decide`) |
| same decision table fed by an external detector (Slips) in place of one or both branches | `dual_model.py` (`ExternalKnown`, `ExternalAnomaly`, `DualModel.decide_external`) |
| leave-one-family-out, time-ordered split | `simulate.py` (`generate(held_out_family=...)`) |
| model as a signed, hash-pinned artefact crossing from the training domain | `dual_model.py` (`to_bytes` / `from_bytes`, schema + feature-schema checks), `release.py` (`release_model`, `load_verified_model`, role `model_release`) |

Scores `c_k`, `s_a` and `τ_a` are stored separately on every `CaseDecision`.
Labels are consumed only in `DualModel.train`; the agent's verdicts are never
fed back as labels. When the external path is used, `model_version` becomes
`<internal>+slips/<module>` so the ledger shows which detector produced the
known-branch claim; the Slips evidence `Description` is only ever an
`Untrusted` excerpt (see [`INTEGRATION.md`](INTEGRATION.md)).

## 3. Agent sandbox (§VII, §VI-C) — `aisoc/sandbox/`

* `untrusted.py` – every log/tool output is wrapped in `Untrusted`; a heuristic
  injection screen adds flags that are shown to humans. **The screen is not a
  boundary.** The boundary is that agent output is a structured
  `ActionRequest` whose action must be in the `WorkOrder` vocabulary.
* `tools.py` – tenant-scoped read-only tools with a per-case budget and an
  independent `ToolSideLog` (second record used for reconciliation).
* `agent.py` – `HeuristicStubAgent` (decides from fields, never from free text)
  and `InjectionFollowingStubAgent` (deliberately obeys injected text, used to
  test L1). Agents cannot: modify policy, write training labels, disable audit,
  export raw telemetry (`FORBIDDEN_FOR_AGENT`).
* `egress.py` – `ControlledEgressProxy`, the sandbox's single channel out.
  Message types are allow-listed (`investigation_report`, `action_request`),
  size- and rate-limited and must canonicalise; the agent identity is bound by
  the channel, not claimed in the message. Every forwarded message is written
  to the ledger as `agent_egress` **before** it is forwarded; if the audit
  domain is unavailable the message is dropped (`AUDIT_UNAVAILABLE`), so an
  outage can never become a blind spot. `fail_open_on_audit_error` exists only
  for the ablation.
* `policy.py` – `C_eff = C_task ∩ C_grant ∩ C_human ∩ C_runtime`. High impact
  and all outbound connections are `reserved`. Egress must give exact
  `ip:port`, scope (public/private is re-derived, not trusted) and TTL.
* `authorization.py` – `ApprovalView` shows supporting *and* missing evidence,
  injection flags, impact and reversibility (§IX-B). `AuthorizationSigner`
  refuses denied decisions and reserved decisions without a valid, bound
  approval. Envelope fields follow §VIII-B. The approval step is pluggable
  (`AISOC.set_approval_provider`): the default is the local `HumanApprover`
  stub; `adapters/aisoc_stack.AiSOCApprovalBridge` routes it through the AiSOC
  approval inbox and fails closed with a *signed* reject on deny, timeout,
  transport error or a mismatched `request_digest` echo.
* `pep.py` – check order: signature → binding (request/params/destination
  digests) → expiry → revocation → approval presence → idempotency → atomic
  nonce → bounded execution with egress default-deny → executor-signed
  receipt. `PEPConfig` flags exist only for ablations.

## 4. OpenWorkProof alignment (§VIII) — `aisoc/owp/`

Object chain: `WorkOrder → CapabilityGrant → PolicyDecision → HumanApproval →
AuthorizationEnvelope → ActionReceipt → VerificationDecision →
AcceptanceDecision`. Schema strings are `owp-soc/<name>/0.1` and are this
project's SOC-extension proposals, not the upstream OWP schema.

* `canonical.py` – RFC 8785 subset; what gets signed is always canonical bytes.
* `ledger.py` – hash chain storing digests and references only; Merkle
  checkpoints signed by the ledger key and published to an `ExternalWitness`
  (append-only JSONL). Detects modification, truncation and forks relative to a
  witnessed checkpoint. `EncryptedEvidenceStore` keeps originals under a
  separate key with an access log, so retention/deletion does not break the
  chain (§IX-C).
* `verifier.py` – chain + witness + reconciliation: an executed tool receipt
  without a prior recorded authorization is a **bypass**; a ledger execution
  without a receipt is an inconsistency; an `action_request` with no earlier
  `agent_egress` record carrying the same digest did not come through the
  audited channel. No witness ⇒ `UNKNOWN`, never `VERIFIED`.
* `objects.py` – `CapabilityGrant.attenuate()` derives a child grant for a
  sub-task that can only **narrow** actions, resources, uses and TTL (parent id
  retained; any widening raises). `HumanApproval.external_ref` and
  `ExternalEvidenceRef` tie approvals and evidence that originated in an
  external system (AiSOC approval id, AiSOC bundle `payload_sha256` and which
  integrity fields were re-derived) into the signed chain, so the external
  system's HMAC tamper-evidence is upgraded to a witnessed commitment.

## 5. Scenarios and ablations (§XI-A) — `aisoc/scenarios.py`

| Scenario | Control exercised |
|---|---|
| injection drives a compromised agent | task scope, forbidden actions, tenant check, egress precision |
| cross-tenant target | policy tenant binding |
| replay | idempotency (same key) and single-use nonce / binding (new key) |
| expired / revoked | PEP expiry and revocation list |
| parameter change after approval | params_digest / request_digest binding |
| ledger tamper & truncation | hash chain + witnessed Merkle root |
| bypass | tool-side reconciliation |
| Slips `Description` as prompt injection | untrusted excerpt + injection flags; structured request boundary |
| Slips anomaly-only / weak-indicator-only windows | `decide_external` ⇒ `SUSPECTED_UNKNOWN` / `UNKNOWN`, human review, no agent action |
| AiSOC approval inbox (approve / deny / undecided / wrong record) | bridge signs every outcome; mismatched `request_digest` ⇒ reject |
| AiSOC bundle anchored | HMAC re-derivation + `ExternalEvidenceRef` digest in ledger |
| egress proxy fail-closed | record-then-forward; audit down / oversize / rate limit ⇒ nothing leaves A |
| signed model release gate | hash + role-bound signature before load; `model_release` ledger entry |
| grant attenuation | narrow-only derivation for sub-tasks |
| ablations | removing nonce ⇒ replay succeeds; removing PEP approval check ⇒ signer still refuses; removing witness ⇒ `UNKNOWN`/`DEFERRED`; egress fail-open ⇒ requests leave A but the verifier reports `FAILED` |

## 6. What this implementation does **not** show

* No public dataset, no LLM. Detection numbers in `report.json` are
  properties of synthetic generators; with Slips as detector the detection
  quality is Slips', not this project's.
* Keys are in memory; "HSM" is an interface, not hardware.
* One process; domain separation is organisational and must be verified by
  checking admin identities and reachable paths (§IV-B).
* The injection screen is heuristic; the NonceStore is single-replica.
* AiSOC is exercised through a fake server derived from its OpenAPI
  description; approvals made in AiSOC are signed by the bridge key, so
  non-repudiation of *which analyst* decided still rests on AiSOC's own audit
  log (see `INTEGRATION.md` §2.3).
* Nothing here is a formal proof, a certification or a zero-day guarantee.
