# Human Agency Profile v0.1

> Engineering protocol note for `openworkproof-human-agency-profile/0.1`.
> This is a verifiable authorization boundary, not a policy engine, an Agent OS,
> or a compliance report.

## Why

A WorkOrder freezes the target, scope, tools, and acceptance criteria of one
job. A CapabilityGrant expresses what capability the system issued. Neither says
which of those capabilities the human is currently willing to let the Agent use
autonomously, and which decisions stay reserved for a human. The Human Agency
Profile v0.1 fills that gap as a **sibling profile signed by the WorkOrder
Acceptor**, without modifying the frozen WorkOrder or CapabilityGrant.

Effective permission is always the intersection:

```text
WorkOrder ∩ CapabilityGrant ∩ active Human Agency Profile
```

Any one of the three layers denying means the call is denied (fail closed). The
profile can only narrow — it can never grant a tool that the WorkOrder or the
Grant does not already allow.

## The three objects

All three objects are closed, immutable, signed protocol objects. Their ids,
digests, and signatures are content-derived over RFC 8785 JCS canonical bytes.

- `HumanAgencyProfileV01` — declares `delegated_actions` (what the Agent may do
  autonomously) and `reserved_decisions` (what stays with a human), plus
  escalation conditions and a fixed revocation/appeal policy.
- `AgencyProfileTransitionV01` — an Acceptor-signed append-only transition that
  `revoked` or `superseded` a target profile. The original profile is never
  modified.
- `AgencyAppealV01` — a signed request by a Manager, Developer, or Verifier for
  human review of a profile.

## Roles and signature authority

- **Acceptor** is the only signer that can create, revoke, or replace an agency
  profile. Profiles and transitions must match the WorkOrder's unique Acceptor
  key binding exactly.
- **Manager / Developer / Verifier** may sign appeals, but an appeal never
  changes the active profile.
- The WorkOrder's `key_bindings` are the sole source of verification public keys.

## State, revoke, replace, appeal

The active profile is resolved deterministically from the signed history graph —
never from a timestamp "latest" rule:

- one unsigned genesis profile → `active`;
- a `superseded` edge → follow the replacement chain to the unique terminal;
- a `revoked` edge → terminal with no active profile;
- fork, cycle, missing replacement, digest mismatch, time reversal, multiple
  genesis → `AGENCY_PROFILE_HISTORY_INVALID` (fail closed);
- expired profile → `AGENCY_PROFILE_EXPIRED`.

An appeal only records a request — it never restores or expands permission.
Only an Acceptor-signed transition/profile can revoke or replace the grant.

## Authorization ordering

The base authorization runs first: bad WorkOrder/Grant, bad request signature,
freshness, or quota errors always win over agency-specific errors. Only after
the base policy allows does the agency layer run, inside the same target lock as
the executor. There is no lock-free "check profile then call executor" wrapper;
a lazy zero-argument callback loads the full profile history inside the held
lock so a concurrent revoke cannot race the execution (TOCTOU).

## Protected dispatcher

`dispatch_protected_agent_action` routes a signed `AgentRequest` by its
`tool_name` to one of four protected executors and passes each a lazy agency
callback:

- `owp.repo_read`
- `owp.apply_patch`
- `owp.run_tests`
- `owp.rollback_patch`

Unknown tools and malformed bundles fail closed. A reserved tool returns
`AGENCY_HUMAN_DECISION_REQUIRED`; a tool that is neither delegated nor reserved
returns `AGENCY_ACTION_NOT_DELEGATED`; a revoked/absent profile returns
`AGENCY_PROFILE_REQUIRED`. The legacy executors keep their default semantics
(`agency_authorize=None`).

## Offline bundle

`agency_bundle.py` exports a minimal, key-free offline bundle whose layout is
exactly `agency-manifest.json`, `agency/work-order.json`,
`agency/profiles/<id>.json`, `agency/transitions/<id>.json`, and
`agency/appeals/<id>.json`. The manifest is a Sidecar-signed snapshot
attestation of a single `evaluated_at` UTC second.

The bundle is a historical snapshot of the authorization boundary at signing
time. It is not a TSA proof and not a current-state proof: an older but validly
signed bundle can still be replayed. Consumers must apply their own freshness
policy to the manifest `evaluated_at` before relying on it.

## JSON Schema vs semantic validation

The packaged JSON Schema (in `schemas/agency-v0.1/`) is only a structural gate:
shapes, enum literals, length patterns, and the uniqueness that JSON Schema can
express. It does not express the semantic facts that the OWP verifier still
enforces:

- content-derived ids and digests (profile_id, transition_id, appeal_id, and
  nested action/decision ids);
- exact WorkOrder binding (work_order_digest and Acceptor key);
- Ed25519 signature verification over canonical bytes;
- causal/time ordering and the deterministic current-profile graph resolution.

Do not treat "passes JSON Schema validation" as "the object is authentic or
current".

## threat model

- A profile can only narrow the WorkOrder/Grant; it cannot expand authority.
- Reserved decisions are enforced before the handler runs (zero handler calls,
  zero business writes on a denied brand-new action).
- History is append-only and immutable; forks, cycles, missing replacements, and
  time reversals all fail closed.
- The offline verifier trusts only the manifest and file bytes, never the
  ledger, network, environment keys, or the system clock.

## Minimal API example

```python
from openworkproof.agency import (
    HumanAgencyProfileV01,
    verify_human_agency_profile,
    resolve_current_human_agency_profile,
)
from openworkproof.models import WorkOrder
from openworkproof.signing import sign_payload

# work_order: a signed WorkOrder with a unique Acceptor key binding
# profile_payload: delegated_actions = (owp.repo_read,),
#                  reserved_decisions = (owp.apply_patch,) ...
profile = HumanAgencyProfileV01.model_validate(
    sign_payload("human-agency-profile", profile_payload, acceptor_private_key)
)
assert verify_human_agency_profile(profile, work_order)
resolved = resolve_current_human_agency_profile(
    work_order, (profile,), (), now=transaction_time
)
```

A complete, self-contained in-process example is
[`examples/human_agency_profile_v01.py`](../../examples/human_agency_profile_v01.py).

## Honest boundaries (not done / not claimed)

This slice is a protocol capability. It is not employee scoring, performance monitoring, legal-liability transfer, automatic accountability, fund custody, or compliance certification. It does not prove that any real customer adopted or
paid for anything, or that any upstream project adopted this work; those facts
remain `not_evidenced`. The Acceptor signature is a protocol authorization, not
legal consent or an audit conclusion.
