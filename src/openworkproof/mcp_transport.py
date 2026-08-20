"""MCP (Model Context Protocol) server for OpenWorkProof.

Exposes the protocol's verification and signing primitives as MCP tools
over stdio.  The server is organised in three layers:

**Standalone verification tools** (no ledger required):

- ``owp_generate_keypair``       — generate an Ed25519 key pair
- ``owp_compute_key_id``         — derive the key_id from a public key
- ``owp_sign_payload``           — sign a canonical payload
- ``owp_verify_signature``       — verify a signed payload
- ``owp_compute_digest``         — compute the canonical SHA-256 digest
- ``owp_verify_work_order``      — verify WorkOrder identity bindings
- ``owp_verify_nested_claim``    — verify AgentRequest / HumanDecision
- ``owp_list_domains``           — list all canonical domains

**Ledger coordination tools** (require a SQLite ledger path):

- ``owp_status``                 — replay a ledger and return its state
- ``owp_run_tests``              — forward a run-tests execution
- ``owp_repo_read``              — forward a repo-read execution
- ``owp_run_verification``       — prepare or commit one versioned verification step
- ``owp_get_decision``           — prepare a versioned verification decision draft
- ``owp_build_delivery_package`` — export a closed delivery package
- ``owp_verify_surface_bundle``  — replay a surface bundle without writes
- ``owp_render_surface_report``  — return its verified derived report
- ``owp_get_settlement_readiness`` — derive the current readiness snapshot

**Standalone validation tools:**

- ``owp_validate_profile``       — validate a signed verification profile
- ``owp_scope_validate``         — intrinsically validate a v0.3 scope
- ``owp_scope_compare``          — compare a v0.3 scope with an observation

**Utility tools:**

- ``owp_get_schema``             — get an authoritative JSON Schema
- ``owp_get_schema_digest``      — get the frozen digest of a schema
- ``owp_analyze_repo``           — analyse a repository structure

Run with ``python -m openworkproof.mcp_transport`` (stdio server) or
``owp-mcp`` after installation.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any, Literal, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Support both MCP SDK 1.x (FastMCP) and 2.x (MCPServer).
try:
    from mcp.server.mcpserver import MCPServer as _McpServer
except ImportError:  # pragma: no cover — fallback for MCP SDK 1.x
    from mcp.server.fastmcp import FastMCP as _McpServer  # type: ignore[no-redef]

from openworkproof import cli as cli_module
from openworkproof.models import (
    AgentRequest,
    ApprovalHumanDecision,
    HumanDecision,
    TerminationHumanDecision,
    WorkOrder,
)
from openworkproof.schema_registry import (
    authoritative_digest,
    authoritative_schema,
)
from openworkproof.services import OpenWorkProofServices
from openworkproof.signing import (
    ALLOWED_CANONICAL_DOMAINS,
    ALLOWED_SIGNED_DOMAINS,
    canonical_bytes,
    digest_payload,
    key_id,
    sign_payload,
    verify_nested_claim,
    verify_payload,
    verify_work_order_identity_bindings,
)
from openworkproof.verification import (
    VerificationCommittedError,
    VerificationCommitIndeterminateError,
)

mcp = _McpServer("openworkproof")

_SCHEMA = "openworkproof/mcp/0.2"
_MAX_PAYLOAD_BYTES = 8 * 1024 * 1024


# ── helpers ──────────────────────────────────────────────────────────


def _ok(data: dict[str, Any]) -> dict[str, Any]:
    """Wrap a successful result.

    The MCP ``schema_version`` always wins — any ``schema_version`` key
    inside *data* (e.g. from the CLI transport) is dropped.
    """
    cleaned = {k: v for k, v in data.items() if k != "schema_version"}
    return {"schema_version": _SCHEMA, "ok": True, **cleaned}


def _err(message: str, **extra: Any) -> dict[str, Any]:
    """Wrap an error result."""
    result: dict[str, Any] = {
        "schema_version": _SCHEMA,
        "ok": False,
        "error": message,
    }
    result.update(extra)
    return result


def _json_object(value: str, *, field: str) -> dict[str, Any]:
    """Decode one bounded JSON object for a v0.2 transport call."""
    if len(value.encode("utf-8")) > _MAX_PAYLOAD_BYTES:
        raise ValueError(f"{field} exceeds 8 MiB")
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} is not valid JSON: {error}") from error
    if type(parsed) is not dict:
        raise ValueError(f"{field} must be a JSON object")
    return parsed


def _service_call(callable_, *args: Any) -> dict[str, Any]:
    """Map one application-service call to stable MCP commit semantics."""
    try:
        return _ok(callable_(*args))
    except VerificationCommittedError as error:
        committed = error.committed
        payload = (
            committed.model_dump(mode="json")
            if hasattr(committed, "model_dump")
            else dict(committed)
        )
        return _ok({"commit_status": "committed_after_ack_loss", **payload})
    except VerificationCommitIndeterminateError as error:
        return _err(str(error), commit_status="indeterminate")
    except Exception as error:
        return _err(str(error))


def _decode_public_key(public_key_b64url: str) -> Ed25519PublicKey | None:
    """Decode a base64url-encoded Ed25519 public key."""
    try:
        raw = base64.urlsafe_b64decode(
            public_key_b64url + "=" * (-len(public_key_b64url) % 4)
        )
        if len(raw) != 32:
            return None
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception:
        return None


def _decode_private_key(private_key_hex: str) -> Ed25519PrivateKey | None:
    """Decode a hex-encoded Ed25519 private key."""
    try:
        raw = bytes.fromhex(private_key_hex)
        return Ed25519PrivateKey.from_private_bytes(raw)
    except Exception:
        return None


# ── standalone verification tools ────────────────────────────────────


@mcp.tool()
def owp_generate_keypair() -> dict[str, Any]:
    """Generate a new Ed25519 key pair for signing OpenWorkProof objects.

    Returns the private key as a hex string and the public key as
    base64url, along with the derived ``key_id``.
    """
    try:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        priv_raw = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        pub_raw = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

        pub_b64url = base64.urlsafe_b64encode(pub_raw).decode("ascii").rstrip("=")

        return _ok({
            "private_key_hex": priv_raw.hex(),
            "public_key_b64url": pub_b64url,
            "key_id": key_id(public_key),
        })
    except Exception as exc:
        return _err(f"key generation failed: {exc}")


@mcp.tool()
def owp_compute_key_id(public_key_b64url: str) -> dict[str, Any]:
    """Compute the OpenWorkProof ``key_id`` for a given Ed25519 public key.

    Args:
        public_key_b64url: The raw public key bytes encoded as
            unpadded base64url (43 characters).
    """
    public_key = _decode_public_key(public_key_b64url)
    if public_key is None:
        return _err("invalid Ed25519 public key (expected 32-byte base64url)")
    return _ok({"key_id": key_id(public_key)})


@mcp.tool()
def owp_sign_payload(
    object_type: str,
    payload: str,
    private_key_hex: str,
) -> dict[str, Any]:
    """Sign a canonical OpenWorkProof payload with an Ed25519 private key.

    Args:
        object_type: One of the allowed signed domains (call
            ``owp_list_domains`` to see the list).
        payload: JSON string of the unsigned payload object.
        private_key_hex: The Ed25519 private key as a hex string.

    Returns:
        The signed payload dict with ``signature_alg``, ``signer_key_id``,
        ``digest``, and ``signature`` fields added.
    """
    if object_type not in ALLOWED_SIGNED_DOMAINS:
        return _err(
            f"object_type '{object_type}' is not a signable domain",
            allowed=sorted(ALLOWED_SIGNED_DOMAINS),
        )

    private_key = _decode_private_key(private_key_hex)
    if private_key is None:
        return _err("invalid Ed25519 private key (expected 64-byte hex)")

    try:
        payload_dict = json.loads(payload)
    except (TypeError, ValueError) as exc:
        return _err(f"payload is not valid JSON: {exc}")

    if not isinstance(payload_dict, dict):
        return _err("payload must be a JSON object")

    try:
        signed = sign_payload(object_type, payload_dict, private_key)
        return _ok({"signed_payload": signed})
    except ValueError as exc:
        return _err(f"signing failed: {exc}")


@mcp.tool()
def owp_verify_signature(
    object_type: str,
    signed_payload: str,
    public_key_b64url: str,
) -> dict[str, Any]:
    """Verify an Ed25519 signature on a signed OpenWorkProof payload.

    Args:
        object_type: The canonical domain of the object.
        signed_payload: JSON string of the signed payload (must
            contain ``signature_alg``, ``signer_key_id``, ``digest``,
            and ``signature``).
        public_key_b64url: The signer's public key as base64url.

    Returns:
        ``{"valid": true}`` if the signature is valid, ``{"valid": false}``
        otherwise.
    """
    if object_type not in ALLOWED_SIGNED_DOMAINS:
        return _err(
            f"object_type '{object_type}' is not a signable domain",
            allowed=sorted(ALLOWED_SIGNED_DOMAINS),
        )

    public_key = _decode_public_key(public_key_b64url)
    if public_key is None:
        return _err("invalid Ed25519 public key")

    try:
        signed_dict = json.loads(signed_payload)
    except (TypeError, ValueError) as exc:
        return _err(f"signed_payload is not valid JSON: {exc}")

    if not isinstance(signed_dict, dict):
        return _err("signed_payload must be a JSON object")

    valid = verify_payload(object_type, signed_dict, public_key)
    return _ok({"valid": valid})


@mcp.tool()
def owp_compute_digest(
    object_type: str,
    payload: str,
) -> dict[str, Any]:
    """Compute the canonical SHA-256 digest of an OpenWorkProof payload.

    The digest is computed over the RFC 8785 JCS canonicalisation of
    ``{"domain": "openworkproof/<object_type>/v0.1", "payload": <payload>}``
    (with ``digest`` and ``signature`` fields stripped from the payload
    at the top level).

    Args:
        object_type: One of the allowed canonical domains.
        payload: JSON string of the payload object.
    """
    if object_type not in ALLOWED_CANONICAL_DOMAINS:
        return _err(
            f"object_type '{object_type}' is not a canonical domain",
            allowed=sorted(ALLOWED_CANONICAL_DOMAINS),
        )

    try:
        payload_dict = json.loads(payload)
    except (TypeError, ValueError) as exc:
        return _err(f"payload is not valid JSON: {exc}")

    if not isinstance(payload_dict, dict):
        return _err("payload must be a JSON object")

    try:
        digest = digest_payload(object_type, payload_dict)
        canonical = canonical_bytes(object_type, payload_dict)
        return _ok({
            "digest": digest,
            "canonical_length": len(canonical),
        })
    except ValueError as exc:
        return _err(f"digest computation failed: {exc}")


@mcp.tool()
def owp_verify_work_order(work_order_json: str) -> dict[str, Any]:
    """Verify a WorkOrder's identity bindings and maintainer signature.

    Args:
        work_order_json: JSON string of the WorkOrder object.

    Returns:
        ``{"valid": true}`` if all six key bindings are well-formed,
        distinct, and the maintainer's signature is valid.
    """
    try:
        wo_dict = json.loads(work_order_json)
    except (TypeError, ValueError) as exc:
        return _err(f"work_order_json is not valid JSON: {exc}")

    try:
        work_order = WorkOrder.model_validate(wo_dict)
    except Exception as exc:
        return _err(f"work order validation failed: {exc}")

    valid = verify_work_order_identity_bindings(work_order)
    return _ok({
        "valid": valid,
        "work_order_digest": work_order.digest,
        "issuer_id": work_order.issuer_id,
    })


@mcp.tool()
def owp_verify_nested_claim(
    claim_json: str,
    work_order_json: str,
) -> dict[str, Any]:
    """Verify a nested claim (AgentRequest or HumanDecision) against a WorkOrder.

    This checks that:
    - The WorkOrder identity bindings are valid.
    - The claim's ``work_order_digest`` matches the WorkOrder.
    - The claim's actor is bound to a matching key in the WorkOrder.
    - The claim's Ed25519 signature is valid.

    Args:
        claim_json: JSON string of the AgentRequest or HumanDecision.
        work_order_json: JSON string of the parent WorkOrder.

    Returns:
        ``{"valid": true}`` if the nested claim passes all checks.
    """
    try:
        claim_dict = json.loads(claim_json)
        wo_dict = json.loads(work_order_json)
    except (TypeError, ValueError) as exc:
        return _err(f"JSON parsing failed: {exc}")

    try:
        work_order = WorkOrder.model_validate(wo_dict)
    except Exception as exc:
        return _err(f"work order validation failed: {exc}")

    claim = None
    for cls in (AgentRequest, ApprovalHumanDecision, TerminationHumanDecision):
        try:
            claim = cls.model_validate(claim_dict)
            break
        except Exception:
            continue

    if claim is None:
        return _err(
            "claim_json is not a valid AgentRequest or HumanDecision"
        )

    valid = verify_nested_claim(claim, work_order)
    return _ok({
        "valid": valid,
        "claim_type": type(claim).__name__,
        "actor_id": claim.actor_id,
        "work_order_digest": work_order.digest,
    })


@mcp.tool()
def owp_list_domains() -> dict[str, Any]:
    """List all allowed canonical domains for OpenWorkProof objects.

    Returns:
        A dict with ``canonical_domains`` (all 9) and ``signed_domains``
        (8 — excludes ``sidecar-event`` which cannot be signed).
    """
    return _ok({
        "canonical_domains": sorted(ALLOWED_CANONICAL_DOMAINS),
        "signed_domains": sorted(ALLOWED_SIGNED_DOMAINS),
    })


@mcp.tool()
def owp_validate_profile(profile_json: str) -> dict[str, Any]:
    """Validate a signed Evidence Lifecycle v0.2, v0.3, or v0.5 profile."""
    try:
        payload = _json_object(profile_json, field="profile_json")
    except ValueError as error:
        return _err(str(error))
    return _service_call(OpenWorkProofServices().validate_profile, payload)


@mcp.tool()
def owp_integrity_observation_validate(payload_json: str) -> dict[str, Any]:
    """Assess one v0.5 population observation set against its contracts.

    This read-only tool never signs, commits, accepts, or settles anything.
    Signer authority is reported as ``not_checked``, never as authorized.
    """
    try:
        payload = _json_object(payload_json, field="payload_json")
    except ValueError as error:
        return _err(str(error))
    return _service_call(
        OpenWorkProofServices().validate_population_observation, payload
    )


@mcp.tool()
def owp_control_observation_validate(payload_json: str) -> dict[str, Any]:
    """Assess one v0.5 control observation set against its contracts.

    This read-only tool never signs, commits, accepts, or settles anything.
    Signer authority is reported as ``not_checked``, never as authorized.
    """
    try:
        payload = _json_object(payload_json, field="payload_json")
    except ValueError as error:
        return _err(str(error))
    return _service_call(
        OpenWorkProofServices().validate_control_observation, payload
    )


@mcp.tool()
def owp_scope_validate(scope_json: str) -> dict[str, Any]:
    """Intrinsically validate a v0.3 scope without checking authority.

    This read-only tool does not accept a ledger, private key, or signature
    instruction. Full Manager authority is checked only by the non-MCP commit
    boundary.
    """
    try:
        payload = _json_object(scope_json, field="scope_json")
    except ValueError as error:
        return _err(str(error))
    return _service_call(OpenWorkProofServices().validate_scope, payload)


@mcp.tool()
def owp_scope_compare(
    scope_json: str,
    observed_scope_json: str,
) -> dict[str, Any]:
    """Compare a signed v0.3 scope with one verifier observation."""
    try:
        manifest = _json_object(scope_json, field="scope_json")
        observed = _json_object(
            observed_scope_json, field="observed_scope_json"
        )
    except ValueError as error:
        return _err(str(error))
    return _service_call(
        OpenWorkProofServices().compare_scope,
        manifest,
        observed,
    )


# ── ledger coordination tools ────────────────────────────────────────


@mcp.tool()
def owp_status(ledger: str) -> dict[str, Any]:
    """Replay an OpenWorkProof ledger and return its authoritative state.

    Args:
        ledger: Path to the SQLite ledger file.
    """
    try:
        result = cli_module.cli_status(ledger)
        return _ok(result)
    except cli_module.CliError as error:
        return _err(str(error))


@mcp.tool()
def owp_run_tests(ledger: str, payload: str) -> dict[str, Any]:
    """Forward a run-tests execution to the ledger coordinator.

    Args:
        ledger: Path to the SQLite ledger file.
        payload: JSON string of the run-tests execution payload (must
            include the signed ``AgentRequest`` and typed arguments).
    """
    return _forward(cli_module.cli_run_tests, ledger, payload)


@mcp.tool()
def owp_repo_read(ledger: str, payload: str) -> dict[str, Any]:
    """Forward a repo-read execution to the ledger coordinator.

    Args:
        ledger: Path to the SQLite ledger file.
        payload: JSON string of the repo-read execution payload.
    """
    return _forward(cli_module.cli_repo_read, ledger, payload)


@mcp.tool()
def owp_run_verification(
    ledger: str,
    payload: str,
    operation: str,
) -> dict[str, Any]:
    """Run exactly one explicit v0.2, v0.3, or v0.5 verification operation.

    ``operation`` must be ``commit_arm``, ``prepare_decision``, or
    ``commit_decision``.  The tool never retries an indeterminate commit.
    """
    try:
        parsed = _json_object(payload, field="payload")
    except ValueError as error:
        return _err(str(error))
    service = OpenWorkProofServices()
    if operation == "commit_arm":
        callable_ = service.commit_arm_result
    elif operation == "prepare_decision":
        callable_ = service.prepare_decision
    elif operation == "commit_decision":
        callable_ = service.commit_decision
    else:
        return _err(
            "operation must be commit_arm, prepare_decision, or commit_decision"
        )
    return _service_call(callable_, Path(ledger), parsed)


@mcp.tool()
def owp_get_decision(ledger: str, request_json: str) -> dict[str, Any]:
    """Prepare, but do not sign or commit, a versioned decision draft."""
    try:
        payload = _json_object(request_json, field="request_json")
    except ValueError as error:
        return _err(str(error))
    return _service_call(
        OpenWorkProofServices().prepare_decision,
        Path(ledger),
        payload,
    )


@mcp.tool()
def owp_build_delivery_package(
    ledger: str,
    output: str,
    privacy_view: str,
) -> dict[str, Any]:
    """Export a public, diagnostic, or customer-private delivery package."""
    if privacy_view not in {"public", "diagnostic", "customer_private"}:
        return _err(
            "privacy_view must be public, diagnostic, or customer_private"
        )
    return _service_call(
        OpenWorkProofServices().build_delivery,
        Path(ledger),
        Path(output),
        privacy_view,
    )


@mcp.tool()
def owp_verify_surface_bundle(package_path: str) -> dict[str, Any]:
    """Verify and replay one surface bundle without writing or signing."""
    return _service_call(
        OpenWorkProofServices().verify_surface,
        Path(package_path),
    )


@mcp.tool()
def owp_render_surface_report(package_path: str) -> dict[str, Any]:
    """Return the verified derived report, never payment or acceptance."""

    def render(path: Path) -> dict[str, Any]:
        verified = OpenWorkProofServices().verify_surface(path)
        return {
            "report": verified["report"],
            "boundary": "not payment or acceptance",
        }

    return _service_call(render, Path(package_path))


@mcp.tool()
def owp_get_settlement_readiness(ledger: str) -> dict[str, Any]:
    """Derive readiness only; this does not prove payment or settlement."""
    return _service_call(
        OpenWorkProofServices().get_settlement_readiness,
        Path(ledger),
    )


def _forward(forwarder, ledger: str, payload: str) -> dict[str, Any]:
    try:
        parsed = json.loads(payload)
    except (TypeError, ValueError) as error:
        return _err(f"payload is not JSON: {error}")
    if not isinstance(parsed, dict):
        return _err("payload must be an object")
    try:
        result = forwarder(Path(ledger), parsed)
    except cli_module.CliError as error:
        return _err(str(error))
    return _ok(result)


# ── utility tools ────────────────────────────────────────────────────


@mcp.tool()
def owp_get_schema(object_type: str, version: str = "0.1") -> dict[str, Any]:
    """Get the authoritative JSON Schema for an OpenWorkProof object type.

    Args:
        object_type: One of ``work-order``, ``capability-grant``,
            ``action-receipt``, ``acceptance-receipt``,
            ``acceptance-rejection-receipt``.
        version: Schema version (default ``0.1``).
    """
    try:
        schema = authoritative_schema(object_type, version)
        return _ok({"object_type": object_type, "version": version, "schema": schema})
    except Exception as exc:
        return _err(f"schema lookup failed: {exc}")


@mcp.tool()
def owp_get_schema_digest(
    object_type: str,
    version: str = "0.1",
) -> dict[str, Any]:
    """Get the frozen SHA-256 digest of an authoritative JSON Schema.

    This digest is a protocol-review anchor: changing it requires an
    explicit version-bump decision.

    Args:
        object_type: One of the five schema-bearing object types.
        version: Schema version (default ``0.1``).
    """
    try:
        digest = authoritative_digest(object_type, version)
        return _ok({
            "object_type": object_type,
            "version": version,
            "schema_digest": digest,
        })
    except Exception as exc:
        return _err(f"digest lookup failed: {exc}")


@mcp.tool()
def owp_analyze_repo(
    source: str,
    clone_enabled: bool = True,
) -> dict[str, Any]:
    """Analyse a repository's structure: file count, languages, dependencies.

    Args:
        source: Local path or remote Git URL to the repository.
        clone_enabled: If ``True`` and *source* is a URL, clone it to a
            temporary directory first (default ``True``).

    Returns:
        Repository analysis including file entries, language stats,
        line counts, and dependency information.
    """
    try:
        from openworkproof.repo_pipeline import (
            analyze_repository,
            to_dict,
        )

        analysis = analyze_repository(source, clone_enabled=clone_enabled)
        return _ok(to_dict(analysis))
    except Exception as exc:
        return _err(f"repository analysis failed: {exc}")


# ── server entry point ───────────────────────────────────────────────



# ── v0.4 read-only binding interfaces (Task 13) ────────────────────────

_PRIVATE_KEY_FIELD_NAMES = (
    "private_key",
    "private_key_hex",
    "signing_key",
    "secret_key",
    "acceptor_key",
    "verifier_key",
    "acceptor_private",
    "verifier_private",
)


def _reject_private_key_fields(payload: Mapping[str, Any]) -> None:
    """Refuse any Acceptor/Verifier private-key argument. MCP validation is
    read-only and never signs or commits."""

    for key in payload:
        lowered = str(key).lower()
        if any(name in lowered for name in _PRIVATE_KEY_FIELD_NAMES):
            raise ValueError("private key arguments are forbidden")


@mcp.tool()
def owp_validate_judgment_commitment(payload_json: str) -> dict[str, Any]:
    """Validate one signed JudgmentCommitment (read-only, no authority).

    Without a ledger or trusted key context the authority is reported as
    ``not_checked``; this tool never signs and never commits.
    """
    try:
        payload = json.loads(payload_json)
        if not isinstance(payload, dict):
            return _err("payload must be a JSON object")
        _reject_private_key_fields(payload)
        return _ok(
            OpenWorkProofServices().validate_judgment_commitment(payload)
        )
    except Exception as exc:
        return _err(f"judgment validation failed: {exc}")


@mcp.tool()
def owp_validate_action_binding_manifest(payload_json: str) -> dict[str, Any]:
    """Validate one signed ActionBindingManifest (read-only, no authority)."""
    try:
        payload = json.loads(payload_json)
        if not isinstance(payload, dict):
            return _err("payload must be a JSON object")
        _reject_private_key_fields(payload)
        return _ok(
            OpenWorkProofServices().validate_action_binding_manifest(payload)
        )
    except Exception as exc:
        return _err(f"binding manifest validation failed: {exc}")


@mcp.tool()
def owp_get_binding_status(ledger_path: str) -> dict[str, Any]:
    """Read the current binding decision head from a ledger (read-only)."""
    try:
        return _ok(OpenWorkProofServices().binding_history(ledger_path))
    except Exception as exc:
        return _err(f"binding status unavailable: {exc}")


@mcp.tool()
def owp_explain_binding_decision(payload_json: str) -> dict[str, Any]:
    """Verify and explain one BindingDecision (read-only)."""
    try:
        payload = json.loads(payload_json)
        if not isinstance(payload, dict):
            return _err("payload must be a JSON object")
        _reject_private_key_fields(payload)
        result = OpenWorkProofServices().verify_binding(payload)
        decision_payload = payload.get("decision", {})
        return _ok(
            {
                "valid": result["valid"],
                "decision": (
                    decision_payload.get("decision")
                    if isinstance(decision_payload, dict)
                    else None
                ),
                "reason_codes": (
                    decision_payload.get("reason_codes")
                    if isinstance(decision_payload, dict)
                    else None
                ),
            }
        )
    except Exception as exc:
        return _err(f"binding decision explanation failed: {exc}")


def main() -> None:
    """Run the stdio MCP server."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
