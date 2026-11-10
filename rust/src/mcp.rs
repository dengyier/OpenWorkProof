use std::future::ready;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use futures::StreamExt;
use rmcp::{
    handler::server::wrapper::Parameters,
    model::CallToolResult,
    schemars::{self, JsonSchema},
    service::{RxJsonRpcMessage, TxJsonRpcMessage},
    transport::async_rw::JsonRpcMessageCodec,
    RoleServer,
    tool, tool_handler, tool_router, ServerHandler, ServiceExt,
};
use serde::Deserialize;
use serde_json::json;
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::{
    canonical::{digest_payload, domains, parse_json, MAX_PAYLOAD_BYTES},
    schema::{authoritative_digest, authoritative_schema},
    signing::{decode_public_key, is_signable, key_id, verify_payload},
};

const VERSION: &str = "0.1";
const SCHEMA: &str = "openworkproof/mcp/0.2";
// Permit JSON escaping of the bounded inner payload plus the request envelope.
const MAX_WIRE_BYTES: usize = 6 * MAX_PAYLOAD_BYTES as usize + 4096;

#[derive(Deserialize, JsonSchema)]
struct DigestArguments {
    object_type: String,
    payload: String,
}

#[derive(Deserialize, JsonSchema)]
struct VerifyArguments {
    object_type: String,
    signed_payload: String,
    public_key_b64url: String,
}

#[derive(Deserialize, JsonSchema)]
struct KeyIdArguments {
    public_key_b64url: String,
}

#[derive(Deserialize, JsonSchema)]
struct SchemaArguments {
    object_type: String,
    #[serde(default = "default_schema_version")]
    version: String,
}

fn default_schema_version() -> String {
    VERSION.to_owned()
}

struct OpenWorkProofServer;

fn tool_error(error: impl AsRef<str>) -> CallToolResult {
    CallToolResult::structured(json!({
        "schema_version": SCHEMA,
        "ok": false,
        "error": error.as_ref(),
    }))
}

fn catalog_domains() -> Vec<&'static str> {
    // The legacy MCP catalog includes the v0.3 scope domains. Digest and
    // signature tools still operate on v0.1 only.
    let mut names: Vec<_> = domains(VERSION)
        .expect("v0.1 canonical domains exist")
        .iter()
        .chain(domains("0.3").expect("v0.3 canonical domains exist"))
        .copied()
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

fn unpadded_public_key(encoded: &str) -> Option<&str> {
    match encoded.len() {
        43 => Some(encoded),
        44 => encoded.strip_suffix('='),
        _ => None,
    }
}

#[tool_router]
impl OpenWorkProofServer {
    #[tool(description = "Get the authoritative JSON Schema for an OpenWorkProof object type.")]
    fn owp_get_schema(&self, Parameters(args): Parameters<SchemaArguments>) -> CallToolResult {
        match authoritative_schema(&args.object_type, &args.version) {
            Ok(schema) => CallToolResult::structured(json!({
                "schema_version": SCHEMA,
                "ok": true,
                "object_type": args.object_type,
                "version": args.version,
                "schema": schema,
            })),
            Err(error) => tool_error(format!("schema lookup failed: {error}")),
        }
    }

    #[tool(description = "Get the frozen SHA-256 digest of an authoritative OpenWorkProof JSON Schema.")]
    fn owp_get_schema_digest(
        &self,
        Parameters(args): Parameters<SchemaArguments>,
    ) -> CallToolResult {
        match authoritative_digest(&args.object_type, &args.version) {
            Ok(digest) => CallToolResult::structured(json!({
                "schema_version": SCHEMA,
                "ok": true,
                "object_type": args.object_type,
                "version": args.version,
                "schema_digest": digest,
            })),
            Err(error) => tool_error(format!("digest lookup failed: {error}")),
        }
    }

    #[tool(description = "Compute the OpenWorkProof key ID of a base64url Ed25519 public key.")]
    fn owp_compute_key_id(&self, Parameters(args): Parameters<KeyIdArguments>) -> CallToolResult {
        let raw: Option<[u8; 32]> = unpadded_public_key(&args.public_key_b64url)
            .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded).ok())
            .and_then(|bytes| bytes.try_into().ok());
        let Some(raw) = raw else {
            return tool_error("invalid Ed25519 public key (expected 32-byte base64url)");
        };
        CallToolResult::structured(json!({
            "schema_version": SCHEMA,
            "ok": true,
            "key_id": key_id(&raw),
        }))
    }

    #[tool(description = "List canonical and signed OpenWorkProof domains.")]
    fn owp_list_domains(&self) -> CallToolResult {
        let canonical = catalog_domains();
        let signed: Vec<_> = canonical
            .iter()
            .copied()
            .filter(|domain| is_signable(VERSION, domain))
            .collect();
        CallToolResult::structured(json!({
            "schema_version": SCHEMA,
            "ok": true,
            "canonical_domains": canonical,
            "signed_domains": signed,
        }))
    }

    #[tool(description = "Compute the canonical SHA-256 digest of an OpenWorkProof v0.1 payload.")]
    fn owp_compute_digest(
        &self,
        Parameters(args): Parameters<DigestArguments>,
    ) -> CallToolResult {
        let allowed = domains(VERSION).expect("v0.1 canonical domains exist");
        if !allowed.contains(&args.object_type.as_str()) {
            let catalog = catalog_domains();
            if !catalog.contains(&args.object_type.as_str()) {
                return CallToolResult::structured(json!({
                    "schema_version": SCHEMA,
                    "ok": false,
                    "error": format!("object_type '{}' is not a canonical domain", args.object_type),
                    "allowed": catalog,
                }));
            }
        }
        let payload = match parse_json(args.payload.as_bytes(), true) {
            Ok(value) if value.is_object() => value,
            Ok(_) => return tool_error("payload must be a JSON object"),
            Err(error) => return tool_error(format!("payload is not valid JSON: {error}")),
        };
        match digest_payload(VERSION, &args.object_type, &payload) {
            Ok((digest, canonical_length)) => CallToolResult::structured(json!({
                "schema_version": SCHEMA,
                "ok": true,
                "digest": digest,
                "canonical_length": canonical_length,
            })),
            Err(error) => tool_error(format!("digest computation failed: {error}")),
        }
    }

    #[tool(description = "Verify an Ed25519 signature on an OpenWorkProof v0.1 payload.")]
    fn owp_verify_signature(
        &self,
        Parameters(args): Parameters<VerifyArguments>,
    ) -> CallToolResult {
        if !is_signable(VERSION, &args.object_type) {
            let allowed: Vec<_> = domains(VERSION)
                .expect("v0.1 canonical domains exist")
                .iter()
                .copied()
                .filter(|domain| is_signable(VERSION, domain))
                .collect();
            return CallToolResult::structured(json!({
                "schema_version": SCHEMA,
                "ok": false,
                "error": format!("object_type '{}' is not a signable domain", args.object_type),
                "allowed": allowed,
            }));
        }
        // A 32-byte URL-safe key may use one padding character.
        let Some(public_key) = unpadded_public_key(&args.public_key_b64url).and_then(decode_public_key)
        else {
            return tool_error("invalid Ed25519 public key");
        };
        let payload = match parse_json(args.signed_payload.as_bytes(), false) {
            Ok(value) if value.is_object() => value,
            Ok(_) => return tool_error("signed_payload must be a JSON object"),
            Err(error) => return tool_error(format!("signed_payload is not valid JSON: {error}")),
        };
        CallToolResult::structured(json!({
            "schema_version": SCHEMA,
            "ok": true,
            "valid": verify_payload(VERSION, &args.object_type, &payload, &public_key),
        }))
    }
}

#[tool_handler(name = "openworkproof-rust")]
impl ServerHandler for OpenWorkProofServer {}

pub fn serve() -> Result<(), String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?
        .block_on(async {
            let (stdin, stdout) = rmcp::transport::stdio();
            let incoming = FramedRead::new(
                stdin,
                JsonRpcMessageCodec::<RxJsonRpcMessage<RoleServer>>::new_with_max_length(
                    MAX_WIRE_BYTES,
                ),
            )
            // An invalid transport frame ends the session without echoing the request.
            .scan((), |_, frame| ready(frame.ok()));
            let outgoing = FramedWrite::new(
                stdout,
                JsonRpcMessageCodec::<TxJsonRpcMessage<RoleServer>>::new(),
            );
            let server = OpenWorkProofServer
                .serve((outgoing, Box::pin(incoming)))
                .await
                .map_err(|error| error.to_string())?;
            server.waiting().await.map_err(|error| error.to_string())?;
            Ok(())
        })
}
