use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::Value;

use crate::{
    canonical::{canonical_bytes, domains, validate_signed},
    digest::sha256_bytes,
};

pub fn is_signable(version: &str, domain: &str) -> bool {
    if !domains(version).is_ok_and(|allowed| allowed.contains(&domain)) {
        return false;
    }
    match version {
        "0.1" => !matches!(domain, "sidecar-event" | "verification-decision"),
        "0.3" => matches!(
            domain,
            "evaluation-scope" | "verification-profile" | "verification-arm-result"
        ),
        "0.4" => domain != "authority-checkpoint",
        "0.5" => domain != "verification-decision",
        _ => false,
    }
}

pub fn key_id(raw: &[u8; 32]) -> String {
    format!("ed25519:{}", sha256_bytes(raw))
}

fn decode_base64url<const LENGTH: usize>(value: &str) -> Option<[u8; LENGTH]> {
    if value.len() != (LENGTH * 8).div_ceil(6) {
        return None;
    }
    let raw: [u8; LENGTH] = URL_SAFE_NO_PAD.decode(value).ok()?.try_into().ok()?;
    (URL_SAFE_NO_PAD.encode(raw) == value).then_some(raw)
}

pub fn decode_public_key(value: &str) -> Option<VerifyingKey> {
    VerifyingKey::from_bytes(&decode_base64url(value)?).ok()
}

pub fn sign_payload(
    version: &str,
    domain: &str,
    payload: Value,
    key: &SigningKey,
) -> Result<Value, String> {
    if !is_signable(version, domain) {
        return Err("object type cannot be signed".into());
    }
    sign_envelope(version, domain, payload, key, "signer_key_id")
}

pub fn sign_authority_checkpoint(payload: Value, key: &SigningKey) -> Result<Value, String> {
    if payload.get("signer_key_id").is_some() {
        return Err("authority checkpoint must use authority_key_id".into());
    }
    let expected = key_id(key.verifying_key().as_bytes());
    if payload.get("authority_key_id").is_some_and(|value| {
        !value.is_null() && value.as_str() != Some(&expected)
    }) {
        return Err("authority_key_id does not match private key".into());
    }
    sign_envelope("0.4", "authority-checkpoint", payload, key, "authority_key_id")
}

fn sign_envelope(
    version: &str,
    domain: &str,
    mut payload: Value,
    key: &SigningKey,
    key_field: &str,
) -> Result<Value, String> {
    // Validate supplied fields before replacing signing metadata.
    canonical_bytes(version, domain, &payload)?;
    let fields = payload.as_object_mut().ok_or("signed payload must be a mapping")?;
    fields.remove("digest");
    fields.remove("signature");
    fields.insert("signature_alg".into(), "Ed25519".into());
    fields.insert(key_field.into(), key_id(key.verifying_key().as_bytes()).into());

    let message = canonical_bytes(version, domain, &payload)?;
    let digest = sha256_bytes(&message);
    let signature = URL_SAFE_NO_PAD.encode(key.sign(&message).to_bytes());

    let fields = payload.as_object_mut().ok_or("signed payload must be a mapping")?;
    fields.insert("digest".into(), digest.into());
    fields.insert("signature".into(), signature.into());
    validate_signed(&payload)?;
    Ok(payload)
}

pub fn verify_payload(version: &str, domain: &str, payload: &Value, key: &VerifyingKey) -> bool {
    is_signable(version, domain) && verify_envelope(version, domain, payload, key, "signer_key_id")
}

pub fn verify_authority_checkpoint(payload: &Value, key: &VerifyingKey) -> bool {
    payload.get("signer_key_id").is_none()
        && verify_envelope("0.4", "authority-checkpoint", payload, key, "authority_key_id")
}

fn verify_envelope(
    version: &str,
    domain: &str,
    payload: &Value,
    key: &VerifyingKey,
    key_field: &str,
) -> bool {
    if payload.get("signature_alg").and_then(Value::as_str) != Some("Ed25519")
        || payload.get(key_field).and_then(Value::as_str) != Some(&key_id(key.as_bytes()))
        || validate_signed(payload).is_err()
    {
        return false;
    }
    let Ok(message) = canonical_bytes(version, domain, payload) else {
        return false;
    };
    if payload.get("digest").and_then(Value::as_str) != Some(&sha256_bytes(&message)) {
        return false;
    }
    let Some(raw) = payload
        .get("signature")
        .and_then(Value::as_str)
        .and_then(decode_base64url::<64>)
    else {
        return false;
    };
    key.verify_strict(&message, &Signature::from_bytes(&raw)).is_ok()
}
