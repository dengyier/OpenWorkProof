use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::{
    borrow::Cow,
    fmt,
    io::{self, Read},
};

use crate::digest::sha256_bytes;

const MAX_DEPTH: usize = 128;
const MAX_NODES: usize = 10_000;
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
pub const MAX_PAYLOAD_BYTES: u64 = 8 * 1024 * 1024;

const V01_DOMAINS: &[&str] = &[
    "acceptance-decision-binding", "acceptance-receipt", "acceptance-rejection-receipt",
    "acceptance-transition", "action-receipt", "agency-appeal", "agency-profile-transition",
    "agent-request", "capability-grant", "dsh-observation-record", "handler-agency-binding",
    "human-agency-profile", "human-decision", "manifest", "sidecar-event", "subject-claim",
    "verification-arm-result", "verification-decision", "verification-profile", "work-order",
];
const V03_DOMAINS: &[&str] = &[
    "evaluation-scope", "scope-member", "scope-population", "scope-requirement",
    "verification-arm-result", "verification-decision", "verification-profile",
];
const V04_DOMAINS: &[&str] = &[
    "action-binding-manifest", "action-receipt", "agent-request", "authority-checkpoint",
    "binding-decision", "judgment-commitment",
];
const V05_DOMAINS: &[&str] = &[
    "retraction-receipt", "verification-arm-result", "verification-decision", "verification-profile",
];

pub fn domains(version: &str) -> Result<&'static [&'static str], &'static str> {
    match version {
        "0.1" => Ok(V01_DOMAINS),
        "0.3" => Ok(V03_DOMAINS),
        "0.4" => Ok(V04_DOMAINS),
        "0.5" => Ok(V05_DOMAINS),
        _ => Err("unknown protocol version"),
    }
}

struct JsonAtDepth<'a> {
    depth: usize,
    remaining: &'a mut usize,
    strip_auth: bool,
}

impl<'de> DeserializeSeed<'de> for JsonAtDepth<'_> {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, input: D) -> Result<Value, D::Error> {
        *self.remaining = self.remaining.checked_sub(1)
            .ok_or_else(|| de::Error::custom("JSON payload exceeds node budget"))?;
        input.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for JsonAtDepth<'_> {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value with unique object keys")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(value.into())
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(value.into())
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(value.into())
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("NaN and infinity are forbidden"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(value.into())
    }

    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<Value, A::Error> {
        self.check_depth()?;
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(self.child())? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(mut self, mut input: A) -> Result<Value, A::Error> {
        self.check_depth()?;
        let mut values = Map::new();
        while let Some(key) = input.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("JSON object keys must be unique"));
            }
            let value = if self.strip_auth && matches!(key.as_str(), "digest" | "signature") {
                input.next_value::<de::IgnoredAny>()?;
                Value::Null
            } else {
                input.next_value_seed(self.child())?
            };
            values.insert(key, value);
        }
        if self.strip_auth {
            values.remove("digest");
            values.remove("signature");
        }
        Ok(Value::Object(values))
    }
}

impl JsonAtDepth<'_> {
    fn child(&mut self) -> JsonAtDepth<'_> {
        JsonAtDepth {
            depth: self.depth + 1,
            remaining: self.remaining,
            strip_auth: false,
        }
    }

    fn check_depth<E: de::Error>(&self) -> Result<(), E> {
        if self.depth > MAX_DEPTH {
            return Err(E::custom("JSON payload exceeds maximum depth"));
        }
        Ok(())
    }
}

// Python decodes the integer token -0 as 0. Serde decodes it as a float.
fn normalize_integer_zero(input: &[u8]) -> Cow<'_, [u8]> {
    let mut normalized = Cow::Borrowed(input);
    let mut in_string = false;
    let mut escaped = false;
    for (index, &byte) in input.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else if byte == b'"' {
            in_string = true;
        } else if byte == b'-'
            && (index == 0 || matches!(input[index - 1], b'[' | b':' | b',' | b' ' | b'\t' | b'\r' | b'\n'))
            && input.get(index + 1) == Some(&b'0')
            && input.get(index + 2).is_none_or(|next| {
                matches!(next, b',' | b']' | b'}' | b' ' | b'\t' | b'\r' | b'\n')
            })
        {
            // Replace the sign with whitespace so parser offsets stay stable.
            normalized.to_mut()[index] = b' ';
        }
    }
    normalized
}

pub fn parse_json(input: &[u8], strip_auth: bool) -> Result<Value, String> {
    if input.len() as u64 > MAX_PAYLOAD_BYTES {
        return Err("payload exceeds 8 MiB".into());
    }
    std::str::from_utf8(input).map_err(|e| e.to_string())?;
    let input = normalize_integer_zero(input);
    let mut parser = serde_json::Deserializer::from_slice(&input);
    // The visitor enforces the Python container depth, starting at zero.
    parser.disable_recursion_limit();
    let mut remaining = MAX_NODES;
    let value = JsonAtDepth { depth: 0, remaining: &mut remaining, strip_auth }
        .deserialize(&mut parser)
        .map_err(|e| e.to_string())?;
    parser.end().map_err(|e| e.to_string())?;
    Ok(value)
}

fn safe_integer(value: &Value) -> bool {
    value.as_u64().is_some_and(|number| number <= MAX_SAFE_INTEGER)
}

pub(crate) fn validate_field(key: &str, value: &Value) -> Result<(), String> {
    let constrained = matches!(key,
        "actual_exit_code" | "amount" | "expected_exit_code" | "expected_state_version"
        | "grant_remaining_before" | "max_size_bytes" | "max_validity_seconds" | "ordinal"
        | "patch_size_bytes" | "remaining_after" | "repair_rounds" | "sequence"
        | "size_bytes" | "state_version_before" | "tool_calls"
    );
    let nullable = matches!(key, "actual_exit_code" | "remaining_after") && value.is_null();
    if constrained && !nullable && !safe_integer(value) {
        return Err(format!("{key} must be a safe non-negative integer"));
    }
    Ok(())
}

fn write_value(
    value: &Value, out: &mut Vec<u8>, depth: usize, nodes: &mut usize, unsigned: bool,
) -> Result<(), String> {
    *nodes += 1;
    if *nodes > MAX_NODES {
        return Err("JSON payload exceeds node budget".into());
    }
    if (value.is_array() || value.is_object()) && depth > MAX_DEPTH {
        return Err("JSON payload exceeds maximum depth".into());
    }
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter()
                .filter(|(key, _)| !(unsigned && matches!(key.as_str(), "digest" | "signature")))
                .collect();
            entries.sort_unstable_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push(b'{');
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 { out.push(b','); }
                serde_json::to_writer(&mut *out, key).map_err(|e| e.to_string())?;
                out.push(b':');
                validate_field(key, item)?;
                write_value(item, out, depth + 1, nodes, false)?;
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 { out.push(b','); }
                write_value(item, out, depth + 1, nodes, false)?;
            }
            out.push(b']');
        }
        Value::Number(n) if n.is_f64() => {
            return Err("floating-point JSON numbers are forbidden".into());
        }
        Value::Number(_) if !safe_integer(value) => {
            return Err("JSON integer is outside the safe non-negative range".into());
        }
        _ => serde_json::to_writer(&mut *out, value).map_err(|e| e.to_string())?,
    }
    Ok(())
}

pub(crate) fn validate_signed(payload: &Value) -> Result<(), String> {
    write_value(payload, &mut Vec::new(), 0, &mut 0, false)
}

pub fn canonical_bytes(version: &str, domain: &str, payload: &Value) -> Result<Vec<u8>, String> {
    if !domains(version)?.contains(&domain) {
        return Err("unknown canonical domain".into());
    }
    if !payload.is_object() {
        return Err("signed payload must be a mapping".into());
    }
    let mut out = format!(r#"{{"domain":"openworkproof/{domain}/v{version}","payload":"#).into_bytes();
    write_value(payload, &mut out, 0, &mut 0, true)?;
    out.push(b'}');
    Ok(out)
}

pub fn digest_payload(version: &str, domain: &str, payload: &Value) -> Result<(String, usize), String> {
    let canonical = canonical_bytes(version, domain, payload)?;
    Ok((sha256_bytes(&canonical), canonical.len()))
}

pub fn read_payload(mut input: impl io::Read, strip_auth: bool) -> Result<Value, String> {
    let mut raw = Vec::new();
    input.by_ref().take(MAX_PAYLOAD_BYTES + 1).read_to_end(&mut raw).map_err(|e| e.to_string())?;
    parse_json(&raw, strip_auth)
}
