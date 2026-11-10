use serde::Deserialize;
use serde_json::Value;

use crate::digest::sha256_bytes;

const REGISTRY_SCHEMA_VERSION: &str = "openworkproof-schema-registry/0.1";
const RESOURCE_SET_ERROR: &str = "authoritative schema resource set is invalid";
const ANCHOR_ERROR: &str = "authoritative schema anchor mismatch";

struct EmbeddedRegistry {
    manifest: &'static [u8],
    anchor: &'static str,
    schemas: &'static [(&'static str, &'static [u8])],
}

macro_rules! registry {
    ($version:literal, $anchor:literal, [$($object_type:literal),+ $(,)?]) => {
        EmbeddedRegistry {
            manifest: include_bytes!(concat!(
                "../../src/openworkproof/schemas/v", $version, "/schema-registry.json",
            )),
            anchor: $anchor,
            schemas: &[$((
                $object_type,
                include_bytes!(concat!(
                    "../../src/openworkproof/schemas/v", $version, "/", $object_type, ".schema.json",
                )),
            )),+],
        }
    };
}

// The registry hashes are the frozen anchors from the Python implementation.
// Authenticating a registry pins both its resource inventory and each exact schema.
const V01: EmbeddedRegistry = registry!(
    "0.1",
    "b543abb2d972a84d3fffe97e6f9381f33b5cfe40fe0c8c7c046f91354f849000",
    [
        "acceptance-receipt",
        "acceptance-rejection-receipt",
        "action-receipt",
        "capability-grant",
        "work-order",
    ]
);
const V02: EmbeddedRegistry = registry!(
    "0.2",
    "ba555173e56743920b136b131505489f0e8765ea21433c96db7dcc3c354141ae",
    [
        "acceptance-transition",
        "commitment-anchor",
        "policy-anchor",
        "subject-claim",
        "verification-arm-result",
        "verification-decision",
        "verification-profile",
    ]
);
const V03: EmbeddedRegistry = registry!(
    "0.3",
    "e934f2295ae36901b9d8430d184549eb367dca4cecd86f30ed625502f072e1b1",
    [
        "evaluation-scope",
        "verification-arm-result",
        "verification-decision",
        "verification-profile",
    ]
);
const V04: EmbeddedRegistry = registry!(
    "0.4",
    "66dea3711f1aa0f725b84f96b042e3b34e17713ace2f1e497df9628a2830d88d",
    [
        "action-binding-manifest",
        "action-receipt",
        "authority-checkpoint",
        "binding-decision",
        "judgment-commitment",
    ]
);
const V05: EmbeddedRegistry = registry!(
    "0.5",
    "bc3e702340b538529b2d5faff5227991e05c08643d5ebc7af5a5a059c85049e8",
    [
        "verification-arm-result",
        "verification-decision",
        "verification-profile",
    ]
);

#[derive(Deserialize)]
struct Manifest {
    protocol_version: String,
    schema_version: String,
    schemas: Vec<ManifestEntry>,
}

#[derive(Deserialize)]
struct ManifestEntry {
    object_type: String,
    path: String,
    sha256: String,
}

fn lookup(object_type: &str, version: &str) -> Result<(&'static [u8], String), String> {
    let registry = match version {
        "0.1" => &V01,
        "0.2" => &V02,
        "0.3" => &V03,
        "0.4" => &V04,
        "0.5" => &V05,
        _ => return Err(format!("unknown protocol version: {version}")),
    };
    let index = registry
        .schemas
        .iter()
        .position(|(name, _)| *name == object_type)
        .ok_or_else(|| format!("unknown object type: {object_type}"))?;

    if sha256_bytes(registry.manifest) != registry.anchor {
        return Err(ANCHOR_ERROR.into());
    }
    let manifest: Manifest = serde_json::from_slice(registry.manifest)
        .map_err(|_| "authoritative schema registry is not canonical")?;
    if manifest.schema_version != REGISTRY_SCHEMA_VERSION
        || manifest.protocol_version != version
    {
        return Err("authoritative schema registry is not frozen".into());
    }
    if manifest.schemas.len() != registry.schemas.len() {
        return Err(RESOURCE_SET_ERROR.into());
    }
    for (entry, &(name, raw)) in manifest.schemas.iter().zip(registry.schemas) {
        if entry.object_type != name || entry.path != format!("{name}.schema.json") {
            return Err(RESOURCE_SET_ERROR.into());
        }
        if sha256_bytes(raw) != entry.sha256 {
            return Err(ANCHOR_ERROR.into());
        }
    }

    Ok((registry.schemas[index].1, manifest.schemas[index].sha256.clone()))
}

pub fn authoritative_schema(object_type: &str, version: &str) -> Result<Value, String> {
    let (raw, _) = lookup(object_type, version)?;
    let schema: Value =
        serde_json::from_slice(raw).map_err(|_| "authoritative schema is invalid")?;
    if !schema.is_object() {
        return Err("authoritative schema is invalid".into());
    }
    Ok(schema)
}

pub fn authoritative_digest(object_type: &str, version: &str) -> Result<String, String> {
    lookup(object_type, version).map(|(_, digest)| digest)
}
