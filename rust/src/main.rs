use ed25519_dalek::SigningKey;
use owp_rust::{
    canonical::{canonical_bytes, digest_payload, read_payload, MAX_PAYLOAD_BYTES},
    digest::file_sha256,
    signing::{
        decode_public_key, sign_authority_checkpoint, sign_payload,
        verify_authority_checkpoint, verify_payload,
    },
};
use serde_json::{json, Value};
use std::{
    env,
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read, Write},
    path::Path,
    process::ExitCode,
};
use zeroize::Zeroizing;

fn version_and_domain<'a>(
    version: &'a OsStr,
    domain: &'a OsStr,
) -> Result<(&'a str, &'a str), String> {
    Ok((
        version.to_str().ok_or("version must be UTF-8")?,
        domain.to_str().ok_or("domain must be UTF-8")?,
    ))
}

fn read_signing_key(path: &Path) -> Result<SigningKey, String> {
    let mut raw = Zeroizing::new([0; 32]);
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    file.read_exact(&mut *raw)
        .map_err(|_| "signing key must be a 32-byte seed")?;
    if file.read(&mut [0]).map_err(|e| e.to_string())? != 0 {
        return Err("signing key must be a 32-byte seed".into());
    }
    Ok(SigningKey::from_bytes(&raw))
}

fn write_signed(payload: Value) -> Result<(), String> {
    let json = payload.to_string();
    if json.len() as u64 >= MAX_PAYLOAD_BYTES {
        return Err("signed payload including its trailing newline exceeds 8 MiB".into());
    }
    println!("{json}");
    Ok(())
}

fn write_validity(valid: bool) -> ExitCode {
    println!("{}", json!({ "valid": valid }));
    if valid { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

fn run(args: &[OsString]) -> Result<ExitCode, String> {
    match args {
        [command] if command == "mcp" => owp_rust::mcp::serve()?,
        [command, path] if command == "hash-file" => {
            let path = Path::new(path);
            let digest = file_sha256(path)
                .map_err(|e| format!("cannot hash {}: {e}", path.display()))?;
            println!("{digest}");
        }
        [command, version, domain] if command == "canonicalize" || command == "digest" => {
            let (version, domain) = version_and_domain(version, domain)?;
            let payload = read_payload(io::stdin().lock(), true)?;
            if command == "canonicalize" {
                let bytes = canonical_bytes(version, domain, &payload)?;
                io::stdout().lock().write_all(&bytes).map_err(|e| e.to_string())?;
            } else {
                let (digest, canonical_length) = digest_payload(version, domain, &payload)?;
                println!("{}", json!({ "digest": digest, "canonical_length": canonical_length }));
            }
        }
        [command, version, domain, path] if command == "sign" => {
            let (version, domain) = version_and_domain(version, domain)?;
            let payload = read_payload(io::stdin().lock(), true)?;
            let key = read_signing_key(Path::new(path))?;
            write_signed(sign_payload(version, domain, payload, &key)?)?;
        }
        [command, version, domain, public_key] if command == "verify" => {
            let (version, domain) = version_and_domain(version, domain)?;
            let payload = read_payload(io::stdin().lock(), false)?;
            let valid = public_key.to_str().and_then(decode_public_key)
                .is_some_and(|key| verify_payload(version, domain, &payload, &key));
            return Ok(write_validity(valid));
        }
        [command, path] if command == "sign-checkpoint" => {
            let payload = read_payload(io::stdin().lock(), true)?;
            let key = read_signing_key(Path::new(path))?;
            write_signed(sign_authority_checkpoint(payload, &key)?)?;
        }
        [command, public_key] if command == "verify-checkpoint" => {
            let payload = read_payload(io::stdin().lock(), false)?;
            let valid = public_key.to_str().and_then(decode_public_key)
                .is_some_and(|key| verify_authority_checkpoint(&payload, &key));
            return Ok(write_validity(valid));
        }
        _ => return Err(concat!(
            "usage: owp-rust hash-file PATH | canonicalize VERSION DOMAIN | ",
            "digest VERSION DOMAIN | sign VERSION DOMAIN KEY_FILE | verify VERSION DOMAIN PUBLIC_KEY | ",
            "sign-checkpoint KEY_FILE | verify-checkpoint PUBLIC_KEY | mcp"
        ).into()),
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
