use sha2::{Digest, Sha256};
use std::{fs::File, io, path::Path};

pub fn sha256_bytes(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

pub fn file_sha256(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}
