"""Sign the frozen SHA256SUMS anchor with an Ed25519 private key.

Produces a plain-text signature record (Ed25519 over the exact SHA256SUMS
bytes, base64url encoded) plus the signer key id and a UTC timestamp.

Usage:
    python sign_manifest.py --role owner --key-hex <32-byte-hex> \
        [--manifest docs/delivery-signoff/SHA256SUMS] \
        [--output docs/delivery-signoff/owner.signature]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]


def load_private_key(key_hex: str) -> Ed25519PrivateKey:
    raw = bytes.fromhex(key_hex)
    if len(raw) != 32:
        raise ValueError("key must be 32 raw bytes (64 hex chars)")
    return Ed25519PrivateKey.from_private_bytes(raw)


def encode_base64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", required=True, choices=("owner", "witness"))
    parser.add_argument("--key-hex", required=True, help="32-byte Ed25519 private key hex")
    parser.add_argument(
        "--manifest",
        default=str(ROOT / "docs/delivery-signoff/SHA256SUMS"),
    )
    parser.add_argument(
        "--output",
        default=str(ROOT / "docs/delivery-signoff/{role}.signature"),
    )
    args = parser.parse_args()
    manifest = Path(args.manifest)
    if not manifest.is_file():
        raise SystemExit(f"missing manifest: {manifest}")

    key = load_private_key(args.key_hex)
    public_key = key.public_key()
    key_id = f"ed25519:{hashlib.sha256(public_key.public_bytes_raw()).hexdigest()}"

    payload = manifest.read_bytes()
    signature = encode_base64url(key.sign(payload))
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    record = (
        f"role: {args.role}\n"
        f"manifest: {manifest.relative_to(ROOT)}\n"
        f"signed_at: {now}\n"
        f"key_id: {key_id}\n"
        f"signature_alg: Ed25519\n"
        f"signature: {signature}\n"
    )

    output = Path(args.output.format(role=args.role))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(record, encoding="utf-8")
    try:
        display = output.relative_to(ROOT)
    except ValueError:
        display = output
    print(f"wrote {display}")
    print(f"key_id: {key_id}")


if __name__ == "__main__":
    main()
