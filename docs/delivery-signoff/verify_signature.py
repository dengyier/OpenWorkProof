"""Verify a delivery sign-off signature record against the frozen SHA256SUMS.

Usage:
    python verify_signature.py --role owner \
        [--signature docs/delivery-signoff/owner.signature] \
        [--public-key-hex <32-byte-hex>] \
        [--manifest docs/delivery-signoff/SHA256SUMS]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[2]


def decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", required=True, choices=("owner", "witness"))
    parser.add_argument(
        "--signature",
        default=str(ROOT / "docs/delivery-signoff/{role}.signature"),
    )
    parser.add_argument("--public-key-hex", required=True)
    parser.add_argument(
        "--manifest",
        default=str(ROOT / "docs/delivery-signoff/SHA256SUMS"),
    )
    args = parser.parse_args()
    signature_path = Path(args.signature.format(role=args.role))
    manifest = Path(args.manifest)

    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(args.public_key_hex))
    expected_key_id = f"ed25519:{hashlib.sha256(public_key.public_bytes_raw()).hexdigest()}"

    if not signature_path.is_file():
        print(f"missing signature: {signature_path}", file=sys.stderr)
        return 1
    if not manifest.is_file():
        print(f"missing manifest: {manifest}", file=sys.stderr)
        return 1

    fields: dict[str, str] = {}
    for line in signature_path.read_text(encoding="utf-8").splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()

    if fields.get("role") != args.role:
        print(f"role mismatch: record says {fields.get('role')!r}", file=sys.stderr)
        return 1
    if fields.get("key_id") != expected_key_id:
        print("key_id mismatch", file=sys.stderr)
        return 1
    if fields.get("signature_alg") != "Ed25519":
        print("signature alg mismatch", file=sys.stderr)
        return 1

    signature = decode_base64url(fields.get("signature", ""))
    try:
        public_key.verify(signature, manifest.read_bytes())
    except Exception as error:  # noqa: BLE001 - verification failure
        print(f"signature invalid: {error}", file=sys.stderr)
        return 1
    print(f"OK: {args.role} signature verified against {manifest.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
