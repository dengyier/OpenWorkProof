"""Compare a compiled Rust binary with the checked-out Python implementation."""

from base64 import urlsafe_b64encode
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openworkproof.repo_pipeline.reader import file_sha256, sha256_bytes
from openworkproof.signing import (
    _canonical_domains_for_version, _signed_domains_for_version, canonical_bytes,
    digest_payload, sign_authority_checkpoint, sign_payload, verify_authority_checkpoint,
    verify_payload,
)


def run(binary, *args, data=None):
    return subprocess.run(
        [str(binary), *map(str, args)],
        input=data,
        capture_output=True,
        check=False,
        timeout=10,
    )


def check_digest(binary):
    with TemporaryDirectory(prefix="owp-rust-parity-") as temp:
        directory = Path(temp)
        inputs = {
            "empty": b"",
            "ascii": b"abc",
            "unicode-crlf": "中文\r\n".encode(),
            "binary": bytes(range(256)),
            "multiple-blocks": bytes(range(251)) * 5000,
        }
        for name, content in inputs.items():
            path = directory / name
            path.write_bytes(content)
            expected = file_sha256(path)
            assert expected == sha256_bytes(content), name
            result = run(binary, "hash-file", path)
            assert result.returncode == 0 and not result.stderr, result
            assert result.stdout == (expected + "\n").encode(), (name, result)
            print(f"PASS hash-file {name} ({len(content)} bytes): {expected}")

        for path in (directory / "missing", directory):
            try:
                file_sha256(path)
            except OSError:
                result = run(binary, "hash-file", path)
                assert result.returncode == 1 and not result.stdout and result.stderr
                print(f"PASS hash-file rejects {path.name if not path.exists() else 'directory'}")
            else:
                raise AssertionError(f"Python unexpectedly accepted {path}")


def check_canonical(binary):
    versions = ("0.1", "0.3", "0.4", "0.5")
    for version in versions:
        for domain in sorted(_canonical_domains_for_version(version)):
            payload = {
                "b": 2, "a": 1, "中文": "转义\n\x00\t", "\U00010000": "UTF-16 first",
                "\uE000": "BMP", "data": {"digest": "keep", "signature": "keep"},
                "digest": -1, "signature": 1.5,
                "actual_exit_code": None, "remaining_after": None,
            }
            raw = json.dumps(payload, ensure_ascii=True).encode()
            expected = canonical_bytes(domain, payload, version=version)
            result = run(binary, "canonicalize", version, domain, data=raw)
            assert result.returncode == 0 and result.stdout == expected, (version, domain, result)
            result = run(binary, "digest", version, domain, data=raw)
            assert result.returncode == 0 and json.loads(result.stdout) == {
                "digest": digest_payload(domain, payload, version=version),
                "canonical_length": len(expected),
            }, (version, domain, result)
        print(f"PASS canonical bytes and digest across all v{version} domains")

    for raw in (
        b'{"sequence":9007199254740991}', b'{"value":-0,"text":"-0"}',
        b'{"digest":1e-0,"value":1}',
        b'{"digest":' + b"[" * 180 + b"0" + b"]" * 180 + b',"value":1}',
        b'{"data":' + b"[" * 128 + b"0" + b"]" * 128 + b"}",
        b'{"items":[' + b",".join([b"0"] * 9998) + b"]}",
    ):
        result = run(binary, "canonicalize", "0.1", "manifest", data=raw)
        assert result.returncode == 0, (raw[:80], result.stderr)
        assert result.stdout == canonical_bytes("manifest", json.loads(raw)), raw[:80]
    print("PASS canonical JSON maximum depth, node budget and integer boundaries")

    for raw in (
        b'{"sequence":true}', b'{"size_bytes":"1"}', b'{"tool_calls":null}',
        b'{"value":-1}', b'{"value":1.0}', b'{"value":-0.0}', b'{"value":-0e0}',
        b'{"value":9007199254740992}', b'{"value":1e309}', b"[]",
        b'{"data":' + b"[" * 129 + b"0" + b"]" * 129 + b"}",
        b'{"items":[' + b",".join([b"0"] * 9999) + b"]}",
    ):
        try:
            canonical_bytes("manifest", json.loads(raw))
        except ValueError:
            result = run(binary, "canonicalize", "0.1", "manifest", data=raw)
            assert result.returncode == 1 and not result.stdout, (raw[:80], result)
        else:
            raise AssertionError(f"Python unexpectedly accepted {raw[:80]!r}")
    print("PASS matching rejections for 12 invalid JSON values")

    for raw in (b'{"a":1,"a":2}', br'{"a":1,"\u0061":2}', b'{"a":{"b":1,"b":2}}', b'{} {}'):
        result = run(binary, "canonicalize", "0.1", "manifest", data=raw)
        assert result.returncode == 1 and not result.stdout, (raw, result)
    for version, domain in (("0.2", "manifest"), ("0.4", "manifest"), ("0.1", "unknown")):
        result = run(binary, "canonicalize", version, domain, data=b"{}")
        assert result.returncode == 1 and not result.stdout, (version, domain, result)
    print("PASS duplicate keys, trailing JSON and unsupported version/domain rejected")


def check_signing(binary):
    seed = bytes(range(32))
    key = Ed25519PrivateKey.from_private_bytes(seed)
    public = key.public_key()
    public_wire = urlsafe_b64encode(public.public_bytes_raw()).rstrip(b"=").decode()
    other_public = Ed25519PrivateKey.from_private_bytes(bytes(reversed(seed))).public_key()
    other_wire = urlsafe_b64encode(other_public.public_bytes_raw()).rstrip(b"=").decode()
    payload = {"title": "迁移样例", "sequence": 1, "meta": {"signature": "keep"}}
    raw = json.dumps(payload).encode()
    with TemporaryDirectory(prefix="owp-rust-signing-") as temp:
        key_path = Path(temp) / "synthetic.seed"
        key_path.touch(mode=0o600)
        key_path.write_bytes(seed)
        for version in ("0.1", "0.3", "0.4", "0.5"):
            for domain in sorted(_signed_domains_for_version(version)):
                python_signed = sign_payload(domain, payload, key, version=version)
                result = run(binary, "verify", version, domain, public_wire,
                             data=json.dumps(python_signed).encode())
                assert result.returncode == 0 and json.loads(result.stdout) == {"valid": True}, result
                result = run(binary, "sign", version, domain, key_path, data=raw)
                assert result.returncode == 0, result
                rust_signed = json.loads(result.stdout)
                assert rust_signed == python_signed, (version, domain)
                assert verify_payload(domain, rust_signed, public, version=version)
            print(f"PASS Python ↔ Rust Ed25519 across all v{version} signed domains")

        invalid_metadata = {**payload, "signature_alg": [1.5]}
        try:
            sign_payload("manifest", invalid_metadata, key)
        except ValueError:
            result = run(binary, "sign", "0.1", "manifest", key_path,
                         data=json.dumps(invalid_metadata).encode())
            assert result.returncode == 1 and not result.stdout, result
        else:
            raise AssertionError("Python unexpectedly signed malformed metadata")
        print("PASS signing rejects malformed metadata before replacing it")

        invalid_key = Path(temp) / "short.seed"
        invalid_key.write_bytes(b"bad")
        result = run(binary, "sign", "0.1", "manifest", invalid_key, data=raw)
        assert result.returncode == 1 and not result.stdout
        for version, domain in (("0.1", "sidecar-event"), ("0.4", "authority-checkpoint")):
            result = run(binary, "sign", version, domain, key_path, data=raw)
            assert result.returncode == 1 and not result.stdout

    signed = sign_payload("manifest", payload, key)
    changed = {**signed, "sequence": 2}
    forged_digest = {**changed, "digest": digest_payload("manifest", changed)}
    for name, domain, candidate, candidate_key, wire in (
        ("tampered", "manifest", changed, public, public_wire),
        ("rehashed without signer", "manifest", forged_digest, public, public_wire),
        ("wrong public key", "manifest", signed, other_public, other_wire),
        ("wrong domain", "work-order", signed, public, public_wire),
        ("padded signature", "manifest", {**signed, "signature": signed["signature"] + "="}, public, public_wire),
        ("missing signature", "manifest", {k: v for k, v in signed.items() if k != "signature"}, public, public_wire),
        ("wrong algorithm", "manifest", {**signed, "signature_alg": "RSA"}, public, public_wire),
    ):
        assert not verify_payload(domain, candidate, candidate_key), name
        result = run(binary, "verify", "0.1", domain, wire, data=json.dumps(candidate).encode())
        assert result.returncode == 1 and json.loads(result.stdout) == {"valid": False}, (name, result)
        print(f"PASS signature rejects {name}")

    # A caller-supplied small-order public key must not validate in Rust.
    weak_raw = b"\x01" + bytes(31)
    weak_wire = urlsafe_b64encode(weak_raw).rstrip(b"=").decode()
    weak = {
        **payload,
        "signature_alg": "Ed25519",
        "signer_key_id": f"ed25519:{sha256_bytes(weak_raw)}",
        "signature": urlsafe_b64encode(weak_raw + bytes(32)).rstrip(b"=").decode(),
    }
    weak["digest"] = digest_payload("manifest", weak)
    result = run(binary, "verify", "0.1", "manifest", weak_wire, data=json.dumps(weak).encode())
    assert result.returncode == 1 and json.loads(result.stdout) == {"valid": False}, result
    print("PASS Rust strict verification rejects the synthetic small-order public key")


def check_checkpoint_and_size(binary):
    seed = bytes(range(32))
    key = Ed25519PrivateKey.from_private_bytes(seed)
    public = key.public_key()
    public_wire = urlsafe_b64encode(public.public_bytes_raw()).rstrip(b"=").decode()
    checkpoint = {"epoch": 1, "authority_key_id": None}
    python_signed = sign_authority_checkpoint(checkpoint, key)
    result = run(binary, "verify-checkpoint", public_wire, data=json.dumps(python_signed).encode())
    assert result.returncode == 0 and json.loads(result.stdout) == {"valid": True}, result

    with TemporaryDirectory(prefix="owp-rust-checkpoint-") as temp:
        key_path = Path(temp) / "synthetic.seed"
        key_path.touch(mode=0o600)
        key_path.write_bytes(seed)
        result = run(binary, "sign-checkpoint", key_path, data=json.dumps(checkpoint).encode())
        assert result.returncode == 0, result
        assert json.loads(result.stdout) == python_signed
        assert verify_authority_checkpoint(json.loads(result.stdout), public)

        for field, value in (("signer_key_id", None), ("authority_key_id", "wrong")):
            result = run(binary, "sign-checkpoint", key_path,
                         data=json.dumps({**checkpoint, field: value}).encode())
            assert result.returncode == 1 and not result.stdout, result

        byte_limit = 8 * 1024 * 1024
        empty_value = b'{"value":""}'
        raw = empty_value[:-2] + b"a" * (byte_limit - len(empty_value)) + empty_value[-2:]
        result = run(binary, "sign", "0.1", "manifest", key_path, data=raw)
        assert result.returncode == 1 and not result.stdout and b"exceeds 8 MiB" in result.stderr
        raw = raw[:-1026] + raw[-2:]
        result = run(binary, "sign", "0.1", "manifest", key_path, data=raw)
        assert result.returncode == 0 and len(result.stdout) <= byte_limit
        check = run(binary, "verify", "0.1", "manifest", public_wire, data=result.stdout)
        assert check.returncode == 0 and json.loads(check.stdout) == {"valid": True}
    print("PASS signing output fits the verification input cap")

    for candidate in ({**python_signed, "epoch": 2}, {**python_signed, "signer_key_id": None}):
        assert not verify_authority_checkpoint(candidate, public)
        result = run(binary, "verify-checkpoint", public_wire, data=json.dumps(candidate).encode())
        assert result.returncode == 1 and json.loads(result.stdout) == {"valid": False}
    print("PASS Python ↔ Rust authority checkpoint and rejection cases")


if __name__ == "__main__":
    executable = Path(sys.argv[1]).resolve()
    check_digest(executable)
    check_canonical(executable)
    check_signing(executable)
    check_checkpoint_and_size(executable)
