"""Compare the installed Python and compiled Rust servers over real MCP stdio."""

import argparse
import asyncio
from base64 import urlsafe_b64encode
from contextlib import asynccontextmanager
from hashlib import sha256
import json
from pathlib import Path
import subprocess

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from openworkproof.signing import sign_payload


ROOT = Path(__file__).resolve().parents[2]
DIGEST = "owp_compute_digest"
VERIFY = "owp_verify_signature"
KEY_ID = "owp_compute_key_id"
DOMAINS = "owp_list_domains"
GET_SCHEMA = "owp_get_schema"
GET_SCHEMA_DIGEST = "owp_get_schema_digest"
SCHEMA = "openworkproof/mcp/0.2"
INPUTS = {
    DIGEST: {"object_type", "payload"},
    VERIFY: {"object_type", "signed_payload", "public_key_b64url"},
    KEY_ID: {"public_key_b64url"},
    DOMAINS: set(),
    GET_SCHEMA: {"object_type", "version"},
    GET_SCHEMA_DIGEST: {"object_type", "version"},
}


@asynccontextmanager
async def connect(command, *args):
    parameters = StdioServerParameters(command=str(command.resolve()), args=list(args))
    async with stdio_client(parameters) as streams:
        async with ClientSession(*streams) as session:
            yield session, await session.initialize()


async def call(session, name, arguments):
    result = (await session.call_tool(name, arguments)).model_dump(by_alias=True)
    assert not result["isError"], result
    content = result["structuredContent"]
    assert content is not None and content["schema_version"] == SCHEMA, result
    return content


async def check_schemas(python, rust):
    registries = sorted((ROOT / "src/openworkproof/schemas").glob("v*/schema-registry.json"))
    assert [path.parent.name for path in registries] == [f"v0.{n}" for n in range(1, 6)]
    count = 0
    for path in registries:
        registry = json.loads(path.read_bytes())
        version = registry["protocol_version"]
        for entry in registry["schemas"]:
            raw = (path.parent / entry["path"]).read_bytes()
            digest = sha256(raw).hexdigest()
            assert digest == entry["sha256"], entry
            arguments = {"object_type": entry["object_type"], "version": version}
            envelope = {"schema_version": SCHEMA, "ok": True, **arguments}
            for session in (python, rust):
                assert await call(session, GET_SCHEMA, arguments) == {
                    **envelope, "schema": json.loads(raw),
                }, arguments
                assert await call(session, GET_SCHEMA_DIGEST, arguments) == {
                    **envelope, "schema_digest": digest,
                }, arguments
            count += 1
    assert count == 24
    print("PASS MCP schema registry: all 24 JSON schemas and frozen digests across v0.1–v0.5")

    for name, error_prefix in ((GET_SCHEMA, "schema"), (GET_SCHEMA_DIGEST, "digest")):
        arguments = {"object_type": "work-order"}
        defaulted = await call(python, name, arguments)
        assert defaulted["ok"] and defaulted["version"] == "0.1"
        assert await call(rust, name, arguments) == defaulted
        assert await call(rust, name, {**arguments, "version": "0.1"}) == defaulted
        for invalid, error in (
            ({"object_type": "work-order", "version": "0.9"}, "unknown protocol version"),
            ({"object_type": "work-order", "version": "0.5"}, "unknown object type"),
            ({"object_type": "../v0.1/work-order", "version": "0.1"}, "unknown object type"),
            ({"object_type": "work-order", "version": "../v0.1"}, "unknown protocol version"),
        ):
            rejected = await call(python, name, invalid)
            assert rejected["ok"] is False
            assert rejected["error"].startswith(f"{error_prefix} lookup failed: {error}")
            assert await call(rust, name, invalid) == rejected
    print("PASS MCP schema lookup defaults to v0.1 and rejects wrong version, object and traversal")


async def check(python_mcp, rust_binary):
    async with connect(python_mcp) as (python, py_info), connect(
        rust_binary, "mcp"
    ) as (rust, rs_info):
        assert py_info.model_dump(by_alias=True)["serverInfo"]["name"] == "openworkproof"
        assert rs_info.model_dump(by_alias=True)["serverInfo"]["name"] == "openworkproof-rust"
        assert py_info.capabilities.tools is not None
        assert rs_info.capabilities.tools is not None
        py_tools = {tool.name: tool for tool in (await python.list_tools()).tools}
        rs_tools = {tool.name: tool for tool in (await rust.list_tools()).tools}
        assert set(rs_tools) == set(INPUTS)
        for name, expected_fields in INPUTS.items():
            for tool in (py_tools[name], rs_tools[name]):
                schema = tool.model_dump(by_alias=True)["inputSchema"]
                properties = schema.get("properties", {})
                optional = {"version"} if name in (GET_SCHEMA, GET_SCHEMA_DIGEST) else set()
                assert set(schema.get("required", [])) == expected_fields - optional, schema
                assert set(properties) == expected_fields, schema
                assert all(field["type"] == "string" for field in properties.values())
                if optional:
                    assert properties["version"]["default"] == "0.1", schema
        print(f"PASS MCP initialize/tools/list: Python {len(py_tools)} tools, Rust {len(rs_tools)} tools")

        await check_schemas(python, rust)

        py_catalog = await call(python, DOMAINS, {})
        assert await call(rust, DOMAINS, {}) == py_catalog
        assert py_catalog["ok"] and len(py_catalog["canonical_domains"]) == 24
        assert len(py_catalog["signed_domains"]) == 18
        for domain in ("scope-member", "scope-population", "scope-requirement", "evaluation-scope"):
            assert domain in py_catalog["canonical_domains"] and domain not in py_catalog["signed_domains"]
            arguments = {"object_type": domain, "payload": "{}"}
            rejected = await call(python, DIGEST, arguments)
            assert rejected["ok"] is False and rejected["error"].startswith("digest computation failed")
            assert await call(rust, DIGEST, arguments) == rejected
        print("PASS MCP domain catalog: 24 canonical, 18 signed; all 4 scope domains reject v0.1 digest")

        payload = {"digest": "old", "a": 1, "\U00010000": "中文", "\uE000": "BMP"}
        digest_args = {"object_type": "manifest", "payload": json.dumps(payload)}
        py_digest = await call(python, DIGEST, digest_args)
        assert py_digest["ok"], py_digest
        assert await call(rust, DIGEST, digest_args) == py_digest
        print(f"PASS MCP canonical digest: {py_digest['digest']} ({py_digest['canonical_length']} bytes)")

        key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        public = urlsafe_b64encode(key.public_key().public_bytes_raw()).decode()
        for raw in (key.public_key().public_bytes_raw(), b"\xff" * 32):
            padded = urlsafe_b64encode(raw).decode()
            expected = {"schema_version": SCHEMA, "ok": True, "key_id": "ed25519:" + sha256(raw).hexdigest()}
            for encoding in (padded, padded.rstrip("=")):
                arguments = {"public_key_b64url": encoding}
                assert await call(python, KEY_ID, arguments) == expected
                assert await call(rust, KEY_ID, arguments) == expected
        print("PASS MCP key ID: padded and unpadded raw public keys match Python full SHA-256 fingerprint")

        signed = sign_payload("manifest", payload, key)
        for signed_payload, public_key, domain, valid in (
            (signed, public.rstrip("="), "manifest", True),
            (signed, public, "manifest", True),
            ({**signed, "a": 2}, public, "manifest", False),
            ({**signed, "signature": "invalid"}, public, "manifest", False),
            (signed, public, "work-order", False),
        ):
            arguments = {
                "object_type": domain,
                "signed_payload": json.dumps(signed_payload),
                "public_key_b64url": public_key,
            }
            expected = {"schema_version": SCHEMA, "ok": True, "valid": valid}
            assert await call(python, VERIFY, arguments) == expected
            assert await call(rust, VERIFY, arguments) == expected
        print("PASS MCP signature: Python-signed evidence, key padding, tamper and domain separation")

        verify_args = {
            "object_type": "manifest",
            "signed_payload": json.dumps(signed),
            "public_key_b64url": public,
        }
        for tool, arguments, prefix in (
            (DIGEST, {**digest_args, "payload": "{"}, "payload is not valid JSON"),
            (DIGEST, {**digest_args, "payload": "[]"}, "payload must be a JSON object"),
            (DIGEST, {**digest_args, "payload": '{"value":1.2}'}, "digest computation failed"),
            (VERIFY, {**verify_args, "signed_payload": "{"}, "signed_payload is not valid JSON"),
            (VERIFY, {**verify_args, "signed_payload": "[]"}, "signed_payload must be a JSON object"),
            (VERIFY, {**verify_args, "public_key_b64url": "invalid"}, "invalid Ed25519 public key"),
            (VERIFY, {**verify_args, "object_type": "sidecar-event"}, "object_type 'sidecar-event'"),
            (KEY_ID, {"public_key_b64url": "invalid"}, "invalid Ed25519 public key"),
        ):
            for session in (python, rust):
                result = await call(session, tool, arguments)
                assert result["ok"] is False and result["error"].startswith(prefix), result
        print("PASS MCP structured errors for malformed input, invalid key and unsigned domain")


def check_frame_limit(rust):
    frame = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "owp-frame-test", "version": "1"},
        },
    }).encode()
    command = [str(rust.resolve()), "mcp"]
    normal = subprocess.run(command, input=frame + b"\n", capture_output=True, timeout=15)
    assert json.loads(normal.stdout.splitlines()[0])["id"] == 1, normal.stderr
    cap = 6 * 8 * 1024 * 1024 + 4096
    oversized = subprocess.run(
        command, input=frame + b" " * (cap - len(frame) + 1) + b"\n",
        capture_output=True, timeout=15,
    )
    assert oversized.returncode != 0 and not oversized.stdout, oversized.stderr
    print(f"PASS MCP rejects an oversized {cap + 1}-byte transport frame before initialize")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python-mcp", type=Path, default=ROOT / ".venv/bin/owp-mcp")
    parser.add_argument("rust", nargs="?", type=Path, default=ROOT / "rust/target/debug/owp-rust")
    options = parser.parse_args()
    asyncio.run(asyncio.wait_for(check(options.python_mcp, options.rust), timeout=45))
    check_frame_limit(options.rust)
