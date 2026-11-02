#!/usr/bin/env python3
"""
Create a properly signed OpenWorkProof demo with real fingerprints
"""

import sys
from pathlib import Path
from datetime import datetime, timezone

# Add OpenWorkProof to path
repo_root = Path(__file__).parent / "OpenWorkProof"
sys.path.insert(0, str(repo_root))

import json
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from openworkproof.environment_fingerprint import (
    EnvironmentFingerprintPayloadV01,
    sign_environment_fingerprint,
)
from openworkproof.delivery_package import export_delivery_package, load_surface_facts

def main():
    demo_dir = Path(__file__).parent / "working-demo-signed"
    demo_dir.mkdir(exist_ok=True)

    print("\n" + "="*70)
    print("🔐 Creating OpenWorkProof Demo with Signed Fingerprints")
    print("="*70 + "\n")

    # Step 1: Create cryptographic keys
    print("1️⃣  Generating cryptographic keys...")
    verifier_private_key = ed25519.Ed25519PrivateKey.generate()
    verifier_public_key = verifier_private_key.public_key()

    # Save public key for reference
    pub_key_pem = verifier_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    pub_key_file = demo_dir / "verifier-public-key.pem"
    with open(pub_key_file, "w") as f:
        f.write(pub_key_pem)
    print(f"   ✅ Generated and saved keys")

    # Step 2: Create delivery package structure (prerequisite)
    print("\n2️⃣  Creating minimal delivery package...")
    delivery_dir = demo_dir / "test-delivery-package"
    delivery_dir.mkdir(exist_ok=True)

    # Create manifest
    now = datetime.now(timezone.utc).isoformat()
    manifest = {
        "schema_version": "openworkproof/delivery-package/0.5",
        "exported_at": now,
        "privacy_view": "customer_private",
        "ledger_state_hash": "placeholder",
        "components": {}
    }

    with open(delivery_dir / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)

    # Create required surface-facts.json (needed by load_surface_facts)
    surface_facts = {
        "schema_version": "openworkproof/surface-facts/0.1",
        "source_revision": "0000000",
        "trusted_verifier_subjects": {
            # Will be populated with key ID
            "verifier-id": "Verifier"
        }
    }

    with open(delivery_dir / "surface-facts.json", "w") as f:
        json.dump(surface_facts, f, indent=2)

    print(f"   ✅ Created at {delivery_dir}")

    # Step 3: Create signed fingerprint
    print("\n3️⃣  Creating signed environment fingerprint...")

    try:
        # Load surface facts
        facts = load_surface_facts(delivery_dir)

        # Create fingerprint payload
        payload = EnvironmentFingerprintPayloadV01.model_validate({
            "schema_version": "openworkproof-execution-environment/0.1",
            "source_revision": facts.source_revision,
            "runner_os": "linux",
            "runner_arch": "amd64",
            "runner_image_digest": "a" * 64,
            "container_image_digest": "b" * 64,
            "toolchain_lock_digest": "c" * 64,
            "command_digest": "d" * 64,
            "arguments_digest": "e" * 64,
            "environment_allowlist_digest": "f" * 64,
            "sandbox_policy_digest": "0" * 64,
            "workflow_identity_digest": "1" * 64,
            "collection_status": "complete",
            "missing_reason_codes": [],
            "collected_at": "2026-10-31T00:10:00Z",
            "collector_actor_id": "demo-verifier",
        })

        # Sign the fingerprint
        signed_fingerprint = sign_environment_fingerprint(payload, verifier_private_key)

        # Save to file
        fingerprint_file = demo_dir / "environment-fingerprint.json"
        with open(fingerprint_file, "w") as f:
            # Convert the signed fingerprint object to dict for JSON serialization
            fp_dict = json.loads(signed_fingerprint.model_dump_json())
            json.dump(fp_dict, f, indent=2)

        print(f"   ✅ Signed fingerprint created at {fingerprint_file}")

    except Exception as e:
        print(f"   ⚠️  Error creating signed fingerprint: {e}")
        print(f"   Creating unsigned placeholder instead...")

        # Fallback: create unsigned placeholder
        fingerprint = {
            "schema_version": "openworkproof/environment-fingerprint/0.1",
            "created_at": now,
            "environment": {
                "python_version": "3.11.0",
                "platform": "linux",
                "platform_release": "6.8.0",
                "implementation": "cpython"
            }
        }

        fingerprint_file = demo_dir / "environment-fingerprint.json"
        with open(fingerprint_file, "w") as f:
            json.dump(fingerprint, f, indent=2)

        print(f"   ⚠️  Using unsigned placeholder at {fingerprint_file}")

    # Step 4: Show what was created
    print("\n" + "="*70)
    print("📂 Demo Files Created")
    print("="*70)
    print(f"\nLocation: {demo_dir}\n")

    for item in sorted(demo_dir.rglob("*")):
        if item.is_file():
            rel_path = str(item.relative_to(demo_dir))
            size = item.stat().st_size
            print(f"  {rel_path:<45} ({size:>6} bytes)")

    # Step 5: Instructions
    print("\n" + "="*70)
    print("🎯 Next Steps")
    print("="*70)

    print(f"""
1. Navigate to demo directory:
   cd {demo_dir}

2. Try building a surface bundle:
   owp surface-build ./test-delivery-package \\
     --fingerprint ./environment-fingerprint.json \\
     --output ./surface-bundle

3. Try verifying it:
   owp surface-verify ./surface-bundle

📝 Note: These are minimal demo files. For production use, integrate with:
   - Real OpenWorkProof ledger system
   - Proper key management
   - Actual execution environment data
   - Complete verification workflows
""")

    print("="*70 + "\n")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
