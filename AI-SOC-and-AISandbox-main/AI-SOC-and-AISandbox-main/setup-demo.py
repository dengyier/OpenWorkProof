#!/usr/bin/env python3
"""
Setup a working OpenWorkProof demo with:
1. A complete ledger
2. Environment fingerprints
3. Delivery package
4. Surface bundle
"""

import sys
from pathlib import Path

# Add paths
repo_root = Path(__file__).parent / "OpenWorkProof"
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "tests"))

import tempfile
import json
from datetime import datetime, timezone

# Import conftest utilities
from conftest import (
    fixed_now,
    ephemeral_role_keys,
    signed_work_order,
    sidecar_receipt_factory,
)

def setup_test_ledger():
    """Create a complete test ledger with all required components."""
    from openworkproof import ledger as ledger_module
    from openworkproof import evidence
    from openworkproof.delivery_package import export_delivery_package
    from openworkproof.surface_bundle import build_surface_bundle

    # Create temporary directory for demo
    demo_dir = Path(__file__).parent / "working-demo"
    demo_dir.mkdir(exist_ok=True)

    work_tmp = tempfile.TemporaryDirectory()
    tmp_path = Path(work_tmp.name)

    print(f"🔧 Setting up test ledger in: {tmp_path}")

    try:
        # Setup time
        now = datetime(2025, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

        # Create cryptographic keys
        print("  1. Generating role keys...")
        keys = ephemeral_role_keys()

        # Create work order
        print("  2. Creating signed work order...")
        order = signed_work_order(keys, clock=lambda: now)

        # Initialize ledger
        print("  3. Initializing ledger...")
        ledger_path = tmp_path / "ledger"
        ledger_path.mkdir()

        # Create ledger structure
        ledger_module.init_ledger(str(ledger_path))

        # Add work order to ledger
        ledger_module.commit_work_order(str(ledger_path), order)

        print(f"✅ Ledger created at: {ledger_path}")

        # Export delivery package
        print("\n📦 Exporting delivery package...")
        delivery_path = demo_dir / "test-delivery-package"
        export_delivery_package(
            str(ledger_path),
            str(delivery_path),
            privacy_view="customer_private"
        )
        print(f"✅ Delivery package exported to: {delivery_path}")

        # Create environment fingerprint
        print("\n🌐 Creating environment fingerprint...")
        fingerprint = {
            "schema_version": "openworkproof/environment-fingerprint/0.1",
            "created_at": now.isoformat(),
            "environment": {
                "python_version": "3.11.0",
                "platform": "linux",
                "platform_release": "6.8.0",
                "implementation": "cpython"
            },
            "dependencies": {
                "openworkproof": "1.5.0"
            },
            "metadata": {
                "recorded_by": "demo-setup",
                "purpose": "surface-bundle-verification"
            }
        }

        fingerprint_file = demo_dir / "environment.json"
        with open(fingerprint_file, "w") as f:
            json.dump(fingerprint, f, indent=2)
        print(f"✅ Fingerprint created at: {fingerprint_file}")

        # Build surface bundle
        print("\n🔗 Building surface bundle...")
        surface_path = demo_dir / "test-surface-bundle"
        try:
            build_surface_bundle(
                str(delivery_path),
                (str(fingerprint_file),),
                str(surface_path)
            )
            print(f"✅ Surface bundle built at: {surface_path}")
        except Exception as e:
            print(f"⚠️  Surface bundle build had issues (this may be expected for incomplete ledgers)")
            print(f"   Error: {e}")
            print(f"   The delivery package and fingerprint are still ready at:")
            print(f"   - Delivery: {delivery_path}")
            print(f"   - Fingerprint: {fingerprint_file}")

        # Create test setup summary
        summary = {
            "status": "ready",
            "timestamp": now.isoformat(),
            "components": {
                "ledger": str(ledger_path),
                "delivery_package": str(delivery_path),
                "fingerprint": str(fingerprint_file),
                "surface_bundle": str(surface_path) if surface_path.exists() else None
            },
            "next_steps": [
                f"cd {demo_dir}",
                "owp delivery-build ./ledger ./delivery-package --privacy-view customer_private",
                "owp surface-build ./delivery-package --fingerprint ./environment.json --output ./surface-bundle",
                "owp surface-verify ./surface-bundle"
            ]
        }

        summary_file = demo_dir / "setup-summary.json"
        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=2)

        print("\n" + "="*70)
        print("📊 Setup Summary")
        print("="*70)
        print(json.dumps(summary, indent=2))

        print("\n" + "="*70)
        print("🎯 Next Steps")
        print("="*70)
        print(f"\n1. Navigate to working directory:")
        print(f"   cd {demo_dir}")
        print(f"\n2. Verify the components exist:")
        print(f"   ls -la")
        print(f"\n3. Check delivery package:")
        print(f"   cat test-delivery-package/manifest.json | head -20")
        print(f"\n4. Check environment fingerprint:")
        print(f"   cat environment.json")
        print(f"\n5. Try the CLI commands:")
        print(f"   owp surface-verify ./test-surface-bundle  (if exists)")
        print(f"\n6. Or manually build and verify:")
        print(f"   owp surface-build ./test-delivery-package --fingerprint ./environment.json --output ./my-surface")
        print(f"   owp surface-verify ./my-surface")

        return demo_dir

    except Exception as e:
        print(f"\n❌ Error during setup: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    print("\n" + "="*70)
    print("🚀 OpenWorkProof Surface Bundle Demo Setup")
    print("="*70 + "\n")

    demo_dir = setup_test_ledger()

    if demo_dir:
        print(f"\n✨ Demo ready! Files at: {demo_dir}\n")
    else:
        print("\n❌ Setup failed. Check errors above.\n")
        sys.exit(1)
