#!/usr/bin/env python3
"""
Demo: Build and verify a surface bundle using OpenWorkProof
"""
import json
import sys
from pathlib import Path

# Ensure we're using the local OpenWorkProof
sys.path.insert(0, str(Path(__file__).parent / "OpenWorkProof"))

from openworkproof.delivery_package import export_delivery_package
from openworkproof.surface_bundle import build_surface_bundle, verify_surface_bundle

def main():
    # Create a working directory for this demo
    demo_dir = Path(__file__).parent / "demo-output"
    demo_dir.mkdir(exist_ok=True)

    print(f"Demo directory: {demo_dir}")

    # For this demo, we'll show the structure and steps.
    # In reality, you'd need:
    # 1. A ledger directory (with signed work orders, execution results, etc.)
    # 2. Environment fingerprints (signed JSON files)

    print("\n" + "="*60)
    print("Surface Bundle Workflow")
    print("="*60)

    print("\nStep 1: Export a delivery package from a ledger")
    print("  Command: owp delivery-build <ledger_dir> <output_dir> --privacy-view {public,diagnostic,customer_private}")
    print("  Example: owp delivery-build ./ledger ./delivery-package --privacy-view customer_private")

    print("\nStep 2: Build a surface bundle from the delivery package")
    print("  Command: owp surface-build <delivery_dir> --fingerprint <env1.json> --fingerprint <env2.json> --output <surface_dir>")
    print("  Example: owp surface-build ./delivery-package --fingerprint ./env-fingerprint.json --output ./surface-bundle")

    print("\nStep 3: Verify the surface bundle offline")
    print("  Command: owp surface-verify <surface_dir>")
    print("  Example: owp surface-verify ./surface-bundle")

    print("\n" + "="*60)
    print("What you need:")
    print("="*60)
    print("1. A LEDGER - contains:")
    print("   - Signed work order")
    print("   - Execution results")
    print("   - Verification decisions")
    print("   - Human agency binding")

    print("\n2. ENVIRONMENT FINGERPRINTS - signed JSON files containing:")
    print("   - Python version")
    print("   - OS info")
    print("   - Dependencies")
    print("   - Signer's public key")

    print("\n3. PRIVACY VIEW - one of:")
    print("   - 'public': shareable with anyone")
    print("   - 'diagnostic': for debugging")
    print("   - 'customer_private': for internal audit")

    print("\n" + "="*60)
    print("To test with real data from the OpenWorkProof test suite:")
    print("="*60)
    print("\nThe project includes test fixtures. You can:")
    print("1. Run the test suite: pytest tests/test_surface_bundle_v01.py -v")
    print("2. Check: tests/integrity-demo/rich-4196/ for example workflows")
    print("3. Review: tests/conftest.py for fixture setup patterns")

    demo_info = {
        "workflow": "surface-bundle",
        "steps": [
            {"step": 1, "command": "export delivery package from ledger"},
            {"step": 2, "command": "create environment fingerprints"},
            {"step": 3, "command": "build surface bundle"},
            {"step": 4, "command": "verify surface bundle offline"},
        ],
        "data_needed": {
            "ledger": "A complete OpenWorkProof ledger directory",
            "fingerprints": "Signed environment fingerprint JSON files",
            "privacy_view": "public|diagnostic|customer_private"
        }
    }

    output_file = demo_dir / "workflow-info.json"
    with open(output_file, "w") as f:
        json.dump(demo_info, f, indent=2)

    print(f"\nWorkflow info saved to: {output_file}")

if __name__ == "__main__":
    main()
