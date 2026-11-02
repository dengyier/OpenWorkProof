#!/usr/bin/env python3
"""
Working example: Build and verify a surface bundle with OpenWorkProof

This demonstrates the complete workflow:
1. Create/load a ledger (with signed work orders, execution results, etc.)
2. Export a delivery package from the ledger
3. Create environment fingerprints
4. Build a surface bundle
5. Verify the surface bundle offline
"""

from pathlib import Path
import json
import sys

# Ensure we import from the local OpenWorkProof
sys.path.insert(0, str(Path(__file__).parent / "OpenWorkProof"))

from openworkproof.delivery_package import export_delivery_package
from openworkproof.surface_bundle import build_surface_bundle, verify_surface_bundle

def main():
    work_dir = Path(__file__).parent / "surface-bundle-demo"
    work_dir.mkdir(exist_ok=True)

    print("\n" + "="*70)
    print("OpenWorkProof Surface Bundle Workflow")
    print("="*70)

    print("\n📋 STEP 1: Understanding the Components")
    print("-" * 70)
    print("""
To build a surface bundle, you need:

1. LEDGER DIRECTORY
   ├── work-order.json          (signed task definition)
   ├── execution-receipt.json   (what the agent actually did)
   ├── verification-result.json (test/verification results)
   ├── verification-decision.json (verifier's conclusion)
   └── acceptance-binding.json  (human approval/rejection)

2. ENVIRONMENT FINGERPRINTS (JSON files, signed)
   - Python version
   - OS and dependencies
   - Reproducibility metadata

3. DELIVERY PACKAGE (exported from ledger)
   - Subset of ledger data for offline verification
   - Privacy-filtered based on your chosen level

4. SURFACE BUNDLE (built from delivery package + fingerprints)
   - Completely offline-verifiable
   - No need for ledger, network, or keys
""")

    print("\n🔧 STEP 2: Command-Line Usage")
    print("-" * 70)
    print("""
Build a delivery package from a ledger:
  $ owp delivery-build ./ledger ./delivery-package \\
    --privacy-view customer_private

Build a surface bundle from the delivery package:
  $ owp surface-build ./delivery-package \\
    --fingerprint ./environment-fingerprint.json \\
    --output ./surface-bundle

Verify the surface bundle offline (anywhere, no dependencies):
  $ owp surface-verify ./surface-bundle
""")

    print("\n📊 STEP 3: Python API (for programmatic use)")
    print("-" * 70)
    print("""
from openworkproof.delivery_package import export_delivery_package
from openworkproof.surface_bundle import (
    build_surface_bundle,
    verify_surface_bundle
)

# Export delivery package from ledger
export_delivery_package(
    ledger_path="./ledger",
    output_path="./delivery-package",
    privacy_view="customer_private"
)

# Build surface bundle
build_surface_bundle(
    delivery_package="./delivery-package",
    fingerprints=("./env-fingerprint.json",),
    output_path="./surface-bundle"
)

# Verify offline
result = verify_surface_bundle("./surface-bundle")
print(result)
""")

    print("\n✅ STEP 4: Testing with OpenWorkProof's Test Fixtures")
    print("-" * 70)
    print("""
The OpenWorkProof project includes complete test fixtures:

View example workflows:
  $ cat OpenWorkProof/tests/integrity-demo/rich-4196/README.md

Review test patterns:
  $ grep -A 30 "_build_surface_from_ledger" OpenWorkProof/tests/test_acceptance_bundle_v01.py

Run the full test suite (requires pytest):
  $ cd OpenWorkProof
  $ pip install -r requirements-lock.txt
  $ pytest tests/test_surface_bundle_v01.py -v
""")

    print("\n⚙️  STEP 5: What Each Component Does")
    print("-" * 70)

    components = {
        "ledger": {
            "purpose": "Central record of all work activity",
            "contains": [
                "Signed authorization (who approved?)",
                "Execution evidence (what actually ran?)",
                "Verification results (tests pass?)",
                "Human decision (accept/reject?)"
            ],
            "requires": ["Git history", "Cryptographic keys", "Network access (optional)"]
        },
        "delivery_package": {
            "purpose": "Standalone export for offline verification",
            "contains": [
                "Subset of ledger data",
                "Privacy-filtered (no PII, secrets removed)",
                "Self-contained (no external dependencies)"
            ],
            "requires": ["None - can be sent via email, stored offline"]
        },
        "surface_bundle": {
            "purpose": "Add environment metadata for reproducibility",
            "contains": [
                "Delivery package data",
                "Environment fingerprints (Python version, OS, etc.)",
                "Verification results"
            ],
            "requires": ["None - complete offline verification"]
        }
    }

    for component, details in components.items():
        print(f"\n  {component.upper().replace('_', ' ')}")
        print(f"  Purpose: {details['purpose']}")
        print(f"  Contains:")
        for item in details['contains']:
            print(f"    • {item}")
        print(f"  Requires: {', '.join(details['requires'])}")

    print("\n\n💡 STEP 6: Common Issues & Solutions")
    print("-" * 70)

    issues = {
        "fingerprint1.json not found": {
            "cause": "You need to create/sign environment fingerprints",
            "solution": "Use `owp` commands to generate, or copy from test fixtures"
        },
        "surface path cannot be resolved": {
            "cause": "surface-build failed (check the delivery-package path)",
            "solution": "Ensure delivery-package exists and is in the correct format"
        },
        "delivery-build missing arguments": {
            "cause": "Missing ledger, output_path, or --privacy-view flag",
            "solution": "owp delivery-build <ledger> <output> --privacy-view {public,diagnostic,customer_private}"
        },
        "No such file or directory": {
            "cause": "Paths don't exist or are relative to wrong directory",
            "solution": "Use absolute paths or check your working directory"
        }
    }

    for issue, details in issues.items():
        print(f"\n  ❌ {issue}")
        print(f"     Cause: {details['cause']}")
        print(f"     Fix: {details['solution']}")

    print("\n\n🔗 STEP 7: Real-World Example (Pseudo-code)")
    print("-" * 70)

    example_code = """
# 1. Agent completes a task (e.g., fixing a bug)
# OpenWorkProof records:
#   - Who authorized it (Manager signature)
#   - What it actually did (Execution log)
#   - Test results (Pass/Fail)

# 2. Export for delivery to customer
owp delivery-build ./ledger ./delivery-package \\
  --privacy-view customer_private

# 3. Add environment details
owp surface-build ./delivery-package \\
  --fingerprint ./python-3.11-ubuntu-22.04.json \\
  --fingerprint ./python-3.12-macos-14.json \\
  --output ./surface-bundle

# 4. Customer can now verify WITHOUT access to:
#   - Original ledger
#   - Private keys
#   - Ledger server
#   - Source repository

owp surface-verify ./surface-bundle

# Result:
{
  "bundle_digest": "sha256:abc123...",
  "decision_status": "VERIFIED",
  "reason_codes": []
}
"""
    print(example_code)

    # Save this info to a file
    info_file = work_dir / "README.md"
    with open(info_file, "w") as f:
        f.write("""# Surface Bundle Workflow

## Quick Start

```bash
# 1. Export delivery package from your ledger
owp delivery-build ./ledger ./delivery-package --privacy-view customer_private

# 2. Build surface bundle with environment fingerprints
owp surface-build ./delivery-package \\
  --fingerprint ./env-fingerprint.json \\
  --output ./surface-bundle

# 3. Verify offline (anywhere, no dependencies needed)
owp surface-verify ./surface-bundle
```

## Next Steps

1. Read: `OpenWorkProof/docs/` for protocol details
2. Test: `OpenWorkProof/tests/test_surface_bundle_v01.py`
3. Review: Example workflows in `OpenWorkProof/tests/integrity-demo/`
4. Integrate: See `OpenWorkProof/docs/integrations/` for your use case

## Resources

- Main README: `OpenWorkProof/README.md`
- MCP Server: `OpenWorkProof/MCP_SERVER.md`
- Specs: `OpenWorkProof/specs/`
""")

    print(f"\n\n✨ Complete guide saved to: {info_file}")
    print("\n" + "="*70 + "\n")

if __name__ == "__main__":
    main()
