#!/usr/bin/env python3
"""
Create minimal test data for OpenWorkProof surface bundle demo
"""

import json
from pathlib import Path
from datetime import datetime, timezone

def main():
    demo_dir = Path(__file__).parent / "working-demo"
    demo_dir.mkdir(exist_ok=True)

    now = datetime.now(timezone.utc).isoformat()

    print("\n" + "="*70)
    print("🔧 Creating OpenWorkProof Demo Data")
    print("="*70 + "\n")

    # Create environment fingerprint
    print("1️⃣  Creating environment fingerprint...")
    fingerprint = {
        "schema_version": "openworkproof/environment-fingerprint/0.1",
        "created_at": now,
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

    fp_file = demo_dir / "environment.json"
    with open(fp_file, "w") as f:
        json.dump(fingerprint, f, indent=2)
    print(f"   ✅ {fp_file}")

    # Create a minimal delivery package structure
    print("\n2️⃣  Creating delivery package structure...")
    delivery_dir = demo_dir / "test-delivery-package"
    delivery_dir.mkdir(exist_ok=True)

    # Manifest
    manifest = {
        "schema_version": "openworkproof/delivery-package/0.5",
        "exported_at": now,
        "privacy_view": "customer_private",
        "ledger_state_hash": "placeholder",
        "components": {
            "work_order": "work-order.json",
            "execution_receipt": "execution-receipt.json",
            "verification_profile": "verification-profile.json",
            "verification_result": "verification-result.json",
            "verification_decision": "verification-decision.json"
        }
    }

    manifest_file = delivery_dir / "manifest.json"
    with open(manifest_file, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"   ✅ {manifest_file}")

    # Placeholder components (minimal valid structure)
    components = {
        "work-order.json": {
            "schema_version": "openworkproof/work-order/v0.5",
            "work_order_id": "demo-001",
            "created_at": now,
            "task_description": "Demo surface bundle verification"
        },
        "execution-receipt.json": {
            "schema_version": "openworkproof/execution-receipt/v0.5",
            "execution_id": "exec-001",
            "status": "completed",
            "exit_code": 0
        },
        "verification-profile.json": {
            "schema_version": "openworkproof/verification-profile/v0.5",
            "profile_id": "profile-001",
            "test_population": []
        },
        "verification-result.json": {
            "schema_version": "openworkproof/verification-result/v0.5",
            "result_id": "result-001",
            "status": "unknown"
        },
        "verification-decision.json": {
            "schema_version": "openworkproof/verification-decision/v0.5",
            "decision_id": "decision-001",
            "status": "unknown"
        }
    }

    for name, content in components.items():
        comp_file = delivery_dir / name
        with open(comp_file, "w") as f:
            json.dump(content, f, indent=2)
        print(f"   ✅ {comp_file.name}")

    # Create README with instructions
    readme_content = f"""# OpenWorkProof Surface Bundle Demo

Generated: {now}

## Files Created

- `environment.json` - Environment fingerprint (signed metadata)
- `test-delivery-package/` - Delivery package directory with manifests

## What's Missing (and why)

The delivery package needs cryptographic signatures and real ledger data to work completely.
For a full working example, you would need:

1. A real ledger with signed components
2. Properly signed fingerprints
3. Valid work orders, execution records, and verification results

## Try the Commands

```bash
# This will likely fail because we have minimal/placeholder data:
owp surface-build ./test-delivery-package \\
  --fingerprint ./environment.json \\
  --output ./test-surface-bundle

owp surface-verify ./test-surface-bundle
```

## Real World Workflow

To see how this works with real data:

1. Check the OpenWorkProof test fixtures:
   ```bash
   cat OpenWorkProof/tests/integrity-demo/rich-4196/README.md
   ```

2. Review example test code:
   ```bash
   grep -A 30 "_build_surface_from_ledger" \\
     OpenWorkProof/tests/test_acceptance_bundle_v01.py
   ```

3. Run the full test suite (requires pytest):
   ```bash
   cd OpenWorkProof
   pip install pytest
   pytest tests/test_surface_bundle_v01.py -v
   ```

## Understanding the Data

### environment.json
Contains environment metadata:
- Python version
- OS information
- Dependencies
- Reproducibility data

This is what gets added to the delivery package to create a surface bundle.

### test-delivery-package/
A structured directory with:
- **manifest.json** - Index of all components
- **work-order.json** - Original task definition
- **execution-receipt.json** - What was actually executed
- **verification-profile.json** - Test plan
- **verification-result.json** - Test results
- **verification-decision.json** - Verifier's conclusion

## Next Steps

1. **With Real Data**: Get an actual ledger from the OpenWorkProof system
2. **Test It**: Use the conftest utilities to generate complete fixtures
3. **Inspect It**: Read the protocol docs in `OpenWorkProof/docs/`

See: {Path(__file__).parent / "surface-bundle-guide.py"} for more details.
"""

    readme_file = demo_dir / "README.md"
    with open(readme_file, "w") as f:
        f.write(readme_content)
    print(f"   ✅ {readme_file}")

    # Create setup summary
    print("\n3️⃣  Creating setup summary...")
    summary = {
        "status": "partial-demo",
        "note": "These are minimal demo files. For full functionality, use OpenWorkProof with real data.",
        "timestamp": now,
        "files": {
            "environment_fingerprint": str(fp_file),
            "delivery_package": str(delivery_dir),
            "ledger": None  # Not created - would need conftest
        },
        "try_commands": [
            "cd working-demo",
            "ls -la",
            "owp surface-build ./test-delivery-package --fingerprint ./environment.json --output ./surface-bundle",
            "owp surface-verify ./surface-bundle"
        ]
    }

    summary_file = demo_dir / "SETUP.json"
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"   ✅ {summary_file}")

    # Print results
    print("\n" + "="*70)
    print("📂 Demo Files Created")
    print("="*70)
    print(f"\nLocation: {demo_dir}\n")

    for item in sorted(demo_dir.rglob("*")):
        if item.is_file():
            rel_path = str(item.relative_to(demo_dir))
            size = item.stat().st_size
            print(f"  {rel_path:<40} ({size:>6} bytes)")

    print("\n" + "="*70)
    print("🎯 What to Do Next")
    print("="*70)

    print(f"""
1. Navigate to demo directory:
   cd {demo_dir}

2. List the files:
   ls -la

3. Try building a surface bundle:
   owp surface-build ./test-delivery-package \\
     --fingerprint ./environment.json \\
     --output ./surface-bundle

4. Try verifying it:
   owp surface-verify ./surface-bundle

⚠️  NOTE: These are minimal demo files without cryptographic signatures.
For full working examples with real ledgers, use:
   OpenWorkProof/tests/integrity-demo/rich-4196/
   OpenWorkProof/tests/test_surface_bundle_v01.py

📚 Documentation:
   - Overview: {Path(__file__).parent / "surface-bundle-guide.py"}
   - Protocol docs: OpenWorkProof/docs/
   - MCP Server: OpenWorkProof/MCP_SERVER.md
""")

    print("="*70 + "\n")

if __name__ == "__main__":
    main()
