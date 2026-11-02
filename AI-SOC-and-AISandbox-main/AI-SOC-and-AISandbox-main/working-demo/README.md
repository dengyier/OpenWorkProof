# OpenWorkProof Surface Bundle Demo

Generated: 2026-10-31T08:54:55.799893+00:00

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
owp surface-build ./test-delivery-package \
  --fingerprint ./environment.json \
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
   grep -A 30 "_build_surface_from_ledger" \
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

See: /workspaces/AI-SOC-and-AISandbox/surface-bundle-guide.py for more details.
