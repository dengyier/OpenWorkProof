# Surface Bundle Workflow

## Quick Start

```bash
# 1. Export delivery package from your ledger
owp delivery-build ./ledger ./delivery-package --privacy-view customer_private

# 2. Build surface bundle with environment fingerprints
owp surface-build ./delivery-package \
  --fingerprint ./env-fingerprint.json \
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
