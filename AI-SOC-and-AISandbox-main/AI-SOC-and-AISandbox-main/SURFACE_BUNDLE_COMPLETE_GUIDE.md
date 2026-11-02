# OpenWorkProof Surface Bundle: Complete Guide

## The Problem You Hit

```
owp surface-build ./delivery-package --fingerprint ./fingerprint.json --output ./surface-bundle
```

**Errors:**
1. `delivery ledger is unavailable` → The ledger directory doesn't exist
2. `environment.json not found` → The fingerprint file doesn't exist
3. `surface path cannot be resolved` → Steps 1-2 failed, so no bundle was created

## The Root Issue

To use surface bundles, you need **real data** that has been cryptographically signed. This data doesn't just exist—it's created by the OpenWorkProof system during actual work:

1. **Agent completes a task** → Execution recorded
2. **Manager authorizes it** → Signed work order
3. **Verifier tests it** → Verification results
4. **Ledger accumulates evidence** → All signed and timestamped
5. **Export for verification** → Delivery package + fingerprints

You can't just create random JSON files—they must be:
- Structurally valid (right schema version)
- Cryptographically signed (ED25519 signatures)
- Semantically correct (consistent references between components)

## Where to Get Real Data

### Option 1: Run the OpenWorkProof Test Suite ⭐ RECOMMENDED

The project includes complete, working examples:

```bash
cd OpenWorkProof
pip install pytest
pytest tests/test_surface_bundle_v01.py -v
```

This shows real fixtures with:
- Complete ledgers
- Signed fingerprints
- Verified surface bundles

### Option 2: Use Test Fixtures Directory

Look at the actual demo directory:

```bash
cd OpenWorkProof/tests/integrity-demo/rich-4196/
cat README.md  # Shows the three demonstration scenarios
```

This is a **real protocol demonstration** with:
- ✅ Complete verified chain
- ✅ Offline replay proof
- ✅ Example population verification
- ✅ Control arm validation

### Option 3: Read the Protocol Specifications

```bash
# Understand the data structure
cat OpenWorkProof/docs/protocol/
ls OpenWorkProof/specs/v0.5/

# Check the exact schema requirements
cat OpenWorkProof/specs/v0.5/verification-decision.schema.json
```

## The Three-Layer Data Model

### Layer 1: LEDGER (Primary Record)
```
ledger/
├── work-order.json (signed)
├── execution-receipt.json (signed)
├── verification-profile.json (signed)
├── verification-result.json (signed)
└── acceptance-binding.json (signed)
```
**Requires:** Git history, cryptographic keys, access to ledger server

### Layer 2: DELIVERY PACKAGE (Portable Export)
```
delivery-package/
├── manifest.json (index)
├── work-order.json (extracted from ledger)
├── execution-receipt.json
├── verification-profile.json
├── verification-result.json
├── verification-decision.json
└── surface-facts.json (metadata)
```
**Requires:** None (self-contained)

### Layer 3: SURFACE BUNDLE (Reproducibility Data)
```
surface-bundle/
├── manifest.json
├── delivery-package/ (nested)
├── environment-fingerprint-1.json (signed)
├── environment-fingerprint-2.json (signed, optional)
└── verification-report.json
```
**Requires:** None (complete offline verification)

## Command Reference

```bash
# Step 1: You need a ledger first
# This usually comes from OpenWorkProof system, not manual creation
owp status ./ledger

# Step 2: Export delivery package from ledger
owp delivery-build ./ledger ./delivery-package \
  --privacy-view customer_private

# Step 3: Add environment fingerprints (usually pre-signed)
owp surface-build ./delivery-package \
  --fingerprint ./environment-prod.json \
  --fingerprint ./environment-staging.json \
  --output ./surface-bundle

# Step 4: Verify offline (anywhere, anytime, no dependencies)
owp surface-verify ./surface-bundle

# Output if successful:
# {
#   "bundle_digest": "sha256:abc123...",
#   "decision_status": "VERIFIED",
#   "reason_codes": []
# }
```

## Why Manual Data Creation Doesn't Work

**Fingerprints must be:**

❌ NOT just JSON with random values
❌ NOT unsigned or self-signed randomly
❌ NOT missing required schema fields

✅ Created by the OpenWorkProof system
✅ Cryptographically signed with specific key
✅ Structurally valid with all required fields
✅ Semantically consistent with the delivery package

**Example of what's required:**

```json
{
  "schema_version": "openworkproof-execution-environment/0.1",  // Must be exact
  "source_revision": "sha256:...",  // Must match delivery package
  "runner_os": "linux",
  "runner_arch": "amd64",
  "runner_image_digest": "...",  // Must be 64-char hex
  "container_image_digest": "...",  // All these digests must be present
  // ... 8 more required digest fields ...
  "collection_status": "complete",
  "missing_reason_codes": [],
  "collected_at": "2026-10-31T00:10:00Z",
  "collector_actor_id": "verifier-id",
  "payload": { /* nested structure */ },
  "signature_alg": "Ed25519",
  "digest": "sha256:...",
  "signature": "...",  // ED25519 cryptographic signature
  "collector_key_id": "key-id"
}
```

## Testing: Three Approaches

### Approach 1: Run Existing Tests (EASIEST)
```bash
cd OpenWorkProof
pytest tests/test_surface_bundle_v01.py::test_surface_bundle_v01_build_and_verify -v
```
**Pros:** Complete, working, verified
**Cons:** Requires pytest setup

### Approach 2: Review Test Fixtures (FASTEST)
```bash
# Look at what the tests create
grep -A 50 "_complete_fingerprint" tests/test_surface_bundle_v01.py

# See real protocol examples
cat tests/integrity-demo/rich-4196/README.md
```
**Pros:** Understand the real format without running tests
**Cons:** Read-only (can't execute commands)

### Approach 3: Read the MCP Server (MOST PRACTICAL)
The OpenWorkProof MCP Server provides a programmatic interface:

```bash
cat MCP_SERVER.md
grep -A 20 "surface-build\|surface-verify" MCP_SERVER.md
```
**Pros:** Shows the actual API
**Cons:** Requires integration with an agent/LLM

## Next Steps

### To Understand the Protocol:
1. Read: `OpenWorkProof/docs/protocol/human-agency-profile-v0.1.md`
2. Check: `OpenWorkProof/README.md` sections on "工作原理" (How It Works)
3. Review: `OpenWorkProof/specs/v0.5/` for detailed schemas

### To Test with Real Data:
1. Install dependencies: `pip install pytest cryptography`
2. Run tests: `pytest tests/test_surface_bundle_v01.py -v`
3. Inspect fixtures: `tests/integrity-demo/rich-4196/`

### To Integrate into Your Workflow:
1. Review: `OpenWorkProof/integrations/` for your platform
2. Check: `OpenWorkProof/docs/integrations/` for setup
3. Look at: `OpenWorkProof/examples/` for reference code

## Key Takeaway

**You cannot manually create OpenWorkProof data.**

The system requires:
- Cryptographic signing (specific keys)
- Semantic consistency (components must reference each other)
- Protocol compliance (exact schema versions)
- Audit trail (all steps recorded and signed)

The **real workflow** is:
1. Define tasks (signed work order)
2. Execute work (recorded execution)
3. Verify results (signed verification)
4. Export for sharing (delivery package)
5. Add environment data (fingerprints)
6. Verify offline (surface bundle)

Each step is cryptographically bound to the others. You can't skip steps or fake data—that's the whole point of the protocol.

## Resources

| Resource | Purpose |
|----------|---------|
| `README.md` / `README_en.md` | Overview and protocol explanation |
| `MCP_SERVER.md` | Integration interface |
| `docs/protocol/` | Protocol specifications |
| `specs/v0.5/` | JSON schema definitions |
| `tests/integrity-demo/` | Complete worked examples |
| `tests/test_surface_bundle_v01.py` | Test implementation patterns |
| `examples/` | Reference code |

---

**Summary:** To use surface bundles, you need real OpenWorkProof ledger data (from running actual work) or you need to run the test suite to see complete examples. Manual JSON file creation won't work because the protocol requires cryptographic signatures and semantic consistency.
