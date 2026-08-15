# Rich #4196 Verification-Integrity v0.5 Demonstration

```yaml
issue_source: https://github.com/Textualize/rich/issues/4196
demo_owner: OpenWorkProof
upstream_adoption: not_evidenced
customer_case: not_evidenced
commercial_validation: not_evidenced
```

## Captured fact

The upstream issue reports that a non-breaking space (NBSP, U+00A0) can be
treated as a line-break opportunity. This directory does not copy an upstream
patch or claim upstream adoption. It reuses the committed OpenWorkProof-owned
fixture under `tests/scope-demo/rich-4196/` and demonstrates the three v0.5
verification-integrity conclusions on top of it.

## The three demonstrations

1. **Population blind spot.** The verifier can see two eligible test nodes
   (`required-test.py::test_nbsp_is_not_breakable` and the legacy check), but
   the selector engine chooses zero of them. The run itself finishes cleanly,
   yet v0.5 derives `UNKNOWN / POPULATION_CAPTURE_FAILED` — never `VERIFIED`.

2. **Control rot.** The registered mutant (`mutant.py`) still fails, but with
   an altered failure signature (different exit code and reason code) than the
   one registered in the negative-control contract. v0.5 derives `UNKNOWN /
   CONTROL_FAILURE_SIGNATURE_MISMATCH`. The exact registered signature derives
   `proven` and is required for the final chain.

3. **Repaired full chain.** With the complete selected population and the
   exact negative control, Profile, positive/negative Results, and the
   `VERIFIED` Decision commit and replay offline from the exported
   customer-private package — without Git, the ledger, or network access.

## Boundary

This is a protocol demonstration, not evidence that Textualize/Rich adopted
OpenWorkProof, not a customer deployment, not proof of universal software
correctness, and not proof of payment, escrow, or settlement.
