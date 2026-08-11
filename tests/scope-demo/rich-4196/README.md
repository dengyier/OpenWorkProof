# Rich #4196 Scope-Gap Demonstration

```yaml
issue_source: https://github.com/Textualize/rich/issues/4196
demo_owner: OpenWorkProof
upstream_adoption: not_evidenced
customer_case: not_evidenced
```

## Captured fact

The upstream issue reports that a non-breaking space (NBSP, U+00A0) can be
treated as a line-break opportunity. This directory does not copy an upstream
patch or claim upstream adoption. It freezes a small OpenWorkProof-owned task
that demonstrates the verification failure mode exposed by the issue.

## Demonstration

`legacy_check.py` checks ordinary ASCII-space tokenization. It returns green
for both the repaired candidate and the registered mutant, so that green result
does not cover the NBSP requirement.

`required-test.py` is the required regression. It passes for `candidate.py`
and fails for `mutant.py`. The v0.3 demo first observes a population that omits
this required test and therefore produces `UNKNOWN` with
`SCOPE_REQUIRED_TARGET_MISSING`. The repaired run observes the exact declared
population in both positive and negative arms; the positive candidate passes,
the mutant is caught, and the bounded conclusion is `VERIFIED` only within the
signed Evaluation Scope.

This is a protocol demonstration, not evidence that Textualize/Rich adopted
OpenWorkProof, not a customer deployment, and not proof of universal software
correctness.
