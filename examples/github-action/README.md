# GitHub Action example

This workflow verifies an existing OpenWorkProof v0.5 delivery package and
publishes an offline-verifiable Surface Bundle. Store the collector's lowercase
64-character Ed25519 seed in the `OPENWORKPROOF_COLLECTOR_PRIVATE_KEY` GitHub
secret, write it to a permission-restricted temporary file, and pass only that
file path to the Action.

The repository fixture key is not production material. Never commit a private
key, reuse fixture keys, or pass key bytes as command-line arguments. The
collector actor id must match the Verifier subject bound by the signed profile.

`VERIFIED` means the signed evidence replayed successfully. It is not production
adoption, payment, settlement, or human acceptance. Download and unpack the
artifact, then run `owp surface-verify openworkproof-surface` independently.
