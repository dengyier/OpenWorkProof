# Surface Bundle v0.1 fixtures

Task 6 generates its signed fixture packages dynamically from the v0.5 ledger
fixtures. No private key, token, customer data, or mutable binary bundle is
committed in this directory. Attack tests rebuild complete canonical objects,
then tamper one layer at a time and require offline verification to fail closed.
