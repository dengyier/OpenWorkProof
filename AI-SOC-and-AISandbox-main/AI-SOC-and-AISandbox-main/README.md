# AI-SOC-and-AISandbox

Reference implementation of the architecture in
**《AI 安全與道德治理：結合 dual_model、Agent 影響限制與 OpenWorkProof 的可驗證 AI SOC 架構》**
(design paper, v2.0, 2026-11-01 — included in this repository as `.docx`).

Three subsystems, bound together by a tamper-evident evidence chain:

| Subsystem | Package | Role |
|---|---|---|
| **AI-IDPS / dual_model** | `aisoc/idps/` | known-pattern branch + normality branch, multi-path case decision (paper Table III); signed model release gate from the training domain |
| **AI Agent sandbox** | `aisoc/sandbox/` | constrained read-only investigation agent, controlled egress proxy (record-then-forward, fail-closed), external policy (`allowed / reserved / denied`), human approval, signing service, Policy Enforcement Point |
| **OpenWorkProof-aligned evidence** | `aisoc/owp/` | `WorkOrder → CapabilityGrant → PolicyDecision → ActionReceipt → VerificationDecision → AcceptanceDecision`, hash-chained ledger, Merkle checkpoints, external witness, independent verifier |
| **Adapters** | `aisoc/adapters/` | [Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) as the AI-IDPS (IDMEFv2 `alerts.json` + Zeek `conn.log` → external detector branches), [AiSOC](https://github.com/beenuar/AiSOC) as the SOC platform (alerts, approval inbox as the human step, HMAC bundles anchored into the ledger) |

The orchestrator is `aisoc/soc.py`. Design mapping and limitations are in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); running against Slips and
AiSOC is described in [`docs/INTEGRATION.md`](docs/INTEGRATION.md).

**新手請先讀** [`docs/GUIDE.zh-TW.md`](docs/GUIDE.zh-TW.md)（繁體中文老師版指南：
核心概念、十三條準則對照程式碼與測試、逐步重現與預期輸出、「動手破壞它」練習、
程式碼閱讀路線）。程式碼中每個重要函數上方都有 `【老師註解】` 區塊；
`grep -rn "老師註解" aisoc/` 可列出全部。

## Quick start

```bash
pip install -r requirements.txt
python -m pytest -q                                   # 85 tests
python -m aisoc simulate --out demo-output/aisoc-run  # train, run SOC, scenarios, ablations
python -m aisoc verify demo-output/aisoc-run          # offline re-verification of the exported run

# Slips output through the same pipeline (fixture; see docs/INTEGRATION.md for a real capture)
python -m aisoc slips-ingest tests/fixtures/slips/alerts.json \
    --conn-log tests/fixtures/slips/conn.log --out demo-output/slips-run
python -m aisoc verify demo-output/slips-run
python -m aisoc aisoc-push demo-output/slips-run --dry-run          # events that would go to AiSOC
python -m aisoc aisoc-bundle-verify tests/fixtures/aisoc/investigation-bundle.json --hmac-key test-key
```

`simulate` writes `report.md` / `report.json` plus the exported `ledger.json`,
`witness-checkpoints.json`, `tool-side-receipts.json`, `trusted-keys.json`,
`cases.json` and `model-card.json`. `verify` recomputes the hash chain, checks
witnessed Merkle roots against the ledger signer's public key, validates every
executor-signed receipt, flags any execution that has no recorded
authorization and any agent request that did not pass through the audited
egress channel.

## What the security scenarios demonstrate

All are run by `simulate` and by `tests/test_end_to_end.py`:

* an agent **fully controlled by prompt injection** proposes exfiltration,
  cross-tenant blocking, audit shutdown and policy change — zero are executed;
* replay of a valid single-use authorization, expired or revoked envelopes, and
  parameter changes after approval are rejected at the PEP;
* ledger modification / truncation after an external checkpoint is detected;
* an execution that **bypasses the ledger** is detected by reconciling the
  tool-side receipt log;
* Slips `Description` text used as prompt injection is flagged and never acted
  on; anomaly-only / weak-indicator-only Slips windows end in mandatory human
  review instead of agent action;
* the AiSOC approval inbox stands in for the human step: approve, deny,
  undecided (timeout) and a mismatched record all yield a *signed* outcome,
  and a one-byte change in an AiSOC evidence bundle is caught by both the
  HMAC re-derivation and the ledger digest;
* the sandbox egress proxy fails closed when the audit domain is down, and a
  model that does not match its signed release manifest is never loaded;
* ablations: removing the nonce re-enables replay; removing the PEP approval
  check still yields zero executions because the signer also refuses; removing
  the witness yields `UNKNOWN` / `DEFERRED`, never `ACCEPTED`; making the
  egress proxy fail open lets requests out, but the verifier then reports
  `FAILED` because they have no egress record.

## Honest scope

Following the paper's research-integrity statement:

* **The bundled model is trained on synthetic data and all agents are
  deterministic stubs.** Detection figures in `report.json` describe this code
  on generated traffic. They are not results on CIC-IDS, UNSW-NB15 or any real
  network, and are not comparable to published IDS numbers. With Slips as the
  detector, detection quality is Slips'; this project adds the decision
  policy, sandbox and evidence chain, not a better classifier.
* Keys live in memory (an HSM *interface*, not hardware); all five trust
  domains run in one process. The paper's guarantees require separately
  administered domains, which code alone cannot establish.
* The injection screen is heuristic and is **not** the security boundary; the
  boundary is that agent output is a structured request that must pass the
  egress proxy, external policy, human reservation and the PEP.
* The AiSOC adapters are tested against a fake server built from the AiSOC
  OpenAPI description, not against a live deployment.
* No zero-day immunity, no unconditional containment, no certification is
  claimed.

## Earlier material

`working-demo/`, `working-demo-signed/`, `surface-bundle-demo/` and the
`*-demo*.py` scripts are earlier Surface-Bundle / environment-fingerprint
experiments that expect an upstream `OpenWorkProof/` checkout (currently empty
here). They are kept for reference and are independent of `aisoc/`.

## License

See [LICENSE](LICENSE).