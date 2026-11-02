"""Adapters to external systems.

* :mod:`aisoc.adapters.slips` — Stratosphere Linux IPS (Slips) as the AI-IDPS
  known-branch / anomaly-signal source (reads its ``alerts.json`` IDMEFv2 output).
* :mod:`aisoc.adapters.aisoc_stack` — beenuar/AiSOC as the SOC platform
  (alert submission, approval inbox bridge, evidence-bundle anchoring).

Both adapters consume the other system's *outputs* over files or HTTP; no
upstream code is vendored. Slips is GPL-2.0, AiSOC is MIT.
"""
