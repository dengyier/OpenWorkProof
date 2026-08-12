"""OpenWorkProof self-owned Rich #4196 v0.4 demo (Task 14, Step 5).

The demo uses the real Issue context (rich-4196) with an OpenWorkProof-owned
task, judgment, clean action, coherent-resign attack and delivery package.
All adoption/use/payment metadata is declared ``not_evidenced``.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from openworkproof.delivery_package import (
    DeliveryPackageError,
    verify_delivery_package,
)
from test_delivery_package_v04 import (
    _build_package,
    _replay_inputs,
)

BUNDLE_PATH = Path(__file__).resolve().parents[1] / (
    "tests/evidence-bundles/rich-4196-binding-v04-delivery-package.json"
)
DEMO_DIR = Path(__file__).resolve().parents[1] / (
    "tests/binding-demo/rich-4196"
)


def test_demo_clean_action_replays_bound(binding_decision_case, tmp_path) -> None:
    inputs = _replay_inputs(binding_decision_case)
    root, _ = _build_package(
        tmp_path,
        privacy_view="customer_private",
        binding_replay="BOUND",
        inputs=inputs,
    )
    result = verify_delivery_package(root)
    assert result.binding_replay == "BOUND"
    assert result.binding_reason_codes == ()


def test_demo_coherent_resign_attack_is_unbound(
    binding_decision_case, tmp_path,
) -> None:
    # Manager/Agent/Sidecar re-sign an internally valid chain for an action
    # outside the Acceptor constraint; the package must report UNBOUND.
    inputs = _replay_inputs(binding_decision_case)
    inputs["observed"]["changed_paths"] = ["docs/outside.md"]
    root, _ = _build_package(
        tmp_path,
        privacy_view="customer_private",
        binding_replay="UNBOUND",
        reason_codes=("ACTION_OUTSIDE_APPROVED_SCOPE",),
        inputs=inputs,
    )
    result = verify_delivery_package(root)
    assert result.binding_replay == "UNBOUND"
    assert result.binding_reason_codes == ("ACTION_OUTSIDE_APPROVED_SCOPE",)


def test_demo_single_byte_tamper_fails(binding_decision_case, tmp_path) -> None:
    inputs = _replay_inputs(binding_decision_case)
    root, _ = _build_package(
        tmp_path,
        privacy_view="customer_private",
        binding_replay="BOUND",
        inputs=inputs,
    )
    report_path = root / "binding-report.json"
    raw = report_path.read_bytes()
    report_path.write_bytes(raw[:7] + b"X" + raw[8:])
    with pytest_raises_delivery():
        verify_delivery_package(root)


def pytest_raises_delivery():
    import pytest

    return pytest.raises(DeliveryPackageError)


def test_demo_evidence_bundle_is_generated_and_verifies(
    binding_decision_case, tmp_path,
) -> None:
    inputs = _replay_inputs(binding_decision_case)
    root, _ = _build_package(
        tmp_path,
        privacy_view="customer_private",
        binding_replay="BOUND",
        inputs=inputs,
    )
    files = {
        path.relative_to(root).as_posix(): base64.b64encode(
            path.read_bytes()
        ).decode("ascii")
        for path in root.iterdir()
        if path.is_file()
    }
    bundle = {
        "schema_version": "openworkproof-evidence-bundle/0.4",
        "metadata": {
            "bug_id": "rich-4196",
            "bug_url": (
                "https://github.com/dengyier/OpenWorkProof/issues/4196"
            ),
            "upstream_adoption": "not_evidenced",
            "customer_use": "not_evidenced",
            "payment": "not_evidenced",
        },
        "files": files,
    }
    BUNDLE_PATH.parent.mkdir(parents=True, exist_ok=True)
    BUNDLE_PATH.write_text(
        json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8"
    )

    import subprocess
    import sys

    script = (
        Path(__file__).resolve().parents[1]
        / "tests/evidence-bundles/verify_evidence_bundle.py"
    )
    completed = subprocess.run(
        [sys.executable, str(script), str(BUNDLE_PATH)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "binding_replay: BOUND" in completed.stdout


def test_demo_directory_declares_not_evidenced() -> None:
    readme = DEMO_DIR / "README.md"
    assert readme.is_file()
    text = readme.read_text(encoding="utf-8")
    for marker in (
        "upstream_adoption: not_evidenced",
        "customer_use: not_evidenced",
        "payment: not_evidenced",
    ):
        assert marker in text
