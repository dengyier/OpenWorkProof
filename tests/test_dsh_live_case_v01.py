"""Developer-only preparation of one disposable case for packed DSH preflight."""

from __future__ import annotations

import os
from pathlib import Path

from openworkproof.dsh_case import load_dsh_case
from scripts.create_dsh_fixture import (
    create_dsh_fixture,
    prepare_dsh_process_case,
)


def test_prepare_disposable_live_case(
    tmp_path: Path,
    signed_work_order,
    signed_subject_claim,
    evaluation_scope_payload_v03,
    frozen_verification_profile_v03,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    supplied = os.environ.get("OWP_DSH_LIVE_CASE_ROOT")
    root = tmp_path if supplied is None else Path(supplied)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    case = create_dsh_fixture(
        root,
        signed_work_order=signed_work_order,
        signed_subject_claim=signed_subject_claim,
        evaluation_scope_payload_v03=evaluation_scope_payload_v03,
        verification_profile_v03=frozen_verification_profile_v03,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
    )

    case_id = prepare_dsh_process_case(root, case, ephemeral_role_keys)

    manifest = load_dsh_case(root)
    assert manifest.case_id == case_id
    assert manifest.candidate_workspace_id == case["candidate"].workspace_id
