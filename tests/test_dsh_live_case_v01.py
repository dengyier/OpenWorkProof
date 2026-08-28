"""Developer-only preparation of one disposable case for packed DSH preflight."""

from __future__ import annotations

import os
import json
import shutil
import socket
import threading
import time
from datetime import datetime
from pathlib import Path

import rfc8785

from openworkproof.dsh_case import load_dsh_case
from openworkproof.dsh_protocol import DshExecutionIdentityV01
from openworkproof.models import RunTestsArguments
from openworkproof.policy import ProspectiveExecutionFacts
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
    coordinator = os.environ.get("OWP_DSH_LIVE_COORDINATOR") == "1"
    patch_ready = Path(
        os.environ.get("OWP_DSH_PATCH_READY", root / "patch-ready.json")
    )
    patch_done = Path(
        os.environ.get("OWP_DSH_PATCH_DONE", root / "patch-done")
    )
    tests_ready = Path(
        os.environ.get("OWP_DSH_TESTS_READY", root / "tests-ready.json")
    )
    tests_done = Path(
        os.environ.get("OWP_DSH_TESTS_DONE", root / "tests-done")
    )
    finalized = Path(
        os.environ.get(
            "OWP_DSH_COORDINATOR_FINALIZED",
            root / "coordinator-finalized.json",
        )
    )
    prepared_case_id: dict[str, str] = {}

    def wait_for(path: Path, label: str) -> None:
        deadline = time.monotonic() + 180
        while not path.exists():
            if time.monotonic() >= deadline:
                raise TimeoutError(f"DSH live {label} did not complete")
            time.sleep(0.05)

    def action_hook(stage: str, open_case) -> None:
        socket_path = Path(
            os.environ.get("OWP_DSH_VERIFIER_SOCKET", root / "verifier.sock")
        )
        if stage == "patch":
            case_id = prepare_dsh_process_case(
                root,
                open_case,
                ephemeral_role_keys,
                live_candidate=True,
                verifier_socket_path=socket_path,
            )
            prepared_case_id["value"] = case_id
            patch_ready.write_bytes(
                rfc8785.dumps(
                    {
                        "case_id": case_id,
                        "fixed_now": fixed_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "test_profile_digest": open_case["profile_digest"],
                    }
                )
                + b"\n"
            )
            wait_for(patch_done, "patch")
            return

        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        listener.listen()
        listener.settimeout(0.1)
        stopped = threading.Event()

        def serve() -> None:
            while not stopped.is_set():
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    raw = b""
                    while not raw.endswith(b"\n") and len(raw) <= 1_048_576:
                        chunk = connection.recv(65_536)
                        if not chunk:
                            break
                        raw += chunk
                    request = json.loads(raw)
                    execution = DshExecutionIdentityV01.model_validate(
                        request["execution"]
                    )
                    facts = ProspectiveExecutionFacts(
                        execution_context_id=request["facts"][
                            "execution_context_id"
                        ],
                        container_instance_id_digest=request["facts"][
                            "container_instance_id_digest"
                        ],
                        controller_id=request["facts"]["controller_id"],
                    )
                    receipt = open_case["external_verifier"](
                        RunTestsArguments.model_validate(request["arguments"]),
                        facts,
                        execution,
                        datetime.strptime(
                            request["requested_at"], "%Y-%m-%dT%H:%M:%SZ"
                        ).replace(tzinfo=open_case["now"].tzinfo),
                    )
                    response = {
                        "schema_version": (
                            "openworkproof-dsh-verifier-response/0.1"
                        ),
                        "case_id": request["case_id"],
                        "execution_identity_digest": request[
                            "execution_identity_digest"
                        ],
                        "receipt": receipt.model_dump(mode="json"),
                    }
                    connection.sendall(rfc8785.dumps(response) + b"\n")

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            tests_ready.write_bytes(
                rfc8785.dumps(
                    {
                        "case_id": prepared_case_id["value"],
                        "fixed_now": fixed_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "test_profile_digest": open_case["profile_digest"],
                    }
                )
                + b"\n"
            )
            wait_for(tests_done, "tests")
        finally:
            stopped.set()
            thread.join(timeout=5)
            listener.close()

    case = create_dsh_fixture(
        root,
        signed_work_order=signed_work_order,
        signed_subject_claim=signed_subject_claim,
        evaluation_scope_payload_v03=evaluation_scope_payload_v03,
        verification_profile_v03=frozen_verification_profile_v03,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        action_hook=action_hook if coordinator else None,
    )

    if coordinator:
        # The fixture's internal delivery export has already been verified and is
        # not part of the private DSH case surface exposed to the packed plugin.
        for disposable in (root / "delivery-case", root / "exported"):
            if disposable.exists():
                shutil.rmtree(disposable)
        finalized.write_bytes(
            rfc8785.dumps(
                {
                    "case_id": prepared_case_id["value"],
                    "status": "FINALIZED",
                }
            )
            + b"\n"
        )
        case_id = prepared_case_id["value"]
    else:
        case_id = prepare_dsh_process_case(root, case, ephemeral_role_keys)

    manifest = load_dsh_case(root)
    assert manifest.case_id == case_id
    assert manifest.candidate_workspace_id == case["candidate"].workspace_id
