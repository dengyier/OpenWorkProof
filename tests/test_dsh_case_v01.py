from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from openworkproof.dsh_case import (
    DecisionTokenStore,
    DshCaseError,
    dsh_case_id,
    load_dsh_case,
)
from openworkproof.dsh_protocol import DshExecutionIdentityV01


NOW = datetime(2026, 8, 26, 0, 0, 0, tzinfo=timezone.utc)
SHA_A = "a" * 64
SHA_B = "b" * 64


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _write_case(tmp_path: Path) -> Path:
    case = tmp_path / "case"
    repo = case / "repo"
    keys = case / "keys"
    evidence = case / "evidence"
    runtime = case / "candidate-runtime"
    repo.mkdir(parents=True)
    keys.mkdir()
    evidence.mkdir()
    runtime.mkdir(mode=0o700)
    (case / "ledger.sqlite3").write_bytes(b"")
    (keys / "sidecar.key").write_bytes(b"s" * 32)
    (keys / "developer.key").write_bytes(b"d" * 32)
    os.chmod(keys / "sidecar.key", 0o600)
    os.chmod(keys / "developer.key", 0o600)

    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "OWP Test")
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-m", "fixture")
    revision = _git(repo, "rev-parse", "HEAD")

    stable = {
        "schema_version": "openworkproof-dsh-case/0.1",
        "work_order_digest": SHA_A,
        "source_revision": revision,
        "allowed_path_roots": ["README.md"],
        "denied_path_roots": ["secrets"],
        "allowed_tools": ["owp_apply_patch", "owp_run_tests"],
        "test_profile_digest": SHA_B,
        "mode": "enforce",
    }
    manifest = {
        **stable,
        "case_id": dsh_case_id(stable),
        "repository_root": str(repo),
        "ledger_path": str(case / "ledger.sqlite3"),
        "evidence_root": str(evidence),
        "candidate_runtime_root": str(runtime),
        "candidate_workspace_id": "c" * 64,
        "verifier_socket_path": str(case / "verifier.sock"),
        "sidecar_key_path": str(keys / "sidecar.key"),
        "developer_key_path": str(keys / "developer.key"),
    }
    (case / "case.json").write_text(
        json.dumps(manifest, sort_keys=True),
        encoding="utf-8",
    )
    return case


def _execution(*, call_id: str = "call-1") -> DshExecutionIdentityV01:
    return DshExecutionIdentityV01(
        session_id="session-1",
        call_id=call_id,
        root_call_id="call-1",
        tool_name="owp_apply_patch",
        arguments_digest=SHA_A,
    )


def test_case_rejects_manager_or_acceptor_private_keys(tmp_path: Path) -> None:
    case = _write_case(tmp_path)
    (case / "acceptor-private-key.hex").write_text("00" * 32)

    with pytest.raises(DshCaseError, match="human private key"):
        load_dsh_case(case)


def test_case_rejects_verifier_private_key_file(tmp_path: Path) -> None:
    case = _write_case(tmp_path)
    (case / "evidence" / "verifier-private-key.hex").write_text("00" * 32)

    with pytest.raises(DshCaseError, match="human private key"):
        load_dsh_case(case)


def test_case_requires_exact_repository_revision(tmp_path: Path) -> None:
    case = _write_case(tmp_path)
    _git(case / "repo", "commit", "--allow-empty", "-m", "drift")

    with pytest.raises(DshCaseError, match="source revision"):
        load_dsh_case(case)


def test_case_rejects_key_mode_broader_than_0600(tmp_path: Path) -> None:
    case = _write_case(tmp_path)
    os.chmod(case / "keys" / "sidecar.key", 0o640)

    with pytest.raises(DshCaseError, match="0600"):
        load_dsh_case(case)


def test_case_rejects_symlinked_runtime_path(tmp_path: Path) -> None:
    case = _write_case(tmp_path)
    original = case / "evidence"
    moved = case / "evidence-real"
    original.rename(moved)
    original.symlink_to(moved, target_is_directory=True)

    with pytest.raises(DshCaseError, match="symlink"):
        load_dsh_case(case)


def test_case_rejects_unknown_control_file(tmp_path: Path) -> None:
    case = _write_case(tmp_path)
    (case / "unexpected.txt").write_text("unexpected", encoding="utf-8")

    with pytest.raises(DshCaseError, match="unknown case control entry"):
        load_dsh_case(case)


def test_case_rejects_unknown_file_in_key_control_directory(
    tmp_path: Path,
) -> None:
    case = _write_case(tmp_path)
    (case / "keys" / "extra.key").write_bytes(b"x" * 32)
    os.chmod(case / "keys" / "extra.key", 0o600)

    with pytest.raises(DshCaseError, match="unknown case control entry"):
        load_dsh_case(case)


def test_case_rejects_parent_traversal_in_runtime_path(tmp_path: Path) -> None:
    case = _write_case(tmp_path)
    manifest_path = case / "case.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["repository_root"] = str(case / "repo" / ".." / "..")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(DshCaseError, match="canonical|escapes"):
        load_dsh_case(case)


def test_case_requires_distinct_sidecar_and_developer_keys(tmp_path: Path) -> None:
    case = _write_case(tmp_path)
    manifest_path = case / "case.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["developer_key_path"] = manifest["sidecar_key_path"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(DshCaseError, match="distinct"):
        load_dsh_case(case)


def test_valid_case_loads_exact_runtime_paths(tmp_path: Path) -> None:
    case = _write_case(tmp_path)

    loaded = load_dsh_case(case)

    assert loaded.repository_root == str((case / "repo").resolve())
    assert loaded.candidate_runtime_root == str(
        (case / "candidate-runtime").resolve()
    )
    assert loaded.candidate_workspace_id == "c" * 64
    assert loaded.verifier_socket_path == str(case / "verifier.sock")
    assert loaded.allowed_tools == ("owp_apply_patch", "owp_run_tests")


def test_case_requires_private_candidate_runtime_root(tmp_path: Path) -> None:
    case = _write_case(tmp_path)
    os.chmod(case / "candidate-runtime", 0o755)

    with pytest.raises(DshCaseError, match="candidate runtime root"):
        load_dsh_case(case)


def test_case_requires_candidate_runtime_outside_frozen_source(
    tmp_path: Path,
) -> None:
    case = _write_case(tmp_path)
    manifest_path = case / "case.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["candidate_runtime_root"] = manifest["repository_root"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(DshCaseError, match="candidate runtime root.*repository"):
        load_dsh_case(case)


def test_case_requires_verifier_transport_for_test_tool(tmp_path: Path) -> None:
    case = _write_case(tmp_path)
    manifest_path = case / "case.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    del manifest["verifier_socket_path"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(DshCaseError, match="Verifier transport"):
        load_dsh_case(case)


def test_case_allows_external_verifier_transport_address(tmp_path: Path) -> None:
    case = _write_case(tmp_path)
    manifest_path = case / "case.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["verifier_socket_path"] = str(tmp_path / "outside.sock")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    loaded = load_dsh_case(case)

    assert loaded.verifier_socket_path == str(tmp_path / "outside.sock")


def test_case_rejects_relative_verifier_transport_address(tmp_path: Path) -> None:
    case = _write_case(tmp_path)
    manifest_path = case / "case.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["verifier_socket_path"] = "verifier.sock"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(DshCaseError, match="transport path must be absolute"):
        load_dsh_case(case)


def test_decision_token_is_exact_one_use() -> None:
    store = DecisionTokenStore(clock=lambda: NOW)
    token = store.issue(_execution(), expires_at=NOW + timedelta(seconds=30))

    assert store.consume(token, _execution())
    assert not store.consume(token, _execution())


def test_mismatched_execution_consumes_token_fail_closed() -> None:
    store = DecisionTokenStore(clock=lambda: NOW)
    token = store.issue(_execution(), expires_at=NOW + timedelta(seconds=30))

    assert not store.consume(token, _execution(call_id="call-2"))
    assert not store.consume(token, _execution())


def test_expired_decision_token_is_rejected() -> None:
    current = [NOW]
    store = DecisionTokenStore(clock=lambda: current[0])
    token = store.issue(_execution(), expires_at=NOW + timedelta(seconds=1))
    current[0] = NOW + timedelta(seconds=2)

    assert not store.consume(token, _execution())
