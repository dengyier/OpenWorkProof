from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from openworkproof.integrity import (
    build_failure_signature,
    population_observation_payload,
)
from openworkproof.models import (
    FailureSignatureV05,
    PopulationContractV05,
    population_contract_id,
    population_member_digest,
)
from openworkproof.scope import (
    _selector_engine_digest,
    _selector_spec_bytes,
    observe_git_population,
    observe_pytest_population,
    scope_member_id,
)


def _contract(
    *,
    rule_id: str,
    selector_kind: str,
    member_kind: str,
    spec_payload: dict[str, Any],
    declared_ids: list[str],
    engine_digest: str | None = None,
) -> PopulationContractV05:
    spec = _selector_spec_bytes(selector_kind, spec_payload)
    payload = {
        "selector_rule_id": rule_id,
        "member_kind": member_kind,
        "selector_spec_digest": hashlib.sha256(spec).hexdigest(),
        "selector_engine_digest": (
            engine_digest if engine_digest is not None else _selector_engine_digest()
        ),
        "declared_selected_member_ids": sorted(set(declared_ids)),
        "minimum_eligible_count": 1,
        "minimum_selected_count": 1,
        "maximum_eligible_count": 4096,
        "maximum_selected_count": 4096,
        "minimum_capture_numerator": 1,
        "minimum_capture_denominator": 100,
        "empty_population_policy": "unknown",
        "required_population_evidence_purposes": [
            "eligible-population",
            "selected-population",
        ],
    }
    return PopulationContractV05.model_validate(
        {"contract_id": population_contract_id(payload), **payload}
    )


def _git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True, exist_ok=True)
    for command in (
        ["git", "init", "-q"],
        ["git", "config", "user.email", "agent@example.test"],
        ["git", "config", "user.name", "Agent"],
    ):
        subprocess.run(command, cwd=repo, check=True, capture_output=True)
    return repo


def _commit(repo: Path, files: dict[str, str], message: str) -> str:
    for relative, content in files.items():
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", message], cwd=repo, check=True, capture_output=True
    )
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def _replay_check(result, eligible_ids: list[str], selected_ids: list[str]) -> None:
    assert result.status == "satisfied"
    assert result.reason_codes == ()
    observation = result.observation
    assert observation is not None
    assert observation.eligible_seen == len(eligible_ids)
    assert observation.selected_count == len(selected_ids)
    assert observation.eligible_population_digest == population_member_digest(
        tuple(sorted(eligible_ids))
    )
    assert observation.selected_population_digest == population_member_digest(
        tuple(sorted(selected_ids))
    )
    if observation.eligible_seen == 0 or observation.selected_count == 0:
        assert (observation.capture_numerator, observation.capture_denominator) == (0, 1)
    else:
        import math as _math

        divisor = _math.gcd(len(selected_ids), len(eligible_ids))
        assert (observation.capture_numerator, observation.capture_denominator) == (
            len(selected_ids) // divisor,
            len(eligible_ids) // divisor,
        )
    inventory = dict(result.evidence_inventory)
    for ref in observation.evidence_refs:
        content = inventory[ref.sha256]
        assert hashlib.sha256(content).hexdigest() == ref.sha256
        assert len(content) == ref.size_bytes



def _fake_python(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\nset -eu\n" + body)
    path.chmod(0o755)
    return path


PYTEST_NODES = (
    "tests/test_a.py::test_a1",
    "tests/test_b.py::test_b1",
    "tests/test_b.py::test_b2",
    "tests/test_c.py::test_c1",
    "tests/test_d.py::test_d1",
)


def _collect_fake(
    tmp_path: Path,
    *,
    name: str,
    selection: list[str] | None = None,
    extra_body: str = "",
) -> Path:
    body = f"""
test "$1" = "-I"
test "$2" = "-m"
test "$3" = "pytest"
test "$4" = "--collect-only"
test "$5" = "-q"
test "$PYTEST_DISABLE_PLUGIN_AUTOLOAD" = "1"
test "$LC_ALL" = "C.UTF-8"
test "$TZ" = "UTC"
{extra_body}
"""
    if selection is None:
        body += "printf '%s\\n' " + " ".join(
            f"'{node}'" for node in PYTEST_NODES
        ) + "\n"
    else:
        body += "if [ \"$#\" -eq 5 ]; then\n"
        body += "printf '%s\\n' " + " ".join(
            f"'{node}'" for node in PYTEST_NODES
        ) + "\n"
        body += "else\n"
        for node in selection:
            body += f"printf '%s\\n' '{node}'\n"
        body += "fi\n"
    return _fake_python(tmp_path / name, body)


PYTEST_FILES = {
    "tests/test_a.py": "def test_a1():\n    assert True\n",
    "tests/test_b.py": "def test_b1():\n    assert True\n\ndef test_b2():\n    assert True\n",
    "tests/test_c.py": "def test_c1():\n    assert True\n",
    "tests/test_d.py": "def test_d1():\n    assert True\n",
}


@pytest.fixture
def pytest_repo(tmp_path: Path):
    repo = _git_repo(tmp_path)
    head = _commit(repo, PYTEST_FILES, "baseline")
    return repo, head


def test_pytest_adapter_observes_eligible_and_selected(
    pytest_repo, tmp_path: Path
) -> None:
    repo, head = pytest_repo
    selector_args = ["tests/test_a.py", "tests/test_b.py::test_b2"]
    python = _collect_fake(
        tmp_path,
        name="fake-python",
        selection=["tests/test_a.py::test_a1", "tests/test_b.py::test_b2"],
    )
    eligible_nodes = list(PYTEST_NODES)
    selected_nodes = ["tests/test_a.py::test_a1", "tests/test_b.py::test_b2"]
    declared = [scope_member_id("test_case", node) for node in selected_nodes]
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="pytest_collection",
        member_kind="test_case",
        spec_payload={
            "source_revision": head,
            "candidate_commit": head,
            "python_executable_digest": hashlib.sha256(
                python.read_bytes()
            ).hexdigest(),
            "argv": ["-I", "-m", "pytest", "--collect-only", "-q"],
            "timeout_seconds": 60,
        },
        declared_ids=declared,
    )
    result = observe_pytest_population(
        repo,
        contract=contract,
        source_revision=head,
        candidate_commit=head,
        python_executable=python,
        selector_args=selector_args,
        timeout_seconds=60,
    )
    eligible_ids = [scope_member_id("test_case", node) for node in eligible_nodes]
    selected_ids = [scope_member_id("test_case", node) for node in selected_nodes]
    _replay_check(result, eligible_ids, selected_ids)
    assert result.selected_member_ids == tuple(selected_ids)


def test_pytest_adapter_deterministic_replay(pytest_repo, tmp_path: Path) -> None:
    repo, head = pytest_repo
    selector_args = ["tests/test_c.py"]
    python = _collect_fake(
        tmp_path,
        name="fake-python",
        selection=["tests/test_c.py::test_c1"],
    )
    declared = [scope_member_id("test_case", "tests/test_c.py::test_c1")]
    spec_payload = {
        "source_revision": head,
        "candidate_commit": head,
        "python_executable_digest": hashlib.sha256(python.read_bytes()).hexdigest(),
        "argv": ["-I", "-m", "pytest", "--collect-only", "-q"],
        "timeout_seconds": 60,
    }
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="pytest_collection",
        member_kind="test_case",
        spec_payload=spec_payload,
        declared_ids=declared,
    )
    kwargs = dict(
        repo=repo,
        contract=contract,
        source_revision=head,
        candidate_commit=head,
        python_executable=python,
        selector_args=selector_args,
        timeout_seconds=60,
    )
    first = observe_pytest_population(**kwargs)
    second = observe_pytest_population(**kwargs)
    assert first.observation is not None and second.observation is not None
    assert (
        first.observation.eligible_population_digest
        == second.observation.eligible_population_digest
    )
    assert (
        first.observation.selected_population_digest
        == second.observation.selected_population_digest
    )
    assert dict(first.evidence_inventory) == dict(second.evidence_inventory)


def test_pytest_adapter_selector_yielding_zero_is_mismatched(
    pytest_repo, tmp_path: Path
) -> None:
    repo, head = pytest_repo
    selector_args = ["tests/test_zz.py"]
    python = _collect_fake(
        tmp_path,
        name="fake-python",
        selection=[],
    )
    declared = [scope_member_id("test_case", "tests/test_c.py::test_c1")]
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="pytest_collection",
        member_kind="test_case",
        spec_payload={
            "source_revision": head,
            "candidate_commit": head,
            "python_executable_digest": hashlib.sha256(python.read_bytes()).hexdigest(),
            "argv": ["-I", "-m", "pytest", "--collect-only", "-q"],
            "timeout_seconds": 60,
        },
        declared_ids=declared,
    )
    result = observe_pytest_population(
        repo,
        contract=contract,
        source_revision=head,
        candidate_commit=head,
        python_executable=python,
        selector_args=selector_args,
        timeout_seconds=60,
    )
    assert result.status == "indeterminate"
    assert "SCOPE_SELECTOR_MISMATCH" in result.reason_codes


def test_pytest_adapter_no_eligible_nodes(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    head = _commit(repo, {"README.md": "no tests"}, "empty")
    python = _fake_python(
        tmp_path / "fake-python",
        '\nprintf ""\nexit 5\n',
    )
    declared = [scope_member_id("test_case", "tests/test_c.py::test_c1")]
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="pytest_collection",
        member_kind="test_case",
        spec_payload={
            "source_revision": head,
            "candidate_commit": head,
            "python_executable_digest": hashlib.sha256(python.read_bytes()).hexdigest(),
            "argv": ["-I", "-m", "pytest", "--collect-only", "-q"],
            "timeout_seconds": 60,
        },
        declared_ids=declared,
    )
    result = observe_pytest_population(
        repo,
        contract=contract,
        source_revision=head,
        candidate_commit=head,
        python_executable=python,
        selector_args=[],
        timeout_seconds=60,
    )
    assert result.status == "satisfied"
    assert result.reason_codes == ()
    assert result.observation is not None
    assert result.observation.eligible_seen == 0
    assert result.observation.selected_count == 0
    assert (result.observation.capture_numerator, result.observation.capture_denominator) == (0, 1)


def test_pytest_adapter_collection_error(pytest_repo, tmp_path: Path) -> None:
    repo, head = pytest_repo
    python = _fake_python(tmp_path / "fake-python", "\nexit 1\n")
    declared = [scope_member_id("test_case", "tests/test_c.py::test_c1")]
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="pytest_collection",
        member_kind="test_case",
        spec_payload={
            "source_revision": head,
            "candidate_commit": head,
            "python_executable_digest": hashlib.sha256(python.read_bytes()).hexdigest(),
            "argv": ["-I", "-m", "pytest", "--collect-only", "-q"],
            "timeout_seconds": 60,
        },
        declared_ids=declared,
    )
    result = observe_pytest_population(
        repo,
        contract=contract,
        source_revision=head,
        candidate_commit=head,
        python_executable=python,
        selector_args=[],
        timeout_seconds=60,
    )
    assert result.status == "indeterminate"
    assert "SCOPE_SELECTOR_MISMATCH" in result.reason_codes


def test_pytest_adapter_timeout(pytest_repo, tmp_path: Path) -> None:
    repo, head = pytest_repo
    python = _fake_python(tmp_path / "fake-python", "\nsleep 30\n")
    declared = [scope_member_id("test_case", "tests/test_c.py::test_c1")]
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="pytest_collection",
        member_kind="test_case",
        spec_payload={
            "source_revision": head,
            "candidate_commit": head,
            "python_executable_digest": hashlib.sha256(python.read_bytes()).hexdigest(),
            "argv": ["-I", "-m", "pytest", "--collect-only", "-q"],
            "timeout_seconds": 1,
        },
        declared_ids=declared,
    )
    result = observe_pytest_population(
        repo,
        contract=contract,
        source_revision=head,
        candidate_commit=head,
        python_executable=python,
        selector_args=[],
        timeout_seconds=1,
    )
    assert result.status == "indeterminate"
    assert "SCOPE_SELECTOR_MISMATCH" in result.reason_codes


def test_pytest_adapter_engine_drift(pytest_repo, tmp_path: Path) -> None:
    repo, head = pytest_repo
    python = _collect_fake(tmp_path, name="fake-python", selection=[])
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="pytest_collection",
        member_kind="test_case",
        spec_payload={
            "source_revision": head,
            "candidate_commit": head,
            "python_executable_digest": hashlib.sha256(python.read_bytes()).hexdigest(),
            "argv": ["-I", "-m", "pytest", "--collect-only", "-q"],
            "timeout_seconds": 60,
        },
        declared_ids=[scope_member_id("test_case", "tests/test_c.py::test_c1")],
        engine_digest="f" * 64,
    )
    result = observe_pytest_population(
        repo,
        contract=contract,
        source_revision=head,
        candidate_commit=head,
        python_executable=python,
        selector_args=[],
        timeout_seconds=60,
    )
    assert result.status == "indeterminate"
    assert "SCOPE_SELECTOR_MISMATCH" in result.reason_codes


def test_git_adapter_add_modify_delete_rename(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    source = _commit(
        repo,
        {"src/a.py": "a", "src/b.py": "b"},
        "baseline",
    )
    candidate = _commit(
        repo,
        {"src/c.py": "c", "src/b.py": "b2"},
        "changes",
    )
    subprocess.run(["git", "mv", "src/a.py", "src/a2.py"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "rm", "-q", "src/c.py"], cwd=repo, check=True, capture_output=True)
    candidate = _commit(repo, {}, "renamed and deleted")
    eligible_ids = [
        scope_member_id("source_file", path)
        for path in ("src/a.py", "src/a2.py", "src/b.py")
    ]
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="git_diff_closure",
        member_kind="source_file",
        spec_payload={
            "source_revision": source,
            "candidate_commit": candidate,
            "git_diff_mode": "name-status-z-find-renames",
        },
        declared_ids=eligible_ids,
    )
    result = observe_git_population(
        repo,
        contract=contract,
        source_revision=source,
        candidate_commit=candidate,
    )
    _replay_check(result, eligible_ids, eligible_ids)


def test_git_adapter_allowlist_exclusion_and_required(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    source = _commit(repo, {"src/a.py": "a"}, "baseline")
    candidate = _commit(
        repo, {"src/b.py": "b", "src/c.py": "c"}, "changes"
    )
    b_id = scope_member_id("source_file", "src/b.py")
    c_id = scope_member_id("source_file", "src/c.py")
    spec_payload = {
        "source_revision": source,
        "candidate_commit": candidate,
        "git_diff_mode": "name-status-z-find-renames",
    }
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="git_diff_closure",
        member_kind="source_file",
        spec_payload=spec_payload,
        declared_ids=[b_id],
    )
    result = observe_git_population(
        repo,
        contract=contract,
        source_revision=source,
        candidate_commit=candidate,
        allowlist_locators=["src/b.py"],
    )
    _replay_check(result, [b_id, c_id], [b_id])

    excluded_contract = _contract(
        rule_id="1" * 64,
        selector_kind="git_diff_closure",
        member_kind="source_file",
        spec_payload=spec_payload,
        declared_ids=[c_id],
    )
    excluded_result = observe_git_population(
        repo,
        contract=excluded_contract,
        source_revision=source,
        candidate_commit=candidate,
        excluded_locators=["src/b.py"],
    )
    _replay_check(excluded_result, [b_id, c_id], [c_id])

    missing_contract = _contract(
        rule_id="1" * 64,
        selector_kind="git_diff_closure",
        member_kind="source_file",
        spec_payload=spec_payload,
        declared_ids=[b_id],
    )
    missing = observe_git_population(
        repo,
        contract=missing_contract,
        source_revision=source,
        candidate_commit=candidate,
        required_locators=["src/zz.py"],
    )
    assert missing.status == "indeterminate"
    assert "SCOPE_REQUIRED_TARGET_MISSING" in missing.reason_codes

    forced_contract = _contract(
        rule_id="1" * 64,
        selector_kind="git_diff_closure",
        member_kind="source_file",
        spec_payload=spec_payload,
        declared_ids=[b_id, c_id],
    )
    forced = observe_git_population(
        repo,
        contract=forced_contract,
        source_revision=source,
        candidate_commit=candidate,
        allowlist_locators=["src/b.py"],
        required_locators=["src/c.py"],
    )
    _replay_check(forced, [b_id, c_id], [b_id, c_id])


def test_git_adapter_rejects_unsafe_inputs(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    source = _commit(repo, {"src/a.py": "a"}, "baseline")
    candidate = _commit(repo, {"src/b.py": "b"}, "changes")
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="git_diff_closure",
        member_kind="source_file",
        spec_payload={
            "source_revision": source,
            "candidate_commit": candidate,
            "git_diff_mode": "name-status-z-find-renames",
        },
        declared_ids=[scope_member_id("source_file", "src/b.py")],
    )
    with pytest.raises(ValueError, match="traverse"):
        observe_git_population(
            repo,
            contract=contract,
            source_revision=source,
            candidate_commit=candidate,
            allowlist_locators=["../evil.py"],
        )
    (repo / "src/dirty.py").write_text("dirty", encoding="utf-8")
    with pytest.raises(ValueError, match="uncommitted"):
        observe_git_population(
            repo,
            contract=contract,
            source_revision=source,
            candidate_commit=candidate,
        )


def test_git_adapter_rejects_symlink_and_revision_drift(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    source = _commit(repo, {"src/a.py": "a"}, "baseline")
    link = repo / "src/link.py"
    link.symlink_to("a.py")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    candidate = _commit(repo, {}, "symlink")
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="git_diff_closure",
        member_kind="source_file",
        spec_payload={
            "source_revision": source,
            "candidate_commit": candidate,
            "git_diff_mode": "name-status-z-find-renames",
        },
        declared_ids=[scope_member_id("source_file", "src/link.py")],
    )
    with pytest.raises(ValueError, match="symlink"):
        observe_git_population(
            repo,
            contract=contract,
            source_revision=source,
            candidate_commit=candidate,
        )
    drifted = _contract(
        rule_id="1" * 64,
        selector_kind="git_diff_closure",
        member_kind="source_file",
        spec_payload={
            "source_revision": candidate,
            "candidate_commit": source,
            "git_diff_mode": "name-status-z-find-renames",
        },
        declared_ids=[scope_member_id("source_file", "src/a.py")],
    )
    result = observe_git_population(
        repo,
        contract=drifted,
        source_revision=source,
        candidate_commit=candidate,
    )
    assert result.status == "indeterminate"
    assert "SCOPE_SELECTOR_MISMATCH" in result.reason_codes


def test_git_adapter_unchanged_count_changed_identity(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    source = _commit(repo, {"src/a.py": "a"}, "baseline")
    first = _commit(repo, {"src/x.py": "x"}, "x")
    common = {
        "rule_id": "1" * 64,
        "selector_kind": "git_diff_closure",
        "member_kind": "source_file",
        "engine_digest": None,
    }
    first_contract = _contract(
        **common,
        spec_payload={
            "source_revision": source,
            "candidate_commit": first,
            "git_diff_mode": "name-status-z-find-renames",
        },
        declared_ids=[scope_member_id("source_file", "src/x.py")],
    )
    second_repo = _git_repo(tmp_path / "second")
    second_source = _commit(second_repo, {"src/a.py": "a"}, "baseline")
    second_candidate = _commit(second_repo, {"src/y.py": "y"}, "y")
    second_contract = _contract(
        **common,
        spec_payload={
            "source_revision": second_source,
            "candidate_commit": second_candidate,
            "git_diff_mode": "name-status-z-find-renames",
        },
        declared_ids=[scope_member_id("source_file", "src/y.py")],
    )
    first_result = observe_git_population(
        repo, contract=first_contract, source_revision=source, candidate_commit=first
    )
    second_result = observe_git_population(
        second_repo,
        contract=second_contract,
        source_revision=second_source,
        candidate_commit=second_candidate,
    )
    assert first_result.observation is not None
    assert second_result.observation is not None
    assert first_result.observation.eligible_seen == 1
    assert second_result.observation.eligible_seen == 1
    assert (
        first_result.observation.eligible_population_digest
        != second_result.observation.eligible_population_digest
    )


def test_failure_signature_builder_sorts_and_stays_closed() -> None:
    first = build_failure_signature(
        execution_status="completed",
        exit_codes=[1],
        reason_codes=["MUTATION_CAUGHT"],
        predicate_ids=["tests_passed"],
        evidence_purposes=["test-result"],
    )
    second = build_failure_signature(
        execution_status="completed",
        exit_codes=[1],
        reason_codes=["MUTATION_CAUGHT"],
        predicate_ids=["tests_passed"],
        evidence_purposes=["test-result"],
    )
    assert first == second
    unsorted = build_failure_signature(
        execution_status="completed",
        exit_codes=[2, 1],
        reason_codes=["MUTATION_CAUGHT"],
        predicate_ids=["tests_passed"],
        evidence_purposes=["test-result"],
    )
    assert unsorted.exit_codes == (1, 2)
    with pytest.raises(Exception):
        FailureSignatureV05.model_validate(
            {
                "execution_status": "completed",
                "exit_codes": [1],
                "reason_codes": ["MUTATION_CAUGHT"],
                "predicate_ids": ["tests_passed"],
                "required_evidence_purposes": ["test-result"],
                "stderr": "noise",
            }
        )


def test_population_observation_payload_replays() -> None:
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="git_diff_closure",
        member_kind="source_file",
        spec_payload={
            "source_revision": "a" * 40,
            "candidate_commit": "b" * 40,
            "git_diff_mode": "name-status-z-find-renames",
        },
        declared_ids=[scope_member_id("source_file", "src/b.py")],
    )
    eligible = [
        scope_member_id("source_file", "src/a.py"),
        scope_member_id("source_file", "src/b.py"),
    ]
    selected = [scope_member_id("source_file", "src/b.py")]
    payload, inventory = population_observation_payload(
        contract=contract,
        eligible_member_ids=eligible,
        selected_member_ids=selected,
        observed_at="2026-01-01T00:10:00Z",
    )
    assert payload["eligible_seen"] == 2
    assert payload["selected_count"] == 1
    assert payload["capture_numerator"] == 1
    assert payload["capture_denominator"] == 2
    for ref in payload["evidence_refs"]:
        content = inventory[ref["sha256"]]
        assert hashlib.sha256(content).hexdigest() == ref["sha256"]


def test_pytest_adapter_required_node_omission(pytest_repo, tmp_path: Path) -> None:
    repo, head = pytest_repo
    selector_args = ["tests/test_a.py"]
    python = _collect_fake(
        tmp_path,
        name="fake-python",
        selection=["tests/test_a.py::test_a1"],
    )
    declared = [scope_member_id("test_case", "tests/test_a.py::test_a1")]
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="pytest_collection",
        member_kind="test_case",
        spec_payload={
            "source_revision": head,
            "candidate_commit": head,
            "python_executable_digest": hashlib.sha256(python.read_bytes()).hexdigest(),
            "argv": ["-I", "-m", "pytest", "--collect-only", "-q"],
            "timeout_seconds": 60,
        },
        declared_ids=declared,
    )
    result = observe_pytest_population(
        repo,
        contract=contract,
        source_revision=head,
        candidate_commit=head,
        python_executable=python,
        selector_args=selector_args,
        timeout_seconds=60,
        required_node_ids=["tests/test_zz.py::test_zz"],
    )
    assert result.status == "indeterminate"
    assert "SCOPE_REQUIRED_TARGET_MISSING" in result.reason_codes


def test_git_adapter_engine_drift(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    source = _commit(repo, {"src/a.py": "a"}, "baseline")
    candidate = _commit(repo, {"src/b.py": "b"}, "changes")
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="git_diff_closure",
        member_kind="source_file",
        spec_payload={
            "source_revision": source,
            "candidate_commit": candidate,
            "git_diff_mode": "name-status-z-find-renames",
        },
        declared_ids=[scope_member_id("source_file", "src/b.py")],
        engine_digest="f" * 64,
    )
    result = observe_git_population(
        repo,
        contract=contract,
        source_revision=source,
        candidate_commit=candidate,
    )
    assert result.status == "indeterminate"
    assert "SCOPE_SELECTOR_MISMATCH" in result.reason_codes


def test_adapter_spec_digest_uses_v03_rule_encoding(tmp_path: Path) -> None:
    """The v0.3 selector builder and the v0.5 adapter must share one spec
    encoding so a contract bound to the rule digest is satisfiable."""
    from openworkproof.scope import select_git_diff_closure

    repo = _git_repo(tmp_path)
    source = _commit(repo, {"src/a.py": "a"}, "baseline")
    candidate = _commit(repo, {"src/b.py": "b"}, "changes")
    execution = select_git_diff_closure(
        repo, source_revision=source, candidate_commit=candidate
    )
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="git_diff_closure",
        member_kind="source_file",
        spec_payload={
            "source_revision": source,
            "candidate_commit": candidate,
            "git_diff_mode": "name-status-z-find-renames",
        },
        declared_ids=[scope_member_id("source_file", "src/b.py")],
    )
    assert contract.selector_spec_digest == hashlib.sha256(
        execution.selector_spec_bytes
    ).hexdigest()
    result = observe_git_population(
        repo,
        contract=contract,
        source_revision=source,
        candidate_commit=candidate,
    )
    assert result.status == "satisfied"


def test_adapter_observed_at_injection_makes_replay_byte_identical(
    pytest_repo, tmp_path: Path
) -> None:
    repo, head = pytest_repo
    selector_args = ["tests/test_c.py"]
    python = _collect_fake(
        tmp_path,
        name="fake-python",
        selection=["tests/test_c.py::test_c1"],
    )
    declared = [scope_member_id("test_case", "tests/test_c.py::test_c1")]
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="pytest_collection",
        member_kind="test_case",
        spec_payload={
            "source_revision": head,
            "candidate_commit": head,
            "python_executable_digest": hashlib.sha256(python.read_bytes()).hexdigest(),
            "argv": ["-I", "-m", "pytest", "--collect-only", "-q"],
            "timeout_seconds": 60,
        },
        declared_ids=declared,
    )
    kwargs = dict(
        repo=repo,
        contract=contract,
        source_revision=head,
        candidate_commit=head,
        python_executable=python,
        selector_args=selector_args,
        timeout_seconds=60,
        observed_at="2026-01-01T00:10:00Z",
    )
    first = observe_pytest_population(**kwargs)
    second = observe_pytest_population(**kwargs)
    assert first.observation is not None and second.observation is not None
    assert first.observation.model_dump(mode="json") == second.observation.model_dump(
        mode="json"
    )
