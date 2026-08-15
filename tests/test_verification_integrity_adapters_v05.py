from __future__ import annotations

import hashlib
import json
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
    _CANONICAL_COLLECT_CONFTEST,
    _CANONICAL_COLLECT_INI,
    _CANONICAL_PYTEST_ENVIRONMENT,
    _selector_engine_digest,
    _selector_spec_bytes,
    observe_git_population,
    observe_pytest_population,
    scope_member_id,
)

_COLLECT_CONFTEST_DIGEST = hashlib.sha256(
    _CANONICAL_COLLECT_CONFTEST.encode("utf-8")
).hexdigest()
_COLLECT_INI_DIGEST = hashlib.sha256(
    _CANONICAL_COLLECT_INI.encode("utf-8")
).hexdigest()


def _contract(
    *,
    rule_id: str,
    selector_kind: str,
    member_kind: str,
    spec_payload: dict[str, Any],
    declared_ids: list[str],
    engine_digest: str | None = None,
    python: Path | None = None,
    selector_args: list[str] | None = None,
    required_node_ids: list[str] | None = None,
    allowlist_locators: list[str] | None = None,
    excluded_locators: list[str] | None = None,
    required_locators: list[str] | None = None,
) -> PopulationContractV05:
    payload_fields = dict(spec_payload)
    if selector_kind == "pytest_collection":
        for key in (
            "python_executable_digest",
            "argv",
            "python_invocation",
            "pyvenv_cfg_digest",
        ):
            payload_fields.pop(key, None)
        payload_fields.update(
            {
                "python_invocation": str(
                    python.parent.resolve(strict=True) / python.name
                ),
                "python_executable_digest": hashlib.sha256(
                    Path(os.path.realpath(python)).read_bytes()
                ).hexdigest(),
                "pyvenv_cfg_digest": (
                    hashlib.sha256(
                        (python.parent.parent / "pyvenv.cfg").read_bytes()
                    ).hexdigest()
                    if (python.parent.parent / "pyvenv.cfg").is_file()
                    else None
                ),
                "argv": [
                    "-I",
                    "-m",
                    "pytest",
                    "--collect-only",
                    "-q",
                    "-c",
                    "owp-collect.ini",
                ],
                "selector_args": list(selector_args or []),
                "required_node_ids": sorted(set(required_node_ids or [])),
                "environment": dict(_CANONICAL_PYTEST_ENVIRONMENT),
                "collector_ini_digest": _COLLECT_INI_DIGEST,
                "collector_conftest_digest": _COLLECT_CONFTEST_DIGEST,
                "collector_channel": "pipe-fd-3-single-document-stdout-crosscheck",
            }
        )
    elif selector_kind == "git_diff_closure":
        payload_fields.update(
            {
                "allowlist_locators": sorted(set(allowlist_locators or [])),
                "excluded_locators": sorted(set(excluded_locators or [])),
                "required_locators": sorted(set(required_locators or [])),
            }
        )
    spec = _selector_spec_bytes(selector_kind, payload_fields)
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
    import json as _json

    body = f"""
test "$1" = "-I"
test "$2" = "-m"
test "$3" = "pytest"
test "$4" = "--collect-only"
test "$5" = "-q"
test "$6" = "-c"
test "$7" = "owp-collect.ini"
test "$PYTEST_DISABLE_PLUGIN_AUTOLOAD" = "1"
test "$LC_ALL" = "C.UTF-8"
test "$TZ" = "UTC"
test -z "${{OWP_COLLECT_OUTPUT:-}}"
{extra_body}
"""

    def emit(nodes: list[str]) -> str:
        document = _json.dumps(
            {"node_ids": sorted(nodes)}, sort_keys=True, separators=(",", ":")
        )
        # Emulate pytest's own reporter: one node-id line per collected
        # test on stdout, plus the canonical document on fd 3.
        ordered = sorted(nodes)
        lines = "".join(f"printf '%s\\n' '{node}'\n" for node in ordered)
        return lines + f"printf '%s\\n' '{document}' >&3\n"

    if selection is None:
        body += emit(list(PYTEST_NODES))
    else:
        body += 'if [ "$#" -eq 7 ]; then\n'
        body += emit(list(PYTEST_NODES))
        body += "else\n"
        body += emit(selection)
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
        python=python,
        selector_args=selector_args,
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
        python=python,
        selector_args=selector_args,
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
        python=python,
        selector_args=selector_args,
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
        '\nprintf \'{"node_ids":[]}\' >&3\nexit 5\n',
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
        python=python,
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
        python=python,
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
        python=python,
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
        python=python,
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
        allowlist_locators=["src/b.py"],
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
        excluded_locators=["src/b.py"],
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
        required_locators=["src/zz.py"],
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
        allowlist_locators=["src/b.py"],
        required_locators=["src/c.py"],
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
        python=python,
        selector_args=selector_args,
        required_node_ids=["tests/test_zz.py::test_zz"],
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
    """The v0.5 adapter spec extends the frozen v0.3 rule encoding with the
    closed selector parameter fields; a contract bound to the extended
    encoding with empty parameters is satisfiable by the adapter."""
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
        python=python,
        selector_args=selector_args,
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


def test_git_adapter_required_overlapping_selection_does_not_crash(
    tmp_path: Path,
) -> None:
    repo = _git_repo(tmp_path)
    source = _commit(repo, {"src/a.py": "a"}, "baseline")
    candidate = _commit(repo, {"src/b.py": "b", "src/c.py": "c"}, "changes")
    b_id = scope_member_id("source_file", "src/b.py")
    c_id = scope_member_id("source_file", "src/c.py")
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="git_diff_closure",
        member_kind="source_file",
        spec_payload={
            "source_revision": source,
            "candidate_commit": candidate,
            "git_diff_mode": "name-status-z-find-renames",
        },
        required_locators=["src/b.py"],
        declared_ids=[b_id, c_id],
    )
    result = observe_git_population(
        repo,
        contract=contract,
        source_revision=source,
        candidate_commit=candidate,
        required_locators=["src/b.py"],
    )
    _replay_check(result, [b_id, c_id], [b_id, c_id])


def test_git_adapter_binds_allowlist_into_selector_spec(tmp_path: Path) -> None:
    """Audit C2: a contract must not accept an allowlist it did not freeze."""
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
    result = observe_git_population(
        repo,
        contract=contract,
        source_revision=source,
        candidate_commit=candidate,
        allowlist_locators=["src/b.py"],
    )
    assert result.status == "indeterminate"
    assert "SCOPE_SELECTOR_MISMATCH" in result.reason_codes


def test_git_adapter_binds_required_into_selector_spec(tmp_path: Path) -> None:
    """Audit C2: a contract must not accept required locators it did not freeze."""
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
    result = observe_git_population(
        repo,
        contract=contract,
        source_revision=source,
        candidate_commit=candidate,
        required_locators=["src/b.py"],
    )
    assert result.status == "indeterminate"
    assert "SCOPE_SELECTOR_MISMATCH" in result.reason_codes


def test_pytest_adapter_binds_selector_args_into_selector_spec(
    pytest_repo, tmp_path: Path
) -> None:
    """Audit C2: selector_args must be frozen in the selector spec digest."""
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
            "python_executable_digest": hashlib.sha256(
                python.read_bytes()
            ).hexdigest(),
            "argv": ["-I", "-m", "pytest", "--collect-only", "-q"],
            "timeout_seconds": 60,
        },
        python=python,
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


def test_pytest_adapter_stdout_divergence_fails_closed(
    pytest_repo, tmp_path: Path
) -> None:
    """Audit A: pytest's own stdout report is a second, independent
    channel for the canonical document. Extra ``::``-containing lines
    (e.g. injected by a collected module) make the channels diverge and
    must close the observation instead of being ignored."""
    repo, head = pytest_repo
    python = _collect_fake(
        tmp_path,
        name="fake-python",
        extra_body=(
            "printf 'tests/test_fake.py::test_injected\\n'\n"
            "printf 'tests/test_fake.py::test_injected\\n' >&2\n"
        ),
    )
    declared = [
        scope_member_id("test_case", node) for node in PYTEST_NODES
    ]
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
        python=python,
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


def test_pytest_adapter_refuses_candidate_conftest_files(tmp_path: Path) -> None:
    """A nested candidate conftest.py runs arbitrary code during collection
    and can overwrite the canonical plugin output; collection must be
    conftest-free (fail closed)."""
    repo = _git_repo(tmp_path)
    head = _commit(
        repo,
        {
            "tests/test_a.py": "def test_a1():\n    assert True\n",
            "tests/conftest.py": (
                "def pytest_collection_finish(session):\n"
                "    import os\n"
                "    with open(os.environ['OWP_COLLECT_OUTPUT'], 'w') as f:\n"
                "        f.write('{\"node_ids\": [\"tests/test_fake.py::test_x\"]}')\n"
            ),
        },
        "malicious conftest",
    )
    python = _collect_fake(tmp_path, name="fake-python")
    declared = [scope_member_id("test_case", "tests/test_a.py::test_a1")]
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
        python=python,
        declared_ids=declared,
    )
    with pytest.raises(ValueError, match="conftest-free"):
        observe_pytest_population(
            repo,
            contract=contract,
            source_revision=head,
            candidate_commit=head,
            python_executable=python,
            selector_args=[],
            timeout_seconds=60,
        )


def test_pytest_adapter_real_venv_collection(tmp_path: Path) -> None:
    """Audit I3: the repository's real venv launcher (.venv/bin/python, a
    symlink) must collect with its own site-packages — dereferencing the
    symlink to the base Python loses pytest and fails collection."""
    venv_python = Path(__file__).resolve().parents[1] / ".venv" / "bin" / "python"
    if not venv_python.is_file():
        pytest.skip("repository venv is unavailable")
    repo = _git_repo(tmp_path)
    head = _commit(
        repo,
        {"tests/test_a.py": "def test_a1():\n    assert True\n"},
        "baseline",
    )
    declared = [scope_member_id("test_case", "tests/test_a.py::test_a1")]
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="pytest_collection",
        member_kind="test_case",
        spec_payload={
            "source_revision": head,
            "candidate_commit": head,
            "timeout_seconds": 120,
        },
        python=venv_python,
        declared_ids=declared,
    )
    result = observe_pytest_population(
        repo,
        contract=contract,
        source_revision=head,
        candidate_commit=head,
        python_executable=venv_python,
        selector_args=[],
        timeout_seconds=120,
    )
    eligible = [scope_member_id("test_case", "tests/test_a.py::test_a1")]
    _replay_check(result, eligible, eligible)


def test_pytest_adapter_candidate_pytest_shadow_cannot_fabricate(
    tmp_path: Path,
) -> None:
    """A candidate commit containing a top-level pytest.py must not shadow
    the real pytest module: -I keeps the checkout off sys.path, so the
    shadow never imports and the canonical collector output wins."""
    venv_python = Path(__file__).resolve().parents[1] / ".venv" / "bin" / "python"
    if not venv_python.is_file():
        pytest.skip("repository venv is unavailable")
    repo = _git_repo(tmp_path)
    head = _commit(
        repo,
        {
            "tests/test_a.py": "def test_a1():\n    assert True\n",
            "pytest.py": (
                "import os\n"
                "raise RuntimeError('shadow pytest module was imported')\n"
            ),
        },
        "hostile shadow",
    )
    declared = [scope_member_id("test_case", "tests/test_a.py::test_a1")]
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="pytest_collection",
        member_kind="test_case",
        spec_payload={
            "source_revision": head,
            "candidate_commit": head,
            "timeout_seconds": 120,
        },
        python=venv_python,
        declared_ids=declared,
    )
    result = observe_pytest_population(
        repo,
        contract=contract,
        source_revision=head,
        candidate_commit=head,
        python_executable=venv_python,
        selector_args=[],
        timeout_seconds=120,
    )
    eligible = [scope_member_id("test_case", "tests/test_a.py::test_a1")]
    _replay_check(result, eligible, eligible)


# ---------------------------------------------------------------------------
# Third-round audit A: pytest selector environment closure + trusted
# collector isolation. Each test is attack-shaped and must be RED against
# the audited baseline.
# ---------------------------------------------------------------------------

_VENV_PYTHON = Path(__file__).resolve().parents[1] / ".venv" / "bin" / "python"

_SLOW_A = (
    "import pytest\n"
    "\n"
    "\n"
    "@pytest.mark.slow\n"
    "def test_a1():\n"
    "    assert True\n"
)

_PLAIN_B = "def test_b1():\n    assert True\n"


def _requires_venv() -> Path:
    if not _VENV_PYTHON.is_file():
        pytest.skip("repository venv is unavailable")
    return _VENV_PYTHON


def test_pytest_adapter_env_addopts_cannot_alter_population(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Audit A: PYTEST_ADDOPTS must not alter the observed population under
    an unchanged selector spec digest. The polluted run must reproduce the
    honest eligible/selected populations exactly."""
    python = _requires_venv()
    repo = _git_repo(tmp_path)
    head = _commit(
        repo,
        {
            "tests/test_a.py": _SLOW_A,
            "tests/test_b.py": _PLAIN_B,
            "pyproject.toml": (
                "[tool.pytest.ini_options]\nmarkers = [\"slow: slow tests\"]\n"
            ),
        },
        "marked tests",
    )
    declared = [
        scope_member_id("test_case", node)
        for node in ("tests/test_a.py::test_a1", "tests/test_b.py::test_b1")
    ]
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="pytest_collection",
        member_kind="test_case",
        spec_payload={
            "source_revision": head,
            "candidate_commit": head,
            "timeout_seconds": 120,
        },
        python=python,
        declared_ids=declared,
    )
    kwargs = dict(
        repo=repo,
        contract=contract,
        source_revision=head,
        candidate_commit=head,
        python_executable=python,
        selector_args=[],
        timeout_seconds=120,
    )
    honest = observe_pytest_population(**kwargs)
    monkeypatch.setenv("PYTEST_ADDOPTS", "-m slow")
    polluted = observe_pytest_population(**kwargs)
    eligible_ids = declared
    _replay_check(honest, eligible_ids, eligible_ids)
    assert polluted.status == "satisfied"
    assert polluted.observation is not None
    assert (
        polluted.observation.eligible_population_digest
        == honest.observation.eligible_population_digest
    )
    assert (
        polluted.observation.selected_population_digest
        == honest.observation.selected_population_digest
    )


def test_pytest_adapter_env_plugins_cannot_alter_population(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Audit A: PYTEST_PLUGINS must not inject a selection-altering plugin."""
    python = _requires_venv()
    plugin = tmp_path / "hostile_plugin.py"
    plugin.write_text(
        "def pytest_collection_modifyitems(items):\n"
        "    items[:] = [i for i in items if 'test_b' not in i.nodeid]\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PYTEST_PLUGINS", str(plugin))
    repo = _git_repo(tmp_path)
    head = _commit(
        repo,
        {"tests/test_a.py": _SLOW_A, "tests/test_b.py": _PLAIN_B},
        "plugin attack",
    )
    declared = [
        scope_member_id("test_case", node)
        for node in ("tests/test_a.py::test_a1", "tests/test_b.py::test_b1")
    ]
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="pytest_collection",
        member_kind="test_case",
        spec_payload={
            "source_revision": head,
            "candidate_commit": head,
            "timeout_seconds": 120,
        },
        python=python,
        declared_ids=declared,
    )
    result = observe_pytest_population(
        repo,
        contract=contract,
        source_revision=head,
        candidate_commit=head,
        python_executable=python,
        selector_args=[],
        timeout_seconds=120,
    )
    _replay_check(result, declared, declared)


def test_pytest_adapter_host_ini_pollution_cannot_alter_population(
    tmp_path: Path,
) -> None:
    """Audit A: a pytest.ini in an ancestor directory of the checkout must
    not feed addopts/markers into the collection (the ini discovery walk is
    closed by the frozen collector ini). Runs in a fresh child process so a
    clean TMPDIR reaches tempfile (gettempdir is cached in-process)."""
    python = _requires_venv()
    host = tmp_path / "host"
    host.mkdir()
    (host / "pytest.ini").write_text(
        "[pytest]\naddopts = -m \"not slow\"\nmarkers = slow: slow tests\n",
        encoding="utf-8",
    )
    repo = _git_repo(tmp_path)
    head = _commit(
        repo,
        {"tests/test_a.py": _SLOW_A, "tests/test_b.py": _PLAIN_B},
        "ini attack",
    )
    declared = [
        scope_member_id("test_case", node)
        for node in ("tests/test_a.py::test_a1", "tests/test_b.py::test_b1")
    ]
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="pytest_collection",
        member_kind="test_case",
        spec_payload={
            "source_revision": head,
            "candidate_commit": head,
            "timeout_seconds": 120,
        },
        python=python,
        declared_ids=declared,
    )
    contract_path = tmp_path / "contract.json"
    contract_path.write_text(
        contract.model_dump_json(), encoding="utf-8"
    )
    child = tmp_path / "observe_child.py"
    child.write_text(
        "import json\n"
        "import sys\n"
        "from pathlib import Path\n"
        "\n"
        "sys.path.insert(0, " + repr(str(Path(__file__).resolve().parents[1] / "src")) + ")\n"
        "from openworkproof.models import PopulationContractV05\n"
        "from openworkproof.scope import observe_pytest_population\n"
        "\n"
        "contract = PopulationContractV05.model_validate(\n"
        "    json.loads(Path(sys.argv[1]).read_text(encoding='utf-8')))\n"
        "repo, head, python_path = Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4])\n"
        "result = observe_pytest_population(\n"
        "    repo, contract=contract, source_revision=head,\n"
        "    candidate_commit=head, python_executable=python_path,\n"
        "    selector_args=[], timeout_seconds=120)\n"
        "print(json.dumps({\n"
        "    'status': result.status,\n"
        "    'reasons': list(result.reason_codes),\n"
        "    'eligible': list(result.eligible_member_ids),\n"
        "}))\n",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    environment["TMPDIR"] = str(host)
    environment["PYTEST_ADDOPTS"] = ""
    completed = subprocess.run(
        [str(python), str(child), str(contract_path), str(repo), head, str(python)],
        cwd=repo,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stderr
    outcome = json.loads(completed.stdout)
    assert outcome["status"] == "satisfied", completed.stderr
    assert sorted(outcome["eligible"]) == sorted(declared), completed.stderr


def test_pytest_adapter_collection_environment_is_closed(
    pytest_repo, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Audit A: the collection child must see a closed environment — no
    PYTEST_ADDOPTS/PLUGINS passthrough and no OWP_COLLECT_OUTPUT channel."""
    repo, head = pytest_repo
    monkeypatch.setenv("PYTEST_ADDOPTS", "-m slow")
    monkeypatch.setenv("PYTEST_PLUGINS", "hostile.plugin")
    full_doc = '{"node_ids":["tests/test_a.py::test_a1","tests/test_b.py::test_b1","tests/test_b.py::test_b2","tests/test_c.py::test_c1","tests/test_d.py::test_d1"]}'
    python = _fake_python(
        tmp_path / "fake-python-closed",
        "\n"
        "test -z \"${PYTEST_ADDOPTS:-}\"\n"
        "test -z \"${PYTEST_PLUGINS:-}\"\n"
        "test -z \"${OWP_COLLECT_OUTPUT:-}\"\n"
        "test \"$PYTEST_DISABLE_PLUGIN_AUTOLOAD\" = \"1\"\n"
        "test \"$LC_ALL\" = \"C.UTF-8\"\n"
        "test \"$TZ\" = \"UTC\"\n"
        "printf '%s\\n' 'tests/test_a.py::test_a1'\n"
        "printf '%s\\n' 'tests/test_b.py::test_b1'\n"
        "printf '%s\\n' 'tests/test_b.py::test_b2'\n"
        "printf '%s\\n' 'tests/test_c.py::test_c1'\n"
        "printf '%s\\n' 'tests/test_d.py::test_d1'\n"
        "printf '%s\\n' '" + full_doc + "' >&3\n",
    )
    declared = [
        scope_member_id("test_case", node) for node in PYTEST_NODES
    ]
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
        python=python,
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
    eligible_ids = [
        scope_member_id("test_case", node) for node in PYTEST_NODES
    ]
    _replay_check(result, eligible_ids, eligible_ids)


def test_pytest_adapter_collected_module_cannot_forge_collector_output(
    tmp_path: Path,
) -> None:
    """Audit A: a collected module registering an atexit writer must not be
    able to overwrite the authoritative node-id output."""
    python = _requires_venv()
    repo = _git_repo(tmp_path)
    head = _commit(
        repo,
        {
            "tests/test_a.py": "def test_a1():\n    assert True\n",
            "tests/test_b.py": (
                "import atexit\n"
                "import json\n"
                "import os\n"
                "\n"
                "\n"
                "def _forge():\n"
                "    out = os.environ.get('OWP_COLLECT_OUTPUT')\n"
                "    if not out:\n"
                "        return\n"
                "    with open(out, 'w', encoding='utf-8') as handle:\n"
                "        handle.write(json.dumps(\n"
                "            {'node_ids': ['tests/test_a.py::test_a1']},\n"
                "            sort_keys=True, separators=(',', ':')))\n"
                "\n"
                "\n"
                "atexit.register(_forge)\n"
                "\n"
                "\n"
                "def test_b1():\n"
                "    assert True\n"
            ),
        },
        "forging module",
    )
    declared = [
        scope_member_id("test_case", node)
        for node in ("tests/test_a.py::test_a1", "tests/test_b.py::test_b1")
    ]
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="pytest_collection",
        member_kind="test_case",
        spec_payload={
            "source_revision": head,
            "candidate_commit": head,
            "timeout_seconds": 120,
        },
        python=python,
        declared_ids=declared,
    )
    result = observe_pytest_population(
        repo,
        contract=contract,
        source_revision=head,
        candidate_commit=head,
        python_executable=python,
        selector_args=[],
        timeout_seconds=120,
    )
    _replay_check(result, declared, declared)


def test_pytest_adapter_fd3_interference_fails_closed(tmp_path: Path) -> None:
    """Audit A: any collected-module write to the collector channel must
    poison the single-document output and fail closed — a module can never
    forge the authoritative node ids."""
    python = _requires_venv()
    repo = _git_repo(tmp_path)
    head = _commit(
        repo,
        {
            "tests/test_a.py": "def test_a1():\n    assert True\n",
            "tests/test_b.py": (
                "import atexit\n"
                "import os\n"
                "\n"
                "\n"
                "def _poison():\n"
                "    try:\n"
                "        os.write(3, b'garbage')\n"
                "    except OSError:\n"
                "        pass\n"
                "\n"
                "\n"
                "atexit.register(_poison)\n"
                "\n"
                "\n"
                "def test_b1():\n"
                "    assert True\n"
            ),
        },
        "poisoning module",
    )
    declared = [
        scope_member_id("test_case", node)
        for node in ("tests/test_a.py::test_a1", "tests/test_b.py::test_b1")
    ]
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="pytest_collection",
        member_kind="test_case",
        spec_payload={
            "source_revision": head,
            "candidate_commit": head,
            "timeout_seconds": 120,
        },
        python=python,
        declared_ids=declared,
    )
    result = observe_pytest_population(
        repo,
        contract=contract,
        source_revision=head,
        candidate_commit=head,
        python_executable=python,
        selector_args=[],
        timeout_seconds=120,
    )
    assert result.status == "indeterminate"
    assert "SCOPE_SELECTOR_MISMATCH" in result.reason_codes


def test_pytest_adapter_selected_outside_eligible_rejected(tmp_path: Path) -> None:
    """Audit A: the same digest must reproduce the same eligible population;
    a module that grows its test set between the eligible and selected
    phases makes selected ⊄ eligible and must be rejected."""
    python = _requires_venv()
    repo = _git_repo(tmp_path)
    head = _commit(
        repo,
        {
            "tests/test_a.py": (
                "from pathlib import Path\n"
                "\n"
                "\n"
                "MARKER = Path('owp-flip.marker')\n"
                "if MARKER.exists():\n"
                "    def test_phantom():  # noqa: E306\n"
                "        assert True\n"
                "MARKER.write_text('flipped', encoding='utf-8')\n"
                "\n"
                "\n"
                "def test_a1():\n"
                "    assert True\n"
            ),
        },
        "flipping module",
    )
    declared = [
        scope_member_id("test_case", node)
        for node in (
            "tests/test_a.py::test_a1",
            "tests/test_a.py::test_phantom",
        )
    ]
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="pytest_collection",
        member_kind="test_case",
        spec_payload={
            "source_revision": head,
            "candidate_commit": head,
            "timeout_seconds": 120,
        },
        python=python,
        declared_ids=declared,
    )
    result = observe_pytest_population(
        repo,
        contract=contract,
        source_revision=head,
        candidate_commit=head,
        python_executable=python,
        selector_args=[],
        timeout_seconds=120,
    )
    assert result.status == "indeterminate"
    assert "SCOPE_SELECTOR_MISMATCH" in result.reason_codes


def test_pytest_adapter_leaked_collector_fd_fails_closed(tmp_path: Path) -> None:
    """A collected module that leaks the collector pipe to a surviving
    descendant must fail closed within the drain grace period instead of
    hanging the verifier forever."""
    python = _requires_venv()
    repo = _git_repo(tmp_path)
    head = _commit(
        repo,
        {
            "tests/test_a.py": "def test_a1():\n    assert True\n",
            "tests/test_b.py": (
                "import subprocess\n"
                "import sys\n"
                "\n"
                "\n"
                "subprocess.Popen(\n"
                "    [sys.executable, '-c', 'import time; time.sleep(20)'],\n"
                "    stdin=subprocess.DEVNULL,\n"
                "    stdout=subprocess.DEVNULL,\n"
                "    stderr=subprocess.DEVNULL,\n"
                "    pass_fds=(3,),\n"
                "    start_new_session=True,\n"
                ")\n"
                "\n"
                "\n"
                "def test_b1():\n"
                "    assert True\n"
            ),
        },
        "leaking module",
    )
    declared = [
        scope_member_id("test_case", node)
        for node in ("tests/test_a.py::test_a1", "tests/test_b.py::test_b1")
    ]
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="pytest_collection",
        member_kind="test_case",
        spec_payload={
            "source_revision": head,
            "candidate_commit": head,
            "timeout_seconds": 120,
        },
        python=python,
        declared_ids=declared,
    )
    import time as _time

    started = _time.monotonic()
    result = observe_pytest_population(
        repo,
        contract=contract,
        source_revision=head,
        candidate_commit=head,
        python_executable=python,
        selector_args=[],
        timeout_seconds=120,
    )
    elapsed = _time.monotonic() - started
    assert result.status == "indeterminate"
    assert "SCOPE_SELECTOR_MISMATCH" in result.reason_codes
    assert elapsed < 15


def test_pytest_adapter_pipe_unavailable_fails_closed(
    pytest_repo, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pipe allocation failure (e.g. EMFILE) must close the observation as
    indeterminate instead of leaking a raw OSError out of the adapter."""
    repo, head = pytest_repo
    python = _collect_fake(tmp_path, name="fake-python")
    declared = [
        scope_member_id("test_case", node) for node in PYTEST_NODES
    ]
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
        python=python,
        declared_ids=declared,
    )
    real_pipe = os.pipe
    real_run = subprocess.run

    def failing_pipe():
        raise OSError(24, "Too many open files")

    def guarded_run(*args, **kwargs):
        os.pipe = real_pipe
        try:
            return real_run(*args, **kwargs)
        finally:
            os.pipe = failing_pipe

    monkeypatch.setattr(os, "pipe", failing_pipe)
    monkeypatch.setattr(subprocess, "run", guarded_run)
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


def test_pytest_adapter_in_process_monkeypatch_cannot_forge_collector_output(
    tmp_path: Path,
) -> None:
    """Audit A / spec-review PoC: a collected module that monkeypatches
    json.dumps, builtins.sorted, and os.write at import time must not be
    able to forge the canonical document — serialization primitives are
    captured at conftest import time, before candidate code runs, and the
    host cross-checks pytest's own stdout report."""
    python = _requires_venv()
    repo = _git_repo(tmp_path)
    head = _commit(
        repo,
        {
            "tests/test_a.py": "def test_real():\n    assert True\n",
            "tests/test_b.py": (
                "import builtins\n"
                "import json\n"
                "import os\n"
                "\n"
                "\n"
                "FORGED = ('{\"node_ids\":[\"tests/test_a.py::test_phantom\"]}'\n"
                "          .encode('utf-8'))\n"
                "json.dumps = lambda *a, **k: FORGED.decode('utf-8')\n"
                "builtins.sorted = lambda items, *a, **k: list(items)\n"
                "os.write = lambda fd, data: len(data)\n"
                "\n"
                "\n"
                "def test_b1():\n"
                "    assert True\n"
            ),
        },
        "monkeypatching module",
    )
    declared = [
        scope_member_id("test_case", node)
        for node in ("tests/test_a.py::test_real", "tests/test_b.py::test_b1")
    ]
    contract = _contract(
        rule_id="1" * 64,
        selector_kind="pytest_collection",
        member_kind="test_case",
        spec_payload={
            "source_revision": head,
            "candidate_commit": head,
            "timeout_seconds": 120,
        },
        python=python,
        declared_ids=declared,
    )
    result = observe_pytest_population(
        repo,
        contract=contract,
        source_revision=head,
        candidate_commit=head,
        python_executable=python,
        selector_args=[],
        timeout_seconds=120,
    )
    _replay_check(result, declared, declared)
    phantom = scope_member_id("test_case", "tests/test_a.py::test_phantom")
    assert phantom not in result.eligible_member_ids
