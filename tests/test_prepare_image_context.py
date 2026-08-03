"""Contracts for the revision-bound candidate context assembler."""

from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "supply-chain" / "images" / "prepare_context.py"
HELPER_SOURCE_BLOBS = {
    "src/openworkproof/__init__.py": b"PACKAGE = True\n",
    "src/openworkproof/models.py": b"MODELS = True\n",
    "src/openworkproof/repo_tools.py": b"REPO_TOOLS = True\n",
    "src/openworkproof/trusted_helper.py": b"TRUSTED_HELPER = True\n",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


@pytest.fixture
def context_inputs(tmp_path: Path) -> dict[str, Path | str | bytes]:
    repo = tmp_path / "repo"
    wheelhouse = tmp_path / "wheelhouse"
    deb_closure = tmp_path / "debs"
    repo.mkdir()
    wheelhouse.mkdir()
    deb_closure.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "tests@example.invalid")
    _git(repo, "config", "user.name", "OpenWorkProof Tests")

    execution_wheel = b"execution wheel\n"
    helper_wheel = b"helper wheel\n"
    deb = b"git deb closure\n"
    execution_wheel_name = "pytest-1.0-py3-none-any.whl"
    helper_wheel_name = "pydantic-1.0-py3-none-any.whl"
    deb_name = "git_1.0_arm64.deb"

    _write(wheelhouse / execution_wheel_name, execution_wheel)
    _write(wheelhouse / helper_wheel_name, helper_wheel)
    _write(
        wheelhouse / "SHA256SUMS",
        (
            f"{_sha256(execution_wheel)}  {execution_wheel_name}\n"
            f"{_sha256(helper_wheel)}  {helper_wheel_name}\n"
        ).encode(),
    )
    _write(deb_closure / deb_name, deb)
    _write(
        deb_closure / "SHA256SUMS",
        f"{_sha256(deb)}  {deb_name}\n".encode(),
    )

    tracked: dict[str, bytes] = {
        "requirements-lock.txt": b"project lock\n",
        "supply-chain/images/execution/Dockerfile": b"FROM execution\n",
        "supply-chain/images/execution/requirements.lock": (
            b"pytest==1.0 \\\n"
            + f"    --hash=sha256:{_sha256(execution_wheel)}\n".encode()
        ),
        "supply-chain/images/trusted-helper/Dockerfile": b"FROM helper\n",
        "supply-chain/images/trusted-helper/requirements.lock": (
            b"pydantic==1.0 \\\n"
            + f"    --hash=sha256:{_sha256(helper_wheel)}\n".encode()
        ),
        "supply-chain/images/trusted-helper/SOURCE_ALLOWLIST": (
            b"src/openworkproof/__init__.py\n"
            b"src/openworkproof/models.py\n"
            b"src/openworkproof/repo_tools.py\n"
            b"src/openworkproof/trusted_helper.py\n"
        ),
        "supply-chain/images/trusted-helper/debian-packages.lock": (
            f"# sha256<TAB>filename<TAB>package<TAB>version<TAB>architecture\n"
            f"{_sha256(deb)}\t{deb_name}\tgit\t1.0\tarm64\n"
        ).encode(),
        **HELPER_SOURCE_BLOBS,
    }
    for relative, data in tracked.items():
        _write(repo / relative, data)
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "fixture")
    revision = _git(repo, "rev-parse", "HEAD")

    return {
        "repo": repo,
        "revision": revision,
        "wheelhouse": wheelhouse,
        "deb_closure": deb_closure,
        "execution_wheel_name": execution_wheel_name,
        "helper_wheel_name": helper_wheel_name,
        "deb_name": deb_name,
    }


def _assemble(
    inputs: dict[str, Path | str | bytes],
    output: Path,
    revision: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(ASSEMBLER),
            "--repo",
            str(inputs["repo"]),
            "--source-revision",
            revision or str(inputs["revision"]),
            "--wheelhouse",
            str(inputs["wheelhouse"]),
            "--deb-closure",
            str(inputs["deb_closure"]),
            "--output-root",
            str(output),
        ],
        capture_output=True,
        text=True,
    )


def test_assembler_rejects_an_unknown_source_revision(
    context_inputs: dict[str, Path | str | bytes], tmp_path: Path
) -> None:
    output = tmp_path / "contexts"

    result = _assemble(context_inputs, output, revision="0" * 40)

    assert result.returncode != 0
    assert "source revision" in result.stderr.lower()
    assert not output.exists()


@pytest.mark.parametrize("mutable_revision", ["HEAD", "main"])
def test_assembler_rejects_mutable_source_revisions(
    context_inputs: dict[str, Path | str | bytes],
    tmp_path: Path,
    mutable_revision: str,
) -> None:
    output = tmp_path / "contexts"

    result = _assemble(context_inputs, output, revision=mutable_revision)

    assert result.returncode != 0
    assert "40 lowercase hexadecimal" in result.stderr
    assert not output.exists()


def test_assembler_uses_git_blobs_and_ignores_worktree_source_drift(
    context_inputs: dict[str, Path | str | bytes], tmp_path: Path
) -> None:
    output = tmp_path / "contexts"
    repo = context_inputs["repo"]
    assert isinstance(repo, Path)
    for relative_path in HELPER_SOURCE_BLOBS:
        (repo / relative_path).write_text(
            "WORKTREE_DRIFT = True\n", encoding="utf-8"
        )

    result = _assemble(context_inputs, output)

    assert result.returncode == 0, result.stderr
    helper_source = output / "trusted-helper/helper-src"
    revision = str(context_inputs["revision"])
    expected_source_sums = []
    for relative_path in HELPER_SOURCE_BLOBS:
        source_blob = subprocess.run(
            ["git", "show", f"{revision}:{relative_path}"],
            cwd=repo,
            check=True,
            capture_output=True,
        ).stdout
        source_name = Path(relative_path).name
        assert (helper_source / source_name).read_bytes() == source_blob
        expected_source_sums.append(
            f"{_sha256(source_blob)}  {source_name}\n"
        )
    assert (helper_source / "SHA256SUMS").read_text(encoding="utf-8") == (
        "".join(expected_source_sums)
    )
    assert (output / "execution/Dockerfile").read_bytes() == b"FROM execution\n"
    assert sorted(path.relative_to(output).as_posix() for path in output.rglob("*")) == [
        "execution",
        "execution/Dockerfile",
        "execution/requirements.lock",
        "execution/wheels",
        "execution/wheels/SHA256SUMS",
        f"execution/wheels/{context_inputs['execution_wheel_name']}",
        "trusted-helper",
        "trusted-helper/Dockerfile",
        "trusted-helper/debs",
        "trusted-helper/debs/SHA256SUMS",
        f"trusted-helper/debs/{context_inputs['deb_name']}",
        "trusted-helper/helper-src",
        "trusted-helper/helper-src/SHA256SUMS",
        "trusted-helper/helper-src/__init__.py",
        "trusted-helper/helper-src/models.py",
        "trusted-helper/helper-src/repo_tools.py",
        "trusted-helper/helper-src/trusted_helper.py",
        "trusted-helper/requirements.lock",
        "trusted-helper/wheels",
        "trusted-helper/wheels/SHA256SUMS",
        f"trusted-helper/wheels/{context_inputs['helper_wheel_name']}",
    ]


@pytest.mark.parametrize("missing_kind", ["wheel", "deb"])
def test_assembler_rejects_missing_inputs_without_partial_output(
    context_inputs: dict[str, Path | str | bytes],
    tmp_path: Path,
    missing_kind: str,
) -> None:
    output = tmp_path / "published-contexts"
    if missing_kind == "wheel":
        wheelhouse = context_inputs["wheelhouse"]
        assert isinstance(wheelhouse, Path)
        (wheelhouse / str(context_inputs["execution_wheel_name"])).unlink()
    else:
        deb_closure = context_inputs["deb_closure"]
        assert isinstance(deb_closure, Path)
        (deb_closure / str(context_inputs["deb_name"])).unlink()

    result = _assemble(context_inputs, output)

    assert result.returncode != 0
    assert "missing" in result.stderr.lower()
    assert not output.exists()
    assert not list(tmp_path.glob(f".{output.name}.tmp-*"))


@pytest.mark.parametrize("unsafe_kind", ["extra-directory", "symlink"])
def test_assembler_rejects_non_regular_artifact_entries(
    context_inputs: dict[str, Path | str | bytes],
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    output = tmp_path / "published-contexts"
    wheelhouse = context_inputs["wheelhouse"]
    assert isinstance(wheelhouse, Path)
    if unsafe_kind == "extra-directory":
        (wheelhouse / ".unexpected").mkdir()
    else:
        (wheelhouse / "linked-wheel.whl").symlink_to(
            wheelhouse / str(context_inputs["execution_wheel_name"])
        )

    result = _assemble(context_inputs, output)

    assert result.returncode != 0
    assert "regular non-symlink" in result.stderr
    assert not output.exists()
    assert not list(tmp_path.glob(f".{output.name}.tmp-*"))
