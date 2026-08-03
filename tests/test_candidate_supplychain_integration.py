"""Explicit integration checks for the external Day 0 candidate artifacts."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE_ROOT = ROOT / "supply-chain" / "images"
ASSEMBLER = IMAGE_ROOT / "prepare_context.py"
INVENTORY = next((IMAGE_ROOT / "candidates").glob("*.json"))
NO_ARTIFACT_ROOT = (
    "set OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT to run candidate supply-chain integration"
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_sums(path: Path) -> list[tuple[str, str]]:
    assert path.is_file(), f"missing SHA256SUMS: {path}"
    rows: list[tuple[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        digest, separator, name = line.partition("  ")
        assert separator and len(digest) == 64 and name
        assert all(character in "0123456789abcdef" for character in digest)
        assert PurePosixPath(name).name == name
        rows.append((digest, name))
    assert rows and len({name for _, name in rows}) == len(rows)
    return rows


def _verify_sums(directory: Path) -> list[tuple[str, str]]:
    rows = _parse_sums(directory / "SHA256SUMS")
    expected = {name for _, name in rows} | {"SHA256SUMS"}
    entries = list(directory.iterdir())
    assert all(
        not path.is_symlink() and stat.S_ISREG(path.lstat().st_mode)
        for path in entries
    )
    actual = {path.name for path in entries}
    assert actual == expected
    for digest, name in rows:
        assert _sha256_file(directory / name) == digest
    return rows


def _external_path(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    assert candidate.is_relative_to(root)
    return candidate


def _file_tree(root: Path) -> dict[str, tuple[str, bytes]]:
    tree: dict[str, tuple[str, bytes]] = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        assert not path.is_symlink()
        if stat.S_ISDIR(mode):
            tree[relative] = ("directory", b"")
        else:
            assert stat.S_ISREG(mode)
            tree[relative] = ("file", path.read_bytes())
    return tree


def _git_bytes(revision: str, relative_path: str) -> bytes:
    return subprocess.run(
        ["git", "show", f"{revision}:{relative_path}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout


def _verify_oci_archive(path: Path, expected_manifest_digest: str) -> None:
    with tarfile.open(path, mode="r") as archive:
        members = {}
        for member in archive.getmembers():
            name = member.name.rstrip("/")
            member_path = PurePosixPath(name)
            assert name and not member_path.is_absolute() and ".." not in member_path.parts
            assert member_path.as_posix() == name
            assert not member.issym() and not member.islnk()
            assert member.isfile() or member.isdir()
            assert name not in members
            members[name] = member
        assert "oci-layout" in members
        assert "index.json" in members

        def member_bytes(name: str) -> bytes:
            member = members[name]
            stream = archive.extractfile(member)
            assert stream is not None
            return stream.read()

        assert json.loads(member_bytes("oci-layout")) == {
            "imageLayoutVersion": "1.0.0"
        }
        index = json.loads(member_bytes("index.json"))
        assert index["schemaVersion"] == 2
        assert len(index["manifests"]) == 1
        manifest_descriptor = index["manifests"][0]
        assert manifest_descriptor["digest"] == expected_manifest_digest
        manifest_name = "blobs/sha256/" + expected_manifest_digest.removeprefix(
            "sha256:"
        )
        manifest_bytes = member_bytes(manifest_name)
        assert _sha256_bytes(manifest_bytes) == expected_manifest_digest.removeprefix(
            "sha256:"
        )
        assert len(manifest_bytes) == manifest_descriptor["size"]
        manifest = json.loads(manifest_bytes)
        assert manifest["schemaVersion"] == 2
        assert manifest["mediaType"] == (
            "application/vnd.oci.image.manifest.v1+json"
        )
        for descriptor in [manifest["config"], *manifest["layers"]]:
            digest = descriptor["digest"].removeprefix("sha256:")
            blob = member_bytes(f"blobs/sha256/{digest}")
            assert _sha256_bytes(blob) == digest
            assert len(blob) == descriptor["size"]


@pytest.mark.parametrize("unsafe_kind", ["directory", "symlink"])
def test_sha256_directory_verifier_rejects_non_regular_entries(
    tmp_path: Path, unsafe_kind: str
) -> None:
    payload = b"artifact\n"
    (tmp_path / "artifact.bin").write_bytes(payload)
    (tmp_path / "SHA256SUMS").write_text(
        f"{_sha256_bytes(payload)}  artifact.bin\n", encoding="utf-8"
    )
    if unsafe_kind == "directory":
        (tmp_path / ".unexpected").mkdir()
    else:
        (tmp_path / "linked.bin").symlink_to(tmp_path / "artifact.bin")

    with pytest.raises(AssertionError):
        _verify_sums(tmp_path)


def _docker(
    executable: str, *args: str, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [executable, *args],
        check=check,
        capture_output=True,
        text=True,
    )


def _verify_live_docker(inventory: dict[str, object]) -> None:
    docker = os.environ.get("OPENWORKPROOF_DOCKER") or shutil.which("docker")
    assert docker, "required live Docker executable is missing"
    info = _docker(docker, "info", check=False)
    assert info.returncode == 0, f"required live Docker daemon is unavailable: {info.stderr}"

    images = inventory["images"]
    assert isinstance(images, dict)
    for image in images.values():
        assert isinstance(image, dict)
        inspected = _docker(
            docker, "image", "inspect", str(image["candidate_name"]), check=False
        )
        assert inspected.returncode == 0, (
            f"required candidate image is missing: {image['candidate_name']}"
        )
        details = json.loads(inspected.stdout)
        assert len(details) == 1
        details = details[0]
        assert details["Id"] == image["local_image_id"]
        assert details["RepoDigests"] == image["local_repo_digests"]
        assert f"{details['Os']}/{details['Architecture']}" == image["platform"]
        assert details["Config"]["User"] == image["user"]
        assert details["Config"]["Entrypoint"] == image["entrypoint"]
        assert details["Config"]["Cmd"] == image["cmd"]
        assert details["Config"]["Labels"] == image["labels"]

    names = {
        key: f"owp-supplychain-{os.getpid()}-{key}"
        for key in ("execution", "helper-python", "helper-git", "helper-dpkg")
    }
    for name in names.values():
        assert _docker(docker, "container", "inspect", name, check=False).returncode != 0

    execution = images["execution"]
    helper = images["trusted_helper"]
    assert isinstance(execution, dict) and isinstance(helper, dict)
    common = ["run", "--rm", "--network", "none", "--read-only"]
    execution_check = (
        "import importlib.util as u; import pytest; "
        "assert pytest.__version__ == '9.1.1'; "
        "assert u.find_spec('rich') is None; "
        "assert u.find_spec('openworkproof') is None; "
        "assert u.find_spec('mcp') is None"
    )
    result = _docker(
        docker,
        *common,
        "--name",
        names["execution"],
        "--user",
        str(execution["user"]),
        str(execution["local_image_id"]),
        "/opt/venv/bin/python",
        "-I",
        "-c",
        execution_check,
    )
    assert result.stdout == ""

    helper_check = (
        "import importlib.util as u; import openworkproof, openworkproof.models, "
        "openworkproof.repo_tools; assert u.find_spec('openworkproof.cli') is None; "
        "assert u.find_spec('openworkproof.mcp_server') is None"
    )
    result = _docker(
        docker,
        *common,
        "--name",
        names["helper-python"],
        "--user",
        str(helper["user"]),
        str(helper["local_image_id"]),
        "-c",
        helper_check,
    )
    assert result.stdout == ""
    result = _docker(
        docker,
        *common,
        "--name",
        names["helper-git"],
        "--user",
        str(helper["user"]),
        "--entrypoint",
        "/usr/bin/git",
        str(helper["local_image_id"]),
        "--version",
    )
    assert result.stdout.strip() == "git version 2.47.3"
    result = _docker(
        docker,
        *common,
        "--name",
        names["helper-dpkg"],
        "--user",
        str(helper["user"]),
        "--entrypoint",
        "/usr/bin/dpkg",
        str(helper["local_image_id"]),
        "--audit",
    )
    assert result.stdout == "" and result.stderr == ""
    for name in names.values():
        assert _docker(docker, "container", "inspect", name, check=False).returncode != 0


@pytest.mark.supplychain
def test_candidate_artifact_chain(tmp_path: Path) -> None:
    required_live = os.environ.get("OPENWORKPROOF_REQUIRE_LIVE_DOCKER") == "1"
    root_value = os.environ.get("OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT")
    if not root_value:
        if required_live:
            pytest.fail("OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT is required for live Docker")
        pytest.skip(NO_ARTIFACT_ROOT)
    artifact_root = Path(root_value).expanduser().resolve()
    assert artifact_root.is_dir(), f"candidate artifact root is missing: {artifact_root}"

    inventory_bytes = INVENTORY.read_bytes()
    inventory = json.loads(inventory_bytes)
    revision = inventory["source_revision"]
    layout = inventory["external_layout"]["relative_paths"]
    paths = {
        key: _external_path(artifact_root, relative)
        for key, relative in layout.items()
    }
    full_wheel_sums = paths["wheelhouse"] / "SHA256SUMS"
    _verify_sums(paths["wheelhouse"])
    assert _sha256_file(full_wheel_sums) == inventory["build_inputs"]["global"][
        "full_wheelhouse_sha256sums_sha256"
    ]
    closure_rows = _verify_sums(paths["git_deb_closure"])
    locked_debs = []
    for line in _git_bytes(
        revision, "supply-chain/images/trusted-helper/debian-packages.lock"
    ).decode().splitlines():
        if line and not line.startswith("#"):
            digest, filename, *_ = line.split("\t")
            locked_debs.append((digest, filename))
    assert closure_rows == locked_debs

    rebuilt = tmp_path / "rebuilt-contexts"
    result = subprocess.run(
        [
            sys.executable,
            str(ASSEMBLER),
            "--repo",
            str(ROOT),
            "--source-revision",
            revision,
            "--wheelhouse",
            str(paths["wheelhouse"]),
            "--deb-closure",
            str(paths["git_deb_closure"]),
            "--output-root",
            str(rebuilt),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert _file_tree(rebuilt / "execution") == _file_tree(
        paths["execution_build_context"]
    )
    assert _file_tree(rebuilt / "trusted-helper") == _file_tree(
        paths["trusted_helper_build_context"]
    )
    execution_context = paths["execution_build_context"]
    helper_context = paths["trusted_helper_build_context"]
    _verify_sums(execution_context / "wheels")
    _verify_sums(helper_context / "wheels")
    _verify_sums(helper_context / "debs")
    _verify_sums(helper_context / "helper-src")
    allowlist = _git_bytes(
        revision, "supply-chain/images/trusted-helper/SOURCE_ALLOWLIST"
    ).decode().splitlines()
    for source in allowlist:
        assert (helper_context / "helper-src" / Path(source).name).read_bytes() == (
            _git_bytes(revision, source)
        )

    archives = paths["archives"]
    archive_rows = _parse_sums(archives / "SHA256SUMS")
    for digest, name in archive_rows:
        assert _sha256_file(archives / name) == digest
    expected_archives = {
        details["filename"]: details["sha256"]
        for image in inventory["images"].values()
        for details in image["archives"].values()
    }
    assert dict((name, digest) for digest, name in archive_rows) == expected_archives
    for image in inventory["images"].values():
        oci = image["archives"]["oci"]
        _verify_oci_archive(
            archives / oci["filename"], image["oci_manifest_digest"]
        )

    archived_inventory = archives / INVENTORY.name
    sidecar = archives / f"{INVENTORY.name}.sha256"
    assert archived_inventory.read_bytes() == inventory_bytes
    inventory_digest = _sha256_bytes(inventory_bytes)
    assert sidecar.read_text(encoding="utf-8") == (
        f"{inventory_digest}  {INVENTORY.name}\n"
    )

    if required_live:
        _verify_live_docker(inventory)
