"""Explicit integration checks for the external Day 0 candidate artifacts."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import copy
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile

import pytest

from tests.test_image_supply_chain import _load_candidate_inventory


ROOT = Path(__file__).resolve().parents[1]
IMAGE_ROOT = ROOT / "supply-chain" / "images"
ASSEMBLER = IMAGE_ROOT / "prepare_context.py"
INVENTORY_ROOT = IMAGE_ROOT / "candidates"
ALL_TRACKED_DEFINITION_PATHS = (
    "requirements-lock.txt",
    "supply-chain/images/execution/Dockerfile",
    "supply-chain/images/execution/requirements.lock",
    "supply-chain/images/execution/run_tests_runner.py",
    "supply-chain/images/execution/verifier_test.py",
    "supply-chain/images/trusted-helper/Dockerfile",
    "supply-chain/images/trusted-helper/requirements.lock",
    "supply-chain/images/trusted-helper/debian-packages.lock",
    "supply-chain/images/trusted-helper/SOURCE_ALLOWLIST",
)
HELPER_SOURCE_PATHS = tuple(
    line
    for line in (
        IMAGE_ROOT / "trusted-helper" / "SOURCE_ALLOWLIST"
    ).read_text(encoding="utf-8").splitlines()
    if line
)
CURRENT_DEFINITION_PATHS = ALL_TRACKED_DEFINITION_PATHS + HELPER_SOURCE_PATHS
REQUEST_INVALID_RESPONSE = (
    '{"code":"REQUEST_INVALID","schema_version":'
    '"openworkproof-trusted-helper-response/0.1","status":"error"}'
)
NO_ARTIFACT_ROOT = (
    "set OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT to run candidate supply-chain integration"
)
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
DOCKER_CONFIG = "application/vnd.docker.container.image.v1+json"
DOCKER_LAYER = "application/vnd.docker.image.rootfs.diff.tar.gzip"
OCI_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
BLOB_PATH_PATTERN = re.compile(r"^blobs/sha256/([0-9a-f]{64})$")
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 128
MAX_JSON_BYTES = 1024 * 1024
MAX_IMAGE_LAYERS = 64
MAX_IMAGE_HISTORY = 256
MAX_SNAPSHOT_ENTRIES = 4096
MAX_SNAPSHOT_DEPTH = 64
MAX_SNAPSHOT_FILE_BYTES = 512 * 1024 * 1024
MAX_SNAPSHOT_TOTAL_BYTES = 1024 * 1024 * 1024


@dataclass(frozen=True)
class _ImageIdentity:
    config_digest: str
    layer_digests: tuple[str, ...]
    rootfs_diff_ids: tuple[str, ...]
    config_semantics: dict[str, object]


def _assert_image_identity_chain(
    docker_archive: _ImageIdentity,
    oci_archive: _ImageIdentity,
    rebuilt_context: _ImageIdentity | None = None,
) -> None:
    assert docker_archive == oci_archive
    if rebuilt_context is not None:
        assert oci_archive == rebuilt_context


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
    assert root.is_absolute(), "artifact root must be absolute"
    root_mode = root.lstat().st_mode
    assert stat.S_ISDIR(root_mode) and not root.is_symlink(), (
        "artifact root must be a regular directory"
    )
    assert root.resolve(strict=True) == root, "artifact root must be canonical"
    assert type(relative) is str and relative, "external path must be non-empty"
    assert "\\" not in relative, "external path must use POSIX separators"
    assert all(part not in {"", ".", ".."} for part in relative.split("/"))
    relative_path = PurePosixPath(relative)
    assert not relative_path.is_absolute()
    assert relative_path.as_posix() == relative
    candidate = root
    for part in relative_path.parts:
        candidate = candidate / part
        mode = candidate.lstat().st_mode
        assert not stat.S_ISLNK(mode), "external path contains a symlink"
        assert stat.S_ISDIR(mode), "external path component must be a directory"
    return candidate


def _stat_token(details: os.stat_result) -> tuple[int, ...]:
    return (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_nlink,
        details.st_uid,
        details.st_gid,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
    )


def _canonical_relative_parts(relative: str) -> tuple[str, ...]:
    assert type(relative) is str and relative
    assert "\\" not in relative
    assert all(part not in {"", ".", ".."} for part in relative.split("/"))
    parsed = PurePosixPath(relative)
    assert not parsed.is_absolute() and parsed.as_posix() == relative
    return parsed.parts


def _assert_fd_binding(
    parent_fd: int,
    name: str,
    child_fd: int,
    expected: tuple[int, ...],
) -> None:
    assert _stat_token(os.fstat(child_fd)) == expected
    bound = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    assert _stat_token(bound) == expected


def _copy_anchored_tree(
    source_fd: int,
    destination: Path,
    budget: dict[str, int],
    *,
    depth: int = 0,
) -> None:
    assert depth <= MAX_SNAPSHOT_DEPTH
    for name in sorted(os.listdir(source_fd)):
        assert name not in {"", ".", ".."} and "/" not in name and "\\" not in name
        before = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        budget["entries"] += 1
        assert budget["entries"] <= MAX_SNAPSHOT_ENTRIES
        target = destination / name
        if stat.S_ISDIR(before.st_mode):
            child_fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=source_fd,
            )
            try:
                token = _stat_token(os.fstat(child_fd))
                assert token == _stat_token(before)
                target.mkdir(mode=0o700)
                _copy_anchored_tree(child_fd, target, budget, depth=depth + 1)
                _assert_fd_binding(source_fd, name, child_fd, token)
            finally:
                os.close(child_fd)
            continue
        assert stat.S_ISREG(before.st_mode), "snapshot entry must be regular or directory"
        assert before.st_nlink == 1, "snapshot source must not be a hard link"
        assert before.st_size <= MAX_SNAPSHOT_FILE_BYTES
        budget["bytes"] += before.st_size
        assert budget["bytes"] <= MAX_SNAPSHOT_TOTAL_BYTES
        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=source_fd)
        try:
            token = _stat_token(os.fstat(file_fd))
            assert token == _stat_token(before)
            copied = 0
            with target.open("xb") as output:
                while True:
                    chunk = os.read(file_fd, 1024 * 1024)
                    if not chunk:
                        break
                    copied += len(chunk)
                    assert copied <= before.st_size
                    output.write(chunk)
            assert copied == before.st_size
            _assert_fd_binding(source_fd, name, file_fd, token)
        finally:
            os.close(file_fd)


def _snapshot_external_subtrees(
    root: Path,
    relative_paths: Mapping[str, str],
    destination: Path,
    *,
    after_open_hook: Callable[[], None] | None = None,
) -> dict[str, Path]:
    assert root.is_absolute() and root.resolve(strict=True) == root
    assert not destination.exists()
    root_details = root.lstat()
    assert stat.S_ISDIR(root_details.st_mode) and not root.is_symlink()
    opened: list[int] = []
    bindings: list[tuple[int, str, int, tuple[int, ...]]] = []
    leaves: dict[str, int] = {}
    succeeded = False
    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened.append(root_fd)
        root_token = _stat_token(os.fstat(root_fd))
        assert root_token == _stat_token(root_details)
        assert type(relative_paths) is dict and relative_paths
        for key, relative in relative_paths.items():
            assert type(key) is str and key and key not in leaves
            parent_fd = root_fd
            for part in _canonical_relative_parts(relative):
                child_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=parent_fd,
                )
                opened.append(child_fd)
                token = _stat_token(os.fstat(child_fd))
                _assert_fd_binding(parent_fd, part, child_fd, token)
                bindings.append((parent_fd, part, child_fd, token))
                parent_fd = child_fd
            leaves[key] = parent_fd
        if after_open_hook is not None:
            after_open_hook()
        for binding in bindings:
            _assert_fd_binding(*binding)
        destination.mkdir(mode=0o700)
        budget = {"entries": 0, "bytes": 0}
        snapshots: dict[str, Path] = {}
        for key, leaf_fd in leaves.items():
            target = destination / key
            target.mkdir(mode=0o700)
            _copy_anchored_tree(leaf_fd, target, budget)
            snapshots[key] = target
        for binding in bindings:
            _assert_fd_binding(*binding)
        assert _stat_token(os.fstat(root_fd)) == root_token
        assert _stat_token(root.lstat()) == root_token
        succeeded = True
        return snapshots
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)
        if not succeeded and destination.exists():
            shutil.rmtree(destination)


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


def _verify_context_manifest_bindings(
    execution_context: Path,
    helper_context: Path,
    inventory: dict[str, object],
) -> None:
    build_inputs = inventory["build_inputs"]
    assert isinstance(build_inputs, dict)
    execution_inputs = build_inputs["execution"]
    helper_inputs = build_inputs["trusted_helper"]
    assert isinstance(execution_inputs, dict) and isinstance(helper_inputs, dict)
    bindings = (
        (
            execution_context / "wheels/SHA256SUMS",
            execution_inputs["wheel_sha256sums_sha256"],
        ),
        (
            helper_context / "wheels/SHA256SUMS",
            helper_inputs["wheel_sha256sums_sha256"],
        ),
        (
            helper_context / "debs/SHA256SUMS",
            helper_inputs["deb_sha256sums_sha256"],
        ),
        (
            helper_context / "helper-src/SHA256SUMS",
            helper_inputs["helper_src_sha256sums_sha256"],
        ),
    )
    for manifest, expected_digest in bindings:
        assert _sha256_file(manifest) == expected_digest


def _git_bytes(revision: str, relative_path: str) -> bytes:
    return subprocess.run(
        ["git", "show", f"{revision}:{relative_path}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout


def _select_inventory_for_definition(
    candidates: Iterable[tuple[Path, dict[str, object]]],
    definition: Mapping[str, bytes],
) -> tuple[Path, dict[str, object]]:
    matches: list[tuple[Path, dict[str, object]]] = []
    for path, inventory in candidates:
        loaded = _load_candidate_inventory(path)
        assert loaded == inventory, "selector inventory differs from strict file bytes"
        inventory = loaded
        revision = inventory["source_revision"]
        assert isinstance(revision, str)
        try:
            revision_definition = {
                relative_path: _git_bytes(revision, relative_path)
                for relative_path in CURRENT_DEFINITION_PATHS
            }
        except subprocess.CalledProcessError:
            continue
        if revision_definition == dict(definition):
            matches.append((path, inventory))
    assert len(matches) == 1, (
        "current candidate definition must select exactly one inventory; "
        f"matched {len(matches)}"
    )
    return matches[0]


def _select_current_inventory() -> tuple[Path, dict[str, object]]:
    candidates = [
        (path, _load_candidate_inventory(path))
        for path in sorted(INVENTORY_ROOT.glob("*.json"))
    ]
    definition = {
        relative_path: (ROOT / relative_path).read_bytes()
        for relative_path in CURRENT_DEFINITION_PATHS
    }
    return _select_inventory_for_definition(candidates, definition)


class _ArchiveMembers(dict[str, tarfile.TarInfo]):
    def __init__(self) -> None:
        super().__init__()
        self.consumed: set[str] = set()
        self.directories: set[str] = set()
        self.regular_files: set[str] = set()


def _safe_archive_members(archive: tarfile.TarFile) -> _ArchiveMembers:
    members = _ArchiveMembers()
    for member in archive:
        assert len(members) < MAX_ARCHIVE_MEMBERS, (
            "archive member count is unbounded"
        )
        name = member.name.rstrip("/")
        member_path = PurePosixPath(name)
        assert name and not member_path.is_absolute() and ".." not in member_path.parts
        assert member_path.as_posix() == name
        assert not member.issym() and not member.islnk()
        assert member.isfile() or member.isdir()
        assert not member.issparse(), "sparse archive members are forbidden"
        assert member.size <= MAX_ARCHIVE_BYTES, "archive member is oversized"
        assert name not in members
        members[name] = member
        if member.isdir():
            members.directories.add(name)
        else:
            members.regular_files.add(name)
    return members


def _archive_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        assert key not in value, f"duplicate archive JSON key: {key}"
        value[key] = item
    return value


def _archive_json(data: bytes, label: str) -> dict[str, object]:
    assert len(data) <= MAX_JSON_BYTES, f"{label} JSON is too large"
    try:
        value = json.loads(
            data.decode("utf-8"), object_pairs_hook=_archive_pairs
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssertionError(f"invalid {label} JSON") from error
    assert type(value) is dict, f"{label} must be an object"
    return value


def _member_bytes(
    archive: tarfile.TarFile,
    members: Mapping[str, tarfile.TarInfo],
    name: str,
) -> bytes:
    assert name in members, f"archive member is missing: {name}"
    member = members[name]
    assert member.isfile(), f"archive member is not a regular file: {name}"
    assert member.size <= MAX_JSON_BYTES, f"archive JSON member is too large: {name}"
    stream = archive.extractfile(member)
    assert stream is not None
    data = stream.read(MAX_JSON_BYTES + 1)
    assert len(data) == member.size
    assert stream.read(1) == b""
    if isinstance(members, _ArchiveMembers):
        members.consumed.add(name)
    return data


def _verify_blob(
    archive: tarfile.TarFile,
    members: Mapping[str, tarfile.TarInfo],
    name: str,
    *,
    expected_digest: str,
    expected_size: int,
) -> None:
    assert name in members, f"archive member is missing: {name}"
    member = members[name]
    assert member.isfile() and member.size == expected_size
    stream = archive.extractfile(member)
    assert stream is not None
    digest = hashlib.sha256()
    read_size = 0
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        read_size += len(chunk)
        assert read_size <= expected_size
        digest.update(chunk)
    assert read_size == expected_size and digest.hexdigest() == expected_digest
    if isinstance(members, _ArchiveMembers):
        members.consumed.add(name)


def _assert_archive_closed(members: _ArchiveMembers) -> None:
    assert members.directories == {"blobs", "blobs/sha256"}
    unreferenced = members.regular_files - members.consumed
    assert not unreferenced, f"unreferenced archive payload: {sorted(unreferenced)}"


def _verify_archive_path(path: Path) -> None:
    details = path.lstat()
    assert stat.S_ISREG(details.st_mode) and not path.is_symlink()
    assert details.st_size <= MAX_ARCHIVE_BYTES, "archive file is oversized"


def _descriptor(
    value: object,
    *,
    label: str,
    media_type: str | None = None,
    platform: tuple[str, str] | None = None,
    allow_annotations: bool = False,
    allow_platform: bool = False,
) -> dict[str, object]:
    assert type(value) is dict, f"{label} descriptor must be an object"
    assert "mediaType" in value, f"{label} descriptor mediaType is required"
    required = {"mediaType", "digest", "size"}
    allowed = set(required)
    if allow_annotations:
        allowed.add("annotations")
    if allow_platform or platform is not None:
        allowed.add("platform")
    assert required <= set(value) <= allowed, f"{label} descriptor keys are not exact"
    assert type(value["mediaType"]) is str and value["mediaType"]
    if media_type is not None:
        assert value["mediaType"] == media_type
    assert type(value["digest"]) is str and OCI_DIGEST_PATTERN.fullmatch(
        value["digest"]
    )
    assert type(value["size"]) is int and value["size"] > 0
    if "annotations" in value:
        assert type(value["annotations"]) is dict
        assert all(
            type(key) is str and type(item) is str
            for key, item in value["annotations"].items()
        )
    if platform is not None:
        assert set(value) >= {"platform"}
        assert value["platform"] == {
            "architecture": platform[0],
            "os": platform[1],
        }
    elif "platform" in value:
        actual_platform = value["platform"]
        assert type(actual_platform) is dict
        assert set(actual_platform) == {"architecture", "os"}
        assert all(type(item) is str and item for item in actual_platform.values())
    return value


def _descriptor_bytes(
    archive: tarfile.TarFile,
    members: Mapping[str, tarfile.TarInfo],
    descriptor: Mapping[str, object],
) -> bytes:
    digest = descriptor["digest"]
    size = descriptor["size"]
    assert isinstance(digest, str) and isinstance(size, int)
    name = f"blobs/sha256/{digest[7:]}"
    data = _member_bytes(archive, members, name)
    assert _sha256_bytes(data) == digest[7:]
    assert len(data) == size
    return data


def _verify_descriptor_blob(
    archive: tarfile.TarFile,
    members: Mapping[str, tarfile.TarInfo],
    descriptor: Mapping[str, object],
) -> None:
    digest = descriptor["digest"]
    size = descriptor["size"]
    assert isinstance(digest, str) and isinstance(size, int)
    _verify_blob(
        archive,
        members,
        f"blobs/sha256/{digest[7:]}",
        expected_digest=digest[7:],
        expected_size=size,
    )


def _config_identity(
    raw: bytes,
    *,
    layer_count: int,
    expected_image: Mapping[str, object] | None,
) -> tuple[tuple[str, ...], dict[str, object]]:
    assert 1 <= layer_count <= MAX_IMAGE_LAYERS, "image layer count is unbounded"
    config = _archive_json(raw, "image config")
    assert set(config) == {
        "architecture",
        "config",
        "created",
        "history",
        "os",
        "rootfs",
    }, "image config keys are not exact"
    assert config["architecture"] == "arm64" and config["os"] == "linux"
    assert type(config["created"]) is str and config["created"]
    rootfs = config["rootfs"]
    assert type(rootfs) is dict and set(rootfs) == {"type", "diff_ids"}
    assert rootfs["type"] == "layers"
    diff_ids = rootfs["diff_ids"]
    assert type(diff_ids) is list and len(diff_ids) == layer_count
    assert all(type(item) is str and OCI_DIGEST_PATTERN.fullmatch(item) for item in diff_ids)
    history = config["history"]
    assert type(history) is list and 1 <= len(history) <= MAX_IMAGE_HISTORY, (
        "image history count is unbounded"
    )
    assert all(type(item) is dict for item in history)
    for item in history:
        if "empty_layer" in item:
            assert type(item["empty_layer"]) is bool
    assert sum(item.get("empty_layer") is not True for item in history) == layer_count

    runtime = config["config"]
    assert type(runtime) is dict, "runtime config must be an object"
    required_runtime = {
        "ArgsEscaped",
        "Entrypoint",
        "Env",
        "Labels",
        "User",
        "WorkingDir",
    }
    assert required_runtime <= set(runtime) <= required_runtime | {"Cmd"}, (
        "runtime config keys are not exact"
    )
    assert runtime["ArgsEscaped"] is True
    assert runtime["User"] == "65532:65532"
    assert runtime["WorkingDir"] == "/workspace"
    assert type(runtime["Entrypoint"]) is list and runtime["Entrypoint"]
    assert all(type(token) is str and token for token in runtime["Entrypoint"])
    assert type(runtime["Env"]) is list and all(
        type(item) is str for item in runtime["Env"]
    )
    assert type(runtime["Labels"]) is dict
    assert all(
        type(key) is str and type(item) is str
        for key, item in runtime["Labels"].items()
    )
    assert not any("license" in key.casefold() for key in runtime["Labels"])
    if "Cmd" in runtime:
        assert type(runtime["Cmd"]) is list
        assert all(type(token) is str for token in runtime["Cmd"])
    if expected_image is not None:
        assert runtime["User"] == expected_image["user"]
        assert runtime["Entrypoint"] == expected_image["entrypoint"]
        assert runtime.get("Cmd") == expected_image["cmd"]
        assert runtime["Labels"] == expected_image["labels"]
    semantics = {
        "architecture": config["architecture"],
        "os": config["os"],
        "user": runtime["User"],
        "entrypoint": runtime["Entrypoint"],
        "cmd": runtime.get("Cmd"),
        "labels": runtime["Labels"],
        "env": runtime["Env"],
        "working_dir": runtime["WorkingDir"],
    }
    return tuple(diff_ids), semantics


def _image_manifest_identity(
    archive: tarfile.TarFile,
    members: Mapping[str, tarfile.TarInfo],
    manifest_raw: bytes,
    *,
    manifest_media_type: str,
    config_media_type: str,
    layer_media_type: str,
    expected_image: Mapping[str, object] | None,
) -> _ImageIdentity:
    manifest = _archive_json(manifest_raw, "image manifest")
    assert set(manifest) == {"schemaVersion", "mediaType", "config", "layers"}
    assert manifest["schemaVersion"] == 2
    assert manifest["mediaType"] == manifest_media_type
    config_descriptor = _descriptor(
        manifest["config"], label="config", media_type=config_media_type
    )
    layers = manifest["layers"]
    assert type(layers) is list and 1 <= len(layers) <= MAX_IMAGE_LAYERS, (
        "image layers must be bounded"
    )
    layer_descriptors = [
        _descriptor(layer, label="layer", media_type=layer_media_type)
        for layer in layers
    ]
    config_raw = _descriptor_bytes(archive, members, config_descriptor)
    for layer in layer_descriptors:
        _verify_descriptor_blob(archive, members, layer)
    diff_ids, semantics = _config_identity(
        config_raw,
        layer_count=len(layer_descriptors),
        expected_image=expected_image,
    )
    return _ImageIdentity(
        config_digest=config_descriptor["digest"],
        layer_digests=tuple(layer["digest"] for layer in layer_descriptors),
        rootfs_diff_ids=diff_ids,
        config_semantics=semantics,
    )


def _verify_docker_archive(
    path: Path,
    expected_tag: str,
    expected_image: Mapping[str, object] | None = None,
) -> _ImageIdentity:
    _verify_archive_path(path)
    with tarfile.open(path, mode="r") as archive:
        members = _safe_archive_members(archive)
        assert {"manifest.json", "oci-layout", "index.json"} <= set(members)
        assert _archive_json(
            _member_bytes(archive, members, "oci-layout"), "oci-layout"
        ) == {"imageLayoutVersion": "1.0.0"}
        legacy = json.loads(
            _member_bytes(archive, members, "manifest.json").decode("utf-8"),
            object_pairs_hook=_archive_pairs,
        )
        assert type(legacy) is list and len(legacy) == 1
        record = legacy[0]
        assert type(record) is dict and set(record) == {"Config", "Layers", "RepoTags"}
        assert type(record["Config"]) is str
        assert type(record["Layers"]) is list and all(
            type(item) is str for item in record["Layers"]
        )
        assert type(record["RepoTags"]) is list
        assert record["RepoTags"] == [expected_tag]
        config_match = BLOB_PATH_PATTERN.fullmatch(record["Config"])
        assert config_match, "Docker Config path is not canonical"
        layer_paths = record["Layers"]
        assert type(layer_paths) is list and 1 <= len(layer_paths) <= MAX_IMAGE_LAYERS
        layer_matches = [BLOB_PATH_PATTERN.fullmatch(item) for item in layer_paths]
        assert all(layer_matches), "Docker Layer path is not canonical"
        assert record["Config"] in members, (
            f"archive member is missing: {record['Config']}"
        )
        legacy_config_member = members[record["Config"]]
        _verify_blob(
            archive,
            members,
            record["Config"],
            expected_digest=config_match.group(1),
            expected_size=legacy_config_member.size,
        )
        for layer_path, match in zip(layer_paths, layer_matches, strict=True):
            assert match is not None
            assert layer_path in members, f"archive member is missing: {layer_path}"
            _verify_blob(
                archive,
                members,
                layer_path,
                expected_digest=match.group(1),
                expected_size=members[layer_path].size,
            )

        index = _archive_json(
            _member_bytes(archive, members, "index.json"), "Docker archive index"
        )
        assert set(index) == {"schemaVersion", "mediaType", "manifests"}
        assert index["schemaVersion"] == 2 and index["mediaType"] == OCI_INDEX
        assert type(index["manifests"]) is list and len(index["manifests"]) == 1
        top = _descriptor(
            index["manifests"][0],
            label="Docker manifest",
            media_type=DOCKER_MANIFEST,
            allow_annotations=True,
        )
        if expected_image is not None:
            assert top["digest"] == expected_image["local_image_id"]
        identity = _image_manifest_identity(
            archive,
            members,
            _descriptor_bytes(archive, members, top),
            manifest_media_type=DOCKER_MANIFEST,
            config_media_type=DOCKER_CONFIG,
            layer_media_type=DOCKER_LAYER,
            expected_image=expected_image,
        )
        assert top["annotations"] == {
            "config.digest": identity.config_digest,
            "io.containerd.image.name": f"docker.io/{expected_tag}",
            "org.opencontainers.image.ref.name": expected_tag.rsplit(":", 1)[1],
        }
        assert identity.config_digest == f"sha256:{config_match.group(1)}"
        assert identity.layer_digests == tuple(
            f"sha256:{match.group(1)}" for match in layer_matches if match is not None
        )
        _assert_archive_closed(members)
        return identity


def _verify_oci_archive(
    path: Path,
    expected_manifest_digest: str,
    expected_image: Mapping[str, object] | None = None,
    *,
    expected_created: str | None = None,
) -> _ImageIdentity:
    _verify_archive_path(path)
    with tarfile.open(path, mode="r") as archive:
        members = _safe_archive_members(archive)
        assert "manifest.json" not in members
        assert {"oci-layout", "index.json"} <= set(members)
        assert _archive_json(
            _member_bytes(archive, members, "oci-layout"), "oci-layout"
        ) == {"imageLayoutVersion": "1.0.0"}
        index = _archive_json(
            _member_bytes(archive, members, "index.json"), "OCI index"
        )
        assert set(index) == {"schemaVersion", "mediaType", "manifests"}
        assert index["schemaVersion"] == 2 and index["mediaType"] == OCI_INDEX
        assert type(index["manifests"]) is list and len(index["manifests"]) == 1
        descriptor = _descriptor(
            index["manifests"][0],
            label="OCI manifest",
            media_type=OCI_MANIFEST,
            platform=("arm64", "linux"),
            allow_annotations=True,
        )
        if expected_created is not None:
            assert descriptor["annotations"] == {
                "org.opencontainers.image.created": expected_created
            }, "OCI manifest descriptor created annotation is not revision-bound"
        assert descriptor["digest"] == expected_manifest_digest
        manifest_raw = _descriptor_bytes(archive, members, descriptor)
        identity = _image_manifest_identity(
            archive,
            members,
            manifest_raw,
            manifest_media_type=OCI_MANIFEST,
            config_media_type=OCI_CONFIG,
            layer_media_type=OCI_LAYER,
            expected_image=expected_image,
        )
        _assert_archive_closed(members)
        return identity


def _write_test_archive(path: Path, files: Mapping[str, bytes]) -> None:
    with tarfile.open(path, mode="w") as archive:
        for name in ("blobs", "blobs/sha256"):
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE
            member.mode = 0o755
            archive.addfile(member)
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(data))


def _synthetic_image_config(
    *, layer_count: int = 1, history_count: int | None = None
) -> bytes:
    if history_count is None:
        history_count = layer_count
    history = [
        {"created_by": f"layer-{index}", "empty_layer": index >= layer_count}
        for index in range(history_count)
    ]
    value = {
        "architecture": "arm64",
        "config": {
            "ArgsEscaped": True,
            "Entrypoint": ["/usr/bin/env", "--"],
            "Env": ["PATH=/usr/bin"],
            "Labels": {},
            "User": "65532:65532",
            "WorkingDir": "/workspace",
        },
        "created": "2026-08-04T00:00:00Z",
        "history": history,
        "os": "linux",
        "rootfs": {
            "type": "layers",
            "diff_ids": [f"sha256:{index:064x}" for index in range(layer_count)],
        },
    }
    return json.dumps(value, separators=(",", ":")).encode()


def _synthetic_oci_files(
    *, descriptor_media_type: bool = True, config: bytes | None = None
) -> tuple[dict[str, bytes], str]:
    if config is None:
        config = _synthetic_image_config()
    config_digest = _sha256_bytes(config)
    layer = b"layer"
    layer_digest = _sha256_bytes(layer)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": f"sha256:{config_digest}",
            "size": len(config),
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": f"sha256:{layer_digest}",
                "size": len(layer),
            }
        ],
    }
    manifest_raw = json.dumps(manifest, separators=(",", ":")).encode()
    manifest_digest = _sha256_bytes(manifest_raw)
    descriptor = {
        "digest": f"sha256:{manifest_digest}",
        "size": len(manifest_raw),
        "platform": {"architecture": "arm64", "os": "linux"},
    }
    if descriptor_media_type:
        descriptor["mediaType"] = "application/vnd.oci.image.manifest.v1+json"
    index = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [descriptor],
    }
    return (
        {
            "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
            "index.json": json.dumps(index, separators=(",", ":")).encode(),
            f"blobs/sha256/{manifest_digest}": manifest_raw,
            f"blobs/sha256/{config_digest}": config,
            f"blobs/sha256/{layer_digest}": layer,
        },
        f"sha256:{manifest_digest}",
    )


def _synthetic_docker_files(
    mutation: str | None = None,
) -> tuple[dict[str, bytes], str, str]:
    revision = "a" * 40
    tag = f"openworkproof/execution-test:{revision}"
    layer_count = MAX_IMAGE_LAYERS + 1 if mutation == "layer-count" else 1
    config = _synthetic_image_config(layer_count=layer_count)
    config_hex = _sha256_bytes(config)
    layer = b"layer"
    layer_hex = _sha256_bytes(layer)
    config_media_type = DOCKER_CONFIG
    if mutation == "config-media-type":
        config_media_type = OCI_CONFIG
    layer_media_type = DOCKER_LAYER
    if mutation == "layer-media-type":
        layer_media_type = OCI_LAYER
    manifest = {
        "config": {
            "digest": f"sha256:{config_hex}",
            "mediaType": config_media_type,
            "size": len(config),
        },
        "layers": [
            {
                "digest": f"sha256:{layer_hex}",
                "mediaType": layer_media_type,
                "size": len(layer),
            }
        ]
        * layer_count,
        "mediaType": DOCKER_MANIFEST,
        "schemaVersion": 2,
    }
    if mutation == "manifest-media-type":
        manifest["mediaType"] = OCI_MANIFEST
    manifest_raw = json.dumps(manifest, separators=(",", ":")).encode()
    manifest_hex = _sha256_bytes(manifest_raw)
    annotations = {
        "config.digest": f"sha256:{config_hex}",
        "io.containerd.image.name": f"docker.io/{tag}",
        "org.opencontainers.image.ref.name": revision,
    }
    if mutation == "missing-config-annotation":
        annotations.pop("config.digest")
    elif mutation == "wrong-config-annotation":
        annotations["config.digest"] = f"sha256:{'f' * 64}"
    elif mutation == "extra-annotation":
        annotations["unexpected"] = "value"
    elif mutation == "image-name":
        annotations["io.containerd.image.name"] = "docker.io/unexpected/name:tag"
    elif mutation == "ref-name":
        annotations["org.opencontainers.image.ref.name"] = "unexpected"
    descriptor = {
        "annotations": annotations,
        "digest": f"sha256:{manifest_hex}",
        "mediaType": DOCKER_MANIFEST,
        "size": len(manifest_raw),
    }
    if mutation == "top-media-type":
        descriptor["mediaType"] = OCI_MANIFEST
    elif mutation == "top-size":
        descriptor["size"] += 1
    descriptors = [descriptor]
    if mutation == "extra-descriptor":
        descriptors.append(copy.deepcopy(descriptor))
    index = {
        "manifests": descriptors,
        "mediaType": OCI_INDEX,
        "schemaVersion": 2,
    }
    legacy = [
        {
            "Config": f"blobs/sha256/{config_hex}",
            "Layers": [f"blobs/sha256/{layer_hex}"] * layer_count,
            "RepoTags": [tag],
        }
    ]
    if mutation == "legacy-config":
        legacy[0]["Config"] = f"blobs/sha256/{layer_hex}"
    elif mutation == "legacy-layers":
        legacy[0]["Layers"] = [f"blobs/sha256/{config_hex}"]
    files = {
        "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
        "index.json": json.dumps(index, separators=(",", ":")).encode(),
        "manifest.json": json.dumps(legacy, separators=(",", ":")).encode(),
        f"blobs/sha256/{manifest_hex}": manifest_raw,
        f"blobs/sha256/{config_hex}": config,
        f"blobs/sha256/{layer_hex}": layer,
    }
    if mutation == "unreferenced-blob":
        files[f"blobs/sha256/{'f' * 64}"] = b"unreferenced"
    if mutation == "provenance-attestation":
        attestation_raw = (
            b'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.'
            b'manifest.v1+json","config":{},"layers":[]}'
        )
        attestation_hex = _sha256_bytes(attestation_raw)
        nested_raw = json.dumps(
            {
                "manifests": [
                    {
                        "digest": descriptor["digest"],
                        "mediaType": OCI_MANIFEST,
                        "platform": {"architecture": "arm64", "os": "linux"},
                        "size": descriptor["size"],
                    },
                    {
                        "annotations": {
                            "vnd.docker.reference.digest": descriptor["digest"],
                            "vnd.docker.reference.type": "attestation-manifest",
                        },
                        "digest": f"sha256:{attestation_hex}",
                        "mediaType": OCI_MANIFEST,
                        "platform": {"architecture": "unknown", "os": "unknown"},
                        "size": len(attestation_raw),
                    },
                ],
                "mediaType": OCI_INDEX,
                "schemaVersion": 2,
            },
            separators=(",", ":"),
        ).encode()
        nested_hex = _sha256_bytes(nested_raw)
        index["manifests"] = [
            {
                "annotations": {
                    "io.containerd.image.name": f"docker.io/{tag}",
                    "org.opencontainers.image.ref.name": revision,
                },
                "digest": f"sha256:{nested_hex}",
                "mediaType": OCI_INDEX,
                "size": len(nested_raw),
            }
        ]
        files["index.json"] = json.dumps(index, separators=(",", ":")).encode()
        files[f"blobs/sha256/{nested_hex}"] = nested_raw
        files[f"blobs/sha256/{attestation_hex}"] = attestation_raw
    return files, tag, f"sha256:{manifest_hex}"


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


@pytest.mark.parametrize(
    "relative_factory",
    (
        lambda root: str(root / "target"),
        lambda root: "foo/../target",
        lambda root: "foo//bar",
        lambda root: "./target",
        lambda root: "foo\\bar",
        lambda root: "",
    ),
    ids=("absolute", "parent", "empty-segment", "dot", "backslash", "empty"),
)
def test_external_path_rejects_noncanonical_relative_forms(
    tmp_path: Path, relative_factory
) -> None:
    (tmp_path / "target").mkdir()
    (tmp_path / "foo").mkdir()
    (tmp_path / "foo/bar").mkdir()

    with pytest.raises(AssertionError):
        _external_path(tmp_path, relative_factory(tmp_path))


def test_external_path_rejects_symlink_component(tmp_path: Path) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "real/artifacts").mkdir()
    (tmp_path / "linked").symlink_to(tmp_path / "real", target_is_directory=True)

    with pytest.raises(AssertionError, match="symlink"):
        _external_path(tmp_path, "linked/artifacts")


def test_docker_archive_rejects_dangling_config_and_layers(tmp_path: Path) -> None:
    path = tmp_path / "candidate.docker-archive.tar"
    manifest = [
        {
            "Config": f"blobs/sha256/{'a' * 64}",
            "Layers": [f"blobs/sha256/{'b' * 64}"],
            "RepoTags": ["openworkproof/execution-test:revision"],
        }
    ]
    _write_test_archive(
        path,
        {
            "manifest.json": json.dumps(manifest).encode(),
            "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
            # Presence is sufficient here: legacy member validation runs first.
            "index.json": b"{}",
        },
    )

    with pytest.raises(AssertionError, match="archive member is missing"):
        _verify_docker_archive(path, "openworkproof/execution-test:revision")


def test_oci_archive_rejects_descriptor_without_media_type(tmp_path: Path) -> None:
    path = tmp_path / "candidate.oci-archive.tar"
    files, manifest_digest = _synthetic_oci_files(descriptor_media_type=False)
    _write_test_archive(path, files)

    with pytest.raises(AssertionError, match="mediaType"):
        _verify_oci_archive(path, manifest_digest)


def test_oci_archive_rejects_empty_config_object(tmp_path: Path) -> None:
    path = tmp_path / "candidate.oci-archive.tar"
    files, manifest_digest = _synthetic_oci_files(config=b"{}")
    _write_test_archive(path, files)

    with pytest.raises(AssertionError, match="config"):
        _verify_oci_archive(path, manifest_digest)


def test_oci_archive_rejects_unreferenced_regular_payload(tmp_path: Path) -> None:
    path = tmp_path / "candidate.oci-archive.tar"
    files, manifest_digest = _synthetic_oci_files()
    files["blobs/sha256/" + "f" * 64] = b"unreferenced"
    _write_test_archive(path, files)

    with pytest.raises(AssertionError, match="unreferenced"):
        _verify_oci_archive(path, manifest_digest)


def test_oci_archive_rejects_nonrevision_descriptor_created_time(
    tmp_path: Path,
) -> None:
    path = tmp_path / "candidate.oci-archive.tar"
    files, manifest_digest = _synthetic_oci_files()
    index = json.loads(files["index.json"])
    index["manifests"][0]["annotations"] = {
        "org.opencontainers.image.created": "2026-08-04T00:00:01Z"
    }
    files["index.json"] = json.dumps(index, separators=(",", ":")).encode()
    _write_test_archive(path, files)

    with pytest.raises(AssertionError, match="created"):
        _verify_oci_archive(
            path,
            manifest_digest,
            expected_created="2026-08-04T00:00:00Z",
        )


def test_synthetic_docker_archive_matches_provenance_free_docker_save_shape(
    tmp_path: Path,
) -> None:
    path = tmp_path / "candidate.docker-archive.tar"
    files, tag, local_image_id = _synthetic_docker_files()
    _write_test_archive(path, files)

    _verify_docker_archive(
        path,
        tag,
        {
            "cmd": None,
            "entrypoint": ["/usr/bin/env", "--"],
            "labels": {},
            "local_image_id": local_image_id,
            "user": "65532:65532",
        },
    )


@pytest.mark.parametrize(
    "mutation",
    (
        "provenance-attestation",
        "top-media-type",
        "extra-descriptor",
        "missing-config-annotation",
        "wrong-config-annotation",
        "extra-annotation",
        "image-name",
        "ref-name",
        "top-size",
        "config-media-type",
        "layer-media-type",
        "manifest-media-type",
        "legacy-config",
        "legacy-layers",
        "layer-count",
        "unreferenced-blob",
    ),
)
def test_docker_archive_rejects_nonactual_provenance_free_shape(
    tmp_path: Path,
    mutation: str,
) -> None:
    path = tmp_path / f"{mutation}.docker-archive.tar"
    files, tag, _ = _synthetic_docker_files(mutation)
    _write_test_archive(path, files)

    with pytest.raises(AssertionError):
        _verify_docker_archive(path, tag)


class _MembersOnlyArchive:
    def __init__(self, members: list[tarfile.TarInfo]) -> None:
        self._members = members

    def getmembers(self) -> list[tarfile.TarInfo]:
        return self._members

    def __iter__(self):
        return iter(self._members)


class _EarlyStopArchive:
    def __init__(self) -> None:
        self.getmembers_called = False
        self.yielded = 0
        self.requested_member_130 = False

    def __iter__(self):
        for index in range(MAX_ARCHIVE_MEMBERS + 2):
            if index == MAX_ARCHIVE_MEMBERS + 1:
                self.requested_member_130 = True
                raise RuntimeError("member 130 must never be requested")
            self.yielded += 1
            yield _regular_tar_member(f"payload-{index}")

    def getmembers(self) -> list[tarfile.TarInfo]:
        self.getmembers_called = True
        return list(self)


def _regular_tar_member(name: str, size: int = 1) -> tarfile.TarInfo:
    member = tarfile.TarInfo(name)
    member.size = size
    member.type = tarfile.REGTYPE
    return member


def test_archive_rejects_more_than_bounded_member_count() -> None:
    archive = _MembersOnlyArchive(
        [_regular_tar_member(f"payload-{index}") for index in range(5000)]
    )

    with pytest.raises(AssertionError, match="member count"):
        _safe_archive_members(archive)  # type: ignore[arg-type]


def test_archive_member_limit_stops_before_requesting_member_130() -> None:
    archive = _EarlyStopArchive()

    with pytest.raises(AssertionError, match="member count"):
        _safe_archive_members(archive)  # type: ignore[arg-type]

    assert not archive.getmembers_called
    assert archive.yielded == MAX_ARCHIVE_MEMBERS + 1
    assert not archive.requested_member_130


def test_real_tar_member_limit_keeps_only_bounded_cache(tmp_path: Path) -> None:
    path = tmp_path / "many-members.tar"
    _write_test_archive(
        path,
        {
            f"payload-{index}": b"x"
            for index in range(MAX_ARCHIVE_MEMBERS + 2)
        },
    )

    with tarfile.open(path, mode="r") as archive:
        with pytest.raises(AssertionError, match="member count"):
            _safe_archive_members(archive)
        assert len(archive.members) <= MAX_ARCHIVE_MEMBERS + 1


def test_archive_json_rejects_payload_larger_than_one_mebibyte() -> None:
    raw = json.dumps({"padding": "x" * (2 * 1024 * 1024)}).encode()

    with pytest.raises(AssertionError, match="JSON.*large"):
        _archive_json(raw, "oversized")


@pytest.mark.parametrize("member_kind", ("oversized", "sparse"))
def test_archive_rejects_oversized_or_sparse_member(member_kind: str) -> None:
    member = _regular_tar_member("payload")
    if member_kind == "oversized":
        member.size = MAX_ARCHIVE_BYTES + 1
    else:
        member.sparse = [(0, 1)]
    archive = _MembersOnlyArchive([member])

    with pytest.raises(AssertionError):
        _safe_archive_members(archive)  # type: ignore[arg-type]


@pytest.mark.parametrize("path_kind", ("symlink", "oversized"))
def test_archive_path_must_be_regular_nonsymlink_and_bounded(
    tmp_path: Path, path_kind: str
) -> None:
    target = tmp_path / "target.tar"
    target.write_bytes(b"tar")
    candidate = tmp_path / "candidate.tar"
    if path_kind == "symlink":
        candidate.symlink_to(target)
    else:
        candidate.write_bytes(b"")
        with candidate.open("r+b") as stream:
            stream.truncate(MAX_ARCHIVE_BYTES + 1)

    with pytest.raises(AssertionError):
        _verify_archive_path(candidate)


def test_image_config_rejects_more_than_64_layers() -> None:
    raw = _synthetic_image_config(layer_count=MAX_IMAGE_LAYERS + 1)

    with pytest.raises(AssertionError, match="layer"):
        _config_identity(
            raw,
            layer_count=MAX_IMAGE_LAYERS + 1,
            expected_image=None,
        )


def test_image_config_rejects_more_than_256_history_records() -> None:
    raw = _synthetic_image_config(layer_count=1, history_count=MAX_IMAGE_HISTORY + 1)

    with pytest.raises(AssertionError, match="history"):
        _config_identity(raw, layer_count=1, expected_image=None)


def test_external_snapshot_stays_anchored_when_open_ancestor_is_replaced(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifact-root"
    original = root / "a/b"
    outside = tmp_path / "outside"
    original.mkdir(parents=True)
    outside.mkdir()
    (original / "proof.txt").write_text("original", encoding="utf-8")
    (outside / "proof.txt").write_text("outside", encoding="utf-8")
    snapshot = tmp_path / "snapshot"

    def replace_open_ancestor() -> None:
        (root / "a").rename(root / "a-original")
        (root / "a").symlink_to(outside, target_is_directory=True)

    try:
        paths = _snapshot_external_subtrees(
            root,
            {"required": "a/b"},
            snapshot,
            after_open_hook=replace_open_ancestor,
        )
    except AssertionError:
        assert not snapshot.exists()
    else:
        assert (paths["required"] / "proof.txt").read_text(encoding="utf-8") == (
            "original"
        )
        assert "outside" not in {
            path.read_text(encoding="utf-8")
            for path in snapshot.rglob("*")
            if path.is_file()
        }


def _open_fd_set() -> set[int]:
    descriptors: set[int] = set()
    for descriptor in range(1024):
        try:
            os.fstat(descriptor)
        except OSError:
            continue
        descriptors.add(descriptor)
    return descriptors


@pytest.mark.parametrize("failed_binding", (1, 2), ids=("first", "child"))
def test_external_snapshot_closes_new_fds_when_initial_binding_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_binding: int,
) -> None:
    root = tmp_path / "root"
    (root / "a/b").mkdir(parents=True)
    snapshot = tmp_path / "snapshot"
    before = _open_fd_set()
    calls = 0

    def fail_selected_binding(*_args) -> None:
        nonlocal calls
        calls += 1
        if calls == failed_binding:
            raise AssertionError("forced binding failure")

    monkeypatch.setattr(
        sys.modules[__name__],
        "_assert_fd_binding",
        fail_selected_binding,
    )
    after: set[int] = set()
    try:
        with pytest.raises(AssertionError, match="forced binding failure"):
            _snapshot_external_subtrees(
                root,
                {"required": "a/b"},
                snapshot,
            )
        after = _open_fd_set()
    finally:
        for descriptor in after - before:
            os.close(descriptor)

    assert after == before
    assert not snapshot.exists()


@pytest.mark.parametrize("entry_kind", ("symlink", "hardlink", "fifo"))
def test_external_snapshot_rejects_nonregular_entries_and_cleans_partial(
    tmp_path: Path,
    entry_kind: str,
) -> None:
    root = tmp_path / "root"
    source = root / "required"
    source.mkdir(parents=True)
    regular = source / "regular"
    regular.write_bytes(b"proof")
    unsafe = source / "unsafe"
    if entry_kind == "symlink":
        unsafe.symlink_to(regular)
    elif entry_kind == "hardlink":
        os.link(regular, unsafe)
    else:
        os.mkfifo(unsafe)
    snapshot = tmp_path / "snapshot"

    with pytest.raises(AssertionError):
        _snapshot_external_subtrees(
            root,
            {"required": "required"},
            snapshot,
        )
    assert not snapshot.exists()


@pytest.mark.parametrize(
    ("limit_name", "limit"),
    (
        ("MAX_SNAPSHOT_ENTRIES", 0),
        ("MAX_SNAPSHOT_DEPTH", 0),
        ("MAX_SNAPSHOT_FILE_BYTES", 0),
        ("MAX_SNAPSHOT_TOTAL_BYTES", 0),
    ),
)
def test_external_snapshot_enforces_resource_bounds_and_cleans_partial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit_name: str,
    limit: int,
) -> None:
    root = tmp_path / "root"
    nested = root / "required/nested"
    nested.mkdir(parents=True)
    (nested / "proof").write_bytes(b"proof")
    snapshot = tmp_path / "snapshot"
    monkeypatch.setitem(globals(), limit_name, limit)

    with pytest.raises(AssertionError):
        _snapshot_external_subtrees(
            root,
            {"required": "required"},
            snapshot,
        )
    assert not snapshot.exists()


def test_context_identity_rejects_self_consistent_archive_replacement() -> None:
    recorded = _ImageIdentity(
        config_digest=f"sha256:{'a' * 64}",
        layer_digests=(f"sha256:{'b' * 64}",),
        rootfs_diff_ids=(f"sha256:{'c' * 64}",),
        config_semantics={"user": "65532:65532"},
    )
    rebuilt = _ImageIdentity(
        config_digest=f"sha256:{'d' * 64}",
        layer_digests=(f"sha256:{'e' * 64}",),
        rootfs_diff_ids=(f"sha256:{'f' * 64}",),
        config_semantics={"user": "65532:65532"},
    )

    with pytest.raises(AssertionError):
        _assert_image_identity_chain(recorded, recorded, rebuilt)


@pytest.mark.parametrize(
    ("group", "key"),
    [
        ("execution", "wheel_sha256sums_sha256"),
        ("trusted_helper", "wheel_sha256sums_sha256"),
        ("trusted_helper", "deb_sha256sums_sha256"),
        ("trusted_helper", "helper_src_sha256sums_sha256"),
    ],
)
def test_context_manifest_binding_rejects_an_arbitrary_inventory_digest(
    tmp_path: Path, group: str, key: str
) -> None:
    execution = tmp_path / "execution"
    helper = tmp_path / "trusted-helper"
    manifest_paths = {
        ("execution", "wheel_sha256sums_sha256"): (
            execution / "wheels/SHA256SUMS"
        ),
        ("trusted_helper", "wheel_sha256sums_sha256"): (
            helper / "wheels/SHA256SUMS"
        ),
        ("trusted_helper", "deb_sha256sums_sha256"): (
            helper / "debs/SHA256SUMS"
        ),
        ("trusted_helper", "helper_src_sha256sums_sha256"): (
            helper / "helper-src/SHA256SUMS"
        ),
    }
    inventory = {"build_inputs": {"execution": {}, "trusted_helper": {}}}
    for (input_group, input_key), path in manifest_paths.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(path.as_posix(), encoding="utf-8")
        inventory["build_inputs"][input_group][input_key] = _sha256_file(path)

    _verify_context_manifest_bindings(execution, helper, inventory)
    inventory["build_inputs"][group][key] = _sha256_bytes(b"arbitrary digest")

    with pytest.raises(AssertionError):
        _verify_context_manifest_bindings(execution, helper, inventory)


def test_current_candidate_inventory_binds_execution_runner() -> None:
    path, inventory = _select_current_inventory()
    revision = inventory["source_revision"]

    assert path.name == f"{revision}.json"
    assert inventory["schema_version"] == (
        "openworkproof-image-candidate-inventory/0.2"
    )
    assert inventory["build_inputs"]["execution"]["runner_sha256"] == (
        _sha256_bytes(_git_bytes(
            revision,
            "supply-chain/images/execution/run_tests_runner.py",
        ))
    )


def test_current_candidate_inventory_binds_fixed_test_source() -> None:
    _, inventory = _select_current_inventory()
    revision = inventory["source_revision"]

    assert inventory["build_inputs"]["execution"][
        "fixed_test_source_sha256"
    ] == _sha256_bytes(_git_bytes(
        revision,
        "supply-chain/images/execution/verifier_test.py",
    ))


def test_candidate_inventory_selector_rejects_zero_matches() -> None:
    with pytest.raises(AssertionError, match="matched 0"):
        _select_inventory_for_definition([], {})


def test_candidate_inventory_selector_rejects_multiple_matches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_path = INVENTORY_ROOT / (
        "4460abf3615252077bd37f182c8b69acf5c9da70.json"
    )
    current = _load_candidate_inventory(current_path)
    definition = {
        relative_path: (ROOT / relative_path).read_bytes()
        for relative_path in CURRENT_DEFINITION_PATHS
    }
    monkeypatch.setattr(
        sys.modules[__name__],
        "_git_bytes",
        lambda revision, relative_path: definition[relative_path],
    )

    with pytest.raises(AssertionError, match="matched 2"):
        _select_inventory_for_definition(
            [(current_path, current), (current_path, current)],
            definition,
        )


def test_candidate_inventory_selector_covers_every_tracked_definition() -> None:
    allowlist = tuple(
        line
        for line in (
            ROOT / "supply-chain/images/trusted-helper/SOURCE_ALLOWLIST"
        ).read_text(encoding="utf-8").splitlines()
        if line
    )
    assert allowlist == (
        "src/openworkproof/__init__.py",
        "src/openworkproof/models.py",
        "src/openworkproof/repo_tools.py",
        "src/openworkproof/trusted_helper.py",
    )
    assert CURRENT_DEFINITION_PATHS == ALL_TRACKED_DEFINITION_PATHS + allowlist


def test_candidate_inventory_selector_rejects_other_revision_alias(
    tmp_path: Path,
) -> None:
    current = _load_candidate_inventory(
        INVENTORY_ROOT / "4460abf3615252077bd37f182c8b69acf5c9da70.json"
    )
    alias_revision = subprocess.run(
        ["git", "rev-parse", f"{current['source_revision']}^"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    mutated = copy.deepcopy(current)
    mutated["source_revision"] = alias_revision
    path = tmp_path / f"{alias_revision}.json"
    path.write_text(json.dumps(mutated), encoding="utf-8")
    definition = {
        relative_path: (ROOT / relative_path).read_bytes()
        for relative_path in CURRENT_DEFINITION_PATHS
    }

    with pytest.raises(AssertionError):
        _select_inventory_for_definition([(path, mutated)], definition)


@pytest.mark.parametrize("relative_path", CURRENT_DEFINITION_PATHS)
def test_candidate_inventory_selector_rejects_each_tracked_definition_mutation(
    relative_path: str,
) -> None:
    candidates = [
        (path, _load_candidate_inventory(path))
        for path in sorted(INVENTORY_ROOT.glob("*.json"))
    ]
    definition = {
        tracked_path: (ROOT / tracked_path).read_bytes()
        for tracked_path in CURRENT_DEFINITION_PATHS
    }
    definition[relative_path] += b"\nmutation"

    with pytest.raises(AssertionError, match="matched 0"):
        _select_inventory_for_definition(candidates, definition)


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
        assert details["Config"].get("Cmd") == image["cmd"]
        assert details["Config"]["Labels"] == image["labels"]

    names = {
        key: f"owp-supplychain-{os.getpid()}-{key}"
        for key in (
            "execution",
            "helper-python",
            "helper-empty",
            "helper-argv",
            "helper-git",
            "helper-dpkg",
        )
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
        "--entrypoint",
        "/opt/venv/bin/python",
        str(execution["local_image_id"]),
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
        "--entrypoint",
        "/opt/venv/bin/python",
        str(helper["local_image_id"]),
        "-I",
        "-c",
        helper_check,
    )
    assert result.stdout == ""
    for name, argv in (
        (names["helper-empty"], ()),
        (names["helper-argv"], ("unexpected",)),
    ):
        result = _docker(
            docker,
            *common,
            "--name",
            name,
            "--user",
            str(helper["user"]),
            str(helper["local_image_id"]),
            *argv,
            check=False,
        )
        assert result.returncode == 64
        assert result.stdout == REQUEST_INVALID_RESPONSE
        assert result.stderr == ""
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


def test_live_execution_probe_overrides_frozen_runner_entrypoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution = {
        "candidate_name": "openworkproof/execution-test:revision",
        "local_image_id": "sha256:" + "a" * 64,
        "local_repo_digests": ["openworkproof/execution-test@sha256:" + "a" * 64],
        "platform": "linux/arm64",
        "user": "65532:65532",
        "entrypoint": [
            "/opt/venv/bin/python",
            "-I",
            "/opt/openworkproof/run_tests_runner.py",
        ],
        "cmd": ["execute"],
        "labels": {"org.openworkproof.image.role": "execution-test"},
    }
    helper = {
        "candidate_name": "openworkproof/trusted-helper-candidate:revision",
        "local_image_id": "sha256:" + "b" * 64,
        "local_repo_digests": [
            "openworkproof/trusted-helper-candidate@sha256:" + "b" * 64
        ],
        "platform": "linux/arm64",
        "user": "65532:65532",
        "entrypoint": ["/opt/venv/bin/python", "-I", "/opt/openworkproof/dispatch.py"],
        "cmd": None,
        "labels": {"org.openworkproof.image.role": "trusted-helper"},
    }
    details = {
        image["candidate_name"]: {
            "Id": image["local_image_id"],
            "RepoDigests": image["local_repo_digests"],
            "Os": "linux",
            "Architecture": "arm64",
            "Config": {
                "User": image["user"],
                "Entrypoint": image["entrypoint"],
                "Cmd": image["cmd"],
                "Labels": image["labels"],
            },
        }
        for image in (execution, helper)
    }
    commands: list[tuple[str, ...]] = []

    def fake_docker(executable: str, *args: str, check: bool = True):
        assert executable == "/usr/bin/docker"
        commands.append(args)
        if args == ("info",):
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[:2] == ("image", "inspect"):
            return subprocess.CompletedProcess(
                args,
                0,
                json.dumps([details[args[2]]]),
                "",
            )
        if args[:2] == ("container", "inspect"):
            return subprocess.CompletedProcess(args, 1, "", "missing")
        assert args[0] == "run"
        name = args[args.index("--name") + 1]
        if name.endswith(("helper-empty", "helper-argv")):
            return subprocess.CompletedProcess(args, 64, REQUEST_INVALID_RESPONSE, "")
        if name.endswith("helper-git"):
            return subprocess.CompletedProcess(args, 0, "git version 2.47.3\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setenv("OPENWORKPROOF_DOCKER", "/usr/bin/docker")
    monkeypatch.setattr(sys.modules[__name__], "_docker", fake_docker)

    _verify_live_docker({"images": {"execution": execution, "trusted_helper": helper}})

    execution_probe = next(
        command
        for command in commands
        if command[:2] == ("run", "--rm")
        and command[command.index("--name") + 1].endswith("-execution")
    )
    assert execution_probe == (
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--name",
        f"owp-supplychain-{os.getpid()}-execution",
        "--user",
        "65532:65532",
        "--entrypoint",
        "/opt/venv/bin/python",
        execution["local_image_id"],
        "-I",
        "-c",
        (
            "import importlib.util as u; import pytest; "
            "assert pytest.__version__ == '9.1.1'; "
            "assert u.find_spec('rich') is None; "
            "assert u.find_spec('openworkproof') is None; "
            "assert u.find_spec('mcp') is None"
        ),
    )


def test_rebuild_command_binds_single_revision_descriptor_created_annotation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    revision = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    revision_epoch = int(subprocess.run(
        ("git", "show", "-s", "--format=%ct", revision),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip())
    expected = (
        "manifest-descriptor:org.opencontainers.image.created="
        + datetime.fromtimestamp(revision_epoch, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    )
    captured: list[tuple[str, ...]] = []

    class CommandCaptured(RuntimeError):
        pass

    def capture(*args: str, **_: object) -> subprocess.CompletedProcess[str]:
        captured.append(args)
        raise CommandCaptured

    monkeypatch.setattr(sys.modules[__name__], "_docker", capture)
    with pytest.raises(CommandCaptured):
        _build_context_identity(
            "/usr/bin/docker",
            tmp_path / "context",
            revision,
            tmp_path / "rebuilt.oci.tar",
            {},
        )

    command = captured[0]
    assert command.count("--annotation") == 1
    annotation_index = command.index("--annotation")
    assert command[annotation_index + 1] == expected


def _revision_created(revision: str) -> str:
    epoch = subprocess.run(
        ("git", "show", "-s", "--format=%ct", revision),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert re.fullmatch(r"[0-9]+", epoch)
    return datetime.fromtimestamp(int(epoch), timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _build_context_argv(
    context: Path,
    revision: str,
    output: Path,
) -> tuple[str, ...]:
    created = _revision_created(revision)
    return (
        "buildx",
        "build",
        "--platform",
        "linux/arm64",
        "--network",
        "none",
        "--pull=false",
        "--provenance=false",
        "--build-arg",
        f"OWP_SOURCE_REVISION={revision}",
        "--annotation",
        f"manifest-descriptor:org.opencontainers.image.created={created}",
        "--output",
        f"type=oci,dest={output}",
        str(context),
    )


def _build_context_identity(
    docker: str,
    context: Path,
    revision: str,
    output: Path,
    expected_image: Mapping[str, object],
) -> _ImageIdentity:
    assert not output.exists()
    result = _docker(
        docker,
        *_build_context_argv(context, revision, output),
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert output.is_file() and not output.is_symlink()
    return _verify_oci_archive(
        output,
        str(expected_image["oci_manifest_digest"]),
        expected_image,
        expected_created=_revision_created(revision),
    )


def _assert_no_owned_docker_residue(docker: str) -> None:
    containers = _docker(
        docker,
        "ps",
        "-aq",
        "--filter",
        "label=openworkproof.execution-owner",
    )
    volumes = _docker(
        docker,
        "volume",
        "ls",
        "-q",
        "--filter",
        "label=openworkproof.execution-owner",
    )
    assert containers.stdout == "" and volumes.stdout == ""


@pytest.mark.supplychain
def test_candidate_artifact_chain(tmp_path: Path) -> None:
    required_live = os.environ.get("OPENWORKPROOF_REQUIRE_LIVE_DOCKER") == "1"
    root_value = os.environ.get("OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT")
    if not root_value:
        if required_live:
            pytest.fail("OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT is required for live Docker")
        pytest.skip(NO_ARTIFACT_ROOT)
    artifact_root = Path(root_value).expanduser()

    inventory_path, inventory = _select_current_inventory()
    inventory_bytes = inventory_path.read_bytes()
    revision = inventory["source_revision"]
    layout = inventory["external_layout"]["relative_paths"]
    paths = _snapshot_external_subtrees(
        artifact_root,
        layout,
        tmp_path / "external-artifact-snapshot",
    )
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
    _verify_context_manifest_bindings(execution_context, helper_context, inventory)
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
    identities: dict[str, tuple[_ImageIdentity, _ImageIdentity]] = {}
    for image_name, image in inventory["images"].items():
        docker_archive = image["archives"]["docker"]
        oci = image["archives"]["oci"]
        docker_identity = _verify_docker_archive(
            archives / docker_archive["filename"],
            image["candidate_name"],
            image,
        )
        oci_identity = _verify_oci_archive(
            archives / oci["filename"],
            image["oci_manifest_digest"],
            image,
            expected_created=_revision_created(revision),
        )
        _assert_image_identity_chain(docker_identity, oci_identity)
        identities[image_name] = (docker_identity, oci_identity)

    archived_inventory = archives / inventory_path.name
    sidecar = archives / f"{inventory_path.name}.sha256"
    assert archived_inventory.read_bytes() == inventory_bytes
    inventory_digest = _sha256_bytes(inventory_bytes)
    assert sidecar.read_text(encoding="utf-8") == (
        f"{inventory_digest}  {inventory_path.name}\n"
    )

    if required_live:
        _verify_live_docker(inventory)
        docker = os.environ.get("OPENWORKPROOF_DOCKER") or shutil.which("docker")
        assert docker is not None
        for image_name, context_name in (
            ("execution", "execution"),
            ("trusted_helper", "trusted-helper"),
        ):
            image = inventory["images"][image_name]
            rebuilt_identity = _build_context_identity(
                docker,
                rebuilt / context_name,
                revision,
                tmp_path / f"{image_name}.rebuilt.oci.tar",
                image,
            )
            docker_identity, oci_identity = identities[image_name]
            _assert_image_identity_chain(
                docker_identity, oci_identity, rebuilt_identity
            )
        _assert_no_owned_docker_residue(docker)
