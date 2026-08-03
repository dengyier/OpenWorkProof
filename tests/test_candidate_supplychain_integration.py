"""Explicit integration checks for the external Day 0 candidate artifacts."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
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
    "supply-chain/images/trusted-helper/Dockerfile",
    "supply-chain/images/trusted-helper/requirements.lock",
    "supply-chain/images/trusted-helper/debian-packages.lock",
    "supply-chain/images/trusted-helper/SOURCE_ALLOWLIST",
)
CURRENT_DEFINITION_PATHS = ALL_TRACKED_DEFINITION_PATHS
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
OCI_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
BLOB_PATH_PATTERN = re.compile(r"^blobs/sha256/([0-9a-f]{64})$")


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
        revision_definition = {
            relative_path: _git_bytes(revision, relative_path)
            for relative_path in CURRENT_DEFINITION_PATHS
        }
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


def _safe_archive_members(archive: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
    members: dict[str, tarfile.TarInfo] = {}
    for member in archive.getmembers():
        name = member.name.rstrip("/")
        member_path = PurePosixPath(name)
        assert name and not member_path.is_absolute() and ".." not in member_path.parts
        assert member_path.as_posix() == name
        assert not member.issym() and not member.islnk()
        assert member.isfile() or member.isdir()
        assert name not in members
        members[name] = member
    return members


def _archive_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        assert key not in value, f"duplicate archive JSON key: {key}"
        value[key] = item
    return value


def _archive_json(data: bytes, label: str) -> dict[str, object]:
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
    stream = archive.extractfile(member)
    assert stream is not None
    data = stream.read()
    assert len(data) == member.size
    return data


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
    data = _member_bytes(archive, members, f"blobs/sha256/{digest[7:]}")
    assert _sha256_bytes(data) == digest[7:]
    assert len(data) == size
    return data


def _config_identity(
    raw: bytes,
    *,
    layer_count: int,
    expected_image: Mapping[str, object] | None,
) -> tuple[tuple[str, ...], dict[str, object]]:
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
    assert type(history) is list and history
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
    expected_image: Mapping[str, object] | None,
) -> _ImageIdentity:
    manifest = _archive_json(manifest_raw, "image manifest")
    assert set(manifest) == {"schemaVersion", "mediaType", "config", "layers"}
    assert manifest["schemaVersion"] == 2 and manifest["mediaType"] == OCI_MANIFEST
    config_descriptor = _descriptor(
        manifest["config"], label="config", media_type=OCI_CONFIG
    )
    layers = manifest["layers"]
    assert type(layers) is list and layers, "image layers must be non-empty"
    layer_descriptors = [
        _descriptor(layer, label="layer", media_type=OCI_LAYER) for layer in layers
    ]
    config_raw = _descriptor_bytes(archive, members, config_descriptor)
    for layer in layer_descriptors:
        _descriptor_bytes(archive, members, layer)
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


def _verify_attestation_manifest(
    archive: tarfile.TarFile,
    members: Mapping[str, tarfile.TarInfo],
    manifest_raw: bytes,
) -> None:
    manifest = _archive_json(manifest_raw, "attestation manifest")
    assert set(manifest) == {"schemaVersion", "mediaType", "config", "layers"}
    assert manifest["schemaVersion"] == 2 and manifest["mediaType"] == OCI_MANIFEST
    config = _descriptor(manifest["config"], label="attestation config")
    _descriptor_bytes(archive, members, config)
    layers = manifest["layers"]
    assert type(layers) is list and layers
    for layer in layers:
        descriptor = _descriptor(
            layer,
            label="attestation layer",
            allow_annotations=True,
        )
        _descriptor_bytes(archive, members, descriptor)


def _verify_docker_archive(
    path: Path,
    expected_tag: str,
    expected_image: Mapping[str, object] | None = None,
) -> _ImageIdentity:
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
        assert type(layer_paths) is list and layer_paths
        layer_matches = [BLOB_PATH_PATTERN.fullmatch(item) for item in layer_paths]
        assert all(layer_matches), "Docker Layer path is not canonical"
        legacy_config = _member_bytes(archive, members, record["Config"])
        assert _sha256_bytes(legacy_config) == config_match.group(1)
        for layer_path, match in zip(layer_paths, layer_matches, strict=True):
            layer = _member_bytes(archive, members, layer_path)
            assert match is not None and _sha256_bytes(layer) == match.group(1)

        index = _archive_json(
            _member_bytes(archive, members, "index.json"), "Docker archive index"
        )
        assert set(index) == {"schemaVersion", "mediaType", "manifests"}
        assert index["schemaVersion"] == 2 and index["mediaType"] == OCI_INDEX
        assert type(index["manifests"]) is list and len(index["manifests"]) == 1
        top = _descriptor(
            index["manifests"][0],
            label="Docker index",
            media_type=OCI_INDEX,
            allow_annotations=True,
        )
        if expected_image is not None:
            assert top["digest"] == expected_image["local_image_id"]
            assert top["annotations"] == {
                "io.containerd.image.name": f"docker.io/{expected_tag}",
                "org.opencontainers.image.ref.name": expected_tag.rsplit(":", 1)[1],
            }
        nested_raw = _descriptor_bytes(archive, members, top)
        nested = _archive_json(nested_raw, "nested image index")
        assert set(nested) == {"schemaVersion", "mediaType", "manifests"}
        assert nested["schemaVersion"] == 2 and nested["mediaType"] == OCI_INDEX
        assert type(nested["manifests"]) is list and nested["manifests"]
        identities: list[tuple[dict[str, object], _ImageIdentity]] = []
        for raw_descriptor in nested["manifests"]:
            descriptor = _descriptor(
                raw_descriptor,
                label="nested manifest",
                allow_annotations=True,
                allow_platform=True,
            )
            manifest_raw = _descriptor_bytes(archive, members, descriptor)
            if descriptor.get("platform") == {"architecture": "arm64", "os": "linux"}:
                assert descriptor["mediaType"] == OCI_MANIFEST
                identities.append(
                    (
                        descriptor,
                        _image_manifest_identity(
                            archive,
                            members,
                            manifest_raw,
                            expected_image=expected_image,
                        ),
                    )
                )
            else:
                _verify_attestation_manifest(archive, members, manifest_raw)
        assert len(identities) == 1
        image_descriptor, identity = identities[0]
        if expected_image is not None:
            assert image_descriptor["digest"] == expected_image["oci_manifest_digest"]
        assert identity.config_digest == f"sha256:{config_match.group(1)}"
        assert identity.layer_digests == tuple(
            f"sha256:{match.group(1)}" for match in layer_matches if match is not None
        )
        return identity


def _verify_oci_archive(
    path: Path,
    expected_manifest_digest: str,
    expected_image: Mapping[str, object] | None = None,
) -> _ImageIdentity:
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
        assert descriptor["digest"] == expected_manifest_digest
        manifest_raw = _descriptor_bytes(archive, members, descriptor)
        return _image_manifest_identity(
            archive,
            members,
            manifest_raw,
            expected_image=expected_image,
        )


def _write_test_archive(path: Path, files: Mapping[str, bytes]) -> None:
    with tarfile.open(path, mode="w") as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(data))


def _synthetic_oci_files(
    *, descriptor_media_type: bool = True, config: bytes = b"{}"
) -> tuple[dict[str, bytes], str]:
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


def test_current_candidate_inventory_is_selected_by_tracked_definition() -> None:
    path, inventory = _select_current_inventory()

    assert path.name == f"{inventory['source_revision']}.json"


def test_candidate_inventory_selector_rejects_zero_matches() -> None:
    with pytest.raises(AssertionError, match="matched 0"):
        _select_inventory_for_definition([], {})


def test_candidate_inventory_selector_rejects_multiple_matches() -> None:
    historical_path = sorted(INVENTORY_ROOT.glob("*.json"))[0]
    historical = _load_candidate_inventory(historical_path)
    revision = historical["source_revision"]
    definition = {
        relative_path: _git_bytes(revision, relative_path)
        for relative_path in CURRENT_DEFINITION_PATHS
    }

    with pytest.raises(AssertionError, match="matched 2"):
        _select_inventory_for_definition(
            [(historical_path, historical), (historical_path, historical)],
            definition,
        )


def test_candidate_inventory_selector_covers_every_tracked_definition() -> None:
    assert CURRENT_DEFINITION_PATHS == ALL_TRACKED_DEFINITION_PATHS


def test_candidate_inventory_selector_rejects_head_revision_alias(
    tmp_path: Path,
) -> None:
    current_path, current = _select_current_inventory()
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    mutated = copy.deepcopy(current)
    mutated["source_revision"] = head
    path = tmp_path / f"{head}.json"
    path.write_text(json.dumps(mutated), encoding="utf-8")
    definition = {
        relative_path: (ROOT / relative_path).read_bytes()
        for relative_path in CURRENT_DEFINITION_PATHS
    }

    with pytest.raises(AssertionError):
        _select_inventory_for_definition([(path, mutated)], definition)


@pytest.mark.parametrize("relative_path", ALL_TRACKED_DEFINITION_PATHS)
def test_candidate_inventory_selector_rejects_each_tracked_definition_mutation(
    relative_path: str,
) -> None:
    candidates = [
        (path, _load_candidate_inventory(path))
        for path in sorted(INVENTORY_ROOT.glob("*.json"))
    ]
    definition = {
        tracked_path: (ROOT / tracked_path).read_bytes()
        for tracked_path in ALL_TRACKED_DEFINITION_PATHS
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
        "--output",
        f"type=oci,dest={output}",
        str(context),
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert output.is_file() and not output.is_symlink()
    return _verify_oci_archive(
        output,
        str(expected_image["oci_manifest_digest"]),
        expected_image,
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
            archives / oci["filename"], image["oci_manifest_digest"], image
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
