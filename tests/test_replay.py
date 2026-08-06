"""Frozen vectors for deterministic source and replay primitives."""

from __future__ import annotations

import base64
import copy
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import struct
import subprocess
from typing import Callable
import zlib

import pytest
import rfc8785

import openworkproof.repo_tools as repo_tools
from openworkproof.models import (
    EvidenceRef,
    PatchResultEvidence,
    ReplayProfile,
    TestResultEvidence as ResultEvidence,
    WorkOrder,
)
from openworkproof.repo_tools import (
    PatchError,
    SourceArchiveError,
    SourceFile,
    apply_patch_phase_b,
    git_blob_oid,
    git_commit_oid,
    git_tree_oid,
    parse_patch_phase_a,
    parse_source_archive,
    write_source_archive,
    validate_canonical_relative_path,
    OPENAT2_RESOLVE_FLAGS,
    ManifestError,
    PathError,
    ReplayError,
    ReplayPatchStep,
    ReplayRollbackStep,
    ReplayTestStep,
    ResolutionManifest,
    ResolutionManifestEntry,
    ResolutionError,
    ResolutionProbe,
    WorkspaceManifest,
    WorkspaceManifestEntry,
    WorkspaceScanRecord,
    build_resolution_manifest,
    build_workspace_manifest,
    derive_execution_snapshot_plan,
    replay_workspace_sequence,
    resolution_manifest_digest,
    root_semantically_covers,
    workspace_manifest_digest,
)


LOCAL_SIGNATURE = 0x04034B50
CENTRAL_SIGNATURE = 0x02014B50
EOCD_SIGNATURE = 0x06054B50
VERSION_NEEDED = 20
VERSION_MADE_BY = 0x0314
DOS_TIME = 0
DOS_DATE = 0x0021
EXTERNAL_ATTRIBUTES = 0o100444 << 16
MAX_SOURCE_ENTRIES = 126
MAX_SOURCE_FILE_BYTES = 1_048_576
MAX_SOURCE_UNCOMPRESSED_BYTES = 8_388_608

KNOWN_BLOB_OID = "ce013625030ba8dba906f756967f9e9ca394464a"
KNOWN_TREE_OID = "aaa96ced2d9a1c8e72c56b253a0e2fe78393feb7"
KNOWN_COMMIT_OID = "67f8f86632fe8e9c1e61f8a45d51d5dfae85ac13"
PARENT_OID = "1" * 40


@dataclass(frozen=True)
class FrozenSourceVector:
    raw: bytes
    files: tuple[SourceFile, ...]
    commit_raw: bytes
    source_commit: str
    tree_oid: str
    manifest: dict
    members: tuple[tuple[bytes, bytes], ...]


def _git_object_oid(kind: bytes, content: bytes) -> str:
    header = kind + b" " + str(len(content)).encode("ascii") + b"\0"
    return hashlib.sha1(header + content).hexdigest()


def _fixture_tree_oid(files: tuple[SourceFile, ...]) -> str:
    root: dict[bytes, object] = {}
    for source_file in files:
        node = root
        segments = source_file.path.encode("utf-8").split(b"/")
        for segment in segments[:-1]:
            node = node.setdefault(segment, {})  # type: ignore[assignment]
        node[segments[-1]] = source_file

    def build(node: dict[bytes, object]) -> str:
        encoded_entries = []
        ordered = sorted(
            node.items(),
            key=lambda item: item[0] + (b"/" if isinstance(item[1], dict) else b""),
        )
        for name, value in ordered:
            if isinstance(value, dict):
                mode = b"40000"
                oid = build(value)
            else:
                assert isinstance(value, SourceFile)
                mode = value.mode.encode("ascii")
                oid = _git_object_oid(b"blob", value.content)
            encoded_entries.append(
                mode + b" " + name + b"\0" + bytes.fromhex(oid)
            )
        return _git_object_oid(b"tree", b"".join(encoded_entries))

    return build(root)


def _canonical_zip(
    members: tuple[tuple[bytes, bytes], ...],
) -> bytes:
    local_parts: list[bytes] = []
    central_parts: list[bytes] = []
    offset = 0
    for name, content in members:
        crc = zlib.crc32(content) & 0xFFFFFFFF
        local = struct.pack(
            "<IHHHHHIIIHH",
            LOCAL_SIGNATURE,
            VERSION_NEEDED,
            0,
            0,
            DOS_TIME,
            DOS_DATE,
            crc,
            len(content),
            len(content),
            len(name),
            0,
        ) + name
        local_parts.extend((local, content))
        central_parts.append(
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                CENTRAL_SIGNATURE,
                VERSION_MADE_BY,
                VERSION_NEEDED,
                0,
                0,
                DOS_TIME,
                DOS_DATE,
                crc,
                len(content),
                len(content),
                len(name),
                0,
                0,
                0,
                0,
                EXTERNAL_ATTRIBUTES,
                offset,
            )
            + name
        )
        offset += len(local) + len(content)

    local_bytes = b"".join(local_parts)
    central_bytes = b"".join(central_parts)
    count = len(members)
    eocd = struct.pack(
        "<IHHHHIIH",
        EOCD_SIGNATURE,
        0,
        0,
        count,
        count,
        len(central_bytes),
        len(local_bytes),
        0,
    )
    return local_bytes + central_bytes + eocd


def _source_vector(
    entry_count: int = 1,
    *,
    with_parent: bool = True,
    files: tuple[SourceFile, ...] | None = None,
    commit_suffix: bytes = b"",
) -> FrozenSourceVector:
    if files is None:
        if entry_count == 1:
            files = (SourceFile("hello.txt", "100644", b"hello\n"),)
        else:
            files = tuple(
                SourceFile(
                    f"src/file-{index:03d}.py",
                    "100755" if index == 0 else "100644",
                    f"value = {index}\n".encode(),
                )
                for index in range(entry_count)
            )
    tree_oid = _fixture_tree_oid(files)
    parent_line = f"parent {PARENT_OID}\n" if with_parent else ""
    commit_raw = (
        f"tree {tree_oid}\n"
        f"{parent_line}"
        "author Fixture <fixture@example.invalid> 0 +0000\n"
        "committer Fixture <fixture@example.invalid> 0 +0000\n"
        "\n"
        "base fixture\n"
    ).encode() + commit_suffix
    source_commit = _git_object_oid(b"commit", commit_raw)
    entries = [
        {
            "path": source_file.path,
            "mode": source_file.mode,
            "size_bytes": len(source_file.content),
            "sha256": hashlib.sha256(source_file.content).hexdigest(),
            "blob_oid": _git_object_oid(b"blob", source_file.content),
        }
        for source_file in files
    ]
    manifest = {
        "schema_version": "openworkproof-source-manifest/0.1",
        "source_commit": source_commit,
        "tree_oid": tree_oid,
        "commit_path": "commit.raw",
        "entries": entries,
    }
    members = tuple(
        sorted(
            (
                (b"commit.raw", commit_raw),
                *(
                    (
                        b"files/" + source_file.path.encode("utf-8"),
                        source_file.content,
                    )
                    for source_file in files
                ),
                (b"source-manifest.json", rfc8785.dumps(manifest)),
            ),
            key=lambda item: item[0],
        )
    )
    return FrozenSourceVector(
        raw=_canonical_zip(members),
        files=files,
        commit_raw=commit_raw,
        source_commit=source_commit,
        tree_oid=tree_oid,
        manifest=manifest,
        members=members,
    )


def _bound_work_order(
    work_order_dict: dict,
    vector: FrozenSourceVector,
) -> WorkOrder:
    candidate = copy.deepcopy(work_order_dict)
    artifact_digest = hashlib.sha256(vector.raw).hexdigest()
    candidate["source_commit"] = vector.source_commit
    candidate["source_artifact"]["sha256"] = artifact_digest
    candidate["source_artifact"]["size_bytes"] = len(vector.raw)
    candidate["replay_profile"]["source_artifact_sha256"] = artifact_digest
    candidate["replay_profile_digest"] = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/replay-profile/v0.1",
                "profile": candidate["replay_profile"],
            }
        )
    ).hexdigest()
    return WorkOrder.model_validate(candidate)


def _parse(
    vector: FrozenSourceVector,
    work_order_dict: dict,
):
    work_order = _bound_work_order(work_order_dict, vector)
    return parse_source_archive(
        vector.raw,
        work_order,
        trusted_helper_image_digest=(
            work_order.replay_profile.trusted_helper_image_digest
        ),
    )


def _replace_member(
    vector: FrozenSourceVector,
    name: bytes,
    content: bytes,
) -> bytes:
    return _canonical_zip(
        tuple(
            (member_name, content if member_name == name else member_content)
            for member_name, member_content in vector.members
        )
    )


def _zip_offsets(raw: bytes) -> tuple[list[int], list[int], int]:
    local_offsets: list[int] = []
    position = 0
    while raw[position : position + 4] == b"PK\x03\x04":
        local_offsets.append(position)
        compressed_size = struct.unpack_from("<I", raw, position + 18)[0]
        name_length, extra_length = struct.unpack_from(
            "<HH", raw, position + 26
        )
        position += 30 + name_length + extra_length + compressed_size

    central_offsets: list[int] = []
    while raw[position : position + 4] == b"PK\x01\x02":
        central_offsets.append(position)
        name_length, extra_length, comment_length = struct.unpack_from(
            "<HHH", raw, position + 28
        )
        position += 46 + name_length + extra_length + comment_length
    assert raw[position : position + 4] == b"PK\x05\x06"
    return local_offsets, central_offsets, position


def _flip_field(
    raw: bytes,
    section: str,
    relative_offset: int,
) -> bytes:
    local_offsets, central_offsets, eocd_offset = _zip_offsets(raw)
    base = {
        "local": local_offsets[0],
        "central": central_offsets[0],
        "eocd": eocd_offset,
    }[section]
    mutated = bytearray(raw)
    mutated[base + relative_offset] ^= 1
    return bytes(mutated)


LOW_LEVEL_FIELDS = (
    ("local_signature", "local", 0),
    ("local_version_needed", "local", 4),
    ("local_flags", "local", 6),
    ("local_method", "local", 8),
    ("local_dos_time", "local", 10),
    ("local_dos_date", "local", 12),
    ("local_crc", "local", 14),
    ("local_compressed_size", "local", 18),
    ("local_uncompressed_size", "local", 22),
    ("local_filename_length", "local", 26),
    ("local_extra_length", "local", 28),
    ("local_filename", "local", 30),
    ("central_signature", "central", 0),
    ("central_version_made_by", "central", 4),
    ("central_version_needed", "central", 6),
    ("central_flags", "central", 8),
    ("central_method", "central", 10),
    ("central_dos_time", "central", 12),
    ("central_dos_date", "central", 14),
    ("central_crc", "central", 16),
    ("central_compressed_size", "central", 20),
    ("central_uncompressed_size", "central", 24),
    ("central_filename_length", "central", 28),
    ("central_extra_length", "central", 30),
    ("central_comment_length", "central", 32),
    ("central_disk_start", "central", 34),
    ("central_internal_attributes", "central", 36),
    ("central_external_attributes", "central", 38),
    ("central_local_offset", "central", 42),
    ("central_filename", "central", 46),
    ("eocd_signature", "eocd", 0),
    ("eocd_current_disk", "eocd", 4),
    ("eocd_start_disk", "eocd", 6),
    ("eocd_entries_on_disk", "eocd", 8),
    ("eocd_total_entries", "eocd", 10),
    ("eocd_central_size", "eocd", 12),
    ("eocd_central_offset", "eocd", 16),
    ("eocd_comment_length", "eocd", 20),
)


def test_frozen_source_vector_round_trips_exact_bytes_and_git_oids(
    work_order_dict: dict,
) -> None:
    vector = _source_vector()
    work_order = _bound_work_order(work_order_dict, vector)

    assert git_blob_oid(b"hello\n") == KNOWN_BLOB_OID
    assert git_tree_oid(vector.files) == KNOWN_TREE_OID
    assert git_commit_oid(vector.commit_raw) == KNOWN_COMMIT_OID
    assert vector.tree_oid == KNOWN_TREE_OID
    assert vector.source_commit == KNOWN_COMMIT_OID
    assert write_source_archive(vector.files, vector.commit_raw) == vector.raw

    parsed = parse_source_archive(
        vector.raw,
        work_order,
        trusted_helper_image_digest=(
            work_order.replay_profile.trusted_helper_image_digest
        ),
    )

    assert parsed.files == vector.files
    assert parsed.commit_raw == vector.commit_raw
    assert parsed.tree_oid == KNOWN_TREE_OID
    assert parsed.source_commit == KNOWN_COMMIT_OID
    assert parsed.artifact_sha256 == hashlib.sha256(vector.raw).hexdigest()
    assert parsed.artifact_size_bytes == len(vector.raw)
    assert parsed.shallow_bytes == f"{KNOWN_COMMIT_OID}\n".encode()


def test_source_parser_never_opens_or_extracts_ambient_files(
    work_order_dict: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vector = _source_vector()
    work_order = _bound_work_order(work_order_dict, vector)

    def forbid_open(*args, **kwargs):
        raise AssertionError("raw source parser attempted ambient filesystem I/O")

    monkeypatch.setattr("builtins.open", forbid_open)

    parsed = parse_source_archive(
        vector.raw,
        work_order,
        trusted_helper_image_digest=(
            work_order.replay_profile.trusted_helper_image_digest
        ),
    )

    assert parsed.source_commit == vector.source_commit


@pytest.mark.parametrize("entry_count", (64, 65, 126))
def test_source_manifest_explicit_entry_limit_overrides_generic_limit(
    work_order_dict: dict,
    entry_count: int,
) -> None:
    vector = _source_vector(entry_count)

    parsed = _parse(vector, work_order_dict)

    assert len(parsed.files) == entry_count
    assert write_source_archive(vector.files, vector.commit_raw) == vector.raw


def test_source_manifest_rejects_127_entries(
    work_order_dict: dict,
) -> None:
    vector = _source_vector(127)
    work_order = _bound_work_order(work_order_dict, vector)

    with pytest.raises(SourceArchiveError, match="126"):
        parse_source_archive(
            vector.raw,
            work_order,
            trusted_helper_image_digest=(
                work_order.replay_profile.trusted_helper_image_digest
            ),
        )
    with pytest.raises(SourceArchiveError, match="126"):
        write_source_archive(vector.files, vector.commit_raw)


@pytest.mark.parametrize(
    ("path", "accepted"),
    (
        ("a" * 506, True),
        ("a" * 507, False),
        ("src/main.py", True),
        (".Git/config", True),
        (".git/config", False),
        ("/absolute", False),
        ("trailing/", False),
        ("empty//segment", False),
        (".", False),
        ("..", False),
        ("a/../b", False),
        ("a\\b", False),
        ("unicodé", False),
        ("glob*", False),
    ),
)
def test_source_paths_obey_ascii_canonical_and_protected_limits(
    work_order_dict: dict,
    path: str,
    accepted: bool,
) -> None:
    vector = _source_vector(files=(SourceFile(path, "100644", b"x\n"),))

    if accepted:
        assert _parse(vector, work_order_dict).files == vector.files
        assert write_source_archive(vector.files, vector.commit_raw) == vector.raw
    else:
        with pytest.raises(SourceArchiveError, match="path"):
            _parse(vector, work_order_dict)
        with pytest.raises(SourceArchiveError, match="path"):
            write_source_archive(vector.files, vector.commit_raw)


@pytest.mark.parametrize(
    ("mode", "accepted"),
    (
        ("100644", True),
        ("100755", True),
        ("100600", False),
        ("120000", False),
        ("160000", False),
    ),
)
def test_source_modes_are_closed(
    work_order_dict: dict,
    mode: str,
    accepted: bool,
) -> None:
    vector = _source_vector(files=(SourceFile("file.txt", mode, b"x\n"),))

    if accepted:
        assert _parse(vector, work_order_dict).files == vector.files
    else:
        with pytest.raises(SourceArchiveError, match="mode"):
            _parse(vector, work_order_dict)
        with pytest.raises(SourceArchiveError, match="mode"):
            write_source_archive(vector.files, vector.commit_raw)


def test_source_file_accepts_one_mib_and_rejects_one_byte_more(
    work_order_dict: dict,
) -> None:
    maximum = _source_vector(
        files=(
            SourceFile(
                "large.txt",
                "100644",
                b"x" * (MAX_SOURCE_FILE_BYTES - 1) + b"\n",
            ),
        )
    )
    oversized = _source_vector(
        files=(
            SourceFile(
                "large.txt",
                "100644",
                b"x" * MAX_SOURCE_FILE_BYTES + b"\n",
            ),
        )
    )

    assert len(_parse(maximum, work_order_dict).files[0].content) == (
        MAX_SOURCE_FILE_BYTES
    )
    with pytest.raises(SourceArchiveError, match="1 MiB"):
        _parse(oversized, work_order_dict)
    with pytest.raises(SourceArchiveError, match="1 MiB"):
        write_source_archive(oversized.files, oversized.commit_raw)


def test_source_total_uncompressed_size_is_bounded(
    work_order_dict: dict,
) -> None:
    files = tuple(
        SourceFile(
            f"file-{index}.txt",
            "100644",
            b"x" * (MAX_SOURCE_FILE_BYTES - 1) + b"\n",
        )
        for index in range(8)
    )
    vector = _source_vector(files=files)
    assert sum(len(content) for _, content in vector.members) > (
        MAX_SOURCE_UNCOMPRESSED_BYTES
    )
    base_work_order = _bound_work_order(work_order_dict, _source_vector())
    artifact_digest = hashlib.sha256(vector.raw).hexdigest()
    forged_profile = base_work_order.replay_profile.model_copy(
        update={"source_artifact_sha256": artifact_digest}
    )
    forged_work_order = base_work_order.model_copy(
        update={
            "source_commit": vector.source_commit,
            "source_artifact": base_work_order.source_artifact.model_copy(
                update={
                    "sha256": artifact_digest,
                    "size_bytes": len(vector.raw),
                }
            ),
            "replay_profile": forged_profile,
            "replay_profile_digest": hashlib.sha256(
                rfc8785.dumps(
                    {
                        "domain": "openworkproof/replay-profile/v0.1",
                        "profile": forged_profile.model_dump(mode="json"),
                    }
                )
            ).hexdigest(),
        }
    )

    with pytest.raises(SourceArchiveError, match="8 MiB"):
        parse_source_archive(
            vector.raw,
            forged_work_order,
            trusted_helper_image_digest=(
                forged_profile.trusted_helper_image_digest
            ),
        )
    with pytest.raises(SourceArchiveError, match="8 MiB"):
        write_source_archive(vector.files, vector.commit_raw)


def test_commit_raw_accepts_64_kib_and_rejects_one_byte_more(
    work_order_dict: dict,
) -> None:
    base = _source_vector()
    maximum = _source_vector(
        commit_suffix=b"x" * (65_536 - len(base.commit_raw))
    )
    oversized = _source_vector(
        commit_suffix=b"x" * (65_537 - len(base.commit_raw))
    )

    assert len(_parse(maximum, work_order_dict).commit_raw) == 65_536
    assert write_source_archive(maximum.files, maximum.commit_raw) == maximum.raw
    with pytest.raises(SourceArchiveError, match="64 KiB"):
        _parse(oversized, work_order_dict)
    with pytest.raises(SourceArchiveError, match="64 KiB"):
        write_source_archive(oversized.files, oversized.commit_raw)


def test_source_manifest_is_bounded_to_64_kib(
    work_order_dict: dict,
) -> None:
    files = tuple(
        SourceFile(
            f"{index:03d}" + "a" * 503,
            "100644",
            b"x\n",
        )
        for index in range(MAX_SOURCE_ENTRIES)
    )
    vector = _source_vector(files=files)
    manifest_bytes = dict(vector.members)[b"source-manifest.json"]
    assert len(manifest_bytes) > 65_536

    with pytest.raises(SourceArchiveError, match="manifest.*64 KiB"):
        _parse(vector, work_order_dict)
    with pytest.raises(SourceArchiveError, match="manifest.*64 KiB"):
        write_source_archive(vector.files, vector.commit_raw)


@pytest.mark.parametrize(
    ("label", "section", "relative_offset"),
    LOW_LEVEL_FIELDS,
)
def test_every_canonical_zip_field_is_frozen(
    work_order_dict: dict,
    label: str,
    section: str,
    relative_offset: int,
) -> None:
    vector = _source_vector()
    work_order = _bound_work_order(work_order_dict, vector)
    mutated = _flip_field(vector.raw, section, relative_offset)

    with pytest.raises(SourceArchiveError, match="canonical ZIP"):
        parse_source_archive(
            mutated,
            work_order.model_copy(
                update={
                    "source_artifact": (
                        work_order.source_artifact.model_copy(
                            update={
                                "sha256": hashlib.sha256(mutated).hexdigest(),
                                "size_bytes": len(mutated),
                            }
                        )
                    ),
                    "replay_profile": (
                        work_order.replay_profile.model_copy(
                            update={
                                "source_artifact_sha256": (
                                    hashlib.sha256(mutated).hexdigest()
                                )
                            }
                        )
                    ),
                }
            ),
            trusted_helper_image_digest=(
                work_order.replay_profile.trusted_helper_image_digest
            ),
        )


def test_source_member_registry_order_and_manifest_jcs_are_closed(
    work_order_dict: dict,
) -> None:
    vector = _source_vector()
    reversed_raw = _canonical_zip(tuple(reversed(vector.members)))
    extra_raw = _canonical_zip(
        tuple(sorted((*vector.members, (b"extra", b"x")), key=lambda item: item[0]))
    )
    noncanonical_manifest = _replace_member(
        vector,
        b"source-manifest.json",
        rfc8785.dumps(vector.manifest) + b"\n",
    )
    work_order = _bound_work_order(work_order_dict, vector)

    for raw in (reversed_raw, extra_raw, noncanonical_manifest):
        forged = work_order.model_copy(
            update={
                "source_artifact": work_order.source_artifact.model_copy(
                    update={
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "size_bytes": len(raw),
                    }
                ),
                "replay_profile": work_order.replay_profile.model_copy(
                    update={
                        "source_artifact_sha256": hashlib.sha256(raw).hexdigest()
                    }
                ),
            }
        )
        with pytest.raises(SourceArchiveError):
            parse_source_archive(
                raw,
                forged,
                trusted_helper_image_digest=(
                    forged.replay_profile.trusted_helper_image_digest
                ),
            )


def test_source_manifest_entry_order_and_missing_members_are_rejected(
    work_order_dict: dict,
) -> None:
    vector = _source_vector(2)
    reversed_manifest = copy.deepcopy(vector.manifest)
    reversed_manifest["entries"].reverse()
    reversed_entries_raw = _replace_member(
        vector,
        b"source-manifest.json",
        rfc8785.dumps(reversed_manifest),
    )
    missing_file_raw = _canonical_zip(
        tuple(
            member
            for member in vector.members
            if member[0] != b"files/src/file-000.py"
        )
    )
    missing_commit_raw = _canonical_zip(
        tuple(member for member in vector.members if member[0] != b"commit.raw")
    )
    work_order = _bound_work_order(work_order_dict, vector)

    for raw in (reversed_entries_raw, missing_file_raw, missing_commit_raw):
        artifact_digest = hashlib.sha256(raw).hexdigest()
        forged_profile = work_order.replay_profile.model_copy(
            update={"source_artifact_sha256": artifact_digest}
        )
        forged = work_order.model_copy(
            update={
                "source_artifact": work_order.source_artifact.model_copy(
                    update={
                        "sha256": artifact_digest,
                        "size_bytes": len(raw),
                    }
                ),
                "replay_profile": forged_profile,
                "replay_profile_digest": hashlib.sha256(
                    rfc8785.dumps(
                        {
                            "domain": "openworkproof/replay-profile/v0.1",
                            "profile": forged_profile.model_dump(mode="json"),
                        }
                    )
                ).hexdigest(),
            }
        )
        with pytest.raises(SourceArchiveError, match="manifest"):
            parse_source_archive(
                raw,
                forged,
                trusted_helper_image_digest=(
                    forged.replay_profile.trusted_helper_image_digest
                ),
            )


MANIFEST_MUTATIONS: tuple[tuple[str, Callable[[dict], None]], ...] = (
    (
        "schema_version",
        lambda manifest: manifest.__setitem__("schema_version", "unknown"),
    ),
    ("source_commit", lambda manifest: manifest.__setitem__("source_commit", "0" * 40)),
    ("tree_oid", lambda manifest: manifest.__setitem__("tree_oid", "0" * 40)),
    ("commit_path", lambda manifest: manifest.__setitem__("commit_path", "other")),
    ("extra_key", lambda manifest: manifest.__setitem__("extra", None)),
    (
        "entry_path",
        lambda manifest: manifest["entries"][0].__setitem__("path", "other.txt"),
    ),
    (
        "entry_mode",
        lambda manifest: manifest["entries"][0].__setitem__("mode", "100755"),
    ),
    (
        "entry_size",
        lambda manifest: manifest["entries"][0].__setitem__("size_bytes", 0),
    ),
    (
        "entry_sha256",
        lambda manifest: manifest["entries"][0].__setitem__("sha256", "0" * 64),
    ),
    (
        "entry_blob_oid",
        lambda manifest: manifest["entries"][0].__setitem__("blob_oid", "0" * 40),
    ),
    (
        "entry_extra_key",
        lambda manifest: manifest["entries"][0].__setitem__("extra", None),
    ),
)


@pytest.mark.parametrize(("label", "mutate"), MANIFEST_MUTATIONS)
def test_source_manifest_fields_are_recomputed_not_trusted(
    work_order_dict: dict,
    label: str,
    mutate: Callable[[dict], None],
) -> None:
    vector = _source_vector()
    manifest = copy.deepcopy(vector.manifest)
    mutate(manifest)
    raw = _replace_member(
        vector,
        b"source-manifest.json",
        rfc8785.dumps(manifest),
    )
    work_order = _bound_work_order(work_order_dict, vector)
    artifact_digest = hashlib.sha256(raw).hexdigest()
    forged_profile = work_order.replay_profile.model_copy(
        update={"source_artifact_sha256": artifact_digest}
    )
    forged = work_order.model_copy(
        update={
            "source_artifact": work_order.source_artifact.model_copy(
                update={"sha256": artifact_digest, "size_bytes": len(raw)}
            ),
            "replay_profile": forged_profile,
            "replay_profile_digest": hashlib.sha256(
                rfc8785.dumps(
                    {
                        "domain": "openworkproof/replay-profile/v0.1",
                        "profile": forged_profile.model_dump(mode="json"),
                    }
                )
            ).hexdigest(),
        }
    )

    with pytest.raises(SourceArchiveError, match="manifest"):
        parse_source_archive(
            raw,
            forged,
            trusted_helper_image_digest=(
                forged.replay_profile.trusted_helper_image_digest
            ),
        )


def test_commit_raw_tree_line_is_unique_and_first(
    work_order_dict: dict,
) -> None:
    vector = _source_vector()
    duplicate = vector.commit_raw + f"tree {vector.tree_oid}\n".encode()
    raw = _replace_member(vector, b"commit.raw", duplicate)
    digest = hashlib.sha256(raw).hexdigest()
    work_order = _bound_work_order(work_order_dict, vector)
    forged_profile = work_order.replay_profile.model_copy(
        update={"source_artifact_sha256": digest}
    )
    forged = work_order.model_copy(
        update={
            "source_artifact": work_order.source_artifact.model_copy(
                update={"sha256": digest, "size_bytes": len(raw)}
            ),
            "replay_profile": forged_profile,
            "replay_profile_digest": hashlib.sha256(
                rfc8785.dumps(
                    {
                        "domain": "openworkproof/replay-profile/v0.1",
                        "profile": forged_profile.model_dump(mode="json"),
                    }
                )
            ).hexdigest(),
        }
    )

    with pytest.raises(SourceArchiveError, match="commit.raw"):
        parse_source_archive(
            raw,
            forged,
            trusted_helper_image_digest=(
                forged.replay_profile.trusted_helper_image_digest
            ),
        )


def test_root_commit_has_no_shallow_file_and_parent_commit_has_exact_boundary(
    work_order_dict: dict,
) -> None:
    root = _source_vector(with_parent=False)
    parent = _source_vector(with_parent=True)

    assert _parse(root, work_order_dict).shallow_bytes is None
    assert _parse(parent, work_order_dict).shallow_bytes == (
        f"{parent.source_commit}\n".encode()
    )


@pytest.mark.parametrize(
    "binding",
    (
        "artifact_sha256",
        "artifact_size",
        "profile_artifact_sha256",
        "replay_profile_digest",
        "source_commit",
        "trusted_helper_image_digest",
    ),
)
def test_work_order_replay_profile_and_actual_artifact_are_three_way_bound(
    work_order_dict: dict,
    binding: str,
) -> None:
    vector = _source_vector()
    work_order = _bound_work_order(work_order_dict, vector)
    helper_digest = work_order.replay_profile.trusted_helper_image_digest

    if binding == "artifact_sha256":
        work_order = work_order.model_copy(
            update={
                "source_artifact": work_order.source_artifact.model_copy(
                    update={"sha256": "0" * 64}
                )
            }
        )
    elif binding == "artifact_size":
        work_order = work_order.model_copy(
            update={
                "source_artifact": work_order.source_artifact.model_copy(
                    update={"size_bytes": len(vector.raw) + 1}
                )
            }
        )
    elif binding == "profile_artifact_sha256":
        work_order = work_order.model_copy(
            update={
                "replay_profile": work_order.replay_profile.model_copy(
                    update={"source_artifact_sha256": "0" * 64}
                )
            }
        )
    elif binding == "replay_profile_digest":
        work_order = work_order.model_copy(
            update={"replay_profile_digest": "0" * 64}
        )
    elif binding == "source_commit":
        work_order = work_order.model_copy(update={"source_commit": "0" * 40})
    else:
        helper_digest = "sha256:" + "0" * 64

    with pytest.raises(SourceArchiveError, match="binding"):
        parse_source_archive(
            vector.raw,
            work_order,
            trusted_helper_image_digest=helper_digest,
        )


def test_truncated_and_trailing_source_bytes_are_rejected_before_parsing(
    work_order_dict: dict,
) -> None:
    vector = _source_vector()
    work_order = _bound_work_order(work_order_dict, vector)

    for raw in (vector.raw[:-1], vector.raw + b"x"):
        forged = work_order.model_copy(
            update={
                "source_artifact": work_order.source_artifact.model_copy(
                    update={
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "size_bytes": len(raw),
                    }
                ),
                "replay_profile": work_order.replay_profile.model_copy(
                    update={
                        "source_artifact_sha256": hashlib.sha256(raw).hexdigest()
                    }
                ),
            }
        )
        with pytest.raises(SourceArchiveError):
            parse_source_archive(
                raw,
                forged,
                trusted_helper_image_digest=(
                    forged.replay_profile.trusted_helper_image_digest
                ),
            )


@dataclass(frozen=True)
class FrozenPatchVector:
    raw: bytes
    parent_files: tuple[SourceFile, ...]
    result_files: tuple[SourceFile, ...]
    target_paths: tuple[str, ...]

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()


def _modify_section(
    *,
    path: str = "src/app.py",
    old_content: bytes = b"alpha\nbeta\n",
    new_content: bytes = b"alpha\nBETA\n",
    mode: str = "100644",
) -> bytes:
    old_oid = _git_object_oid(b"blob", old_content)
    new_oid = _git_object_oid(b"blob", new_content)
    return (
        f"diff --git a/{path} b/{path}\n"
        f"index {old_oid}..{new_oid} {mode}\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        "@@ -1,2 +1,2 @@\n"
        " alpha\n"
        "-beta\n"
        "+BETA\n"
    ).encode()


def _create_section(
    *,
    path: str = "src/new.py",
    content: bytes = b"created\n",
    mode: str = "100644",
) -> bytes:
    new_oid = _git_object_oid(b"blob", content)
    payload = content.removesuffix(b"\n").decode("utf-8")
    return (
        f"diff --git a/{path} b/{path}\n"
        f"new file mode {mode}\n"
        f"index {'0' * 40}..{new_oid}\n"
        "--- /dev/null\n"
        f"+++ b/{path}\n"
        "@@ -0,0 +1,1 @@\n"
        f"+{payload}\n"
    ).encode()


def _delete_section(
    *,
    path: str = "docs/remove.txt",
    content: bytes = b"remove\n",
    mode: str = "100644",
) -> bytes:
    old_oid = _git_object_oid(b"blob", content)
    payload = content.removesuffix(b"\n").decode("utf-8")
    return (
        f"diff --git a/{path} b/{path}\n"
        f"deleted file mode {mode}\n"
        f"index {old_oid}..{'0' * 40}\n"
        f"--- a/{path}\n"
        "+++ /dev/null\n"
        "@@ -1,1 +0,0 @@\n"
        f"-{payload}\n"
    ).encode()


def _patch_vector() -> FrozenPatchVector:
    parent_files = (
        SourceFile("docs/keep.txt", "100644", b"keep\n"),
        SourceFile("docs/remove.txt", "100644", b"remove\n"),
        SourceFile("src/app.py", "100644", b"alpha\nbeta\n"),
        SourceFile("src/keep.py", "100755", b"keep = True\n"),
    )
    result_files = (
        SourceFile("docs/keep.txt", "100644", b"keep\n"),
        SourceFile("src/app.py", "100644", b"alpha\nBETA\n"),
        SourceFile("src/keep.py", "100755", b"keep = True\n"),
        SourceFile("src/new.py", "100644", b"created\n"),
    )
    return FrozenPatchVector(
        raw=(
            _delete_section()
            + _modify_section()
            + _create_section()
        ),
        parent_files=parent_files,
        result_files=result_files,
        target_paths=("docs/remove.txt", "src/app.py", "src/new.py"),
    )


def _parse_patch(raw: bytes, target_paths: tuple[str, ...]):
    return parse_patch_phase_a(
        raw,
        expected_patch_digest=hashlib.sha256(raw).hexdigest(),
        expected_patch_size_bytes=len(raw),
        declared_target_paths=target_paths,
    )


def _replay_profile(work_order_dict: dict) -> tuple[ReplayProfile, str]:
    return (
        ReplayProfile.model_validate(work_order_dict["replay_profile"]),
        work_order_dict["replay_profile_digest"],
    )


def _apply_vector(
    vector: FrozenPatchVector,
    work_order_dict: dict,
    *,
    raw: bytes | None = None,
    parent_files: tuple[SourceFile, ...] | None = None,
    observed_paths: tuple[str, ...] | None = None,
    occurred_at: str = "2026-01-01T00:00:01Z",
    replay_profile_digest: str | None = None,
):
    patch_raw = vector.raw if raw is None else raw
    parsed = _parse_patch(patch_raw, vector.target_paths)
    profile, expected_profile_digest = _replay_profile(work_order_dict)
    return apply_patch_phase_b(
        parsed,
        vector.parent_files if parent_files is None else parent_files,
        parent_commit="2" * 40,
        parent_manifest_digest="a" * 64,
        workspace_manifest_digest="b" * 64,
        occurred_at=occurred_at,
        replay_profile=profile,
        replay_profile_digest=(
            expected_profile_digest
            if replay_profile_digest is None
            else replay_profile_digest
        ),
        observed_manifest_delta_paths=(
            vector.target_paths if observed_paths is None else observed_paths
        ),
    )


def test_patch_phase_a_derives_exact_sorted_paths_without_parent_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vector = _patch_vector()

    def forbid_access(*args, **kwargs):
        raise AssertionError("Phase A attempted external or parent access")

    monkeypatch.setattr("builtins.open", forbid_access)
    monkeypatch.setattr(subprocess, "run", forbid_access)
    monkeypatch.setattr(subprocess, "Popen", forbid_access)

    parsed = _parse_patch(vector.raw, vector.target_paths)

    assert parsed.raw == vector.raw
    assert parsed.patch_digest == vector.digest
    assert parsed.patch_size_bytes == len(vector.raw)
    assert parsed.derived_patch_paths == vector.target_paths
    assert tuple(section.operation for section in parsed.sections) == (
        "delete",
        "modify",
        "create",
    )


def test_patch_phase_b_applies_all_branches_and_rebuilds_exact_commit(
    work_order_dict: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vector = _patch_vector()

    def forbid_process(*args, **kwargs):
        raise AssertionError("reference applier called shell or Git")

    monkeypatch.setattr(subprocess, "run", forbid_process)
    monkeypatch.setattr(subprocess, "Popen", forbid_process)

    result = _apply_vector(vector, work_order_dict)
    expected_tree = _fixture_tree_oid(vector.result_files)
    unix_seconds = int(
        datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc).timestamp()
    )
    expected_commit_raw = (
        f"tree {expected_tree}\n"
        f"parent {'2' * 40}\n"
        "author OpenWorkProof Sidecar "
        f"<sidecar@openworkproof.invalid> {unix_seconds} +0000\n"
        "committer OpenWorkProof Sidecar "
        f"<sidecar@openworkproof.invalid> {unix_seconds} +0000\n"
        "\n"
        f"OpenWorkProof patch {vector.digest}\n"
    ).encode()
    expected_commit = _git_object_oid(b"commit", expected_commit_raw)

    assert result.files == vector.result_files
    assert result.changed_paths == vector.target_paths
    assert result.tree_oid == expected_tree
    assert result.commit_raw == expected_commit_raw
    assert result.candidate_commit == expected_commit
    assert isinstance(result.evidence, PatchResultEvidence)
    assert result.evidence.parent_commit == "2" * 40
    assert result.evidence.parent_manifest_digest == "a" * 64
    assert result.evidence.candidate_commit == expected_commit
    assert result.evidence.workspace_manifest_digest == "b" * 64
    assert result.evidence.patch_digest == vector.digest
    assert result.evidence.patch_size_bytes == len(vector.raw)
    assert (
        result.evidence.replay_profile_digest
        == work_order_dict["replay_profile_digest"]
    )


def test_patch_size_limit_accepts_65536_and_rejects_65537() -> None:
    path = "new.txt"
    fixed_without_payload = _create_section(path=path, content=b"x\n")
    payload_length = 65_536 - len(fixed_without_payload) + 1
    content = b"x" * payload_length + b"\n"
    maximum = _create_section(path=path, content=content)
    assert len(maximum) == 65_536

    parsed = _parse_patch(maximum, (path,))

    assert parsed.patch_size_bytes == 65_536
    oversized = _create_section(path=path, content=b"x" * (payload_length + 1) + b"\n")
    assert len(oversized) == 65_537
    with pytest.raises(PatchError, match="65536"):
        _parse_patch(oversized, (path,))


@pytest.mark.parametrize(
    ("label", "mutate"),
    (
        ("bom", lambda raw: b"\xef\xbb\xbf" + raw),
        ("nul", lambda raw: raw.replace(b"alpha", b"alp\0a", 1)),
        ("cr", lambda raw: raw.replace(b"\n", b"\r\n", 1)),
        ("invalid_utf8", lambda raw: raw.replace(b"alpha", b"\xfflpha", 1)),
        ("missing_final_lf", lambda raw: raw[:-1]),
        ("empty", lambda raw: b""),
        (
            "header_path_mismatch",
            lambda raw: raw.replace(
                b"diff --git a/src/app.py b/src/app.py",
                b"diff --git a/src/app.py b/src/other.py",
            ),
        ),
        (
            "uppercase_oid",
            lambda raw: raw.replace(
                _git_object_oid(b"blob", b"alpha\nbeta\n").encode(),
                _git_object_oid(b"blob", b"alpha\nbeta\n").upper().encode(),
            ),
        ),
        ("bad_mode", lambda raw: raw.replace(b"100644", b"100600", 1)),
        ("leading_zero", lambda raw: raw.replace(b"@@ -1,2", b"@@ -01,2")),
        (
            "unsafe_integer",
            lambda raw: raw.replace(
                b"@@ -1,2",
                b"@@ -9007199254740992,2",
            ),
        ),
        ("old_count", lambda raw: raw.replace(b"@@ -1,2", b"@@ -1,1")),
        ("new_count", lambda raw: raw.replace(b"+1,2 @@", b"+1,1 @@")),
        (
            "no_change_line",
            lambda raw: raw.replace(b"-beta\n+BETA\n", b" beta\n BETA\n"),
        ),
        ("hunk_section", lambda raw: raw.replace(b" @@\n", b" @@ function\n")),
        (
            "extended_header",
            lambda raw: raw.replace(
                b"--- a/src/app.py\n",
                b"similarity index 100%\n--- a/src/app.py\n",
            ),
        ),
        (
            "quoted_path",
            lambda raw: raw.replace(
                b"a/src/app.py b/src/app.py",
                b'"a/src/app.py" "b/src/app.py"',
            ),
        ),
    ),
)
def test_patch_phase_a_rejects_every_noncanonical_byte_grammar(
    label: str,
    mutate: Callable[[bytes], bytes],
) -> None:
    raw = mutate(_modify_section())

    with pytest.raises(PatchError):
        _parse_patch(raw, ("src/app.py",))


@pytest.mark.parametrize(
    "raw",
    (
        b"diff --git a/old b/new\nsimilarity index 100%\nrename from old\nrename to new\n",
        b"diff --git a/old b/new\nsimilarity index 100%\ncopy from old\ncopy to new\n",
        b"diff --git a/file b/file\nold mode 100644\nnew mode 100755\n",
        b"diff --git a/file b/file\nBinary files a/file and b/file differ\n",
        b"diff --cc file\nindex 1111111,2222222..3333333\n",
        b"diff --git a/sub b/sub\nindex 1111111111111111111111111111111111111111..2222222222222222222222222222222222222222 160000\n",
        b"diff --git a/link b/link\nnew file mode 120000\n",
    ),
)
def test_patch_phase_a_rejects_unsupported_git_features(raw: bytes) -> None:
    with pytest.raises(PatchError):
        _parse_patch(raw, ("file",))


@pytest.mark.parametrize(
    ("path", "accepted"),
    (
        ("a" * 512, True),
        ("a" * 513, False),
        ("src/main.py", True),
        ("/absolute", False),
        ("trailing/", False),
        ("empty//segment", False),
        (".", False),
        ("..", False),
        ("a/../b", False),
        ("a\\b", False),
        ("unicodé", False),
        ("glob*", False),
    ),
)
def test_patch_paths_follow_canonical_512_byte_grammar(
    path: str,
    accepted: bool,
) -> None:
    raw = _create_section(path=path)

    if accepted:
        assert _parse_patch(raw, (path,)).derived_patch_paths == (path,)
    else:
        with pytest.raises(PatchError, match="path"):
            _parse_patch(raw, (path,))


def test_patch_sections_and_declared_paths_are_exact_sorted_unique() -> None:
    first = _create_section(path="a.txt", content=b"a\n")
    second = _create_section(path="b.txt", content=b"b\n")

    parsed = _parse_patch(first + second, ("a.txt", "b.txt"))
    assert parsed.derived_patch_paths == ("a.txt", "b.txt")

    with pytest.raises(PatchError, match="order"):
        _parse_patch(second + first, ("a.txt", "b.txt"))
    with pytest.raises(PatchError, match="duplicate"):
        _parse_patch(first + first, ("a.txt",))
    with pytest.raises(PatchError, match="target"):
        _parse_patch(first + second, ("a.txt",))


def test_patch_phase_a_rejects_digest_and_size_before_grammar() -> None:
    raw = _modify_section()
    digest = hashlib.sha256(raw).hexdigest()

    with pytest.raises(PatchError, match="digest"):
        parse_patch_phase_a(
            raw,
            expected_patch_digest="0" * 64,
            expected_patch_size_bytes=len(raw),
            declared_target_paths=("src/app.py",),
        )
    with pytest.raises(PatchError, match="size"):
        parse_patch_phase_a(
            raw,
            expected_patch_digest=digest,
            expected_patch_size_bytes=len(raw) + 1,
            declared_target_paths=("src/app.py",),
        )


def test_patch_phase_a_rejects_more_than_32_target_paths() -> None:
    sections = tuple(
        _create_section(path=f"file-{index:02d}.txt", content=b"x\n")
        for index in range(33)
    )
    paths = tuple(f"file-{index:02d}.txt" for index in range(33))

    with pytest.raises(PatchError, match="32"):
        _parse_patch(b"".join(sections), paths)


def test_patch_phase_a_accepts_omitted_count_and_multiple_ordered_hunks() -> None:
    old = b"a\nb\nc\nd\n"
    new = b"A\nb\nc\nD\n"
    old_oid = _git_object_oid(b"blob", old)
    new_oid = _git_object_oid(b"blob", new)
    raw = (
        "diff --git a/file.txt b/file.txt\n"
        f"index {old_oid}..{new_oid} 100644\n"
        "--- a/file.txt\n"
        "+++ b/file.txt\n"
        "@@ -1 +1 @@\n"
        "-a\n"
        "+A\n"
        "@@ -4 +4 @@\n"
        "-d\n"
        "+D\n"
    ).encode()

    parsed = _parse_patch(raw, ("file.txt",))

    assert len(parsed.sections[0].hunks) == 2


@pytest.mark.parametrize(
    "raw_mutation",
    (
        lambda raw: raw.replace(
            _git_object_oid(b"blob", b"alpha\nbeta\n").encode(),
            b"f" * 40,
        ),
        lambda raw: raw.replace(
            _git_object_oid(b"blob", b"alpha\nBETA\n").encode(),
            b"e" * 40,
        ),
        lambda raw: raw.replace(b" alpha\n", b" gamma\n"),
        lambda raw: raw.replace(b"@@ -1,2 +1,2", b"@@ -2,2 +2,2"),
        lambda raw: raw.replace(b"-beta\n+BETA\n", b"-beta\n+beta\n"),
        lambda raw: raw.replace(
            b"@@ -1,2 +1,2 @@\n alpha\n-beta\n+BETA\n",
            b"@@ -1,2 +0,0 @@\n-alpha\n-beta\n",
        ),
    ),
)
def test_patch_phase_b_rejects_oid_context_offset_noop_and_empty_modify(
    work_order_dict: dict,
    raw_mutation: Callable[[bytes], bytes],
) -> None:
    vector = _patch_vector()
    raw = raw_mutation(vector.raw)

    with pytest.raises(PatchError):
        _apply_vector(vector, work_order_dict, raw=raw)


@pytest.mark.parametrize(
    "content",
    (
        b"\xef\xbb\xbfalpha\nbeta\n",
        b"alpha\0\nbeta\n",
        b"alpha\r\nbeta\n",
        b"\xff\nbeta\n",
        b"alpha\nbeta",
    ),
)
def test_patch_phase_b_rejects_noncanonical_touched_parent_text(
    work_order_dict: dict,
    content: bytes,
) -> None:
    vector = _patch_vector()
    parent_files = tuple(
        SourceFile(item.path, item.mode, content)
        if item.path == "src/app.py"
        else item
        for item in vector.parent_files
    )

    with pytest.raises(PatchError, match="text"):
        _apply_vector(vector, work_order_dict, parent_files=parent_files)


def test_patch_phase_b_enforces_parent_mode_and_create_preconditions(
    work_order_dict: dict,
) -> None:
    vector = _patch_vector()
    wrong_mode = tuple(
        SourceFile(item.path, "100755", item.content)
        if item.path == "src/app.py"
        else item
        for item in vector.parent_files
    )
    existing_create = (*vector.parent_files, SourceFile("src/new.py", "100644", b"x\n"))
    missing_parent_raw = _create_section(path="missing/new.py")

    with pytest.raises(PatchError, match="mode"):
        _apply_vector(vector, work_order_dict, parent_files=wrong_mode)
    with pytest.raises(PatchError, match="exist"):
        _apply_vector(vector, work_order_dict, parent_files=existing_create)
    with pytest.raises(PatchError, match="parent"):
        _apply_vector(
            FrozenPatchVector(
                raw=missing_parent_raw,
                parent_files=vector.parent_files,
                result_files=vector.result_files,
                target_paths=("missing/new.py",),
            ),
            work_order_dict,
        )


def test_patch_phase_b_delete_keeps_immediate_parent_directory(
    work_order_dict: dict,
) -> None:
    raw = _delete_section(path="only/remove.txt")
    vector = FrozenPatchVector(
        raw=raw,
        parent_files=(
            SourceFile("only/remove.txt", "100644", b"remove\n"),
        ),
        result_files=(),
        target_paths=("only/remove.txt",),
    )

    with pytest.raises(PatchError, match="parent"):
        _apply_vector(vector, work_order_dict)


def test_patch_phase_b_rejects_file_directory_prefix_collision(
    work_order_dict: dict,
) -> None:
    raw = _create_section(path="src/app.py/child.txt")
    vector = _patch_vector()
    collision = FrozenPatchVector(
        raw=raw,
        parent_files=vector.parent_files,
        result_files=vector.result_files,
        target_paths=("src/app.py/child.txt",),
    )

    with pytest.raises(PatchError, match="collision"):
        _apply_vector(collision, work_order_dict)


def test_patch_phase_b_requires_exact_manifest_delta_and_replay_digest(
    work_order_dict: dict,
) -> None:
    vector = _patch_vector()

    with pytest.raises(PatchError, match="manifest delta"):
        _apply_vector(
            vector,
            work_order_dict,
            observed_paths=("src/app.py",),
        )
    with pytest.raises(PatchError, match="replay profile"):
        _apply_vector(
            vector,
            work_order_dict,
            replay_profile_digest="0" * 64,
        )


@pytest.mark.parametrize(
    "occurred_at",
    (
        "1969-12-31T23:59:59Z",
        "2026-01-01T00:00:00.1Z",
        "2026-01-01T00:00:00+00:00",
        "2026-01-01 00:00:00Z",
        "2026-01-01T00:00:60Z",
        "not-a-time",
    ),
)
def test_patch_phase_b_commit_time_is_canonical_utc_second(
    work_order_dict: dict,
    occurred_at: str,
) -> None:
    with pytest.raises(PatchError, match="time"):
        _apply_vector(
            _patch_vector(),
            work_order_dict,
            occurred_at=occurred_at,
        )


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _scan_regular(
    path: bytes,
    *,
    content: bytes = b"x\n",
    mode: int = 0o100644,
    link_count: int = 1,
    read_token_before: str = "stable",
    read_token_after: str = "stable",
) -> WorkspaceScanRecord:
    return WorkspaceScanRecord(
        path_bytes=path,
        entry_type="regular",
        posix_mode=mode,
        size_bytes=len(content),
        content=content,
        symlink_target=None,
        link_count=link_count,
        read_token_before=read_token_before,
        read_token_after=read_token_after,
    )


def _scan_directory(path: bytes) -> WorkspaceScanRecord:
    return WorkspaceScanRecord(
        path_bytes=path,
        entry_type="directory",
        posix_mode=0o040755,
        size_bytes=None,
        content=None,
        symlink_target=None,
        link_count=1,
        read_token_before="stable",
        read_token_after="stable",
    )


def _scan_symlink(
    path: bytes,
    target: bytes = b"src/app.py",
) -> WorkspaceScanRecord:
    return WorkspaceScanRecord(
        path_bytes=path,
        entry_type="symlink",
        posix_mode=0o120777,
        size_bytes=len(target),
        content=None,
        symlink_target=target,
        link_count=1,
        read_token_before="stable",
        read_token_after="stable",
    )


def _scan_other(
    path: bytes,
    *,
    mode: int,
) -> WorkspaceScanRecord:
    return WorkspaceScanRecord(
        path_bytes=path,
        entry_type="other",
        posix_mode=mode,
        size_bytes=0,
        content=None,
        symlink_target=None,
        link_count=1,
        read_token_before="stable",
        read_token_after="stable",
    )


@pytest.mark.parametrize(
    "path",
    (
        "a",
        "a" * 512,
        "src/main.py",
        ".gitignore",
        ".Git/config",
        "src/.git/config",
    ),
)
def test_canonical_relative_path_accepts_only_frozen_ascii_profile(
    path: str,
) -> None:
    assert validate_canonical_relative_path(path) == path


@pytest.mark.parametrize(
    "path",
    (
        "",
        "a" * 513,
        "/absolute",
        "trailing/",
        "empty//segment",
        ".",
        "..",
        "a/./b",
        "a/../b",
        "a\\b",
        "unicodé",
        "glob*",
        "question?",
        "class[ab]",
        ".git",
        ".git/config",
    ),
)
def test_canonical_relative_path_rejects_aliases_and_protected_git(
    path: str,
) -> None:
    with pytest.raises(PathError, match="path|protected"):
        validate_canonical_relative_path(path)


def test_root_coverage_is_segment_aware_and_source_type_aware() -> None:
    files = (
        SourceFile(".Git/config", "100644", b"case-sensitive\n"),
        SourceFile("README.md", "100644", b"readme\n"),
        SourceFile("src/app.py", "100644", b"app\n"),
        SourceFile("src/pkg/module.py", "100644", b"module\n"),
        SourceFile("src2/other.py", "100644", b"other\n"),
    )

    assert root_semantically_covers("src", "src", files) is True
    assert root_semantically_covers("src", "src/app.py", files) is True
    assert root_semantically_covers("src", "src/pkg/module.py", files) is True
    assert root_semantically_covers("src", "src2/other.py", files) is False
    assert root_semantically_covers("README.md", "README.md", files) is True
    assert root_semantically_covers("README.md", "README.md/child", files) is False
    assert root_semantically_covers(".Git", ".Git/config", files) is True

    with pytest.raises(PathError, match="source|root"):
        root_semantically_covers("missing", "missing/file.py", files)


def test_workspace_manifest_encodes_all_entry_types_in_raw_byte_order() -> None:
    head = "1" * 40
    records = (
        _scan_other(b"socket", mode=0o140777),
        _scan_regular(b"src/app.py", content=b"print('ok')\n", mode=0o100755),
        _scan_symlink(b"link", b"src/app.py"),
        _scan_directory(b"src"),
    )

    manifest = build_workspace_manifest(head, records)

    assert manifest.schema_version == "openworkproof-workspace-manifest/0.1"
    assert manifest.head_commit == head
    assert tuple(
        base64.urlsafe_b64decode(
            entry.path_bytes_b64url + "=" * (-len(entry.path_bytes_b64url) % 4)
        )
        for entry in manifest.entries
    ) == (b"link", b"socket", b"src", b"src/app.py")
    by_path = {
        entry.path_bytes_b64url: entry for entry in manifest.entries
    }
    assert by_path[_b64url(b"src")].type == "directory"
    assert by_path[_b64url(b"src")].posix_mode == "040755"
    assert by_path[_b64url(b"src")].size_bytes is None
    assert by_path[_b64url(b"src/app.py")].type == "regular"
    assert by_path[_b64url(b"src/app.py")].posix_mode == "100755"
    assert by_path[_b64url(b"src/app.py")].size_bytes == len(b"print('ok')\n")
    assert by_path[_b64url(b"src/app.py")].sha256 == hashlib.sha256(
        b"print('ok')\n"
    ).hexdigest()
    assert by_path[_b64url(b"link")].type == "symlink"
    assert by_path[_b64url(b"link")].symlink_target_b64url == _b64url(
        b"src/app.py"
    )
    assert by_path[_b64url(b"socket")].type == "other"


def test_workspace_manifest_has_no_ignored_or_output_exclusion() -> None:
    records = tuple(
        _scan_regular(path)
        for path in (
            b".git/config",
            b".pytest_cache/state",
            b"ignored.log",
            b"output/result.json",
        )
    )

    manifest = build_workspace_manifest("1" * 40, records)

    assert {
        entry.path_bytes_b64url for entry in manifest.entries
    } == {_b64url(record.path_bytes) for record in records}


@pytest.mark.parametrize("entry_count", (64, 65, 512))
def test_workspace_manifest_uses_explicit_512_entry_limit(
    entry_count: int,
) -> None:
    records = tuple(
        _scan_regular(f"file-{index:03d}.txt".encode("ascii"))
        for index in range(entry_count)
    )

    manifest = build_workspace_manifest("1" * 40, records)

    assert len(manifest.entries) == entry_count


def test_workspace_manifest_rejects_513_entries() -> None:
    records = tuple(
        _scan_regular(f"file-{index:03d}.txt".encode("ascii"))
        for index in range(513)
    )

    with pytest.raises(ManifestError, match="512"):
        build_workspace_manifest("1" * 40, records)


@pytest.mark.parametrize(
    ("label", "records"),
    (
        (
            "duplicate",
            (_scan_regular(b"same"), _scan_regular(b"same")),
        ),
        (
            "hardlink",
            (_scan_regular(b"a", link_count=2),),
        ),
        (
            "read_race",
            (
                _scan_regular(
                    b"a",
                    read_token_before="before",
                    read_token_after="after",
                ),
            ),
        ),
    ),
)
def test_workspace_manifest_rejects_duplicate_hardlink_and_read_race(
    label: str,
    records: tuple[WorkspaceScanRecord, ...],
) -> None:
    with pytest.raises(ManifestError, match="duplicate|hardlink|race"):
        build_workspace_manifest("1" * 40, records)


def test_workspace_manifest_digest_uses_exact_domain_and_closed_shape() -> None:
    manifest = build_workspace_manifest(
        "1" * 40,
        (
            _scan_directory(b"src"),
            _scan_regular(b"src/app.py", content=b"app\n"),
        ),
    )
    expected_manifest = {
        "schema_version": "openworkproof-workspace-manifest/0.1",
        "head_commit": "1" * 40,
        "entries": [
            {
                "path_bytes_b64url": _b64url(b"src"),
                "type": "directory",
                "posix_mode": "040755",
                "size_bytes": None,
                "sha256": None,
                "symlink_target_b64url": None,
            },
            {
                "path_bytes_b64url": _b64url(b"src/app.py"),
                "type": "regular",
                "posix_mode": "100644",
                "size_bytes": 4,
                "sha256": hashlib.sha256(b"app\n").hexdigest(),
                "symlink_target_b64url": None,
            },
        ],
    }
    expected = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/workspace-manifest/v0.1",
                "manifest": expected_manifest,
            }
        )
    ).hexdigest()

    assert workspace_manifest_digest(manifest) == expected


def _assert_workspace_manifest_serializers_reject(manifest: object) -> None:
    for serializer in (
        repo_tools._workspace_manifest_json,
        workspace_manifest_digest,
    ):
        with pytest.raises(ManifestError):
            serializer(manifest)


@pytest.mark.parametrize(
    "case",
    (
        "manifest_type",
        "head_type",
        "head_digest",
        "entries_type",
        "entry_type",
        "escape_path",
        "overlong_path",
        "bogus_type",
        "illegal_mode",
        "negative_size",
        "oversized_integer",
        "illegal_digest",
        "missing_digest",
        "mutually_exclusive_fields",
        "entry_count",
    ),
)
def test_workspace_manifest_serializers_reject_forged_dataclasses(
    case: str,
) -> None:
    valid = build_workspace_manifest(
        "1" * 40,
        (_scan_regular(b"src/app.py", content=b"app\n"),),
    )
    entry = valid.entries[0]
    forged: dict[str, object] = {
        "manifest_type": object(),
        "head_type": replace(valid, head_commit=1),
        "head_digest": replace(valid, head_commit="g" * 40),
        "entries_type": replace(valid, entries=[entry]),
        "entry_type": replace(valid, entries=(object(),)),
        "escape_path": replace(
            valid,
            entries=(
                replace(entry, path_bytes_b64url=_b64url(b"../escape")),
            ),
        ),
        "overlong_path": replace(
            valid,
            entries=(
                replace(entry, path_bytes_b64url=_b64url(b"a" * 513)),
            ),
        ),
        "bogus_type": replace(
            valid,
            entries=(replace(entry, type="bogus"),),
        ),
        "illegal_mode": replace(
            valid,
            entries=(replace(entry, posix_mode="999999"),),
        ),
        "negative_size": replace(
            valid,
            entries=(replace(entry, size_bytes=-1),),
        ),
        "oversized_integer": replace(
            valid,
            entries=(replace(entry, size_bytes=9_007_199_254_740_992),),
        ),
        "illegal_digest": replace(
            valid,
            entries=(replace(entry, sha256="g" * 64),),
        ),
        "missing_digest": replace(
            valid,
            entries=(replace(entry, sha256=None),),
        ),
        "mutually_exclusive_fields": replace(
            valid,
            entries=(
                replace(
                    entry,
                    symlink_target_b64url=_b64url(b"target"),
                ),
            ),
        ),
        "entry_count": replace(valid, entries=(entry,) * 513),
    }

    _assert_workspace_manifest_serializers_reject(forged[case])


@pytest.mark.parametrize(
    ("entry_type", "posix_mode"),
    (
        ("regular", "500644"),
        ("other", "410777"),
    ),
)
def test_workspace_manifest_serializers_reject_modes_above_posix_boundary(
    entry_type: str,
    posix_mode: str,
) -> None:
    valid = build_workspace_manifest(
        "1" * 40,
        (_scan_regular(b"src/app.py", content=b"app\n"),),
    )
    entry = valid.entries[0]
    forged_entry = replace(
        entry,
        type=entry_type,
        posix_mode=posix_mode,
        sha256=entry.sha256 if entry_type == "regular" else None,
    )

    _assert_workspace_manifest_serializers_reject(
        replace(valid, entries=(forged_entry,))
    )


def test_workspace_manifest_serializers_accept_posix_mode_upper_boundary() -> None:
    valid = build_workspace_manifest(
        "1" * 40,
        (_scan_regular(b"socket", content=b""),),
    )
    boundary_entry = replace(
        valid.entries[0],
        type="other",
        posix_mode="177777",
        sha256=None,
    )
    boundary = replace(valid, entries=(boundary_entry,))

    assert repo_tools._workspace_manifest_json(boundary)["entries"][0][
        "posix_mode"
    ] == "177777"
    assert len(workspace_manifest_digest(boundary)) == 64


def test_execution_snapshot_plan_is_read_only_and_metadata_normalized() -> None:
    files = (
        SourceFile("src/app.py", "100644", b"app\n"),
        SourceFile("src/tool.py", "100755", b"tool\n"),
    )
    manifest = build_workspace_manifest(
        "1" * 40,
        (
            _scan_directory(b"src"),
            _scan_regular(b"src/app.py", content=b"app\n"),
            _scan_regular(
                b"src/tool.py",
                content=b"tool\n",
                mode=0o100755,
            ),
        ),
    )

    first = derive_execution_snapshot_plan(manifest, files)
    second = derive_execution_snapshot_plan(manifest, files)

    assert first == second
    assert first.files == files
    assert first.read_only is True
    assert first.owner_uid == 65_532
    assert first.owner_gid == 65_532
    assert first.atime_unix_seconds == 0
    assert first.mtime_unix_seconds == 0
    assert first.clear_extended_attributes is True
    assert first.clear_posix_acls is True
    assert first.clear_file_capabilities is True


@pytest.mark.parametrize(
    "record",
    (
        _scan_regular(b"\xff"),
        _scan_regular(b"a/../b"),
        _scan_regular(b"bad-mode", mode=0o100600),
        _scan_symlink(b"link"),
        _scan_other(b"socket", mode=0o140777),
        _scan_other(b"fifo", mode=0o010644),
        _scan_other(b"device", mode=0o020600),
    ),
)
def test_execution_snapshot_rejects_noncanonical_or_special_entries(
    record: WorkspaceScanRecord,
) -> None:
    manifest = build_workspace_manifest("1" * 40, (record,))

    with pytest.raises(ManifestError, match="canonical|mode|symlink|other"):
        derive_execution_snapshot_plan(manifest, ())


def _resolution_workspace():
    return build_workspace_manifest(
        "1" * 40,
        (
            _scan_symlink(b"link", b"src"),
            _scan_directory(b"src"),
            _scan_regular(b"src/app.py", content=b"app\n"),
            _scan_directory(b"src/pkg"),
            _scan_regular(b"src/pkg/module.py", content=b"module\n"),
        ),
    )


def test_resolution_manifest_binds_exact_openat2_results_and_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbid_resolution_substitute(*args, **kwargs):
        raise AssertionError("host-language path resolution was used")

    monkeypatch.setattr("builtins.open", forbid_resolution_substitute)
    monkeypatch.setattr("os.path.realpath", forbid_resolution_substitute)
    monkeypatch.setattr("pathlib.Path.resolve", forbid_resolution_substitute)
    workspace = _resolution_workspace()
    requested = ("link/child.py", "src/app.py", "src/new.py")
    probes = (
        ResolutionProbe(
            requested_path="link/child.py",
            resolved_relative_path=None,
            openat2_flags=OPENAT2_RESOLVE_FLAGS,
        ),
        ResolutionProbe(
            requested_path="src/app.py",
            resolved_relative_path="src/app.py",
            openat2_flags=OPENAT2_RESOLVE_FLAGS,
        ),
        ResolutionProbe(
            requested_path="src/new.py",
            resolved_relative_path="src/new.py",
            openat2_flags=OPENAT2_RESOLVE_FLAGS,
        ),
    )

    manifest = build_resolution_manifest(workspace, requested, probes)
    expected_manifest = {
        "schema_version": "openworkproof-resolution-manifest/0.1",
        "workspace_manifest_digest": workspace_manifest_digest(workspace),
        "requested_paths": list(requested),
        "resolved_entries": [
            {
                "requested_path": "link/child.py",
                "resolved_relative_path": None,
            },
            {
                "requested_path": "src/app.py",
                "resolved_relative_path": "src/app.py",
            },
            {
                "requested_path": "src/new.py",
                "resolved_relative_path": "src/new.py",
            },
        ],
    }
    expected_digest = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/resolution-manifest/v0.1",
                "manifest": expected_manifest,
            }
        )
    ).hexdigest()

    assert manifest.workspace_manifest_digest == workspace_manifest_digest(
        workspace
    )
    assert manifest.requested_paths == requested
    assert tuple(
        (entry.requested_path, entry.resolved_relative_path)
        for entry in manifest.resolved_entries
    ) == (
        ("link/child.py", None),
        ("src/app.py", "src/app.py"),
        ("src/new.py", "src/new.py"),
    )
    assert resolution_manifest_digest(manifest) == expected_digest


def _assert_resolution_manifest_serializers_reject(manifest: object) -> None:
    for serializer in (
        repo_tools._resolution_manifest_json,
        resolution_manifest_digest,
    ):
        with pytest.raises(ResolutionError):
            serializer(manifest)


@pytest.mark.parametrize(
    "case",
    (
        "manifest_type",
        "digest_type",
        "illegal_digest",
        "requested_paths_type",
        "resolved_entries_type",
        "requested_path_type",
        "entry_type",
        "missing_entry",
        "escape_requested",
        "protected_requested",
        "duplicate_requested",
        "unsorted_requested",
        "escape_resolved",
        "mismatched_resolved",
        "resolved_type",
        "path_count",
    ),
)
def test_resolution_manifest_serializers_reject_forged_dataclasses(
    case: str,
) -> None:
    entry = ResolutionManifestEntry(
        requested_path="src/app.py",
        resolved_relative_path="src/app.py",
    )
    valid = ResolutionManifest(
        schema_version="openworkproof-resolution-manifest/0.1",
        workspace_manifest_digest="a" * 64,
        requested_paths=("src/app.py",),
        resolved_entries=(entry,),
    )
    many_paths = tuple(f"src/{index:02d}.py" for index in range(33))
    forged: dict[str, object] = {
        "manifest_type": object(),
        "digest_type": replace(valid, workspace_manifest_digest=1),
        "illegal_digest": replace(valid, workspace_manifest_digest="g" * 64),
        "requested_paths_type": replace(
            valid,
            requested_paths=["src/app.py"],
        ),
        "resolved_entries_type": replace(valid, resolved_entries=[entry]),
        "requested_path_type": replace(valid, requested_paths=(1,)),
        "entry_type": replace(valid, resolved_entries=(object(),)),
        "missing_entry": replace(valid, resolved_entries=()),
        "escape_requested": replace(
            valid,
            requested_paths=("../escape",),
            resolved_entries=(
                replace(
                    entry,
                    requested_path="../escape",
                    resolved_relative_path=None,
                ),
            ),
        ),
        "protected_requested": replace(
            valid,
            requested_paths=(".git/config",),
            resolved_entries=(
                replace(
                    entry,
                    requested_path=".git/config",
                    resolved_relative_path=None,
                ),
            ),
        ),
        "duplicate_requested": replace(
            valid,
            requested_paths=("src/app.py", "src/app.py"),
            resolved_entries=(entry, entry),
        ),
        "unsorted_requested": replace(
            valid,
            requested_paths=("src/z.py", "src/a.py"),
            resolved_entries=(
                ResolutionManifestEntry("src/z.py", None),
                ResolutionManifestEntry("src/a.py", None),
            ),
        ),
        "escape_resolved": replace(
            valid,
            resolved_entries=(
                replace(entry, resolved_relative_path="../escape"),
            ),
        ),
        "mismatched_resolved": replace(
            valid,
            resolved_entries=(
                replace(entry, resolved_relative_path="src/other.py"),
            ),
        ),
        "resolved_type": replace(
            valid,
            resolved_entries=(replace(entry, resolved_relative_path=1),),
        ),
        "path_count": replace(
            valid,
            requested_paths=many_paths,
            resolved_entries=tuple(
                ResolutionManifestEntry(path, None) for path in many_paths
            ),
        ),
    }

    _assert_resolution_manifest_serializers_reject(forged[case])


def test_resolution_manifest_rejects_incomplete_openat2_flags() -> None:
    workspace = _resolution_workspace()
    probe = ResolutionProbe(
        requested_path="src/app.py",
        resolved_relative_path="src/app.py",
        openat2_flags=(
            "RESOLVE_BENEATH",
            "RESOLVE_NO_MAGICLINKS",
        ),
    )

    with pytest.raises(ResolutionError, match="openat2|flag"):
        build_resolution_manifest(workspace, ("src/app.py",), (probe,))


@pytest.mark.parametrize(
    ("requested", "probes"),
    (
        (
            ("src/new.py", "src/app.py"),
            (
                ResolutionProbe(
                    "src/new.py",
                    "src/new.py",
                    OPENAT2_RESOLVE_FLAGS,
                ),
                ResolutionProbe(
                    "src/app.py",
                    "src/app.py",
                    OPENAT2_RESOLVE_FLAGS,
                ),
            ),
        ),
        (
            ("src/app.py", "src/app.py"),
            (
                ResolutionProbe(
                    "src/app.py",
                    "src/app.py",
                    OPENAT2_RESOLVE_FLAGS,
                ),
                ResolutionProbe(
                    "src/app.py",
                    "src/app.py",
                    OPENAT2_RESOLVE_FLAGS,
                ),
            ),
        ),
        (
            ("src/app.py",),
            (
                ResolutionProbe(
                    "src/other.py",
                    "src/other.py",
                    OPENAT2_RESOLVE_FLAGS,
                ),
            ),
        ),
    ),
)
def test_resolution_manifest_requires_sorted_unique_aligned_vectors(
    requested: tuple[str, ...],
    probes: tuple[ResolutionProbe, ...],
) -> None:
    with pytest.raises(ResolutionError, match="order|duplicate|align"):
        build_resolution_manifest(_resolution_workspace(), requested, probes)


def test_resolution_manifest_rejects_symlink_escape_claim() -> None:
    workspace = _resolution_workspace()
    probe = ResolutionProbe(
        requested_path="link/child.py",
        resolved_relative_path="link/child.py",
        openat2_flags=OPENAT2_RESOLVE_FLAGS,
    )

    with pytest.raises(ResolutionError, match="symlink|resolution"):
        build_resolution_manifest(workspace, ("link/child.py",), (probe,))


def test_resolution_manifest_keeps_missing_or_file_parent_unresolved() -> None:
    workspace = _resolution_workspace()
    requested = ("missing/new.py", "src/app.py/child.py")
    probes = tuple(
        ResolutionProbe(path, None, OPENAT2_RESOLVE_FLAGS)
        for path in requested
    )

    manifest = build_resolution_manifest(workspace, requested, probes)

    assert tuple(
        entry.resolved_relative_path for entry in manifest.resolved_entries
    ) == (None, None)


def _candidate_workspace_manifest(
    files: tuple[SourceFile, ...],
    *,
    head_commit: str,
):
    directories: set[str] = set()
    records: list[WorkspaceScanRecord] = []
    for source_file in files:
        segments = source_file.path.split("/")
        directories.update(
            "/".join(segments[:index])
            for index in range(1, len(segments))
        )
        records.append(
            _scan_regular(
                source_file.path.encode("ascii"),
                content=source_file.content,
                mode=int(source_file.mode, 8),
            )
        )
    records.extend(
        _scan_directory(directory.encode("ascii"))
        for directory in directories
    )
    return build_workspace_manifest(head_commit, tuple(records))


def _apply_candidate_patch(
    raw: bytes,
    target_paths: tuple[str, ...],
    parent_files: tuple[SourceFile, ...],
    work_order_dict: dict,
):
    parsed = _parse_patch(raw, target_paths)
    replay_profile, replay_digest = _replay_profile(work_order_dict)
    return apply_patch_phase_b(
        parsed,
        parent_files,
        parent_commit="2" * 40,
        parent_manifest_digest="a" * 64,
        workspace_manifest_digest="b" * 64,
        occurred_at="2026-01-01T00:00:01Z",
        replay_profile=replay_profile,
        replay_profile_digest=replay_digest,
        observed_manifest_delta_paths=target_paths,
    )


@pytest.mark.parametrize("path_length", tuple(range(507, 513)))
def test_candidate_accepts_507_to_512_byte_paths_after_source_materialization(
    work_order_dict: dict,
    path_length: int,
) -> None:
    path = "p" * path_length
    parent_files = (SourceFile("base.txt", "100644", b"base\n"),)

    application = _apply_candidate_patch(
        _create_section(path=path, content=b"candidate\n"),
        (path,),
        parent_files,
        work_order_dict,
    )
    manifest = _candidate_workspace_manifest(
        application.files,
        head_commit=application.candidate_commit,
    )

    assert application.files == (
        *parent_files,
        SourceFile(path, "100644", b"candidate\n"),
    )
    assert len(manifest.entries) == 2
    assert derive_execution_snapshot_plan(
        manifest,
        application.files,
    ).files == application.files


def test_candidate_may_create_127th_regular_file_within_manifest_limit(
    work_order_dict: dict,
) -> None:
    parent_files = tuple(
        SourceFile(f"file-{index:03d}.txt", "100644", b"x\n")
        for index in range(126)
    )
    path = "z-new.txt"

    application = _apply_candidate_patch(
        _create_section(path=path, content=b"new\n"),
        (path,),
        parent_files,
        work_order_dict,
    )
    manifest = _candidate_workspace_manifest(
        application.files,
        head_commit=application.candidate_commit,
    )

    assert len(application.files) == 127
    assert len(manifest.entries) == 127
    assert derive_execution_snapshot_plan(
        manifest,
        application.files,
    ).files == application.files


def test_candidate_modified_file_may_exceed_source_one_mib_limit(
    work_order_dict: dict,
) -> None:
    old_content = b"a\n" * 524_288
    new_content = old_content + b"x\n"
    path = "large.txt"
    old_oid = _git_object_oid(b"blob", old_content)
    new_oid = _git_object_oid(b"blob", new_content)
    raw = (
        f"diff --git a/{path} b/{path}\n"
        f"index {old_oid}..{new_oid} 100644\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        "@@ -524288,0 +524289,1 @@\n"
        "+x\n"
    ).encode()

    application = _apply_candidate_patch(
        raw,
        (path,),
        (SourceFile(path, "100644", old_content),),
        work_order_dict,
    )
    manifest = _candidate_workspace_manifest(
        application.files,
        head_commit=application.candidate_commit,
    )

    assert len(application.files[0].content) == 1_048_578
    assert manifest.entries[0].size_bytes == 1_048_578
    assert derive_execution_snapshot_plan(
        manifest,
        application.files,
    ).files == application.files


def _workspace_manifest_dict(
    files: tuple[SourceFile, ...],
    *,
    head_commit: str,
) -> dict:
    directories: set[bytes] = set()
    entries: list[tuple[bytes, dict]] = []
    for source_file in files:
        path_bytes = source_file.path.encode("ascii")
        segments = path_bytes.split(b"/")
        for index in range(1, len(segments)):
            directories.add(b"/".join(segments[:index]))
        entries.append(
            (
                path_bytes,
                {
                    "path_bytes_b64url": _b64url(path_bytes),
                    "type": "regular",
                    "posix_mode": source_file.mode,
                    "size_bytes": len(source_file.content),
                    "sha256": hashlib.sha256(source_file.content).hexdigest(),
                    "symlink_target_b64url": None,
                },
            )
        )
    entries.extend(
        (
            path,
            {
                "path_bytes_b64url": _b64url(path),
                "type": "directory",
                "posix_mode": "040755",
                "size_bytes": None,
                "sha256": None,
                "symlink_target_b64url": None,
            },
        )
        for path in directories
    )
    return {
        "schema_version": "openworkproof-workspace-manifest/0.1",
        "head_commit": head_commit,
        "entries": [
            entry for _, entry in sorted(entries, key=lambda item: item[0])
        ],
    }


def _workspace_digest_for_files(
    files: tuple[SourceFile, ...],
    *,
    head_commit: str,
) -> str:
    return hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/workspace-manifest/v0.1",
                "manifest": _workspace_manifest_dict(
                    files,
                    head_commit=head_commit,
                ),
            }
        )
    ).hexdigest()


@dataclass(frozen=True)
class FrozenReplaySequence:
    source: FrozenSourceVector
    work_order: WorkOrder
    patch_raw: bytes
    patch_step: ReplayPatchStep
    test_step: ReplayTestStep
    rollback_step: ReplayRollbackStep
    result_files: tuple[SourceFile, ...]
    result_commit: str
    result_manifest_digest: str
    parent_manifest_digest: str


def _replay_sequence_fixture(
    work_order_dict: dict,
) -> FrozenReplaySequence:
    parent_files = (
        SourceFile("src/app.py", "100644", b"alpha\nbeta\n"),
        SourceFile("src/keep.py", "100755", b"keep = True\n"),
    )
    result_files = (
        SourceFile("src/app.py", "100644", b"alpha\nBETA\n"),
        SourceFile("src/keep.py", "100755", b"keep = True\n"),
    )
    source = _source_vector(files=parent_files)
    work_order = _bound_work_order(work_order_dict, source)
    patch_raw = _modify_section()
    parsed = _parse_patch(patch_raw, ("src/app.py",))
    parent_manifest_digest = _workspace_digest_for_files(
        parent_files,
        head_commit=source.source_commit,
    )
    profile = work_order.replay_profile
    occurred_at = "2026-01-01T00:00:01Z"
    provisional = apply_patch_phase_b(
        parsed,
        parent_files,
        parent_commit=source.source_commit,
        parent_manifest_digest=parent_manifest_digest,
        workspace_manifest_digest="0" * 64,
        occurred_at=occurred_at,
        replay_profile=profile,
        replay_profile_digest=work_order.replay_profile_digest,
        observed_manifest_delta_paths=("src/app.py",),
    )
    result_manifest_digest = _workspace_digest_for_files(
        result_files,
        head_commit=provisional.candidate_commit,
    )
    patch_receipt_id = "8" * 64
    patch_receipt_digest = "9" * 64
    application = apply_patch_phase_b(
        parsed,
        parent_files,
        parent_commit=source.source_commit,
        parent_manifest_digest=parent_manifest_digest,
        workspace_manifest_digest=result_manifest_digest,
        occurred_at=occurred_at,
        replay_profile=profile,
        replay_profile_digest=work_order.replay_profile_digest,
        observed_manifest_delta_paths=("src/app.py",),
    )
    verifier_profile = next(
        item for item in work_order.test_profiles if item.test_mode == "verifier"
    )
    test_evidence = ResultEvidence(
        schema_version="openworkproof-test-result/0.1",
        test_mode="verifier",
        command_digest=verifier_profile.command_digest,
        source_commit=source.source_commit,
        candidate_commit=application.candidate_commit,
        workspace_manifest_digest=result_manifest_digest,
        container_image_digest=verifier_profile.container_image_digest,
        fixed_test_source_digest=verifier_profile.fixed_test_source_digest,
        actual_exit_code=0,
    )
    return FrozenReplaySequence(
        source=source,
        work_order=work_order,
        patch_raw=patch_raw,
        patch_step=ReplayPatchStep(
            patch_bytes=patch_raw,
            target_paths=("src/app.py",),
            occurred_at=occurred_at,
            evidence=application.evidence,
            patch_receipt_id=patch_receipt_id,
            patch_receipt_digest=patch_receipt_digest,
        ),
        test_step=ReplayTestStep(evidence=test_evidence),
        rollback_step=ReplayRollbackStep(
            target_patch_receipt_id=patch_receipt_id,
            target_patch_receipt_digest=patch_receipt_digest,
            before_commit=application.candidate_commit,
            after_commit=source.source_commit,
            after_manifest_digest=parent_manifest_digest,
        ),
        result_files=result_files,
        result_commit=application.candidate_commit,
        result_manifest_digest=result_manifest_digest,
        parent_manifest_digest=parent_manifest_digest,
    )


def _replay(
    vector: FrozenReplaySequence,
    steps: tuple[ReplayPatchStep | ReplayTestStep | ReplayRollbackStep, ...],
):
    return replay_workspace_sequence(
        source_bytes=vector.source.raw,
        work_order=vector.work_order,
        trusted_helper_image_digest=(
            vector.work_order.replay_profile.trusted_helper_image_digest
        ),
        steps=steps,
    )


def test_replay_sequence_rebuilds_patch_test_and_rollback_checkpoints(
    work_order_dict: dict,
) -> None:
    vector = _replay_sequence_fixture(work_order_dict)

    candidate = _replay(
        vector,
        (vector.patch_step, vector.test_step),
    )
    restored = _replay(
        vector,
        (vector.patch_step, vector.test_step, vector.rollback_step),
    )

    assert candidate.files == vector.result_files
    assert candidate.head_commit == vector.result_commit
    assert candidate.workspace_manifest_digest == vector.result_manifest_digest
    assert candidate.verified_test_results == (vector.test_step.evidence,)
    assert restored.files == vector.source.files
    assert restored.head_commit == vector.source.source_commit
    assert restored.workspace_manifest_digest == vector.parent_manifest_digest
    assert restored.verified_test_results == (vector.test_step.evidence,)


def test_replay_rollback_distinguishes_identical_diff_in_distinct_receipts(
    work_order_dict: dict,
) -> None:
    vector = _replay_sequence_fixture(work_order_dict)
    other_patch = ReplayPatchStep(
        patch_bytes=vector.patch_step.patch_bytes,
        target_paths=vector.patch_step.target_paths,
        occurred_at=vector.patch_step.occurred_at,
        evidence=vector.patch_step.evidence,
        patch_receipt_id="a" * 64,
        patch_receipt_digest="b" * 64,
    )
    wrong_receipt_rollback = ReplayRollbackStep(
        target_patch_receipt_id=other_patch.patch_receipt_id,
        target_patch_receipt_digest=other_patch.patch_receipt_digest,
        before_commit=vector.rollback_step.before_commit,
        after_commit=vector.rollback_step.after_commit,
        after_manifest_digest=vector.rollback_step.after_manifest_digest,
    )

    restored = _replay(
        vector,
        (vector.patch_step, vector.rollback_step),
    )
    assert restored.head_commit == vector.source.source_commit

    with pytest.raises(ReplayError, match="receipt|rollback|target"):
        _replay(vector, (vector.patch_step, wrong_receipt_rollback))


def test_replay_rejects_mutated_exact_diff_or_receipt_time(
    work_order_dict: dict,
) -> None:
    vector = _replay_sequence_fixture(work_order_dict)
    mutated_bytes = vector.patch_raw.replace(b"+BETA\n", b"+GAMMA\n")
    mutated_patch = ReplayPatchStep(
        patch_bytes=mutated_bytes,
        target_paths=vector.patch_step.target_paths,
        occurred_at=vector.patch_step.occurred_at,
        evidence=vector.patch_step.evidence,
        patch_receipt_id=vector.patch_step.patch_receipt_id,
        patch_receipt_digest=vector.patch_step.patch_receipt_digest,
    )
    mutated_time = ReplayPatchStep(
        patch_bytes=vector.patch_step.patch_bytes,
        target_paths=vector.patch_step.target_paths,
        occurred_at="2026-01-01T00:00:02Z",
        evidence=vector.patch_step.evidence,
        patch_receipt_id=vector.patch_step.patch_receipt_id,
        patch_receipt_digest=vector.patch_step.patch_receipt_digest,
    )

    with pytest.raises(ReplayError, match="patch|digest"):
        _replay(vector, (mutated_patch,))
    with pytest.raises(ReplayError, match="commit|time"):
        _replay(vector, (mutated_time,))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("source_commit", "3" * 40),
        ("candidate_commit", "4" * 40),
        ("workspace_manifest_digest", "5" * 64),
        ("command_digest", "6" * 64),
        ("container_image_digest", "sha256:" + "7" * 64),
    ),
)
def test_replay_rejects_mutated_test_result_sources(
    work_order_dict: dict,
    field: str,
    value: str,
) -> None:
    vector = _replay_sequence_fixture(work_order_dict)
    mutated = ReplayTestStep(
        evidence=vector.test_step.evidence.model_copy(
            update={field: value}
        )
    )

    with pytest.raises(ReplayError, match="test|evidence|source"):
        _replay(vector, (vector.patch_step, mutated))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("target_patch_receipt_id", "3" * 64),
        ("target_patch_receipt_digest", "3" * 64),
        ("before_commit", "4" * 40),
        ("after_commit", "5" * 40),
        ("after_manifest_digest", "6" * 64),
    ),
)
def test_replay_rollback_must_match_recorded_parent_checkpoint(
    work_order_dict: dict,
    field: str,
    value: str,
) -> None:
    vector = _replay_sequence_fixture(work_order_dict)
    values = {
        "target_patch_receipt_id": (
            vector.rollback_step.target_patch_receipt_id
        ),
        "target_patch_receipt_digest": (
            vector.rollback_step.target_patch_receipt_digest
        ),
        "before_commit": vector.rollback_step.before_commit,
        "after_commit": vector.rollback_step.after_commit,
        "after_manifest_digest": vector.rollback_step.after_manifest_digest,
    }
    values[field] = value
    mutated = ReplayRollbackStep(**values)

    with pytest.raises(ReplayError, match="rollback|checkpoint|parent"):
        _replay(vector, (vector.patch_step, mutated))


def _source_with_workspace_entry_count(
    entry_count: int,
) -> FrozenSourceVector:
    if entry_count not in {512, 513}:
        raise AssertionError("fixture supports only the frozen boundary")
    depth_four_files = 8 if entry_count == 512 else 9
    files = tuple(
        SourceFile(
            (
                f"d{index:03d}/a/b/c/file.txt"
                if index < depth_four_files
                else f"d{index:03d}/a/b/file.txt"
            ),
            "100644",
            b"x\n",
        )
        for index in range(126)
    )
    vector = _source_vector(files=files)
    assert len(
        _workspace_manifest_dict(
            files,
            head_commit=vector.source_commit,
        )["entries"]
    ) == entry_count
    return vector


def test_offline_replay_accepts_512_workspace_entries(
    work_order_dict: dict,
) -> None:
    source = _source_with_workspace_entry_count(512)
    work_order = _bound_work_order(work_order_dict, source)

    checkpoint = replay_workspace_sequence(
        source_bytes=source.raw,
        work_order=work_order,
        trusted_helper_image_digest=(
            work_order.replay_profile.trusted_helper_image_digest
        ),
        steps=(),
    )

    assert len(checkpoint.workspace_manifest.entries) == 512


def test_offline_replay_rejects_513_workspace_entries(
    work_order_dict: dict,
) -> None:
    source = _source_with_workspace_entry_count(513)
    work_order = _bound_work_order(work_order_dict, source)

    with pytest.raises(ReplayError, match="512"):
        replay_workspace_sequence(
            source_bytes=source.raw,
            work_order=work_order,
            trusted_helper_image_digest=(
                work_order.replay_profile.trusted_helper_image_digest
            ),
            steps=(),
        )


def test_patch_evidence_pair_derivation_is_pure_and_starts_at_one(
    work_order_dict: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = WorkOrder.model_validate(work_order_dict).evidence_policy

    def forbid_ambient_state(*args, **kwargs):
        raise AssertionError("paired ordinal derivation touched ambient state")

    monkeypatch.setattr("builtins.open", forbid_ambient_state)
    monkeypatch.setattr("sqlite3.connect", forbid_ambient_state)

    state = repo_tools.derive_patch_evidence_pair_state(policy, ())

    assert state.consumed_input_ordinals == ()
    assert state.committed_input_refs == ()
    assert state.burned_result_ordinals == ()
    assert state.committed_result_ordinals == ()
    assert state.next_pair.input_artifact.purpose == "patch_input"
    assert state.next_pair.input_artifact.ordinal == 1
    assert state.next_pair.result_artifact.purpose == "patch_result"
    assert state.next_pair.result_artifact.ordinal == 1


def test_failed_patch_commits_input_burns_result_and_uses_next_pair(
    work_order_dict: dict,
) -> None:
    policy = WorkOrder.model_validate(work_order_dict).evidence_policy
    failed_input = b"diff --git a/app.py b/app.py\n"
    failed_input_artifact = next(
        artifact
        for artifact in policy.artifacts
        if artifact.purpose == "patch_input" and artifact.ordinal == 1
    )
    failed_input_ref = EvidenceRef(
        path=f"{policy.evidence_root}/{failed_input_artifact.path}",
        sha256=hashlib.sha256(failed_input).hexdigest(),
        media_type=failed_input_artifact.media_type,
        size_bytes=len(failed_input),
    )
    failed = repo_tools.PatchEvidenceUse(
        patch_receipt_id="a" * 64,
        execution_status="failed",
        patch_input_ref=failed_input_ref,
        patch_result_ordinal=None,
    )

    after_failed = repo_tools.derive_patch_evidence_pair_state(
        policy,
        (failed,),
    )

    assert after_failed.consumed_input_ordinals == (1,)
    assert after_failed.committed_input_refs == (failed_input_ref,)
    assert isinstance(after_failed.committed_input_refs[0], EvidenceRef)
    assert after_failed.burned_result_ordinals == (1,)
    assert after_failed.committed_result_ordinals == ()
    assert after_failed.next_pair.input_artifact.ordinal == 2
    assert after_failed.next_pair.result_artifact.ordinal == 2

    succeeded_input = b"diff --git a/app.py b/app.py\n@@ -1 +1 @@\n-old\n+new\n"
    succeeded_input_artifact = next(
        artifact
        for artifact in policy.artifacts
        if artifact.purpose == "patch_input" and artifact.ordinal == 2
    )
    succeeded_input_ref = EvidenceRef(
        path=f"{policy.evidence_root}/{succeeded_input_artifact.path}",
        sha256=hashlib.sha256(succeeded_input).hexdigest(),
        media_type=succeeded_input_artifact.media_type,
        size_bytes=len(succeeded_input),
    )
    succeeded = repo_tools.PatchEvidenceUse(
        patch_receipt_id="b" * 64,
        execution_status="succeeded",
        patch_input_ref=succeeded_input_ref,
        patch_result_ordinal=2,
    )
    exhausted = repo_tools.derive_patch_evidence_pair_state(
        policy,
        (failed, succeeded),
    )

    assert exhausted.consumed_input_ordinals == (1, 2)
    assert exhausted.committed_input_refs == (
        failed_input_ref,
        succeeded_input_ref,
    )
    assert exhausted.burned_result_ordinals == (1,)
    assert exhausted.committed_result_ordinals == (2,)
    assert exhausted.next_pair is None


@pytest.mark.parametrize("path_kind", ("child_only", "wrong_root"))
def test_patch_evidence_ref_requires_exact_evidence_root_path(
    work_order_dict: dict,
    path_kind: str,
) -> None:
    policy = WorkOrder.model_validate(work_order_dict).evidence_policy
    input_artifact = next(
        artifact
        for artifact in policy.artifacts
        if artifact.purpose == "patch_input" and artifact.ordinal == 1
    )
    input_bytes = b"diff --git a/app.py b/app.py\n"
    input_ref = EvidenceRef(
        path=(
            input_artifact.path
            if path_kind == "child_only"
            else f"wrong-root/{input_artifact.path}"
        ),
        sha256=hashlib.sha256(input_bytes).hexdigest(),
        media_type=input_artifact.media_type,
        size_bytes=len(input_bytes),
    )
    use = repo_tools.PatchEvidenceUse(
        patch_receipt_id="a" * 64,
        execution_status="failed",
        patch_input_ref=input_ref,
        patch_result_ordinal=None,
    )

    with pytest.raises(
        repo_tools.EvidenceOrdinalError,
        match="EvidenceRef|root|path",
    ):
        repo_tools.derive_patch_evidence_pair_state(policy, (use,))


def test_burned_patch_result_hole_cannot_be_filled_by_later_receipt(
    work_order_dict: dict,
) -> None:
    policy = WorkOrder.model_validate(work_order_dict).evidence_policy
    input_artifact = next(
        artifact
        for artifact in policy.artifacts
        if artifact.purpose == "patch_input" and artifact.ordinal == 1
    )
    input_bytes = b"diff --git a/app.py b/app.py\n"
    input_ref = EvidenceRef(
        path=f"{policy.evidence_root}/{input_artifact.path}",
        sha256=hashlib.sha256(input_bytes).hexdigest(),
        media_type=input_artifact.media_type,
        size_bytes=len(input_bytes),
    )
    failed = repo_tools.PatchEvidenceUse(
        patch_receipt_id="a" * 64,
        execution_status="failed",
        patch_input_ref=input_ref,
        patch_result_ordinal=None,
    )
    illegal_refill = repo_tools.PatchEvidenceUse(
        patch_receipt_id="b" * 64,
        execution_status="succeeded",
        patch_input_ref=input_ref,
        patch_result_ordinal=1,
    )

    with pytest.raises(
        repo_tools.EvidenceOrdinalError,
        match="burn|ordinal|pair",
    ):
        repo_tools.derive_patch_evidence_pair_state(
            policy,
            (failed, illegal_refill),
        )


def test_resolution_manifest_bytes_independent_rehash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rfc8785  # noqa: PLC0415

    from openworkproof.repo_tools import (
        ResolutionError,
        _resolution_manifest_json,
        validate_resolution_manifest_bytes,
    )

    workspace = _resolution_workspace()
    requested = ("src/app.py",)
    probes = (
        ResolutionProbe(
            requested_path="src/app.py",
            resolved_relative_path="src/app.py",
            openat2_flags=OPENAT2_RESOLVE_FLAGS,
        ),
    )
    manifest = build_resolution_manifest(workspace, requested, probes)
    preimage = rfc8785.dumps(
        _resolution_manifest_json(manifest)
    )

    parsed = validate_resolution_manifest_bytes(manifest, preimage)
    assert parsed == manifest

    tampered = preimage.replace(b"src/app.py", b"src/evil.py")
    with pytest.raises(ResolutionError, match="do not match"):
        validate_resolution_manifest_bytes(manifest, tampered)

    with pytest.raises(ResolutionError, match="bytes"):
        validate_resolution_manifest_bytes(manifest, b"")
    with pytest.raises(ResolutionError, match="cannot be parsed"):
        validate_resolution_manifest_bytes(manifest, b"not json")
