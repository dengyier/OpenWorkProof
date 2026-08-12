"""Frozen schema-registry coverage for judgment/action binding v0.4."""

from __future__ import annotations

import hashlib
import json
from importlib import resources
from pathlib import Path

import pytest
import rfc8785

from openworkproof.models import (
    ACTION_RECEIPT_V04_ADAPTER,
    ActionBindingManifest,
    AuthorityCheckpoint,
    BindingDecision,
    JudgmentCommitment,
)
import openworkproof.schema_registry as api


PROJECT_ROOT = Path(__file__).resolve().parents[1]
V04_OBJECT_PATHS = {
    "action-binding-manifest": "action-binding-manifest.schema.json",
    "action-receipt": "action-receipt.schema.json",
    "authority-checkpoint": "authority-checkpoint.schema.json",
    "binding-decision": "binding-decision.schema.json",
    "judgment-commitment": "judgment-commitment.schema.json",
}
V04_SCHEMA_FACTORIES = {
    "action-receipt": ACTION_RECEIPT_V04_ADAPTER.json_schema,
    "action-binding-manifest": ActionBindingManifest.model_json_schema,
    "authority-checkpoint": AuthorityCheckpoint.model_json_schema,
    "binding-decision": BindingDecision.model_json_schema,
    "judgment-commitment": JudgmentCommitment.model_json_schema,
}
FROZEN_V04_DIGESTS = {
    "action-receipt.schema.json": (
        "7a7cd836da6f15bc003e96bc7b0b6ac1357c422f09395da9da050ec2f66f181e"
    ),
    "action-binding-manifest.schema.json": (
        "6e4dc37a733345ea2e74188a38cea4527e2fcfb5bf1cd487bcfc2bbc6f2f59b2"
    ),
    "authority-checkpoint.schema.json": (
        "deb518fb233088e69ba203df98c896d60a4e902e1484b1e05673cc55a60ead55"
    ),
    "binding-decision.schema.json": (
        "4a120533fdd611bf1f1f4aa292289e70658e5f59eecefc07c9bc513abce8acbe"
    ),
    "judgment-commitment.schema.json": (
        "29a2fbca6bdd5dc6aaf2c023e6a0fd0361531a30ae7486cdc5f1023e2542ecd2"
    ),
    "schema-registry.json": (
        "66dea3711f1aa0f725b84f96b042e3b34e17713ace2f1e497df9628a2830d88d"
    ),
}
V04_FILENAMES = frozenset({"schema-registry.json", *V04_OBJECT_PATHS.values()})
FROZEN_OLD_DIGESTS = {
    "0.1": {
        "acceptance-receipt.schema.json": "5436e77e03d64cf131f2273b7527e63aa854f9c3de7b60aeae8751024267ff0e",
        "acceptance-rejection-receipt.schema.json": "cab320167c5af36afcc06506d13cbaa85c3dd9f6b470c4db12d127726fa86ae8",
        "action-receipt.schema.json": "1aba0e2a9cf3b55478d5def0ef7f89d84976fc22798bb6d709d21afb31cedde8",
        "capability-grant.schema.json": "f7c01f4ed227954f6310fd03ab5cbf52916510971c01c7f22ff9115e358cd17e",
        "schema-registry.json": "b543abb2d972a84d3fffe97e6f9381f33b5cfe40fe0c8c7c046f91354f849000",
        "work-order.schema.json": "171b59390c66d586d7ee387d783ca8bc759779a08c36d31c85cf232998568013",
    },
    "0.2": {
        "acceptance-transition.schema.json": "504a06d4748b0ea045f40c2182ee85e2b59cea8793d6c9259f695dc6c764e1a0",
        "commitment-anchor.schema.json": "ccd6116e57589a12e6a6015c39205f47731bf4fc011d719469f9a944d10cf61f",
        "policy-anchor.schema.json": "7423e5f09f6f22d8785daa7e9dd7c79489b494f63ad12b28a74e480967127d0b",
        "schema-registry.json": "ba555173e56743920b136b131505489f0e8765ea21433c96db7dcc3c354141ae",
        "subject-claim.schema.json": "ec9cd237217dc96a376ce1e67349414abcaa9369a9d4de8d1f85c17e635d1bfe",
        "verification-arm-result.schema.json": "c65913e8dc1f42d0f295be3d136b0566d2e0b7b2ae12b4e1b74634d010750310",
        "verification-decision.schema.json": "d4f15b2aabcf7eadfdf703d37ae7164de9c9d3a3ef0b2a6648a18094e6e7fec1",
        "verification-profile.schema.json": "22df63576418905c68d910f573a7f444700f9b3f7098590dca1876618d70b32c",
    },
    "0.3": {
        "evaluation-scope.schema.json": "dd63163297871008cd18b2de54fc6d22fedf71009bfbd7c849b632a02783d330",
        "schema-registry.json": "e934f2295ae36901b9d8430d184549eb367dca4cecd86f30ed625502f072e1b1",
        "verification-arm-result.schema.json": "73d16598938c5e17d073ab75c779816d5ad4b8a4cfc14f18fed3c8370ca2309b",
        "verification-decision.schema.json": "e1ec873558bba467f22923d79e7b0592df4910aee32047b5037da99701c08408",
        "verification-profile.schema.json": "ac6cb592983cfdda7132ff7c636106e70f5e5b8ccf0f35b9689ff82ae487dd96",
    },
}


def _snapshot(directory: Path) -> dict[str, bytes]:
    return {
        path.name: path.read_bytes()
        for path in directory.iterdir()
        if path.is_file()
    }


def _write_old_v04_set(directory: Path) -> dict[str, bytes]:
    directory.mkdir()
    for filename in V04_FILENAMES:
        directory.joinpath(filename).write_bytes(f"old:{filename}".encode())
    return _snapshot(directory)


def _transaction_artifacts(parent: Path) -> set[str]:
    prefixes = (
        ".openworkproof-schema-backup-",
        ".openworkproof-schema-stage-",
    )
    return {
        path.name
        for path in parent.iterdir()
        if path.name.startswith(prefixes)
    }


def test_v04_registry_has_exact_object_paths_order_and_canonical_bytes() -> None:
    assert api.V04_OBJECT_PATHS == V04_OBJECT_PATHS
    assert list(api.V04_OBJECT_PATHS) == sorted(
        V04_OBJECT_PATHS,
        key=lambda value: value.encode("utf-8"),
    )
    assert api.V04_SCHEMA_FACTORIES == V04_SCHEMA_FACTORIES
    assert "agent-request" not in api.V04_OBJECT_PATHS

    generated = api._generated_files(version="0.4")
    registry_bytes = generated["schema-registry.json"]
    expected_registry = {
        "schema_version": "openworkproof-schema-registry/0.1",
        "protocol_version": "0.4",
        "schemas": [
            {
                "object_type": object_type,
                "path": path,
                "sha256": FROZEN_V04_DIGESTS[path],
            }
            for object_type, path in V04_OBJECT_PATHS.items()
        ],
    }

    assert set(generated) == V04_FILENAMES
    assert registry_bytes == rfc8785.dumps(expected_registry)
    assert json.loads(registry_bytes) == expected_registry
    assert hashlib.sha256(registry_bytes).hexdigest() == (
        FROZEN_V04_DIGESTS["schema-registry.json"]
    )


def test_v04_runtime_and_spec_bytes_match_factories_and_frozen_hashes() -> None:
    runtime = resources.files("openworkproof").joinpath("schemas", "v0.4")
    public = PROJECT_ROOT / "specs" / "v0.4"

    assert {path.name for path in runtime.iterdir()} == V04_FILENAMES
    assert {path.name for path in public.iterdir()} == V04_FILENAMES
    for filename, expected_digest in FROZEN_V04_DIGESTS.items():
        runtime_bytes = runtime.joinpath(filename).read_bytes()
        public_bytes = public.joinpath(filename).read_bytes()
        assert runtime_bytes == public_bytes
        assert hashlib.sha256(runtime_bytes).hexdigest() == expected_digest
        assert runtime_bytes == rfc8785.dumps(json.loads(runtime_bytes))

    for object_type, factory in V04_SCHEMA_FACTORIES.items():
        filename = V04_OBJECT_PATHS[object_type]
        assert runtime.joinpath(filename).read_bytes() == rfc8785.dumps(factory())
        assert api.authoritative_schema(object_type, version="0.4") == factory()
        assert api.authoritative_digest(object_type, version="0.4") == (
            FROZEN_V04_DIGESTS[filename]
        )


def test_v04_writer_atomically_replaces_both_targets_on_success(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "runtime"
    mirror = tmp_path / "specs"
    _write_old_v04_set(destination)
    _write_old_v04_set(mirror)

    api.write_authoritative_schemas(destination, mirror=mirror, version="0.4")

    assert _snapshot(destination) == api._generated_files(version="0.4")
    assert _snapshot(mirror) == _snapshot(destination)
    assert _transaction_artifacts(tmp_path) == set()


def test_v04_writer_rolls_back_atomic_replacement_after_commit_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "runtime"
    mirror = tmp_path / "specs"
    destination_before = _write_old_v04_set(destination)
    mirror_before = _write_old_v04_set(mirror)
    original_replace = Path.replace
    failed = False

    def fail_mirror_install(source: Path, target: Path) -> Path:
        nonlocal failed
        if Path(target) == mirror and not failed:
            failed = True
            raise OSError("simulated v0.4 mirror commit failure")
        return original_replace(source, target)

    monkeypatch.setattr(Path, "replace", fail_mirror_install)

    with pytest.raises(OSError, match="simulated v0.4 mirror commit failure"):
        api.write_authoritative_schemas(
            destination,
            mirror=mirror,
            version="0.4",
        )

    assert _snapshot(destination) == destination_before
    assert _snapshot(mirror) == mirror_before
    assert _transaction_artifacts(tmp_path) == set()


def test_v04_writer_cleans_all_stages_after_second_stage_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "runtime"
    mirror = tmp_path / "specs"
    original_write_bytes = Path.write_bytes
    stage_writes = 0

    def fail_first_mirror_stage_write(path: Path, content: bytes) -> int:
        nonlocal stage_writes
        if path.parent.name.startswith(".openworkproof-schema-stage-"):
            stage_writes += 1
            if stage_writes == len(V04_FILENAMES) + 1:
                raise OSError("simulated v0.4 second-stage failure")
        return original_write_bytes(path, content)

    monkeypatch.setattr(Path, "write_bytes", fail_first_mirror_stage_write)

    with pytest.raises(OSError, match="simulated v0.4 second-stage failure"):
        api.write_authoritative_schemas(
            destination,
            mirror=mirror,
            version="0.4",
        )

    assert stage_writes == len(V04_FILENAMES) + 1
    assert destination.exists() is False
    assert mirror.exists() is False
    assert _transaction_artifacts(tmp_path) == set()


def test_frozen_v01_v02_v03_runtime_and_spec_digests_remain_unchanged() -> None:
    for version, expected_files in FROZEN_OLD_DIGESTS.items():
        runtime = PROJECT_ROOT / "src" / "openworkproof" / "schemas" / f"v{version}"
        public = PROJECT_ROOT / "specs" / f"v{version}"
        assert api._FROZEN_DIGESTS_BY_VERSION[version] == expected_files
        assert {path.name for path in runtime.iterdir()} == set(expected_files)
        assert {path.name for path in public.iterdir()} == set(expected_files)
        for filename, expected_digest in expected_files.items():
            runtime_bytes = runtime.joinpath(filename).read_bytes()
            assert runtime_bytes == public.joinpath(filename).read_bytes()
            assert hashlib.sha256(runtime_bytes).hexdigest() == expected_digest
