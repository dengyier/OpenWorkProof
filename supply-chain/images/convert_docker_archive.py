#!/usr/bin/env python3
"""Convert a Buildx docker/OCI archive to the OpenWorkProof docker-v2 contract.

Docker 29.x Buildx exports ``type=docker`` and ``type=oci`` archives whose
index.json descriptor carries an OCI-v1 manifest and a ``platform`` key. The
OpenWorkProof candidate contract (see tests/test_candidate_supplychain_
integration.py::_verify_docker_archive / _verify_oci_archive) requires:

- docker archive: index.json is an OCI index whose single descriptor has
  exactly {mediaType, digest, size, annotations}, mediaType is the docker-v2
  manifest type, and annotations are exactly
  {config.digest, io.containerd.image.name, org.opencontainers.image.ref.name};
  the legacy manifest.json is a one-record list with Config/Layers blob paths
  and a non-empty RepoTags list.
- oci archive: index.json is an OCI index whose single descriptor has exactly
  {mediaType, digest, size, platform, annotations} (the ``platform`` key is
  required: ``linux/arm64``) and the ``org.opencontainers.image.created``
  annotation.

This tool rewrites an archive in place to that contract. It is idempotent:
running it twice on the same archive is a no-op. Blob contents are never
modified, so config/layer digests and rootfs diff ids are preserved; only the
manifest blob (mediaType strings) and the index.json/legacy manifest.json
metadata are rewritten.
"""

import argparse
import copy
import hashlib
import io
import json
import os
import tarfile
import tempfile
from pathlib import Path

DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
DOCKER_CONFIG = "application/vnd.docker.container.image.v1+json"
DOCKER_LAYER = "application/vnd.docker.image.rootfs.diff.tar.gzip"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_LAYOUT = {"imageLayoutVersion": "1.0.0"}

MANIFEST_JSON_KEYS = {"Config", "Layers", "RepoTags"}


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canonical_json(value: object) -> bytes:
    """Compact JSON bytes used for manifest digest computation."""
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _load_archive(path: Path):
    members: dict[str, tuple[tarfile.TarInfo, bytes | None]] = {}
    with tarfile.open(path, "r") as archive:
        for member in archive.getmembers():
            name = member.name
            if (
                name.startswith("/")
                or "\\" in name
                or any(part in {"", ".", ".."} for part in name.split("/"))
            ):
                raise ValueError(f"unsafe archive member: {name}")
            if name in members:
                raise ValueError(f"duplicate archive member: {name}")
            if member.isdir():
                data = None
            elif member.isreg() and not member.issym() and not member.islnk():
                data = archive.extractfile(member).read()
            else:
                raise RuntimeError(
                    f"unsupported archive member: {member.name}"
                )
            members[member.name] = (member, data)
    index = json.loads(members["index.json"][1])
    oci_layout = json.loads(members["oci-layout"][1])
    legacy = (
        json.loads(members["manifest.json"][1])
        if "manifest.json" in members
        else None
    )
    if oci_layout != OCI_LAYOUT:
        raise ValueError("oci-layout is not imageLayoutVersion 1.0.0")
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or len(manifests) != 1:
        raise ValueError("index.json must contain exactly one manifest")
    return members, index, legacy


def _config_platform(members: dict, manifest: dict) -> dict:
    """Derive the image platform from the real image config blob, never by
    relabeling. The blob must first replay the manifest descriptor exactly
    (digest and size); a tampered or mislabeled blob fails closed before
    any content is trusted."""
    config_descriptor = manifest["config"]
    config_digest = config_descriptor["digest"]
    if (
        type(config_digest) is not str
        or not config_digest.startswith("sha256:")
        or len(config_digest) != 71
        or any(
            character not in "0123456789abcdef"
            for character in config_digest[7:]
        )
    ):
        raise ValueError("image config descriptor digest is invalid")
    config_hex = config_digest[7:]
    config_key = f"blobs/sha256/{config_hex}"
    config_bytes = members.get(config_key)
    if config_bytes is None or config_bytes[1] is None:
        raise ValueError(f"config blob is missing: {config_key}")
    if _sha256_bytes(config_bytes[1]) != config_digest:
        raise ValueError(
            "config blob digest does not replay the manifest descriptor"
        )
    size = config_descriptor.get("size")
    if type(size) is not int or size != len(config_bytes[1]):
        raise ValueError(
            "config blob size does not replay the manifest descriptor"
        )
    config = json.loads(config_bytes[1])
    architecture = config.get("architecture")
    operating_system = config.get("os")
    if (
        type(architecture) is not str
        or not architecture
        or type(operating_system) is not str
        or not operating_system
    ):
        raise ValueError("image config platform is invalid")
    return {"architecture": architecture, "os": operating_system}


def _rewrite(path: Path) -> dict:
    """Rewrite one archive in place; returns the new manifest digest."""
    members, index, legacy = _load_archive(path)
    descriptor = index["manifests"][0]
    blob_hex = descriptor["digest"].split(":", 1)[1]
    blob_key = f"blobs/sha256/{blob_hex}"
    manifest_bytes = members[blob_key][1]
    if manifest_bytes is None:
        raise ValueError(f"manifest blob is missing: {blob_key}")
    parsed = json.loads(manifest_bytes)

    if legacy is None:
        # Pure OCI archive (no legacy manifest.json): keep the OCI manifest
        # blob and digest, keep the platform descriptor, and normalize the
        # index descriptor to the contract's exact key set (mediaType,
        # digest, size, platform, annotations).
        new_digest = descriptor["digest"]
        annotations = dict(descriptor.get("annotations", {}))
        descriptor = {
            "mediaType": OCI_MANIFEST,
            "digest": new_digest,
            "size": descriptor["size"],
            "platform": _config_platform(members, parsed),
            "annotations": annotations,
        }
    elif parsed.get("mediaType") == OCI_MANIFEST:
        candidate_name = legacy[0]["RepoTags"][0]
        tag = candidate_name.rsplit(":", 1)[1]
        config = parsed["config"]
        layers = parsed["layers"]
        docker_manifest = {
            "schemaVersion": 2,
            "mediaType": DOCKER_MANIFEST,
            "config": {
                "mediaType": DOCKER_CONFIG,
                "digest": config["digest"],
                "size": config["size"],
            },
            "layers": [
                {
                    "mediaType": DOCKER_LAYER,
                    "digest": layer["digest"],
                    "size": layer["size"],
                }
                for layer in layers
            ],
        }
        docker_bytes = _canonical_json(docker_manifest)
        new_digest = _sha256_bytes(docker_bytes)
        new_key = f"blobs/sha256/{new_digest.split(':', 1)[1]}"
        member = tarfile.TarInfo(new_key)
        member.size = len(docker_bytes)
        member.mode = 0o644
        members[new_key] = (member, docker_bytes)
        # The superseded OCI manifest blob is no longer referenced by either
        # the legacy manifest.json or the rewritten index.json; drop it so the
        # archive stays closed (every payload blob must be referenced).
        members.pop(blob_key, None)
        annotations = {
            "config.digest": config["digest"],
            "io.containerd.image.name": f"docker.io/{candidate_name}",
            "org.opencontainers.image.ref.name": tag,
        }
        descriptor = {
            "mediaType": DOCKER_MANIFEST,
            "digest": new_digest,
            "size": len(docker_bytes),
            "annotations": annotations,
        }
    elif parsed.get("mediaType") == DOCKER_MANIFEST:
        # Idempotent pass: keep the existing manifest digest, only normalize
        # the descriptor to the exact three-key annotation contract. Buildx
        # docker outputs may carry extra descriptor annotations (e.g. a wall
        # clock ``org.opencontainers.image.created``) and omit
        # ``config.digest``; both break the closed identity chain, so the
        # annotations are rebuilt from the manifest blob and the legacy
        # RepoTags rather than preserved verbatim.
        new_digest = descriptor["digest"]
        candidate_name = legacy[0]["RepoTags"][0]
        tag = candidate_name.rsplit(":", 1)[1]
        annotations = {
            "config.digest": parsed["config"]["digest"],
            "io.containerd.image.name": f"docker.io/{candidate_name}",
            "org.opencontainers.image.ref.name": tag,
        }
        descriptor = {
            "mediaType": DOCKER_MANIFEST,
            "digest": new_digest,
            "size": descriptor["size"],
            "annotations": annotations,
        }
    else:
        raise ValueError(f"unsupported manifest mediaType: {parsed.get('mediaType')}")

    index = {
        "schemaVersion": 2,
        "mediaType": OCI_INDEX,
        "manifests": [descriptor],
    }
    members["index.json"] = (
        members["index.json"][0],
        _canonical_json(index),
    )
    if legacy is not None:
        legacy[0]["RepoTags"] = [legacy[0]["RepoTags"][0]]
        members["manifest.json"] = (
            members["manifest.json"][0],
            _canonical_json(legacy),
        )

    # Prune any blob not reachable from the index manifest or the legacy
    # manifest (e.g. a superseded OCI manifest blob left by an earlier pass),
    # so every archive payload is referenced and the archive stays closed.
    _prune_unreferenced_blobs(members, index)

    # Write to a temporary file in the same directory first, then atomically
    # replace, so a failure never corrupts the source archive. Member sizes
    # are normalized to the actual content length on write.
    file_descriptor, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=".convert-", suffix=".tar"
    )
    os.close(file_descriptor)
    tmp_path = Path(tmp_name)
    try:
        with tarfile.open(tmp_path, "w") as archive:
            for name in sorted(members):
                member, data = members[name]
                if data is None:
                    archive.addfile(member)
                else:
                    rewritten = copy.copy(member)
                    rewritten.size = len(data)
                    archive.addfile(rewritten, io.BytesIO(data))
        os.replace(tmp_path, path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise
    return new_digest


def _prune_unreferenced_blobs(
    members: dict[str, tuple[tarfile.TarInfo, bytes | None]],
    index: dict,
) -> None:
    """Drop blobs/sha256 members that no manifest references."""
    descriptor = index["manifests"][0]
    blob_hex = descriptor["digest"].split(":", 1)[1]
    referenced = {blob_hex}
    manifest_raw = members[f"blobs/sha256/{blob_hex}"][1]
    if manifest_raw is None:
        raise ValueError("manifest blob is missing during prune")
    manifest = json.loads(manifest_raw)
    referenced.add(manifest["config"]["digest"].split(":", 1)[1])
    for layer in manifest["layers"]:
        referenced.add(layer["digest"].split(":", 1)[1])
    for name in list(members):
        if name.startswith("blobs/sha256/") and name.split("/")[-1] not in referenced:
            del members[name]


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Rewrite a Buildx docker/oci archive to the OpenWorkProof "
            "docker-v2 contract (idempotent)."
        )
    )
    parser.add_argument("archive", type=Path, help="path to the archive tar")
    args = parser.parse_args()
    digest = _rewrite(args.archive)
    print(f"rewritten {args.archive} manifest digest: {digest}")


if __name__ == "__main__":
    main()
