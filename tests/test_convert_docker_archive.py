from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import tarfile
from pathlib import Path

import pytest

_CONVERTER_PATH = (
    Path(__file__).resolve().parent.parent
    / "supply-chain"
    / "images"
    / "convert_docker_archive.py"
)


def _load_converter():
    spec = importlib.util.spec_from_file_location(
        "convert_docker_archive", _CONVERTER_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


CONVERTER = _load_converter()
_rewrite = CONVERTER._rewrite

OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
DOCKER_CONFIG = "application/vnd.docker.container.image.v1+json"


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _blob(name: str, data: bytes) -> tarfile.TarInfo:
    member = tarfile.TarInfo(name)
    member.size = len(data)
    member.mode = 0o644
    return member


def _make_oci_archive(
    path: Path,
    *,
    config_bytes: bytes,
    config_descriptor: dict | None = None,
    manifest_override: dict | None = None,
) -> None:
    """Build a minimal pure-OCI archive with one config blob."""
    def add(name: str, data: bytes) -> None:
        archive.addfile(_blob(name, data), io.BytesIO(data))

    with tarfile.open(path, "w") as archive:
        add("oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
        config_digest = _sha256_bytes(config_bytes)
        descriptor = config_descriptor or {
            "mediaType": DOCKER_CONFIG,
            "digest": config_digest,
            "size": len(config_bytes),
        }
        manifest = manifest_override or {
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": descriptor,
            "layers": [],
        }
        manifest_raw = json.dumps(
            manifest, separators=(",", ":")
        ).encode("utf-8")
        manifest_digest = _sha256_bytes(manifest_raw)
        add(
            f"blobs/sha256/{config_digest.split(':', 1)[1]}",
            config_bytes,
        )
        add(
            f"blobs/sha256/{manifest_digest.split(':', 1)[1]}",
            manifest_raw,
        )
        index = {
            "schemaVersion": 2,
            "mediaType": OCI_INDEX,
            "manifests": [
                {
                    "mediaType": OCI_MANIFEST,
                    "digest": manifest_digest,
                    "size": len(manifest_raw),
                    "platform": {"architecture": "arm64", "os": "linux"},
                    "annotations": {},
                }
            ],
        }
        add(
            "index.json",
            json.dumps(index, separators=(",", ":")).encode("utf-8"),
        )


_CONFIG = (
    b'{"architecture":"arm64","os":"linux",'
    b'"config":{},"rootfs":{"type":"layers","diff_ids":[]}}'
)


def test_converter_accepts_honest_config_blob(tmp_path: Path) -> None:
    archive = tmp_path / "honest.tar"
    _make_oci_archive(archive, config_bytes=_CONFIG)
    _rewrite(archive)  # must not raise


def test_converter_rejects_config_blob_whose_content_mismatches_digest(
    tmp_path: Path,
) -> None:
    """Audit G: the config blob found by the manifest digest key must
    actually hash to that digest before its content is trusted."""
    archive = tmp_path / "tampered-digest.tar"
    _make_oci_archive(archive, config_bytes=_CONFIG)
    # Rewrite the archive with tampered content stored under the HONEST
    # digest key: the blob exists, but its content no longer hashes to the
    # manifest descriptor's digest.
    config_key = f"blobs/sha256/{_sha256_bytes(_CONFIG).split(':', 1)[1]}"
    tampered = b'{"architecture":"arm64","os":"linux","evil":true}'
    with tarfile.open(archive, "r") as source:
        entries = []
        for member in source.getmembers():
            data = (
                source.extractfile(member).read() if member.isfile() else b""
            )
            if member.name == config_key:
                data = tampered
            entries.append((member.name, data))
    with tarfile.open(archive, "w") as output:
        for name, data in entries:
            rewritten = tarfile.TarInfo(name)
            rewritten.size = len(data)
            rewritten.mode = 0o644
            output.addfile(rewritten, io.BytesIO(data))
    with pytest.raises(ValueError, match="config blob digest does not replay"):
        _rewrite(archive)


def test_converter_rejects_config_blob_size_mismatch(tmp_path: Path) -> None:
    """Audit G: the manifest descriptor's config size must equal the blob
    size before the content is trusted."""
    archive = tmp_path / "tampered-size.tar"
    _make_oci_archive(
        archive,
        config_bytes=_CONFIG,
        config_descriptor={
            "mediaType": DOCKER_CONFIG,
            "digest": _sha256_bytes(_CONFIG),
            "size": len(_CONFIG) + 7,
        },
    )
    with pytest.raises(ValueError, match="config blob size does not replay"):
        _rewrite(archive)


def test_converter_rejects_malformed_config_digest(tmp_path: Path) -> None:
    """Audit G: a config descriptor whose digest is not a valid sha256:
    reference must fail closed with ValueError, never an IndexError."""
    archive = tmp_path / "malformed-digest.tar"
    _make_oci_archive(
        archive,
        config_bytes=_CONFIG,
        config_descriptor={
            "mediaType": DOCKER_CONFIG,
            "digest": "not-a-digest",
            "size": len(_CONFIG),
        },
    )
    with pytest.raises(ValueError, match="image config descriptor digest is invalid"):
        _rewrite(archive)
