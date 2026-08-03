"""Static contracts for the Day 0 candidate image supply chain."""

from __future__ import annotations

import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
IMAGE_ROOT = ROOT / "supply-chain" / "images"
BASE_IMAGE = (
    "docker.io/library/python@sha256:"
    "57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de"
)
SOURCE_REVISION = "33a485eacf4ab97b2507f00e5a824ba4a5c8c29c"
INVENTORY_PATH = (
    IMAGE_ROOT / "candidates" / f"{SOURCE_REVISION}.json"
)


def _read(relative_path: str) -> str:
    path = IMAGE_ROOT / relative_path
    assert path.is_file(), f"missing supply-chain input: {path}"
    return path.read_text(encoding="utf-8")


def _locked_packages(lock_text: str) -> tuple[str, ...]:
    return tuple(
        match.group(1)
        for match in re.finditer(
            r"^([a-z0-9][a-z0-9-]*)==[^\s\\]+\s+\\$",
            lock_text,
            flags=re.MULTILINE,
        )
    )


def test_execution_image_contract_is_minimal_and_offline() -> None:
    dockerfile = _read("execution/Dockerfile")
    lock_text = _read("execution/requirements.lock")

    assert f"FROM {BASE_IMAGE}" in dockerfile
    assert not dockerfile.startswith("# syntax=")
    assert "COPY wheels/ /tmp/wheels/" in dockerfile
    assert "sha256sum -c SHA256SUMS" in dockerfile
    assert "--no-index" in dockerfile
    assert "--require-hashes" in dockerfile
    assert not re.search(r"\b(?:apt-get|apt|curl|wget)\b", dockerfile)
    assert "COPY helper-src/" not in dockerfile
    assert "src/openworkproof" not in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert 'ENTRYPOINT ["/usr/bin/env", "--"]' in dockerfile
    assert _locked_packages(lock_text) == (
        "iniconfig",
        "markdown-it-py",
        "mdurl",
        "packaging",
        "pluggy",
        "pygments",
        "pytest",
    )


def test_trusted_helper_candidate_has_a_closed_package_surface() -> None:
    dockerfile = _read("trusted-helper/Dockerfile")
    lock_text = _read("trusted-helper/requirements.lock")
    source_allowlist = _read("trusted-helper/SOURCE_ALLOWLIST")

    assert f"FROM {BASE_IMAGE}" in dockerfile
    assert not dockerfile.startswith("# syntax=")
    assert "COPY wheels/ /tmp/wheels/" in dockerfile
    assert "COPY debs/ /tmp/debs/" in dockerfile
    assert dockerfile.count("sha256sum -c SHA256SUMS") == 3
    assert "dpkg --install /tmp/debs/*.deb" in dockerfile
    assert not re.search(r"\b(?:apt-get|apt|curl|wget)\b", dockerfile)
    assert "USER 65532:65532" in dockerfile
    assert 'ENTRYPOINT ["/opt/venv/bin/python", "-I"]' in dockerfile
    assert _locked_packages(lock_text) == (
        "annotated-types",
        "pydantic",
        "pydantic-core",
        "rfc8785",
        "typing-extensions",
        "typing-inspection",
    )
    assert source_allowlist.splitlines() == [
        "src/openworkproof/__init__.py",
        "src/openworkproof/models.py",
        "src/openworkproof/repo_tools.py",
    ]
    assert "COPY helper-src/ /opt/venv/lib/python3.12/site-packages/openworkproof/" in dockerfile
    assert (
        "cd /opt/venv/lib/python3.12/site-packages/openworkproof/"
        in dockerfile
    )
    assert "rm SHA256SUMS" in dockerfile
    assert "mcp_server.py" not in dockerfile
    assert "cli.py" not in dockerfile


def test_helper_debian_lock_is_an_exact_sha256_closure() -> None:
    lock_text = _read("trusted-helper/debian-packages.lock")
    rows = tuple(
        line.split("\t")
        for line in lock_text.splitlines()
        if line and not line.startswith("#")
    )

    assert rows
    assert all(len(row) == 5 for row in rows)
    assert all(re.fullmatch(r"[0-9a-f]{64}", row[0]) for row in rows)
    assert all(
        row[1].endswith(("_arm64.deb", "_all.deb")) for row in rows
    )
    assert all(row[4] in {"arm64", "all"} for row in rows)
    assert len({row[1] for row in rows}) == len(rows)
    assert len({row[2] for row in rows}) == len(rows)
    assert {row[2] for row in rows} >= {"git", "git-man"}


def test_both_images_carry_auditable_oci_provenance() -> None:
    for relative_path, role in (
        ("execution/Dockerfile", "execution-test"),
        ("trusted-helper/Dockerfile", "trusted-helper-candidate"),
    ):
        dockerfile = _read(relative_path)
        assert "ARG OWP_SOURCE_REVISION" in dockerfile
        assert "org.opencontainers.image.source=" in dockerfile
        assert "org.opencontainers.image.revision=$OWP_SOURCE_REVISION" in dockerfile
        assert f"org.openworkproof.image.role={role}" in dockerfile
        assert "org.openworkproof.base.digest=sha256:57cd7c3a7a273101" in dockerfile


def test_supply_chain_record_keeps_day0_and_acceptor_claims_closed() -> None:
    record = _read("README.md")

    assert "requirements-lock.txt" in record
    assert "be6f8e10d7a82b978913eb2b6a73ee11efc5a9af623e5a783163e3cb78179f8c" in record
    assert "e8d3ccaaa1cf735113e7bd533637cef028d710725981fbe20968179c70ea3a72" in record
    assert "trusted-helper-candidate" in record
    assert "不构成 Acceptor access" in record
    assert "不构成 clean-cache reacquisition" in record
    assert "不构成 Day 0 PASS" in record


def test_candidate_inventory_is_closed_and_claims_only_local_evidence() -> None:
    assert INVENTORY_PATH.is_file(), f"missing candidate inventory: {INVENTORY_PATH}"
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))

    assert set(inventory) == {
        "schema_version",
        "source_revision",
        "base_image",
        "build_inputs",
        "images",
        "external_layout",
        "license",
        "claims",
    }
    assert inventory["schema_version"] == (
        "openworkproof-image-candidate-inventory/0.1"
    )
    assert inventory["source_revision"] == SOURCE_REVISION
    assert inventory["base_image"] == {
        "reference": BASE_IMAGE,
        "platform": "linux/arm64",
        "python_version": "3.12.13",
    }
    assert set(inventory["build_inputs"]) == {"execution", "trusted_helper"}
    for inputs in inventory["build_inputs"].values():
        assert all(
            re.fullmatch(r"[0-9a-f]{64}", digest)
            for digest in inputs.values()
        )

    assert set(inventory["images"]) == {"execution", "trusted_helper"}
    for image in inventory["images"].values():
        assert set(image) == {
            "candidate_name",
            "local_image_id",
            "local_repo_digests",
            "platform",
            "user",
            "entrypoint",
            "cmd",
            "labels",
            "oci_manifest_digest",
            "archives",
        }
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", image["local_image_id"])
        assert type(image["local_repo_digests"]) is list
        assert image["platform"] == "linux/arm64"
        assert image["user"] == "65532:65532"
        assert image["labels"]["org.opencontainers.image.revision"] == SOURCE_REVISION
        assert re.fullmatch(
            r"sha256:[0-9a-f]{64}", image["oci_manifest_digest"]
        )
        assert set(image["archives"]) == {"docker", "oci"}
        assert image["archives"]["docker"]["format"] == "docker-archive"
        assert image["archives"]["oci"]["format"] == (
            "oci-image-layout-archive"
        )

    assert inventory["external_layout"] == {
        "local_root": "/Users/molin/Project/openWorkProof-day0",
        "path_rule": "join-local-root-with-relative-path-no-parent-traversal",
        "relative_paths": {
            "wheelhouse": "wheelhouse/linux-arm64-cp312-full",
            "git_deb_closure": "debs/linux-arm64-trixie-git",
            "execution_build_context": "build-contexts/execution",
            "trusted_helper_build_context": "build-contexts/trusted-helper",
            "archives": "oci",
        },
    }
    assert inventory["license"] == {
        "status": "PENDING",
        "spdx": "NOASSERTION",
        "oci_label_present": False,
    }
    assert inventory["claims"] == {
        "registry_pushed": False,
        "acceptor_access": False,
        "clean_cache_reacquisition": False,
        "final_trusted_helper": False,
        "day0_pass": False,
        "acceptor_acquisition_path": None,
    }
