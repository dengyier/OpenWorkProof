"""Static contracts for the Day 0 candidate image supply chain."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE_ROOT = ROOT / "supply-chain" / "images"
BASE_IMAGE = (
    "docker.io/library/python@sha256:"
    "57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de"
)
CANDIDATE_PATHS = tuple(sorted((IMAGE_ROOT / "candidates").glob("*.json")))


def _read(relative_path: str) -> str:
    path = IMAGE_ROOT / relative_path
    assert path.is_file(), f"missing supply-chain input: {path}"
    return path.read_text(encoding="utf-8")


def _git_bytes(revision: str, relative_path: str) -> bytes:
    return subprocess.run(
        ["git", "show", f"{revision}:{relative_path}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout


def _locked_packages(lock_text: str) -> tuple[str, ...]:
    return tuple(
        match.group(1)
        for match in re.finditer(
            r"^([a-z0-9][a-z0-9-]*)==[^\s\\]+\s+\\$",
            lock_text,
            flags=re.MULTILINE,
        )
    )


def _assert_fixed_helper_process_config(dockerfile: str) -> None:
    instructions: dict[str, list[object]] = {"ENTRYPOINT": [], "CMD": []}
    in_continuation = False
    for raw_line in dockerfile.splitlines():
        stripped = raw_line.lstrip()
        assert not re.match(
            r"#\s*(?:syntax|escape|check)\s*=", stripped, re.IGNORECASE
        ), "Docker parser directives are not allowed"
        if in_continuation:
            in_continuation = raw_line.rstrip().endswith("\\")
            continue
        if not stripped or stripped.startswith("#"):
            continue

        parts = stripped.split(None, 1)
        name = parts[0].upper()
        continues = raw_line.rstrip().endswith("\\")
        if name in instructions:
            assert len(parts) == 2, f"missing {name} value"
            assert not continues, f"continued {name} is not allowed"
            try:
                value = json.loads(parts[1])
            except json.JSONDecodeError as error:
                raise AssertionError(f"invalid {name} JSON") from error
            instructions[name].append(value)
        elif continues:
            in_continuation = True

    assert not in_continuation, "unterminated Dockerfile continuation"
    assert instructions["ENTRYPOINT"] == [[
        "/opt/venv/bin/python",
        "-I",
        "-m",
        "openworkproof.trusted_helper",
    ]]
    assert instructions["CMD"] == [[]]


def test_supplychain_test_contract_is_portable_and_registered() -> None:
    test_source = Path(__file__).read_text(encoding="utf-8")
    forbidden_home = "/Users" + "/molin/"
    project_config = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    record = _read("README.md")

    assert forbidden_home not in test_source
    assert '"supplychain:' in project_config
    assert "OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT" in record


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

    assert f"FROM {BASE_IMAGE}" in dockerfile
    assert not dockerfile.startswith("# syntax=")
    assert "COPY wheels/ /tmp/wheels/" in dockerfile
    assert "COPY debs/ /tmp/debs/" in dockerfile
    assert dockerfile.count("sha256sum -c SHA256SUMS") == 3
    assert "dpkg --install /tmp/debs/*.deb" in dockerfile
    assert not re.search(r"\b(?:apt-get|apt|curl|wget)\b", dockerfile)
    assert "USER 65532:65532" in dockerfile
    assert _locked_packages(lock_text) == (
        "annotated-types",
        "pydantic",
        "pydantic-core",
        "rfc8785",
        "typing-extensions",
        "typing-inspection",
    )
    assert "COPY helper-src/ /opt/venv/lib/python3.12/site-packages/openworkproof/" in dockerfile
    assert (
        "cd /opt/venv/lib/python3.12/site-packages/openworkproof/"
        in dockerfile
    )
    assert "rm SHA256SUMS" in dockerfile
    assert "mcp_server.py" not in dockerfile
    assert "cli.py" not in dockerfile


def test_trusted_helper_candidate_has_a_fixed_repo_read_entrypoint() -> None:
    dockerfile = _read("trusted-helper/Dockerfile")

    _assert_fixed_helper_process_config(dockerfile)


@pytest.mark.parametrize(
    "shadow",
    (
        '\n entrypoint ["/bin/false"]\n cmd ["shadow"]\n',
        "\nentrypoint /bin/false\ncmd shadow\n",
        '\nENTRYPOINT ["/bin/false"\n',
        '\nCMD ["shadow", \\\n"continued"]\n',
    ),
)
def test_trusted_helper_candidate_rejects_shadow_process_config(
    shadow: str,
) -> None:
    dockerfile = _read("trusted-helper/Dockerfile")

    with pytest.raises(AssertionError):
        _assert_fixed_helper_process_config(dockerfile + shadow)


def test_helper_process_config_parser_ignores_blank_lines_and_comments() -> None:
    dockerfile = _read("trusted-helper/Dockerfile")

    _assert_fixed_helper_process_config(
        dockerfile + '\n  # entrypoint ["/bin/false"]\n\n'
    )


def test_trusted_helper_candidate_rejects_escape_directive_shadow() -> None:
    dockerfile = _read("trusted-helper/Dockerfile")
    mutated = (
        "# escape=`\n"
        + dockerfile
        + 'RUN true \\\nENTRYPOINT ["/bin/false"]\n'
    )

    with pytest.raises(AssertionError):
        _assert_fixed_helper_process_config(mutated)


@pytest.mark.parametrize(
    "directive",
    (
        "# escape=`\n",
        " # ESCAPE = \\\n",
        "# syntax=docker/dockerfile:1\n",
        "  # check = skip=JSONArgsRecommended\n",
    ),
)
def test_helper_process_config_parser_rejects_parser_directives(
    directive: str,
) -> None:
    dockerfile = _read("trusted-helper/Dockerfile")

    with pytest.raises(AssertionError):
        _assert_fixed_helper_process_config(directive + dockerfile)


def test_trusted_helper_source_allowlist_is_the_exact_repo_read_closure() -> None:
    source_allowlist = _read("trusted-helper/SOURCE_ALLOWLIST")

    assert source_allowlist == (
        "src/openworkproof/__init__.py\n"
        "src/openworkproof/models.py\n"
        "src/openworkproof/repo_tools.py\n"
        "src/openworkproof/trusted_helper.py\n"
    )


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


@pytest.mark.parametrize("inventory_path", CANDIDATE_PATHS, ids=lambda path: path.stem)
def test_candidate_inventory_is_closed_and_claims_only_local_evidence(
    inventory_path: Path,
) -> None:
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    source_revision = inventory_path.stem

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
    assert inventory["source_revision"] == source_revision
    assert inventory["base_image"] == {
        "reference": BASE_IMAGE,
        "platform": "linux/arm64",
        "python_version": "3.12.13",
    }
    assert set(inventory["build_inputs"]) == {
        "global",
        "execution",
        "trusted_helper",
    }
    tracked_inputs = {
        ("global", "project_requirements_lock_sha256"): "requirements-lock.txt",
        ("execution", "dockerfile_sha256"): (
            "supply-chain/images/execution/Dockerfile"
        ),
        ("execution", "requirements_lock_sha256"): (
            "supply-chain/images/execution/requirements.lock"
        ),
        ("trusted_helper", "dockerfile_sha256"): (
            "supply-chain/images/trusted-helper/Dockerfile"
        ),
        ("trusted_helper", "requirements_lock_sha256"): (
            "supply-chain/images/trusted-helper/requirements.lock"
        ),
        ("trusted_helper", "debian_packages_lock_sha256"): (
            "supply-chain/images/trusted-helper/debian-packages.lock"
        ),
        ("trusted_helper", "source_allowlist_sha256"): (
            "supply-chain/images/trusted-helper/SOURCE_ALLOWLIST"
        ),
    }
    for (group, key), relative_path in tracked_inputs.items():
        assert inventory["build_inputs"][group][key] == hashlib.sha256(
            _git_bytes(inventory["source_revision"], relative_path)
        ).hexdigest()
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
        assert image["labels"]["org.opencontainers.image.revision"] == source_revision
        assert re.fullmatch(
            r"sha256:[0-9a-f]{64}", image["oci_manifest_digest"]
        )
        assert set(image["archives"]) == {"docker", "oci"}
        assert image["archives"]["docker"]["format"] == "docker-archive"
        assert image["archives"]["oci"]["format"] == (
            "oci-image-layout-archive"
        )

    assert set(inventory["external_layout"]) == {
        "local_root",
        "path_rule",
        "relative_paths",
    }
    assert Path(inventory["external_layout"]["local_root"]).is_absolute()
    assert inventory["external_layout"]["path_rule"] == (
        "join-local-root-with-relative-path-no-parent-traversal"
    )
    relative_paths = inventory["external_layout"]["relative_paths"]
    assert relative_paths["wheelhouse"] == "wheelhouse/linux-arm64-cp312-full"
    assert relative_paths["git_deb_closure"] == "debs/linux-arm64-trixie-git"
    if source_revision == "33a485eacf4ab97b2507f00e5a824ba4a5c8c29c":
        assert relative_paths == {
            "wheelhouse": "wheelhouse/linux-arm64-cp312-full",
            "git_deb_closure": "debs/linux-arm64-trixie-git",
            "execution_build_context": "build-contexts/execution",
            "trusted_helper_build_context": "build-contexts/trusted-helper",
            "archives": "oci",
        }
    else:
        assert relative_paths == {
            "wheelhouse": "wheelhouse/linux-arm64-cp312-full",
            "git_deb_closure": "debs/linux-arm64-trixie-git",
            "execution_build_context": f"build-contexts/{source_revision}/execution",
            "trusted_helper_build_context": (
                f"build-contexts/{source_revision}/trusted-helper"
            ),
            "archives": f"oci/{source_revision}",
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
