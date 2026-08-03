"""Static contracts for the Day 0 candidate image supply chain."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE_ROOT = ROOT / "supply-chain" / "images"
BASE_IMAGE = (
    "docker.io/library/python@sha256:"
    "57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de"
)
CANDIDATE_PATHS = tuple(sorted((IMAGE_ROOT / "candidates").glob("*.json")))
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")
TRACKED_INPUTS = {
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


def _assert_exact_keys(
    value: object, expected: set[str], label: str
) -> dict[str, object]:
    assert type(value) is dict, f"{label} must be an object"
    assert set(value) == expected, f"{label} keys are not exact"
    return value


def _assert_string(value: object, label: str) -> str:
    assert type(value) is str and value, f"{label} must be a non-empty string"
    return value


def _assert_sha256(value: object, label: str) -> str:
    value = _assert_string(value, label)
    assert SHA256_PATTERN.fullmatch(value), f"{label} must be sha256 hex"
    return value


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        assert key not in value, f"duplicate JSON key: {key}"
        value[key] = item
    return value


def _load_candidate_inventory(inventory_path: Path) -> dict[str, object]:
    mode = inventory_path.lstat().st_mode
    assert stat.S_ISREG(mode) and not inventory_path.is_symlink(), (
        "inventory must be a regular non-symlink file"
    )
    try:
        text = inventory_path.read_bytes().decode("utf-8")
        inventory = json.loads(text, object_pairs_hook=_no_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssertionError("inventory must be strict UTF-8 JSON") from error

    inventory = _assert_exact_keys(
        inventory,
        {
            "schema_version",
            "source_revision",
            "base_image",
            "build_inputs",
            "images",
            "external_layout",
            "license",
            "claims",
        },
        "inventory",
    )
    assert inventory["schema_version"] == (
        "openworkproof-image-candidate-inventory/0.1"
    )
    revision = _assert_string(inventory["source_revision"], "source_revision")
    assert REVISION_PATTERN.fullmatch(revision)
    assert inventory_path.stem == revision
    exists = subprocess.run(
        ["git", "cat-file", "-e", f"{revision}^{{commit}}"],
        cwd=ROOT,
        capture_output=True,
    )
    assert exists.returncode == 0, "source_revision commit does not exist"
    resolved = subprocess.run(
        ["git", "rev-parse", "--verify", f"{revision}^{{commit}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert resolved == revision, "source_revision does not resolve exactly"

    base = _assert_exact_keys(
        inventory["base_image"], {"reference", "platform", "python_version"}, "base"
    )
    assert base == {
        "reference": BASE_IMAGE,
        "platform": "linux/arm64",
        "python_version": "3.12.13",
    }

    build_inputs = _assert_exact_keys(
        inventory["build_inputs"], {"global", "execution", "trusted_helper"}, "inputs"
    )
    expected_input_keys = {
        "global": {
            "project_requirements_lock_sha256",
            "full_wheelhouse_sha256sums_sha256",
        },
        "execution": {
            "dockerfile_sha256",
            "requirements_lock_sha256",
            "wheel_sha256sums_sha256",
        },
        "trusted_helper": {
            "dockerfile_sha256",
            "requirements_lock_sha256",
            "debian_packages_lock_sha256",
            "source_allowlist_sha256",
            "wheel_sha256sums_sha256",
            "deb_sha256sums_sha256",
            "helper_src_sha256sums_sha256",
        },
    }
    for group, expected_keys in expected_input_keys.items():
        values = _assert_exact_keys(build_inputs[group], expected_keys, group)
        for key, digest in values.items():
            _assert_sha256(digest, f"{group}.{key}")
    for (group, key), relative_path in TRACKED_INPUTS.items():
        assert build_inputs[group][key] == hashlib.sha256(
            _git_bytes(revision, relative_path)
        ).hexdigest()

    images = _assert_exact_keys(
        inventory["images"], {"execution", "trusted_helper"}, "images"
    )
    image_repositories = {
        "execution": "openworkproof/execution-test",
        "trusted_helper": "openworkproof/trusted-helper-candidate",
    }
    image_roles = {
        "execution": "execution-test",
        "trusted_helper": "trusted-helper-candidate",
    }
    image_titles = {
        "execution": "OpenWorkProof Rich execution/test candidate",
        "trusted_helper": "OpenWorkProof trusted-helper candidate",
    }
    image_descriptions = {
        "execution": (
            "Offline Python 3.12 pytest runtime for the fixed Rich 15 source test"
        ),
        "trusted_helper": (
            "Offline candidate containing Git and the frozen OpenWorkProof helper subset"
        ),
    }
    for image_name, repository in image_repositories.items():
        image = _assert_exact_keys(
            images[image_name],
            {
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
            },
            image_name,
        )
        candidate_name = _assert_string(image["candidate_name"], "candidate_name")
        assert candidate_name in {f"{repository}:candidate", f"{repository}:{revision}"}
        image_id = _assert_string(image["local_image_id"], "local_image_id")
        assert IMAGE_ID_PATTERN.fullmatch(image_id)
        repo_digests = image["local_repo_digests"]
        assert type(repo_digests) is list and repo_digests == [f"{repository}@{image_id}"]
        assert image["platform"] == "linux/arm64"
        assert image["user"] == "65532:65532"
        assert type(image["entrypoint"]) is list and image["entrypoint"]
        assert all(type(token) is str and token for token in image["entrypoint"])
        assert image["cmd"] is None or (
            type(image["cmd"]) is list
            and all(type(token) is str for token in image["cmd"])
        )
        if image_name == "execution":
            assert image["entrypoint"] == ["/usr/bin/env", "--"]
            assert image["cmd"] == [
                "/opt/venv/bin/python",
                "-I",
                "-m",
                "pytest",
            ]
        elif revision == "33a485eacf4ab97b2507f00e5a824ba4a5c8c29c":
            assert image["entrypoint"] == ["/opt/venv/bin/python", "-I"]
            assert image["cmd"] == ["-c", "import sys; sys.exit(64)"]
        else:
            assert image["entrypoint"] == [
                "/opt/venv/bin/python",
                "-I",
                "-m",
                "openworkproof.trusted_helper",
            ]
            assert image["cmd"] is None
        labels = _assert_exact_keys(
            image["labels"],
            {
                "org.opencontainers.image.title",
                "org.opencontainers.image.description",
                "org.opencontainers.image.source",
                "org.opencontainers.image.revision",
                "org.openworkproof.image.role",
                "org.openworkproof.base.digest",
            },
            "labels",
        )
        assert labels == {
            "org.opencontainers.image.title": image_titles[image_name],
            "org.opencontainers.image.description": image_descriptions[image_name],
            "org.opencontainers.image.source": "https://github.com/dengyier/OpenWorkProof",
            "org.opencontainers.image.revision": revision,
            "org.openworkproof.image.role": image_roles[image_name],
            "org.openworkproof.base.digest": BASE_IMAGE.rsplit("@", 1)[1],
        }
        assert not any("license" in key.casefold() for key in labels)
        manifest_digest = _assert_string(
            image["oci_manifest_digest"], "oci_manifest_digest"
        )
        assert IMAGE_ID_PATTERN.fullmatch(manifest_digest)
        archives = _assert_exact_keys(
            image["archives"], {"docker", "oci"}, "archives"
        )
        for archive_name, expected_format in (
            ("docker", "docker-archive"),
            ("oci", "oci-image-layout-archive"),
        ):
            archive = _assert_exact_keys(
                archives[archive_name], {"format", "filename", "sha256"}, "archive"
            )
            assert archive["format"] == expected_format
            filename = _assert_string(archive["filename"], "archive filename")
            assert filename == (
                f"openworkproof-{image_roles[image_name]}-candidate."
                f"{archive_name}-archive.tar"
            ).replace("-candidate-candidate", "-candidate")
            _assert_sha256(archive["sha256"], "archive sha256")

    layout = _assert_exact_keys(
        inventory["external_layout"], {"local_root", "path_rule", "relative_paths"}, "layout"
    )
    local_root = _assert_string(layout["local_root"], "local_root")
    assert Path(local_root).is_absolute()
    assert layout["path_rule"] == "join-local-root-with-relative-path-no-parent-traversal"
    relative_paths = _assert_exact_keys(
        layout["relative_paths"],
        {
            "wheelhouse",
            "git_deb_closure",
            "execution_build_context",
            "trusted_helper_build_context",
            "archives",
        },
        "relative_paths",
    )
    assert all(type(value) is str and value for value in relative_paths.values())
    expected_relative_paths = {
        "wheelhouse": "wheelhouse/linux-arm64-cp312-full",
        "git_deb_closure": "debs/linux-arm64-trixie-git",
        "execution_build_context": f"build-contexts/{revision}/execution",
        "trusted_helper_build_context": f"build-contexts/{revision}/trusted-helper",
        "archives": f"oci/{revision}",
    }
    if revision == "33a485eacf4ab97b2507f00e5a824ba4a5c8c29c":
        expected_relative_paths.update(
            {
                "execution_build_context": "build-contexts/execution",
                "trusted_helper_build_context": "build-contexts/trusted-helper",
                "archives": "oci",
            }
        )
    assert relative_paths == expected_relative_paths

    license_record = _assert_exact_keys(
        inventory["license"], {"status", "spdx", "oci_label_present"}, "license"
    )
    assert license_record["status"] == "PENDING"
    assert license_record["spdx"] == "NOASSERTION"
    assert type(license_record["oci_label_present"]) is bool
    labels_have_license = any(
        "license" in key.casefold()
        for image in images.values()
        for key in image["labels"]
    )
    assert license_record["oci_label_present"] is labels_have_license

    claims = _assert_exact_keys(
        inventory["claims"],
        {
            "registry_pushed",
            "acceptor_access",
            "clean_cache_reacquisition",
            "final_trusted_helper",
            "day0_pass",
            "acceptor_acquisition_path",
        },
        "claims",
    )
    for key in (
        "registry_pushed",
        "acceptor_access",
        "clean_cache_reacquisition",
        "final_trusted_helper",
        "day0_pass",
    ):
        assert type(claims[key]) is bool, f"{key} must be bool"
        assert claims[key] is False
    assert claims["acceptor_acquisition_path"] is None
    return inventory


def _write_inventory(
    tmp_path: Path, inventory: dict[str, object], *, name: str | None = None
) -> Path:
    source_revision = inventory["source_revision"]
    assert isinstance(source_revision, str)
    path = tmp_path / (name or f"{source_revision}.json")
    path.write_text(json.dumps(inventory), encoding="utf-8")
    return path


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
    inventory = _load_candidate_inventory(inventory_path)
    assert inventory["source_revision"] == inventory_path.stem


def test_inventory_loader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    original = CANDIDATE_PATHS[-1].read_text(encoding="utf-8")
    duplicate = original.replace(
        "{\n",
        '{\n  "schema_version": "shadowed",\n',
        1,
    )
    path = tmp_path / CANDIDATE_PATHS[-1].name
    path.write_text(duplicate, encoding="utf-8")

    with pytest.raises(AssertionError, match="duplicate"):
        _load_candidate_inventory(path)


@pytest.mark.parametrize(
    "location",
    ("top", "build_input", "image", "label", "archive"),
)
def test_inventory_loader_rejects_unknown_nested_fields(
    tmp_path: Path, location: str
) -> None:
    inventory = copy.deepcopy(_load_candidate_inventory(CANDIDATE_PATHS[-1]))
    if location == "top":
        inventory["unexpected"] = "value"
    elif location == "build_input":
        inventory["build_inputs"]["execution"]["unexpected"] = "value"
    elif location == "image":
        inventory["images"]["execution"]["unexpected"] = "value"
    elif location == "label":
        inventory["images"]["execution"]["labels"]["unexpected"] = "value"
    else:
        inventory["images"]["execution"]["archives"]["oci"][
            "unexpected"
        ] = "value"

    with pytest.raises(AssertionError, match="keys"):
        _load_candidate_inventory(_write_inventory(tmp_path, inventory))


def test_inventory_loader_rejects_bool_as_integer_alias(tmp_path: Path) -> None:
    inventory = copy.deepcopy(_load_candidate_inventory(CANDIDATE_PATHS[-1]))
    inventory["claims"]["day0_pass"] = 0

    with pytest.raises(AssertionError, match="bool"):
        _load_candidate_inventory(_write_inventory(tmp_path, inventory))


def test_inventory_loader_rejects_source_revision_drift_to_head(
    tmp_path: Path,
) -> None:
    inventory = copy.deepcopy(_load_candidate_inventory(CANDIDATE_PATHS[-1]))
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    inventory["source_revision"] = head

    with pytest.raises(AssertionError):
        _load_candidate_inventory(
            _write_inventory(tmp_path, inventory, name=f"{head}.json")
        )


def test_inventory_loader_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / CANDIDATE_PATHS[-1].name
    target.write_bytes(CANDIDATE_PATHS[-1].read_bytes())
    link = tmp_path / "linked.json"
    link.symlink_to(target)

    with pytest.raises(AssertionError, match="regular"):
        _load_candidate_inventory(link)
