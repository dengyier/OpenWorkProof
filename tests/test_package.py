import json
from importlib.metadata import version
from pathlib import Path
import tomllib

import openworkproof


ROOT = Path(__file__).resolve().parents[1]


def test_package_version_is_protocol_version() -> None:
    assert openworkproof.__version__ == version("openworkproof")


def test_release_metadata_is_synchronized() -> None:
    expected_version = "1.2.0"
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    server = json.loads((ROOT / "server.json").read_text())
    legacy_mcp = json.loads((ROOT / "mcp.json").read_text())

    assert openworkproof.__version__ == expected_version
    assert version("openworkproof") == expected_version
    assert pyproject["project"]["version"] == expected_version
    assert pyproject["project"]["license"] == "Apache-2.0"
    assert not any(
        classifier.startswith("License ::")
        for classifier in pyproject["project"]["classifiers"]
    )

    for metadata in (server, legacy_mcp):
        assert metadata["version"] == expected_version
        assert metadata["packages"][0]["version"] == expected_version
        assert metadata["license"] == "Apache-2.0"
