import json
import asyncio
from importlib.metadata import version
from pathlib import Path
import subprocess
import sys
import sysconfig
import tomllib

import openworkproof


ROOT = Path(__file__).resolve().parents[1]


def test_catalog_package_name_and_legacy_mcp_commands_start_same_server() -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def inspect(command: str) -> set[str]:
        script_name = command + (".exe" if sys.platform == "win32" else "")
        executable = Path(sysconfig.get_path("scripts")) / script_name
        assert executable.is_file(), f"Missing installed MCP command: {command}"
        async with stdio_client(StdioServerParameters(command=str(executable))) as streams:
            async with ClientSession(*streams) as client:
                initialized = await client.initialize()
                assert initialized.serverInfo.name == "openworkproof"
                return {tool.name for tool in (await client.list_tools()).tools}

    async def check() -> None:
        package_named = await inspect("openworkproof")
        legacy = await inspect("owp-mcp")
        assert package_named == legacy
        assert "owp_verify_work_order" in package_named
        assert "owp_status" in package_named

    asyncio.run(asyncio.wait_for(check(), timeout=30))


def test_package_version_is_protocol_version() -> None:
    assert openworkproof.__version__ == version("openworkproof")


def test_release_metadata_is_synchronized() -> None:
    expected_version = "1.4.1"
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

    assert legacy_mcp["license"] == "Apache-2.0"
    publisher = server["_meta"]["io.modelcontextprotocol.registry/publisher-provided"]
    assert publisher["license"] == "Apache-2.0"
    assert server["websiteUrl"] == pyproject["project"]["urls"]["Homepage"]
    assert not {"homepage", "author", "license", "keywords"} & server.keys()


def test_dir_exposes_all_public_names_without_lazy_import() -> None:
    script = """
import sys
import openworkproof

names = set(dir(openworkproof))
missing = sorted(set(openworkproof.__all__) - names)
assert not missing, f"missing from dir(openworkproof): {missing}"

lazy_names = set(openworkproof._LAZY_EXPORTS)
assert not (lazy_names & set(openworkproof.__dict__)), "dir() triggered __getattr__"
lazy_modules = {module for module, _ in openworkproof._LAZY_EXPORTS.values()}
assert not (lazy_modules & set(sys.modules)), "dir() triggered lazy import"

assert set(openworkproof.__all__) == {"__version__"} | lazy_names
"""
    subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )
