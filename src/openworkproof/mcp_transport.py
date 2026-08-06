"""MCP (Model Context Protocol) transport for OpenWorkProof.

Exposes the protocol coordinators as MCP tools over stdio. Tools carry the
same JSON protocol messages as the CLI transport:

- ``owp_status(ledger)``          — replay a ledger and return its state
- ``owp_run_tests(ledger, payload)`` — forward one run-tests execution
- ``owp_repo_read(ledger, payload)`` — forward one repo-read execution

Run with ``python -m openworkproof.mcp_transport`` (stdio server).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from openworkproof import cli as cli_module

mcp = FastMCP("openworkproof")

_SCHEMA = "openworkproof/mcp/0.1"


@mcp.tool()
def owp_status(ledger: str) -> dict[str, Any]:
    """Replay an OpenWorkProof ledger and return its authoritative state."""
    try:
        result = cli_module.cli_status(ledger)
        result["schema_version"] = _SCHEMA
        return result
    except cli_module.CliError as error:
        return {"schema_version": _SCHEMA, "error": str(error)}


@mcp.tool()
def owp_run_tests(ledger: str, payload: str) -> dict[str, Any]:
    """Forward one run-tests execution payload (JSON string)."""
    return _forward(cli_module.cli_run_tests, ledger, payload)


@mcp.tool()
def owp_repo_read(ledger: str, payload: str) -> dict[str, Any]:
    """Forward one repo-read execution payload (JSON string)."""
    return _forward(cli_module.cli_repo_read, ledger, payload)


def _forward(forwarder, ledger: str, payload: str) -> dict[str, Any]:
    try:
        parsed = json.loads(payload)
    except (TypeError, ValueError) as error:
        return {"schema_version": _SCHEMA, "error": f"payload is not JSON: {error}"}
    if type(parsed) is not dict:
        return {"schema_version": _SCHEMA, "error": "payload must be an object"}
    try:
        result = forwarder(Path(ledger), parsed)
    except cli_module.CliError as error:
        return {"schema_version": _SCHEMA, "error": str(error)}
    result["schema_version"] = _SCHEMA
    return result


def main() -> None:
    """Run the stdio MCP server."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
