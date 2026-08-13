"""Management-plane client for AgentTeams (hiclaw) via the in-container
``agt`` CLI.

AgentTeams exposes its declarative resource API (workers/teams/managers/
humans) through ``agentteams-controller`` on ``:8090`` inside the container,
which is not mapped to the host by the default installer. The official tool
chain (``install/agentteams-apply.sh``) therefore drives ``agt`` through
``docker exec``. This client mirrors that pattern so OWP can manage
AgentTeams resources programmatically without guessing the host-facing REST
address.

Config comes from environment variables:

- ``AGENTTEAMS_DOCKER``      — container runtime binary (default ``docker``)
- ``AGENTTEAMS_CONTAINER``   — controller container name (default
  ``agentteams-controller``)
- ``AGENTTEAMS_AGT_TIMEOUT`` — subprocess timeout seconds (default 30.0)

Only reads resource state and applies declarative YAML; it never stores
credentials (no API key / admin password is accepted).
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from typing import Any

_logger = logging.getLogger("openworkproof.agentteams_controller_client")

DEFAULT_DOCKER = "docker"
DEFAULT_CONTAINER = "agentteams-controller"
DEFAULT_TIMEOUT = 30.0


class AgentTeamsControllerError(Exception):
    """Base class for management-plane failures."""


class AgentTeamsUnavailableError(AgentTeamsControllerError):
    """The controller container or the agt CLI is not reachable."""


class AgentTeamsApplyError(AgentTeamsControllerError):
    """The declarative resource apply was rejected."""


class AgentTeamsControllerClient:
    """Drive ``agt`` inside the AgentTeams controller container."""

    def __init__(
        self,
        *,
        docker: str | None = None,
        container: str | None = None,
        timeout: float | None = None,
    ) -> None:
        self._docker = docker or os.environ.get(
            "AGENTTEAMS_DOCKER", DEFAULT_DOCKER
        )
        self._container = container or os.environ.get(
            "AGENTTEAMS_CONTAINER", DEFAULT_CONTAINER
        )
        self._timeout = float(
            os.environ.get("AGENTTEAMS_AGT_TIMEOUT", str(DEFAULT_TIMEOUT))
        )

    # ---- primitive ---------------------------------------------------------

    def _agt(self, *args: str) -> str:
        command = [self._docker, "exec", self._container, "agt", *args]
        _logger.debug("running %s", " ".join(command))
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise AgentTeamsUnavailableError(
                f"cannot reach AgentTeams controller: {error}"
            ) from error
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise AgentTeamsControllerError(
                f"agt {' '.join(args)} failed: {detail}"
            )
        return completed.stdout

    # ---- resource reads ----------------------------------------------------

    def get_workers(self) -> list[dict[str, Any]]:
        """Return all workers with normalized fields (JSON contract of
        ``agt get workers -o json``)."""
        payload = json.loads(self._agt("get", "workers", "-o", "json"))
        return list(payload.get("workers", []))

    def get_worker(self, name: str) -> dict[str, Any] | None:
        """Return one worker by name, or ``None`` when absent."""
        for worker in self.get_workers():
            if worker.get("name") == name:
                return worker
        return None

    def get_managers(self) -> list[dict[str, Any]]:
        payload = json.loads(self._agt("get", "managers", "-o", "json"))
        return list(payload.get("managers", []))

    def get_teams(self) -> list[dict[str, Any]]:
        payload = json.loads(self._agt("get", "teams", "-o", "json"))
        return list(payload.get("teams", []))

    # ---- resource writes ---------------------------------------------------

    def apply_yaml(self, path: str) -> str:
        """Apply one YAML resource file (workers/teams/humans), replicating
        the official ``agentteams-apply.sh`` behaviour."""
        if not os.path.isfile(path):
            raise AgentTeamsControllerError(f"resource file is missing: {path}")
        try:
            return self._agt("apply", "-f", path)
        except AgentTeamsControllerError as error:
            raise AgentTeamsApplyError(str(error)) from error

    def delete_worker(self, name: str) -> str:
        return self._agt("delete", "worker", name)
