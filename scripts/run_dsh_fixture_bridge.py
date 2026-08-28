"""Run the installed DSH bridge at one deterministic fixture timestamp."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from openworkproof.dsh_bridge import run_stdio_bridge


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--at", required=True)
    args = parser.parse_args()
    now = datetime.strptime(args.at, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    return run_stdio_bridge(
        sys.stdin,
        sys.stdout,
        sys.stderr,
        clock=lambda: now,
    )


if __name__ == "__main__":
    raise SystemExit(main())
