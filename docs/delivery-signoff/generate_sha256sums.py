"""Generate the frozen SHA256SUMS anchor for the delivery sign-off.

The frozen set is every git-tracked file at HEAD, excluding the
delivery-signoff directory itself (to avoid self-reference). The
resulting SHA256SUMS is the immutable anchor signed by the Owner and
independent witness.

Usage:
    python generate_sha256sums.py [--output SHA256SUMS]
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def git_tracked_files() -> list[str]:
    """Return sorted git-tracked file paths relative to the repo root."""
    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files"],
        check=True,
        capture_output=True,
        text=True,
    )
    files = [line for line in result.stdout.splitlines() if line.strip()]
    files.sort()
    return files


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default=str(ROOT / "docs/delivery-signoff/SHA256SUMS"),
    )
    args = parser.parse_args()
    output = Path(args.output)

    lines: list[str] = []
    for relative in git_tracked_files():
        if relative.startswith("docs/delivery-signoff/"):
            continue
        path = ROOT / relative
        if not path.is_file():
            raise SystemExit(f"tracked file missing: {relative}")
        lines.append(f"{sha256_of(path)}  {relative}")
    lines.sort(key=lambda line: line.split("  ", 1)[1])

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(lines)} entries -> {output}")


if __name__ == "__main__":
    main()
