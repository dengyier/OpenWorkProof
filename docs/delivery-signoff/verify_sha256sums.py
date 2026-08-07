"""Verify a frozen SHA256SUMS anchor by recomputing every digest.

Exits 0 when all entries match and the file count matches the frozen
manifest; exits 1 otherwise.

Usage:
    python verify_sha256sums.py [--manifest SHA256SUMS]
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        default=str(ROOT / "docs/delivery-signoff/SHA256SUMS"),
    )
    args = parser.parse_args()
    manifest = Path(args.manifest)

    if not manifest.is_file():
        print(f"missing manifest: {manifest}", file=sys.stderr)
        return 1

    failures: list[str] = []
    total = 0
    for line in manifest.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        expected, _, relative = line.partition("  ")
        if not relative:
            print(f"malformed line: {line!r}", file=sys.stderr)
            failures.append(line)
            continue
        path = ROOT / relative
        total += 1
        if not path.is_file():
            failures.append(f"{relative}: missing")
            continue
        actual = sha256_of(path)
        if actual != expected:
            failures.append(f"{relative}: digest mismatch")

    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"{len(failures)} failure(s) across {total} entries", file=sys.stderr)
        return 1
    print(f"OK: {total} entries verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
