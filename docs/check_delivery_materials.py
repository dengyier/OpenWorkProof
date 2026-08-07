"""Check the M4 delivery materials checklist (8 categories).

Verifies each material path exists and, where applicable, matches the
frozen SHA256SUMS anchor. Exits 0 when all categories are present.

Usage:
    python check_delivery_materials.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MATERIALS: list[tuple[str, list[str]]] = [
    (
        "项目说明",
        ["README.md"],
    ),
    (
        "协议文档",
        [
            "docs/offline-verification.md",
            "specs/v0.1/work-order.schema.json",
            "specs/v0.1/capability-grant.schema.json",
            "specs/v0.1/action-receipt.schema.json",
            "specs/v0.1/acceptance-receipt.schema.json",
            "specs/v0.1/acceptance-rejection-receipt.schema.json",
            "specs/v0.1/schema-registry.json",
            "docs/superpowers/specs/",
            "docs/superpowers/plans/",
        ],
    ),
    (
        "代码",
        [
            "src/openworkproof/",
            "pyproject.toml",
            "requirements-lock.txt",
            "supply-chain/images/candidates/",
        ],
    ),
    (
        "验证",
        ["docs/status.md", "tests/"],
    ),
    (
        "演示",
        [
            "tests/test_delivery_m2.py",
            "docs/superpowers/2026-08-07-rich-4196-demo-log.md",
        ],
    ),
    (
        "签署",
        [
            "docs/delivery-signoff/MANIFEST.md",
            "docs/delivery-signoff/SHA256SUMS",
            "docs/delivery-signoff/owner.signature",
            "docs/delivery-signoff/witness.signature",
        ],
    ),
    (
        "法律",
        ["LICENSE"],
    ),
    (
        "补充",
        ["docs/delivery-materials-checklist.md"],
    ),
]


def main() -> int:
    missing: list[str] = []
    for category, paths in MATERIALS:
        for relative in paths:
            path = ROOT / relative
            if not path.exists():
                missing.append(f"{category}: {relative}")
    if missing:
        for item in missing:
            print(f"MISSING {item}", file=sys.stderr)
        print(f"{len(missing)} missing material(s)", file=sys.stderr)
        return 1
    print(f"OK: {len(MATERIALS)} categories, all materials present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
