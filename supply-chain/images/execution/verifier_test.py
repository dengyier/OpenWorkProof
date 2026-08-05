"""Independent regression test for the frozen Rich candidate source."""

from __future__ import annotations

import sys


# Candidate source is mounted read-only here by the execution contract.
sys.path.insert(0, "/workspace")

from rich._wrap import divide_line, words  # noqa: E402


def test_non_breaking_space_stays_inside_one_wrapping_token() -> None:
    # Provenance: https://github.com/Textualize/rich/issues/4196 at
    # frozen upstream commit 9d8f9a372cc5916fd4781fec207ced7ddac2f08f.
    token = "left\N{NO-BREAK SPACE}right"

    assert list(words(token)) == [(0, len(token), token)]
    assert divide_line(f"x {token}", width=len(token), fold=False) == [2]
