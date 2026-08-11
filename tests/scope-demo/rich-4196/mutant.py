from __future__ import annotations

import re


def wrap_tokens(text: str) -> tuple[str, ...]:
    """Registered negative control: incorrectly treats NBSP as whitespace."""
    return tuple(part for part in re.split(r"\s+", text) if part)
