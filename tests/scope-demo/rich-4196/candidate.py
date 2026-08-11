from __future__ import annotations

import re


_BREAKABLE_SPACE = re.compile(r"[\t\n\r\f\v ]+")


def wrap_tokens(text: str) -> tuple[str, ...]:
    """Split only on breakable ASCII whitespace; NBSP remains in a token."""
    return tuple(part for part in _BREAKABLE_SPACE.split(text) if part)
