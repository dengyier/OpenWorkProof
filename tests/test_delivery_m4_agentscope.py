"""M4 delivery validation: AgentScope #2239 DictMixin attribute-protocol bug.

Functional-layer demo against a *real*, still-open framework issue:
`AgentScope <https://github.com/agentscope-ai/agentscope>`_ issue `#2239
<https://github.com/agentscope-ai/agentscope/issues/2239>`_ —
``DictMixin.__getattr__`` delegates directly to ``dict.__getitem__``, so a
missing mapping key raises ``KeyError`` while Python's attribute protocol
requires ``AttributeError``. As a result ``copy.deepcopy()`` on any
``DictMixin`` subclass (e.g. ``ChatResponse``) crashes with
``KeyError('__deepcopy__')``, and ``hasattr()`` / ``getattr(..., default)``
also raise instead of returning ``False`` / the fallback.

The demo pins the pre-fix source
(``src/agentscope/_utils/_mixin.py`` @ ``8f24009``, 2026-08-12). Two upstream
fix PRs (#2241, #2281) are still open, so the bug is reproducible on current
``main``.

Layers of validation:

1. **Functional layer** (all tests here): the trimmed pinned candidate is
   executable; the bug reproduces (deepcopy / hasattr / getattr default all
   raise ``KeyError``); the focused fix (translate ``KeyError`` to
   ``AttributeError`` while preserving mapping-style ``KeyError``) applies to
   the candidate and resolves every failure; and a regression matrix guards
   the attribute/dict protocol surface (existing-key attribute access,
   ``__setattr__``, deepcopy content preservation, mapping ``KeyError``).

AgentScope and its source code remain the property of their respective
rights holders; OpenWorkProof only owns its own protocol and the task
packaging. This test is fully offline — the candidate source is embedded.
"""

from __future__ import annotations

import copy
import types

import pytest

# Pre-fix AgentScope main at the time of capture (issue #2239, 2026-08-12).
AGENTSCOPE_PINNED_COMMIT = "8f24009"
AGENTSCOPE_ISSUE = 2239

# Repo-relative path of the buggy file in the pinned AgentScope tree.
AGENTSCOPE_PATH = "src/agentscope/_utils/_mixin.py"

# The candidate path inside the demo workspace (developer grant scope).
CANDIDATE_PATH = "src/mixin.py"

# Trimmed, executable candidate content — verbatim from the pinned pre-fix
# source (src/agentscope/_utils/_mixin.py @ 8f24009, issue #2239).
AGENTSCOPE_MIXIN_CANDIDATE = '''"""Trimmed from agentscope-ai/agentscope @ 8f24009 (issue #2239, pre-fix).

``DictMixin.__getattr__`` delegates directly to ``dict.__getitem__``; a
missing mapping key raises ``KeyError``, while Python's attribute protocol
expects ``AttributeError``. ``copy.deepcopy()`` / ``hasattr()`` /
``getattr(..., default)`` on any subclass (e.g. ``ChatResponse``) therefore
crash with ``KeyError`` (e.g. ``KeyError('__deepcopy__')``).
"""


class DictMixin(dict):
    """The dictionary mixin that allows attribute-style access."""

    __setattr__ = dict.__setitem__
    __getattr__ = dict.__getitem__
'''

# The buggy line present verbatim in the pinned candidate content.
_BUG_LINES = "    __getattr__ = dict.__getitem__\n"

# The focused fix: translate KeyError to AttributeError for attribute
# lookup, preserving KeyError for direct mapping access (mirrors the
# behaviour requested in issue #2239 and implemented by PRs #2241/#2281).
_FIXED_GETATTR = (
    "    def __getattr__(self, name):\n"
    "        try:\n"
    "            return dict.__getitem__(self, name)\n"
    "        except KeyError:\n"
    "            raise AttributeError(name) from None\n"
)


def _load_module(source: str, name: str) -> types.ModuleType:
    module = types.ModuleType(name)
    exec(compile(source, name, "exec"), module.__dict__)  # noqa: S102
    return module


def _chat_response(module: types.ModuleType):
    """A DictMixin subclass mirroring the issue's ChatResponse scenario."""

    class ChatResponse(module.DictMixin):
        pass

    return ChatResponse()


# ---------------------------------------------------------------------------
# Functional layer
# ---------------------------------------------------------------------------


def test_agentscope_2239_bug_reproduces_on_pinned_source() -> None:
    """The pinned pre-fix mixin breaks the attribute protocol and deepcopy."""
    module = _load_module(
        AGENTSCOPE_MIXIN_CANDIDATE, "agentscope_mixin_prefix"
    )
    response = _chat_response(module)
    # deepcopy() crashes on the empty response (issue reproduction).
    with pytest.raises(KeyError, match="__deepcopy__"):
        copy.deepcopy(response)
    # Attribute protocol expects False / fallback, not KeyError.
    with pytest.raises(KeyError, match="missing"):
        hasattr(response, "missing")
    with pytest.raises(KeyError, match="missing"):
        getattr(response, "missing", "fallback")


def test_agentscope_2239_fix_applies_and_resolves() -> None:
    """The focused fix applies to the candidate and resolves every failure."""
    # Patch evidence: the buggy line is present, the fix is not.
    assert _BUG_LINES in AGENTSCOPE_MIXIN_CANDIDATE
    assert "def __getattr__" not in AGENTSCOPE_MIXIN_CANDIDATE
    fixed_source = AGENTSCOPE_MIXIN_CANDIDATE.replace(
        _BUG_LINES, _FIXED_GETATTR
    )
    assert _BUG_LINES not in fixed_source
    assert _FIXED_GETATTR in fixed_source

    module = _load_module(fixed_source, "agentscope_mixin_fixed")
    response = _chat_response(module)

    # Attribute protocol restored.
    assert hasattr(response, "missing") is False
    assert getattr(response, "missing", "fallback") == "fallback"
    # deepcopy() now works on the empty response.
    cloned = copy.deepcopy(response)
    assert type(cloned) is type(response)
    # Mapping-style access still raises KeyError.
    with pytest.raises(KeyError, match="missing"):
        response["missing"]


def test_agentscope_2239_regression_matrix() -> None:
    """The fixed mixin keeps the dict surface intact."""
    module = _load_module(
        AGENTSCOPE_MIXIN_CANDIDATE.replace(_BUG_LINES, _FIXED_GETATTR),
        "agentscope_mixin_regression",
    )
    response = _chat_response(module)

    # Attribute access to existing keys still works.
    response["content"] = "ok"
    assert response.content == "ok"
    # __setattr__ still writes through to the mapping.
    response.note = "stored"
    assert response["note"] == "stored"
    # deepcopy preserves content.
    cloned = copy.deepcopy(response)
    assert cloned["content"] == "ok"
    assert cloned.note == "stored"
    # True missing attributes still raise AttributeError (not KeyError).
    with pytest.raises(AttributeError, match="missing"):
        _ = response.missing
    # Mapping access to missing keys keeps raising KeyError.
    with pytest.raises(KeyError, match="content2"):
        _ = response["content2"]
