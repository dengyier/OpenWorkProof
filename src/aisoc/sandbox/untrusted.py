"""Data/control separation primitives.

Anything that comes from logs, URLs, attachments or tool outputs is wrapped in
``Untrusted`` so it cannot be confused with instructions. A heuristic injection
screen flags suspicious content for the analyst view; it is *not* a security
boundary. The actual boundary is that agent output can only select from an
enumerated action set and must pass external policy (see ``policy.py``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Generic, List, TypeVar

T = TypeVar("T")

_INJECTION_PATTERNS = [
    r"ignore (all |any )?(previous|prior|above) instructions",
    r"you are now",
    r"system prompt",
    r"as an? (ai|assistant|agent),? you must",
    r"\bexfil(trate)?\b",
    r"curl\s+-X\s+POST",
    r"base64\s+-d",
    r"disable (the )?audit",
    r"approve (this|the) (action|request)",
    r"(send|upload|post) .* to https?://",
    r"\bdrop table\b",
    r"new tenant",
]
_COMPILED = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]


# ── 【老師註解】Untrusted ─────────────────────────────────────────
# 做什麼：一個「標籤盒子」。任何來自日誌、URL、附件、工具輸出的東西都要先裝進來，標明 source 與注入旗標。
# 為什麼：Prompt injection 的本質是「資料被當成指令」。把資料統一包成 Untrusted，程式碼在型別層面就分得出
#         「這是證據（可以看）」和「這是指令（可以做）」。
# 怎麼看：__str__ 故意 raise TypeError——誰想偷懶把它直接拼進字串／提示詞，程式立刻炸掉，而不是默默洩漏。
#         要用內容必須明確寫 .content，等於每次都在程式碼裡留下「我知道這是不可信資料」的簽字。
# 誠實提醒：flags 只是啟發式偵測，給人看的提示，不是安全邊界（邊界在 policy.py / pep.py）。
# 對應：準則 #11；測試 tests/test_policy_pep.py::test_injection_screen_flags_instructions
@dataclass(frozen=True)
class Untrusted(Generic[T]):
    source: str
    content: T
    flags: List[str] = field(default_factory=list)

    def __str__(self) -> str:  # pragma: no cover - guard against accidental string use
        raise TypeError("Untrusted content must be accessed via .content explicitly")


def screen_text(text: str) -> List[str]:
    return [p.pattern for p, _ in zip(_COMPILED, _INJECTION_PATTERNS) if p.search(text)]


# ── 【老師註解】wrap ──────────────────────────────────────────────
# 做什麼：把任意內容包成 Untrusted；若內容是字串或 dict，順便跑一次 screen_text 把可疑句型記進 flags。
# 為什麼：旗標會一路帶到 ApprovalView，讓審批的人看到「這個案子的日誌裡有人寫了 ignore previous instructions」。
# 拿掉會怎樣：人類審批時看不到注入痕跡，更容易被「看起來很合理」的建議帶著走（橡皮圖章風險）。
# 對應：準則 #11；情境「Slips Description text as prompt injection」
def wrap(source: str, content: Any) -> Untrusted[Any]:
    flags: List[str] = []
    if isinstance(content, str):
        flags = screen_text(content)
    elif isinstance(content, dict):
        for v in content.values():
            if isinstance(v, str):
                flags.extend(screen_text(v))
    return Untrusted(source=source, content=content, flags=sorted(set(flags)))
