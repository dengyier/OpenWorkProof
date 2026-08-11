from __future__ import annotations

import runpy
import sys


module = runpy.run_path(sys.argv[1])
assert module["wrap_tokens"]("alpha\u00a0beta") == ("alpha\u00a0beta",)
