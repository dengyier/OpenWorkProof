from __future__ import annotations

import runpy
import sys


module = runpy.run_path(sys.argv[1])
assert module["wrap_tokens"]("alpha beta") == ("alpha", "beta")
