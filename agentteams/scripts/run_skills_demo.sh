#!/usr/bin/env bash
# 调用 OWP Skill 工具生成运行证据（Skill 工程体系 25% 权重的实证）。
# Wrapper around the python script (PYTHONPATH setup).

set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
export PYTHONPATH="$REPO/src${PYTHONPATH:+:$PYTHONPATH}"
if [ -x "$REPO/.venv/bin/python" ]; then
  PY="$REPO/.venv/bin/python"
else
  PY=python
fi
exec "$PY" "$REPO/agentteams/scripts/run_skills_demo.py" "$@"
