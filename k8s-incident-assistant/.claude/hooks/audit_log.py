#!/usr/bin/env python3
"""PostToolUse hook: append every tool call to .claude/audit.log (JSON lines).

An audit trail answers "what did the AI look at and run?" during a review.
"""
import datetime
import json
import os
import sys

PROJECT_DIR = os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())
LOG = os.path.join(PROJECT_DIR, ".claude", "audit.log")

try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)

entry = {
    "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "session": data.get("session_id"),
    "tool": data.get("tool_name"),
    "input": data.get("tool_input"),
}
try:
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
except OSError:
    pass
sys.exit(0)
