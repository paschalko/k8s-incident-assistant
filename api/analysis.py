"""Turns raw evidence into structured, redacted findings.

This reuses tools/log_summary.py (the same summariser the Claude agents call), so the
API and the agent always see the same redacted view of the evidence.
"""
from __future__ import annotations

import os
import re
import sys
from collections import Counter
from functools import lru_cache

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import log_summary as ls  # noqa: E402

# Which runbook fits which evidence. Each pattern that matches adds one point.
# Ties keep this order, so root causes (OOM) rank above their symptoms (crash loops).
RUNBOOK_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "oomkilled": [re.compile(p, re.I) for p in (r"OOMKill", r"exit code:?\s*137", r"out of memory")],
    "crashloopbackoff": [re.compile(p, re.I) for p in (r"CrashLoopBackOff", r"Back-off restarting", r"Restart Count:\s*[1-9]")],
    "imagepullbackoff": [re.compile(p, re.I) for p in (r"ImagePullBackOff", r"ErrImagePull")],
    "bad-deploy-rollback": [re.compile(p, re.I) for p in (r"Argo CD synced", r"Scaled up replica set", r"\brelease\b")],
    "leaked-credentials": [re.compile(p, re.I) for p in (r"UnauthorizedAccess", r"Discovery:", r"AKIA[0-9A-Z]{4}",
                                                          r"secret scanning", r"MaliciousIPCaller")],
}
SECURITY_RUNBOOKS = {"leaked-credentials"}


def analyse_text(raw: str, name: str, max_lines: int = 25) -> dict:
    """Summarise one piece of evidence. Everything returned has been through redact()."""
    out: list[str] = []
    ls.summarise(raw, name, max_lines, emit=out.append)

    levels: Counter[str] = Counter()
    signals, security, suspicious = [], [], []
    records = ls.load_json_records(raw)
    for n, raw_line in enumerate(raw.splitlines(), 1):
        line = ls.redact(raw_line).strip()
        if (m := ls.LEVEL_RE.search(line)):
            levels[m.group(1).upper().replace("WARNING", "WARN")] += 1
        if ls.K8S_SIGNALS.search(line):
            signals.append({"line": n, "text": line[:300]})
        if ls.SECURITY_SIGNALS.search(raw_line):
            security.append({"line": n, "text": line[:300]})
        if ls.SUSPICIOUS_RE.search(raw_line):
            suspicious.append({"line": n, "text": line[:300]})

    return {
        "name": ls.redact(name),
        "lines": len(raw.splitlines()),
        "format": "json" if records else "text",
        "levels": dict(levels),
        "runtime_signals": signals[:max_lines],
        "security_signals": security[:max_lines],
        "suspicious_lines": suspicious,
        "summary": "\n".join(out),
    }


@lru_cache(maxsize=256)
def _analyse_file_cached(path: str, mtime: float) -> dict:
    with open(path, encoding="utf-8", errors="replace") as f:
        return analyse_text(f.read(), os.path.basename(path))


def analyse_file(path: str) -> dict:
    """Cached by path and modification time, so an edited file is re-read."""
    return _analyse_file_cached(path, os.path.getmtime(path))


def match_runbooks(texts: list[str]) -> list[dict]:
    joined = "\n".join(texts)
    matches = []
    for runbook, patterns in RUNBOOK_PATTERNS.items():
        hits = [p.pattern for p in patterns if p.search(joined)]
        if hits:
            matches.append({"runbook": runbook, "score": len(hits), "matched": hits})
    return sorted(matches, key=lambda m: -m["score"])


def triage(evidence: list[tuple[str, str]], context: str = "") -> dict:
    """Combine several pieces of evidence into one triage result. Never changes anything."""
    files = [analyse_text(raw, name) for name, raw in evidence]
    runbooks = match_runbooks([context] + [raw for _, raw in evidence])
    kinds = []
    if any(f["runtime_signals"] for f in files) or any(r["runbook"] not in SECURITY_RUNBOOKS for r in runbooks):
        kinds.append("reliability")
    if any(f["security_signals"] for f in files) or any(r["runbook"] in SECURITY_RUNBOOKS for r in runbooks):
        kinds.append("security")
    injected = [{"file": f["name"], **s} for f in files for s in f["suspicious_lines"]]
    return {
        "incident_types": kinds,
        "suggested_runbooks": runbooks,
        "prompt_injection_warnings": injected,
        "evidence": files,
        "next_step": "Suggestions only. A person must review and apply any change.",
    }
