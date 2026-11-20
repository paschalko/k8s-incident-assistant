"""Read-only access to incidents, evidence and runbooks on disk."""
from __future__ import annotations

import os
import re

from .analysis import ROOT

INCIDENT_ID_RE = re.compile(r"^INC-\d{3,6}$")
FILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")
SEVERITY_RE = re.compile(r"\*\*Severity:\*\*\s*(SEV-\d)", re.I)


class NotFound(Exception):
    pass


def _dir(name: str) -> str:
    return os.path.join(os.environ.get("TRIAGE_DATA_DIR", ROOT), name)


def list_incidents() -> list[dict]:
    items = []
    for fname in sorted(os.listdir(_dir("incidents"))):
        if not fname.endswith(".md"):
            continue
        incident_id = fname.split("-")[0] + "-" + fname.split("-")[1]
        with open(os.path.join(_dir("incidents"), fname), encoding="utf-8") as f:
            text = f.read()
        title = text.splitlines()[0].lstrip("# ").split("–", 1)[-1].strip()
        sev = SEVERITY_RE.search(text)
        items.append({"id": incident_id, "title": title, "severity": sev.group(1).upper() if sev else None,
                      "file": fname, "text": text})
    return items


def get_incident(incident_id: str) -> dict:
    if not INCIDENT_ID_RE.match(incident_id):
        raise NotFound(f"No incident called {incident_id}.")
    for item in list_incidents():
        if item["id"] == incident_id:
            return item
    raise NotFound(f"No incident called {incident_id}.")


def evidence_files(incident_id: str) -> list[str]:
    folder = os.path.join(_dir("logs"), incident_id)
    if not INCIDENT_ID_RE.match(incident_id) or not os.path.isdir(folder):
        return []
    return sorted(f for f in os.listdir(folder) if FILE_NAME_RE.match(f))


def evidence_path(incident_id: str, name: str) -> str:
    """Only files that are actually listed in the incident's folder can be opened (no ../ tricks)."""
    if not FILE_NAME_RE.match(name) or name not in evidence_files(incident_id):
        raise NotFound(f"{incident_id} has no evidence file called {name}.")
    return os.path.join(_dir("logs"), incident_id, name)


def list_runbooks() -> list[dict]:
    rows = []
    with open(os.path.join(_dir("runbooks"), "INDEX.md"), encoding="utf-8") as f:
        for line in f:
            m = re.match(r"\|\s*\[(?P<file>[\w.-]+)\]\([\w.-]+\)\s*\|\s*(?P<when>[^|]+)\|\s*(?P<owner>[^|]+)\|", line)
            if m:
                rows.append({"runbook": m["file"].removesuffix(".md"), "use_when": m["when"].strip().replace("`", ""),
                             "owner": m["owner"].strip()})
    return rows
