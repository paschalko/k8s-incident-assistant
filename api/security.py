"""API keys with roles.

Keys come from the TRIAGE_API_KEYS environment variable (in production, injected from a
secrets manager), written as `role:key` pairs separated by commas:

    TRIAGE_API_KEYS="viewer:abc123,analyst:def456"

viewer  - can read incidents, evidence summaries and runbooks
analyst - everything a viewer can do, plus submit new evidence for triage

If no keys are set, every protected endpoint refuses (fail closed).
"""
from __future__ import annotations

import hashlib
import hmac
import os

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

ROLES = {"viewer": 1, "analyst": 2}
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _digest(key: str) -> bytes:
    return hashlib.sha256(key.encode()).digest()


def _load_keys() -> list[tuple[bytes, str]]:
    keys = []
    for pair in os.environ.get("TRIAGE_API_KEYS", "").split(","):
        role, _, key = pair.strip().partition(":")
        if role in ROLES and len(key) >= 8:
            keys.append((_digest(key), role))
    return keys


def current_role(key: str | None = Security(api_key_header)) -> str:
    if not key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Send an API key in the X-API-Key header.")
    given = _digest(key)
    for stored, role in _load_keys():
        if hmac.compare_digest(given, stored):
            return role
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "That API key isn't valid.")


def require(role: str):
    def check(actual: str = Depends(current_role)) -> str:
        if ROLES[actual] < ROLES[role]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"This needs the {role} role.")
        return actual
    return check
