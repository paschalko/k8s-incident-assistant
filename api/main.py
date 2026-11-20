"""Incident Triage API: a read-only HTTP front end for the triage assistant.

Run locally:
    pip install -r api/requirements.txt
    TRIAGE_API_KEYS="viewer:viewer-dev-key,analyst:analyst-dev-key" uvicorn api.main:app --reload
Then open http://127.0.0.1:8000/docs
"""
from __future__ import annotations

import logging
import math
import os
import time
import uuid
from functools import lru_cache
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import analysis, store
from .models import (ErrorResponse, EvidenceAnalysis, IncidentDetail, IncidentSummary, Page, Runbook,
                     TriageRequest, TriageResult)
from .security import require

VERSION = "1.0.0"
log = logging.getLogger("triage_api")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(message)s")

app = FastAPI(
    title="Incident Triage API",
    version=VERSION,
    description="Read-only API over the incident triage assistant. It summarises evidence, flags prompt "
                "injection, hides secrets and suggests runbooks. It never changes anything; a person applies every fix.",
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse},
               422: {"model": ErrorResponse}},
)
viewer = Depends(require("viewer"))
analyst = Depends(require("analyst"))


# ───────── observability and errors ─────────

@app.middleware("http")
async def request_context(request: Request, call_next):
    """Give every request an ID and log one structured line per request."""
    request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
    request.state.request_id = request_id
    start = time.perf_counter()
    response = await call_next(request)
    ms = round((time.perf_counter() - start) * 1000, 1)
    response.headers["X-Request-ID"] = request_id
    log.info('{"request_id":"%s","method":"%s","path":"%s","status":%d,"ms":%s}',
             request_id, request.method, request.url.path, response.status_code, ms)
    return response


def _error(request: Request, status: int, code: str, message: str, details=None) -> JSONResponse:
    body = {"code": code, "message": message, "request_id": getattr(request.state, "request_id", None)}
    if details:
        body["details"] = details
    return JSONResponse({"error": body}, status_code=status)


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    codes = {401: "unauthorised", 403: "forbidden", 404: "not_found"}
    return _error(request, exc.status_code, codes.get(exc.status_code, "error"), str(exc.detail))


@app.exception_handler(store.NotFound)
async def not_found(request: Request, exc: store.NotFound):
    return _error(request, 404, "not_found", str(exc))


@app.exception_handler(RequestValidationError)
async def invalid(request: Request, exc: RequestValidationError):
    details = [{"field": ".".join(str(p) for p in e["loc"][1:]), "problem": e["msg"]} for e in exc.errors()]
    return _error(request, 422, "invalid_request", "Some of the request isn't valid.", details)


@app.exception_handler(Exception)
async def unexpected(request: Request, exc: Exception):
    log.exception("unhandled error, request_id=%s", getattr(request.state, "request_id", None))
    return _error(request, 500, "internal_error", "Something went wrong on our side. Quote the request ID if you report it.")


# ───────── helpers ─────────

def _incident_triage(incident_id: str) -> dict:
    files = store.evidence_files(incident_id)
    stamps = tuple(os.path.getmtime(store.evidence_path(incident_id, f)) for f in files)
    return _incident_triage_cached(incident_id, stamps)


@lru_cache(maxsize=64)
def _incident_triage_cached(incident_id: str, _stamps: tuple) -> dict:
    incident = store.get_incident(incident_id)
    evidence = []
    for name in store.evidence_files(incident_id):
        with open(store.evidence_path(incident_id, name), encoding="utf-8", errors="replace") as f:
            evidence.append((name, f.read()))
    return {"incident_id": incident_id, **analysis.triage(evidence, context=incident["text"])}


def _summary(item: dict) -> dict:
    result = _incident_triage(item["id"])
    return {"id": item["id"], "title": item["title"], "severity": item["severity"],
            "incident_types": result["incident_types"], "evidence_count": len(result["evidence"])}


# ───────── routes ─────────

@app.get("/health", tags=["status"])
def health():
    return {"status": "ok", "version": VERSION}


@app.get("/v1/incidents", response_model=Page[IncidentSummary], tags=["incidents"], dependencies=[viewer])
async def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    type: Literal["reliability", "security"] | None = Query(None, description="Only incidents of this type."),
    severity: str | None = Query(None, pattern=r"^SEV-\d$"),
):
    items = await run_in_threadpool(lambda: [_summary(i) for i in store.list_incidents()])
    if type:
        items = [i for i in items if type in i["incident_types"]]
    if severity:
        items = [i for i in items if i["severity"] == severity.upper()]
    start = (page - 1) * page_size
    return {"items": items[start:start + page_size], "total": len(items), "page": page,
            "page_size": page_size, "pages": max(1, math.ceil(len(items) / page_size))}


@app.get("/v1/incidents/{incident_id}", response_model=IncidentDetail, tags=["incidents"], dependencies=[viewer])
async def get_incident(incident_id: str):
    item = store.get_incident(incident_id)
    summary = await run_in_threadpool(_summary, item)
    return {**summary, "report": analysis.ls.redact(item["text"]), "evidence_files": store.evidence_files(incident_id)}


@app.get("/v1/incidents/{incident_id}/evidence/{name}", response_model=EvidenceAnalysis, tags=["incidents"],
         dependencies=[viewer])
async def get_evidence(incident_id: str, name: str):
    store.get_incident(incident_id)
    return await run_in_threadpool(analysis.analyse_file, store.evidence_path(incident_id, name))


@app.get("/v1/incidents/{incident_id}/triage", response_model=TriageResult, tags=["triage"], dependencies=[viewer])
async def triage_incident(incident_id: str):
    store.get_incident(incident_id)
    return await run_in_threadpool(_incident_triage, incident_id)


@app.post("/v1/triage", response_model=TriageResult, tags=["triage"], dependencies=[analyst])
async def triage_new_evidence(body: TriageRequest):
    """Triage evidence you send in. Nothing is stored, and the response never contains a full secret."""
    evidence = [(e.name, e.content) for e in body.evidence]
    result = await run_in_threadpool(analysis.triage, evidence, body.context)
    return {"incident_id": body.incident_id, **result}


@app.get("/v1/runbooks", response_model=list[Runbook], tags=["runbooks"], dependencies=[viewer])
def runbooks():
    return store.list_runbooks()
