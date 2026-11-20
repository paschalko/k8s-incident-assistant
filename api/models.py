from __future__ import annotations

from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, Field, field_validator

from .store import FILE_NAME_RE, INCIDENT_ID_RE

T = TypeVar("T")
MAX_FILE_CHARS = 200_000


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int
    pages: int


class IncidentSummary(BaseModel):
    id: str
    title: str
    severity: str | None
    incident_types: list[Literal["reliability", "security"]]
    evidence_count: int


class Line(BaseModel):
    line: int
    text: str


class EvidenceAnalysis(BaseModel):
    name: str
    lines: int
    format: Literal["json", "text"]
    levels: dict[str, int]
    runtime_signals: list[Line]
    security_signals: list[Line]
    suspicious_lines: list[Line]
    summary: str


class RunbookMatch(BaseModel):
    runbook: str
    score: int
    matched: list[str]


class InjectionWarning(Line):
    file: str


class TriageResult(BaseModel):
    incident_id: str | None = None
    incident_types: list[Literal["reliability", "security"]]
    suggested_runbooks: list[RunbookMatch]
    prompt_injection_warnings: list[InjectionWarning]
    evidence: list[EvidenceAnalysis]
    next_step: str


class IncidentDetail(IncidentSummary):
    report: str
    evidence_files: list[str]


class Runbook(BaseModel):
    runbook: str
    use_when: str
    owner: str


class EvidenceIn(BaseModel):
    name: str = Field(examples=["checkout-api.log"])
    content: str = Field(min_length=1, max_length=MAX_FILE_CHARS)

    @field_validator("name")
    @classmethod
    def safe_name(cls, v: str) -> str:
        if not FILE_NAME_RE.match(v):
            raise ValueError("use letters, numbers, dots, dashes and underscores only")
        return v


class TriageRequest(BaseModel):
    incident_id: str | None = Field(default=None, examples=["INC-2041"])
    context: str = Field(default="", max_length=20_000, description="Free text from the incident report.")
    evidence: list[EvidenceIn] = Field(min_length=1, max_length=10)

    @field_validator("incident_id")
    @classmethod
    def valid_id(cls, v: str | None) -> str | None:
        if v is not None and not INCIDENT_ID_RE.match(v):
            raise ValueError("incident IDs look like INC-2041")
        return v


class ErrorBody(BaseModel):
    code: str
    message: str
    details: list[dict] | None = None
    request_id: str | None = None


class ErrorResponse(BaseModel):
    error: ErrorBody
