from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class JobStatusResponse(BaseModel):
    id: str
    filename: str
    status: str
    warnings: list[str]
    created_at: datetime
    updated_at: datetime
    error_message: Optional[str] = None

    model_config = {"from_attributes": True}


class ExternalCheckResponse(BaseModel):
    service: str
    status: str
    scan_status: str = "unknown"
    malicious_count: int
    suspicious_count: int
    result_summary: dict
    result_fetched: bool = False

    model_config = {"from_attributes": True}


class LinkResponse(BaseModel):
    id: int
    original_url: str
    normalized_url: str
    hostname: Optional[str]
    display_text: Optional[str]
    has_display_mismatch: bool
    is_suspicious_tld: bool
    is_ip_literal: bool
    is_punycode: bool
    is_shortener: bool
    is_tracking_heavy: bool
    is_safelink: bool
    dedup_key: Optional[str] = None
    verdict: Optional[str] = None
    external_checks: list[ExternalCheckResponse] = []

    model_config = {"from_attributes": True}


class LlmAssessmentResponse(BaseModel):
    classification: str
    risk_score: int
    confidence: int
    recommended_action: str
    rationale: Optional[str]
    evidence: list[str]
    analyst_summary: Optional[str]
    is_deterministic_fallback: bool

    model_config = {"from_attributes": True}


class SenderInfo(BaseModel):
    from_address: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    to: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None


class HeaderFinding(BaseModel):
    id: str
    severity: str  # info, warning, critical
    title: str
    detail: str


class JobResultResponse(BaseModel):
    id: str
    filename: str
    status: str
    warnings: list[str]
    subject: Optional[str] = None
    sender: SenderInfo
    authentication_results: Optional[str] = None
    received_chain: list[str] = []
    raw_headers: Optional[str] = None
    structured_headers: dict = {}
    attachment_metadata: list[dict] = []
    header_findings: list[dict] = []
    links: list[LinkResponse] = []
    deterministic_scores: Optional[dict] = None
    deterministic_findings: list[dict] = []
    assessment: Optional[LlmAssessmentResponse] = None
    reputation_stats: Optional[dict] = None
    enable_virustotal: bool = True
    enable_urlscan: bool = True
    enable_llm: bool = True

    model_config = {"from_attributes": True}


class PipelineTraceResponse(BaseModel):
    job_id: str
    status: str
    summary: dict
    events: list[dict]
    reputation_stats: dict

    model_config = {"from_attributes": True}
