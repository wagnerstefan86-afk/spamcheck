"""Pydantic response schemas for the MailScope API.

Includes both legacy UI-oriented responses and Copilot-optimized service responses.
"""

from pydantic import BaseModel, Field
from typing import Optional, Literal
from datetime import datetime


# ─── Shared Sub-Models ──────────────────────────────────────────────────────

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


# ─── Analysis Summary Sub-Models (Copilot-ready) ───────────────────────────

class ActionDecisionResponse(BaseModel):
    """Operative action decision for the end user."""
    action: Literal["open", "manual_review", "do_not_open"]
    label: str = Field(description="User-facing label (German)")
    reason: str = Field(description="Short explanation for the user")
    primary_driver: Optional[str] = Field(default=None, description="Key signal that drove this decision")


class IdentitySummaryResponse(BaseModel):
    """Summary of sender identity assessment."""
    from_domain: Optional[str] = None
    reply_to_domain: Optional[str] = None
    return_path_domain: Optional[str] = None
    consistency: Literal["consistent", "partial_mismatch", "suspicious"]
    consistency_detail: str
    is_bulk_sender: bool
    auth_spf: Optional[str] = None
    auth_dkim: Optional[str] = None
    auth_dmarc: Optional[str] = None


class ReputationSummaryResponse(BaseModel):
    """Summary of link reputation analysis."""
    total_links: int = 0
    malicious: int = 0
    suspicious: int = 0
    clean: int = 0
    coverage: Literal["clean", "partially_analyzed", "unknown", "not_checked", "none"] = "none"
    coverage_percent: Optional[int] = None
    links_fully_analyzed: int = 0
    links_without_result: int = 0


class DecisionFactorsResponse(BaseModel):
    """Top signals driving the decision."""
    negative: list[dict] = Field(default_factory=list, description="Top negative signal keys/labels")
    positive: list[dict] = Field(default_factory=list, description="Top positive signal keys/labels")


class NormalizedSignalResponse(BaseModel):
    """A single normalized analysis signal."""
    key: str
    canonical_key: str
    label: str
    severity: Literal["positive", "noteworthy", "critical", "context"]
    tier: int = Field(ge=1, le=5)
    direction: Literal["positive", "negative"]
    domain: str
    category: str


class AnalysisSummaryResponse(BaseModel):
    """Central analysis result object — the primary Copilot data contract.

    This is the structured output that Copilot Studio consumes to formulate
    natural-language responses. All fields are JSON-safe and self-contained.
    """
    version: int = Field(default=2, description="Schema version for forward compatibility")

    # Action decision — the primary output
    action_decision: ActionDecisionResponse
    action_label: str = Field(description="Short action label for quick display")
    action_reason: str = Field(description="Human-readable reason for the decision")

    # Classification
    classification: str = Field(description="Email classification: phishing, suspicious, advertising, legitimate, unknown")
    risk_score: int = Field(ge=0, le=100, description="Overall risk score 0-100")
    confidence: int = Field(ge=0, le=100, description="Confidence in the assessment 0-100")

    # Content risk
    content_risk_level: Literal["none", "low", "high"] = "none"

    # Decision factors
    decision_factors: DecisionFactorsResponse = Field(default_factory=DecisionFactorsResponse)

    # Identity
    identity_summary: IdentitySummaryResponse

    # Reputation
    reputation_summary: ReputationSummaryResponse = Field(default_factory=ReputationSummaryResponse)

    # Signals (normalized)
    signals: list[NormalizedSignalResponse] = Field(default_factory=list)

    # Escalation
    escalation_hint: Optional[str] = Field(default=None, description="Hint for Copilot to suggest escalation to IT security")

    # Override
    override_applied: bool = Field(default=False, description="Whether content risk overrode a benign classification")

    model_config = {"from_attributes": True}


# ─── Job Status Response ────────────────────────────────────────────────────

class JobStatusResponse(BaseModel):
    id: str
    filename: str
    status: str
    warnings: list[str]
    created_at: datetime
    updated_at: datetime
    error_message: Optional[str] = None

    model_config = {"from_attributes": True}


# ─── Job Result Response (Legacy / UI-oriented) ────────────────────────────

class JobResultResponse(BaseModel):
    """Full analysis result — used by the standalone web UI.

    Contains all raw data needed for frontend rendering.
    For Copilot integration, prefer /summary endpoint instead.
    """
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
    analysis_summary: Optional[AnalysisSummaryResponse] = None
    enable_virustotal: bool = True
    enable_urlscan: bool = True
    enable_llm: bool = False

    model_config = {"from_attributes": True}


# ─── Copilot Service Response ──────────────────────────────────────────────

class ServiceResultResponse(BaseModel):
    """Copilot-optimized analysis result.

    Contains only the structured analysis summary plus essential metadata.
    Designed for consumption by Copilot Studio REST connector.
    """
    job_id: str
    filename: str
    status: str
    subject: Optional[str] = None
    sender: SenderInfo
    analysis_summary: AnalysisSummaryResponse
    warnings: list[str] = []

    model_config = {"from_attributes": True}


# ─── Pipeline Trace Response (Internal/Debug) ──────────────────────────────

class PipelineTraceResponse(BaseModel):
    """Debug/analyst endpoint: full pipeline trace.

    Not intended for Copilot consumption — for internal diagnostics only.
    """
    job_id: str
    status: str
    summary: dict
    events: list[dict]
    reputation_stats: dict

    model_config = {"from_attributes": True}
