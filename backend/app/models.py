import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, Float, ForeignKey, JSON
from sqlalchemy.orm import relationship
from .database import Base


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id = Column(String, primary_key=True)
    filename = Column(String, nullable=False)
    status = Column(String, default="queued")  # queued, parsing, extracting_links, checking_reputation, llm_assessment, completed, completed_with_warnings, failed
    error_message = Column(Text, nullable=True)
    warnings = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    # Parsed email data
    subject = Column(Text, nullable=True)
    sender_from = Column(String, nullable=True)
    sender_reply_to = Column(String, nullable=True)
    sender_return_path = Column(String, nullable=True)
    recipient_to = Column(Text, nullable=True)
    date = Column(String, nullable=True)
    message_id = Column(String, nullable=True)
    authentication_results = Column(Text, nullable=True)
    received_chain = Column(JSON, default=list)
    raw_headers = Column(Text, nullable=True)
    structured_headers = Column(JSON, default=dict)
    body_text = Column(Text, nullable=True)
    body_html = Column(Text, nullable=True)
    attachment_metadata = Column(JSON, default=list)

    # Header analysis findings
    header_findings = Column(JSON, default=list)

    # Deterministic scores
    phishing_likelihood_score = Column(Integer, nullable=True)
    advertising_likelihood_score = Column(Integer, nullable=True)
    legitimacy_likelihood_score = Column(Integer, nullable=True)
    deterministic_findings = Column(JSON, default=list)

    # Pipeline trace — structured events for observability
    pipeline_trace = Column(JSON, default=list)
    pipeline_summary = Column(JSON, default=dict)

    # Reputation pipeline stats
    reputation_stats = Column(JSON, default=dict)

    links = relationship("ExtractedLink", back_populates="job", cascade="all, delete-orphan")
    llm_assessment = relationship("LlmAssessment", back_populates="job", uselist=False, cascade="all, delete-orphan")


class ExtractedLink(Base):
    __tablename__ = "extracted_links"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("analysis_jobs.id"), nullable=False)
    original_url = Column(Text, nullable=False)
    normalized_url = Column(Text, nullable=False)
    hostname = Column(String, nullable=True)
    display_text = Column(Text, nullable=True)
    has_display_mismatch = Column(Boolean, default=False)
    is_suspicious_tld = Column(Boolean, default=False)
    is_ip_literal = Column(Boolean, default=False)
    is_punycode = Column(Boolean, default=False)
    is_shortener = Column(Boolean, default=False)
    is_tracking_heavy = Column(Boolean, default=False)
    is_safelink = Column(Boolean, default=False)

    # Dedup key for provider-level dedup
    dedup_key = Column(String, nullable=True)

    # Aggregated verdict across all providers
    verdict = Column(String, nullable=True)  # LinkVerdict value

    job = relationship("AnalysisJob", back_populates="links")
    external_checks = relationship("ExternalCheckResult", back_populates="link", cascade="all, delete-orphan")


class ExternalCheckResult(Base):
    __tablename__ = "external_check_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    link_id = Column(Integer, ForeignKey("extracted_links.id"), nullable=False)
    service = Column(String, nullable=False)  # virustotal, urlscan
    submission_id = Column(String, nullable=True)
    status = Column(String, default="pending")  # legacy: pending, completed, failed, timeout
    scan_status = Column(String, default="queued")  # ScanStatus enum value — granular
    result_summary = Column(JSON, default=dict)
    malicious_count = Column(Integer, default=0)
    suspicious_count = Column(Integer, default=0)
    result_fetched = Column(Boolean, default=False)  # confirms API result was actually downloaded
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    link = relationship("ExtractedLink", back_populates="external_checks")


class LlmAssessment(Base):
    __tablename__ = "llm_assessments"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("analysis_jobs.id"), nullable=False)
    classification = Column(String, nullable=False)  # phishing, advertising, legitimate, suspicious, unknown
    risk_score = Column(Integer, default=0)
    confidence = Column(Integer, default=0)
    recommended_action = Column(String, nullable=False)  # delete, open_ticket, verify_via_known_channel, allow, manual_review
    rationale = Column(Text, nullable=True)
    evidence = Column(JSON, default=list)
    analyst_summary = Column(Text, nullable=True)
    is_deterministic_fallback = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    job = relationship("AnalysisJob", back_populates="llm_assessment")
