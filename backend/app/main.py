import asyncio
import uuid
import logging
from datetime import datetime, timedelta

from fastapi import FastAPI, UploadFile, File, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .config import get_settings, Settings
from .database import get_db, init_db
from .models import AnalysisJob, ExtractedLink, ExternalCheckResult, LlmAssessment
from .schemas import (
    JobStatusResponse, JobResultResponse, LinkResponse, LlmAssessmentResponse,
    SenderInfo, ExternalCheckResponse, PipelineTraceResponse,
    ServiceResultResponse, AnalysisSummaryResponse,
    ActionDecisionResponse, IdentitySummaryResponse, ReputationSummaryResponse,
    DecisionFactorsResponse, NormalizedSignalResponse,
)
from .services.analysis_runner import run_analysis

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="MailScope Email Security Analysis",
    version="4.0.0",
    description=(
        "Analysiert E-Mail-Dateien auf Phishing, Spoofing und andere Sicherheitsrisiken. "
        "Deterministischer Analyseservice — vorbereitet für Copilot Studio Integration."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    init_db()


def _log_task_exception(task: asyncio.Task, job_id: str):
    """Callback to log unhandled exceptions from background analysis tasks."""
    if task.cancelled():
        logger.warning("Analysis task cancelled for job %s", job_id)
        return
    exc = task.exception()
    if exc:
        logger.error("Unhandled exception in analysis task for job %s: %s", job_id, exc, exc_info=exc)


# ─── Health ─────────────────────────────────────────────────────────────────

@app.get("/api/health", tags=["System"])
async def health():
    settings = get_settings()
    return {
        "status": "ok",
        "service": "mailscope",
        "version": "4.0.0",
        "mode": settings.service_mode,
        "capabilities": {
            "virustotal": settings.enable_virustotal,
            "urlscan": settings.enable_urlscan,
            "llm_legacy": settings.enable_llm,
            "deterministic_engine": True,
        },
    }


# ─── Upload / Analyse starten ──────────────────────────────────────────────

@app.post("/api/upload", response_model=JobStatusResponse, tags=["Analysis"])
async def upload_email(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    settings = get_settings()
    logger.info("Upload started: filename=%s, content_type=%s", file.filename, file.content_type)

    if not file.filename:
        logger.warning("Upload rejected: no filename")
        raise HTTPException(400, "Kein Dateiname angegeben")

    lower = file.filename.lower()
    if not (lower.endswith(".eml") or lower.endswith(".msg")):
        logger.warning("Upload rejected: unsupported format: %s", file.filename)
        raise HTTPException(400, "Nur .eml und .msg Dateien werden unterstützt")

    raw_bytes = await file.read()
    size_kb = len(raw_bytes) / 1024
    logger.info("File received: %s (%.1f KB)", file.filename, size_kb)

    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    if len(raw_bytes) > max_bytes:
        logger.warning("Upload rejected: file too large (%.1f KB > %d MB)", size_kb, settings.max_upload_size_mb)
        raise HTTPException(400, f"Datei zu groß ({size_kb:.0f} KB). Maximum: {settings.max_upload_size_mb} MB.")

    if len(raw_bytes) == 0:
        logger.warning("Upload rejected: empty file: %s", file.filename)
        raise HTTPException(400, "Datei ist leer. Bitte laden Sie eine gültige .eml oder .msg Datei hoch.")

    # Compute expiry if retention is configured
    expires_at = None
    if settings.job_retention_hours > 0:
        expires_at = datetime.utcnow() + timedelta(hours=settings.job_retention_hours)

    job_id = str(uuid.uuid4())
    job = AnalysisJob(id=job_id, filename=file.filename, status="queued", warnings=[], expires_at=expires_at)
    db.add(job)
    db.commit()
    db.refresh(job)

    logger.info("Job created: %s for file %s (%.1f KB)", job_id, file.filename, size_kb)

    # Launch background analysis with exception logging
    task = asyncio.create_task(run_analysis(job_id, file.filename, raw_bytes))
    task.add_done_callback(lambda t: _log_task_exception(t, job_id))

    return job


# ─── Status abfragen ───────────────────────────────────────────────────────

@app.get("/api/jobs/{job_id}", response_model=JobStatusResponse, tags=["Analysis"])
async def get_job_status(job_id: str, db: Session = Depends(get_db)):
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(404, "Job nicht gefunden")
    return job


# ─── Ergebnis abrufen (Legacy / UI-orientiert) ─────────────────────────────

@app.get("/api/jobs/{job_id}/result", response_model=JobResultResponse, tags=["Analysis"])
async def get_job_result(job_id: str, db: Session = Depends(get_db)):
    """Full analysis result including raw data — used by the standalone web UI."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(404, "Job nicht gefunden")

    settings = get_settings()

    links = db.query(ExtractedLink).filter(ExtractedLink.job_id == job_id).all()
    link_responses = []
    for link in links:
        checks = db.query(ExternalCheckResult).filter(ExternalCheckResult.link_id == link.id).all()
        link_responses.append(LinkResponse(
            id=link.id,
            original_url=link.original_url,
            normalized_url=link.normalized_url,
            hostname=link.hostname,
            display_text=link.display_text,
            has_display_mismatch=link.has_display_mismatch,
            is_suspicious_tld=link.is_suspicious_tld,
            is_ip_literal=link.is_ip_literal,
            is_punycode=link.is_punycode,
            is_shortener=link.is_shortener,
            is_tracking_heavy=link.is_tracking_heavy,
            is_safelink=link.is_safelink,
            dedup_key=link.dedup_key,
            verdict=link.verdict,
            external_checks=[ExternalCheckResponse(
                service=c.service,
                status=c.status,
                scan_status=c.scan_status or "unknown",
                malicious_count=c.malicious_count,
                suspicious_count=c.suspicious_count,
                result_summary=c.result_summary or {},
                result_fetched=c.result_fetched or False,
            ) for c in checks],
        ))

    assessment = None
    llm = db.query(LlmAssessment).filter(LlmAssessment.job_id == job_id).first()
    if llm:
        assessment = LlmAssessmentResponse(
            classification=llm.classification,
            risk_score=llm.risk_score,
            confidence=llm.confidence,
            recommended_action=llm.recommended_action,
            rationale=llm.rationale,
            evidence=llm.evidence or [],
            analyst_summary=llm.analyst_summary,
            is_deterministic_fallback=llm.is_deterministic_fallback,
        )

    det_scores = None
    if job.phishing_likelihood_score is not None:
        det_scores = {
            "phishing_likelihood_score": job.phishing_likelihood_score,
            "advertising_likelihood_score": job.advertising_likelihood_score,
            "legitimacy_likelihood_score": job.legitimacy_likelihood_score,
        }

    # Build analysis_summary from stored data
    summary = _build_summary_response(job)

    return JobResultResponse(
        id=job.id,
        filename=job.filename,
        status=job.status,
        warnings=job.warnings or [],
        subject=job.subject,
        sender=SenderInfo(
            from_address=job.sender_from,
            reply_to=job.sender_reply_to,
            return_path=job.sender_return_path,
            to=job.recipient_to,
            date=job.date,
            message_id=job.message_id,
        ),
        authentication_results=job.authentication_results,
        received_chain=job.received_chain or [],
        raw_headers=job.raw_headers,
        structured_headers=job.structured_headers or {},
        attachment_metadata=job.attachment_metadata or [],
        header_findings=job.header_findings or [],
        links=link_responses,
        deterministic_scores=det_scores,
        deterministic_findings=job.deterministic_findings or [],
        assessment=assessment,
        reputation_stats=job.reputation_stats,
        analysis_summary=summary,
        enable_virustotal=settings.enable_virustotal,
        enable_urlscan=settings.enable_urlscan,
        enable_llm=settings.enable_llm,
    )


# ─── Copilot-optimiertes Ergebnis (Service-Endpoint) ───────────────────────

@app.get("/api/jobs/{job_id}/summary", response_model=ServiceResultResponse, tags=["Copilot Service"])
async def get_job_summary(job_id: str, db: Session = Depends(get_db)):
    """Copilot-optimized structured analysis summary.

    Returns only the essential analysis result — designed for consumption
    by Copilot Studio REST connector. No raw headers, no trace data.
    """
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(404, detail="Job nicht gefunden")

    if job.status not in ("completed", "completed_with_warnings"):
        raise HTTPException(
            409,
            detail=f"Analyse noch nicht abgeschlossen (Status: {job.status})",
        )

    summary = _build_summary_response(job)
    if not summary:
        raise HTTPException(500, detail="Analyseergebnis konnte nicht erstellt werden")

    return ServiceResultResponse(
        job_id=job.id,
        filename=job.filename,
        status=job.status,
        subject=job.subject,
        sender=SenderInfo(
            from_address=job.sender_from,
            reply_to=job.sender_reply_to,
            return_path=job.sender_return_path,
            to=job.recipient_to,
            date=job.date,
            message_id=job.message_id,
        ),
        analysis_summary=summary,
        warnings=job.warnings or [],
    )


# ─── Pipeline Trace (intern / analytisch) ──────────────────────────────────

@app.get("/api/jobs/{job_id}/trace", response_model=PipelineTraceResponse, tags=["Debug"])
async def get_job_trace(job_id: str, db: Session = Depends(get_db)):
    """Debug endpoint: returns the full pipeline trace for a job.

    Shows every step that was executed, with timestamps, status, and details.
    Internal/analyst use only — not intended for Copilot consumption.
    """
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(404, "Job nicht gefunden")

    return PipelineTraceResponse(
        job_id=job.id,
        status=job.status,
        summary=job.pipeline_summary or {},
        events=job.pipeline_trace or [],
        reputation_stats=job.reputation_stats or {},
    )


# ─── Export (Legacy) ────────────────────────────────────────────────────────

@app.get("/api/jobs/{job_id}/export", tags=["Analysis"])
async def export_job(job_id: str, db: Session = Depends(get_db)):
    """Export full analysis as structured JSON (legacy endpoint)."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(404, "Job nicht gefunden")

    if job.status not in ("completed", "completed_with_warnings"):
        raise HTTPException(400, "Analyse noch nicht abgeschlossen")

    links = db.query(ExtractedLink).filter(ExtractedLink.job_id == job_id).all()
    link_data = []
    for link in links:
        checks = db.query(ExternalCheckResult).filter(ExternalCheckResult.link_id == link.id).all()
        link_data.append({
            "original_url": link.original_url,
            "normalized_url": link.normalized_url,
            "hostname": link.hostname,
            "display_text": link.display_text,
            "dedup_key": link.dedup_key,
            "verdict": link.verdict,
            "flags": {
                "display_mismatch": link.has_display_mismatch,
                "suspicious_tld": link.is_suspicious_tld,
                "ip_literal": link.is_ip_literal,
                "punycode": link.is_punycode,
                "shortener": link.is_shortener,
                "tracking_heavy": link.is_tracking_heavy,
                "safelink": link.is_safelink,
            },
            "external_checks": [{
                "service": c.service,
                "status": c.status,
                "scan_status": c.scan_status,
                "malicious_count": c.malicious_count,
                "suspicious_count": c.suspicious_count,
                "result_summary": c.result_summary,
                "result_fetched": c.result_fetched,
            } for c in checks],
        })

    llm = db.query(LlmAssessment).filter(LlmAssessment.job_id == job_id).first()
    assessment = None
    if llm:
        assessment = {
            "classification": llm.classification,
            "risk_score": llm.risk_score,
            "confidence": llm.confidence,
            "recommended_action": llm.recommended_action,
            "rationale": llm.rationale,
            "evidence": llm.evidence,
            "analyst_summary": llm.analyst_summary,
            "is_deterministic_fallback": llm.is_deterministic_fallback,
        }

    return {
        "job_id": job.id,
        "filename": job.filename,
        "status": job.status,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "sender": {
            "from": job.sender_from,
            "reply_to": job.sender_reply_to,
            "return_path": job.sender_return_path,
            "to": job.recipient_to,
            "date": job.date,
            "message_id": job.message_id,
        },
        "subject": job.subject,
        "authentication_results": job.authentication_results,
        "received_chain": job.received_chain,
        "attachment_metadata": job.attachment_metadata,
        "header_findings": job.header_findings,
        "deterministic_scores": {
            "phishing_likelihood_score": job.phishing_likelihood_score,
            "advertising_likelihood_score": job.advertising_likelihood_score,
            "legitimacy_likelihood_score": job.legitimacy_likelihood_score,
        },
        "deterministic_findings": job.deterministic_findings,
        "links": link_data,
        "assessment": assessment,
        "analysis_summary": job.analysis_summary,
        "reputation_stats": job.reputation_stats,
        "warnings": job.warnings,
        "pipeline_summary": job.pipeline_summary,
    }


# ─── Helpers ────────────────────────────────────────────────────────────────

def _build_summary_response(job: AnalysisJob) -> AnalysisSummaryResponse | None:
    """Build AnalysisSummaryResponse from stored analysis_summary JSON."""
    summary_data = job.analysis_summary
    if not summary_data or not isinstance(summary_data, dict) or "version" not in summary_data:
        return None

    try:
        action = summary_data.get("action_decision", {})
        identity = summary_data.get("identity_summary", {})
        reputation = summary_data.get("reputation_summary", {})
        factors = summary_data.get("decision_factors", {})

        signals = []
        for s in summary_data.get("signals", []):
            signals.append(NormalizedSignalResponse(
                key=s.get("key", ""),
                canonical_key=s.get("canonical_key", ""),
                label=s.get("label", ""),
                severity=s.get("severity", "context"),
                tier=s.get("tier", 1),
                direction=s.get("direction", "positive"),
                domain=s.get("domain", ""),
                category=s.get("category", ""),
            ))

        return AnalysisSummaryResponse(
            version=summary_data.get("version", 2),
            action_decision=ActionDecisionResponse(
                action=action.get("action", "manual_review"),
                label=action.get("label", ""),
                reason=action.get("reason", ""),
                primary_driver=action.get("primary_driver"),
            ),
            action_label=summary_data.get("action_label", action.get("label", "")),
            action_reason=summary_data.get("action_reason", action.get("reason", "")),
            classification=summary_data.get("classification", "unknown"),
            risk_score=summary_data.get("risk_score", 0),
            confidence=summary_data.get("confidence", 0),
            content_risk_level=summary_data.get("content_risk_level", "none"),
            decision_factors=DecisionFactorsResponse(
                negative=factors.get("negative", []),
                positive=factors.get("positive", []),
            ),
            identity_summary=IdentitySummaryResponse(**identity) if identity else IdentitySummaryResponse(
                consistency="partial_mismatch", consistency_detail="Nicht verfügbar", is_bulk_sender=False
            ),
            reputation_summary=ReputationSummaryResponse(**reputation) if reputation else ReputationSummaryResponse(),
            signals=signals,
            escalation_hint=summary_data.get("escalation_hint"),
            override_applied=summary_data.get("override_applied", False),
        )
    except Exception as e:
        logger.error("Failed to build summary response for job %s: %s", job.id, e)
        return None
