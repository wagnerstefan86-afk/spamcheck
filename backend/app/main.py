import asyncio
import uuid
import logging

from fastapi import FastAPI, UploadFile, File, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .config import get_settings, Settings
from .database import get_db, init_db
from .models import AnalysisJob, ExtractedLink, ExternalCheckResult, LlmAssessment
from .schemas import JobStatusResponse, JobResultResponse, LinkResponse, LlmAssessmentResponse, SenderInfo, ExternalCheckResponse
from .services.analysis_runner import run_analysis

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="MailScope Email Security Analysis",
    version="2.0.0",
    description="Analysiert E-Mail-Dateien auf Phishing, Spoofing und andere Sicherheitsrisiken.",
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


@app.get("/api/health")
async def health():
    settings = get_settings()
    return {
        "status": "ok",
        "service": "mailscope",
        "enable_virustotal": settings.enable_virustotal,
        "enable_urlscan": settings.enable_urlscan,
        "enable_llm": settings.enable_llm,
    }


@app.post("/api/upload", response_model=JobStatusResponse)
async def upload_email(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    settings = get_settings()

    if not file.filename:
        raise HTTPException(400, "Kein Dateiname angegeben")

    lower = file.filename.lower()
    if not (lower.endswith(".eml") or lower.endswith(".msg")):
        raise HTTPException(400, "Nur .eml und .msg Dateien werden unterstützt")

    raw_bytes = await file.read()
    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    if len(raw_bytes) > max_bytes:
        raise HTTPException(400, f"Datei zu groß (max {settings.max_upload_size_mb} MB)")

    job_id = str(uuid.uuid4())
    job = AnalysisJob(id=job_id, filename=file.filename, status="queued", warnings=[])
    db.add(job)
    db.commit()
    db.refresh(job)

    # Launch background analysis
    asyncio.create_task(run_analysis(job_id, file.filename, raw_bytes))

    return job


@app.get("/api/jobs/{job_id}", response_model=JobStatusResponse)
async def get_job_status(job_id: str, db: Session = Depends(get_db)):
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(404, "Job nicht gefunden")
    return job


@app.get("/api/jobs/{job_id}/result", response_model=JobResultResponse)
async def get_job_result(job_id: str, db: Session = Depends(get_db)):
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
            external_checks=[ExternalCheckResponse(
                service=c.service,
                status=c.status,
                malicious_count=c.malicious_count,
                suspicious_count=c.suspicious_count,
                result_summary=c.result_summary or {},
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
        enable_virustotal=settings.enable_virustotal,
        enable_urlscan=settings.enable_urlscan,
        enable_llm=settings.enable_llm,
    )


@app.get("/api/jobs/{job_id}/export")
async def export_job(job_id: str, db: Session = Depends(get_db)):
    """Export full analysis as structured JSON."""
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
                "malicious_count": c.malicious_count,
                "suspicious_count": c.suspicious_count,
                "result_summary": c.result_summary,
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
        "warnings": job.warnings,
    }
