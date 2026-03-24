"""Orchestrates the full email analysis pipeline as a background task."""

import asyncio
import logging
import uuid as uuid_mod

from sqlalchemy.orm import Session

from ..config import get_settings
from ..database import SessionLocal
from ..models import AnalysisJob, ExtractedLink, ExternalCheckResult, LlmAssessment
from .parser import parse_email_file
from .link_extractor import extract_and_normalize
from .link_analyzer import analyze_link
from .header_analyzer import analyze_headers
from .pre_scorer import compute_pre_scores, deterministic_assessment
from . import virustotal, urlscan, llm_client

logger = logging.getLogger(__name__)


def _update_status(db: Session, job: AnalysisJob, status: str):
    job.status = status
    db.commit()


def _add_warning(db: Session, job: AnalysisJob, warning: str):
    warnings = list(job.warnings or [])
    warnings.append(warning)
    job.warnings = warnings
    db.commit()


async def run_analysis(job_id: str, filename: str, raw_bytes: bytes):
    """Main analysis pipeline. Runs as a background task."""
    db = SessionLocal()
    settings = get_settings()

    try:
        job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            logger.error("Job %s not found", job_id)
            return

        # --- Stage 1: Parse ---
        _update_status(db, job, "parsing")
        try:
            parsed = parse_email_file(filename, raw_bytes)
        except Exception as e:
            logger.error("Parse failed: %s", e)
            job.status = "failed"
            job.error_message = f"Parsing fehlgeschlagen: {e}"
            db.commit()
            return

        job.subject = parsed.get("subject")
        job.sender_from = parsed.get("from")
        job.sender_reply_to = parsed.get("reply_to")
        job.sender_return_path = parsed.get("return_path")
        job.recipient_to = parsed.get("to")
        job.date = parsed.get("date")
        job.message_id = parsed.get("message_id")
        job.authentication_results = parsed.get("authentication_results")
        job.received_chain = parsed.get("received_chain", [])
        job.raw_headers = parsed.get("raw_headers")
        job.structured_headers = parsed.get("structured_headers", {})
        # Don't store full bodies at high detail — truncate for DB
        job.body_text = (parsed.get("body_text") or "")[:10000]
        job.body_html = (parsed.get("body_html") or "")[:10000]
        job.attachment_metadata = parsed.get("attachment_metadata", [])
        db.commit()

        # --- Stage 1b: Header analysis ---
        header_findings = analyze_headers(parsed)
        job.header_findings = header_findings
        db.commit()

        # --- Stage 2: Link extraction ---
        _update_status(db, job, "extracting_links")
        url_tuples = extract_and_normalize(
            parsed.get("body_text", ""),
            parsed.get("body_html", ""),
        )

        link_dicts = []
        for original, normalized, display_text, is_safelink in url_tuples:
            flags = analyze_link(original, normalized, display_text)
            link = ExtractedLink(
                job_id=job_id,
                original_url=original,
                normalized_url=normalized,
                hostname=flags["hostname"],
                display_text=display_text,
                has_display_mismatch=flags["has_display_mismatch"],
                is_suspicious_tld=flags["is_suspicious_tld"],
                is_ip_literal=flags["is_ip_literal"],
                is_punycode=flags["is_punycode"],
                is_shortener=flags["is_shortener"],
                is_tracking_heavy=flags["is_tracking_heavy"],
                is_safelink=is_safelink,
            )
            db.add(link)
            link_dicts.append({**flags, "original_url": original, "normalized_url": normalized})
        db.commit()

        # --- Stage 3: External reputation checks ---
        _update_status(db, job, "checking_reputation")
        db_links = db.query(ExtractedLink).filter(ExtractedLink.job_id == job_id).all()
        external_results_all = []

        for db_link in db_links:
            url_to_check = db_link.normalized_url

            # VirusTotal
            if settings.enable_virustotal and settings.virustotal_api_key:
                try:
                    vt_result = await virustotal.check_url(url_to_check)
                    ext = ExternalCheckResult(
                        link_id=db_link.id,
                        service="virustotal",
                        submission_id=vt_result.get("submission_id", ""),
                        status=vt_result.get("status", "failed"),
                        result_summary=vt_result.get("result_summary", {}),
                        malicious_count=vt_result.get("malicious_count", 0),
                        suspicious_count=vt_result.get("suspicious_count", 0),
                    )
                    db.add(ext)
                    external_results_all.append(vt_result)
                except Exception as e:
                    logger.error("VT check failed for link %s: %s", db_link.id, e)
                    _add_warning(db, job, f"VirusTotal-Prüfung fehlgeschlagen für {url_to_check[:60]}")
                    ext = ExternalCheckResult(
                        link_id=db_link.id, service="virustotal", status="failed",
                        result_summary={"error": str(e)},
                    )
                    db.add(ext)
            elif settings.enable_virustotal:
                _add_warning(db, job, "VirusTotal aktiviert, aber kein API-Key konfiguriert")

            # urlscan
            if settings.enable_urlscan and settings.urlscan_api_key:
                try:
                    us_result = await urlscan.check_url(url_to_check)
                    ext = ExternalCheckResult(
                        link_id=db_link.id,
                        service="urlscan",
                        submission_id=us_result.get("submission_id", ""),
                        status=us_result.get("status", "failed"),
                        result_summary=us_result.get("result_summary", {}),
                        malicious_count=us_result.get("malicious_count", 0),
                        suspicious_count=us_result.get("suspicious_count", 0),
                    )
                    db.add(ext)
                    external_results_all.append(us_result)
                except Exception as e:
                    logger.error("urlscan check failed for link %s: %s", db_link.id, e)
                    _add_warning(db, job, f"urlscan-Prüfung fehlgeschlagen für {url_to_check[:60]}")
                    ext = ExternalCheckResult(
                        link_id=db_link.id, service="urlscan", status="failed",
                        result_summary={"error": str(e)},
                    )
                    db.add(ext)
            elif settings.enable_urlscan:
                _add_warning(db, job, "urlscan aktiviert, aber kein API-Key konfiguriert")

            db.commit()

        # --- Stage 4: Deterministic pre-scoring ---
        scores = compute_pre_scores(header_findings, link_dicts, external_results_all)
        job.phishing_likelihood_score = scores["phishing_likelihood_score"]
        job.advertising_likelihood_score = scores["advertising_likelihood_score"]
        job.legitimacy_likelihood_score = scores["legitimacy_likelihood_score"]
        job.deterministic_findings = scores["findings"]
        db.commit()

        # --- Stage 5: LLM Assessment ---
        _update_status(db, job, "llm_assessment")

        assessment_data = None
        is_fallback = False

        if settings.enable_llm and settings.openai_api_key:
            try:
                assessment_data = await llm_client.get_assessment(
                    parsed, header_findings, link_dicts, external_results_all, scores,
                )
            except Exception as e:
                logger.error("LLM assessment failed: %s", e)
                _add_warning(db, job, f"LLM-Bewertung fehlgeschlagen: {e}")

        if not assessment_data:
            if settings.enable_llm and settings.openai_api_key:
                _add_warning(db, job, "LLM-Bewertung fehlgeschlagen, verwende deterministische Bewertung")
            elif settings.enable_llm:
                _add_warning(db, job, "LLM aktiviert, aber kein API-Key konfiguriert")
            assessment_data = deterministic_assessment(scores, scores.get("findings", []))
            is_fallback = True

        llm_record = LlmAssessment(
            job_id=job_id,
            classification=assessment_data["classification"],
            risk_score=assessment_data["risk_score"],
            confidence=assessment_data["confidence"],
            recommended_action=assessment_data["recommended_action"],
            rationale=assessment_data.get("rationale", ""),
            evidence=assessment_data.get("evidence", []),
            analyst_summary=assessment_data.get("analyst_summary", ""),
            is_deterministic_fallback=is_fallback,
        )
        db.add(llm_record)

        # --- Done ---
        has_warnings = bool(job.warnings)
        job.status = "completed_with_warnings" if has_warnings else "completed"
        db.commit()

    except Exception as e:
        logger.exception("Analysis pipeline failed for job %s", job_id)
        try:
            job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
            if job:
                job.status = "failed"
                job.error_message = str(e)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()
