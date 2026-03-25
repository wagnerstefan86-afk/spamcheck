"""Orchestrates the full email analysis pipeline as a background task.

Includes structured event tracing, provider-level dedup, and proper
aggregation that distinguishes clean results from missing results.
"""

import asyncio
import logging
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from ..config import get_settings
from ..database import SessionLocal
from ..models import AnalysisJob, ExtractedLink, ExternalCheckResult, LlmAssessment
from .parser import parse_email_file
from .link_extractor import extract_and_normalize
from .link_analyzer import analyze_link
from .header_analyzer import analyze_headers
from .pre_scorer import compute_pre_scores, deterministic_assessment
from .scan_status import ScanStatus, JobTrace, LinkVerdict, compute_link_verdict
from . import virustotal, urlscan, llm_client

logger = logging.getLogger(__name__)

# Max unique URLs to send to external providers per job
MAX_REPUTATION_URLS = 50


def _update_status(db: Session, job: AnalysisJob, status: str):
    job.status = status
    db.commit()


def _add_warning(db: Session, job: AnalysisJob, warning: str):
    warnings = list(job.warnings or [])
    warnings.append(warning)
    job.warnings = warnings
    db.commit()


def _compute_dedup_key(normalized_url: str) -> str:
    """Compute a dedup key for provider-level deduplication.

    Strips scheme, trailing slashes, common tracking fragments.
    URLs that differ only in http/https or trailing slash share a key.
    """
    try:
        parsed = urlparse(normalized_url.lower().rstrip("/"))
        # Use netloc + path + sorted query as dedup key
        return f"{parsed.netloc}{parsed.path}{'?' + parsed.query if parsed.query else ''}"
    except Exception:
        return normalized_url.lower().rstrip("/")


async def _check_url_with_providers(
    url: str,
    settings,
    trace: JobTrace,
) -> list[dict]:
    """Run all enabled providers for a single URL. Returns list of result dicts."""
    results = []

    # VirusTotal
    if settings.enable_virustotal:
        if settings.virustotal_api_key:
            try:
                vt_result = await virustotal.check_url(url, trace)
                results.append(vt_result)
            except Exception as e:
                trace.emit("reputation", "provider_exception", provider="virustotal",
                           url=url, status=ScanStatus.API_ERROR.value,
                           detail=f"Unhandled: {e}")
                results.append({
                    "service": "virustotal",
                    "scan_status": ScanStatus.API_ERROR.value,
                    "status": "failed",
                    "malicious_count": 0,
                    "suspicious_count": 0,
                    "result_summary": {"error": str(e)[:200]},
                    "result_fetched": False,
                })
        else:
            trace.emit("reputation", "not_executed", provider="virustotal",
                        url=url, status=ScanStatus.NOT_EXECUTED.value,
                        detail="API key not configured")
            results.append({
                "service": "virustotal",
                "scan_status": ScanStatus.NOT_EXECUTED.value,
                "status": "not_executed",
                "malicious_count": 0,
                "suspicious_count": 0,
                "result_summary": {},
                "result_fetched": False,
            })

    # urlscan
    if settings.enable_urlscan:
        if settings.urlscan_api_key:
            try:
                us_result = await urlscan.check_url(url, trace)
                results.append(us_result)
            except Exception as e:
                trace.emit("reputation", "provider_exception", provider="urlscan",
                           url=url, status=ScanStatus.API_ERROR.value,
                           detail=f"Unhandled: {e}")
                results.append({
                    "service": "urlscan",
                    "scan_status": ScanStatus.API_ERROR.value,
                    "status": "failed",
                    "malicious_count": 0,
                    "suspicious_count": 0,
                    "result_summary": {"error": str(e)[:200]},
                    "result_fetched": False,
                })
        else:
            trace.emit("reputation", "not_executed", provider="urlscan",
                        url=url, status=ScanStatus.NOT_EXECUTED.value,
                        detail="API key not configured")
            results.append({
                "service": "urlscan",
                "scan_status": ScanStatus.NOT_EXECUTED.value,
                "status": "not_executed",
                "malicious_count": 0,
                "suspicious_count": 0,
                "result_summary": {},
                "result_fetched": False,
            })

    return results


async def run_analysis(job_id: str, filename: str, raw_bytes: bytes):
    """Main analysis pipeline. Runs as a background task."""
    db = SessionLocal()
    settings = get_settings()
    trace = JobTrace(job_id)

    try:
        job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            logger.error("Job %s not found", job_id)
            return

        trace.emit("pipeline", "analysis_started", detail=f"file={filename}")

        # --- Stage 1: Parse ---
        _update_status(db, job, "parsing")
        trace.emit("pipeline", "stage_started", detail="parsing")
        try:
            parsed = parse_email_file(filename, raw_bytes)
            trace.emit("pipeline", "file_parsed", detail=f"subject={parsed.get('subject', '')[:60]}")
        except Exception as e:
            trace.emit("pipeline", "parse_failed", detail=str(e)[:200])
            logger.error("Parse failed: %s", e)
            job.status = "failed"
            job.error_message = f"Parsing fehlgeschlagen: {e}"
            job.pipeline_trace = trace.to_list()
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
        job.body_text = (parsed.get("body_text") or "")[:10000]
        job.body_html = (parsed.get("body_html") or "")[:10000]
        job.attachment_metadata = parsed.get("attachment_metadata", [])
        db.commit()

        # --- Stage 1b: Header analysis ---
        header_findings = analyze_headers(parsed)
        job.header_findings = header_findings
        db.commit()
        trace.emit("pipeline", "headers_analyzed", detail=f"{len(header_findings)} findings")

        # --- Stage 2: Link extraction ---
        _update_status(db, job, "extracting_links")
        trace.emit("pipeline", "stage_started", detail="link_extraction")

        url_tuples = extract_and_normalize(
            parsed.get("body_text", ""),
            parsed.get("body_html", ""),
        )

        trace.emit("pipeline", "links_extracted",
                    detail=f"{len(url_tuples)} unique links after normalization/dedup")

        link_dicts = []
        for original, normalized, display_text, is_safelink in url_tuples:
            flags = analyze_link(original, normalized, display_text)
            dedup_key = _compute_dedup_key(normalized)
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
                dedup_key=dedup_key,
            )
            db.add(link)
            link_dicts.append({**flags, "original_url": original, "normalized_url": normalized})
        db.commit()

        # --- Stage 3: External reputation checks ---
        _update_status(db, job, "checking_reputation")
        trace.emit("pipeline", "stage_started", detail="reputation_checks")

        db_links = db.query(ExtractedLink).filter(ExtractedLink.job_id == job_id).all()
        external_results_all = []

        # Provider-level dedup: group links by dedup_key, only scan each unique URL once
        dedup_map: dict[str, list[ExtractedLink]] = {}
        for db_link in db_links:
            key = db_link.dedup_key or _compute_dedup_key(db_link.normalized_url)
            dedup_map.setdefault(key, []).append(db_link)

        unique_urls = list(dedup_map.keys())
        skipped_count = 0

        if len(unique_urls) > MAX_REPUTATION_URLS:
            trace.emit("reputation", "url_limit_applied",
                        detail=f"Limiting from {len(unique_urls)} to {MAX_REPUTATION_URLS} unique URLs")
            _add_warning(db, job,
                         f"Zu viele Links ({len(unique_urls)}), nur {MAX_REPUTATION_URLS} werden geprüft")
            skipped_keys = unique_urls[MAX_REPUTATION_URLS:]
            unique_urls = unique_urls[:MAX_REPUTATION_URLS]
            skipped_count = len(skipped_keys)

            # Mark skipped links
            for key in skipped_keys:
                for db_link in dedup_map[key]:
                    for svc in ["virustotal", "urlscan"]:
                        if (svc == "virustotal" and settings.enable_virustotal) or \
                           (svc == "urlscan" and settings.enable_urlscan):
                            ext = ExternalCheckResult(
                                link_id=db_link.id,
                                service=svc,
                                status="skipped",
                                scan_status=ScanStatus.SKIPPED.value,
                                result_fetched=False,
                            )
                            db.add(ext)
                    db_link.verdict = LinkVerdict.NOT_CHECKED.value
            db.commit()

        trace.emit("reputation", "dedup_summary",
                    detail=f"{len(db_links)} total links -> {len(unique_urls)} unique URLs to check, {skipped_count} skipped")

        # Process each unique URL
        for idx, dedup_key in enumerate(unique_urls):
            link_group = dedup_map[dedup_key]
            representative_link = link_group[0]
            url_to_check = representative_link.normalized_url

            trace.emit("reputation", "checking_url",
                        url=url_to_check,
                        detail=f"URL {idx+1}/{len(unique_urls)}, covers {len(link_group)} link(s)")

            # Run providers
            provider_results = await _check_url_with_providers(url_to_check, settings, trace)

            # Store results for ALL links sharing this dedup_key
            provider_statuses = []
            for pr in provider_results:
                scan_status_str = pr.get("scan_status", ScanStatus.API_ERROR.value)
                try:
                    scan_status = ScanStatus(scan_status_str)
                except ValueError:
                    scan_status = ScanStatus.API_ERROR
                provider_statuses.append(scan_status)

                for db_link in link_group:
                    ext = ExternalCheckResult(
                        link_id=db_link.id,
                        service=pr["service"],
                        submission_id=pr.get("submission_id", ""),
                        status=pr.get("status", "failed"),
                        scan_status=scan_status_str,
                        result_summary=pr.get("result_summary", {}),
                        malicious_count=pr.get("malicious_count", 0),
                        suspicious_count=pr.get("suspicious_count", 0),
                        result_fetched=pr.get("result_fetched", False),
                    )
                    db.add(ext)

                external_results_all.append(pr)

            # Compute and store link verdict
            verdict = compute_link_verdict(provider_statuses)
            for db_link in link_group:
                db_link.verdict = verdict.value

            db.commit()

        # Compute reputation stats for the job
        rep_stats = _compute_reputation_stats(db, job_id)
        job.reputation_stats = rep_stats
        db.commit()

        trace.emit("reputation", "phase_completed", data=rep_stats,
                    detail=f"clean={rep_stats.get('clean', 0)}, malicious={rep_stats.get('malicious', 0)}, "
                           f"unknown={rep_stats.get('unknown', 0)}, failed={rep_stats.get('total_failures', 0)}")

        # --- Stage 4: Deterministic pre-scoring ---
        scores = compute_pre_scores(header_findings, link_dicts, external_results_all)
        job.phishing_likelihood_score = scores["phishing_likelihood_score"]
        job.advertising_likelihood_score = scores["advertising_likelihood_score"]
        job.legitimacy_likelihood_score = scores["legitimacy_likelihood_score"]
        job.deterministic_findings = scores["findings"]
        db.commit()
        trace.emit("pipeline", "prescoring_done",
                    detail=f"phishing={scores['phishing_likelihood_score']}, "
                           f"advertising={scores['advertising_likelihood_score']}")

        # --- Stage 5: LLM Assessment ---
        _update_status(db, job, "llm_assessment")
        trace.emit("pipeline", "stage_started", detail="llm_assessment")

        assessment_data = None
        is_fallback = False

        if settings.enable_llm and settings.openai_api_key:
            try:
                assessment_data = await llm_client.get_assessment(
                    parsed, header_findings, link_dicts, external_results_all, scores,
                )
                trace.emit("pipeline", "llm_completed",
                            detail=f"classification={assessment_data.get('classification', '?')}")
            except Exception as e:
                logger.error("LLM assessment failed: %s", e)
                trace.emit("pipeline", "llm_failed", detail=str(e)[:200])
                _add_warning(db, job, f"LLM-Bewertung fehlgeschlagen: {e}")

        if not assessment_data:
            if settings.enable_llm and settings.openai_api_key:
                _add_warning(db, job, "LLM-Bewertung fehlgeschlagen, verwende deterministische Bewertung")
            elif settings.enable_llm:
                _add_warning(db, job, "LLM aktiviert, aber kein API-Key konfiguriert")
                trace.emit("pipeline", "llm_not_executed", detail="No API key")
            assessment_data = deterministic_assessment(scores, scores.get("findings", []))
            is_fallback = True
            trace.emit("pipeline", "deterministic_fallback",
                        detail=f"classification={assessment_data['classification']}")

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
        trace.emit("pipeline", "analysis_completed", detail=job.status)

        # Persist trace
        job.pipeline_trace = trace.to_list()
        job.pipeline_summary = trace.summary()
        db.commit()

    except Exception as e:
        logger.exception("Analysis pipeline failed for job %s", job_id)
        trace.emit("pipeline", "pipeline_exception", detail=str(e)[:300])
        try:
            # Rollback any dirty session state before attempting error recovery
            db.rollback()
            job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
            if job:
                job.status = "failed"
                job.error_message = str(e)[:500]
                job.pipeline_trace = trace.to_list()
                job.pipeline_summary = trace.summary()
                db.commit()
        except Exception as recovery_err:
            logger.error("Error recovery failed for job %s: %s", job_id, recovery_err)
            # Last resort: try a fresh session to set failed status
            try:
                db.rollback()
                db2 = SessionLocal()
                try:
                    j = db2.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
                    if j:
                        j.status = "failed"
                        j.error_message = f"Pipeline failed: {str(e)[:200]} (recovery also failed: {str(recovery_err)[:100]})"
                        db2.commit()
                finally:
                    db2.close()
            except Exception:
                logger.critical("Could not set failed status for job %s", job_id)
    finally:
        db.close()


def _compute_reputation_stats(db: Session, job_id: str) -> dict:
    """Compute aggregate reputation stats for a job."""
    links = db.query(ExtractedLink).filter(ExtractedLink.job_id == job_id).all()

    stats = {
        "total_links": len(links),
        "unique_checked": 0,
        "verdicts": {},
        "provider_breakdown": {},
        "total_result_fetched": 0,
        "total_failures": 0,
        "clean": 0,
        "suspicious": 0,
        "malicious": 0,
        "unknown": 0,
        "not_checked": 0,
    }

    # Count verdicts
    for link in links:
        v = link.verdict or "unknown"
        stats["verdicts"][v] = stats["verdicts"].get(v, 0) + 1
        if v in ("clean", "suspicious", "malicious", "unknown", "not_checked"):
            stats[v] = stats.get(v, 0) + 1

    # Provider breakdown
    checks = (
        db.query(ExternalCheckResult)
        .join(ExtractedLink)
        .filter(ExtractedLink.job_id == job_id)
        .all()
    )

    for check in checks:
        svc = check.service
        if svc not in stats["provider_breakdown"]:
            stats["provider_breakdown"][svc] = {
                "total": 0,
                "result_fetched": 0,
                "completed_clean": 0,
                "completed_suspicious": 0,
                "completed_malicious": 0,
                "timeout": 0,
                "rate_limited": 0,
                "api_error": 0,
                "submit_failed": 0,
                "not_executed": 0,
                "skipped": 0,
            }
        bd = stats["provider_breakdown"][svc]
        bd["total"] += 1
        scan_st = check.scan_status or "unknown"
        if scan_st in bd:
            bd[scan_st] += 1
        if check.result_fetched:
            bd["result_fetched"] += 1
            stats["total_result_fetched"] += 1

    # Count total failures
    for svc_stats in stats["provider_breakdown"].values():
        stats["total_failures"] += (
            svc_stats.get("timeout", 0) +
            svc_stats.get("rate_limited", 0) +
            svc_stats.get("api_error", 0) +
            svc_stats.get("submit_failed", 0)
        )

    # Unique checked = links with at least one non-skipped/non-not_executed check
    seen_dedup = set()
    for link in links:
        key = link.dedup_key or link.normalized_url.lower()
        if key not in seen_dedup:
            has_real_check = any(
                c.scan_status not in (ScanStatus.SKIPPED.value, ScanStatus.NOT_EXECUTED.value, None)
                for c in link.external_checks
            )
            if has_real_check:
                stats["unique_checked"] += 1
            seen_dedup.add(key)

    return stats
