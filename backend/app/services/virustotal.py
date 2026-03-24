"""VirusTotal URL API client with structured status tracking."""

import asyncio
import logging
import httpx

from ..config import get_settings
from .scan_status import ScanStatus, JobTrace

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"


async def submit_url(url: str, headers: dict, trace: JobTrace | None = None) -> tuple[str, ScanStatus]:
    """Submit a URL for scanning. Returns (analysis_id, status)."""
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            if trace:
                trace.emit("reputation", "request_sent", provider="virustotal", url=url)

            resp = await client.post(
                f"{VT_BASE}/urls",
                headers=headers,
                data={"url": url},
            )

            if resp.status_code == 429:
                if trace:
                    trace.emit("reputation", "rate_limited", provider="virustotal", url=url,
                               status=ScanStatus.RATE_LIMITED, detail=f"HTTP 429")
                return "", ScanStatus.RATE_LIMITED

            if resp.status_code >= 400:
                if trace:
                    trace.emit("reputation", "api_error", provider="virustotal", url=url,
                               status=ScanStatus.API_ERROR,
                               detail=f"HTTP {resp.status_code}: {resp.text[:200]}")
                return "", ScanStatus.API_ERROR

            data = resp.json()
            analysis_id = data.get("data", {}).get("id", "")

            if not analysis_id:
                if trace:
                    trace.emit("reputation", "invalid_response", provider="virustotal", url=url,
                               status=ScanStatus.INVALID_RESPONSE, detail="No analysis_id in response")
                return "", ScanStatus.INVALID_RESPONSE

            if trace:
                trace.emit("reputation", "response_received", provider="virustotal", url=url,
                           status=ScanStatus.RESPONSE_RECEIVED,
                           detail=f"analysis_id={analysis_id[:40]}")

            return analysis_id, ScanStatus.RESPONSE_RECEIVED

        except httpx.TimeoutException:
            if trace:
                trace.emit("reputation", "timeout", provider="virustotal", url=url,
                           status=ScanStatus.TIMEOUT, detail="Submit request timed out")
            return "", ScanStatus.TIMEOUT
        except Exception as e:
            if trace:
                trace.emit("reputation", "api_error", provider="virustotal", url=url,
                           status=ScanStatus.API_ERROR, detail=str(e)[:200])
            logger.error("VT submit failed for %s: %s", url[:80], e)
            return "", ScanStatus.API_ERROR


async def poll_analysis(analysis_id: str, headers: dict, url: str,
                        trace: JobTrace | None = None) -> tuple[dict | None, ScanStatus]:
    """Poll for analysis results. Returns (result_data, status)."""
    settings = get_settings()
    interval = settings.poll_interval_seconds
    max_wait = settings.max_poll_seconds
    elapsed = 0

    if trace:
        trace.emit("reputation", "polling_started", provider="virustotal", url=url,
                    detail=f"max_wait={max_wait}s, interval={interval}s")

    while elapsed < max_wait:
        await asyncio.sleep(interval)
        elapsed += interval

        async with httpx.AsyncClient(timeout=30) as client:
            try:
                resp = await client.get(
                    f"{VT_BASE}/analyses/{analysis_id}",
                    headers=headers,
                )

                if resp.status_code == 429:
                    if trace:
                        trace.emit("reputation", "rate_limited_during_poll", provider="virustotal",
                                   url=url, status=ScanStatus.RATE_LIMITED,
                                   detail=f"HTTP 429 at {elapsed}s")
                    # Continue polling - might succeed on next attempt
                    continue

                if resp.status_code >= 400:
                    logger.warning("VT poll HTTP %d for %s", resp.status_code, analysis_id[:40])
                    continue

                data = resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                status = attrs.get("status", "queued")

                if status == "completed":
                    stats = attrs.get("stats", {})
                    result = {
                        "status": "completed",
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                    }

                    if trace:
                        trace.emit("reputation", "result_fetched", provider="virustotal", url=url,
                                   status=ScanStatus.RESULT_FETCHED,
                                   detail=f"malicious={result['malicious']}, suspicious={result['suspicious']}, harmless={result['harmless']}",
                                   data=result)

                    return result, ScanStatus.RESULT_FETCHED

            except httpx.TimeoutException:
                logger.warning("VT poll timeout at %ds for %s", elapsed, analysis_id[:40])
                continue
            except Exception as e:
                logger.warning("VT poll error at %ds: %s", elapsed, e)
                continue

    if trace:
        trace.emit("reputation", "polling_timeout", provider="virustotal", url=url,
                    status=ScanStatus.TIMEOUT,
                    detail=f"No completed result after {max_wait}s")

    return None, ScanStatus.TIMEOUT


async def check_url(url: str, trace: JobTrace | None = None) -> dict:
    """Submit URL and poll for results with full status tracking.

    Returns a dict with:
      - service, submission_id, scan_status (ScanStatus value)
      - malicious_count, suspicious_count
      - result_summary
      - result_fetched (bool): whether the result was actually downloaded
    """
    settings = get_settings()

    result = {
        "service": "virustotal",
        "submission_id": "",
        "scan_status": ScanStatus.NOT_EXECUTED.value,
        "status": "failed",  # legacy compat
        "malicious_count": 0,
        "suspicious_count": 0,
        "result_summary": {},
        "result_fetched": False,
    }

    if not settings.virustotal_api_key:
        if trace:
            trace.emit("reputation", "not_executed", provider="virustotal", url=url,
                        status=ScanStatus.NOT_EXECUTED, detail="No API key configured")
        result["scan_status"] = ScanStatus.NOT_EXECUTED.value
        return result

    headers = {"x-apikey": settings.virustotal_api_key}

    # Step 1: Submit
    analysis_id, submit_status = await submit_url(url, headers, trace)

    if submit_status != ScanStatus.RESPONSE_RECEIVED:
        result["scan_status"] = submit_status.value
        result["status"] = submit_status.value
        return result

    result["submission_id"] = analysis_id

    # Step 2: Poll for results
    poll_result, poll_status = await poll_analysis(analysis_id, headers, url, trace)

    if poll_result and poll_status == ScanStatus.RESULT_FETCHED:
        malicious = poll_result.get("malicious", 0)
        suspicious = poll_result.get("suspicious", 0)

        # Determine terminal status
        if malicious > 0:
            final_status = ScanStatus.COMPLETED_MALICIOUS
        elif suspicious > 0:
            final_status = ScanStatus.COMPLETED_SUSPICIOUS
        else:
            final_status = ScanStatus.COMPLETED_CLEAN

        result["scan_status"] = final_status.value
        result["status"] = "completed"  # legacy compat
        result["malicious_count"] = malicious
        result["suspicious_count"] = suspicious
        result["result_summary"] = poll_result
        result["result_fetched"] = True

        if trace:
            trace.emit("reputation", "verdict", provider="virustotal", url=url,
                        status=final_status.value,
                        detail=f"Final: {final_status.value} (malicious={malicious}, suspicious={suspicious})")
    else:
        result["scan_status"] = poll_status.value
        result["status"] = poll_status.value

        if trace:
            trace.emit("reputation", "scan_incomplete", provider="virustotal", url=url,
                        status=poll_status.value,
                        detail=f"No result fetched, final status: {poll_status.value}")

    return result
