"""urlscan.io API client with structured status tracking."""

import asyncio
import logging
import httpx

from ..config import get_settings
from .scan_status import ScanStatus, JobTrace

logger = logging.getLogger(__name__)

URLSCAN_BASE = "https://urlscan.io/api/v1"


async def submit_scan(url: str, headers: dict, settings, trace: JobTrace | None = None) -> tuple[str, ScanStatus]:
    """Submit URL for scanning. Returns (uuid, status)."""
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            if trace:
                trace.emit("reputation", "request_sent", provider="urlscan", url=url)

            resp = await client.post(
                f"{URLSCAN_BASE}/scan/",
                headers=headers,
                json={"url": url, "visibility": settings.urlscan_visibility},
            )

            if resp.status_code == 429:
                if trace:
                    trace.emit("reputation", "rate_limited", provider="urlscan", url=url,
                               status=ScanStatus.RATE_LIMITED, detail="HTTP 429")
                return "", ScanStatus.RATE_LIMITED

            if resp.status_code >= 400:
                body_text = resp.text[:200]
                if trace:
                    trace.emit("reputation", "api_error", provider="urlscan", url=url,
                               status=ScanStatus.API_ERROR,
                               detail=f"HTTP {resp.status_code}: {body_text}")
                return "", ScanStatus.API_ERROR

            data = resp.json()
            scan_uuid = data.get("uuid", "")

            if not scan_uuid:
                if trace:
                    trace.emit("reputation", "invalid_response", provider="urlscan", url=url,
                               status=ScanStatus.INVALID_RESPONSE, detail="No uuid in response")
                return "", ScanStatus.INVALID_RESPONSE

            if trace:
                trace.emit("reputation", "response_received", provider="urlscan", url=url,
                           status=ScanStatus.RESPONSE_RECEIVED,
                           detail=f"uuid={scan_uuid[:40]}")

            return scan_uuid, ScanStatus.RESPONSE_RECEIVED

        except httpx.TimeoutException:
            if trace:
                trace.emit("reputation", "timeout", provider="urlscan", url=url,
                           status=ScanStatus.TIMEOUT, detail="Submit request timed out")
            return "", ScanStatus.TIMEOUT
        except Exception as e:
            if trace:
                trace.emit("reputation", "api_error", provider="urlscan", url=url,
                           status=ScanStatus.API_ERROR, detail=str(e)[:200])
            logger.error("urlscan submit failed for %s: %s", url[:80], e)
            return "", ScanStatus.API_ERROR


async def poll_result(scan_uuid: str, url: str, trace: JobTrace | None = None) -> tuple[dict | None, ScanStatus]:
    """Poll for scan results. Returns (result_data, status)."""
    settings = get_settings()
    interval = settings.poll_interval_seconds
    max_wait = settings.max_poll_seconds

    # Wait initial delay before polling (urlscan needs time)
    initial_delay = 10
    await asyncio.sleep(initial_delay)
    elapsed = initial_delay

    if trace:
        trace.emit("reputation", "polling_started", provider="urlscan", url=url,
                    detail=f"initial_delay={initial_delay}s, max_wait={max_wait}s, interval={interval}s")

    while elapsed < max_wait:
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                resp = await client.get(f"{URLSCAN_BASE}/result/{scan_uuid}/")

                if resp.status_code == 404:
                    # Not ready yet — this is expected for urlscan
                    await asyncio.sleep(interval)
                    elapsed += interval
                    continue

                if resp.status_code == 429:
                    if trace:
                        trace.emit("reputation", "rate_limited_during_poll", provider="urlscan",
                                   url=url, status=ScanStatus.RATE_LIMITED,
                                   detail=f"HTTP 429 at {elapsed}s")
                    await asyncio.sleep(interval)
                    elapsed += interval
                    continue

                if resp.status_code >= 400:
                    logger.warning("urlscan poll HTTP %d for %s", resp.status_code, scan_uuid[:40])
                    await asyncio.sleep(interval)
                    elapsed += interval
                    continue

                data = resp.json()
                verdicts = data.get("verdicts", {}).get("overall", {})
                result = {
                    "status": "completed",
                    "malicious": verdicts.get("malicious", False),
                    "score": verdicts.get("score", 0),
                    "categories": verdicts.get("categories", []),
                    "brands": [b.get("name", "") for b in verdicts.get("brands", [])],
                }

                if trace:
                    trace.emit("reputation", "result_fetched", provider="urlscan", url=url,
                               status=ScanStatus.RESULT_FETCHED,
                               detail=f"malicious={result['malicious']}, score={result['score']}",
                               data=result)

                return result, ScanStatus.RESULT_FETCHED

            except httpx.TimeoutException:
                logger.warning("urlscan poll timeout at %ds for %s", elapsed, scan_uuid[:40])
                await asyncio.sleep(interval)
                elapsed += interval
                continue
            except Exception as e:
                if "404" not in str(e):
                    logger.warning("urlscan poll error at %ds: %s", elapsed, e)
                await asyncio.sleep(interval)
                elapsed += interval
                continue

    if trace:
        trace.emit("reputation", "polling_timeout", provider="urlscan", url=url,
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
        "service": "urlscan",
        "submission_id": "",
        "scan_status": ScanStatus.NOT_EXECUTED.value,
        "status": "failed",  # legacy compat
        "malicious_count": 0,
        "suspicious_count": 0,
        "result_summary": {},
        "result_fetched": False,
    }

    if not settings.urlscan_api_key:
        if trace:
            trace.emit("reputation", "not_executed", provider="urlscan", url=url,
                        status=ScanStatus.NOT_EXECUTED, detail="No API key configured")
        return result

    headers = {
        "API-Key": settings.urlscan_api_key,
        "Content-Type": "application/json",
    }

    # Step 1: Submit
    scan_uuid, submit_status = await submit_scan(url, headers, settings, trace)

    if submit_status != ScanStatus.RESPONSE_RECEIVED:
        result["scan_status"] = submit_status.value
        result["status"] = submit_status.value
        return result

    result["submission_id"] = scan_uuid

    # Step 2: Poll for results
    scan_result, poll_status = await poll_result(scan_uuid, url, trace)

    if scan_result and poll_status == ScanStatus.RESULT_FETCHED:
        is_malicious = scan_result.get("malicious", False)
        score = scan_result.get("score", 0)

        if is_malicious:
            final_status = ScanStatus.COMPLETED_MALICIOUS
        elif score > 50:
            final_status = ScanStatus.COMPLETED_SUSPICIOUS
        else:
            final_status = ScanStatus.COMPLETED_CLEAN

        result["scan_status"] = final_status.value
        result["status"] = "completed"  # legacy compat
        result["malicious_count"] = 1 if is_malicious else 0
        result["suspicious_count"] = 1 if score > 50 else 0
        result["result_summary"] = scan_result
        result["result_fetched"] = True

        if trace:
            trace.emit("reputation", "verdict", provider="urlscan", url=url,
                        status=final_status.value,
                        detail=f"Final: {final_status.value} (malicious={is_malicious}, score={score})")
    else:
        result["scan_status"] = poll_status.value
        result["status"] = poll_status.value

        if trace:
            trace.emit("reputation", "scan_incomplete", provider="urlscan", url=url,
                        status=poll_status.value,
                        detail=f"No result fetched, final status: {poll_status.value}")

    return result
