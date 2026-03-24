"""urlscan.io API client."""

import asyncio
import logging
import httpx

from ..config import get_settings

logger = logging.getLogger(__name__)

URLSCAN_BASE = "https://urlscan.io/api/v1"


async def submit_scan(url: str) -> dict | None:
    settings = get_settings()
    if not settings.urlscan_api_key:
        logger.warning("urlscan API key not configured")
        return None

    headers = {
        "API-Key": settings.urlscan_api_key,
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.post(
                f"{URLSCAN_BASE}/scan/",
                headers=headers,
                json={"url": url, "visibility": settings.urlscan_visibility},
            )
            resp.raise_for_status()
            data = resp.json()
            return {
                "uuid": data.get("uuid", ""),
                "result_url": data.get("result", ""),
            }
        except Exception as e:
            logger.error("urlscan submit failed for %s: %s", url[:80], e)
            return None


async def get_result(uuid: str) -> dict | None:
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.get(f"{URLSCAN_BASE}/result/{uuid}/")
            if resp.status_code == 404:
                return None  # not ready yet
            resp.raise_for_status()
            data = resp.json()
            verdicts = data.get("verdicts", {}).get("overall", {})
            return {
                "status": "completed",
                "malicious": verdicts.get("malicious", False),
                "score": verdicts.get("score", 0),
                "categories": verdicts.get("categories", []),
                "brands": [b.get("name", "") for b in verdicts.get("brands", [])],
            }
        except Exception as e:
            if "404" not in str(e):
                logger.error("urlscan result fetch failed: %s", e)
            return None


async def check_url(url: str) -> dict:
    """Submit URL and poll for results."""
    settings = get_settings()
    result = {
        "service": "urlscan",
        "submission_id": "",
        "status": "failed",
        "malicious_count": 0,
        "suspicious_count": 0,
        "result_summary": {},
    }

    submission = await submit_scan(url)
    if not submission:
        return result

    uuid = submission["uuid"]
    result["submission_id"] = uuid

    # Wait initial delay before polling
    await asyncio.sleep(10)
    elapsed = 10
    interval = settings.poll_interval_seconds
    max_wait = settings.max_poll_seconds

    while elapsed < max_wait:
        scan_result = await get_result(uuid)
        if scan_result and scan_result.get("status") == "completed":
            result["status"] = "completed"
            result["malicious_count"] = 1 if scan_result.get("malicious") else 0
            result["suspicious_count"] = 1 if scan_result.get("score", 0) > 50 else 0
            result["result_summary"] = scan_result
            return result

        await asyncio.sleep(interval)
        elapsed += interval

    result["status"] = "timeout"
    return result
