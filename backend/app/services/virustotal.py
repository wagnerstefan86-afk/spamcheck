"""VirusTotal URL API client."""

import asyncio
import base64
import logging
import httpx

from ..config import get_settings

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"


async def submit_url(url: str) -> dict | None:
    settings = get_settings()
    if not settings.virustotal_api_key:
        logger.warning("VirusTotal API key not configured")
        return None

    headers = {"x-apikey": settings.virustotal_api_key}

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.post(
                f"{VT_BASE}/urls",
                headers=headers,
                data={"url": url},
            )
            resp.raise_for_status()
            data = resp.json()
            analysis_id = data.get("data", {}).get("id", "")
            return {"analysis_id": analysis_id}
        except Exception as e:
            logger.error("VT submit failed for %s: %s", url[:80], e)
            return None


async def get_analysis(analysis_id: str) -> dict | None:
    settings = get_settings()
    headers = {"x-apikey": settings.virustotal_api_key}

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.get(
                f"{VT_BASE}/analyses/{analysis_id}",
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("stats", {})
            return {
                "status": attrs.get("status", "queued"),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }
        except Exception as e:
            logger.error("VT analysis fetch failed: %s", e)
            return None


async def check_url(url: str) -> dict:
    """Submit URL and poll for results."""
    settings = get_settings()
    result = {
        "service": "virustotal",
        "submission_id": "",
        "status": "failed",
        "malicious_count": 0,
        "suspicious_count": 0,
        "result_summary": {},
    }

    submission = await submit_url(url)
    if not submission:
        return result

    analysis_id = submission["analysis_id"]
    result["submission_id"] = analysis_id

    elapsed = 0
    interval = settings.poll_interval_seconds
    max_wait = settings.max_poll_seconds

    while elapsed < max_wait:
        await asyncio.sleep(interval)
        elapsed += interval

        analysis = await get_analysis(analysis_id)
        if not analysis:
            continue

        if analysis["status"] == "completed":
            result["status"] = "completed"
            result["malicious_count"] = analysis["malicious"]
            result["suspicious_count"] = analysis["suspicious"]
            result["result_summary"] = analysis
            return result

    result["status"] = "timeout"
    return result
