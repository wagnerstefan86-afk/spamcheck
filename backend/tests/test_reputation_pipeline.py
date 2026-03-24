"""Tests for VirusTotal and urlscan provider clients with status tracking."""

import sys
import os
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

import httpx

from app.services.scan_status import ScanStatus, LinkVerdict, compute_link_verdict, JobTrace

# Pre-import the modules to make patching work
import app.services.virustotal as vt_module
import app.services.urlscan as us_module


# ---------------------------------------------------------------------------
# VirusTotal tests
# ---------------------------------------------------------------------------

class TestVirusTotalCheckUrl:
    @pytest.fixture
    def trace(self):
        return JobTrace("vt-test-job")

    @pytest.mark.asyncio
    async def test_no_api_key_returns_not_executed(self, trace):
        with patch.object(vt_module, "get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(virustotal_api_key="")
            result = await vt_module.check_url("https://example.com", trace)

        assert result["scan_status"] == ScanStatus.NOT_EXECUTED.value
        assert result["result_fetched"] is False
        not_exec_events = [e for e in trace.events if e.event == "not_executed"]
        assert len(not_exec_events) == 1

    @pytest.mark.asyncio
    async def test_submit_rate_limited(self, trace):
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.text = "Rate limited"

        with patch.object(vt_module, "get_settings") as mock_settings, \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            mock_settings.return_value = MagicMock(
                virustotal_api_key="test-key",
                poll_interval_seconds=1,
                max_poll_seconds=5,
            )
            result = await vt_module.check_url("https://example.com", trace)

        assert result["scan_status"] == ScanStatus.RATE_LIMITED.value
        assert result["result_fetched"] is False
        rate_events = [e for e in trace.events if e.event == "rate_limited"]
        assert len(rate_events) >= 1

    @pytest.mark.asyncio
    async def test_submit_timeout(self, trace):
        with patch.object(vt_module, "get_settings") as mock_settings, \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=httpx.TimeoutException("timeout")):
            mock_settings.return_value = MagicMock(
                virustotal_api_key="test-key",
                poll_interval_seconds=1,
                max_poll_seconds=5,
            )
            result = await vt_module.check_url("https://example.com", trace)

        assert result["scan_status"] == ScanStatus.TIMEOUT.value
        assert result["result_fetched"] is False

    @pytest.mark.asyncio
    async def test_successful_clean_result(self, trace):
        submit_response = MagicMock()
        submit_response.status_code = 200
        submit_response.json.return_value = {"data": {"id": "analysis-123"}}

        poll_response = MagicMock()
        poll_response.status_code = 200
        poll_response.json.return_value = {
            "data": {"attributes": {
                "status": "completed",
                "stats": {"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 5},
            }},
        }

        with patch.object(vt_module, "get_settings") as mock_settings, \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=submit_response), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=poll_response), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            mock_settings.return_value = MagicMock(
                virustotal_api_key="test-key",
                poll_interval_seconds=1,
                max_poll_seconds=60,
            )
            result = await vt_module.check_url("https://example.com", trace)

        assert result["scan_status"] == ScanStatus.COMPLETED_CLEAN.value
        assert result["result_fetched"] is True
        assert result["malicious_count"] == 0

        event_names = [e.event for e in trace.events]
        assert "request_sent" in event_names
        assert "response_received" in event_names
        assert "result_fetched" in event_names
        assert "verdict" in event_names

    @pytest.mark.asyncio
    async def test_successful_malicious_result(self, trace):
        submit_response = MagicMock()
        submit_response.status_code = 200
        submit_response.json.return_value = {"data": {"id": "analysis-456"}}

        poll_response = MagicMock()
        poll_response.status_code = 200
        poll_response.json.return_value = {
            "data": {"attributes": {
                "status": "completed",
                "stats": {"malicious": 5, "suspicious": 2, "harmless": 40, "undetected": 10},
            }},
        }

        with patch.object(vt_module, "get_settings") as mock_settings, \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=submit_response), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=poll_response), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            mock_settings.return_value = MagicMock(
                virustotal_api_key="test-key",
                poll_interval_seconds=1,
                max_poll_seconds=60,
            )
            result = await vt_module.check_url("https://evil.com", trace)

        assert result["scan_status"] == ScanStatus.COMPLETED_MALICIOUS.value
        assert result["result_fetched"] is True
        assert result["malicious_count"] == 5

    @pytest.mark.asyncio
    async def test_request_marked_as_sent(self, trace):
        submit_response = MagicMock()
        submit_response.status_code = 200
        submit_response.json.return_value = {"data": {"id": "analysis-789"}}

        poll_response = MagicMock()
        poll_response.status_code = 200
        poll_response.json.return_value = {
            "data": {"attributes": {
                "status": "completed",
                "stats": {"malicious": 0, "suspicious": 0, "harmless": 50, "undetected": 5},
            }},
        }

        with patch.object(vt_module, "get_settings") as mock_settings, \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=submit_response), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=poll_response), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            mock_settings.return_value = MagicMock(
                virustotal_api_key="test-key",
                poll_interval_seconds=1,
                max_poll_seconds=60,
            )
            await vt_module.check_url("https://example.com", trace)

        event_names = [e.event for e in trace.events]
        sent_idx = event_names.index("request_sent")
        received_idx = event_names.index("response_received")
        assert sent_idx < received_idx

    @pytest.mark.asyncio
    async def test_response_marked_as_received(self, trace):
        submit_response = MagicMock()
        submit_response.status_code = 200
        submit_response.json.return_value = {"data": {"id": "analysis-abc"}}

        poll_response = MagicMock()
        poll_response.status_code = 200
        poll_response.json.return_value = {
            "data": {"attributes": {
                "status": "completed",
                "stats": {"malicious": 0, "suspicious": 0, "harmless": 50, "undetected": 5},
            }},
        }

        with patch.object(vt_module, "get_settings") as mock_settings, \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=submit_response), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=poll_response), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            mock_settings.return_value = MagicMock(
                virustotal_api_key="test-key",
                poll_interval_seconds=1,
                max_poll_seconds=60,
            )
            await vt_module.check_url("https://example.com", trace)

        received_events = [e for e in trace.events if e.event == "response_received"]
        assert len(received_events) == 1
        assert "analysis-abc" in received_events[0].detail


# ---------------------------------------------------------------------------
# urlscan tests
# ---------------------------------------------------------------------------

class TestUrlscanCheckUrl:
    @pytest.fixture
    def trace(self):
        return JobTrace("us-test-job")

    @pytest.mark.asyncio
    async def test_no_api_key_returns_not_executed(self, trace):
        with patch.object(us_module, "get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(urlscan_api_key="")
            result = await us_module.check_url("https://example.com", trace)

        assert result["scan_status"] == ScanStatus.NOT_EXECUTED.value
        assert result["result_fetched"] is False

    @pytest.mark.asyncio
    async def test_submit_rate_limited(self, trace):
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.text = "Rate limited"

        with patch.object(us_module, "get_settings") as mock_settings, \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            mock_settings.return_value = MagicMock(
                urlscan_api_key="test-key",
                urlscan_visibility="private",
                poll_interval_seconds=1,
                max_poll_seconds=5,
            )
            result = await us_module.check_url("https://example.com", trace)

        assert result["scan_status"] == ScanStatus.RATE_LIMITED.value
        assert result["result_fetched"] is False

    @pytest.mark.asyncio
    async def test_successful_clean_result(self, trace):
        submit_response = MagicMock()
        submit_response.status_code = 200
        submit_response.json.return_value = {"uuid": "scan-uuid-123", "result": "https://urlscan.io/result/123/"}

        poll_response = MagicMock()
        poll_response.status_code = 200
        poll_response.json.return_value = {
            "verdicts": {"overall": {
                "malicious": False,
                "score": 0,
                "categories": [],
                "brands": [],
            }},
        }

        with patch.object(us_module, "get_settings") as mock_settings, \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=submit_response), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=poll_response), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            mock_settings.return_value = MagicMock(
                urlscan_api_key="test-key",
                urlscan_visibility="private",
                poll_interval_seconds=1,
                max_poll_seconds=60,
            )
            result = await us_module.check_url("https://example.com", trace)

        assert result["scan_status"] == ScanStatus.COMPLETED_CLEAN.value
        assert result["result_fetched"] is True
        assert result["malicious_count"] == 0


# ---------------------------------------------------------------------------
# Aggregation logic tests
# ---------------------------------------------------------------------------

class TestAggregationWithMixedResults:
    def test_rate_limited_not_counted_as_clean(self):
        statuses = [ScanStatus.RATE_LIMITED, ScanStatus.RATE_LIMITED]
        verdict = compute_link_verdict(statuses)
        assert verdict != LinkVerdict.CLEAN
        assert verdict == LinkVerdict.UNKNOWN

    def test_timeout_not_counted_as_clean(self):
        statuses = [ScanStatus.TIMEOUT, ScanStatus.TIMEOUT]
        verdict = compute_link_verdict(statuses)
        assert verdict != LinkVerdict.CLEAN
        assert verdict == LinkVerdict.UNKNOWN

    def test_one_clean_one_rate_limited(self):
        statuses = [ScanStatus.COMPLETED_CLEAN, ScanStatus.RATE_LIMITED]
        verdict = compute_link_verdict(statuses)
        assert verdict == LinkVerdict.PARTIALLY_ANALYZED

    def test_one_malicious_one_timeout(self):
        statuses = [ScanStatus.COMPLETED_MALICIOUS, ScanStatus.TIMEOUT]
        verdict = compute_link_verdict(statuses)
        assert verdict == LinkVerdict.MALICIOUS

    def test_not_executed_is_not_failure(self):
        statuses = [ScanStatus.NOT_EXECUTED]
        verdict = compute_link_verdict(statuses)
        assert verdict == LinkVerdict.NOT_CHECKED
