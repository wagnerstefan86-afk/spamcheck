"""Tests for ScanStatus enum, LinkVerdict computation, and JobTrace."""

import pytest
from app.services.scan_status import (
    ScanStatus,
    LinkVerdict,
    compute_link_verdict,
    JobTrace,
)


# ---------------------------------------------------------------------------
# ScanStatus properties
# ---------------------------------------------------------------------------

class TestScanStatusProperties:
    def test_terminal_states(self):
        assert ScanStatus.COMPLETED_CLEAN.is_terminal
        assert ScanStatus.COMPLETED_MALICIOUS.is_terminal
        assert ScanStatus.TIMEOUT.is_terminal
        assert ScanStatus.RATE_LIMITED.is_terminal
        assert ScanStatus.API_ERROR.is_terminal
        assert ScanStatus.SKIPPED.is_terminal
        assert ScanStatus.NOT_EXECUTED.is_terminal

    def test_non_terminal_states(self):
        assert not ScanStatus.QUEUED.is_terminal
        assert not ScanStatus.REQUEST_SENT.is_terminal
        assert not ScanStatus.POLLING.is_terminal
        assert not ScanStatus.RESULT_FETCHED.is_terminal

    def test_success_states(self):
        assert ScanStatus.COMPLETED_CLEAN.is_success
        assert ScanStatus.COMPLETED_SUSPICIOUS.is_success
        assert ScanStatus.COMPLETED_MALICIOUS.is_success
        assert not ScanStatus.TIMEOUT.is_success
        assert not ScanStatus.RATE_LIMITED.is_success

    def test_failure_states(self):
        assert ScanStatus.TIMEOUT.is_failure
        assert ScanStatus.RATE_LIMITED.is_failure
        assert ScanStatus.API_ERROR.is_failure
        assert ScanStatus.SUBMIT_FAILED.is_failure
        assert ScanStatus.INVALID_RESPONSE.is_failure
        assert not ScanStatus.COMPLETED_CLEAN.is_failure
        assert not ScanStatus.SKIPPED.is_failure

    def test_counts_as_clean(self):
        assert ScanStatus.COMPLETED_CLEAN.counts_as_clean
        assert not ScanStatus.COMPLETED_SUSPICIOUS.counts_as_clean
        assert not ScanStatus.TIMEOUT.counts_as_clean
        assert not ScanStatus.NOT_EXECUTED.counts_as_clean

    def test_rate_limited_not_clean(self):
        """Rate-limit must never count as clean."""
        assert not ScanStatus.RATE_LIMITED.counts_as_clean
        assert ScanStatus.RATE_LIMITED.is_failure

    def test_timeout_not_clean(self):
        """Timeout must never count as clean."""
        assert not ScanStatus.TIMEOUT.counts_as_clean
        assert ScanStatus.TIMEOUT.is_failure

    def test_not_executed_distinct_from_failed(self):
        """not_executed (no API key) is different from failure states."""
        assert not ScanStatus.NOT_EXECUTED.is_failure
        assert ScanStatus.NOT_EXECUTED.is_terminal


# ---------------------------------------------------------------------------
# LinkVerdict computation
# ---------------------------------------------------------------------------

class TestComputeLinkVerdict:
    def test_no_providers(self):
        assert compute_link_verdict([]) == LinkVerdict.NOT_CHECKED

    def test_all_clean(self):
        statuses = [ScanStatus.COMPLETED_CLEAN, ScanStatus.COMPLETED_CLEAN]
        assert compute_link_verdict(statuses) == LinkVerdict.CLEAN

    def test_one_malicious_overrides(self):
        statuses = [ScanStatus.COMPLETED_CLEAN, ScanStatus.COMPLETED_MALICIOUS]
        assert compute_link_verdict(statuses) == LinkVerdict.MALICIOUS

    def test_suspicious_without_malicious(self):
        statuses = [ScanStatus.COMPLETED_CLEAN, ScanStatus.COMPLETED_SUSPICIOUS]
        assert compute_link_verdict(statuses) == LinkVerdict.SUSPICIOUS

    def test_malicious_overrides_suspicious(self):
        statuses = [ScanStatus.COMPLETED_SUSPICIOUS, ScanStatus.COMPLETED_MALICIOUS]
        assert compute_link_verdict(statuses) == LinkVerdict.MALICIOUS

    def test_mixed_success_and_failure(self):
        """If one provider succeeded and one failed -> partially_analyzed."""
        statuses = [ScanStatus.COMPLETED_CLEAN, ScanStatus.TIMEOUT]
        assert compute_link_verdict(statuses) == LinkVerdict.PARTIALLY_ANALYZED

    def test_all_failures(self):
        """All providers failed -> unknown."""
        statuses = [ScanStatus.TIMEOUT, ScanStatus.API_ERROR]
        assert compute_link_verdict(statuses) == LinkVerdict.UNKNOWN

    def test_all_skipped(self):
        statuses = [ScanStatus.SKIPPED, ScanStatus.NOT_EXECUTED]
        assert compute_link_verdict(statuses) == LinkVerdict.NOT_CHECKED

    def test_rate_limited_only(self):
        """Rate-limited only -> unknown, NOT clean."""
        statuses = [ScanStatus.RATE_LIMITED]
        assert compute_link_verdict(statuses) == LinkVerdict.UNKNOWN

    def test_timeout_only(self):
        """Timeout only -> unknown, NOT clean."""
        statuses = [ScanStatus.TIMEOUT]
        assert compute_link_verdict(statuses) == LinkVerdict.UNKNOWN

    def test_single_clean(self):
        """Single provider clean with no failures -> clean."""
        statuses = [ScanStatus.COMPLETED_CLEAN]
        assert compute_link_verdict(statuses) == LinkVerdict.CLEAN

    def test_clean_and_skipped(self):
        """Clean + skipped -> clean (skipped is not a failure)."""
        statuses = [ScanStatus.COMPLETED_CLEAN, ScanStatus.SKIPPED]
        # skipped is not in _FAILURE_STATES, not in _SUCCESS_STATES
        # has_clean=True, has_failure=False -> CLEAN
        assert compute_link_verdict(statuses) == LinkVerdict.CLEAN

    def test_not_executed_and_timeout(self):
        statuses = [ScanStatus.NOT_EXECUTED, ScanStatus.TIMEOUT]
        assert compute_link_verdict(statuses) == LinkVerdict.UNKNOWN


# ---------------------------------------------------------------------------
# JobTrace
# ---------------------------------------------------------------------------

class TestJobTrace:
    def test_emit_creates_event(self):
        trace = JobTrace("test-job-123")
        ev = trace.emit("pipeline", "analysis_started", detail="test file")
        assert ev.stage == "pipeline"
        assert ev.event == "analysis_started"
        assert ev.detail == "test file"
        assert len(trace.events) == 1

    def test_emit_truncates_url(self):
        trace = JobTrace("test-job")
        long_url = "https://example.com/" + "a" * 200
        ev = trace.emit("reputation", "request_sent", url=long_url)
        assert len(ev.url) <= 120

    def test_to_list(self):
        trace = JobTrace("test-job")
        trace.emit("pipeline", "start")
        trace.emit("reputation", "check", provider="virustotal", url="https://x.com")
        result = trace.to_list()
        assert len(result) == 2
        assert result[0]["stage"] == "pipeline"
        assert result[1]["provider"] == "virustotal"

    def test_summary(self):
        trace = JobTrace("test-job")
        trace.emit("pipeline", "start")
        trace.emit("pipeline", "error_occurred")
        trace.emit("pipeline", "done")
        summary = trace.summary()
        assert summary["job_id"] == "test-job"
        assert summary["total_events"] == 3
        assert summary["error_events"] == 1  # "error" in event name
        assert "pipeline" in summary["stages"]
        assert summary["duration_ms"] >= 0

    def test_events_have_timestamps(self):
        trace = JobTrace("test-job")
        trace.emit("pipeline", "test")
        ev = trace.events[0]
        assert ev.timestamp.endswith("Z")

    def test_to_dict_omits_empty_fields(self):
        trace = JobTrace("test-job")
        ev = trace.emit("pipeline", "simple")
        d = ev.to_dict()
        # provider, url, status, detail should be absent when empty
        assert "provider" not in d
        assert "url" not in d
        # timestamp, stage, event always present
        assert "timestamp" in d
        assert "stage" in d
        assert "event" in d

    def test_trace_preserves_order(self):
        trace = JobTrace("test-job")
        for i in range(10):
            trace.emit("pipeline", f"step_{i}")
        events = trace.to_list()
        for i in range(10):
            assert events[i]["event"] == f"step_{i}"
