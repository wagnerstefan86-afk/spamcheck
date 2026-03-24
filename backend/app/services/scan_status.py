"""Structured scan status model and pipeline event tracing.

Provides clear, granular status values for provider scans and
a lightweight event trace system for job-level observability.
"""

import datetime
import enum
import logging
from dataclasses import dataclass, field, asdict
from typing import Any

logger = logging.getLogger(__name__)


class ScanStatus(str, enum.Enum):
    """Granular status for an individual provider scan step."""

    # Pre-execution
    QUEUED = "queued"
    SKIPPED = "skipped"              # provider disabled or link filtered out
    NOT_EXECUTED = "not_executed"     # no API key configured

    # Execution lifecycle
    REQUEST_SENT = "request_sent"
    RESPONSE_RECEIVED = "response_received"
    RESULT_PENDING = "result_pending"   # async scan submitted, polling not done
    POLLING = "polling"
    RESULT_FETCHED = "result_fetched"   # raw result downloaded from provider

    # Terminal – successful
    COMPLETED_CLEAN = "completed_clean"
    COMPLETED_SUSPICIOUS = "completed_suspicious"
    COMPLETED_MALICIOUS = "completed_malicious"

    # Terminal – failure
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    API_ERROR = "api_error"
    INVALID_RESPONSE = "invalid_response"
    SUBMIT_FAILED = "submit_failed"

    @property
    def is_terminal(self) -> bool:
        return self in _TERMINAL_STATES

    @property
    def is_success(self) -> bool:
        return self in _SUCCESS_STATES

    @property
    def is_failure(self) -> bool:
        return self in _FAILURE_STATES

    @property
    def counts_as_clean(self) -> bool:
        """Only COMPLETED_CLEAN counts as verified clean."""
        return self == ScanStatus.COMPLETED_CLEAN


_TERMINAL_STATES = {
    ScanStatus.COMPLETED_CLEAN,
    ScanStatus.COMPLETED_SUSPICIOUS,
    ScanStatus.COMPLETED_MALICIOUS,
    ScanStatus.RATE_LIMITED,
    ScanStatus.TIMEOUT,
    ScanStatus.API_ERROR,
    ScanStatus.INVALID_RESPONSE,
    ScanStatus.SUBMIT_FAILED,
    ScanStatus.SKIPPED,
    ScanStatus.NOT_EXECUTED,
}

_SUCCESS_STATES = {
    ScanStatus.COMPLETED_CLEAN,
    ScanStatus.COMPLETED_SUSPICIOUS,
    ScanStatus.COMPLETED_MALICIOUS,
}

_FAILURE_STATES = {
    ScanStatus.RATE_LIMITED,
    ScanStatus.TIMEOUT,
    ScanStatus.API_ERROR,
    ScanStatus.INVALID_RESPONSE,
    ScanStatus.SUBMIT_FAILED,
}


class LinkVerdict(str, enum.Enum):
    """Aggregated verdict for a link across all providers."""

    CLEAN = "clean"                     # at least one provider confirmed clean, none negative
    SUSPICIOUS = "suspicious"           # at least one provider flagged suspicious
    MALICIOUS = "malicious"             # at least one provider flagged malicious
    UNKNOWN = "unknown"                 # no provider returned a usable result
    PARTIALLY_ANALYZED = "partially_analyzed"  # mixed: some succeeded, some failed
    NOT_CHECKED = "not_checked"         # no providers were executed at all


def compute_link_verdict(provider_statuses: list["ScanStatus"]) -> LinkVerdict:
    """Determine aggregate verdict for a link from its provider scan statuses.

    Rules:
    - If ANY provider says malicious -> MALICIOUS
    - If ANY provider says suspicious (and none malicious) -> SUSPICIOUS
    - If at least one provider completed clean and none negative -> CLEAN
    - If some succeeded and some failed -> PARTIALLY_ANALYZED
    - If all were skipped/not_executed -> NOT_CHECKED
    - Otherwise -> UNKNOWN
    """
    if not provider_statuses:
        return LinkVerdict.NOT_CHECKED

    has_malicious = any(s == ScanStatus.COMPLETED_MALICIOUS for s in provider_statuses)
    has_suspicious = any(s == ScanStatus.COMPLETED_SUSPICIOUS for s in provider_statuses)
    has_clean = any(s == ScanStatus.COMPLETED_CLEAN for s in provider_statuses)
    has_failure = any(s.is_failure for s in provider_statuses)
    has_success = any(s.is_success for s in provider_statuses)
    all_skipped = all(s in (ScanStatus.SKIPPED, ScanStatus.NOT_EXECUTED) for s in provider_statuses)

    if has_malicious:
        return LinkVerdict.MALICIOUS
    if has_suspicious:
        return LinkVerdict.SUSPICIOUS
    if has_clean and not has_failure:
        return LinkVerdict.CLEAN
    if has_success and has_failure:
        return LinkVerdict.PARTIALLY_ANALYZED
    if all_skipped:
        return LinkVerdict.NOT_CHECKED
    return LinkVerdict.UNKNOWN


# ---------------------------------------------------------------------------
# Pipeline Event Trace
# ---------------------------------------------------------------------------

@dataclass
class PipelineEvent:
    """A single structured event in the analysis pipeline."""

    timestamp: str
    stage: str          # e.g. "parsing", "link_extraction", "reputation", "llm"
    event: str          # e.g. "request_sent", "result_fetched", "error"
    provider: str = ""  # "virustotal", "urlscan", or ""
    url: str = ""       # the URL being checked (truncated)
    status: str = ""    # ScanStatus value if applicable
    detail: str = ""    # human-readable detail
    data: dict = field(default_factory=dict)  # arbitrary structured data

    def to_dict(self) -> dict:
        d = asdict(self)
        # Remove empty fields for cleaner output
        return {k: v for k, v in d.items() if v or k in ("timestamp", "stage", "event")}


class JobTrace:
    """Collects structured pipeline events for a single job."""

    def __init__(self, job_id: str):
        self.job_id = job_id
        self.events: list[PipelineEvent] = []
        self._start_time = datetime.datetime.utcnow()

    def emit(
        self,
        stage: str,
        event: str,
        *,
        provider: str = "",
        url: str = "",
        status: str = "",
        detail: str = "",
        data: dict | None = None,
    ) -> PipelineEvent:
        ev = PipelineEvent(
            timestamp=datetime.datetime.utcnow().isoformat() + "Z",
            stage=stage,
            event=event,
            provider=provider,
            url=url[:120] if url else "",
            status=status,
            detail=detail,
            data=data or {},
        )
        self.events.append(ev)
        # Also log structured for log aggregation
        logger.info(
            "TRACE job=%s stage=%s event=%s provider=%s status=%s url=%s detail=%s",
            self.job_id, stage, event, provider, status,
            url[:80] if url else "", detail[:120] if detail else "",
        )
        return ev

    def to_list(self) -> list[dict]:
        return [e.to_dict() for e in self.events]

    def summary(self) -> dict:
        """Return a compact summary of the trace."""
        total = len(self.events)
        errors = sum(1 for e in self.events if "error" in e.event or "failed" in e.event)
        stages = sorted(set(e.stage for e in self.events))
        duration_ms = int(
            (datetime.datetime.utcnow() - self._start_time).total_seconds() * 1000
        )
        return {
            "job_id": self.job_id,
            "total_events": total,
            "error_events": errors,
            "stages": stages,
            "duration_ms": duration_ms,
        }
