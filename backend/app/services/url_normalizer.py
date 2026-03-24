"""URL normalization: SafeLinks unwrap, HTML entity decode, UTM strip, dedup."""

import html
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


SAFELINK_PATTERN = re.compile(
    r"https?://[a-z0-9.-]*safelinks\.protection\.outlook\.com/\?",
    re.IGNORECASE,
)

UTM_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id"}

REDIRECT_PARAMS = {"url", "u", "redirect", "redirect_uri", "target", "goto", "next", "link", "dest", "destination"}


def unwrap_safelinks(url: str) -> str:
    if not SAFELINK_PATTERN.match(url):
        return url
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if "url" in qs:
        return qs["url"][0]
    return url


def decode_html_entities(url: str) -> str:
    return html.unescape(url)


def strip_utm(url: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    filtered = {k: v for k, v in qs.items() if k.lower() not in UTM_PARAMS}
    new_query = urlencode(filtered, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def try_unwrap_redirect(url: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    for param in REDIRECT_PARAMS:
        if param in qs:
            candidate = qs[param][0]
            if candidate.startswith("http://") or candidate.startswith("https://"):
                return candidate
    return url


def normalize_url(url: str) -> tuple[str, bool]:
    """Normalize a URL. Returns (normalized_url, was_safelink)."""
    original = url.strip()
    is_safelink = bool(SAFELINK_PATTERN.match(original))

    normalized = decode_html_entities(original)
    normalized = unwrap_safelinks(normalized)
    normalized = try_unwrap_redirect(normalized)
    normalized = strip_utm(normalized)
    normalized = normalized.rstrip("/")

    return normalized, is_safelink


def deduplicate_urls(url_tuples: list[tuple[str, str, str | None, bool]]) -> list[tuple[str, str, str | None, bool]]:
    """Deduplicate by normalized URL. Input: (original, normalized, display_text, is_safelink)."""
    seen = set()
    result = []
    for item in url_tuples:
        canonical = item[1].lower()
        if canonical not in seen:
            seen.add(canonical)
            result.append(item)
    return result
