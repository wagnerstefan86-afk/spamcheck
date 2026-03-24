"""Per-link heuristic analysis."""

import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz",
    ".club", ".work", ".click", ".loan", ".racing", ".win", ".icu",
    ".cam", ".rest", ".monster",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "bl.ink", "short.io", "cutt.ly",
    "rb.gy", "shorturl.at",
}

IP_URL_RE = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

TRACKING_PARAMS = {"mc_cid", "mc_eid", "fbclid", "gclid", "msclkid", "yclid", "dclid"}


def analyze_link(original_url: str, normalized_url: str, display_text: str | None) -> dict:
    """Analyze a single link for suspicious characteristics."""
    flags = {
        "has_display_mismatch": False,
        "is_suspicious_tld": False,
        "is_ip_literal": False,
        "is_punycode": False,
        "is_shortener": False,
        "is_tracking_heavy": False,
        "hostname": "",
    }

    try:
        parsed = urlparse(normalized_url)
        hostname = parsed.hostname or ""
    except Exception:
        hostname = ""

    flags["hostname"] = hostname

    # IP literal
    if IP_URL_RE.match(normalized_url):
        flags["is_ip_literal"] = True

    # Punycode
    if hostname.startswith("xn--") or any(part.startswith("xn--") for part in hostname.split(".")):
        flags["is_punycode"] = True

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld) or hostname.endswith(tld.lstrip(".")):
            flags["is_suspicious_tld"] = True
            break

    # URL shortener
    if hostname in URL_SHORTENERS:
        flags["is_shortener"] = True

    # Display text mismatch
    if display_text and display_text.startswith("http"):
        try:
            display_host = urlparse(display_text).hostname or ""
            if display_host and hostname and display_host.lower() != hostname.lower():
                flags["has_display_mismatch"] = True
        except Exception:
            pass
    elif display_text:
        # Check if display text looks like a domain but doesn't match
        domain_like = re.match(r"^[\w.-]+\.\w{2,}$", display_text.strip())
        if domain_like and hostname and display_text.strip().lower() not in hostname.lower():
            flags["has_display_mismatch"] = True

    # Tracking-heavy
    try:
        parsed = urlparse(normalized_url)
        params = set(parsed.query.split("&")) if parsed.query else set()
        param_keys = {p.split("=")[0].lower() for p in params if "=" in p}
        if len(param_keys & TRACKING_PARAMS) >= 2:
            flags["is_tracking_heavy"] = True
    except Exception:
        pass

    return flags
