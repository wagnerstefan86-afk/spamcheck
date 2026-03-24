"""Extract URLs from email text and HTML bodies."""

import re
from html.parser import HTMLParser
from .url_normalizer import normalize_url, deduplicate_urls

URL_RE = re.compile(r"https?://[^\s<>\"'\)\]\}]+", re.IGNORECASE)


class LinkHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[tuple[str, str | None]] = []
        self._current_href: str | None = None
        self._current_text = ""

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for name, value in attrs:
                if name == "href" and value and (value.startswith("http://") or value.startswith("https://")):
                    self._current_href = value
                    self._current_text = ""

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text += data

    def handle_endtag(self, tag):
        if tag == "a" and self._current_href is not None:
            self.links.append((self._current_href, self._current_text.strip() or None))
            self._current_href = None
            self._current_text = ""


def extract_urls_from_text(text: str) -> list[tuple[str, str | None]]:
    """Returns list of (url, display_text=None) from plain text."""
    if not text:
        return []
    matches = URL_RE.findall(text)
    return [(m.rstrip(".,;:!?)>"), None) for m in matches]


def extract_urls_from_html(html_body: str) -> list[tuple[str, str | None]]:
    """Returns list of (url, display_text) from HTML."""
    if not html_body:
        return []
    parser = LinkHTMLParser()
    try:
        parser.feed(html_body)
    except Exception:
        pass

    # Also find bare URLs in HTML that aren't in <a> tags
    bare = URL_RE.findall(html_body)
    href_urls = {link[0] for link in parser.links}
    for url in bare:
        url = url.rstrip(".,;:!?)>\"'")
        if url not in href_urls:
            parser.links.append((url, None))

    return parser.links


def extract_and_normalize(body_text: str, body_html: str) -> list[tuple[str, str, str | None, bool]]:
    """Extract, normalize and deduplicate URLs.

    Returns list of (original_url, normalized_url, display_text, is_safelink).
    """
    raw_links = extract_urls_from_text(body_text) + extract_urls_from_html(body_html)

    normalized = []
    for original, display_text in raw_links:
        norm, is_safelink = normalize_url(original)
        normalized.append((original, norm, display_text, is_safelink))

    return deduplicate_urls(normalized)
