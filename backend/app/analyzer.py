import re
from email import policy
from email.parser import Parser

from .models import (
    AnalysisResult,
    HeaderAnalysis,
    SenderAnalysis,
    UrlAnalysis,
)

FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "protonmail.com", "zoho.com", "yandex.com", "gmx.com",
    "gmx.de", "web.de", "t-online.de", "freenet.de", "mail.ru",
    "icloud.com", "live.com", "msn.com",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz",
    ".club", ".work", ".click", ".loan", ".racing", ".win",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "bl.ink", "short.io", "cutt.ly",
}

HOMOGRAPH_CHARS = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u04bb": "h",
    "\u0456": "i", "\u0458": "j", "\u04c0": "l", "\u0455": "s",
    "\u051b": "q",
}

IP_URL_PATTERN = re.compile(
    r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
)
URL_PATTERN = re.compile(
    r"https?://[^\s<>\"'\)\]}]+"
)
EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def parse_headers(email_text: str) -> HeaderAnalysis:
    parser = Parser(policy=policy.default)
    msg = parser.parsestr(email_text)

    analysis = HeaderAnalysis()

    from_header = msg.get("From", "")
    match = EMAIL_PATTERN.search(from_header)
    if match:
        analysis.from_address = match.group(0)

    analysis.return_path = msg.get("Return-Path", "").strip("<>").strip()

    received = msg.get_all("Received") or []
    analysis.received_chain = [r.strip() for r in received]

    auth_results = msg.get("Authentication-Results", "")
    received_spf = msg.get("Received-SPF", "")

    spf_text = received_spf or auth_results
    if "spf=" in spf_text.lower() or "received-spf" in spf_text.lower():
        analysis.spf = spf_text[:200]
        analysis.spf_pass = "pass" in spf_text.lower()
    elif received_spf:
        analysis.spf = received_spf[:200]
        analysis.spf_pass = "pass" in received_spf.lower()

    dkim_sig = msg.get("DKIM-Signature", "")
    if dkim_sig:
        analysis.dkim = dkim_sig[:200]
    if auth_results and "dkim=pass" in auth_results.lower():
        analysis.dkim_pass = True
    elif dkim_sig:
        analysis.dkim = dkim_sig[:200]

    dmarc_text = ""
    if auth_results and "dmarc=" in auth_results.lower():
        dmarc_text = auth_results
    else:
        dmarc_header = msg.get("DMARC-Filter", "")
        if dmarc_header:
            dmarc_text = dmarc_header

    if dmarc_text:
        analysis.dmarc = dmarc_text[:200]
        analysis.dmarc_pass = "dmarc=pass" in dmarc_text.lower()

    return analysis


def analyze_urls(email_text: str) -> list[UrlAnalysis]:
    urls = URL_PATTERN.findall(email_text)
    results = []
    seen = set()

    for url in urls:
        url = url.rstrip(".,;:!?)")
        if url in seen:
            continue
        seen.add(url)

        analysis = UrlAnalysis(url=url)
        reasons = []

        if IP_URL_PATTERN.match(url):
            reasons.append("IP-basierte URL (kein Domainname)")

        try:
            domain_part = url.split("//", 1)[1].split("/", 1)[0].split(":")[0].lower()
        except IndexError:
            domain_part = ""

        if domain_part in URL_SHORTENERS:
            reasons.append(f"URL-Shortener erkannt: {domain_part}")

        for tld in SUSPICIOUS_TLDS:
            if domain_part.endswith(tld):
                reasons.append(f"Verdächtige TLD: {tld}")
                break

        for cyrillic, latin in HOMOGRAPH_CHARS.items():
            if cyrillic in domain_part:
                reasons.append(f"Homograph-Angriff: '{cyrillic}' sieht aus wie '{latin}'")
                break

        if domain_part.count(".") > 3:
            reasons.append("Ungewöhnlich viele Subdomains")

        if len(url) > 200:
            reasons.append("Übermäßig lange URL")

        if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            reasons.append("URL enthält @-Zeichen (mögliche Täuschung)")

        if reasons:
            analysis.is_suspicious = True
            analysis.reasons = reasons
        results.append(analysis)

    return results


def analyze_sender(email_text: str, headers: HeaderAnalysis) -> SenderAnalysis:
    address = headers.from_address
    if not address:
        match = EMAIL_PATTERN.search(email_text)
        address = match.group(0) if match else ""

    sender = SenderAnalysis(address=address)
    if not address:
        return sender

    parts = address.rsplit("@", 1)
    if len(parts) == 2:
        sender.domain = parts[1].lower()

    if sender.domain in FREEMAIL_DOMAINS:
        sender.is_freemail = True

    indicators = []

    if headers.return_path and headers.from_address:
        rp_domain = headers.return_path.rsplit("@", 1)[-1].lower() if "@" in headers.return_path else ""
        from_domain = headers.from_address.rsplit("@", 1)[-1].lower() if "@" in headers.from_address else ""
        if rp_domain and from_domain and rp_domain != from_domain:
            indicators.append(
                f"Return-Path Domain ({rp_domain}) weicht von From ab ({from_domain})"
            )

    for cyrillic, latin in HOMOGRAPH_CHARS.items():
        if cyrillic in sender.domain:
            indicators.append(f"Homograph im Domainnamen: '{cyrillic}' ähnelt '{latin}'")
            break

    sender.spoofing_indicators = indicators
    return sender


def calculate_risk_score(
    headers: HeaderAnalysis,
    urls: list[UrlAnalysis],
    sender: SenderAnalysis,
) -> tuple[int, list[str]]:
    score = 0
    warnings: list[str] = []

    if not headers.spf_pass:
        score += 15
        warnings.append("SPF-Prüfung nicht bestanden oder nicht vorhanden")
    if not headers.dkim_pass:
        score += 15
        warnings.append("DKIM-Prüfung nicht bestanden oder nicht vorhanden")
    if not headers.dmarc_pass:
        score += 10
        warnings.append("DMARC-Prüfung nicht bestanden oder nicht vorhanden")

    suspicious_urls = [u for u in urls if u.is_suspicious]
    url_score = min(len(suspicious_urls) * 10, 30)
    score += url_score
    if suspicious_urls:
        warnings.append(f"{len(suspicious_urls)} verdächtige URL(s) gefunden")

    if sender.is_freemail:
        score += 5
        warnings.append("Absender nutzt Freemail-Dienst")

    if sender.spoofing_indicators:
        score += 20
        for ind in sender.spoofing_indicators:
            warnings.append(f"Spoofing-Indikator: {ind}")

    score = min(score, 100)
    return score, warnings


def get_risk_level(score: int) -> str:
    if score <= 25:
        return "niedrig"
    if score <= 55:
        return "mittel"
    return "hoch"


def analyze_email(email_text: str) -> AnalysisResult:
    headers = parse_headers(email_text)
    urls = analyze_urls(email_text)
    sender = analyze_sender(email_text, headers)
    score, warnings = calculate_risk_score(headers, urls, sender)
    risk_level = get_risk_level(score)

    level_labels = {"niedrig": "Niedrig", "mittel": "Mittel", "hoch": "Hoch"}
    summary = (
        f"Risiko-Bewertung: {level_labels.get(risk_level, risk_level)} ({score}/100). "
        f"{'Keine auffälligen Probleme.' if not warnings else f'{len(warnings)} Warnung(en) erkannt.'}"
    )

    return AnalysisResult(
        risk_score=score,
        risk_level=risk_level,
        summary=summary,
        headers=headers,
        urls=urls,
        sender=sender,
        warnings=warnings,
    )
