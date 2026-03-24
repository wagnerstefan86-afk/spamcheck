"""Deterministic header analysis heuristics."""

import re

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
DOMAIN_RE = re.compile(r"@([\w.-]+)")

BULK_HEADERS = {"list-unsubscribe", "feedback-id", "x-mailer", "precedence", "x-campaign"}
SPAM_HEADERS = {"x-spam-flag", "x-spam-status", "x-spam-score", "x-forefront-antispam-report"}


def _get_domain(address: str) -> str:
    match = DOMAIN_RE.search(address)
    return match.group(1).lower() if match else ""


def _check_auth_results(auth_results: str) -> dict[str, str]:
    results = {"spf": "none", "dkim": "none", "dmarc": "none"}
    if not auth_results:
        return results
    lower = auth_results.lower()
    for proto in ["spf", "dkim", "dmarc"]:
        match = re.search(rf"{proto}=([\w]+)", lower)
        if match:
            results[proto] = match.group(1)
    return results


def analyze_headers(parsed: dict) -> list[dict]:
    findings = []
    _id = 0

    def add(severity: str, title: str, detail: str):
        nonlocal _id
        _id += 1
        findings.append({"id": f"HDR-{_id:03d}", "severity": severity, "title": title, "detail": detail})

    auth = _check_auth_results(parsed.get("authentication_results", ""))

    # SPF
    if auth["spf"] in ("fail", "softfail"):
        add("critical", "SPF fehlgeschlagen", f"SPF-Ergebnis: {auth['spf']}. Der Absender-Server ist nicht autorisiert.")
    elif auth["spf"] == "none":
        add("warning", "Kein SPF-Ergebnis", "Es wurde kein SPF-Eintrag gefunden oder geprüft.")

    # DKIM
    if auth["dkim"] == "fail":
        add("critical", "DKIM fehlgeschlagen", "Die DKIM-Signatur konnte nicht verifiziert werden.")
    elif auth["dkim"] == "none":
        add("warning", "Kein DKIM-Ergebnis", "Keine DKIM-Signatur vorhanden oder geprüft.")

    # DMARC
    if auth["dmarc"] == "fail":
        add("critical", "DMARC fehlgeschlagen", "DMARC-Prüfung fehlgeschlagen. Die E-Mail entspricht nicht der Domain-Policy.")
    elif auth["dmarc"] == "none":
        add("warning", "Kein DMARC-Ergebnis", "Kein DMARC-Eintrag gefunden.")

    # From vs Reply-To mismatch
    from_addr = parsed.get("from", "")
    reply_to = parsed.get("reply_to", "")
    if from_addr and reply_to:
        from_domain = _get_domain(from_addr)
        reply_domain = _get_domain(reply_to)
        if from_domain and reply_domain and from_domain != reply_domain:
            add("critical", "From / Reply-To Mismatch",
                f"From-Domain ({from_domain}) weicht von Reply-To-Domain ({reply_domain}) ab. Häufiges Phishing-Merkmal.")

    # From vs Return-Path mismatch
    return_path = parsed.get("return_path", "")
    if from_addr and return_path:
        from_domain = _get_domain(from_addr)
        rp_domain = _get_domain(return_path)
        if from_domain and rp_domain and from_domain != rp_domain:
            add("warning", "From / Return-Path Mismatch",
                f"From-Domain ({from_domain}) weicht von Return-Path-Domain ({rp_domain}) ab.")

    # Display name vs domain inconsistency
    if from_addr:
        # Check if display name contains a different domain
        parts = from_addr.split("<")
        if len(parts) == 2:
            display_name = parts[0].strip().strip('"').lower()
            email_domain = _get_domain(parts[1])
            domain_in_name = re.search(r"[\w-]+\.(com|org|net|de|io|co)", display_name)
            if domain_in_name and email_domain and domain_in_name.group(0) != email_domain:
                add("critical", "Display-Name / Domain-Inkonsistenz",
                    f"Der Anzeigename enthält '{domain_in_name.group(0)}', aber die tatsächliche Domain ist '{email_domain}'.")

    # Received chain anomalies
    received_chain = parsed.get("received_chain", [])
    if len(received_chain) > 8:
        add("info", "Lange Received-Kette", f"{len(received_chain)} Received-Header gefunden. Ungewöhnlich lang.")

    # Bulk / marketing headers
    structured = parsed.get("structured_headers", {})
    bulk_found = []
    for header in BULK_HEADERS:
        for key in structured:
            if key.lower() == header:
                bulk_found.append(key)
    if bulk_found:
        add("info", "Massen-/Marketing-Header erkannt",
            f"Gefundene Header: {', '.join(bulk_found)}. Deutet auf Newsletter/Werbung hin.")

    # Spam confidence headers
    for header in SPAM_HEADERS:
        for key in structured:
            if key.lower() == header:
                val = structured[key] if isinstance(structured[key], str) else str(structured[key])
                if any(w in val.lower() for w in ["spam", "high", "bulk", "phish"]):
                    add("warning", f"Spam-Header erkannt: {key}",
                        f"Wert: {val[:200]}")

    # SCL / SFV hints (Microsoft)
    auth_or_antispam = parsed.get("authentication_results", "") + " " + structured.get("X-Forefront-Antispam-Report", "")
    scl_match = re.search(r"SCL[=:](\d+)", auth_or_antispam, re.IGNORECASE)
    if scl_match:
        scl = int(scl_match.group(1))
        if scl >= 5:
            add("warning", f"Hoher SCL-Wert: {scl}", "Microsoft Spam Confidence Level >= 5 deutet auf Spam hin.")

    return findings
