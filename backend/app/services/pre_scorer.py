"""Deterministic pre-scoring before LLM assessment."""


def compute_pre_scores(
    header_findings: list[dict],
    links: list[dict],
    external_results: list[dict],
) -> dict:
    """Compute phishing, advertising, and legitimacy likelihood scores.

    Args:
        header_findings: list of header analysis findings
        links: list of link analysis dicts (with flags)
        external_results: list of external check results
    """
    phishing = 0.0
    advertising = 0.0
    legitimacy = 50.0  # start neutral

    findings = []

    # Header findings
    for f in header_findings:
        sev = f.get("severity", "info")
        title = f.get("title", "")

        if "SPF fehlgeschlagen" in title:
            phishing += 20
            legitimacy -= 15
            findings.append({"factor": "spf_fail", "impact": "phishing+20", "detail": title})
        elif "Kein SPF" in title:
            phishing += 5
            findings.append({"factor": "spf_missing", "impact": "phishing+5", "detail": title})

        if "DKIM fehlgeschlagen" in title:
            phishing += 15
            legitimacy -= 10
            findings.append({"factor": "dkim_fail", "impact": "phishing+15", "detail": title})
        elif "Kein DKIM" in title:
            phishing += 5
            findings.append({"factor": "dkim_missing", "impact": "phishing+5", "detail": title})

        if "DMARC fehlgeschlagen" in title:
            phishing += 20
            legitimacy -= 15
            findings.append({"factor": "dmarc_fail", "impact": "phishing+20", "detail": title})

        if "Mismatch" in title and sev == "critical":
            phishing += 15
            findings.append({"factor": "header_mismatch", "impact": "phishing+15", "detail": title})
        elif "Mismatch" in title:
            phishing += 8
            findings.append({"factor": "header_mismatch_minor", "impact": "phishing+8", "detail": title})

        if "Display-Name" in title and "Inkonsistenz" in title:
            phishing += 15
            findings.append({"factor": "display_name_spoof", "impact": "phishing+15", "detail": title})

        if "Massen" in title or "Marketing" in title:
            advertising += 25
            findings.append({"factor": "bulk_headers", "impact": "advertising+25", "detail": title})

        if "Spam-Header" in title or "SCL" in title:
            phishing += 10
            advertising += 10
            findings.append({"factor": "spam_header", "impact": "phishing+10, advertising+10", "detail": title})

    # Link analysis
    domains = set()
    for link in links:
        hostname = link.get("hostname", "")
        if hostname:
            domains.add(hostname)

        if link.get("has_display_mismatch"):
            phishing += 15
            findings.append({"factor": "display_mismatch", "impact": "phishing+15", "detail": f"URL display mismatch: {hostname}"})
        if link.get("is_shortener"):
            phishing += 8
            findings.append({"factor": "url_shortener", "impact": "phishing+8", "detail": f"URL-Shortener: {hostname}"})
        if link.get("is_punycode"):
            phishing += 12
            findings.append({"factor": "punycode", "impact": "phishing+12", "detail": f"Punycode-Domain: {hostname}"})
        if link.get("is_ip_literal"):
            phishing += 15
            findings.append({"factor": "ip_literal", "impact": "phishing+15", "detail": f"IP-basierte URL: {hostname}"})
        if link.get("is_suspicious_tld"):
            phishing += 10
            findings.append({"factor": "suspicious_tld", "impact": "phishing+10", "detail": f"Verdächtige TLD: {hostname}"})
        if link.get("is_tracking_heavy"):
            advertising += 8
            findings.append({"factor": "tracking_heavy", "impact": "advertising+8", "detail": f"Tracking-URL: {hostname}"})

    # Multiple unrelated domains
    if len(domains) > 5:
        phishing += 10
        findings.append({"factor": "many_domains", "impact": "phishing+10", "detail": f"{len(domains)} verschiedene Domains in Links"})

    # External check results
    total_malicious = 0
    total_suspicious = 0
    for result in external_results:
        total_malicious += result.get("malicious_count", 0)
        total_suspicious += result.get("suspicious_count", 0)

    if total_malicious > 0:
        phishing += min(total_malicious * 10, 30)
        findings.append({"factor": "vt_malicious", "impact": f"phishing+{min(total_malicious * 10, 30)}", "detail": f"{total_malicious} als bösartig erkannte URL(s)"})
    if total_suspicious > 0:
        phishing += min(total_suspicious * 5, 15)
        findings.append({"factor": "vt_suspicious", "impact": f"phishing+{min(total_suspicious * 5, 15)}", "detail": f"{total_suspicious} als verdächtig erkannte URL(s)"})

    # Normalize to 0-100
    phishing = min(int(phishing), 100)
    advertising = min(int(advertising), 100)
    legitimacy = max(0, min(int(legitimacy), 100))

    # If neither phishing nor advertising is high, legitimacy increases
    if phishing < 20 and advertising < 20:
        legitimacy = min(legitimacy + 20, 100)

    return {
        "phishing_likelihood_score": phishing,
        "advertising_likelihood_score": advertising,
        "legitimacy_likelihood_score": legitimacy,
        "findings": findings,
    }


def deterministic_assessment(scores: dict, findings: list[dict]) -> dict:
    """Produce a deterministic assessment when LLM is disabled or fails."""
    phishing = scores["phishing_likelihood_score"]
    advertising = scores["advertising_likelihood_score"]

    if phishing >= 60:
        return {
            "classification": "phishing",
            "risk_score": phishing,
            "confidence": min(phishing, 85),
            "recommended_action": "delete",
            "rationale": f"Deterministische Analyse: Hohe Phishing-Wahrscheinlichkeit ({phishing}/100) basierend auf {len(findings)} Befunden.",
            "evidence": [f["detail"] for f in findings[:10]],
            "analyst_summary": "Die automatische Analyse hat starke Phishing-Indikatoren erkannt. Die E-Mail sollte gelöscht werden.",
        }
    elif phishing >= 35:
        return {
            "classification": "suspicious",
            "risk_score": phishing,
            "confidence": min(phishing, 70),
            "recommended_action": "manual_review",
            "rationale": f"Deterministische Analyse: Mittlere Phishing-Wahrscheinlichkeit ({phishing}/100). Manuelle Prüfung empfohlen.",
            "evidence": [f["detail"] for f in findings[:10]],
            "analyst_summary": "Die E-Mail weist einige verdächtige Merkmale auf und sollte manuell geprüft werden.",
        }
    elif advertising >= 30:
        return {
            "classification": "advertising",
            "risk_score": max(10, phishing),
            "confidence": min(advertising, 80),
            "recommended_action": "allow",
            "rationale": f"Deterministische Analyse: Wahrscheinlich Werbung/Newsletter (Advertising-Score: {advertising}/100).",
            "evidence": [f["detail"] for f in findings[:10]],
            "analyst_summary": "Die E-Mail scheint ein Newsletter oder Werbung zu sein. Nicht bösartig, aber möglicherweise unerwünscht.",
        }
    else:
        return {
            "classification": "legitimate",
            "risk_score": phishing,
            "confidence": min(60 + (100 - phishing) // 3, 90),
            "recommended_action": "allow",
            "rationale": f"Deterministische Analyse: Geringe Phishing-Wahrscheinlichkeit ({phishing}/100). Keine auffälligen Befunde.",
            "evidence": [f["detail"] for f in findings[:10]] if findings else ["Keine auffälligen Befunde"],
            "analyst_summary": "Die automatische Analyse hat keine starken Bedrohungsindikatoren erkannt.",
        }
