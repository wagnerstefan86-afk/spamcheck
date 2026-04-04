"""Deterministic Decision Engine for email security analysis.

Python port of the TypeScript Decision Engine from frontend/src/lib/analysis/.
Produces a structured analysis_summary without any LLM dependency.

This is the central intelligence of the backend service, designed for
consumption by Copilot Studio via the /summary API endpoint.
"""

import re
from typing import Optional


# ─── Content Risk Patterns ──────────────────────────────────────────────────

CONTENT_RISK_PATTERNS = [
    # Account threats
    ("account_threat", re.compile(r"konto.{0,20}(gesperrt|deaktiviert|eingeschränkt|suspendiert|geschlossen)", re.I)),
    ("account_threat", re.compile(r"account.{0,20}(suspended|locked|disabled|restricted|closed|terminated)", re.I)),
    ("account_threat", re.compile(r"(sperrung|deaktivierung|einschränkung).{0,20}(ihres?|your).{0,20}(konto|account)", re.I)),
    # Urgent action
    ("urgent_action", re.compile(r"(sofort|umgehend|dringend|innerhalb von \d+).{0,30}(handeln|bestätigen|reagieren|erneuern|verifizieren|aktualisieren)", re.I)),
    ("urgent_action", re.compile(r"(immediate|urgent|within \d+).{0,30}(action|verify|confirm|renew|update|respond)", re.I)),
    ("urgent_action", re.compile(r"letzte (mahnung|warnung|aufforderung|erinnerung)", re.I)),
    ("urgent_action", re.compile(r"(final|last) (warning|notice|reminder)", re.I)),
    # Credential lures
    ("credential_lure", re.compile(r"(passwort|kennwort|password).{0,20}(abgelaufen|erneuern|bestätigen|zurücksetzen|ändern|expired|renew|confirm|reset)", re.I)),
    ("credential_lure", re.compile(r"(login|anmeldung|identität|identity).{0,20}(bestätigen|verifizieren|confirm|verify)", re.I)),
    ("credential_lure", re.compile(r"klicken sie.{0,30}(bestätigen|verifizieren|einloggen|anmelden)", re.I)),
    ("credential_lure", re.compile(r"click.{0,30}(verify|confirm|sign.?in|log.?in)", re.I)),
    # Payment lures
    ("payment_lure", re.compile(r"(zahlung|payment|transaktion|transaction).{0,20}(fehlgeschlagen|abgelehnt|ausstehend|failed|declined|pending)", re.I)),
    ("payment_lure", re.compile(r"(rechnung|invoice|abbuchung).{0,20}(überfällig|offen|unbezahlt|overdue|outstanding)", re.I)),
    # Deletion threats
    ("deletion_threat", re.compile(r"(daten|fotos|dateien|files|photos|videos|account).{0,30}(gelöscht|werden gelöscht|permanently deleted|will be deleted)", re.I)),
    ("deletion_threat", re.compile(r"(löschung|deletion).{0,20}(ihrer|your|aller)", re.I)),
    # Generic branding
    ("generic_branding", re.compile(r"sehr geehrte[rs]? (kunde|kundin|nutzer|nutzerin|mitglied|user)", re.I)),
    ("generic_branding", re.compile(r"dear (customer|user|member|valued|account holder)", re.I)),
]

STRONG_CONTENT_TYPES = {"account_threat", "credential_lure", "payment_lure", "deletion_threat"}


# ─── Identity Assessment ────────────────────────────────────────────────────

def _extract_domain(address: str | None) -> str | None:
    if not address:
        return None
    m = re.search(r"@([a-zA-Z0-9.-]+)", address)
    return m.group(1).lower() if m else None


def _parse_auth_results(auth_results: str | None) -> dict[str, str]:
    results = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    if not auth_results:
        return results
    for proto in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{proto}\s*=\s*(\w+)", auth_results, re.I)
        if m:
            status = m.group(1).lower()
            if status in ("pass",):
                results[proto] = "pass"
            elif status in ("fail", "hardfail"):
                results[proto] = "fail"
            elif status in ("softfail",):
                results[proto] = "softfail"
            elif status in ("none",):
                results[proto] = "none"
            elif status in ("neutral",):
                results[proto] = "neutral"
            else:
                results[proto] = "unknown"
    return results


def _detect_bulk_sender(header_findings: list[dict], structured_headers: dict,
                        classification: str | None) -> bool:
    for f in header_findings:
        title = f.get("title", "")
        detail = f.get("detail", "")
        if re.search(r"massen|marketing|bulk", title, re.I):
            return True
        if re.search(r"list.?unsubscribe", title, re.I) or re.search(r"list.?unsubscribe", detail, re.I):
            return True
    for key in structured_headers:
        if key.lower() in ("list-unsubscribe",):
            return True
        if key.lower() == "precedence" and str(structured_headers[key]).lower() == "bulk":
            return True
    if classification == "advertising":
        return True
    return False


def assess_identity(
    parsed: dict,
    header_findings: list[dict],
    structured_headers: dict,
    classification: str | None,
) -> dict:
    from_domain = _extract_domain(parsed.get("from", ""))
    reply_to_domain = _extract_domain(parsed.get("reply_to", ""))
    return_path_domain = _extract_domain(parsed.get("return_path", ""))
    auth = _parse_auth_results(parsed.get("authentication_results", ""))
    is_bulk = _detect_bulk_sender(header_findings, structured_headers, classification)

    domains = [d for d in (from_domain, reply_to_domain, return_path_domain) if d]
    unique = list(set(domains))

    consistency = "consistent"
    detail = "Alle Absender-Domains stimmen überein."

    if len(unique) > 1:
        has_auth_fail = auth.get("spf") == "fail" or auth.get("dkim") == "fail"
        if has_auth_fail:
            consistency = "suspicious"
            detail = "Abweichende Domains bei fehlgeschlagener Authentifizierung."
        elif is_bulk:
            consistency = "partial_mismatch"
            detail = "Abweichende Domains — typisch für Mailing-Dienste."
        else:
            consistency = "partial_mismatch"
            detail = "Abweichende Domains — manuelle Prüfung empfohlen."
    elif len(domains) == 0:
        consistency = "partial_mismatch"
        detail = "Keine Absender-Domain extrahierbar."

    return {
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
        "consistency": consistency,
        "consistency_detail": detail,
        "is_bulk_sender": is_bulk,
        "auth_spf": auth.get("spf"),
        "auth_dkim": auth.get("dkim"),
        "auth_dmarc": auth.get("dmarc"),
    }


# ─── Link Stats ─────────────────────────────────────────────────────────────

FAILURE_STATUSES = {"rate_limited", "timeout", "api_error", "submit_failed", "invalid_response"}
SKIPPED_STATUSES = {"skipped", "not_executed"}


def summarize_links(links: list[dict]) -> dict:
    """Compute link statistics from link objects with external_checks."""
    malicious = 0
    suspicious = 0
    total = len(links)
    provider_scans_total = 0
    provider_scans_successful = 0
    provider_scans_failed = 0
    provider_scans_skipped = 0
    links_fully_analyzed = 0
    links_partially_analyzed = 0
    links_without_result = 0

    verdicts = {"clean": 0, "suspicious": 0, "malicious": 0, "unknown": 0,
                "partially_analyzed": 0, "not_checked": 0}

    for link in links:
        verdict = link.get("verdict", "unknown")
        if verdict in verdicts:
            verdicts[verdict] += 1
        else:
            verdicts["unknown"] += 1

        checks = link.get("external_checks", [])
        non_skipped = 0
        fetched = 0

        for check in checks:
            provider_scans_total += 1
            scan_status = check.get("scan_status", "")
            if scan_status in SKIPPED_STATUSES:
                provider_scans_skipped += 1
                continue
            non_skipped += 1
            if check.get("result_fetched"):
                fetched += 1
                provider_scans_successful += 1
                malicious += check.get("malicious_count", 0)
                suspicious += check.get("suspicious_count", 0)
            elif scan_status in FAILURE_STATUSES or check.get("status") in ("error", "timeout", "failed"):
                provider_scans_failed += 1
            elif check.get("status") == "completed":
                provider_scans_successful += 1

        if non_skipped == 0:
            links_without_result += 1
        elif fetched >= non_skipped:
            links_fully_analyzed += 1
        elif fetched > 0:
            links_partially_analyzed += 1
        else:
            links_without_result += 1

    # Coverage
    attempted = provider_scans_total - provider_scans_skipped
    coverage_percent = round((provider_scans_successful / attempted) * 100) if attempted > 0 else None

    if total == 0:
        coverage = "none"
    elif verdicts["not_checked"] == total:
        coverage = "not_checked"
    elif links_fully_analyzed == 0 and links_partially_analyzed == 0:
        coverage = "unknown"
    elif links_fully_analyzed == total:
        coverage = "clean"
    elif links_fully_analyzed > 0 or links_partially_analyzed > 0:
        coverage = "partially_analyzed"
    else:
        coverage = "unknown"

    return {
        "total_links": total,
        "malicious": malicious,
        "suspicious": suspicious,
        "clean": verdicts["clean"],
        "coverage": coverage,
        "coverage_percent": coverage_percent,
        "links_fully_analyzed": links_fully_analyzed,
        "links_partially_analyzed": links_partially_analyzed,
        "links_without_result": links_without_result,
        "provider_scans_total": provider_scans_total,
        "provider_scans_successful": provider_scans_successful,
        "provider_scans_failed": provider_scans_failed,
        "verdicts": verdicts,
    }


# ─── Content Risk Detection ─────────────────────────────────────────────────

def detect_content_risks(subject: str, body_text: str, evidence: list[str],
                         classification: str | None) -> list[dict]:
    matches = []
    seen = set()
    body_preview = body_text[:500] if body_text else ""

    sources = [("subject", subject), ("body", body_preview)]
    for ev in evidence:
        sources.append(("evidence", ev))

    for source_name, text in sources:
        if not text:
            continue
        for risk_type, pattern in CONTENT_RISK_PATTERNS:
            if risk_type not in seen and pattern.search(text):
                matches.append({
                    "type": risk_type,
                    "source": source_name,
                    "matched_text": text[:100],
                })
                seen.add(risk_type)

    if classification in ("phishing", "scam") and "credential_lure" not in seen:
        matches.append({"type": "credential_lure", "source": "evidence",
                        "matched_text": f"classification: {classification}"})

    return matches


def assess_content_risk_level(matches: list[dict]) -> str:
    if not matches:
        return "none"
    types = {m["type"] for m in matches}
    strong = [t for t in STRONG_CONTENT_TYPES if t in types]
    has_urgent = "urgent_action" in types

    if len(strong) >= 2:
        return "high"
    if strong and has_urgent:
        return "high"
    if strong:
        return "high"
    return "low"


# ─── Signal Normalization ───────────────────────────────────────────────────

def _derive_canonical_key(key: str) -> str:
    parts = key.split(":")
    if parts[0] in ("auth", "links") and len(parts) >= 3:
        return f"{parts[0]}:{parts[1]}"
    return key


def _severity_to_tier(severity: str) -> int:
    return {"critical": 5, "noteworthy": 3, "positive": 2, "context": 1}.get(severity, 1)


def _severity_to_direction(severity: str) -> str:
    return "positive" if severity in ("positive", "context") else "negative"


def _key_to_domain(key: str) -> str:
    prefix = key.split(":")[0]
    return {"auth": "auth", "identity": "identity", "links": "links",
            "bulk": "bulk", "reputation": "links"}.get(prefix, "content")


def _key_to_category(key: str) -> str:
    if key.startswith("auth:"):
        return "authentication"
    if key.startswith("identity:"):
        return "identity_consistency"
    if any(key.startswith(p) for p in ("links:malicious", "links:suspicious", "links:clean")):
        return "link_reputation"
    if key.startswith("links:structural"):
        return "link_structure"
    if key.startswith("bulk:"):
        return "bulk_context"
    if key.startswith("content:"):
        return "content_risk"
    if key.startswith("reputation:") or key.startswith("links:unknown") or key.startswith("links:not_checked") or key.startswith("links:partial"):
        return "reputation_coverage"
    return "content_analysis"


def _make_signal(key: str, label: str, severity: str, tier: int,
                 domain: str, category: str, direction: str | None = None,
                 promotable: bool = True, downgrade_eligible: bool = False) -> dict:
    return {
        "key": key,
        "canonical_key": _derive_canonical_key(key),
        "label": label,
        "severity": severity,
        "tier": tier,
        "direction": direction or _severity_to_direction(severity),
        "domain": domain,
        "category": category,
        "promotable": promotable,
        "downgrade_eligible": downgrade_eligible,
    }


def normalize_signals(identity: dict, link_stats: dict, content_risk_level: str,
                      content_risks: list[dict], header_findings: list[dict],
                      det_findings: list[dict], assessment: dict) -> list[dict]:
    """Central signal normalization — single source of truth."""
    signals = []
    seen_canonical = set()

    is_bulk = identity.get("is_bulk_sender", False)
    has_hard_critical = (
        identity.get("auth_spf") == "fail" or identity.get("auth_dkim") == "fail"
        or link_stats.get("malicious", 0) > 0
        or identity.get("consistency") == "suspicious"
        or any(re.search(r"display.?name.*(inkonsistenz|spoof)", f.get("title", ""), re.I)
               for f in header_findings)
    )
    auth_passed = sum(1 for p in ("auth_spf", "auth_dkim", "auth_dmarc")
                      if identity.get(p) == "pass")
    bulk_downgrade_allowed = is_bulk and not has_hard_critical and auth_passed >= 2

    # 1. Auth signals
    for proto in ("spf", "dkim", "dmarc"):
        status = identity.get(f"auth_{proto}", "unknown")
        if status in ("unknown", "neutral"):
            continue
        is_pass = status == "pass"
        key = f"auth:{proto}:{status}"
        label = f"{proto.upper()} bestanden" if is_pass else (
            f"{proto.upper()} fehlgeschlagen" if status == "fail" else f"{proto.upper()} {status}")
        sev = "positive" if is_pass else ("critical" if status == "fail" else "noteworthy")
        tier = 2 if is_pass else (5 if status == "fail" else 3)
        signals.append(_make_signal(key, label, sev, tier, "auth", "authentication"))
        seen_canonical.add(_derive_canonical_key(key))

    # 2. Identity consistency
    cons = identity.get("consistency", "consistent")
    if cons == "consistent":
        signals.append(_make_signal("identity:consistent", "Konsistente Absenderidentität",
                                     "positive", 2, "identity", "identity_consistency"))
    elif cons == "suspicious":
        signals.append(_make_signal("identity:suspicious", "Verdächtige Identitätsabweichung",
                                     "critical", 5, "identity", "identity_consistency"))
    else:
        sev = "noteworthy" if (is_bulk and bulk_downgrade_allowed) else "critical"
        tier = 3 if sev == "noteworthy" else 4
        signals.append(_make_signal("identity:mismatch",
                                     "Domain-Abweichung (From/Reply-To/Return-Path)",
                                     sev, tier, "identity", "identity_consistency",
                                     downgrade_eligible=True))

    # 3. Link signals
    mal = link_stats.get("malicious", 0)
    sus = link_stats.get("suspicious", 0)
    total = link_stats.get("total_links", 0)
    cov = link_stats.get("coverage", "none")

    if mal > 0:
        signals.append(_make_signal(f"links:malicious:{mal}",
                                     f"{mal} maliziöse Link-Bewertungen",
                                     "critical", 5, "links", "link_reputation"))
    if sus > 0:
        signals.append(_make_signal(f"links:suspicious:{sus}",
                                     f"{sus} verdächtige Link-Bewertungen",
                                     "noteworthy", 3, "links", "link_reputation"))

    # Reputation coverage
    if total > 0 and mal == 0:
        if cov == "clean":
            signals.append(_make_signal("links:clean",
                                         "Keine negativen Reputationstreffer erkannt",
                                         "positive", 2, "links", "link_reputation"))
        elif cov == "partially_analyzed":
            signals.append(_make_signal("links:partial",
                                         "Keine negativen Treffer in verfügbaren Ergebnissen — Bewertung unvollständig",
                                         "context", 1, "links", "reputation_coverage",
                                         direction="positive"))
        elif cov == "not_checked":
            signals.append(_make_signal("links:not_checked",
                                         "Keine belastbare Reputationsbewertung verfügbar",
                                         "noteworthy", 3, "links", "reputation_coverage",
                                         direction="negative"))
        elif cov == "unknown":
            signals.append(_make_signal("links:unknown",
                                         "Reputationsbewertung nicht belastbar",
                                         "noteworthy", 3, "links", "reputation_coverage",
                                         direction="negative"))

    # 4. Bulk context
    if is_bulk:
        signals.append(_make_signal("bulk:detected", "Newsletter-/Mailing-Dienst erkannt",
                                     "context", 1, "bulk", "bulk_context"))

    # 5. Display-Name spoofing
    for f in header_findings:
        if re.search(r"display.?name.*(inkonsistenz|spoof)", f.get("title", ""), re.I):
            if "identity:spoofing" not in seen_canonical:
                signals.append(_make_signal("identity:spoofing",
                                             "Display-Name-Spoofing erkannt",
                                             "critical", 5, "identity", "identity_consistency"))
                seen_canonical.add("identity:spoofing")
            break

    # 6. Content risk signals
    content_labels = {
        "account_threat": "Kontosperrung/-bedrohung im Inhalt",
        "urgent_action": "Dringlichkeits-/Handlungsdruck",
        "credential_lure": "Aufforderung zur Passwort-/Login-Eingabe",
        "payment_lure": "Zahlungsaufforderung/-drohung",
        "generic_branding": "Generische Anrede ohne persönlichen Bezug",
        "deletion_threat": "Löschungsdrohung für Daten/Konto",
    }
    seen_content = set()
    for risk in content_risks:
        rt = risk["type"]
        if rt in seen_content:
            continue
        seen_content.add(rt)
        key = f"content:{rt}"
        sev = "noteworthy" if rt == "generic_branding" else "critical"
        tier = 3 if rt == "generic_branding" else 5
        signals.append(_make_signal(key, content_labels.get(rt, rt),
                                     sev, tier, "content", "content_risk"))

    # 7. High content risk: demote auth passes and clean links
    if content_risk_level == "high":
        for s in signals:
            if s["domain"] == "auth" and s["direction"] == "positive":
                s["severity"] = "context"
                s["tier"] = 1
                s["promotable"] = False
            if s["key"] == "links:clean":
                s["severity"] = "context"
                s["tier"] = 1
                s["promotable"] = False
                s["label"] = "Keine negativen Reputationstreffer, aber Bewertung nicht ausreichend zur Entlastung"
            if s["key"] == "links:partial":
                s["severity"] = "context"
                s["tier"] = 1
                s["promotable"] = False

    # Reputation gap demotes clean
    has_rep_gap = any(s["key"] in ("reputation:unknown", "links:unknown", "links:not_checked")
                      for s in signals)
    if has_rep_gap:
        for s in signals:
            if s["key"] == "links:clean":
                s["severity"] = "context"
                s["tier"] = 1
                s["promotable"] = False

    return signals


# ─── Decision Factors ───────────────────────────────────────────────────────

MAX_FACTORS = 4


def extract_decision_factors(signals: list[dict]) -> dict:
    promotable = [s for s in signals if s.get("promotable")]
    negative = sorted(
        [s for s in promotable if s["direction"] == "negative" and s["tier"] >= 3],
        key=lambda s: -s["tier"]
    )[:MAX_FACTORS]
    positive = sorted(
        [s for s in promotable if s["direction"] == "positive" and s["tier"] >= 1],
        key=lambda s: -s["tier"]
    )[:MAX_FACTORS]

    return {
        "negative": [{"key": s["key"], "label": s["label"], "tier": s["tier"]} for s in negative],
        "positive": [{"key": s["key"], "label": s["label"], "tier": s["tier"]} for s in positive],
    }


# ─── Conflict Assessment ───────────────────────────────────────────────────

def assess_conflict(signals: list[dict], identity: dict) -> dict:
    positives = [s for s in signals if s["direction"] == "positive" and s["tier"] >= 2]
    negatives = [s for s in signals if s["direction"] == "negative" and s["tier"] >= 3]
    has_conflict = len(positives) > 0 and len(negatives) > 0

    if not has_conflict:
        return {"has_conflict": False, "dominant_signal": None,
                "bulk_downgrade_applied": False, "bulk_downgrade_blocked": False}

    dominant = sorted(negatives, key=lambda s: -s["tier"])[0]
    is_bulk = identity.get("is_bulk_sender", False)
    auth_passed = sum(1 for p in ("auth_spf", "auth_dkim", "auth_dmarc")
                      if identity.get(p) == "pass")
    hard_criticals = [s for s in signals if s["tier"] == 5 and s["direction"] == "negative"]
    bulk_allowed = is_bulk and len(hard_criticals) == 0 and auth_passed >= 2

    return {
        "has_conflict": True,
        "dominant_signal": dominant["key"],
        "bulk_downgrade_applied": is_bulk and bulk_allowed,
        "bulk_downgrade_blocked": is_bulk and not bulk_allowed,
    }


# ─── Action Decision Engine V1 ─────────────────────────────────────────────

def compute_action_decision(
    content_risk_level: str,
    signals: list[dict],
    identity: dict,
    link_stats: dict,
    conflict: dict,
) -> dict:
    """Deterministic 3-level action decision: open / manual_review / do_not_open."""

    # ─── Hard "do_not_open" rules ───
    if content_risk_level == "high":
        driver = next((s["key"] for s in signals
                       if s["domain"] == "content" and s["direction"] == "negative"), "content:high_risk")
        return {
            "action": "do_not_open",
            "label": "Nicht öffnen",
            "reason": "Die E-Mail zeigt starke Hinweise auf Phishing oder Missbrauch. Öffnen Sie keine Links oder Anhänge.",
            "primary_driver": driver,
        }

    spoofing = any(s["key"] == "identity:spoofing" for s in signals)
    if spoofing:
        return {
            "action": "do_not_open",
            "label": "Nicht öffnen",
            "reason": "Es wurden Anzeichen für Absender-Spoofing erkannt. Interagieren Sie nicht mit dieser E-Mail.",
            "primary_driver": "identity:spoofing",
        }

    if link_stats.get("malicious", 0) > 0:
        driver = next((s["key"] for s in signals if s["key"].startswith("links:malicious")), "links:malicious")
        return {
            "action": "do_not_open",
            "label": "Nicht öffnen",
            "reason": "Mindestens ein Link wurde von Reputationsdiensten als schädlich eingestuft.",
            "primary_driver": driver,
        }

    hard_neg = next((s for s in signals if s["tier"] == 5 and s["direction"] == "negative"
                     and s["domain"] != "content"), None)
    if hard_neg and identity.get("consistency") == "suspicious":
        return {
            "action": "do_not_open",
            "label": "Nicht öffnen",
            "reason": "Kritische Sicherheitsbefunde in Kombination mit verdächtiger Absenderidentität.",
            "primary_driver": hard_neg["key"],
        }

    # ─── "open" eligibility ───
    has_hard_neg = any(s["tier"] >= 5 and s["direction"] == "negative" for s in signals)
    has_medium_neg = any(s["tier"] >= 3 and s["direction"] == "negative"
                         and s.get("category") != "reputation_coverage" for s in signals)

    auth_pass_count = sum(1 for p in ("auth_spf", "auth_dkim", "auth_dmarc")
                          if identity.get(p) == "pass")
    identity_ok = identity.get("consistency") in ("consistent", "partial_mismatch")
    cov = link_stats.get("coverage", "none")

    strong_evidence = (
        cov in ("clean", "none")
        and auth_pass_count >= 2
        and identity_ok
    )
    adequate_evidence = (
        cov in ("clean", "partially_analyzed", "none")
        and auth_pass_count >= 1
        and identity_ok
    )

    if not has_hard_neg and not has_medium_neg and strong_evidence:
        return {
            "action": "open",
            "label": "Öffnen",
            "reason": "Es wurden keine relevanten Risikosignale erkannt. Die E-Mail kann geöffnet werden.",
            "primary_driver": None,
        }

    if (identity.get("is_bulk_sender") and not has_hard_neg and adequate_evidence
            and conflict.get("bulk_downgrade_applied")):
        return {
            "action": "open",
            "label": "Öffnen",
            "reason": "Newsletter/Mailing-Dienst mit gültiger Authentifizierung erkannt.",
            "primary_driver": "bulk:detected",
        }

    # ─── "manual_review" — default ───
    reason = "Die Bewertung ist nicht eindeutig. Bitte prüfen Sie die E-Mail sorgfältig oder leiten Sie sie an die IT-Sicherheit weiter."
    driver = None

    if has_hard_neg:
        neg = next((s for s in signals if s["tier"] >= 5 and s["direction"] == "negative"), None)
        reason = "Es bestehen sicherheitsrelevante Auffälligkeiten. Bitte prüfen Sie die E-Mail sorgfältig."
        driver = neg["key"] if neg else None
    elif cov in ("unknown", "not_checked"):
        reason = "Die Reputationsbewertung ist nicht belastbar. Eine abschließende Einschätzung ist nicht möglich."
        driver = "reputation:insufficient"
    elif cov == "partially_analyzed":
        reason = "Die Reputationsprüfung ist unvollständig. Bitte behandeln Sie die E-Mail mit Vorsicht."
        driver = "reputation:partial"
    elif conflict.get("has_conflict"):
        reason = "Es liegen widersprüchliche Signale vor. Bitte prüfen Sie die E-Mail sorgfältig."
        driver = conflict.get("dominant_signal")
    elif link_stats.get("suspicious", 0) > 0:
        reason = "Mindestens ein Link wurde als verdächtig eingestuft. Bitte seien Sie vorsichtig."
        driver = next((s["key"] for s in signals if s["key"].startswith("links:suspicious")), None)

    return {
        "action": "manual_review",
        "label": "Vorsicht – bitte prüfen",
        "reason": reason,
        "primary_driver": driver,
    }


# ─── Escalation Hint ───────────────────────────────────────────────────────

def _compute_escalation_hint(action: dict, content_risk_level: str,
                              identity: dict, link_stats: dict) -> str | None:
    if action["action"] == "do_not_open":
        if content_risk_level == "high":
            return "Weiterleitung an IT-Sicherheit empfohlen: Starke Phishing-Indikatoren im Inhalt erkannt."
        if link_stats.get("malicious", 0) > 0:
            return "Weiterleitung an IT-Sicherheit empfohlen: Schädliche Links erkannt."
        if identity.get("consistency") == "suspicious":
            return "Weiterleitung an IT-Sicherheit empfohlen: Verdächtige Absenderidentität."
        return "Weiterleitung an IT-Sicherheit empfohlen."
    if action["action"] == "manual_review":
        if action.get("primary_driver", "").startswith("reputation:"):
            return "Ergebnis nicht belastbar — bei Unsicherheit IT-Sicherheit konsultieren."
    return None


# ─── Main Entry Point ──────────────────────────────────────────────────────

def compute_analysis_summary(
    parsed: dict,
    header_findings: list[dict],
    links: list[dict],
    scores: dict,
    assessment: dict,
    reputation_stats: dict,
    structured_headers: dict | None = None,
) -> dict:
    """Compute the complete analysis_summary — the primary Copilot data contract.

    Args:
        parsed: Parsed email data (from/reply_to/return_path/subject/body_text/authentication_results)
        header_findings: From header analyzer
        links: Link dicts with external_checks and verdict
        scores: From pre_scorer (phishing/advertising/legitimacy + findings)
        assessment: The deterministic assessment (classification/risk_score/confidence/...)
        reputation_stats: From _compute_reputation_stats
        structured_headers: Optional structured headers for bulk detection

    Returns:
        Complete analysis_summary dict ready for DB storage and API response.
    """
    classification = assessment.get("classification", "unknown")
    risk_score = assessment.get("risk_score", 0)
    confidence = assessment.get("confidence", 0)

    # Identity
    identity = assess_identity(
        parsed, header_findings,
        structured_headers or parsed.get("structured_headers", {}),
        classification,
    )

    # Link stats
    link_stats = summarize_links(links)

    # Content risk
    subject = parsed.get("subject", "")
    body_text = parsed.get("body_text", "")
    evidence = assessment.get("evidence", [])
    content_risks = detect_content_risks(subject, body_text, evidence, classification)
    content_risk_level = assess_content_risk_level(content_risks)

    # Signals
    det_findings = scores.get("findings", [])
    signals = normalize_signals(
        identity, link_stats, content_risk_level, content_risks,
        header_findings, det_findings, assessment,
    )

    # Decision factors
    factors = extract_decision_factors(signals)

    # Conflict
    conflict = assess_conflict(signals, identity)

    # Override check
    override_applied = content_risk_level == "high"

    # Action decision
    action = compute_action_decision(
        content_risk_level, signals, identity, link_stats, conflict,
    )

    # Escalation hint
    escalation = _compute_escalation_hint(action, content_risk_level, identity, link_stats)

    # Reputation summary
    rep_summary = {
        "total_links": link_stats["total_links"],
        "malicious": link_stats["malicious"],
        "suspicious": link_stats["suspicious"],
        "clean": link_stats["clean"],
        "coverage": link_stats["coverage"],
        "coverage_percent": link_stats["coverage_percent"],
        "links_fully_analyzed": link_stats["links_fully_analyzed"],
        "links_without_result": link_stats["links_without_result"],
    }

    # Build serializable signals (strip internal fields)
    serializable_signals = [
        {
            "key": s["key"],
            "canonical_key": s["canonical_key"],
            "label": s["label"],
            "severity": s["severity"],
            "tier": s["tier"],
            "direction": s["direction"],
            "domain": s["domain"],
            "category": s["category"],
        }
        for s in signals
    ]

    return {
        "version": 2,
        "action_decision": action,
        "action_label": action["label"],
        "action_reason": action["reason"],
        "classification": classification,
        "risk_score": risk_score,
        "confidence": confidence,
        "content_risk_level": content_risk_level,
        "decision_factors": factors,
        "identity_summary": identity,
        "reputation_summary": rep_summary,
        "signals": serializable_signals,
        "escalation_hint": escalation,
        "override_applied": override_applied,
    }
