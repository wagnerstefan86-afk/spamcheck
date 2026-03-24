/**
 * Evidence classification and analysis utilities.
 *
 * Classifies findings into four groups with finer fachliche Einordnung:
 * - critical: real security risks (auth failures, malicious URLs, identity spoofing)
 * - noteworthy: relevant but explainable deviations (mismatches in bulk context, high SCL)
 * - positive: legitimizing signals (auth pass, clean reputation, consistent identity)
 * - context: informational/neutral (marketing headers, tracking, technical metadata)
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export type EvidenceSeverity = "positive" | "noteworthy" | "critical" | "context";

export type EvidenceItem = {
  text: string;
  source: "evidence" | "header" | "link" | "auth" | "scoring";
  severity: EvidenceSeverity;
};

export type EvidenceGroups = {
  critical: EvidenceItem[];
  noteworthy: EvidenceItem[];
  positive: EvidenceItem[];
  context: EvidenceItem[];
};

export type AuthSignal = {
  protocol: "SPF" | "DKIM" | "DMARC";
  status: "pass" | "fail" | "none" | "softfail" | "neutral" | "unknown";
};

export type IdentityAssessment = {
  fromDomain: string | null;
  replyToDomain: string | null;
  returnPathDomain: string | null;
  authSignals: AuthSignal[];
  consistency: "consistent" | "partial_mismatch" | "suspicious";
  consistencyDetail: string;
  isBulkSender: boolean;
};

export type LinkStats = {
  total: number;
  malicious: number;
  suspicious: number;
  scansFailed: number;
  scansCompleted: number;
  criticalLinks: CriticalLink[];
};

export type CriticalLink = {
  link: any;
  reasons: string[];
};

export type ScoreDriver = {
  label: string;
  impact: string;
  direction: "positive" | "negative" | "neutral";
  category: "phishing" | "advertising" | "legitimacy";
};

// ─── Header Finding Classification ──────────────────────────────────────────
// Instead of mapping purely on severity, we classify based on the finding's
// actual title/content to avoid Newsletter artifacts looking like real risks.

/** Findings that are legitimizing (positive) regardless of backend severity */
const POSITIVE_FINDING_PATTERNS = [
  /spf.*(?:bestanden|pass)/i,
  /dkim.*(?:bestanden|pass)/i,
  /dmarc.*(?:bestanden|pass)/i,
  /authentifizierung.*(?:erfolgreich|valide)/i,
];

/** Findings that are contextual (neutral) — typical for bulk/marketing mail */
const CONTEXT_FINDING_PATTERNS = [
  /massen.*header|marketing.*header|bulk.*header/i,
  /list.?unsubscribe/i,
  /hoher scl/i,                // High SCL in marketing context is normal
  /spam.*header.*(?:scl|bcl)/i, // Spam confidence level headers
  /lange received/i,           // Long received chains are informational
];

/** Findings that are always critical — real security indicators */
const CRITICAL_FINDING_PATTERNS = [
  /spf.*fehlgeschlagen|spf.*fail/i,
  /dkim.*fehlgeschlagen|dkim.*fail/i,
  /dmarc.*fehlgeschlagen|dmarc.*fail/i,
  /display.?name.*(?:inkonsistenz|spoof)/i,
  /from.*reply.?to.*mismatch/i,   // only critical if NOT bulk context
];

/** Findings that are noteworthy — relevant but not automatically dangerous */
const NOTEWORTHY_FINDING_PATTERNS = [
  /return.?path.*mismatch/i,
  /kein.*(?:spf|dkim|dmarc)/i,  // Missing auth is noteworthy, not critical
];

function classifyHeaderFinding(
  title: string,
  detail: string,
  backendSeverity: string,
  isBulkMail: boolean
): EvidenceSeverity {
  const combined = `${title} ${detail}`;

  // 1. Check explicit positive patterns
  for (const p of POSITIVE_FINDING_PATTERNS) {
    if (p.test(combined)) return "positive";
  }

  // 2. Check context patterns (newsletter/marketing artifacts)
  for (const p of CONTEXT_FINDING_PATTERNS) {
    if (p.test(combined)) return "context";
  }

  // 3. Check critical patterns
  for (const p of CRITICAL_FINDING_PATTERNS) {
    if (p.test(combined)) {
      // Return-Path and From/Reply-To mismatches in bulk mail context
      // are typically caused by mailing services, not spoofing
      if (isBulkMail && /mismatch/i.test(combined)) return "noteworthy";
      return "critical";
    }
  }

  // 4. Check noteworthy patterns
  for (const p of NOTEWORTHY_FINDING_PATTERNS) {
    if (p.test(combined)) return "noteworthy";
  }

  // 5. Fallback: use backend severity, but downgrade "warning" in bulk context
  if (backendSeverity === "critical") return "critical";
  if (backendSeverity === "warning") {
    return isBulkMail ? "noteworthy" : "noteworthy";
  }
  return "positive";
}

// ─── Evidence Text Classification ───────────────────────────────────────────

const EVIDENCE_POSITIVE = [
  /spf.*(pass|erfolgreich|valide|bestanden)/i,
  /dkim.*(pass|erfolgreich|valide|bestanden)/i,
  /dmarc.*(pass|erfolgreich|valide|bestanden)/i,
  /keine.*(bösartig|malizi|suspicious|verdächtig|bedroh)/i,
  /no.*(malicious|suspicious|threat)/i,
  /reputation.*(gut|unauffällig|clean|good)/i,
  /authentif.*(erfolgreich|valide|bestanden)/i,
  /legitimate|legitim/i,
  /vertrauenswürdig|trusted/i,
];

const EVIDENCE_CRITICAL = [
  /phishing/i,
  /malicious|maliziös|bösartig/i,
  /spoofing|spoof/i,
  /spf.*(fail|none|softfail)/i,
  /dkim.*(fail|none)/i,
  /dmarc.*(fail|none|reject)/i,
  /verdächtig.*domain|suspicious.*domain/i,
  /identitätsabweichung|identity.*mismatch/i,
  /impersonat/i,
];

const EVIDENCE_CONTEXT = [
  /newsletter|marketing|bulk|mailing/i,
  /list.?unsubscribe|abmelde/i,
  /tracking|click.?tracking/i,
];

function classifyEvidenceText(text: string): EvidenceSeverity {
  for (const p of EVIDENCE_CRITICAL) {
    if (p.test(text)) return "critical";
  }
  for (const p of EVIDENCE_POSITIVE) {
    if (p.test(text)) return "positive";
  }
  for (const p of EVIDENCE_CONTEXT) {
    if (p.test(text)) return "context";
  }
  return "noteworthy";
}

// ─── Bulk Mail Detection ────────────────────────────────────────────────────

function detectBulkMail(result: any): boolean {
  const findings: any[] = result.header_findings || [];
  for (const f of findings) {
    if (/massen|marketing|bulk/i.test(f.title)) return true;
    if (/list.?unsubscribe/i.test(f.title) || /list.?unsubscribe/i.test(f.detail || "")) return true;
  }
  // Check structured headers if available
  const headers = result.structured_headers || {};
  if (headers["list-unsubscribe"] || headers["List-Unsubscribe"]) return true;
  if (headers["precedence"] === "bulk" || headers["Precedence"] === "bulk") return true;
  // Check classification
  if (result.assessment?.classification === "advertising") return true;
  return false;
}

// ─── Main Classification Function ───────────────────────────────────────────

export function classifyEvidence(result: any): EvidenceGroups {
  const groups: EvidenceGroups = { critical: [], noteworthy: [], positive: [], context: [] };
  const isBulk = detectBulkMail(result);

  // 1. Classify assessment evidence strings
  const evidence: string[] = result.assessment?.evidence || [];
  for (const e of evidence) {
    const severity = classifyEvidenceText(e);
    groups[severity].push({ text: e, source: "evidence", severity });
  }

  // 2. Classify header findings with fachliche Einordnung
  const findings: any[] = result.header_findings || [];
  for (const f of findings) {
    const severity = classifyHeaderFinding(f.title, f.detail || "", f.severity, isBulk);
    const text = f.detail ? `${f.title}: ${f.detail}` : f.title;
    groups[severity].push({ text, source: "header", severity });
  }

  // 3. Use deterministic_findings for additional context (if available)
  const detFindings: any[] = result.deterministic_findings || [];
  for (const df of detFindings) {
    // Skip if already covered by header findings (avoid duplicates)
    const isDuplicate = findings.some(
      (hf: any) => hf.title === df.detail || (df.factor && hf.title?.toLowerCase().includes(df.factor.replace(/_/g, " ")))
    );
    if (isDuplicate) continue;

    const severity = classifyDetFinding(df.factor, isBulk);
    if (severity && df.detail) {
      groups[severity].push({ text: df.detail, source: "scoring", severity });
    }
  }

  return groups;
}

function classifyDetFinding(factor: string, isBulk: boolean): EvidenceSeverity | null {
  // Security failures → critical
  if (/^(spf_fail|dkim_fail|dmarc_fail|display_name_spoof)$/.test(factor)) return "critical";
  if (/^(vt_malicious)$/.test(factor)) return "critical";

  // Missing auth → noteworthy
  if (/^(spf_missing|dkim_missing)$/.test(factor)) return "noteworthy";

  // Mismatch in bulk context → noteworthy, otherwise critical
  if (/^(header_mismatch|header_mismatch_minor)$/.test(factor)) {
    return isBulk ? "noteworthy" : "critical";
  }

  // Link issues
  if (/^(display_mismatch|ip_literal|punycode|suspicious_tld)$/.test(factor)) return "critical";
  if (/^(vt_suspicious)$/.test(factor)) return "noteworthy";

  // Bulk/marketing signals → context
  if (/^(bulk_headers|spam_header|tracking_heavy)$/.test(factor)) return "context";
  if (/^(url_shortener|many_domains)$/.test(factor)) return isBulk ? "context" : "noteworthy";

  return null; // Skip unknown factors to avoid noise
}

// ─── Identity Assessment ────────────────────────────────────────────────────

function extractDomain(email: string | null | undefined): string | null {
  if (!email) return null;
  // Handle "Name <email@domain>" format
  const match = email.match(/@([a-zA-Z0-9.-]+)/);
  return match ? match[1].toLowerCase() : null;
}

function parseAuthResults(authResults: string | null): AuthSignal[] {
  if (!authResults) return [];
  const signals: AuthSignal[] = [];

  // Parse SPF
  const spfMatch = authResults.match(/spf\s*=\s*(\w+)/i);
  if (spfMatch) {
    signals.push({ protocol: "SPF", status: normalizeAuthStatus(spfMatch[1]) });
  }

  // Parse DKIM
  const dkimMatch = authResults.match(/dkim\s*=\s*(\w+)/i);
  if (dkimMatch) {
    signals.push({ protocol: "DKIM", status: normalizeAuthStatus(dkimMatch[1]) });
  }

  // Parse DMARC
  const dmarcMatch = authResults.match(/dmarc\s*=\s*(\w+)/i);
  if (dmarcMatch) {
    signals.push({ protocol: "DMARC", status: normalizeAuthStatus(dmarcMatch[1]) });
  }

  return signals;
}

function normalizeAuthStatus(raw: string): AuthSignal["status"] {
  const s = raw.toLowerCase();
  if (s === "pass") return "pass";
  if (s === "fail" || s === "hardfail") return "fail";
  if (s === "softfail") return "softfail";
  if (s === "none") return "none";
  if (s === "neutral") return "neutral";
  return "unknown";
}

export function assessIdentity(result: any): IdentityAssessment {
  const fromDomain = extractDomain(result.sender?.from_address);
  const replyToDomain = extractDomain(result.sender?.reply_to);
  const returnPathDomain = extractDomain(result.sender?.return_path);
  const authSignals = parseAuthResults(result.authentication_results);
  const isBulk = detectBulkMail(result);

  // Determine domain consistency
  let consistency: IdentityAssessment["consistency"] = "consistent";
  let consistencyDetail = "Alle Absender-Domains stimmen überein.";
  const domains = [fromDomain, replyToDomain, returnPathDomain].filter(Boolean) as string[];
  const uniqueDomains = [...new Set(domains)];

  if (uniqueDomains.length > 1) {
    if (isBulk) {
      // In bulk mail, different domains are expected (e.g., sendgrid, mailchimp)
      consistency = "partial_mismatch";
      consistencyDetail = "Abweichende Domains — typisch für Mailing-Dienste.";
    } else {
      // In non-bulk mail, different domains are suspicious
      const hasAuthFailure = authSignals.some((s) => s.status === "fail");
      consistency = hasAuthFailure ? "suspicious" : "partial_mismatch";
      consistencyDetail = hasAuthFailure
        ? "Abweichende Domains bei fehlgeschlagener Authentifizierung."
        : "Abweichende Domains — manuelle Prüfung empfohlen.";
    }
  } else if (uniqueDomains.length === 1) {
    consistencyDetail = "Alle Absender-Domains stimmen überein.";
  } else if (domains.length === 0) {
    consistency = "partial_mismatch";
    consistencyDetail = "Keine Absender-Domain extrahierbar.";
  }

  return {
    fromDomain,
    replyToDomain,
    returnPathDomain,
    authSignals,
    consistency,
    consistencyDetail,
    isBulkSender: isBulk,
  };
}

// ─── Link Analysis ──────────────────────────────────────────────────────────

const LINK_REASON_LABELS: Record<string, string> = {
  is_ip_literal: "Direkte IP-Adresse statt Domain",
  is_punycode: "Internationalisierte Domain (Punycode)",
  has_display_mismatch: "Angezeigter Text weicht von URL ab",
  is_suspicious_tld: "Verdächtige Top-Level-Domain",
  malicious: "Von Reputationsdienst als maliziös eingestuft",
  suspicious: "Von Reputationsdienst als verdächtig eingestuft",
};

export function summarizeLinks(links: any[]): LinkStats {
  let malicious = 0;
  let suspicious = 0;
  let scansFailed = 0;
  let scansCompleted = 0;
  const criticalLinks: CriticalLink[] = [];

  for (const link of links) {
    const reasons: string[] = [];

    // Check structural flags
    if (link.is_ip_literal) reasons.push(LINK_REASON_LABELS.is_ip_literal);
    if (link.is_punycode) reasons.push(LINK_REASON_LABELS.is_punycode);
    if (link.has_display_mismatch) reasons.push(LINK_REASON_LABELS.has_display_mismatch);
    if (link.is_suspicious_tld) reasons.push(LINK_REASON_LABELS.is_suspicious_tld);

    // Check external scan results
    for (const check of link.external_checks || []) {
      if (check.status === "completed") {
        scansCompleted++;
        if (check.malicious_count > 0) {
          malicious += check.malicious_count;
          reasons.push(`${LINK_REASON_LABELS.malicious} (${check.service}: ${check.malicious_count})`);
        }
        if (check.suspicious_count > 0) {
          suspicious += check.suspicious_count;
          reasons.push(`${LINK_REASON_LABELS.suspicious} (${check.service}: ${check.suspicious_count})`);
        }
      } else if (check.status === "error" || check.status === "timeout" || check.status === "failed") {
        scansFailed++;
      }
    }

    if (reasons.length > 0) {
      criticalLinks.push({ link, reasons });
    }
  }

  return { total: links.length, malicious, suspicious, scansFailed, scansCompleted, criticalLinks };
}

// ─── Score Drivers ──────────────────────────────────────────────────────────

export function extractScoreDrivers(result: any): ScoreDriver[] {
  const drivers: ScoreDriver[] = [];
  const detFindings: any[] = result.deterministic_findings || [];

  for (const df of detFindings) {
    if (!df.detail || !df.impact) continue;

    // Parse impact string (e.g., "phishing+20", "legitimacy-15")
    const impactMatch = df.impact.match(/(phishing|advertising|legitimacy)([+-]\d+)/);
    if (!impactMatch) continue;

    const category = impactMatch[1] as ScoreDriver["category"];
    const value = parseInt(impactMatch[2]);
    const direction: ScoreDriver["direction"] =
      (category === "legitimacy" && value > 0) || (category !== "legitimacy" && value < 0)
        ? "positive"
        : value === 0
        ? "neutral"
        : "negative";

    drivers.push({
      label: df.detail,
      impact: df.impact,
      direction,
      category,
    });
  }

  return drivers;
}

// ─── Decision Explanation Generator ─────────────────────────────────────────

export function generateDecisionExplanation(result: any, identity: IdentityAssessment, linkStats: LinkStats): string | null {
  const a = result.assessment;
  if (!a) return null;

  // If LLM provided a summary, prefer that
  if (a.analyst_summary) return null; // will be shown as-is

  const parts: string[] = [];

  // Auth status summary
  const authPassed = identity.authSignals.filter((s) => s.status === "pass");
  const authFailed = identity.authSignals.filter((s) => s.status === "fail");
  if (authPassed.length > 0 && authFailed.length === 0) {
    parts.push(`Die Authentifizierung (${authPassed.map((s) => s.protocol).join(", ")}) ist valide.`);
  } else if (authFailed.length > 0) {
    parts.push(`Die Authentifizierung ist teilweise fehlgeschlagen (${authFailed.map((s) => s.protocol).join(", ")}).`);
  }

  // Link status
  if (linkStats.total > 0) {
    if (linkStats.malicious > 0) {
      parts.push(`Es wurden ${linkStats.malicious} maliziöse Link-Bewertungen festgestellt.`);
    } else if (linkStats.criticalLinks.length > 0) {
      parts.push(`${linkStats.criticalLinks.length} von ${linkStats.total} Links weisen technische Auffälligkeiten auf.`);
    } else {
      parts.push(`Alle ${linkStats.total} geprüften Links sind reputationsmäßig unauffällig.`);
    }
  }

  // Identity consistency
  if (identity.consistency === "partial_mismatch" && identity.isBulkSender) {
    parts.push("Domain-Abweichungen passen zu typischen Newsletter-Versandmustern.");
  } else if (identity.consistency === "suspicious") {
    parts.push("Die Absenderidentität weist kritische Inkonsistenzen auf.");
  }

  return parts.length > 0 ? parts.join(" ") : null;
}
