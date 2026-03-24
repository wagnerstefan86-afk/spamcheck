/**
 * Classifies evidence items and header findings into three groups:
 * - positive: legitimizing signals
 * - noteworthy: explainable deviations
 * - critical: real risk indicators
 */

export type EvidenceItem = {
  text: string;
  source: "evidence" | "header" | "link" | "auth";
  severity: "positive" | "noteworthy" | "critical";
};

export type EvidenceGroups = {
  positive: EvidenceItem[];
  noteworthy: EvidenceItem[];
  critical: EvidenceItem[];
};

const POSITIVE_PATTERNS = [
  /spf.*(pass|erfolgreich|valide|bestanden)/i,
  /dkim.*(pass|erfolgreich|valide|bestanden)/i,
  /dmarc.*(pass|erfolgreich|valide|bestanden)/i,
  /authentif.*(erfolgreich|valide|bestanden|passed)/i,
  /keine.*(bösartig|malizi|suspicious|verdächtig|bedroh)/i,
  /no.*(malicious|suspicious|threat)/i,
  /legitimate|legitim/i,
  /reputation.*(gut|unauffällig|clean|good)/i,
  /bekannt|consistent|konsistent/i,
  /valid sender|gültiger absender/i,
  /trusted|vertrauenswürdig/i,
];

const CRITICAL_PATTERNS = [
  /phishing/i,
  /malicious|maliziös|bösartig/i,
  /spoofing|spoof/i,
  /fehlgeschlagen|failed|fail\b/i,
  /spf.*(fail|none|softfail)/i,
  /dkim.*(fail|none)/i,
  /dmarc.*(fail|none|reject)/i,
  /verdächtig.*domain|suspicious.*domain/i,
  /identitätsabweichung|identity.*mismatch/i,
  /credential|password|passwort/i,
  /urgency|dringend/i,
  /impersonat/i,
];

function classifyText(text: string): "positive" | "noteworthy" | "critical" {
  for (const p of CRITICAL_PATTERNS) {
    if (p.test(text)) return "critical";
  }
  for (const p of POSITIVE_PATTERNS) {
    if (p.test(text)) return "positive";
  }
  return "noteworthy";
}

function headerSeverityToGroup(severity: string): "positive" | "noteworthy" | "critical" {
  if (severity === "critical" || severity === "high") return "critical";
  if (severity === "warning" || severity === "medium") return "noteworthy";
  return "positive";
}

export function classifyEvidence(result: any): EvidenceGroups {
  const groups: EvidenceGroups = { positive: [], noteworthy: [], critical: [] };

  // Classify assessment evidence strings
  const evidence: string[] = result.assessment?.evidence || [];
  for (const e of evidence) {
    const severity = classifyText(e);
    groups[severity].push({ text: e, source: "evidence", severity });
  }

  // Classify header findings
  const findings: any[] = result.header_findings || [];
  for (const f of findings) {
    const mappedSeverity = headerSeverityToGroup(f.severity);
    // Use the title + detail for better context
    const text = f.detail ? `${f.title}: ${f.detail}` : f.title;
    groups[mappedSeverity].push({ text, source: "header", severity: mappedSeverity });
  }

  return groups;
}

/**
 * Summarize link analysis into compact stats
 */
export type LinkStats = {
  total: number;
  malicious: number;
  suspicious: number;
  scansFailed: number;
  scansCompleted: number;
  criticalLinks: any[];
};

export function summarizeLinks(links: any[]): LinkStats {
  let malicious = 0;
  let suspicious = 0;
  let scansFailed = 0;
  let scansCompleted = 0;
  const criticalLinks: any[] = [];

  for (const link of links) {
    let linkIsCritical = false;

    // Check flags
    const hasRiskyFlag =
      link.is_ip_literal ||
      link.is_punycode ||
      link.has_display_mismatch ||
      link.is_suspicious_tld;

    if (hasRiskyFlag) linkIsCritical = true;

    // Check external scan results
    for (const check of link.external_checks || []) {
      if (check.status === "completed") {
        scansCompleted++;
        if (check.malicious_count > 0) {
          malicious += check.malicious_count;
          linkIsCritical = true;
        }
        if (check.suspicious_count > 0) {
          suspicious += check.suspicious_count;
          linkIsCritical = true;
        }
      } else if (check.status === "error" || check.status === "timeout") {
        scansFailed++;
      }
    }

    if (linkIsCritical) {
      criticalLinks.push(link);
    }
  }

  return {
    total: links.length,
    malicious,
    suspicious,
    scansFailed,
    scansCompleted,
    criticalLinks,
  };
}
