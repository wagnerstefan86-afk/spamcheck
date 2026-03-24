/**
 * Link analysis and summarization.
 */

import type { LinkStats, CriticalLink } from "./types";

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

    if (link.is_ip_literal) reasons.push(LINK_REASON_LABELS.is_ip_literal);
    if (link.is_punycode) reasons.push(LINK_REASON_LABELS.is_punycode);
    if (link.has_display_mismatch) reasons.push(LINK_REASON_LABELS.has_display_mismatch);
    if (link.is_suspicious_tld) reasons.push(LINK_REASON_LABELS.is_suspicious_tld);

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
