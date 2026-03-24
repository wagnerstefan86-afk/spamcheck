/**
 * Link analysis and summarization.
 *
 * Uses backend-provided verdict, scan_status, and result_fetched fields
 * to derive accurate reputation coverage instead of inferring from counts.
 */

import type { LinkStats, CriticalLink, ReputationCoverage } from "./types";

const LINK_REASON_LABELS: Record<string, string> = {
  is_ip_literal: "Direkte IP-Adresse statt Domain",
  is_punycode: "Internationalisierte Domain (Punycode)",
  has_display_mismatch: "Angezeigter Text weicht von URL ab",
  is_suspicious_tld: "Verdächtige Top-Level-Domain",
  malicious: "Von Reputationsdienst als maliziös eingestuft",
  suspicious: "Von Reputationsdienst als verdächtig eingestuft",
};

/**
 * Computes the overall reputation coverage from per-link verdicts.
 *
 * Rules (conservative):
 * - If ANY link is malicious → coverage is irrelevant (malicious dominates)
 * - If ALL links have verdict "clean" and resultFetchedCount > 0 → "clean"
 * - If some links clean, some unknown/partial → "partially_analyzed"
 * - If all links are "not_checked" → "not_checked"
 * - Otherwise → "unknown"
 */
function computeReputationCoverage(
  total: number,
  verdicts: LinkStats["verdicts"],
  resultFetchedCount: number,
): ReputationCoverage {
  if (total === 0) return "none";

  // Malicious/suspicious links — coverage doesn't matter, threat is confirmed
  if (verdicts.malicious > 0 || verdicts.suspicious > 0) {
    // Still return the actual coverage for display purposes
    if (resultFetchedCount > 0 && resultFetchedCount >= total) return "clean";
    if (resultFetchedCount > 0) return "partially_analyzed";
    return "unknown";
  }

  // All not_checked → providers were never executed
  if (verdicts.not_checked === total) return "not_checked";

  // Hard rule: no result_fetched at all → never clean
  if (resultFetchedCount === 0) return "unknown";

  // All links have clean verdict and at least one result was fetched
  if (verdicts.clean === total && resultFetchedCount > 0) return "clean";

  // Some clean, some not → partially analyzed
  if (verdicts.clean > 0 && verdicts.clean < total) return "partially_analyzed";

  // Mix of unknown/partial/not_checked
  if (verdicts.partially_analyzed > 0) return "partially_analyzed";

  return "unknown";
}

export function summarizeLinks(links: any[]): LinkStats {
  let malicious = 0;
  let suspicious = 0;
  let scansFailed = 0;
  let scansCompleted = 0;
  let resultFetchedCount = 0;
  const criticalLinks: CriticalLink[] = [];

  const verdicts = {
    clean: 0,
    suspicious: 0,
    malicious: 0,
    unknown: 0,
    partially_analyzed: 0,
    not_checked: 0,
  };

  for (const link of links) {
    const reasons: string[] = [];

    if (link.is_ip_literal) reasons.push(LINK_REASON_LABELS.is_ip_literal);
    if (link.is_punycode) reasons.push(LINK_REASON_LABELS.is_punycode);
    if (link.has_display_mismatch) reasons.push(LINK_REASON_LABELS.has_display_mismatch);
    if (link.is_suspicious_tld) reasons.push(LINK_REASON_LABELS.is_suspicious_tld);

    // Track per-link verdict from backend
    const verdict = link.verdict || "unknown";
    if (verdict in verdicts) {
      verdicts[verdict as keyof typeof verdicts]++;
    } else {
      verdicts.unknown++;
    }

    // Track whether any provider actually returned a result for this link
    let linkHasResult = false;

    for (const check of link.external_checks || []) {
      // Use result_fetched (new backend field) as primary indicator
      if (check.result_fetched) {
        linkHasResult = true;
      }

      if (check.status === "completed" || check.result_fetched) {
        scansCompleted++;
        if (check.malicious_count > 0) {
          malicious += check.malicious_count;
          reasons.push(`${LINK_REASON_LABELS.malicious} (${check.service}: ${check.malicious_count})`);
        }
        if (check.suspicious_count > 0) {
          suspicious += check.suspicious_count;
          reasons.push(`${LINK_REASON_LABELS.suspicious} (${check.service}: ${check.suspicious_count})`);
        }
      } else if (check.status === "error" || check.status === "timeout" || check.status === "failed"
        || check.scan_status === "rate_limited" || check.scan_status === "timeout"
        || check.scan_status === "api_error" || check.scan_status === "submit_failed") {
        scansFailed++;
      }
    }

    if (linkHasResult) {
      resultFetchedCount++;
    }

    if (reasons.length > 0) {
      criticalLinks.push({ link, reasons });
    }
  }

  const reputationCoverage = computeReputationCoverage(links.length, verdicts, resultFetchedCount);

  return {
    total: links.length,
    malicious,
    suspicious,
    scansFailed,
    scansCompleted,
    criticalLinks,
    resultFetchedCount,
    verdicts,
    reputationCoverage,
  };
}
