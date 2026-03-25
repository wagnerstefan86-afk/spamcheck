/**
 * Link analysis and summarization.
 *
 * Separates link-level and provider-level metrics for audit-ready display.
 *
 * Link-level: each link counted once (fully/partially/without result)
 * Provider-level: each provider scan attempt counted separately
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

/** Terminal failure statuses from the backend ScanStatus enum */
const FAILURE_STATUSES = new Set([
  "rate_limited", "timeout", "api_error", "submit_failed", "invalid_response",
]);

/** Statuses that mean the provider was never attempted */
const SKIPPED_STATUSES = new Set([
  "skipped", "not_executed",
]);

/**
 * Classify a single link's provider coverage.
 *
 * - "fully_analyzed": all non-skipped providers returned result_fetched=true
 * - "partially_analyzed": at least one returned result_fetched, but not all non-skipped
 * - "without_result": no provider returned result_fetched=true
 */
function classifyLinkCoverage(
  checks: any[],
): "fully_analyzed" | "partially_analyzed" | "without_result" {
  if (checks.length === 0) return "without_result";

  let nonSkippedCount = 0;
  let fetchedCount = 0;

  for (const check of checks) {
    const scanStatus = check.scan_status || "";
    if (SKIPPED_STATUSES.has(scanStatus)) continue;
    nonSkippedCount++;
    if (check.result_fetched) fetchedCount++;
  }

  if (nonSkippedCount === 0) return "without_result";
  if (fetchedCount >= nonSkippedCount) return "fully_analyzed";
  if (fetchedCount > 0) return "partially_analyzed";
  return "without_result";
}

/**
 * Compute aggregated reputation coverage from link-level metrics.
 *
 * Rules (conservative):
 * - All links fully analyzed, none negative → "clean"
 * - Some links have results but not all fully → "partially_analyzed"
 * - All links not_checked → "not_checked"
 * - No usable results at all → "unknown"
 */
function computeReputationCoverage(
  total: number,
  linksFullyAnalyzed: number,
  linksPartiallyAnalyzed: number,
  verdicts: LinkStats["verdicts"],
): ReputationCoverage {
  if (total === 0) return "none";

  // All not_checked → no providers executed
  if (verdicts.not_checked === total) return "not_checked";

  // No link has any provider result
  if (linksFullyAnalyzed === 0 && linksPartiallyAnalyzed === 0) return "unknown";

  // All links fully analyzed by all providers
  if (linksFullyAnalyzed === total) return "clean";

  // Some links have results, but not all are fully covered
  if (linksFullyAnalyzed > 0 || linksPartiallyAnalyzed > 0) return "partially_analyzed";

  return "unknown";
}

export function summarizeLinks(links: any[]): LinkStats {
  let malicious = 0;
  let suspicious = 0;

  // Provider-level counters
  let providerScansTotal = 0;
  let providerScansSuccessful = 0;
  let providerScansFailed = 0;
  let providerScansSkipped = 0;

  // Link-level counters
  let linksFullyAnalyzed = 0;
  let linksPartiallyAnalyzed = 0;
  let linksWithoutResult = 0;

  // Legacy counters (kept for signal logic compat)
  let scansCompleted = 0;
  let scansFailed = 0;
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

    const checks: any[] = link.external_checks || [];

    // Provider-level: count each individual scan
    for (const check of checks) {
      providerScansTotal++;
      const scanStatus = check.scan_status || "";

      if (SKIPPED_STATUSES.has(scanStatus)) {
        providerScansSkipped++;
      } else if (check.result_fetched) {
        providerScansSuccessful++;
        // Legacy compat
        scansCompleted++;
      } else if (FAILURE_STATUSES.has(scanStatus)
        || check.status === "error" || check.status === "timeout" || check.status === "failed") {
        providerScansFailed++;
        // Legacy compat
        scansFailed++;
      } else if (check.status === "completed") {
        // Legacy completed without result_fetched — count as successful
        providerScansSuccessful++;
        scansCompleted++;
      }

      // Count malicious/suspicious from successful checks
      if (check.result_fetched || check.status === "completed") {
        if (check.malicious_count > 0) {
          malicious += check.malicious_count;
          reasons.push(`${LINK_REASON_LABELS.malicious} (${check.service}: ${check.malicious_count})`);
        }
        if (check.suspicious_count > 0) {
          suspicious += check.suspicious_count;
          reasons.push(`${LINK_REASON_LABELS.suspicious} (${check.service}: ${check.suspicious_count})`);
        }
      }
    }

    // Link-level: classify this link's coverage
    const linkCoverage = classifyLinkCoverage(checks);
    if (linkCoverage === "fully_analyzed") {
      linksFullyAnalyzed++;
      resultFetchedCount++;
    } else if (linkCoverage === "partially_analyzed") {
      linksPartiallyAnalyzed++;
      resultFetchedCount++;
    } else {
      linksWithoutResult++;
    }

    if (reasons.length > 0) {
      criticalLinks.push({ link, reasons });
    }
  }

  const reputationCoverage = computeReputationCoverage(
    links.length, linksFullyAnalyzed, linksPartiallyAnalyzed, verdicts
  );

  // Provider coverage percentage (excluding skipped)
  const attemptedScans = providerScansTotal - providerScansSkipped;
  const coveragePercent = attemptedScans > 0
    ? Math.round((providerScansSuccessful / attemptedScans) * 100)
    : null;

  return {
    total: links.length,
    malicious,
    suspicious,
    criticalLinks,

    // Link-level
    linksFullyAnalyzed,
    linksPartiallyAnalyzed,
    linksWithoutResult,

    // Provider-level
    providerScansTotal,
    providerScansSuccessful,
    providerScansFailed,
    providerScansSkipped,

    // Derived
    coveragePercent,
    verdicts,
    reputationCoverage,

    // Legacy
    scansCompleted,
    scansFailed,
    resultFetchedCount,
  };
}
