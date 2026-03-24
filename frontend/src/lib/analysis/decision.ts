/**
 * Score driver extraction and decision explanation generation.
 *
 * Uses conflict assessment to produce weighted, honest explanations.
 */

import type {
  ScoreDriver,
  IdentityAssessment,
  LinkStats,
  ConflictAssessment,
} from "./types";

// ─── Score Drivers ──────────────────────────────────────────────────────────

export function extractScoreDrivers(result: any): ScoreDriver[] {
  const drivers: ScoreDriver[] = [];
  const detFindings: any[] = result.deterministic_findings || [];

  for (const df of detFindings) {
    if (!df.detail || !df.impact) continue;

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

    drivers.push({ label: df.detail, impact: df.impact, direction, category });
  }

  return drivers;
}

// ─── Decision Explanation ───────────────────────────────────────────────────

/**
 * Generates a data-driven decision explanation that integrates conflict awareness.
 *
 * The explanation addresses:
 * - Primary positive/negative drivers
 * - Bulk context (correctly scoped)
 * - Dominant signal in conflict cases
 *
 * Returns null only if LLM analyst_summary is present AND no conflict exists.
 */
export function generateDecisionExplanation(
  result: any,
  identity: IdentityAssessment,
  linkStats: LinkStats,
  conflict: ConflictAssessment
): string | null {
  const a = result.assessment;
  if (!a) return null;

  // If LLM provided a summary AND there's no conflict, defer to LLM
  if (a.analyst_summary && !conflict.hasConflict) return null;

  const parts: string[] = [];

  // Auth status
  const authPassed = identity.authSignals.filter((s) => s.status === "pass");
  const authFailed = identity.authSignals.filter((s) => s.status === "fail");
  if (authPassed.length > 0 && authFailed.length === 0) {
    parts.push(`Authentifizierung (${authPassed.map((s) => s.protocol).join(", ")}) ist valide.`);
  } else if (authFailed.length > 0) {
    parts.push(`Authentifizierung teilweise fehlgeschlagen (${authFailed.map((s) => s.protocol).join(", ")}).`);
  }

  // Link status
  if (linkStats.total > 0) {
    if (linkStats.malicious > 0) {
      parts.push(`${linkStats.malicious} maliziöse Link-Bewertungen festgestellt.`);
    } else if (linkStats.criticalLinks.length > 0) {
      parts.push(`${linkStats.criticalLinks.length} von ${linkStats.total} Links mit technischen Auffälligkeiten.`);
    } else {
      parts.push(`Alle ${linkStats.total} Links reputationsmäßig unauffällig.`);
    }
  }

  // Bulk context — scoped correctly
  if (identity.isBulkSender && conflict.bulkDowngradeApplied) {
    parts.push("Domain-Abweichungen passen zu typischen Newsletter-Versandmustern und werden durch gültige Authentifizierung gestützt.");
  } else if (identity.isBulkSender && conflict.bulkDowngradeBlocked) {
    parts.push(`Newsletter-Kontext erkannt, aber Entschärfung nicht möglich: ${conflict.bulkDowngradeBlockReason?.replace("Herabstufung blockiert: ", "")}.`);
  } else if (identity.consistency === "suspicious") {
    parts.push("Kritische Inkonsistenzen in der Absenderidentität.");
  }

  // Conflict dominance — the key new addition
  if (conflict.hasConflict && conflict.dominantSignal) {
    // Only add if not already covered by the above
    const d = conflict.dominantSignal;
    if (d.tier === 5 && d.domain === "links" && authPassed.length > 0) {
      // Already covered by conflict.explanation, which is shown separately
    } else if (d.tier === 5 && d.domain === "auth" && linkStats.criticalLinks.length === 0) {
      // Already covered
    }
    // The conflict explanation itself is shown via the UI component
  }

  return parts.length > 0 ? parts.join(" ") : null;
}
