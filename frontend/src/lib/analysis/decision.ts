/**
 * Score driver extraction, decision factors, and explanation generation.
 *
 * Provides:
 * - extractScoreDrivers(): raw score impact parsing
 * - extractDecisionFactors(): top 2-4 positive/negative signals for the decision
 * - generateDecisionExplanation(): conflict-aware 1-2 sentence explanation
 */

import type {
  ScoreDriver,
  IdentityAssessment,
  LinkStats,
  ConflictAssessment,
  PrioritizedSignal,
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

// ─── Decision Factors ───────────────────────────────────────────────────────

export type DecisionFactors = {
  negative: PrioritizedSignal[];
  positive: PrioritizedSignal[];
  /** Labels of signals promoted to this block, for dedup in EvidenceGroups */
  promotedLabels: Set<string>;
};

const MAX_FACTORS = 4;

/**
 * Extracts the top 2-4 positive and negative signals for the decision summary.
 *
 * Signals are selected by tier (highest first), deduplicated by domain,
 * and capped at MAX_FACTORS per side.
 */
export function extractDecisionFactors(signals: PrioritizedSignal[]): DecisionFactors {
  const negative = signals
    .filter((s) => s.direction === "negative" && s.tier >= 3)
    .sort((a, b) => b.tier - a.tier)
    .slice(0, MAX_FACTORS);

  const positive = signals
    .filter((s) => s.direction === "positive" && s.tier >= 1)
    .sort((a, b) => b.tier - a.tier)
    .slice(0, MAX_FACTORS);

  const promotedLabels = new Set<string>();
  for (const s of [...negative, ...positive]) {
    promotedLabels.add(s.label);
  }

  return { negative, positive, promotedLabels };
}

// ─── Decision Explanation ───────────────────────────────────────────────────

/**
 * Generates a compact 1-2 sentence explanation integrating conflict awareness.
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

  // Auth status — one sentence
  const authPassed = identity.authSignals.filter((s) => s.status === "pass");
  const authFailed = identity.authSignals.filter((s) => s.status === "fail");
  if (authPassed.length > 0 && authFailed.length === 0) {
    parts.push(`Authentifizierung (${authPassed.map((s) => s.protocol).join(", ")}) ist valide.`);
  } else if (authFailed.length > 0) {
    parts.push(`Authentifizierung teilweise fehlgeschlagen (${authFailed.map((s) => s.protocol).join(", ")}).`);
  }

  // Link status — one sentence
  if (linkStats.total > 0) {
    if (linkStats.malicious > 0) {
      parts.push(`${linkStats.malicious} maliziöse Link-Bewertungen festgestellt.`);
    } else if (linkStats.criticalLinks.length > 0) {
      parts.push(`${linkStats.criticalLinks.length} von ${linkStats.total} Links mit technischen Auffälligkeiten.`);
    } else {
      parts.push(`Alle ${linkStats.total} Links reputationsmäßig unauffällig.`);
    }
  }

  // Bulk context or identity — one sentence, not both
  if (identity.isBulkSender && conflict.bulkDowngradeApplied) {
    parts.push("Domain-Abweichungen passen zu typischen Newsletter-Versandmustern.");
  } else if (identity.isBulkSender && conflict.bulkDowngradeBlocked) {
    parts.push(`Newsletter-Kontext erkannt, aber Entschärfung nicht möglich.`);
  } else if (identity.consistency === "suspicious") {
    parts.push("Kritische Inkonsistenzen in der Absenderidentität.");
  }

  return parts.length > 0 ? parts.join(" ") : null;
}
