/**
 * Score driver extraction, decision factors, explanation, and analysis summary.
 */

import type {
  ScoreDriver,
  IdentityAssessment,
  LinkStats,
  ConflictAssessment,
  PrioritizedSignal,
  NormalizedSignal,
  AnalysisSummary,
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
  promotedKeys: Set<string>;
};

const MAX_FACTORS = 4;

export function extractDecisionFactors(signals: PrioritizedSignal[]): DecisionFactors {
  const negative = signals
    .filter((s) => s.direction === "negative" && s.tier >= 3)
    .sort((a, b) => b.tier - a.tier)
    .slice(0, MAX_FACTORS);

  const positive = signals
    .filter((s) => s.direction === "positive" && s.tier >= 1)
    .sort((a, b) => b.tier - a.tier)
    .slice(0, MAX_FACTORS);

  const promotedKeys = new Set<string>();
  for (const s of negative) promotedKeys.add(s.key);
  for (const s of positive) promotedKeys.add(s.key);

  return { negative, positive, promotedKeys };
}

// ─── Decision Explanation ───────────────────────────────────────────────────

export function generateDecisionExplanation(
  result: any,
  identity: IdentityAssessment,
  linkStats: LinkStats,
  conflict: ConflictAssessment
): string | null {
  const a = result.assessment;
  if (!a) return null;
  if (a.analyst_summary && !conflict.hasConflict) return null;

  const parts: string[] = [];

  const authPassed = identity.authSignals.filter((s) => s.status === "pass");
  const authFailed = identity.authSignals.filter((s) => s.status === "fail");
  if (authPassed.length > 0 && authFailed.length === 0) {
    parts.push(`Authentifizierung (${authPassed.map((s) => s.protocol).join(", ")}) ist valide.`);
  } else if (authFailed.length > 0) {
    parts.push(`Authentifizierung teilweise fehlgeschlagen (${authFailed.map((s) => s.protocol).join(", ")}).`);
  }

  if (linkStats.total > 0) {
    if (linkStats.malicious > 0) parts.push(`${linkStats.malicious} maliziöse Link-Bewertungen festgestellt.`);
    else if (linkStats.criticalLinks.length > 0) parts.push(`${linkStats.criticalLinks.length} von ${linkStats.total} Links mit technischen Auffälligkeiten.`);
    else parts.push(`Alle ${linkStats.total} Links reputationsmäßig unauffällig.`);
  }

  if (identity.isBulkSender && conflict.bulkDowngradeApplied) {
    parts.push("Domain-Abweichungen passen zu typischen Newsletter-Versandmustern.");
  } else if (identity.isBulkSender && conflict.bulkDowngradeBlocked) {
    parts.push("Newsletter-Kontext erkannt, aber Entschärfung nicht möglich.");
  } else if (identity.consistency === "suspicious") {
    parts.push("Kritische Inkonsistenzen in der Absenderidentität.");
  }

  return parts.length > 0 ? parts.join(" ") : null;
}

// ─── Analysis Summary (serializable, API/export-ready) ──────────────────────

/**
 * Builds a serializable analysis summary from NormalizedSignals.
 *
 * This can be:
 * - returned as API response
 * - included in JSON export
 * - used for backend-ready signal transfer
 */
export function buildAnalysisSummary(
  normalizedSignals: NormalizedSignal[],
  factors: DecisionFactors,
  conflict: ConflictAssessment
): AnalysisSummary {
  return {
    signals: normalizedSignals.map((s) => ({
      key: s.key,
      canonicalKey: s.canonicalKey,
      label: s.label,
      severity: s.severity,
      tier: s.tier,
      direction: s.direction,
      domain: s.domain,
      category: s.category,
      sourceType: s.sourceType,
      sourceRef: s.sourceRef,
      promotable: s.promotable,
      downgradeEligible: s.downgradeEligible,
    })),
    decisionFactors: {
      negative: factors.negative.map((s) => s.key),
      positive: factors.positive.map((s) => s.key),
    },
    promotedKeys: Array.from(factors.promotedKeys),
    conflict: {
      hasConflict: conflict.hasConflict,
      dominantSignalKey: conflict.dominantSignal?.key || null,
      explanation: conflict.explanation,
      bulkDowngradeApplied: conflict.bulkDowngradeApplied,
    },
  };
}
