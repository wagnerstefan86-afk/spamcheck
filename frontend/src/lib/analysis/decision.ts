/**
 * Score drivers, decision factors, explanation, analysis summary,
 * and the central analyzeResult() pipeline.
 */

import type {
  ScoreDriver,
  IdentityAssessment,
  LinkStats,
  ConflictAssessment,
  PrioritizedSignal,
  NormalizedSignal,
  AnalysisSummary,
  AnalysisResult,
} from "./types";
import { assessIdentity } from "./identity";
import { summarizeLinks } from "./links";
import { normalizeSignals, toPrioritizedSignals, toEvidenceGroups } from "./normalize";
import { assessConflict } from "./priority";

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

/**
 * Generates a decision explanation from normalized signals and conflict.
 *
 * Derives text from:
 * - PrioritizedSignal[] (auth status, link status from signal domains)
 * - ConflictAssessment (conflict explanation, bulk downgrade)
 * - assessment.analyst_summary (whether to suppress generated text)
 */
export function generateDecisionExplanation(
  signals: PrioritizedSignal[],
  conflict: ConflictAssessment,
  hasAnalystSummary: boolean
): string | null {
  if (hasAnalystSummary && !conflict.hasConflict) return null;

  const parts: string[] = [];

  // Auth summary from signals
  const authPass = signals.filter((s) => s.domain === "auth" && s.direction === "positive");
  const authFail = signals.filter((s) => s.domain === "auth" && s.direction === "negative" && s.tier >= 5);
  if (authPass.length > 0 && authFail.length === 0) {
    const protocols = authPass.map((s) => s.label.split(" ")[0]).join(", ");
    parts.push(`Authentifizierung (${protocols}) ist valide.`);
  } else if (authFail.length > 0) {
    const protocols = authFail.map((s) => s.label.split(" ")[0]).join(", ");
    parts.push(`Authentifizierung teilweise fehlgeschlagen (${protocols}).`);
  }

  // Link summary from signals
  const maliciousLink = signals.find((s) => s.key.startsWith("links:malicious"));
  const structuralLink = signals.find((s) => s.key === "links:structural");
  const cleanLink = signals.find((s) => s.key === "links:clean");
  if (maliciousLink) {
    parts.push(`${maliciousLink.label}.`);
  } else if (structuralLink) {
    parts.push(`${structuralLink.label}.`);
  } else if (cleanLink) {
    parts.push(`${cleanLink.label}.`);
  }

  // Bulk / identity context from conflict
  if (conflict.bulkDowngradeApplied) {
    parts.push("Domain-Abweichungen passen zu typischen Newsletter-Versandmustern.");
  } else if (conflict.bulkDowngradeBlocked) {
    parts.push("Newsletter-Kontext erkannt, aber Entschärfung nicht möglich.");
  } else {
    const suspiciousIdentity = signals.find((s) => s.key === "identity:suspicious");
    if (suspiciousIdentity) {
      parts.push("Kritische Inkonsistenzen in der Absenderidentität.");
    }
  }

  return parts.length > 0 ? parts.join(" ") : null;
}

// ─── Analysis Summary (serializable) ────────────────────────────────────────

export function buildAnalysisSummary(
  normalizedSignals: NormalizedSignal[],
  factors: DecisionFactors,
  conflict: ConflictAssessment,
  explanation: string | null,
  classification: string | null,
  analystSummary: string | null
): AnalysisSummary {
  return {
    version: 1,
    classification,
    analystSummary,
    explanation,
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

// ─── Central Pipeline ───────────────────────────────────────────────────────

/**
 * Complete analysis pipeline. One call, one result.
 *
 * This is the single entry point for producing all analysis outputs
 * from a raw backend result. UI components and export consume its output.
 */
export function analyzeResult(result: any): AnalysisResult {
  const a = result.assessment;

  // 1. Core extraction
  const identity = assessIdentity(result);
  const linkStats = summarizeLinks(result.links || []);

  // 2. Normalize — single source of truth
  const normalized = normalizeSignals(result, identity, linkStats, identity.isBulkSender);

  // 3. Project views
  const signals = toPrioritizedSignals(normalized);
  const conflict = assessConflict(signals, identity);
  const decisionFactors = extractDecisionFactors(signals);
  const evidenceGroups = toEvidenceGroups(normalized);
  const scoreDrivers = extractScoreDrivers(result);

  // 4. Decision explanation — derived from signals and conflict
  const explanation = generateDecisionExplanation(
    signals,
    conflict,
    !!a?.analyst_summary
  );

  // 5. Serializable summary
  const summary = buildAnalysisSummary(
    normalized,
    decisionFactors,
    conflict,
    explanation,
    a?.classification || null,
    a?.analyst_summary || null
  );

  return {
    identity,
    linkStats,
    normalized,
    signals,
    conflict,
    decisionFactors,
    evidenceGroups,
    scoreDrivers,
    explanation,
    summary,
  };
}
