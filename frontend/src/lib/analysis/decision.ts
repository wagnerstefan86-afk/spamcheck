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
  ActionDecision,
  ActionLevel,
} from "./types";
import { assessIdentity } from "./identity";
import { summarizeLinks } from "./links";
import { normalizeSignals, toPrioritizedSignals, toEvidenceGroups } from "./normalize";
import { assessConflict } from "./priority";
import { detectContentRisks, assessContentRiskLevel } from "./content";

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
  hasAnalystSummary: boolean,
  contentRiskLevel: "none" | "low" | "high" = "none",
  allNormalized: NormalizedSignal[] = []
): string | null {
  if (hasAnalystSummary && !conflict.hasConflict && contentRiskLevel === "none") return null;

  const parts: string[] = [];

  // Content risk — most important, comes first
  const contentSignals = signals.filter((s) => s.domain === "content" && s.direction === "negative");
  if (contentSignals.length > 0) {
    const labels = contentSignals.map((s) => s.label).slice(0, 2);
    parts.push(`Inhaltliche Risikomerkmale: ${labels.join(", ")}.`);
  }

  // Auth summary — use allNormalized to find auth signals (may be demoted from PrioritizedSignals)
  const authSource = allNormalized.length > 0 ? allNormalized : signals;
  const allAuthPositive = authSource.filter((s) => s.domain === "auth" && s.direction === "positive");
  const authFail = signals.filter((s) => s.domain === "auth" && s.direction === "negative" && s.tier >= 5);
  if (authFail.length > 0) {
    const protocols = authFail.map((s) => s.label.split(" ")[0]).join(", ");
    parts.push(`Authentifizierung teilweise fehlgeschlagen (${protocols}).`);
  } else if (allAuthPositive.length > 0 && contentRiskLevel === "high") {
    parts.push("Authentifizierung ist technisch valide, belegt aber nicht die Gutartigkeit des Inhalts.");
  } else if (allAuthPositive.length > 0) {
    const protocols = allAuthPositive.map((s) => s.label.split(" ")[0]).join(", ");
    parts.push(`Authentifizierung (${protocols}) ist valide.`);
  }

  // Reputation coverage — use new granular signals
  const reputationUnknown = signals.find((s) => s.key === "reputation:unknown");
  const linksUnknown = signals.find((s) => s.key === "links:unknown");
  const linksNotChecked = signals.find((s) => s.key === "links:not_checked");
  const linksPartial = signals.find((s) => s.key === "links:partial");
  const hasReputationGap = reputationUnknown || linksUnknown || linksNotChecked;

  if (linksNotChecked) {
    parts.push("Reputationsprüfung wurde nicht ausgeführt — keine Entwarnung möglich.");
  } else if (linksUnknown) {
    parts.push("Reputationsbewertung nicht belastbar — kein verwertbares Provider-Ergebnis erhalten.");
  } else if (reputationUnknown) {
    parts.push("Provider-Scans konnten nicht vollständig durchgeführt werden — Reputationsbewertung nicht belastbar.");
  } else if (linksPartial) {
    parts.push("Auf Basis der verfügbaren Reputationsergebnisse keine negativen Treffer — Bewertung jedoch unvollständig.");
  }

  // Link summary from signals
  const maliciousLink = signals.find((s) => s.key.startsWith("links:malicious"));
  const structuralLink = signals.find((s) => s.key === "links:structural");
  const cleanLink = signals.find((s) => s.key === "links:clean" && s.tier >= 2); // only if not demoted
  if (maliciousLink) {
    parts.push(`${maliciousLink.label}.`);
  } else if (structuralLink) {
    parts.push(`${structuralLink.label}.`);
  } else if (cleanLink && !hasReputationGap) {
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

// ─── Action Decision Engine V1 ───────────────────────────────────────────────

/**
 * Deterministic action decision for end users.
 *
 * Three levels:
 * - "open": safe to open, no significant risk
 * - "manual_review": unclear, user should be cautious or escalate
 * - "do_not_open": strong risk indicators, do not interact
 *
 * Rules are ordered: hard blocks first, then open eligibility, then fallback.
 */
export function computeActionDecision(
  contentRiskLevel: "none" | "low" | "high",
  signals: PrioritizedSignal[],
  normalized: NormalizedSignal[],
  identity: IdentityAssessment,
  linkStats: LinkStats,
  conflict: ConflictAssessment,
  classification: string | null,
): ActionDecision {

  // ─── Hard "do_not_open" rules ──────────────────────────────────────

  // 1. High content risk (credential lure, account threat, etc.)
  if (contentRiskLevel === "high") {
    const contentSignal = signals.find((s) => s.domain === "content" && s.direction === "negative");
    return {
      action: "do_not_open",
      label: "Nicht öffnen",
      reason: "Die E-Mail zeigt starke Hinweise auf Phishing oder Missbrauch. Öffnen Sie keine Links oder Anhänge.",
      primaryDriver: contentSignal?.key || "content:high_risk",
    };
  }

  // 2. Identity spoofing detected
  const spoofingSignal = signals.find((s) => s.key === "identity:spoofing");
  if (spoofingSignal) {
    return {
      action: "do_not_open",
      label: "Nicht öffnen",
      reason: "Es wurden Anzeichen für Absender-Spoofing erkannt. Interagieren Sie nicht mit dieser E-Mail.",
      primaryDriver: "identity:spoofing",
    };
  }

  // 3. Malicious links detected
  if (linkStats.malicious > 0) {
    return {
      action: "do_not_open",
      label: "Nicht öffnen",
      reason: "Mindestens ein Link wurde von Reputationsdiensten als schädlich eingestuft.",
      primaryDriver: signals.find((s) => s.key.startsWith("links:malicious"))?.key || "links:malicious",
    };
  }

  // 4. Hard critical negative signal at tier 5 (auth fail + suspicious identity)
  const hardNegative = signals.find(
    (s) => s.tier === 5 && s.direction === "negative" && s.domain !== "content"
  );
  if (hardNegative && identity.consistency === "suspicious") {
    return {
      action: "do_not_open",
      label: "Nicht öffnen",
      reason: "Kritische Sicherheitsbefunde in Kombination mit verdächtiger Absenderidentität.",
      primaryDriver: hardNegative.key,
    };
  }

  // ─── "open" eligibility ────────────────────────────────────────────

  const hasHardNegative = signals.some(
    (s) => s.tier >= 5 && s.direction === "negative"
  );
  const hasMediumNegative = signals.some(
    (s) => s.tier >= 3 && s.direction === "negative"
      && s.category !== "reputation_coverage" // not_checked/unknown is handled via evidence quality
  );
  const authPassCount = identity.authSignals.filter((a) => a.status === "pass").length;
  const identityOk = identity.consistency === "consistent" || identity.consistency === "partial_mismatch";
  const reputationCov = linkStats.reputationCoverage;

  // Evidence quality check: is the analysis basis strong enough for "open"?
  const hasStrongEvidence =
    (reputationCov === "clean" || reputationCov === "none") // no links, or all fully verified clean
    && authPassCount >= 2
    && identityOk;

  const hasAdequateEvidence =
    (reputationCov === "clean" || reputationCov === "partially_analyzed" || reputationCov === "none")
    && authPassCount >= 1
    && identityOk;

  // "open" requires: no hard negatives, no significant negatives, adequate evidence
  if (!hasHardNegative && !hasMediumNegative && hasStrongEvidence) {
    return {
      action: "open",
      label: "Öffnen",
      reason: "Es wurden keine relevanten Risikosignale erkannt. Die E-Mail kann geöffnet werden.",
      primaryDriver: null,
    };
  }

  // Bulk sender (newsletter) with good auth and no hard negatives
  if (identity.isBulkSender && !hasHardNegative && hasAdequateEvidence
    && conflict.bulkDowngradeApplied) {
    return {
      action: "open",
      label: "Öffnen",
      reason: "Newsletter/Mailing-Dienst mit gültiger Authentifizierung erkannt.",
      primaryDriver: "bulk:detected",
    };
  }

  // ─── "manual_review" — default for unclear cases ───────────────────

  // Determine the primary reason for caution
  let reason = "Die Bewertung ist nicht eindeutig. Bitte prüfen Sie die E-Mail sorgfältig oder leiten Sie sie an die IT-Sicherheit weiter.";
  let driver: string | null = null;

  if (hasHardNegative) {
    const neg = signals.find((s) => s.tier >= 5 && s.direction === "negative");
    reason = "Es bestehen sicherheitsrelevante Auffälligkeiten. Bitte prüfen Sie die E-Mail sorgfältig.";
    driver = neg?.key || null;
  } else if (reputationCov === "unknown" || reputationCov === "not_checked") {
    reason = "Die Reputationsbewertung ist nicht belastbar. Eine abschließende Einschätzung ist nicht möglich.";
    driver = "reputation:insufficient";
  } else if (reputationCov === "partially_analyzed") {
    reason = "Die Reputationsprüfung ist unvollständig. Bitte behandeln Sie die E-Mail mit Vorsicht.";
    driver = "reputation:partial";
  } else if (conflict.hasConflict) {
    reason = "Es liegen widersprüchliche Signale vor. Bitte prüfen Sie die E-Mail sorgfältig.";
    driver = conflict.dominantSignal?.key || null;
  } else if (linkStats.suspicious > 0) {
    reason = "Mindestens ein Link wurde als verdächtig eingestuft. Bitte seien Sie vorsichtig.";
    driver = signals.find((s) => s.key.startsWith("links:suspicious"))?.key || null;
  }

  return {
    action: "manual_review",
    label: "Vorsicht – bitte prüfen",
    reason,
    primaryDriver: driver,
  };
}

// ─── Analysis Summary (serializable) ────────────────────────────────────────

export function buildAnalysisSummary(
  normalizedSignals: NormalizedSignal[],
  factors: DecisionFactors,
  conflict: ConflictAssessment,
  explanation: string | null,
  classification: string | null,
  analystSummary: string | null,
  contentRiskLevel: "none" | "low" | "high" = "none",
  overrideApplied: boolean = false,
  actionDecision: ActionDecision | null = null,
): AnalysisSummary {
  return {
    version: 1,
    classification,
    analystSummary,
    explanation,
    contentRiskLevel,
    overrideApplied,
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
    actionDecision: actionDecision
      ? { action: actionDecision.action, label: actionDecision.label, reason: actionDecision.reason, primaryDriver: actionDecision.primaryDriver }
      : { action: "manual_review" as const, label: "Vorsicht – bitte prüfen", reason: "Keine Entscheidung berechnet.", primaryDriver: null },
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

  // 2. Content risk detection (pre-normalization — affects auth weighting)
  const contentRisks = detectContentRisks(result);
  const contentRiskLevel = assessContentRiskLevel(contentRisks);

  // 3. Normalize — single source of truth
  // normalizeSignals internally uses content risk for auth reweighting
  const normalized = normalizeSignals(result, identity, linkStats, identity.isBulkSender);

  // 4. Project views
  const signals = toPrioritizedSignals(normalized);
  const conflict = assessConflict(signals, identity);
  const decisionFactors = extractDecisionFactors(signals);
  const evidenceGroups = toEvidenceGroups(normalized);
  const scoreDrivers = extractScoreDrivers(result);

  // 5. Decision override: phishing content must not result in "allow"
  const overrideApplied = evaluateDecisionOverride(contentRiskLevel, signals, linkStats);

  // 6. Action decision — deterministic, operative recommendation for end user
  const actionDecision = computeActionDecision(
    contentRiskLevel,
    signals,
    normalized,
    identity,
    linkStats,
    conflict,
    a?.classification || null,
  );

  // 7. Decision explanation — derived from signals and conflict
  const explanation = generateDecisionExplanation(
    signals,
    conflict,
    !!a?.analyst_summary,
    contentRiskLevel,
    normalized
  );

  // 8. Serializable summary
  const summary = buildAnalysisSummary(
    normalized,
    decisionFactors,
    conflict,
    explanation,
    a?.classification || null,
    a?.analyst_summary || null,
    contentRiskLevel,
    overrideApplied,
    actionDecision,
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
    contentRiskLevel,
    overrideApplied,
    actionDecision,
    summary,
  };
}

// ─── Decision Override ──────────────────────────────────────────────────────

/**
 * Evaluates whether content risk should override a "legitimate/allow" decision.
 *
 * Rules (conservative — few, clear):
 * 1. High content risk → always override (must not be "allow")
 * 2. High content risk + unknown reputation → strong override
 * 3. Low content risk alone → no override
 */
function evaluateDecisionOverride(
  contentRiskLevel: "none" | "low" | "high",
  signals: PrioritizedSignal[],
  linkStats: LinkStats
): boolean {
  if (contentRiskLevel !== "high") return false;

  // High content risk always triggers override
  return true;
}
