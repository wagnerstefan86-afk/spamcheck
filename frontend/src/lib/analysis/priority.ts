/**
 * Conflict assessment and bulk downgrade guard.
 *
 * Operates on PrioritizedSignal[] (projected from NormalizedSignal[]).
 * Signal collection is done exclusively by normalizeSignals() in normalize.ts.
 */

import type {
  AuthSignal,
  IdentityAssessment,
  LinkStats,
  PrioritizedSignal,
  ConflictAssessment,
} from "./types";

// ─── Bulk Downgrade Guard ───────────────────────────────────────────────────

export type BulkDowngradeDecision = {
  allowed: boolean;
  reason: string | null;
};

/**
 * Evaluates whether bulk/newsletter context allows downgrading soft-critical signals.
 *
 * Can work on PrioritizedSignal[] or on pre-computed flags for bootstrap.
 */
export function evaluateBulkDowngrade(signals: PrioritizedSignal[], authSignals: AuthSignal[]): BulkDowngradeDecision {
  const hardCriticals = signals.filter((s) => s.tier === 5 && s.direction === "negative");
  if (hardCriticals.length > 0) {
    return { allowed: false, reason: `Herabstufung blockiert: ${hardCriticals[0].label}` };
  }
  const authPassed = authSignals.filter((a) => a.status === "pass").length;
  if (authPassed < 2) {
    return { allowed: false, reason: "Herabstufung blockiert: Unzureichende Authentifizierung (weniger als 2 Protokolle bestanden)" };
  }
  return { allowed: true, reason: null };
}

/**
 * Lightweight bulk downgrade check using raw inputs.
 * Used by normalizeSignals() to avoid circular dependency.
 */
export function evaluateBulkDowngradeFromRaw(
  authSignals: AuthSignal[],
  hasHardCritical: boolean
): BulkDowngradeDecision {
  if (hasHardCritical) {
    return { allowed: false, reason: "Herabstufung blockiert: Kritisches Signal vorhanden" };
  }
  const authPassed = authSignals.filter((a) => a.status === "pass").length;
  if (authPassed < 2) {
    return { allowed: false, reason: "Herabstufung blockiert: Unzureichende Authentifizierung (weniger als 2 Protokolle bestanden)" };
  }
  return { allowed: true, reason: null };
}

// ─── Conflict Assessment ────────────────────────────────────────────────────

export function assessConflict(
  signals: PrioritizedSignal[],
  identity: IdentityAssessment
): ConflictAssessment {
  const positives = signals.filter((s) => s.direction === "positive" && s.tier >= 2);
  const negatives = signals.filter((s) => s.direction === "negative" && s.tier >= 3);
  const hasConflict = positives.length > 0 && negatives.length > 0;

  if (!hasConflict) {
    return {
      hasConflict: false, dominantSignal: null, explanation: null,
      bulkDowngradeApplied: false, bulkDowngradeBlocked: false, bulkDowngradeBlockReason: null,
    };
  }

  const sorted = [...negatives].sort((a, b) => b.tier - a.tier);
  const dominant = sorted[0];

  const bulkDowngrade = identity.isBulkSender
    ? evaluateBulkDowngrade(signals, identity.authSignals)
    : { allowed: false, reason: null };
  const bulkDowngradeApplied = identity.isBulkSender && bulkDowngrade.allowed;
  const bulkDowngradeBlocked = identity.isBulkSender && !bulkDowngrade.allowed;

  const explanation = generateConflictExplanation(dominant, positives, identity, bulkDowngradeApplied);

  return {
    hasConflict: true, dominantSignal: dominant, explanation,
    bulkDowngradeApplied, bulkDowngradeBlocked,
    bulkDowngradeBlockReason: bulkDowngradeBlocked ? bulkDowngrade.reason : null,
  };
}

function generateConflictExplanation(
  dominant: PrioritizedSignal,
  positives: PrioritizedSignal[],
  identity: IdentityAssessment,
  bulkDowngradeApplied: boolean
): string {
  const hasAuthPositive = positives.some((p) => p.domain === "auth");
  // Only consider links as truly clean if the signal is links:clean (verified), not partial/unknown
  const hasVerifiedCleanLinks = positives.some((p) => p.key === "links:clean" && p.tier >= 2);

  if (dominant.tier === 5) {
    if (dominant.domain === "links") {
      return hasAuthPositive
        ? "Technische Authentifizierung ist gültig, aber ein kritischer Link-Befund überwiegt."
        : "Ein kritischer Link-Befund ist ausschlaggebend für die Bewertung.";
    }
    if (dominant.domain === "auth") {
      return hasVerifiedCleanLinks
        ? "Keine negativen Reputationstreffer bei Links, aber eine fehlgeschlagene Authentifizierung bleibt ein starkes Warnsignal."
        : "Fehlgeschlagene Authentifizierung ist das dominierende Risikosignal.";
    }
    if (dominant.domain === "identity") {
      return "Trotz positiver Einzelsignale bleibt die Identitätsabweichung ein starkes Warnsignal.";
    }
    if (dominant.domain === "content") {
      return hasAuthPositive
        ? "Technische Authentifizierung ist valide, belegt aber nicht die Gutartigkeit des Inhalts."
        : "Inhaltliche Risikomerkmale sind ausschlaggebend für die Bewertung.";
    }
  }

  if (dominant.tier === 4 && bulkDowngradeApplied) {
    return "Es bestehen kleinere Abweichungen in der Versandidentität, diese sind jedoch konsistent mit typischem Newsletter-Versand und durch gültige Authentifizierung gestützt.";
  }
  if (dominant.tier === 4) {
    return hasAuthPositive
      ? "Domain-Abweichungen liegen vor, werden aber durch gültige Authentifizierung relativiert."
      : "Domain-Abweichungen erfordern eine manuelle Prüfung.";
  }
  if (dominant.tier === 3) {
    return "Mehrere positive Signale sprechen für Legitimität, dennoch bestehen einzelne Auffälligkeiten.";
  }

  return "Gemischte Signale erfordern eine kontextbezogene Bewertung.";
}
