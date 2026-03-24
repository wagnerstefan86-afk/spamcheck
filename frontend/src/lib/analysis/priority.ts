/**
 * Priority model and conflict assessment.
 *
 * Assigns stable keys to every signal for explicit referencing.
 * Key format: "domain:type[:qualifier]"
 */

import type {
  AuthSignal,
  IdentityAssessment,
  LinkStats,
  PrioritizedSignal,
  ConflictAssessment,
  PRIORITY_TIER,
} from "./types";

// ─── Signal Collection ──────────────────────────────────────────────────────

export function collectSignals(
  identity: IdentityAssessment,
  linkStats: LinkStats,
  headerFindings: any[],
  detFindings: any[]
): PrioritizedSignal[] {
  const signals: PrioritizedSignal[] = [];

  // Auth signals — key: "auth:{protocol}:{status}"
  for (const auth of identity.authSignals) {
    if (auth.status === "pass") {
      signals.push({
        key: `auth:${auth.protocol.toLowerCase()}:pass`,
        tier: 2 as typeof PRIORITY_TIER.POSITIVE,
        domain: "auth",
        label: `${auth.protocol} bestanden`,
        direction: "positive",
      });
    } else if (auth.status === "fail") {
      signals.push({
        key: `auth:${auth.protocol.toLowerCase()}:fail`,
        tier: 5 as typeof PRIORITY_TIER.CRITICAL_HARD,
        domain: "auth",
        label: `${auth.protocol} fehlgeschlagen`,
        direction: "negative",
      });
    } else if (auth.status === "none" || auth.status === "softfail") {
      signals.push({
        key: `auth:${auth.protocol.toLowerCase()}:${auth.status}`,
        tier: 3 as typeof PRIORITY_TIER.NOTEWORTHY,
        domain: "auth",
        label: `${auth.protocol} nicht vorhanden/softfail`,
        direction: "negative",
      });
    }
  }

  // Identity consistency — key: "identity:{status}"
  if (identity.consistency === "consistent") {
    signals.push({
      key: "identity:consistent",
      tier: 2 as typeof PRIORITY_TIER.POSITIVE,
      domain: "identity",
      label: "Konsistente Absenderidentität",
      direction: "positive",
    });
  } else if (identity.consistency === "suspicious") {
    signals.push({
      key: "identity:suspicious",
      tier: 5 as typeof PRIORITY_TIER.CRITICAL_HARD,
      domain: "identity",
      label: "Verdächtige Identitätsabweichung",
      direction: "negative",
    });
  } else if (identity.consistency === "partial_mismatch") {
    signals.push({
      key: "identity:mismatch",
      tier: 4 as typeof PRIORITY_TIER.CRITICAL_SOFT,
      domain: "identity",
      label: "Domain-Abweichung (From/Reply-To/Return-Path)",
      direction: "negative",
    });
  }

  // Link signals — key: "links:{type}[:{count}]"
  if (linkStats.malicious > 0) {
    signals.push({
      key: `links:malicious:${linkStats.malicious}`,
      tier: 5 as typeof PRIORITY_TIER.CRITICAL_HARD,
      domain: "links",
      label: `${linkStats.malicious} maliziöse Link-Bewertungen`,
      direction: "negative",
    });
  }

  const structuralLinkIssues = linkStats.criticalLinks.filter((cl) =>
    cl.reasons.some((r) => /Punycode|IP-Adresse/i.test(r))
  );
  if (structuralLinkIssues.length > 0) {
    signals.push({
      key: "links:structural",
      tier: 5 as typeof PRIORITY_TIER.CRITICAL_HARD,
      domain: "links",
      label: "Links mit Punycode oder IP-Literal",
      direction: "negative",
    });
  }

  if (linkStats.suspicious > 0) {
    signals.push({
      key: `links:suspicious:${linkStats.suspicious}`,
      tier: 3 as typeof PRIORITY_TIER.NOTEWORTHY,
      domain: "links",
      label: `${linkStats.suspicious} verdächtige Link-Bewertungen`,
      direction: "negative",
    });
  }

  if (linkStats.total > 0 && linkStats.malicious === 0 && linkStats.criticalLinks.length === 0) {
    signals.push({
      key: "links:clean",
      tier: 2 as typeof PRIORITY_TIER.POSITIVE,
      domain: "links",
      label: "Alle Links reputationsmäßig unauffällig",
      direction: "positive",
    });
  }

  // Bulk context — key: "bulk:detected"
  if (identity.isBulkSender) {
    signals.push({
      key: "bulk:detected",
      tier: 1 as typeof PRIORITY_TIER.CONTEXT,
      domain: "bulk",
      label: "Newsletter-/Mailing-Dienst erkannt",
      direction: "positive",
    });
  }

  // Display-Name spoofing — key: "identity:spoofing"
  for (const f of headerFindings) {
    if (/display.?name.*(?:inkonsistenz|spoof)/i.test(f.title)) {
      signals.push({
        key: "identity:spoofing",
        tier: 5 as typeof PRIORITY_TIER.CRITICAL_HARD,
        domain: "identity",
        label: "Display-Name-Spoofing erkannt",
        direction: "negative",
      });
      break; // only add once
    }
  }

  return signals;
}

// ─── Bulk Downgrade Guard ───────────────────────────────────────────────────

export type BulkDowngradeDecision = {
  allowed: boolean;
  reason: string | null;
};

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
  const hasCleanLinks = positives.some((p) => p.domain === "links");

  if (dominant.tier === 5) {
    if (dominant.domain === "links") {
      return hasAuthPositive
        ? "Technische Authentifizierung ist gültig, aber ein kritischer Link-Befund überwiegt."
        : "Ein kritischer Link-Befund ist ausschlaggebend für die Bewertung.";
    }
    if (dominant.domain === "auth") {
      return hasCleanLinks
        ? "Links sind unauffällig, aber eine fehlgeschlagene Authentifizierung bleibt ein starkes Warnsignal."
        : "Fehlgeschlagene Authentifizierung ist das dominierende Risikosignal.";
    }
    if (dominant.domain === "identity") {
      return "Trotz positiver Einzelsignale bleibt die Identitätsabweichung ein starkes Warnsignal.";
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
