/**
 * Priority model and conflict assessment.
 *
 * Central logic that determines:
 * - Which signals can override others
 * - Whether bulk-context downgrade is safe
 * - What the dominant signal is in conflict cases
 *
 * ## Priority Rules (explicit, ordered)
 *
 * 1. HARD CRITICAL signals (tier 5) are NEVER downgraded:
 *    - Malicious links (VT confirmed)
 *    - Auth failures (SPF/DKIM/DMARC fail)
 *    - Display-Name spoofing
 *    - Punycode / IP-literal URLs
 *
 * 2. SOFT CRITICAL signals (tier 4) CAN be downgraded to noteworthy
 *    IF AND ONLY IF all of these hold:
 *    - Bulk/newsletter context detected
 *    - No hard-critical signals present
 *    - Auth is predominantly positive (≥2 of SPF/DKIM/DMARC pass)
 *    - No malicious links
 *
 * 3. Positive signals (tier 2) DO NOT neutralize critical signals.
 *    Auth pass is a positive signal, but it cannot "heal" a malicious link.
 *
 * 4. Bulk context (tier 1) provides CONTEXT, not absolution.
 *    It can explain mismatches but not excuse security failures.
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

/**
 * Collects all prioritized signals from the analysis result.
 * This is the single source of truth for conflict resolution.
 */
export function collectSignals(
  identity: IdentityAssessment,
  linkStats: LinkStats,
  headerFindings: any[],
  detFindings: any[]
): PrioritizedSignal[] {
  const signals: PrioritizedSignal[] = [];

  // --- Auth signals ---
  for (const auth of identity.authSignals) {
    if (auth.status === "pass") {
      signals.push({
        tier: 2 as typeof PRIORITY_TIER.POSITIVE,
        domain: "auth",
        label: `${auth.protocol} bestanden`,
        direction: "positive",
      });
    } else if (auth.status === "fail") {
      signals.push({
        tier: 5 as typeof PRIORITY_TIER.CRITICAL_HARD,
        domain: "auth",
        label: `${auth.protocol} fehlgeschlagen`,
        direction: "negative",
      });
    } else if (auth.status === "none" || auth.status === "softfail") {
      signals.push({
        tier: 3 as typeof PRIORITY_TIER.NOTEWORTHY,
        domain: "auth",
        label: `${auth.protocol} nicht vorhanden/softfail`,
        direction: "negative",
      });
    }
  }

  // --- Identity consistency ---
  if (identity.consistency === "consistent") {
    signals.push({
      tier: 2 as typeof PRIORITY_TIER.POSITIVE,
      domain: "identity",
      label: "Konsistente Absenderidentität",
      direction: "positive",
    });
  } else if (identity.consistency === "suspicious") {
    signals.push({
      tier: 5 as typeof PRIORITY_TIER.CRITICAL_HARD,
      domain: "identity",
      label: "Verdächtige Identitätsabweichung",
      direction: "negative",
    });
  } else if (identity.consistency === "partial_mismatch") {
    // Soft-critical: can be downgraded in bulk context
    signals.push({
      tier: 4 as typeof PRIORITY_TIER.CRITICAL_SOFT,
      domain: "identity",
      label: "Domain-Abweichung (From/Reply-To/Return-Path)",
      direction: "negative",
    });
  }

  // --- Link signals ---
  if (linkStats.malicious > 0) {
    signals.push({
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
      tier: 5 as typeof PRIORITY_TIER.CRITICAL_HARD,
      domain: "links",
      label: "Links mit Punycode oder IP-Literal",
      direction: "negative",
    });
  }

  if (linkStats.suspicious > 0) {
    signals.push({
      tier: 3 as typeof PRIORITY_TIER.NOTEWORTHY,
      domain: "links",
      label: `${linkStats.suspicious} verdächtige Link-Bewertungen`,
      direction: "negative",
    });
  }

  if (linkStats.total > 0 && linkStats.malicious === 0 && linkStats.criticalLinks.length === 0) {
    signals.push({
      tier: 2 as typeof PRIORITY_TIER.POSITIVE,
      domain: "links",
      label: "Alle Links reputationsmäßig unauffällig",
      direction: "positive",
    });
  }

  // --- Bulk context ---
  if (identity.isBulkSender) {
    signals.push({
      tier: 1 as typeof PRIORITY_TIER.CONTEXT,
      domain: "bulk",
      label: "Newsletter-/Mailing-Dienst erkannt",
      direction: "positive",
    });
  }

  // --- Display-Name spoofing from header findings ---
  for (const f of headerFindings) {
    if (/display.?name.*(?:inkonsistenz|spoof)/i.test(f.title)) {
      signals.push({
        tier: 5 as typeof PRIORITY_TIER.CRITICAL_HARD,
        domain: "identity",
        label: "Display-Name-Spoofing erkannt",
        direction: "negative",
      });
    }
  }

  return signals;
}

// ─── Bulk Downgrade Guard ───────────────────────────────────────────────────

export type BulkDowngradeDecision = {
  allowed: boolean;
  reason: string | null;
};

/**
 * Determines whether bulk-context downgrade is safe.
 *
 * Downgrade is ONLY allowed when ALL of:
 * - No hard-critical signals (tier 5)
 * - Auth predominantly positive (≥2 pass)
 * - No malicious links
 * - No display-name spoofing
 */
export function evaluateBulkDowngrade(signals: PrioritizedSignal[], authSignals: AuthSignal[]): BulkDowngradeDecision {
  const hardCriticals = signals.filter((s) => s.tier === 5 && s.direction === "negative");
  if (hardCriticals.length > 0) {
    return {
      allowed: false,
      reason: `Herabstufung blockiert: ${hardCriticals[0].label}`,
    };
  }

  const authPassed = authSignals.filter((a) => a.status === "pass").length;
  if (authPassed < 2) {
    return {
      allowed: false,
      reason: "Herabstufung blockiert: Unzureichende Authentifizierung (weniger als 2 Protokolle bestanden)",
    };
  }

  return { allowed: true, reason: null };
}

// ─── Conflict Assessment ────────────────────────────────────────────────────

/**
 * Analyzes whether the signals contain conflicts and determines dominance.
 *
 * A conflict exists when both positive (tier ≥ 2) and negative (tier ≥ 3)
 * signals are present.
 */
export function assessConflict(
  signals: PrioritizedSignal[],
  identity: IdentityAssessment
): ConflictAssessment {
  const positives = signals.filter((s) => s.direction === "positive" && s.tier >= 2);
  const negatives = signals.filter((s) => s.direction === "negative" && s.tier >= 3);
  const hasConflict = positives.length > 0 && negatives.length > 0;

  if (!hasConflict) {
    return {
      hasConflict: false,
      dominantSignal: null,
      explanation: null,
      bulkDowngradeApplied: false,
      bulkDowngradeBlocked: false,
      bulkDowngradeBlockReason: null,
    };
  }

  // Find highest-priority negative signal (the dominant one)
  const sorted = [...negatives].sort((a, b) => b.tier - a.tier);
  const dominant = sorted[0];

  // Check bulk downgrade status
  const bulkDowngrade = identity.isBulkSender
    ? evaluateBulkDowngrade(signals, identity.authSignals)
    : { allowed: false, reason: null };
  const bulkDowngradeApplied = identity.isBulkSender && bulkDowngrade.allowed;
  const bulkDowngradeBlocked = identity.isBulkSender && !bulkDowngrade.allowed;

  // Generate conflict explanation
  const explanation = generateConflictExplanation(dominant, positives, identity, bulkDowngradeApplied);

  return {
    hasConflict: true,
    dominantSignal: dominant,
    explanation,
    bulkDowngradeApplied,
    bulkDowngradeBlocked,
    bulkDowngradeBlockReason: bulkDowngradeBlocked ? bulkDowngrade.reason : null,
  };
}

// ─── Conflict Explanation Generator ─────────────────────────────────────────

function generateConflictExplanation(
  dominant: PrioritizedSignal,
  positives: PrioritizedSignal[],
  identity: IdentityAssessment,
  bulkDowngradeApplied: boolean
): string {
  const positiveLabels = positives.map((p) => p.label);
  const hasAuthPositive = positives.some((p) => p.domain === "auth");
  const hasCleanLinks = positives.some((p) => p.domain === "links");

  // Hard critical dominant → positive signals cannot compensate
  if (dominant.tier === 5) {
    if (dominant.domain === "links") {
      if (hasAuthPositive) {
        return "Technische Authentifizierung ist gültig, aber ein kritischer Link-Befund überwiegt.";
      }
      return "Ein kritischer Link-Befund ist ausschlaggebend für die Bewertung.";
    }
    if (dominant.domain === "auth") {
      if (hasCleanLinks) {
        return "Links sind unauffällig, aber eine fehlgeschlagene Authentifizierung bleibt ein starkes Warnsignal.";
      }
      return "Fehlgeschlagene Authentifizierung ist das dominierende Risikosignal.";
    }
    if (dominant.domain === "identity") {
      return "Trotz positiver Einzelsignale bleibt die Identitätsabweichung ein starkes Warnsignal.";
    }
  }

  // Soft critical (tier 4) with bulk downgrade applied
  if (dominant.tier === 4 && bulkDowngradeApplied) {
    return "Es bestehen kleinere Abweichungen in der Versandidentität, diese sind jedoch konsistent mit typischem Newsletter-Versand und durch gültige Authentifizierung gestützt.";
  }

  // Soft critical without bulk downgrade
  if (dominant.tier === 4) {
    if (hasAuthPositive) {
      return "Domain-Abweichungen liegen vor, werden aber durch gültige Authentifizierung relativiert.";
    }
    return "Domain-Abweichungen erfordern eine manuelle Prüfung.";
  }

  // Noteworthy dominant (tier 3)
  if (dominant.tier === 3) {
    return "Mehrere positive Signale sprechen für Legitimität, dennoch bestehen einzelne Auffälligkeiten.";
  }

  return "Gemischte Signale erfordern eine kontextbezogene Bewertung.";
}
