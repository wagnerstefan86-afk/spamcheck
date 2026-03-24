/**
 * Central signal normalization — the single source of truth for all signals.
 *
 * Raw sources → normalizeSignals() → NormalizedSignal[]
 *   → toPrioritizedSignals() → assessConflict() / extractDecisionFactors()
 *   → toEvidenceGroups() → UI
 *   → buildAnalysisSummary() → Export / API
 *
 * No other module should independently collect or derive signals.
 */

import type {
  NormalizedSignal,
  EvidenceSeverity,
  PriorityTier,
  SignalDomain,
  SignalCategory,
  IdentityAssessment,
  LinkStats,
  PrioritizedSignal,
  EvidenceItem,
  EvidenceGroups,
  PRIORITY_TIER,
} from "./types";
import { evaluateBulkDowngradeFromRaw } from "./priority";
import { detectContentRisks, assessContentRiskLevel } from "./content";
import type { ContentRiskMatch } from "./content";

// ─── Canonical Key ──────────────────────────────────────────────────────────

export function deriveCanonicalKey(key: string): string {
  const parts = key.split(":");
  if (parts[0] === "auth" && parts.length >= 3) return `${parts[0]}:${parts[1]}`;
  if (parts[0] === "links" && parts.length >= 3) return `${parts[0]}:${parts[1]}`;
  return key;
}

// ─── Signal Key Mapping Tables ──────────────────────────────────────────────

const HEADER_FINDING_SIGNAL_MAP: Array<{ pattern: RegExp; key: string }> = [
  { pattern: /spf.*(?:bestanden|pass)/i, key: "auth:spf:pass" },
  { pattern: /dkim.*(?:bestanden|pass)/i, key: "auth:dkim:pass" },
  { pattern: /dmarc.*(?:bestanden|pass)/i, key: "auth:dmarc:pass" },
  { pattern: /spf.*(?:fehlgeschlagen|fail)/i, key: "auth:spf:fail" },
  { pattern: /dkim.*(?:fehlgeschlagen|fail)/i, key: "auth:dkim:fail" },
  { pattern: /dmarc.*(?:fehlgeschlagen|fail)/i, key: "auth:dmarc:fail" },
  { pattern: /kein.*spf/i, key: "auth:spf:none" },
  { pattern: /kein.*dkim/i, key: "auth:dkim:none" },
  { pattern: /kein.*dmarc/i, key: "auth:dmarc:none" },
  { pattern: /display.?name.*(?:inkonsistenz|spoof)/i, key: "identity:spoofing" },
  { pattern: /from.*reply.?to.*mismatch/i, key: "identity:mismatch" },
  { pattern: /from.*return.?path.*mismatch/i, key: "identity:mismatch" },
  { pattern: /return.?path.*mismatch/i, key: "identity:mismatch" },
  { pattern: /massen.*header|marketing.*header|bulk.*header/i, key: "bulk:detected" },
];

const DET_FACTOR_SIGNAL_MAP: Record<string, string> = {
  spf_fail: "auth:spf:fail",
  spf_missing: "auth:spf:none",
  dkim_fail: "auth:dkim:fail",
  dkim_missing: "auth:dkim:none",
  dmarc_fail: "auth:dmarc:fail",
  display_name_spoof: "identity:spoofing",
  header_mismatch: "identity:mismatch",
  header_mismatch_minor: "identity:mismatch",
  vt_malicious: "links:malicious",
  vt_suspicious: "links:suspicious",
  display_mismatch: "links:structural",
  ip_literal: "links:structural",
  punycode: "links:structural",
  suspicious_tld: "links:structural",
  bulk_headers: "bulk:detected",
};

const EVIDENCE_TEXT_SIGNAL_MAP: Array<{ pattern: RegExp; key: string }> = [
  { pattern: /spf.*(pass|erfolgreich|bestanden)/i, key: "auth:spf:pass" },
  { pattern: /dkim.*(pass|erfolgreich|bestanden)/i, key: "auth:dkim:pass" },
  { pattern: /dmarc.*(pass|erfolgreich|bestanden)/i, key: "auth:dmarc:pass" },
  { pattern: /spf.*(fail|none|softfail)/i, key: "auth:spf:fail" },
  { pattern: /dkim.*(fail|none)/i, key: "auth:dkim:fail" },
  { pattern: /dmarc.*(fail|none|reject)/i, key: "auth:dmarc:fail" },
  { pattern: /keine.*(bösartig|malizi|suspicious|verdächtig)/i, key: "links:clean" },
  { pattern: /no.*(malicious|suspicious|threat)/i, key: "links:clean" },
  { pattern: /malicious|maliziös|bösartig/i, key: "links:malicious" },
  { pattern: /spoofing|spoof/i, key: "identity:spoofing" },
  { pattern: /impersonat/i, key: "identity:spoofing" },
];

function matchSignalKey(text: string, map: Array<{ pattern: RegExp; key: string }>): string | null {
  for (const entry of map) {
    if (entry.pattern.test(text)) return entry.key;
  }
  return null;
}

// ─── Severity Classification ────────────────────────────────────────────────

const POSITIVE_FINDING = [/spf.*(?:bestanden|pass)/i, /dkim.*(?:bestanden|pass)/i, /dmarc.*(?:bestanden|pass)/i, /authentifizierung.*(?:erfolgreich|valide)/i];
const CONTEXT_FINDING = [/massen.*header|marketing.*header|bulk.*header/i, /list.?unsubscribe/i, /hoher scl/i, /spam.*header.*(?:scl|bcl)/i, /lange received/i];
const HARD_CRITICAL_FINDING = [/spf.*fehlgeschlagen|spf.*fail/i, /dkim.*fehlgeschlagen|dkim.*fail/i, /dmarc.*fehlgeschlagen|dmarc.*fail/i, /display.?name.*(?:inkonsistenz|spoof)/i];
const SOFT_CRITICAL_FINDING = [/from.*reply.?to.*mismatch/i, /from.*return.?path.*mismatch/i];
const NOTEWORTHY_FINDING = [/return.?path.*mismatch/i, /kein.*(?:spf|dkim|dmarc)/i];

function classifyHeaderSeverity(combined: string, backendSeverity: string, isBulk: boolean, bulkDowngradeAllowed: boolean): EvidenceSeverity {
  for (const p of POSITIVE_FINDING) { if (p.test(combined)) return "positive"; }
  for (const p of CONTEXT_FINDING) { if (p.test(combined)) return "context"; }
  for (const p of HARD_CRITICAL_FINDING) { if (p.test(combined)) return "critical"; }
  for (const p of SOFT_CRITICAL_FINDING) {
    if (p.test(combined)) return (isBulk && bulkDowngradeAllowed) ? "noteworthy" : "critical";
  }
  for (const p of NOTEWORTHY_FINDING) { if (p.test(combined)) return "noteworthy"; }
  if (backendSeverity === "critical") return "critical";
  if (backendSeverity === "warning") return "noteworthy";
  return "positive";
}

// IMPORTANT: "keine bösartigen" must match POSITIVE before CRITICAL.
// EV_POSITIVE is checked first now to prevent "bösartig" in "keine bösartigen" from matching CRITICAL.
const EV_POSITIVE = [/keine.*(bösartig|malizi|suspicious|verdächtig|bedroh)/i, /no.*(malicious|suspicious|threat)/i, /spf.*(pass|erfolgreich|valide|bestanden)/i, /dkim.*(pass|erfolgreich|valide|bestanden)/i, /dmarc.*(pass|erfolgreich|valide|bestanden)/i, /reputation.*(gut|unauffällig|clean|good)/i, /authentif.*(erfolgreich|valide|bestanden)/i, /legitimate|legitim/i, /vertrauenswürdig|trusted/i];
const EV_CRITICAL = [/phishing/i, /(?<!keine?.{0,20})(malicious|maliziös|bösartig)/i, /spoofing|spoof/i, /spf.*(fail|none|softfail)/i, /dkim.*(fail|none)/i, /dmarc.*(fail|none|reject)/i, /verdächtig.*domain|suspicious.*domain/i, /identitätsabweichung|identity.*mismatch/i, /impersonat/i];
const EV_CONTEXT = [/newsletter|marketing|bulk|mailing/i, /list.?unsubscribe|abmelde/i, /tracking|click.?tracking/i];

function classifyEvidenceTextSeverity(text: string): EvidenceSeverity {
  // Check POSITIVE first — "keine bösartigen" must not match CRITICAL "bösartig"
  for (const p of EV_POSITIVE) { if (p.test(text)) return "positive"; }
  for (const p of EV_CRITICAL) { if (p.test(text)) return "critical"; }
  for (const p of EV_CONTEXT) { if (p.test(text)) return "context"; }
  return "noteworthy";
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function severityToTier(severity: EvidenceSeverity): PriorityTier {
  switch (severity) {
    case "critical": return 5 as typeof PRIORITY_TIER.CRITICAL_HARD;
    case "noteworthy": return 3 as typeof PRIORITY_TIER.NOTEWORTHY;
    case "positive": return 2 as typeof PRIORITY_TIER.POSITIVE;
    case "context": return 1 as typeof PRIORITY_TIER.CONTEXT;
  }
}

function keyToDomain(key: string): SignalDomain {
  const prefix = key.split(":")[0];
  if (prefix === "auth") return "auth";
  if (prefix === "identity") return "identity";
  if (prefix === "links") return "links";
  if (prefix === "bulk") return "bulk";
  return "content";
}

function keyToCategory(key: string): SignalCategory {
  if (key.startsWith("auth:")) return "authentication";
  if (key.startsWith("identity:")) return "identity_consistency";
  if (key.startsWith("links:malicious") || key.startsWith("links:suspicious") || key.startsWith("links:clean")) return "link_reputation";
  if (key.startsWith("links:structural")) return "link_structure";
  if (key.startsWith("bulk:")) return "bulk_context";
  if (key.startsWith("content:")) return "content_risk";
  if (key.startsWith("reputation:")) return "reputation_coverage";
  return "content_analysis";
}

function severityToDirection(severity: EvidenceSeverity): "positive" | "negative" {
  return (severity === "positive" || severity === "context") ? "positive" : "negative";
}

function makeSignal(input: Omit<NormalizedSignal, "canonicalKey" | "direction"> & { direction?: "positive" | "negative" }): NormalizedSignal {
  return {
    ...input,
    canonicalKey: deriveCanonicalKey(input.key),
    direction: input.direction ?? severityToDirection(input.severity),
  };
}

function classifyDetSeverity(factor: string, isBulk: boolean, bulkDowngradeAllowed: boolean): EvidenceSeverity | null {
  if (/^(spf_fail|dkim_fail|dmarc_fail|display_name_spoof|vt_malicious)$/.test(factor)) return "critical";
  if (/^(display_mismatch|ip_literal|punycode|suspicious_tld)$/.test(factor)) return "critical";
  if (/^(spf_missing|dkim_missing)$/.test(factor)) return "noteworthy";
  if (/^(header_mismatch)$/.test(factor)) return (isBulk && bulkDowngradeAllowed) ? "noteworthy" : "critical";
  if (/^(header_mismatch_minor)$/.test(factor)) return (isBulk && bulkDowngradeAllowed) ? "context" : "noteworthy";
  if (/^(vt_suspicious)$/.test(factor)) return "noteworthy";
  if (/^(bulk_headers|spam_header|tracking_heavy)$/.test(factor)) return "context";
  if (/^(url_shortener|many_domains)$/.test(factor)) return isBulk ? "context" : "noteworthy";
  return null;
}

// ─── Pre-scan for hard criticals (bulk downgrade bootstrap) ─────────────────

function hasHardCriticalIndicators(
  identity: IdentityAssessment,
  linkStats: LinkStats,
  headerFindings: any[]
): boolean {
  // Auth failures
  if (identity.authSignals.some((a) => a.status === "fail")) return true;
  // Malicious links
  if (linkStats.malicious > 0) return true;
  // Display-name spoofing
  if (headerFindings.some((f: any) => /display.?name.*(?:inkonsistenz|spoof)/i.test(f.title))) return true;
  // Suspicious identity (auth fail + domain mismatch)
  if (identity.consistency === "suspicious") return true;
  return false;
}

// ─── Main Normalization ─────────────────────────────────────────────────────

/**
 * Single entry point for all signal derivation.
 *
 * All downstream views (PrioritizedSignal[], EvidenceGroups, DecisionFactors,
 * ConflictAssessment, AnalysisSummary) are projections of this output.
 */
export function normalizeSignals(
  result: any,
  identity: IdentityAssessment,
  linkStats: LinkStats,
  isBulk: boolean,
): NormalizedSignal[] {
  const signals: NormalizedSignal[] = [];
  const seenCanonical = new Set<string>();
  const headerFindings: any[] = result.header_findings || [];

  // Compute bulk downgrade from raw inputs (no circular dependency)
  const hasHardCritical = hasHardCriticalIndicators(identity, linkStats, headerFindings);
  const bulkDowngrade = isBulk
    ? evaluateBulkDowngradeFromRaw(identity.authSignals, hasHardCritical)
    : { allowed: false, reason: null };
  const bulkDowngradeAllowed = bulkDowngrade.allowed;

  // 1. Auth signals (from parsed authentication_results)
  for (const auth of identity.authSignals) {
    const status = auth.status;
    if (status === "unknown" || status === "neutral") continue;
    const key = `auth:${auth.protocol.toLowerCase()}:${status}`;
    const isPass = status === "pass";
    signals.push(makeSignal({
      key,
      label: isPass ? `${auth.protocol} bestanden` : status === "fail" ? `${auth.protocol} fehlgeschlagen` : `${auth.protocol} ${status}`,
      severity: isPass ? "positive" : status === "fail" ? "critical" : "noteworthy",
      tier: isPass ? 2 : status === "fail" ? 5 : 3,
      domain: "auth",
      category: "authentication",
      sourceType: "auth_result",
      sourceRef: `auth:${auth.protocol.toLowerCase()}`,
      evidenceText: null,
      promotable: true,
      downgradeEligible: false,
    }));
    seenCanonical.add(deriveCanonicalKey(key));
  }

  // 2. Identity consistency
  const identityDomains = [identity.fromDomain, identity.replyToDomain, identity.returnPathDomain].filter(Boolean);
  const identitySourceRef = identityDomains.length > 0
    ? `domains:${identityDomains.join(",")}`
    : null;
  const identityKey = identity.consistency === "consistent" ? "identity:consistent"
    : identity.consistency === "suspicious" ? "identity:suspicious"
    : "identity:mismatch";
  signals.push(makeSignal({
    key: identityKey,
    label: identity.consistency === "consistent" ? "Konsistente Absenderidentität"
      : identity.consistency === "suspicious" ? "Verdächtige Identitätsabweichung"
      : "Domain-Abweichung (From/Reply-To/Return-Path)",
    severity: identity.consistency === "consistent" ? "positive"
      : identity.consistency === "suspicious" ? "critical" : "noteworthy",
    tier: identity.consistency === "consistent" ? 2
      : identity.consistency === "suspicious" ? 5 : 4,
    domain: "identity",
    category: "identity_consistency",
    sourceType: "identity_derived",
    sourceRef: identitySourceRef,
    evidenceText: identity.consistencyDetail,
    promotable: true,
    downgradeEligible: identity.consistency === "partial_mismatch",
  }));

  // 3. Link signals (with improved sourceRef)
  if (linkStats.malicious > 0) {
    const maliciousUrls = linkStats.criticalLinks
      .filter((cl) => cl.reasons.some((r) => /maliziös|malicious/i.test(r)))
      .map((cl) => cl.link?.hostname || cl.link?.normalized_url)
      .filter(Boolean)
      .slice(0, 3);
    signals.push(makeSignal({
      key: `links:malicious:${linkStats.malicious}`,
      label: `${linkStats.malicious} maliziöse Link-Bewertungen`,
      severity: "critical", tier: 5, domain: "links", category: "link_reputation",
      sourceType: "link_analysis",
      sourceRef: maliciousUrls.length > 0 ? `urls:${maliciousUrls.join(",")}` : `count:${linkStats.malicious}`,
      evidenceText: null,
      promotable: true, downgradeEligible: false,
    }));
  }

  const structuralIssues = linkStats.criticalLinks.filter((cl) =>
    cl.reasons.some((r) => /Punycode|IP-Adresse/i.test(r))
  );
  if (structuralIssues.length > 0) {
    const structuralUrls = structuralIssues
      .map((cl) => cl.link?.hostname || cl.link?.normalized_url)
      .filter(Boolean)
      .slice(0, 3);
    signals.push(makeSignal({
      key: "links:structural",
      label: "Links mit Punycode oder IP-Literal",
      severity: "critical", tier: 5, domain: "links", category: "link_structure",
      sourceType: "link_analysis",
      sourceRef: structuralUrls.length > 0 ? `urls:${structuralUrls.join(",")}` : `count:${structuralIssues.length}`,
      evidenceText: null,
      promotable: true, downgradeEligible: false,
    }));
  }

  if (linkStats.suspicious > 0) {
    signals.push(makeSignal({
      key: `links:suspicious:${linkStats.suspicious}`,
      label: `${linkStats.suspicious} verdächtige Link-Bewertungen`,
      severity: "noteworthy", tier: 3, domain: "links", category: "link_reputation",
      sourceType: "link_analysis",
      sourceRef: `count:${linkStats.suspicious}`,
      evidenceText: null,
      promotable: true, downgradeEligible: false,
    }));
  }

  if (linkStats.total > 0 && linkStats.malicious === 0 && linkStats.criticalLinks.length === 0) {
    signals.push(makeSignal({
      key: "links:clean",
      label: "Alle Links reputationsmäßig unauffällig",
      severity: "positive", tier: 2, domain: "links", category: "link_reputation",
      sourceType: "link_analysis",
      sourceRef: `total:${linkStats.total}`,
      evidenceText: null,
      promotable: true, downgradeEligible: false,
    }));
  }

  // 4. Bulk context (with detection source)
  if (isBulk) {
    const bulkSource = detectBulkSource(result);
    signals.push(makeSignal({
      key: "bulk:detected",
      label: "Newsletter-/Mailing-Dienst erkannt",
      severity: "context", tier: 1, domain: "bulk", category: "bulk_context",
      sourceType: "bulk_detection",
      sourceRef: bulkSource,
      evidenceText: null,
      promotable: true, downgradeEligible: false,
    }));
  }

  // 5. Display-Name spoofing from header findings
  for (const f of headerFindings) {
    if (/display.?name.*(?:inkonsistenz|spoof)/i.test(f.title)) {
      if (!seenCanonical.has("identity:spoofing")) {
        signals.push(makeSignal({
          key: "identity:spoofing",
          label: "Display-Name-Spoofing erkannt",
          severity: "critical", tier: 5, domain: "identity", category: "identity_consistency",
          sourceType: "header_finding", sourceRef: f.id || null,
          evidenceText: f.detail ? `${f.title}: ${f.detail}` : f.title,
          promotable: true, downgradeEligible: false,
        }));
        seenCanonical.add("identity:spoofing");
      }
      break;
    }
  }

  // 6. Header findings → evidence signals
  for (let i = 0; i < headerFindings.length; i++) {
    const f = headerFindings[i];
    const combined = `${f.title} ${f.detail || ""}`;
    const signalKey = matchSignalKey(combined, HEADER_FINDING_SIGNAL_MAP);
    const severity = classifyHeaderSeverity(combined, f.severity, isBulk, bulkDowngradeAllowed);
    const key = signalKey || (f.id ? `header:${f.id}` : `header:idx:${i}`);

    signals.push(makeSignal({
      key,
      label: f.title,
      severity,
      tier: severityToTier(severity),
      domain: keyToDomain(key),
      category: keyToCategory(key),
      sourceType: "header_finding",
      sourceRef: f.id || `idx:${i}`,
      evidenceText: f.detail ? `${f.title}: ${f.detail}` : f.title,
      promotable: !!signalKey,
      downgradeEligible: SOFT_CRITICAL_FINDING.some((p) => p.test(combined)),
    }));
  }

  // 7. Deterministic findings (deduplicated against header findings)
  const detFindings: any[] = result.deterministic_findings || [];
  for (const df of detFindings) {
    if (!df.detail) continue;
    const isDuplicate = headerFindings.some(
      (hf: any) => hf.title === df.detail || (df.factor && hf.title?.toLowerCase().includes(df.factor.replace(/_/g, " ")))
    );
    if (isDuplicate) continue;

    const signalKey = DET_FACTOR_SIGNAL_MAP[df.factor] || null;
    const severity = classifyDetSeverity(df.factor, isBulk, bulkDowngradeAllowed);
    if (!severity) continue;

    const key = signalKey || `det:${df.factor}`;
    signals.push(makeSignal({
      key,
      label: df.detail,
      severity,
      tier: severityToTier(severity),
      domain: keyToDomain(key),
      category: keyToCategory(key),
      sourceType: "det_finding",
      sourceRef: df.factor,
      evidenceText: df.detail,
      promotable: !!signalKey,
      downgradeEligible: /^header_mismatch/.test(df.factor),
    }));
  }

  // 8. LLM evidence strings
  const evidence: string[] = result.assessment?.evidence || [];
  for (let i = 0; i < evidence.length; i++) {
    const e = evidence[i];
    const signalKey = matchSignalKey(e, EVIDENCE_TEXT_SIGNAL_MAP);
    const severity = classifyEvidenceTextSeverity(e);
    const key = signalKey || `evidence:${i}`;

    signals.push(makeSignal({
      key,
      label: e.length > 80 ? e.substring(0, 77) + "..." : e,
      severity,
      tier: severityToTier(severity),
      domain: keyToDomain(key),
      category: signalKey ? keyToCategory(signalKey) : "content_analysis",
      sourceType: "llm_evidence",
      sourceRef: `evidence:${i}`,
      evidenceText: e,
      promotable: !!signalKey,
      downgradeEligible: false,
    }));
  }

  // 9. Content risk signals
  const contentRisks = detectContentRisks(result);
  const contentRiskLevel = assessContentRiskLevel(contentRisks);
  const contentRiskTypes = new Set(contentRisks.map((r) => r.type));

  for (const risk of contentRisks) {
    const key = `content:${risk.type}`;
    // Avoid duplicates (same type from different sources)
    if (signals.some((s) => s.key === key)) continue;

    const CONTENT_LABELS: Record<string, string> = {
      account_threat: "Kontosperrung/-bedrohung im Inhalt",
      urgent_action: "Dringlichkeits-/Handlungsdruck",
      credential_lure: "Aufforderung zur Passwort-/Login-Eingabe",
      payment_lure: "Zahlungsaufforderung/-drohung",
      generic_branding: "Generische Anrede ohne persönlichen Bezug",
      deletion_threat: "Löschungsdrohung für Daten/Konto",
    };

    signals.push(makeSignal({
      key,
      label: CONTENT_LABELS[risk.type] || risk.type,
      severity: risk.type === "generic_branding" ? "noteworthy" : "critical",
      tier: risk.type === "generic_branding" ? 3 : 5,
      domain: "content",
      category: "content_risk",
      sourceType: "content_analysis",
      sourceRef: `${risk.source}:${risk.type}`,
      evidenceText: risk.matchedText,
      promotable: true,
      downgradeEligible: false,
    }));
  }

  // 10. Reputation unknown signal (failed scans ≠ clean)
  if (linkStats.total > 0 && linkStats.scansFailed > 0) {
    const failRatio = linkStats.scansFailed / Math.max(1, linkStats.scansFailed + linkStats.scansCompleted);
    // If more than half the scans failed, or all scans failed, this is noteworthy
    const isSignificant = failRatio >= 0.5 || linkStats.scansCompleted === 0;
    if (isSignificant) {
      const severityLevel: EvidenceSeverity = contentRiskLevel === "high" ? "critical" : "noteworthy";
      signals.push(makeSignal({
        key: "reputation:unknown",
        label: `${linkStats.scansFailed} Reputations-Scan(s) fehlgeschlagen — Ergebnis unsicher`,
        severity: severityLevel,
        tier: contentRiskLevel === "high" ? 4 : 3,
        domain: "links",
        category: "reputation_coverage",
        sourceType: "reputation_scan",
        sourceRef: `failed:${linkStats.scansFailed},completed:${linkStats.scansCompleted}`,
        evidenceText: `${linkStats.scansFailed} von ${linkStats.scansFailed + linkStats.scansCompleted} Reputations-Scans fehlgeschlagen. Ergebnis ist nicht belastbar.`,
        promotable: true,
        downgradeEligible: false,
      }));
    }
  }

  // 11. Auth reweighting: demote auth:*:pass when content risk is high
  // Auth pass becomes "context" tier (hygiene, not exoneration) instead of "positive"
  if (contentRiskLevel === "high") {
    for (const s of signals) {
      if (s.domain === "auth" && s.direction === "positive" && s.severity === "positive") {
        s.severity = "context";
        s.tier = 1 as typeof PRIORITY_TIER.CONTEXT;
        s.direction = "positive"; // still positive, but demoted
        s.promotable = false; // no longer a decision factor
      }
    }
    // Also demote "links:clean" if reputation is unknown
    const hasUnknownReputation = signals.some((s) => s.key === "reputation:unknown");
    if (hasUnknownReputation) {
      for (const s of signals) {
        if (s.key === "links:clean") {
          s.severity = "context";
          s.tier = 1 as typeof PRIORITY_TIER.CONTEXT;
          s.promotable = false;
        }
      }
    }
  }

  return signals;
}

// ─── Bulk detection source ──────────────────────────────────────────────────

function detectBulkSource(result: any): string {
  const headers = result.structured_headers || {};
  if (headers["list-unsubscribe"] || headers["List-Unsubscribe"]) return "header:list-unsubscribe";
  if (headers["precedence"] === "bulk" || headers["Precedence"] === "bulk") return "header:precedence:bulk";
  const findings: any[] = result.header_findings || [];
  for (const f of findings) {
    if (/massen|marketing|bulk/i.test(f.title)) return `finding:${f.id || f.title}`;
    if (/list.?unsubscribe/i.test(f.title) || /list.?unsubscribe/i.test(f.detail || "")) return `finding:${f.id || "list-unsubscribe"}`;
  }
  if (result.assessment?.classification === "advertising") return "classification:advertising";
  return "heuristic";
}

// ─── Projection: PrioritizedSignal[] ────────────────────────────────────────

export function toPrioritizedSignals(signals: NormalizedSignal[]): PrioritizedSignal[] {
  const seen = new Set<string>();
  const result: PrioritizedSignal[] = [];

  for (const s of signals) {
    if (!s.promotable) continue;
    if (seen.has(s.key)) continue;
    seen.add(s.key);

    result.push({
      key: s.key,
      tier: s.tier,
      domain: s.domain,
      label: s.label,
      direction: s.direction,
    });
  }

  return result;
}

// ─── Projection: EvidenceGroups ─────────────────────────────────────────────

export function toEvidenceGroups(signals: NormalizedSignal[]): EvidenceGroups {
  const groups: EvidenceGroups = { critical: [], noteworthy: [], positive: [], context: [] };

  for (const s of signals) {
    if (!s.evidenceText) continue;

    const item: EvidenceItem = {
      key: s.key,
      text: s.evidenceText,
      source: s.sourceType,
      severity: s.severity,
    };
    groups[s.severity].push(item);
  }

  return groups;
}
