/**
 * Central signal normalization.
 *
 * Transforms raw analysis sources into NormalizedSignal[].
 * This is the single transformation point — all downstream views
 * (PrioritizedSignal[], EvidenceGroups, DecisionFactors) derive from it.
 *
 * ## Source mapping
 *
 * | Raw source               | sourceType       | Key pattern              |
 * |--------------------------|------------------|--------------------------|
 * | authentication_results   | auth_result      | auth:{proto}:{status}    |
 * | header_findings[]        | header_finding   | auth:*  / identity:*     |
 * | deterministic_findings[] | det_finding      | auth:*  / links:*        |
 * | link analysis            | link_analysis    | links:{type}[:{count}]   |
 * | sender domain comparison | identity_derived | identity:{status}        |
 * | assessment.evidence[]    | llm_evidence     | (mapped or evidence:{i}) |
 * | structured_headers       | bulk_detection   | bulk:detected            |
 */

import type {
  NormalizedSignal,
  EvidenceSeverity,
  PriorityTier,
  SignalDomain,
  SignalCategory,
  SignalSourceType,
  IdentityAssessment,
  LinkStats,
  PrioritizedSignal,
  EvidenceItem,
  EvidenceGroups,
  PRIORITY_TIER,
} from "./types";
import { evaluateBulkDowngrade } from "./priority";

// ─── Canonical Key ──────────────────────────────────────────────────────────

/**
 * Derives the dedup group from a signal key.
 * "auth:spf:pass" → "auth:spf"
 * "links:malicious:3" → "links:malicious"
 * "identity:mismatch" → "identity:mismatch"
 */
export function deriveCanonicalKey(key: string): string {
  const parts = key.split(":");
  // For auth signals, canonical is domain:protocol (drop status)
  if (parts[0] === "auth" && parts.length >= 3) return `${parts[0]}:${parts[1]}`;
  // For links with counts, drop the count
  if (parts[0] === "links" && parts.length >= 3) return `${parts[0]}:${parts[1]}`;
  return key;
}

// ─── Signal Key Mapping Tables ──────────────────────────────────────────────
// Centralized: these tables define ALL semantic mappings from raw sources
// to signal keys. Previously scattered across evidence.ts.

/** Header finding title → signal key (if semantically equivalent) */
const HEADER_FINDING_SIGNAL_MAP: Array<{ pattern: RegExp; key: string }> = [
  // Auth pass
  { pattern: /spf.*(?:bestanden|pass)/i, key: "auth:spf:pass" },
  { pattern: /dkim.*(?:bestanden|pass)/i, key: "auth:dkim:pass" },
  { pattern: /dmarc.*(?:bestanden|pass)/i, key: "auth:dmarc:pass" },
  // Auth fail
  { pattern: /spf.*(?:fehlgeschlagen|fail)/i, key: "auth:spf:fail" },
  { pattern: /dkim.*(?:fehlgeschlagen|fail)/i, key: "auth:dkim:fail" },
  { pattern: /dmarc.*(?:fehlgeschlagen|fail)/i, key: "auth:dmarc:fail" },
  // Auth missing
  { pattern: /kein.*spf/i, key: "auth:spf:none" },
  { pattern: /kein.*dkim/i, key: "auth:dkim:none" },
  { pattern: /kein.*dmarc/i, key: "auth:dmarc:none" },
  // Identity
  { pattern: /display.?name.*(?:inkonsistenz|spoof)/i, key: "identity:spoofing" },
  { pattern: /from.*reply.?to.*mismatch/i, key: "identity:mismatch" },
  { pattern: /from.*return.?path.*mismatch/i, key: "identity:mismatch" },
  { pattern: /return.?path.*mismatch/i, key: "identity:mismatch" },
  // Bulk
  { pattern: /massen.*header|marketing.*header|bulk.*header/i, key: "bulk:detected" },
];

/** Deterministic finding factor → signal key */
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

/** LLM evidence text → signal key */
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

// ─── Severity Classification Tables ─────────────────────────────────────────

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

const EV_CRITICAL = [/phishing/i, /malicious|maliziös|bösartig/i, /spoofing|spoof/i, /spf.*(fail|none|softfail)/i, /dkim.*(fail|none)/i, /dmarc.*(fail|none|reject)/i, /verdächtig.*domain|suspicious.*domain/i, /identitätsabweichung|identity.*mismatch/i, /impersonat/i];
const EV_POSITIVE = [/spf.*(pass|erfolgreich|valide|bestanden)/i, /dkim.*(pass|erfolgreich|valide|bestanden)/i, /dmarc.*(pass|erfolgreich|valide|bestanden)/i, /keine.*(bösartig|malizi|suspicious|verdächtig|bedroh)/i, /no.*(malicious|suspicious|threat)/i, /reputation.*(gut|unauffällig|clean|good)/i, /authentif.*(erfolgreich|valide|bestanden)/i, /legitimate|legitim/i, /vertrauenswürdig|trusted/i];
const EV_CONTEXT = [/newsletter|marketing|bulk|mailing/i, /list.?unsubscribe|abmelde/i, /tracking|click.?tracking/i];

function classifyEvidenceTextSeverity(text: string): EvidenceSeverity {
  for (const p of EV_CRITICAL) { if (p.test(text)) return "critical"; }
  for (const p of EV_POSITIVE) { if (p.test(text)) return "positive"; }
  for (const p of EV_CONTEXT) { if (p.test(text)) return "context"; }
  return "noteworthy";
}

// ─── Tier/Domain/Category derivation ────────────────────────────────────────

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
  return "content_analysis";
}

function severityToDirection(severity: EvidenceSeverity): "positive" | "negative" {
  return (severity === "positive" || severity === "context") ? "positive" : "negative";
}

// ─── Main Normalization ─────────────────────────────────────────────────────

/**
 * Normalizes all raw analysis sources into a flat NormalizedSignal array.
 *
 * This is the single entry point for all signal derivation.
 * The result can be projected into PrioritizedSignal[], EvidenceGroups, etc.
 */
export function normalizeSignals(
  result: any,
  identity: IdentityAssessment,
  linkStats: LinkStats,
  isBulk: boolean,
): NormalizedSignal[] {
  const signals: NormalizedSignal[] = [];
  const seenCanonical = new Set<string>();

  // Compute bulk downgrade eligibility once
  // We need PrioritizedSignals for the guard — bootstrap from identity/link signals
  const bootstrapSignals = bootstrapPrioritySignals(identity, linkStats, result.header_findings || []);
  const bulkDowngrade = isBulk
    ? evaluateBulkDowngrade(bootstrapSignals, identity.authSignals)
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
    sourceRef: null,
    evidenceText: identity.consistencyDetail,
    promotable: true,
    downgradeEligible: identity.consistency === "partial_mismatch",
  }));

  // 3. Link signals
  if (linkStats.malicious > 0) {
    signals.push(makeSignal({
      key: `links:malicious:${linkStats.malicious}`,
      label: `${linkStats.malicious} maliziöse Link-Bewertungen`,
      severity: "critical", tier: 5, domain: "links", category: "link_reputation",
      sourceType: "link_analysis", sourceRef: null, evidenceText: null,
      promotable: true, downgradeEligible: false,
    }));
  }
  const structuralIssues = linkStats.criticalLinks.filter((cl) =>
    cl.reasons.some((r) => /Punycode|IP-Adresse/i.test(r))
  );
  if (structuralIssues.length > 0) {
    signals.push(makeSignal({
      key: "links:structural",
      label: "Links mit Punycode oder IP-Literal",
      severity: "critical", tier: 5, domain: "links", category: "link_structure",
      sourceType: "link_analysis", sourceRef: null, evidenceText: null,
      promotable: true, downgradeEligible: false,
    }));
  }
  if (linkStats.suspicious > 0) {
    signals.push(makeSignal({
      key: `links:suspicious:${linkStats.suspicious}`,
      label: `${linkStats.suspicious} verdächtige Link-Bewertungen`,
      severity: "noteworthy", tier: 3, domain: "links", category: "link_reputation",
      sourceType: "link_analysis", sourceRef: null, evidenceText: null,
      promotable: true, downgradeEligible: false,
    }));
  }
  if (linkStats.total > 0 && linkStats.malicious === 0 && linkStats.criticalLinks.length === 0) {
    signals.push(makeSignal({
      key: "links:clean",
      label: "Alle Links reputationsmäßig unauffällig",
      severity: "positive", tier: 2, domain: "links", category: "link_reputation",
      sourceType: "link_analysis", sourceRef: null, evidenceText: null,
      promotable: true, downgradeEligible: false,
    }));
  }

  // 4. Bulk context
  if (isBulk) {
    signals.push(makeSignal({
      key: "bulk:detected",
      label: "Newsletter-/Mailing-Dienst erkannt",
      severity: "context", tier: 1, domain: "bulk", category: "bulk_context",
      sourceType: "bulk_detection", sourceRef: null, evidenceText: null,
      promotable: true, downgradeEligible: false,
    }));
  }

  // 5. Display-Name spoofing from header findings
  const headerFindings: any[] = result.header_findings || [];
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

  return signals;
}

// ─── Det finding severity (unchanged logic, moved here) ─────────────────────

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

// ─── Helper: construct NormalizedSignal ──────────────────────────────────────

function makeSignal(input: Omit<NormalizedSignal, "canonicalKey" | "direction"> & { direction?: "positive" | "negative" }): NormalizedSignal {
  return {
    ...input,
    canonicalKey: deriveCanonicalKey(input.key),
    direction: input.direction ?? severityToDirection(input.severity),
  };
}

// ─── Bootstrap PrioritizedSignals for bulk guard ────────────────────────────
// Needed because bulk downgrade guard requires signals, but we're still building them.

function bootstrapPrioritySignals(
  identity: IdentityAssessment,
  linkStats: LinkStats,
  headerFindings: any[]
): PrioritizedSignal[] {
  const signals: PrioritizedSignal[] = [];
  for (const auth of identity.authSignals) {
    if (auth.status === "pass") signals.push({ key: `auth:${auth.protocol.toLowerCase()}:pass`, tier: 2 as any, domain: "auth", label: "", direction: "positive" });
    else if (auth.status === "fail") signals.push({ key: `auth:${auth.protocol.toLowerCase()}:fail`, tier: 5 as any, domain: "auth", label: "", direction: "negative" });
  }
  if (linkStats.malicious > 0) signals.push({ key: "links:malicious", tier: 5 as any, domain: "links", label: "", direction: "negative" });
  for (const f of headerFindings) {
    if (/display.?name.*(?:inkonsistenz|spoof)/i.test(f.title)) {
      signals.push({ key: "identity:spoofing", tier: 5 as any, domain: "identity", label: "", direction: "negative" });
      break;
    }
  }
  return signals;
}

// ─── Projection Functions ───────────────────────────────────────────────────
// Project NormalizedSignal[] into the view types used by UI components.

/**
 * Projects NormalizedSignals into PrioritizedSignals for conflict resolution.
 * Only includes promotable signals (those with known semantic keys).
 */
export function toPrioritizedSignals(signals: NormalizedSignal[]): PrioritizedSignal[] {
  const seen = new Set<string>();
  const result: PrioritizedSignal[] = [];

  for (const s of signals) {
    if (!s.promotable) continue;
    // Deduplicate by key (multiple raw sources may map to same signal)
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

/**
 * Projects NormalizedSignals into EvidenceGroups for UI display.
 * Includes ALL signals (promotable or not) for complete evidence listing.
 */
export function toEvidenceGroups(signals: NormalizedSignal[]): EvidenceGroups {
  const groups: EvidenceGroups = { critical: [], noteworthy: [], positive: [], context: [] };

  for (const s of signals) {
    // Skip signals without evidence text (derived signals like identity:consistent)
    if (!s.evidenceText) continue;

    // Map sourceType to the legacy source field for component compatibility
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
