/**
 * Evidence classification with stable keys and priority-aware bulk downgrade.
 *
 * Every evidence item gets a deterministic key:
 * - Header findings: "header:{finding_id}" (e.g. "header:HDR-001")
 * - Assessment evidence: "evidence:{index}" (e.g. "evidence:0")
 * - Deterministic findings: "det:{factor}" (e.g. "det:spf_fail")
 *
 * Additionally, each item gets a `signalKey` if it maps to a known
 * PrioritizedSignal, enabling exact dedup against promoted factors.
 */

import type { EvidenceSeverity, EvidenceItem, EvidenceGroups, PrioritizedSignal } from "./types";
import type { BulkDowngradeDecision } from "./priority";
import { evaluateBulkDowngrade } from "./priority";
import type { AuthSignal } from "./types";

// ─── Signal Key Mapping ─────────────────────────────────────────────────────
// Maps evidence content to the PrioritizedSignal key it corresponds to.
// This is the bridge between evidence items and the promotion system.

/**
 * Determines the signal key this header finding maps to (if any).
 * Returns null if no direct signal correspondence exists.
 */
function headerFindingToSignalKey(title: string, detail: string): string | null {
  const combined = `${title} ${detail}`.toLowerCase();

  // Auth results → auth:{protocol}:{status}
  if (/spf.*(?:bestanden|pass)/.test(combined)) return "auth:spf:pass";
  if (/spf.*(?:fehlgeschlagen|fail)/.test(combined)) return "auth:spf:fail";
  if (/kein.*spf/.test(combined)) return "auth:spf:none";
  if (/dkim.*(?:bestanden|pass)/.test(combined)) return "auth:dkim:pass";
  if (/dkim.*(?:fehlgeschlagen|fail)/.test(combined)) return "auth:dkim:fail";
  if (/kein.*dkim/.test(combined)) return "auth:dkim:none";
  if (/dmarc.*(?:bestanden|pass)/.test(combined)) return "auth:dmarc:pass";
  if (/dmarc.*(?:fehlgeschlagen|fail)/.test(combined)) return "auth:dmarc:fail";
  if (/kein.*dmarc/.test(combined)) return "auth:dmarc:none";

  // Identity
  if (/display.?name.*(?:inkonsistenz|spoof)/.test(combined)) return "identity:spoofing";
  if (/from.*reply.?to.*mismatch/.test(combined)) return "identity:mismatch";
  if (/from.*return.?path.*mismatch/.test(combined)) return "identity:mismatch";
  if (/return.?path.*mismatch/.test(combined)) return "identity:mismatch";

  // Bulk
  if (/massen.*header|marketing.*header|bulk.*header/.test(combined)) return "bulk:detected";

  return null;
}

/**
 * Maps deterministic finding factor to signal key.
 */
function detFactorToSignalKey(factor: string): string | null {
  const map: Record<string, string> = {
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
  return map[factor] || null;
}

/**
 * Maps assessment evidence text to signal key.
 */
function evidenceTextToSignalKey(text: string): string | null {
  const lower = text.toLowerCase();
  if (/spf.*(pass|erfolgreich|bestanden)/.test(lower)) return "auth:spf:pass";
  if (/dkim.*(pass|erfolgreich|bestanden)/.test(lower)) return "auth:dkim:pass";
  if (/dmarc.*(pass|erfolgreich|bestanden)/.test(lower)) return "auth:dmarc:pass";
  if (/spf.*(fail|none|softfail)/.test(lower)) return "auth:spf:fail";
  if (/dkim.*(fail|none)/.test(lower)) return "auth:dkim:fail";
  if (/dmarc.*(fail|none|reject)/.test(lower)) return "auth:dmarc:fail";
  if (/keine.*(bösartig|malizi|suspicious|verdächtig)/.test(lower)) return "links:clean";
  if (/no.*(malicious|suspicious|threat)/.test(lower)) return "links:clean";
  if (/malicious|maliziös|bösartig/.test(lower)) return "links:malicious";
  if (/spoofing|spoof/.test(lower)) return "identity:spoofing";
  if (/impersonat/.test(lower)) return "identity:spoofing";
  return null;
}

// ─── Pattern Tables ─────────────────────────────────────────────────────────

const POSITIVE_FINDING_PATTERNS = [
  /spf.*(?:bestanden|pass)/i,
  /dkim.*(?:bestanden|pass)/i,
  /dmarc.*(?:bestanden|pass)/i,
  /authentifizierung.*(?:erfolgreich|valide)/i,
];

const CONTEXT_FINDING_PATTERNS = [
  /massen.*header|marketing.*header|bulk.*header/i,
  /list.?unsubscribe/i,
  /hoher scl/i,
  /spam.*header.*(?:scl|bcl)/i,
  /lange received/i,
];

const HARD_CRITICAL_FINDING_PATTERNS = [
  /spf.*fehlgeschlagen|spf.*fail/i,
  /dkim.*fehlgeschlagen|dkim.*fail/i,
  /dmarc.*fehlgeschlagen|dmarc.*fail/i,
  /display.?name.*(?:inkonsistenz|spoof)/i,
];

const SOFT_CRITICAL_FINDING_PATTERNS = [
  /from.*reply.?to.*mismatch/i,
  /from.*return.?path.*mismatch/i,
];

const NOTEWORTHY_FINDING_PATTERNS = [
  /return.?path.*mismatch/i,
  /kein.*(?:spf|dkim|dmarc)/i,
];

function classifyHeaderFinding(
  title: string, detail: string, backendSeverity: string,
  isBulkMail: boolean, bulkDowngradeAllowed: boolean
): EvidenceSeverity {
  const combined = `${title} ${detail}`;
  for (const p of POSITIVE_FINDING_PATTERNS) { if (p.test(combined)) return "positive"; }
  for (const p of CONTEXT_FINDING_PATTERNS) { if (p.test(combined)) return "context"; }
  for (const p of HARD_CRITICAL_FINDING_PATTERNS) { if (p.test(combined)) return "critical"; }
  for (const p of SOFT_CRITICAL_FINDING_PATTERNS) {
    if (p.test(combined)) return (isBulkMail && bulkDowngradeAllowed) ? "noteworthy" : "critical";
  }
  for (const p of NOTEWORTHY_FINDING_PATTERNS) { if (p.test(combined)) return "noteworthy"; }
  if (backendSeverity === "critical") return "critical";
  if (backendSeverity === "warning") return "noteworthy";
  return "positive";
}

const EVIDENCE_CRITICAL = [
  /phishing/i, /malicious|maliziös|bösartig/i, /spoofing|spoof/i,
  /spf.*(fail|none|softfail)/i, /dkim.*(fail|none)/i, /dmarc.*(fail|none|reject)/i,
  /verdächtig.*domain|suspicious.*domain/i, /identitätsabweichung|identity.*mismatch/i,
  /impersonat/i,
];
const EVIDENCE_POSITIVE = [
  /spf.*(pass|erfolgreich|valide|bestanden)/i, /dkim.*(pass|erfolgreich|valide|bestanden)/i,
  /dmarc.*(pass|erfolgreich|valide|bestanden)/i,
  /keine.*(bösartig|malizi|suspicious|verdächtig|bedroh)/i,
  /no.*(malicious|suspicious|threat)/i, /reputation.*(gut|unauffällig|clean|good)/i,
  /authentif.*(erfolgreich|valide|bestanden)/i, /legitimate|legitim/i, /vertrauenswürdig|trusted/i,
];
const EVIDENCE_CONTEXT = [
  /newsletter|marketing|bulk|mailing/i, /list.?unsubscribe|abmelde/i, /tracking|click.?tracking/i,
];

function classifyEvidenceText(text: string): EvidenceSeverity {
  for (const p of EVIDENCE_CRITICAL) { if (p.test(text)) return "critical"; }
  for (const p of EVIDENCE_POSITIVE) { if (p.test(text)) return "positive"; }
  for (const p of EVIDENCE_CONTEXT) { if (p.test(text)) return "context"; }
  return "noteworthy";
}

function classifyDetFinding(factor: string, isBulk: boolean, bulkDowngradeAllowed: boolean): EvidenceSeverity | null {
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

// ─── Main Classification Function ───────────────────────────────────────────

export function classifyEvidence(
  result: any,
  isBulk: boolean,
  signals: PrioritizedSignal[],
  authSignals: AuthSignal[]
): EvidenceGroups {
  const groups: EvidenceGroups = { critical: [], noteworthy: [], positive: [], context: [] };

  const downgradeDecision: BulkDowngradeDecision = isBulk
    ? evaluateBulkDowngrade(signals, authSignals)
    : { allowed: false, reason: null };
  const bulkDowngradeAllowed = downgradeDecision.allowed;

  // 1. Assessment evidence strings — key: "evidence:{index}"
  const evidence: string[] = result.assessment?.evidence || [];
  for (let i = 0; i < evidence.length; i++) {
    const e = evidence[i];
    const severity = classifyEvidenceText(e);
    const signalKey = evidenceTextToSignalKey(e);
    groups[severity].push({
      key: signalKey || `evidence:${i}`,
      text: e,
      source: "evidence",
      severity,
    });
  }

  // 2. Header findings — key: "header:{id}" or "header:idx:{index}"
  const findings: any[] = result.header_findings || [];
  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    const severity = classifyHeaderFinding(f.title, f.detail || "", f.severity, isBulk, bulkDowngradeAllowed);
    const text = f.detail ? `${f.title}: ${f.detail}` : f.title;
    const signalKey = headerFindingToSignalKey(f.title, f.detail || "");
    groups[severity].push({
      key: signalKey || (f.id ? `header:${f.id}` : `header:idx:${i}`),
      text,
      source: "header",
      severity,
    });
  }

  // 3. Deterministic findings — key: "det:{factor}"
  const detFindings: any[] = result.deterministic_findings || [];
  for (const df of detFindings) {
    const isDuplicate = findings.some(
      (hf: any) => hf.title === df.detail || (df.factor && hf.title?.toLowerCase().includes(df.factor.replace(/_/g, " ")))
    );
    if (isDuplicate) continue;
    const severity = classifyDetFinding(df.factor, isBulk, bulkDowngradeAllowed);
    if (severity && df.detail) {
      const signalKey = detFactorToSignalKey(df.factor);
      groups[severity].push({
        key: signalKey || `det:${df.factor}`,
        text: df.detail,
        source: "scoring",
        severity,
      });
    }
  }

  return groups;
}
