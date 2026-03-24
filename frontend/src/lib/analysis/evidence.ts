/**
 * Evidence classification with priority-aware bulk downgrade.
 *
 * Uses the priority model to guard against unsafe downgrades.
 */

import type { EvidenceSeverity, EvidenceItem, EvidenceGroups, PrioritizedSignal } from "./types";
import type { BulkDowngradeDecision } from "./priority";
import { evaluateBulkDowngrade } from "./priority";
import type { AuthSignal } from "./types";

// ─── Pattern Tables ─────────────────────────────────────────────────────────
// Ordered by priority: earlier match wins. No catch-all wildcards.

/** Always positive regardless of backend severity */
const POSITIVE_FINDING_PATTERNS = [
  /spf.*(?:bestanden|pass)/i,
  /dkim.*(?:bestanden|pass)/i,
  /dmarc.*(?:bestanden|pass)/i,
  /authentifizierung.*(?:erfolgreich|valide)/i,
];

/** Informational/neutral — typical for bulk/marketing mail */
const CONTEXT_FINDING_PATTERNS = [
  /massen.*header|marketing.*header|bulk.*header/i,
  /list.?unsubscribe/i,
  /hoher scl/i,
  /spam.*header.*(?:scl|bcl)/i,
  /lange received/i,
];

/** Hard-critical — real security indicators, NEVER downgraded */
const HARD_CRITICAL_FINDING_PATTERNS = [
  /spf.*fehlgeschlagen|spf.*fail/i,
  /dkim.*fehlgeschlagen|dkim.*fail/i,
  /dmarc.*fehlgeschlagen|dmarc.*fail/i,
  /display.?name.*(?:inkonsistenz|spoof)/i,
];

/** Soft-critical — can be downgraded in safe bulk context */
const SOFT_CRITICAL_FINDING_PATTERNS = [
  /from.*reply.?to.*mismatch/i,
  /from.*return.?path.*mismatch/i,
];

/** Always noteworthy */
const NOTEWORTHY_FINDING_PATTERNS = [
  /return.?path.*mismatch/i,
  /kein.*(?:spf|dkim|dmarc)/i,
];

// ─── Header Finding Classification ──────────────────────────────────────────

function classifyHeaderFinding(
  title: string,
  detail: string,
  backendSeverity: string,
  isBulkMail: boolean,
  bulkDowngradeAllowed: boolean
): EvidenceSeverity {
  const combined = `${title} ${detail}`;

  // 1. Positive patterns — always positive
  for (const p of POSITIVE_FINDING_PATTERNS) {
    if (p.test(combined)) return "positive";
  }

  // 2. Context patterns — always context
  for (const p of CONTEXT_FINDING_PATTERNS) {
    if (p.test(combined)) return "context";
  }

  // 3. Hard-critical — NEVER downgraded
  for (const p of HARD_CRITICAL_FINDING_PATTERNS) {
    if (p.test(combined)) return "critical";
  }

  // 4. Soft-critical — downgraded ONLY if bulk + guard passed
  for (const p of SOFT_CRITICAL_FINDING_PATTERNS) {
    if (p.test(combined)) {
      if (isBulkMail && bulkDowngradeAllowed) return "noteworthy";
      return "critical";
    }
  }

  // 5. Noteworthy patterns
  for (const p of NOTEWORTHY_FINDING_PATTERNS) {
    if (p.test(combined)) return "noteworthy";
  }

  // 6. Fallback on backend severity
  if (backendSeverity === "critical") return "critical";
  if (backendSeverity === "warning") return "noteworthy";
  return "positive";
}

// ─── Evidence Text Classification ───────────────────────────────────────────

const EVIDENCE_CRITICAL = [
  /phishing/i,
  /malicious|maliziös|bösartig/i,
  /spoofing|spoof/i,
  /spf.*(fail|none|softfail)/i,
  /dkim.*(fail|none)/i,
  /dmarc.*(fail|none|reject)/i,
  /verdächtig.*domain|suspicious.*domain/i,
  /identitätsabweichung|identity.*mismatch/i,
  /impersonat/i,
];

const EVIDENCE_POSITIVE = [
  /spf.*(pass|erfolgreich|valide|bestanden)/i,
  /dkim.*(pass|erfolgreich|valide|bestanden)/i,
  /dmarc.*(pass|erfolgreich|valide|bestanden)/i,
  /keine.*(bösartig|malizi|suspicious|verdächtig|bedroh)/i,
  /no.*(malicious|suspicious|threat)/i,
  /reputation.*(gut|unauffällig|clean|good)/i,
  /authentif.*(erfolgreich|valide|bestanden)/i,
  /legitimate|legitim/i,
  /vertrauenswürdig|trusted/i,
];

const EVIDENCE_CONTEXT = [
  /newsletter|marketing|bulk|mailing/i,
  /list.?unsubscribe|abmelde/i,
  /tracking|click.?tracking/i,
];

function classifyEvidenceText(text: string): EvidenceSeverity {
  for (const p of EVIDENCE_CRITICAL) {
    if (p.test(text)) return "critical";
  }
  for (const p of EVIDENCE_POSITIVE) {
    if (p.test(text)) return "positive";
  }
  for (const p of EVIDENCE_CONTEXT) {
    if (p.test(text)) return "context";
  }
  return "noteworthy";
}

// ─── Deterministic Finding Classification ───────────────────────────────────

function classifyDetFinding(factor: string, isBulk: boolean, bulkDowngradeAllowed: boolean): EvidenceSeverity | null {
  // Hard-critical: NEVER downgraded
  if (/^(spf_fail|dkim_fail|dmarc_fail|display_name_spoof|vt_malicious)$/.test(factor)) return "critical";
  if (/^(display_mismatch|ip_literal|punycode|suspicious_tld)$/.test(factor)) return "critical";

  // Missing auth → noteworthy
  if (/^(spf_missing|dkim_missing)$/.test(factor)) return "noteworthy";

  // Soft-critical mismatches: downgrade only with guard
  if (/^(header_mismatch)$/.test(factor)) {
    return (isBulk && bulkDowngradeAllowed) ? "noteworthy" : "critical";
  }
  if (/^(header_mismatch_minor)$/.test(factor)) {
    return (isBulk && bulkDowngradeAllowed) ? "context" : "noteworthy";
  }

  // Suspicious (from VT) → noteworthy
  if (/^(vt_suspicious)$/.test(factor)) return "noteworthy";

  // Bulk/marketing context
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

  // Determine if bulk downgrade is safe using the priority guard
  const downgradeDecision: BulkDowngradeDecision = isBulk
    ? evaluateBulkDowngrade(signals, authSignals)
    : { allowed: false, reason: null };
  const bulkDowngradeAllowed = downgradeDecision.allowed;

  // 1. Classify assessment evidence strings
  const evidence: string[] = result.assessment?.evidence || [];
  for (const e of evidence) {
    const severity = classifyEvidenceText(e);
    groups[severity].push({ text: e, source: "evidence", severity });
  }

  // 2. Classify header findings with guarded downgrade
  const findings: any[] = result.header_findings || [];
  for (const f of findings) {
    const severity = classifyHeaderFinding(f.title, f.detail || "", f.severity, isBulk, bulkDowngradeAllowed);
    const text = f.detail ? `${f.title}: ${f.detail}` : f.title;
    groups[severity].push({ text, source: "header", severity });
  }

  // 3. Deterministic findings (deduplicated)
  const detFindings: any[] = result.deterministic_findings || [];
  for (const df of detFindings) {
    const isDuplicate = findings.some(
      (hf: any) => hf.title === df.detail || (df.factor && hf.title?.toLowerCase().includes(df.factor.replace(/_/g, " ")))
    );
    if (isDuplicate) continue;
    const severity = classifyDetFinding(df.factor, isBulk, bulkDowngradeAllowed);
    if (severity && df.detail) {
      groups[severity].push({ text: df.detail, source: "scoring", severity });
    }
  }

  return groups;
}
