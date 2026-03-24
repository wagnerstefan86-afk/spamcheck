/**
 * Shared types for the analysis module.
 */

export type EvidenceSeverity = "positive" | "noteworthy" | "critical" | "context";

export type EvidenceItem = {
  text: string;
  source: "evidence" | "header" | "link" | "auth" | "scoring";
  severity: EvidenceSeverity;
};

export type EvidenceGroups = {
  critical: EvidenceItem[];
  noteworthy: EvidenceItem[];
  positive: EvidenceItem[];
  context: EvidenceItem[];
};

export type AuthSignal = {
  protocol: "SPF" | "DKIM" | "DMARC";
  status: "pass" | "fail" | "none" | "softfail" | "neutral" | "unknown";
};

export type IdentityAssessment = {
  fromDomain: string | null;
  replyToDomain: string | null;
  returnPathDomain: string | null;
  authSignals: AuthSignal[];
  consistency: "consistent" | "partial_mismatch" | "suspicious";
  consistencyDetail: string;
  isBulkSender: boolean;
};

export type CriticalLink = {
  link: any;
  reasons: string[];
};

export type LinkStats = {
  total: number;
  malicious: number;
  suspicious: number;
  scansFailed: number;
  scansCompleted: number;
  criticalLinks: CriticalLink[];
};

export type ScoreDriver = {
  label: string;
  impact: string;
  direction: "positive" | "negative" | "neutral";
  category: "phishing" | "advertising" | "legitimacy";
};

/**
 * Signal priority tiers (higher number = higher priority).
 *
 * TIER 1 (informational): context, bulk-mail markers
 * TIER 2 (baseline positive): auth pass, clean links
 * TIER 3 (noteworthy): mismatches, missing auth
 * TIER 4 (critical-overridable): identity mismatches that CAN be downgraded
 * TIER 5 (critical-hard): malicious links, auth failures, spoofing — NEVER downgraded
 */
export const PRIORITY_TIER = {
  CONTEXT: 1,
  POSITIVE: 2,
  NOTEWORTHY: 3,
  CRITICAL_SOFT: 4,
  CRITICAL_HARD: 5,
} as const;

export type PriorityTier = (typeof PRIORITY_TIER)[keyof typeof PRIORITY_TIER];

/**
 * Describes a signal with its priority for conflict resolution.
 */
export type PrioritizedSignal = {
  tier: PriorityTier;
  domain: "auth" | "links" | "identity" | "content" | "bulk";
  label: string;
  direction: "positive" | "negative";
};

/**
 * Result of conflict analysis: which signals are in tension,
 * which one dominates, and a human-readable explanation.
 */
export type ConflictAssessment = {
  hasConflict: boolean;
  dominantSignal: PrioritizedSignal | null;
  explanation: string | null;
  /** Whether bulk-context downgrade was applied and why */
  bulkDowngradeApplied: boolean;
  bulkDowngradeBlocked: boolean;
  bulkDowngradeBlockReason: string | null;
};
