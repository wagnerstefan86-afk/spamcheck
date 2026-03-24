/**
 * Shared types for the analysis module.
 *
 * ## Type Hierarchy
 *
 * NormalizedSignal — the canonical internal representation.
 * All other signal/evidence types derive from it.
 *
 * Raw sources (header_findings, deterministic_findings, auth_results, etc.)
 *   → normalize.ts → NormalizedSignal[]
 *     → priority views (PrioritizedSignal[])
 *     → evidence views (EvidenceItem[] / EvidenceGroups)
 *     → decision factors
 *     → serializable AnalysisSummary
 */

// ─── Signal Domains & Categories ────────────────────────────────────────────

export type SignalDomain = "auth" | "identity" | "links" | "content" | "bulk";

export type SignalCategory =
  | "authentication"
  | "identity_consistency"
  | "link_reputation"
  | "link_structure"
  | "bulk_context"
  | "content_analysis";

// ─── Source Tracing ─────────────────────────────────────────────────────────

export type SignalSourceType =
  | "auth_result"       // parsed from authentication_results string
  | "header_finding"    // from header_findings[]
  | "det_finding"       // from deterministic_findings[]
  | "link_analysis"     // derived from link scan results
  | "identity_derived"  // derived from sender domain comparison
  | "llm_evidence"      // from assessment.evidence[]
  | "bulk_detection";   // derived from structured_headers / header_findings

// ─── Priority Tiers ────────────────────────────────────────────────────────

export const PRIORITY_TIER = {
  CONTEXT: 1,
  POSITIVE: 2,
  NOTEWORTHY: 3,
  CRITICAL_SOFT: 4,
  CRITICAL_HARD: 5,
} as const;

export type PriorityTier = (typeof PRIORITY_TIER)[keyof typeof PRIORITY_TIER];

// ─── NormalizedSignal — the canonical type ──────────────────────────────────

export type EvidenceSeverity = "positive" | "noteworthy" | "critical" | "context";

export type NormalizedSignal = {
  /** Stable key. Format: "domain:type[:qualifier]" */
  key: string;

  /**
   * Dedup group key. Signals with the same canonicalKey represent the same
   * semantic concept from different sources (e.g. "auth:spf" groups
   * "auth:spf:pass" and "auth:spf:fail").
   */
  canonicalKey: string;

  /** Human-readable label for UI display */
  label: string;

  /** Severity for evidence grouping */
  severity: EvidenceSeverity;

  /** Priority tier for conflict resolution */
  tier: PriorityTier;

  /** Positive = legitimizing, negative = risk indicator */
  direction: "positive" | "negative";

  /** Signal domain */
  domain: SignalDomain;

  /** Finer-grained category */
  category: SignalCategory;

  // ── Source tracing ──
  /** What kind of raw source this signal was derived from */
  sourceType: SignalSourceType;

  /**
   * Reference to the specific raw source item.
   * Examples: "HDR-001", "spf_fail", "evidence:2", "link:42"
   */
  sourceRef: string | null;

  /** Original finding/evidence text (for display) */
  evidenceText: string | null;

  // ── Promotion / conflict metadata ──
  /** Eligible for promotion to DecisionFactors block */
  promotable: boolean;

  /** Can be downgraded from critical to noteworthy in bulk context */
  downgradeEligible: boolean;
};

// ─── Derived view types (for UI components) ─────────────────────────────────
// These are thin projections of NormalizedSignal, kept for component API stability.

export type EvidenceItem = {
  key: string;
  text: string;
  source: SignalSourceType;
  severity: EvidenceSeverity;
};

export type EvidenceGroups = {
  critical: EvidenceItem[];
  noteworthy: EvidenceItem[];
  positive: EvidenceItem[];
  context: EvidenceItem[];
};

export type PrioritizedSignal = {
  key: string;
  tier: PriorityTier;
  domain: SignalDomain;
  label: string;
  direction: "positive" | "negative";
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

export type ConflictAssessment = {
  hasConflict: boolean;
  dominantSignal: PrioritizedSignal | null;
  explanation: string | null;
  bulkDowngradeApplied: boolean;
  bulkDowngradeBlocked: boolean;
  bulkDowngradeBlockReason: string | null;
};

// ─── Serializable Analysis Summary (API/Export ready) ───────────────────────

export type AnalysisSummary = {
  signals: Array<{
    key: string;
    canonicalKey: string;
    label: string;
    severity: EvidenceSeverity;
    tier: PriorityTier;
    direction: "positive" | "negative";
    domain: SignalDomain;
    category: SignalCategory;
    sourceType: SignalSourceType;
    sourceRef: string | null;
    promotable: boolean;
    downgradeEligible: boolean;
  }>;
  decisionFactors: {
    negative: string[]; // signal keys
    positive: string[]; // signal keys
  };
  promotedKeys: string[];
  conflict: {
    hasConflict: boolean;
    dominantSignalKey: string | null;
    explanation: string | null;
    bulkDowngradeApplied: boolean;
  };
};
