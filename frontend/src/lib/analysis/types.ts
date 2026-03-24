/**
 * Shared types for the analysis module.
 *
 * ## Type Hierarchy
 *
 * Raw backend result
 *   → analyzeResult() → AnalysisResult (internal, with Sets/rich objects)
 *     → AnalysisSummary (serializable, export/API-ready)
 *     → UI component props (EvidenceGroups, DecisionFactors, etc.)
 */

// ─── Signal Domains & Categories ────────────────────────────────────────────

/** Top-level signal domain. Used for conflict resolution grouping. */
export type SignalDomain = "auth" | "identity" | "links" | "content" | "bulk";

/** Finer-grained signal category for filtering and display. */
export type SignalCategory =
  | "authentication"
  | "identity_consistency"
  | "link_reputation"
  | "link_structure"
  | "bulk_context"
  | "content_analysis"
  | "content_risk"
  | "reputation_coverage";

// ─── Source Tracing ─────────────────────────────────────────────────────────

/** Identifies the raw data source a signal was derived from. */
export type SignalSourceType =
  | "auth_result"       // parsed from authentication_results header string
  | "header_finding"    // from header_findings[] array
  | "det_finding"       // from deterministic_findings[] array
  | "link_analysis"     // derived from link scan results
  | "identity_derived"  // derived from sender domain comparison
  | "llm_evidence"      // from assessment.evidence[] (LLM output)
  | "bulk_detection"    // derived from structured_headers / header_findings
  | "content_analysis"  // derived from subject/body pattern matching
  | "reputation_scan";  // derived from link scan completion status

// ─── Priority Tiers ────────────────────────────────────────────────────────

/**
 * Signal priority tiers (higher = more severe).
 *
 * 1 = informational context (bulk markers)
 * 2 = baseline positive (auth pass, clean links)
 * 3 = noteworthy (missing auth, suspicious links)
 * 4 = critical-soft (identity mismatches that CAN be downgraded in bulk context)
 * 5 = critical-hard (auth failures, malicious links, spoofing — NEVER downgraded)
 */
export const PRIORITY_TIER = {
  CONTEXT: 1,
  POSITIVE: 2,
  NOTEWORTHY: 3,
  CRITICAL_SOFT: 4,
  CRITICAL_HARD: 5,
} as const;

export type PriorityTier = (typeof PRIORITY_TIER)[keyof typeof PRIORITY_TIER];

// ─── NormalizedSignal — the canonical internal type ─────────────────────────

/** Evidence severity bucket — determines which UI group a signal appears in. */
export type EvidenceSeverity = "positive" | "noteworthy" | "critical" | "context";

/**
 * The canonical internal signal representation.
 *
 * Every piece of analysis evidence is normalized into this shape.
 * All downstream views (UI components, export, API) are projections of it.
 */
export type NormalizedSignal = {
  /** Stable key. Format: "domain:type[:qualifier]". Example: "auth:spf:pass" */
  key: string;

  /**
   * Dedup group key. Strips volatile qualifiers (status, count).
   * "auth:spf:pass" → "auth:spf", "links:malicious:3" → "links:malicious"
   */
  canonicalKey: string;

  /** Human-readable label for UI display */
  label: string;

  /** Severity bucket for evidence grouping */
  severity: EvidenceSeverity;

  /** Priority tier for conflict resolution (1–5) */
  tier: PriorityTier;

  /** Direction: positive = legitimizing, negative = risk indicator */
  direction: "positive" | "negative";

  /** Top-level signal domain */
  domain: SignalDomain;

  /** Finer-grained signal category */
  category: SignalCategory;

  /** What kind of raw source this signal was derived from */
  sourceType: SignalSourceType;

  /**
   * Reference to the specific raw source item.
   * Format depends on sourceType:
   * - auth_result: "auth:spf" (protocol reference)
   * - header_finding: "HDR-001" (finding ID) or "idx:0" (fallback index)
   * - det_finding: "spf_fail" (factor name)
   * - link_analysis: "urls:evil.com,bad.com" or "count:3" or "total:5"
   * - identity_derived: "domains:x.com,y.com" (involved domains)
   * - llm_evidence: "evidence:0" (array index)
   * - bulk_detection: "header:list-unsubscribe" or "classification:advertising"
   */
  sourceRef: string | null;

  /** Original finding/evidence text (for display). Null for derived signals. */
  evidenceText: string | null;

  /** Eligible for promotion to DecisionFactors block */
  promotable: boolean;

  /** Can be downgraded from critical to noteworthy in bulk context */
  downgradeEligible: boolean;
};

// ─── Derived view types (for UI components) ─────────────────────────────────

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

// ─── AnalysisResult — the complete internal analysis ────────────────────────

/** Complete analysis result. Produced by analyzeResult(), consumed by UI. */
export type AnalysisResult = {
  identity: IdentityAssessment;
  linkStats: LinkStats;
  normalized: NormalizedSignal[];
  signals: PrioritizedSignal[];
  conflict: ConflictAssessment;
  decisionFactors: {
    negative: PrioritizedSignal[];
    positive: PrioritizedSignal[];
    promotedKeys: Set<string>;
  };
  evidenceGroups: EvidenceGroups;
  scoreDrivers: ScoreDriver[];
  /** Decision explanation derived from normalized signals and conflict */
  explanation: string | null;
  /** Content risk level: "none" | "low" | "high" */
  contentRiskLevel: "none" | "low" | "high";
  /** Whether a decision override was applied (phishing content overrides "allow") */
  overrideApplied: boolean;
  /** Serializable summary — ready for export/API */
  summary: AnalysisSummary;
};

// ─── AnalysisSummary — the serializable export format ───────────────────────

/**
 * Serializable analysis summary.
 *
 * This is the official export/API format. All fields are JSON-safe
 * (no Sets, no functions, no circular references).
 *
 * Consumers: JSON export, future backend API, audit trail.
 */
export type AnalysisSummary = {
  /** Schema version for forward compatibility */
  version: 1;

  /** Backend classification (if available) */
  classification: string | null;

  /** LLM analyst summary (if available) */
  analystSummary: string | null;

  /** Generated decision explanation derived from conflict/signal analysis */
  explanation: string | null;

  /** All normalized signals with full metadata */
  signals: Array<{
    /** Stable signal key */
    key: string;
    /** Dedup group key */
    canonicalKey: string;
    /** Human-readable label */
    label: string;
    /** Severity bucket */
    severity: EvidenceSeverity;
    /** Priority tier (1–5) */
    tier: PriorityTier;
    /** Positive = legitimizing, negative = risk */
    direction: "positive" | "negative";
    /** Signal domain */
    domain: SignalDomain;
    /** Signal category */
    category: SignalCategory;
    /** Raw source type */
    sourceType: SignalSourceType;
    /** Reference to specific raw source item */
    sourceRef: string | null;
    /** Eligible for decision factors */
    promotable: boolean;
    /** Can be bulk-downgraded */
    downgradeEligible: boolean;
  }>;

  /** Top decision factors (signal keys) */
  decisionFactors: {
    /** Keys of top negative signals */
    negative: string[];
    /** Keys of top positive signals */
    positive: string[];
  };

  /** Signal keys promoted to the decision factors block */
  promotedKeys: string[];

  /** Conflict assessment summary */
  conflict: {
    hasConflict: boolean;
    dominantSignalKey: string | null;
    explanation: string | null;
    bulkDowngradeApplied: boolean;
  };

  /** Content risk level derived from subject/body/evidence patterns */
  contentRiskLevel: "none" | "low" | "high";

  /** Whether a decision override was applied due to content risk */
  overrideApplied: boolean;
};
