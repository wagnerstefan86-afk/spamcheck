/**
 * Analysis module — public API.
 *
 * Primary pipeline: normalizeSignals() → toPrioritizedSignals() / toEvidenceGroups()
 * Legacy: collectSignals() and classifyEvidence() are deprecated.
 */

// Core types
export type {
  NormalizedSignal,
  EvidenceSeverity,
  EvidenceItem,
  EvidenceGroups,
  AuthSignal,
  IdentityAssessment,
  CriticalLink,
  LinkStats,
  ScoreDriver,
  PrioritizedSignal,
  ConflictAssessment,
  SignalDomain,
  SignalCategory,
  SignalSourceType,
  AnalysisSummary,
} from "./types";

// Identity & Auth
export { assessIdentity, detectBulkMail } from "./identity";

// Central normalization (primary API)
export { normalizeSignals, toPrioritizedSignals, toEvidenceGroups, deriveCanonicalKey } from "./normalize";

// Conflict assessment
export { assessConflict } from "./priority";

// Evidence classification (legacy — use toEvidenceGroups instead)
export { classifyEvidence } from "./evidence";

// Link analysis
export { summarizeLinks } from "./links";

// Decision factors, explanation, summary
export type { DecisionFactors } from "./decision";
export { extractScoreDrivers, generateDecisionExplanation, extractDecisionFactors, buildAnalysisSummary } from "./decision";
