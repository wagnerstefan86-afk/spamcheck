/**
 * Analysis module — public API.
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

// Central normalization
export { normalizeSignals, toPrioritizedSignals, toEvidenceGroups, deriveCanonicalKey } from "./normalize";

// Priority & Conflict (operates on PrioritizedSignal[])
export { collectSignals, assessConflict } from "./priority";

// Evidence classification (legacy adapter)
export { classifyEvidence } from "./evidence";

// Link analysis
export { summarizeLinks } from "./links";

// Decision factors, explanation, summary
export type { DecisionFactors } from "./decision";
export { extractScoreDrivers, generateDecisionExplanation, extractDecisionFactors, buildAnalysisSummary } from "./decision";
