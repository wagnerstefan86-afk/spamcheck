/**
 * Analysis module — public API.
 *
 * Re-exports all types and functions needed by UI components.
 * Internal helpers (pattern tables, normalizers) stay encapsulated.
 */

// Types
export type {
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
} from "./types";

// Identity & Auth
export { assessIdentity, detectBulkMail } from "./identity";

// Priority & Conflict
export { collectSignals, assessConflict } from "./priority";

// Evidence classification
export { classifyEvidence } from "./evidence";

// Link analysis
export { summarizeLinks } from "./links";

// Score drivers & Decision explanation & Decision factors
export type { DecisionFactors } from "./decision";
export { extractScoreDrivers, generateDecisionExplanation, extractDecisionFactors } from "./decision";
