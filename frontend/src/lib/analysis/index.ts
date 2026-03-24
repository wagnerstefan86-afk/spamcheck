/**
 * Analysis module — public API.
 *
 * Primary entry point: analyzeResult(rawResult) → AnalysisResult
 * All UI components and export consume AnalysisResult projections.
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
  ReputationCoverage,
  ScoreDriver,
  PrioritizedSignal,
  ConflictAssessment,
  SignalDomain,
  SignalCategory,
  SignalSourceType,
  AnalysisSummary,
  AnalysisResult,
} from "./types";

// Central pipeline (primary API)
export type { DecisionFactors } from "./decision";
export { analyzeResult, buildAnalysisSummary, generateDecisionExplanation, extractDecisionFactors, extractScoreDrivers } from "./decision";

// Normalization (for direct use in tests)
export { normalizeSignals, toPrioritizedSignals, toEvidenceGroups, deriveCanonicalKey } from "./normalize";

// Identity & Auth (for direct use)
export { assessIdentity, detectBulkMail } from "./identity";

// Conflict assessment
export { assessConflict } from "./priority";

// Link analysis
export { summarizeLinks } from "./links";

// Content risk detection
export { detectContentRisks, assessContentRiskLevel } from "./content";
export type { ContentRiskMatch, ContentRiskType } from "./content";
