/**
 * Re-export from analysis module.
 * Components import types from here for convenience.
 */
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
  AnalysisSummary,
  AnalysisResult,
} from "./analysis";

export {
  analyzeResult,
  assessIdentity,
  summarizeLinks,
  extractScoreDrivers,
  assessConflict,
  generateDecisionExplanation,
  extractDecisionFactors,
  normalizeSignals,
  toPrioritizedSignals,
  toEvidenceGroups,
  buildAnalysisSummary,
} from "./analysis";

export type { DecisionFactors } from "./analysis";
