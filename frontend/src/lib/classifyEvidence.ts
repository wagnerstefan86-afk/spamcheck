/**
 * Backward-compatibility re-export.
 * All logic lives in lib/analysis/*.ts modules.
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
} from "./analysis";

export {
  assessIdentity,
  summarizeLinks,
  extractScoreDrivers,
  assessConflict,
  classifyEvidence,
  generateDecisionExplanation,
  extractDecisionFactors,
  normalizeSignals,
  toPrioritizedSignals,
  toEvidenceGroups,
  buildAnalysisSummary,
} from "./analysis";

export type { DecisionFactors } from "./analysis";
