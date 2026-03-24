/**
 * Backward-compatibility re-export.
 * All logic lives in lib/analysis/*.ts modules.
 */

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
} from "./analysis";

export {
  assessIdentity,
  summarizeLinks,
  extractScoreDrivers,
  collectSignals,
  assessConflict,
  classifyEvidence,
  generateDecisionExplanation,
  extractDecisionFactors,
} from "./analysis";

export type { DecisionFactors } from "./analysis";
