/**
 * Backward-compatibility re-export.
 *
 * All logic has moved to lib/analysis/*.ts modules.
 * This file exists so existing imports continue to work.
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
  ConflictAssessment,
} from "./analysis";

export {
  assessIdentity,
  summarizeLinks,
  extractScoreDrivers,
  collectSignals,
  assessConflict,
} from "./analysis";

// classifyEvidence and generateDecisionExplanation have changed signatures
// (they now require additional parameters). Components should import from
// ./analysis directly. These re-exports are kept for type-compatibility.
export { classifyEvidence } from "./analysis";
export { generateDecisionExplanation } from "./analysis";
