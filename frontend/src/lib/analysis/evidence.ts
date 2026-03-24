/**
 * Evidence classification — thin adapter.
 *
 * Delegates to normalize.ts for the actual signal production,
 * then projects into EvidenceGroups.
 *
 * This module exists for backward compatibility with the existing
 * component API (classifyEvidence). New code should prefer
 * normalizeSignals() + toEvidenceGroups() directly.
 */

import type { EvidenceGroups, PrioritizedSignal, AuthSignal } from "./types";
import { normalizeSignals, toEvidenceGroups } from "./normalize";
import type { IdentityAssessment, LinkStats } from "./types";
import { assessIdentity } from "./identity";
import { summarizeLinks } from "./links";

/**
 * Legacy API — classifies evidence into groups.
 *
 * Internally uses normalizeSignals + toEvidenceGroups.
 * Kept for ResultView compatibility.
 */
export function classifyEvidence(
  result: any,
  isBulk: boolean,
  _signals: PrioritizedSignal[], // kept for API compat, not used internally
  _authSignals: AuthSignal[]     // kept for API compat, not used internally
): EvidenceGroups {
  const identity = assessIdentity(result);
  const linkStats = summarizeLinks(result.links || []);
  const normalized = normalizeSignals(result, identity, linkStats, isBulk);
  return toEvidenceGroups(normalized);
}
