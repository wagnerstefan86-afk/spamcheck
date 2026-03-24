/**
 * Evidence classification — legacy adapter.
 *
 * @deprecated Use normalizeSignals() + toEvidenceGroups() directly.
 * Kept only for backward compatibility with tests that still import classifyEvidence.
 */

import type { EvidenceGroups, PrioritizedSignal, AuthSignal } from "./types";
import { normalizeSignals, toEvidenceGroups } from "./normalize";
import { assessIdentity } from "./identity";
import { summarizeLinks } from "./links";

export function classifyEvidence(
  result: any,
  isBulk: boolean,
  _signals: PrioritizedSignal[],
  _authSignals: AuthSignal[]
): EvidenceGroups {
  const identity = assessIdentity(result);
  const linkStats = summarizeLinks(result.links || []);
  const normalized = normalizeSignals(result, identity, linkStats, isBulk);
  return toEvidenceGroups(normalized);
}
