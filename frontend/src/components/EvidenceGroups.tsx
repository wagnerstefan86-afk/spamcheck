"use client";

import { useState } from "react";
import type { EvidenceGroups as EvidenceGroupsType, EvidenceItem, EvidenceSeverity } from "../lib/analysis";

type Props = {
  groups: EvidenceGroupsType;
  /** Signal keys already promoted to DecisionFactors — for exact dedup */
  promotedKeys?: Set<string>;
};

/**
 * Dedup rule: An evidence item is "promoted" if its key matches a promoted
 * signal key exactly. No fuzzy text matching.
 *
 * Visibility rules for promoted items:
 * - In "critical": stay visible but dimmed (preserve audit trail)
 * - In other groups: hidden entirely (reduce noise)
 */
function splitByPromotion(
  items: EvidenceItem[],
  promotedKeys: Set<string>,
  isCriticalGroup: boolean
): { visible: EvidenceItem[]; promoted: EvidenceItem[] } {
  const visible: EvidenceItem[] = [];
  const promoted: EvidenceItem[] = [];

  for (const item of items) {
    if (promotedKeys.has(item.key)) {
      if (isCriticalGroup) {
        promoted.push(item); // show dimmed in critical
      }
      // else: hidden entirely in non-critical groups
    } else {
      visible.push(item);
    }
  }

  return { visible, promoted };
}

function GroupSection({
  title, items, variant, promotedKeys,
}: {
  title: string;
  items: EvidenceItem[];
  variant: EvidenceSeverity;
  promotedKeys: Set<string>;
}) {
  const isCritical = variant === "critical";
  const { visible, promoted } = splitByPromotion(items, promotedKeys, isCritical);

  if (visible.length === 0 && promoted.length === 0) return null;

  const styles = {
    positive: { dot: "bg-emerald-500", bg: "bg-emerald-50/50", border: "border-emerald-200", title: "text-emerald-700" },
    noteworthy: { dot: "bg-amber-500", bg: "bg-amber-50/50", border: "border-amber-200", title: "text-amber-700" },
    critical: { dot: "bg-red-500", bg: "bg-red-50/50", border: "border-red-200", title: "text-red-700" },
    context: { dot: "bg-gray-400", bg: "bg-gray-50", border: "border-gray-200", title: "text-gray-500" },
  };
  const s = styles[variant];

  return (
    <div className={`rounded-xl border ${s.border} ${s.bg} px-4 py-2.5`}>
      <p className={`text-[11px] font-semibold ${s.title} uppercase tracking-wider mb-1.5`}>
        {title} ({visible.length + promoted.length})
      </p>
      <ul className="space-y-1">
        {visible.map((item) => (
          <li key={item.key} className="flex items-start gap-2 text-[13px] text-text-primary/80 leading-snug">
            <span className={`w-1.5 h-1.5 rounded-full ${s.dot} mt-1.5 shrink-0`} />
            {item.text}
          </li>
        ))}
        {promoted.map((item) => (
          <li key={`p-${item.key}`} className="flex items-start gap-2 text-[13px] text-text-tertiary leading-snug">
            <span className="w-1.5 h-1.5 rounded-full bg-gray-300 mt-1.5 shrink-0" />
            {item.text}
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function EvidenceGroups({ groups, promotedKeys }: Props) {
  const [expanded, setExpanded] = useState(false);
  const keys = promotedKeys || new Set<string>();

  const total = groups.critical.length + groups.noteworthy.length + groups.positive.length + groups.context.length;
  if (total === 0) return null;

  // Only show "Kritische Risiken" if there are REAL critical items (not just false positives)
  // Filter out items that are positive statements misclassified as critical
  const realCritical = groups.critical.filter(
    (i) => !(/keine.*(bösartig|malizi|suspicious|verdächtig)/i.test(i.text) || /no.*(malicious|suspicious|threat)/i.test(i.text))
  );
  const hasCritical = realCritical.length > 0;
  const restCount = groups.noteworthy.length + groups.positive.length + groups.context.length
    + (groups.critical.length - realCritical.length); // misclassified items go to rest

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <p className="text-xs text-text-secondary uppercase tracking-wider font-semibold">Analyse-Ergebnisse</p>
        <span className="text-[11px] text-text-tertiary">{total} Befunde</span>
      </div>

      {hasCritical && (
        <GroupSection title="Kritische Risiken" items={realCritical} variant="critical" promotedKeys={keys} />
      )}

      {restCount > 0 && (
        <>
          <button
            onClick={() => setExpanded(!expanded)}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-text-secondary hover:text-accent transition-colors"
          >
            <svg
              className={`w-3.5 h-3.5 transition-transform duration-200 ${expanded ? "rotate-180" : ""}`}
              fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
            {expanded ? "Details ausblenden" : `${restCount} weitere Befunde anzeigen`}
          </button>

          {expanded && (
            <div className="space-y-2">
              <GroupSection title="Auffälligkeiten" items={groups.noteworthy} variant="noteworthy" promotedKeys={keys} />
              <GroupSection title="Positive Signale" items={groups.positive} variant="positive" promotedKeys={keys} />
              <GroupSection title="Kontext" items={groups.context} variant="context" promotedKeys={keys} />
            </div>
          )}
        </>
      )}
    </div>
  );
}
