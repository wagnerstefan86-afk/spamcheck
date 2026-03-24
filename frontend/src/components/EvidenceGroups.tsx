"use client";

import { useState } from "react";
import type { EvidenceGroups as EvidenceGroupsType, EvidenceItem, EvidenceSeverity } from "../lib/classifyEvidence";

type Props = {
  groups: EvidenceGroupsType;
  /** Labels already shown in DecisionFactors — shown dimmed or filtered */
  promotedLabels?: Set<string>;
};

function isPromoted(text: string, promotedLabels: Set<string>): boolean {
  const lower = text.toLowerCase();
  let found = false;
  promotedLabels.forEach((label) => {
    if (lower.includes(label.toLowerCase())) found = true;
  });
  return found;
}

function GroupSection({
  title,
  items,
  variant,
  promotedLabels,
}: {
  title: string;
  items: EvidenceItem[];
  variant: EvidenceSeverity;
  promotedLabels: Set<string>;
}) {
  // Split into primary (not promoted) and secondary (promoted → already shown above)
  const primary = items.filter((item) => !isPromoted(item.text, promotedLabels));
  const secondary = items.filter((item) => isPromoted(item.text, promotedLabels));

  if (primary.length === 0 && secondary.length === 0) return null;

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
        {title} ({items.length})
      </p>
      <ul className="space-y-1">
        {primary.map((item, i) => (
          <li key={i} className="flex items-start gap-2 text-[13px] text-text-primary/80 leading-snug">
            <span className={`w-1.5 h-1.5 rounded-full ${s.dot} mt-1.5 shrink-0`} />
            {item.text}
          </li>
        ))}
        {/* Secondary items shown dimmed — already in DecisionFactors */}
        {secondary.map((item, i) => (
          <li key={`s-${i}`} className="flex items-start gap-2 text-[13px] text-text-tertiary leading-snug">
            <span className={`w-1.5 h-1.5 rounded-full bg-gray-300 mt-1.5 shrink-0`} />
            {item.text}
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function EvidenceGroups({ groups, promotedLabels }: Props) {
  const [expanded, setExpanded] = useState(false);
  const promoted = promotedLabels || new Set<string>();

  const total = groups.critical.length + groups.noteworthy.length + groups.positive.length + groups.context.length;
  if (total === 0) return null;

  // Critical items always visible, rest collapsed
  const hasCritical = groups.critical.length > 0;
  const restCount = groups.noteworthy.length + groups.positive.length + groups.context.length;

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <p className="text-xs text-text-secondary uppercase tracking-wider font-semibold">Analyse-Ergebnisse</p>
        <span className="text-[11px] text-text-tertiary">{total} Befunde</span>
      </div>

      {/* Critical always visible */}
      {hasCritical && (
        <GroupSection title="Kritische Risiken" items={groups.critical} variant="critical" promotedLabels={promoted} />
      )}

      {/* Rest collapsed by default */}
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
            {expanded
              ? "Details ausblenden"
              : `${restCount} weitere Befunde anzeigen`}
          </button>

          {expanded && (
            <div className="space-y-2">
              <GroupSection title="Auffälligkeiten" items={groups.noteworthy} variant="noteworthy" promotedLabels={promoted} />
              <GroupSection title="Positive Signale" items={groups.positive} variant="positive" promotedLabels={promoted} />
              <GroupSection title="Kontext" items={groups.context} variant="context" promotedLabels={promoted} />
            </div>
          )}
        </>
      )}

      {/* If no critical and no rest, just show minimal */}
      {!hasCritical && restCount === 0 && null}
    </div>
  );
}
