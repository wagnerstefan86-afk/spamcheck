"use client";

import type { EvidenceGroups as EvidenceGroupsType, EvidenceItem } from "../lib/classifyEvidence";

type Props = {
  groups: EvidenceGroupsType;
};

function GroupSection({
  title,
  items,
  variant,
}: {
  title: string;
  items: EvidenceItem[];
  variant: "positive" | "noteworthy" | "critical";
}) {
  if (items.length === 0) return null;

  const styles = {
    positive: {
      dot: "bg-emerald-500",
      bg: "bg-emerald-50/50",
      border: "border-emerald-200",
      title: "text-emerald-700",
      icon: (
        <svg className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
    },
    noteworthy: {
      dot: "bg-amber-500",
      bg: "bg-amber-50/50",
      border: "border-amber-200",
      title: "text-amber-700",
      icon: (
        <svg className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
    },
    critical: {
      dot: "bg-red-500",
      bg: "bg-red-50/50",
      border: "border-red-200",
      title: "text-red-700",
      icon: (
        <svg className="w-4 h-4 text-red-500 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M12 3l9.5 16.5H2.5L12 3z" />
        </svg>
      ),
    },
  };

  const s = styles[variant];

  return (
    <div className={`rounded-xl border ${s.border} ${s.bg} px-4 py-3`}>
      <p className={`text-xs font-semibold ${s.title} uppercase tracking-wider mb-2.5`}>
        {title} ({items.length})
      </p>
      <ul className="space-y-1.5">
        {items.map((item, i) => (
          <li key={i} className="flex items-start gap-2 text-sm text-text-primary/80 leading-relaxed">
            <span className={`w-1.5 h-1.5 rounded-full ${s.dot} mt-2 shrink-0`} />
            {item.text}
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function EvidenceGroups({ groups }: Props) {
  const hasAny = groups.positive.length + groups.noteworthy.length + groups.critical.length > 0;
  if (!hasAny) return null;

  return (
    <div className="space-y-3">
      <p className="text-xs text-text-secondary uppercase tracking-wider font-semibold">Analyse-Ergebnisse</p>
      {/* Critical first to draw attention */}
      <GroupSection title="Kritische Risiken" items={groups.critical} variant="critical" />
      <GroupSection title="Auffälligkeiten" items={groups.noteworthy} variant="noteworthy" />
      <GroupSection title="Positive Signale" items={groups.positive} variant="positive" />
    </div>
  );
}
