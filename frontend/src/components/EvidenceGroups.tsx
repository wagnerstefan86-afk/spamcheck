"use client";

import type { EvidenceGroups as EvidenceGroupsType, EvidenceItem, EvidenceSeverity } from "../lib/classifyEvidence";

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
  variant: EvidenceSeverity;
}) {
  if (items.length === 0) return null;

  const styles = {
    positive: {
      dot: "bg-emerald-500",
      bg: "bg-emerald-50/50",
      border: "border-emerald-200",
      title: "text-emerald-700",
    },
    noteworthy: {
      dot: "bg-amber-500",
      bg: "bg-amber-50/50",
      border: "border-amber-200",
      title: "text-amber-700",
    },
    critical: {
      dot: "bg-red-500",
      bg: "bg-red-50/50",
      border: "border-red-200",
      title: "text-red-700",
    },
    context: {
      dot: "bg-gray-400",
      bg: "bg-gray-50",
      border: "border-gray-200",
      title: "text-gray-500",
    },
  };

  const s = styles[variant];

  return (
    <div className={`rounded-xl border ${s.border} ${s.bg} px-4 py-3`}>
      <p className={`text-xs font-semibold ${s.title} uppercase tracking-wider mb-2`}>
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
  const total = groups.critical.length + groups.noteworthy.length + groups.positive.length + groups.context.length;
  if (total === 0) return null;

  return (
    <div className="space-y-3">
      <p className="text-xs text-text-secondary uppercase tracking-wider font-semibold">Analyse-Ergebnisse</p>
      {/* Priority order: Critical → Noteworthy → Positive → Context */}
      <GroupSection title="Kritische Risiken" items={groups.critical} variant="critical" />
      <GroupSection title="Auffälligkeiten" items={groups.noteworthy} variant="noteworthy" />
      <GroupSection title="Positive Signale" items={groups.positive} variant="positive" />
      <GroupSection title="Kontext" items={groups.context} variant="context" />
    </div>
  );
}
