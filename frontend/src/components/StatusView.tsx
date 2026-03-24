"use client";

const STAGES = [
  { key: "queued", label: "In Warteschlange" },
  { key: "parsing", label: "E-Mail wird geparst" },
  { key: "extracting_links", label: "Links werden extrahiert" },
  { key: "checking_reputation", label: "Reputationsprüfung (VT/urlscan)" },
  { key: "llm_assessment", label: "KI-Bewertung" },
];

type Props = {
  status: {
    id: string;
    filename: string;
    status: string;
    warnings: string[];
  };
};

export default function StatusView({ status }: Props) {
  const currentIdx = STAGES.findIndex((s) => s.key === status.status);

  return (
    <div className="card max-w-xl mx-auto">
      <h2 className="text-lg font-semibold mb-1">Analyse läuft</h2>
      <p className="text-sm text-slate-500 mb-6">{status.filename}</p>

      <div className="space-y-4">
        {STAGES.map((stage, i) => {
          const isDone = i < currentIdx;
          const isActive = i === currentIdx;
          return (
            <div key={stage.key} className="flex items-center gap-3">
              <div
                className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold shrink-0
                  ${isDone ? "bg-emerald-500/20 text-emerald-400" : ""}
                  ${isActive ? "bg-accent/20 text-accent pulse-dot" : ""}
                  ${!isDone && !isActive ? "bg-slate-800 text-slate-600" : ""}
                `}
              >
                {isDone ? "\u2713" : i + 1}
              </div>
              <span
                className={`text-sm ${isActive ? "text-white font-medium" : isDone ? "text-slate-400" : "text-slate-600"}`}
              >
                {stage.label}
              </span>
            </div>
          );
        })}
      </div>

      {status.warnings.length > 0 && (
        <div className="mt-4 pt-4 border-t border-border">
          <p className="text-xs text-amber-400 font-medium mb-1">Warnungen:</p>
          {status.warnings.map((w, i) => (
            <p key={i} className="text-xs text-amber-300/70">{w}</p>
          ))}
        </div>
      )}
    </div>
  );
}
