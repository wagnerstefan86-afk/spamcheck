"use client";

const STAGES = [
  { key: "queued", label: "In Warteschlange", icon: "clock" },
  { key: "parsing", label: "E-Mail wird geparst", icon: "doc" },
  { key: "extracting_links", label: "Links werden extrahiert", icon: "link" },
  { key: "checking_reputation", label: "Reputationsprüfung (VT/urlscan)", icon: "shield" },
  { key: "llm_assessment", label: "KI-Bewertung", icon: "sparkle" },
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
      <div className="text-center mb-8">
        <div className="w-12 h-12 rounded-full bg-red-50 flex items-center justify-center mx-auto mb-3">
          <svg className="w-6 h-6 text-accent animate-spin" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
        </div>
        <h2 className="text-xl font-semibold text-text-primary">Analyse läuft</h2>
        <p className="text-sm text-text-secondary mt-1">{status.filename}</p>
      </div>

      <div className="space-y-1">
        {STAGES.map((stage, i) => {
          const isDone = i < currentIdx;
          const isActive = i === currentIdx;
          return (
            <div
              key={stage.key}
              className={`flex items-center gap-3.5 px-4 py-3 rounded-xl transition-all duration-300
                ${isActive ? "bg-red-50" : ""}
                ${isDone ? "bg-emerald-50/50" : ""}
              `}
            >
              <div
                className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold shrink-0 transition-all duration-300
                  ${isDone ? "bg-emerald-500 text-white shadow-sm" : ""}
                  ${isActive ? "bg-accent text-white shadow-sm pulse-dot" : ""}
                  ${!isDone && !isActive ? "bg-gray-100 text-text-tertiary" : ""}
                `}
              >
                {isDone ? (
                  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                ) : (
                  i + 1
                )}
              </div>
              <span
                className={`text-sm transition-all duration-300
                  ${isActive ? "text-accent font-semibold" : ""}
                  ${isDone ? "text-emerald-700 font-medium" : ""}
                  ${!isDone && !isActive ? "text-text-tertiary" : ""}
                `}
              >
                {stage.label}
              </span>
            </div>
          );
        })}
      </div>

      {status.warnings.length > 0 && (
        <div className="mt-6 pt-4 border-t border-gray-100">
          <p className="text-xs font-semibold text-amber-600 mb-2">Warnungen</p>
          {status.warnings.map((w, i) => (
            <p key={i} className="text-xs text-amber-700/70 leading-relaxed">{w}</p>
          ))}
        </div>
      )}
    </div>
  );
}
