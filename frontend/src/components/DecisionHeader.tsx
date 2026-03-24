"use client";

const classLabels: Record<string, string> = {
  phishing: "Phishing-Verdacht",
  suspicious: "Verdächtig",
  advertising: "Werbung / Newsletter",
  legitimate: "Wahrscheinlich legitim",
  unknown: "Nicht eindeutig",
};

const actionLabels: Record<string, string> = {
  delete: "E-Mail löschen",
  open_ticket: "Sicherheitsticket eröffnen",
  verify_via_known_channel: "Absender über bekannten Kanal verifizieren",
  allow: "Zulassen",
  manual_review: "Manuelle Prüfung erforderlich",
};

function scoreColor(score: number) {
  if (score <= 25) return { bg: "bg-emerald-500", text: "text-emerald-600", ring: "ring-emerald-100", bgLight: "bg-emerald-50" };
  if (score <= 55) return { bg: "bg-amber-500", text: "text-amber-600", ring: "ring-amber-100", bgLight: "bg-amber-50" };
  return { bg: "bg-red-500", text: "text-red-600", ring: "ring-red-100", bgLight: "bg-red-50" };
}

function classStyle(classification: string) {
  switch (classification) {
    case "phishing": return { bg: "bg-red-50", border: "border-red-200", text: "text-red-700", icon: "text-red-500" };
    case "suspicious": return { bg: "bg-amber-50", border: "border-amber-200", text: "text-amber-700", icon: "text-amber-500" };
    case "advertising": return { bg: "bg-blue-50", border: "border-blue-200", text: "text-blue-700", icon: "text-blue-500" };
    case "legitimate": return { bg: "bg-emerald-50", border: "border-emerald-200", text: "text-emerald-700", icon: "text-emerald-500" };
    default: return { bg: "bg-gray-50", border: "border-gray-200", text: "text-gray-600", icon: "text-gray-400" };
  }
}

type Props = {
  assessment: any;
};

export default function DecisionHeader({ assessment }: Props) {
  if (!assessment) return null;

  const a = assessment;
  const sc = scoreColor(a.risk_score);
  const cs = classStyle(a.classification);

  return (
    <div className="card relative overflow-hidden">
      {/* Top accent gradient */}
      <div className={`absolute top-0 left-0 right-0 h-1 ${sc.bg}`} />

      {/* Main decision row */}
      <div className="flex flex-col sm:flex-row sm:items-center gap-5 pt-2">
        {/* Classification */}
        <div className="flex-1 min-w-0">
          <div className={`inline-flex items-center gap-2.5 px-4 py-2 rounded-xl border ${cs.bg} ${cs.border}`}>
            <svg className={`w-5 h-5 ${cs.icon} shrink-0`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              {a.classification === "phishing" && <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M12 3l9.5 16.5H2.5L12 3z" />}
              {a.classification === "suspicious" && <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />}
              {a.classification === "advertising" && <path strokeLinecap="round" strokeLinejoin="round" d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z" />}
              {a.classification === "legitimate" && <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />}
              {a.classification === "unknown" && <path strokeLinecap="round" strokeLinejoin="round" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01" />}
            </svg>
            <span className={`text-lg font-bold ${cs.text}`}>
              {classLabels[a.classification] || a.classification}
            </span>
          </div>
        </div>

        {/* Risk score - prominent circle */}
        <div className="flex items-center gap-5">
          <div className={`w-20 h-20 rounded-full ${sc.bgLight} ring-4 ${sc.ring} flex flex-col items-center justify-center`}>
            <span className={`text-2xl font-bold tabular-nums leading-none ${sc.text}`}>{a.risk_score}</span>
            <span className="text-[10px] text-text-tertiary font-medium mt-0.5">von 100</span>
          </div>
        </div>
      </div>

      {/* Score bar */}
      <div className="w-full h-1.5 bg-gray-100 rounded-full mt-5 mb-5">
        <div className={`score-bar ${sc.bg}`} style={{ width: `${a.risk_score}%` }} />
      </div>

      {/* Action + Confidence row */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="flex-1 bg-gray-50 rounded-xl px-4 py-3">
          <p className="text-[11px] text-text-tertiary uppercase tracking-wider font-medium mb-0.5">Empfehlung</p>
          <p className="text-sm font-semibold text-text-primary">
            {actionLabels[a.recommended_action] || a.recommended_action}
          </p>
        </div>
        <div className="sm:w-36 bg-gray-50 rounded-xl px-4 py-3">
          <p className="text-[11px] text-text-tertiary uppercase tracking-wider font-medium mb-0.5">Konfidenz</p>
          <p className="text-sm font-semibold text-text-primary">{a.confidence}%</p>
        </div>
      </div>
    </div>
  );
}
