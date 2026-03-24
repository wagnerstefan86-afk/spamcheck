"use client";

import type { IdentityAssessment, AuthSignal } from "../lib/classifyEvidence";

type Props = {
  identity: IdentityAssessment;
};

function AuthBadge({ signal }: { signal: AuthSignal }) {
  const styles: Record<string, { bg: string; text: string; label: string }> = {
    pass: { bg: "bg-emerald-50", text: "text-emerald-700", label: "bestanden" },
    fail: { bg: "bg-red-50", text: "text-red-700", label: "fehlgeschlagen" },
    softfail: { bg: "bg-amber-50", text: "text-amber-700", label: "softfail" },
    none: { bg: "bg-gray-100", text: "text-gray-500", label: "nicht vorhanden" },
    neutral: { bg: "bg-gray-100", text: "text-gray-500", label: "neutral" },
    unknown: { bg: "bg-gray-100", text: "text-gray-400", label: "unbekannt" },
  };
  const s = styles[signal.status] || styles.unknown;

  return (
    <div className={`flex items-center justify-between px-3 py-2 rounded-lg ${s.bg}`}>
      <span className="text-xs font-semibold text-text-primary">{signal.protocol}</span>
      <span className={`text-xs font-medium ${s.text}`}>{s.label}</span>
    </div>
  );
}

function ConsistencyIndicator({ consistency, detail }: { consistency: IdentityAssessment["consistency"]; detail: string }) {
  const styles = {
    consistent: { bg: "bg-emerald-50", border: "border-emerald-200", text: "text-emerald-700", icon: "text-emerald-500", label: "Konsistent" },
    partial_mismatch: { bg: "bg-amber-50", border: "border-amber-200", text: "text-amber-700", icon: "text-amber-500", label: "Teilweise abweichend" },
    suspicious: { bg: "bg-red-50", border: "border-red-200", text: "text-red-700", icon: "text-red-500", label: "Auffällig" },
  };
  const s = styles[consistency];

  return (
    <div className={`flex items-start gap-2.5 px-3 py-2.5 rounded-lg border ${s.bg} ${s.border}`}>
      <svg className={`w-4 h-4 ${s.icon} shrink-0 mt-0.5`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        {consistency === "consistent" && <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />}
        {consistency === "partial_mismatch" && <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />}
        {consistency === "suspicious" && <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M12 3l9.5 16.5H2.5L12 3z" />}
      </svg>
      <div>
        <p className={`text-xs font-semibold ${s.text}`}>{s.label}</p>
        <p className="text-xs text-text-secondary mt-0.5">{detail}</p>
      </div>
    </div>
  );
}

export default function IdentityBlock({ identity }: Props) {
  const { fromDomain, replyToDomain, returnPathDomain, authSignals, consistency, consistencyDetail, isBulkSender } = identity;

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <p className="text-xs text-text-secondary uppercase tracking-wider font-semibold">Identität & Authentifizierung</p>
        {isBulkSender && (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-blue-50 text-blue-600 border border-blue-200">
            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
            Mailing-Dienst
          </span>
        )}
      </div>

      {/* Domain overview */}
      <div className="space-y-1.5 mb-4">
        {[
          { label: "From", value: fromDomain },
          { label: "Reply-To", value: replyToDomain },
          { label: "Return-Path", value: returnPathDomain },
        ].map((d) => (
          <div key={d.label} className="flex items-center text-sm">
            <span className="text-text-tertiary w-24 shrink-0 text-xs font-medium">{d.label}</span>
            <span className={`font-mono text-xs ${d.value ? "text-text-primary" : "text-text-tertiary"}`}>
              {d.value || "\u2014"}
            </span>
          </div>
        ))}
      </div>

      {/* Auth signals */}
      {authSignals.length > 0 && (
        <div className="grid grid-cols-3 gap-2 mb-4">
          {authSignals.map((signal) => (
            <AuthBadge key={signal.protocol} signal={signal} />
          ))}
        </div>
      )}

      {/* Consistency verdict */}
      <ConsistencyIndicator consistency={consistency} detail={consistencyDetail} />
    </div>
  );
}
