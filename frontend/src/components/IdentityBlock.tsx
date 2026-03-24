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
    <div className={`flex items-center justify-between px-3 py-1.5 rounded-lg ${s.bg}`}>
      <span className="text-xs font-semibold text-text-primary">{signal.protocol}</span>
      <span className={`text-xs font-medium ${s.text}`}>{s.label}</span>
    </div>
  );
}

/**
 * Generates a precise consistency description that names specific domains
 * and explains why the mismatch is or isn't concerning.
 */
function buildConsistencyDetail(identity: IdentityAssessment): { label: string; detail: string; severity: "ok" | "info" | "warn" } {
  const { fromDomain, replyToDomain, returnPathDomain, consistency, isBulkSender, authSignals } = identity;

  if (consistency === "consistent") {
    return {
      label: "Konsistent",
      detail: fromDomain
        ? `Alle Absender-Domains stimmen überein (${fromDomain}).`
        : "Alle Absender-Domains stimmen überein.",
      severity: "ok",
    };
  }

  if (consistency === "suspicious") {
    // Identify which domains differ
    const diffs: string[] = [];
    if (replyToDomain && fromDomain && replyToDomain !== fromDomain) {
      diffs.push(`Reply-To: ${replyToDomain}`);
    }
    if (returnPathDomain && fromDomain && returnPathDomain !== fromDomain) {
      diffs.push(`Return-Path: ${returnPathDomain}`);
    }
    const failedProtos = authSignals.filter((s) => s.status === "fail").map((s) => s.protocol);
    const detail = diffs.length > 0
      ? `From-Domain ${fromDomain || "?"} weicht ab (${diffs.join(", ")}). ${failedProtos.length > 0 ? `${failedProtos.join("/")} fehlgeschlagen — ` : ""}erhöhtes Risiko.`
      : "Abweichende Domains bei fehlgeschlagener Authentifizierung.";
    return { label: "Auffällig", detail, severity: "warn" };
  }

  // partial_mismatch
  const diffs: string[] = [];
  if (replyToDomain && fromDomain && replyToDomain !== fromDomain) {
    diffs.push(`Reply-To: ${replyToDomain}`);
  }
  if (returnPathDomain && fromDomain && returnPathDomain !== fromDomain) {
    diffs.push(`Return-Path: ${returnPathDomain}`);
  }

  if (isBulkSender && diffs.length > 0) {
    return {
      label: "Typisch für Mailing-Dienst",
      detail: `From: ${fromDomain || "?"}, ${diffs.join(", ")}. Abweichung typisch für Newsletter-Versand über externe Dienste.`,
      severity: "info",
    };
  }

  if (diffs.length > 0) {
    return {
      label: "Teilweise abweichend",
      detail: `From: ${fromDomain || "?"}, ${diffs.join(", ")}. Manuelle Prüfung empfohlen.`,
      severity: "info",
    };
  }

  return {
    label: "Teilweise abweichend",
    detail: "Keine Absender-Domain extrahierbar.",
    severity: "info",
  };
}

function ConsistencyIndicator({ label, detail, severity }: { label: string; detail: string; severity: "ok" | "info" | "warn" }) {
  const styles = {
    ok: { bg: "bg-emerald-50", border: "border-emerald-200", text: "text-emerald-700", icon: "text-emerald-500" },
    info: { bg: "bg-amber-50", border: "border-amber-200", text: "text-amber-700", icon: "text-amber-500" },
    warn: { bg: "bg-red-50", border: "border-red-200", text: "text-red-700", icon: "text-red-500" },
  };
  const s = styles[severity];

  return (
    <div className={`flex items-start gap-2.5 px-3 py-2 rounded-lg border ${s.bg} ${s.border}`}>
      <svg className={`w-3.5 h-3.5 ${s.icon} shrink-0 mt-0.5`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        {severity === "ok" && <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />}
        {severity === "info" && <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />}
        {severity === "warn" && <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M12 3l9.5 16.5H2.5L12 3z" />}
      </svg>
      <div>
        <p className={`text-[11px] font-semibold ${s.text}`}>{label}</p>
        <p className="text-xs text-text-secondary mt-0.5 leading-relaxed">{detail}</p>
      </div>
    </div>
  );
}

export default function IdentityBlock({ identity }: Props) {
  const { fromDomain, replyToDomain, returnPathDomain, authSignals, isBulkSender } = identity;
  const consistencyInfo = buildConsistencyDetail(identity);

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs text-text-secondary uppercase tracking-wider font-semibold">Identität & Authentifizierung</p>
        {isBulkSender && (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-blue-50 text-blue-600 border border-blue-200">
            Mailing-Dienst
          </span>
        )}
      </div>

      {/* Compact: Auth badges + Domain overview side-by-side on larger screens */}
      <div className="flex flex-col sm:flex-row gap-3 mb-3">
        {/* Auth signals */}
        {authSignals.length > 0 && (
          <div className="flex gap-2 flex-1">
            {authSignals.map((signal) => (
              <div key={signal.protocol} className="flex-1">
                <AuthBadge signal={signal} />
              </div>
            ))}
          </div>
        )}

        {/* Domain overview */}
        <div className="sm:border-l sm:border-gray-200 sm:pl-3 space-y-0.5 text-xs">
          {[
            { label: "From", value: fromDomain },
            { label: "Reply-To", value: replyToDomain },
            { label: "Ret-Path", value: returnPathDomain },
          ].map((d) => (
            <div key={d.label} className="flex items-center">
              <span className="text-text-tertiary w-16 shrink-0 font-medium">{d.label}</span>
              <span className={`font-mono ${d.value ? "text-text-primary" : "text-text-tertiary"}`}>
                {d.value || "\u2014"}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Consistency verdict — precise */}
      <ConsistencyIndicator label={consistencyInfo.label} detail={consistencyInfo.detail} severity={consistencyInfo.severity} />
    </div>
  );
}
