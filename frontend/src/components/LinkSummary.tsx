"use client";

import { useState } from "react";
import type { LinkStats, CriticalLink, ReputationCoverage } from "../lib/analysis";

type Props = {
  links: any[];
  stats: LinkStats;
};

/** Reputation coverage badge labels */
const COVERAGE_LABELS: Record<ReputationCoverage, string> = {
  clean: "Keine negativen Reputationstreffer erkannt",
  partially_analyzed: "Keine negativen Treffer in verfügbaren Ergebnissen — Bewertung unvollständig",
  unknown: "Reputationsbewertung nicht belastbar",
  not_checked: "Keine belastbare Reputationsbewertung verfügbar",
  none: "",
};

const COVERAGE_STYLE: Record<ReputationCoverage, { bg: string; text: string; border: string }> = {
  clean: { bg: "bg-emerald-50/50", text: "text-emerald-700", border: "border-emerald-200/70" },
  partially_analyzed: { bg: "bg-amber-50/50", text: "text-amber-700", border: "border-amber-200/70" },
  unknown: { bg: "bg-orange-50/50", text: "text-orange-700", border: "border-orange-200/70" },
  not_checked: { bg: "bg-gray-50", text: "text-gray-600", border: "border-gray-200" },
  none: { bg: "", text: "", border: "" },
};

export default function LinkSummary({ links, stats }: Props) {
  const [expanded, setExpanded] = useState(false);

  if (links.length === 0) return null;

  const hasCritical = stats.criticalLinks.length > 0;
  const nonCriticalCount = links.length - stats.criticalLinks.length;
  const cov = stats.reputationCoverage;
  const covStyle = COVERAGE_STYLE[cov];
  const attemptedScans = stats.providerScansTotal - stats.providerScansSkipped;

  return (
    <div className="card">
      <p className="text-xs text-text-secondary uppercase tracking-wider font-semibold mb-3">Link-Analyse</p>

      {/* Link-level summary */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
        <span className="font-medium text-text-primary">{stats.total} Links erkannt</span>
        {stats.malicious > 0 && (
          <>
            <span className="text-text-tertiary">&middot;</span>
            <span className="text-red-600 font-semibold">{stats.malicious} maliziös</span>
          </>
        )}
        {stats.suspicious > 0 && (
          <>
            <span className="text-text-tertiary">&middot;</span>
            <span className="text-amber-600 font-semibold">{stats.suspicious} verdächtig</span>
          </>
        )}
      </div>

      {/* Link-level & provider-level breakdown */}
      {cov !== "none" && (
        <div className={`mt-3 px-3 py-2.5 rounded-lg border ${covStyle.bg} ${covStyle.border}`}>
          <p className={`text-xs font-medium ${covStyle.text}`}>
            {COVERAGE_LABELS[cov]}
          </p>

          {/* Link-level detail */}
          <div className="mt-1.5 space-y-0.5">
            <p className="text-[11px] text-text-secondary">
              <span className="font-medium">Links:</span>{" "}
              {stats.linksFullyAnalyzed > 0 && (
                <>{stats.linksFullyAnalyzed} vollständig geprüft</>
              )}
              {stats.linksFullyAnalyzed > 0 && stats.linksPartiallyAnalyzed > 0 && " · "}
              {stats.linksPartiallyAnalyzed > 0 && (
                <>{stats.linksPartiallyAnalyzed} teilweise geprüft</>
              )}
              {(stats.linksFullyAnalyzed > 0 || stats.linksPartiallyAnalyzed > 0) && stats.linksWithoutResult > 0 && " · "}
              {stats.linksWithoutResult > 0 && (
                <span className="text-text-tertiary">{stats.linksWithoutResult} ohne belastbares Ergebnis</span>
              )}
              {stats.linksFullyAnalyzed === 0 && stats.linksPartiallyAnalyzed === 0 && stats.linksWithoutResult === 0 && (
                <span className="text-text-tertiary">keine Ergebnisse</span>
              )}
            </p>

            {/* Provider-level detail */}
            {attemptedScans > 0 && (
              <p className="text-[11px] text-text-tertiary">
                <span className="font-medium text-text-secondary">Provider-Scans:</span>{" "}
                {stats.providerScansSuccessful} von {attemptedScans} erfolgreich
                {stats.providerScansFailed > 0 && (
                  <> · {stats.providerScansFailed} fehlgeschlagen</>
                )}
                {stats.coveragePercent !== null && (
                  <> · Coverage {stats.coveragePercent}%</>
                )}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Critical links with explicit reasons */}
      {hasCritical && (
        <div className="mt-4 space-y-2.5">
          <p className="text-[11px] text-red-600 uppercase tracking-wider font-semibold">
            Auffällige Links ({stats.criticalLinks.length})
          </p>
          {stats.criticalLinks.map((cl: CriticalLink, idx: number) => (
            <div key={cl.link.id || idx} className="px-3.5 py-3 rounded-xl border border-red-200 bg-red-50/50">
              <p className="text-xs text-text-primary break-all font-mono leading-relaxed">{cl.link.normalized_url}</p>
              {cl.link.display_text && cl.link.display_text !== cl.link.normalized_url && (
                <p className="text-[11px] text-text-tertiary mt-1">
                  Angezeigt als: <span className="text-text-secondary">{cl.link.display_text}</span>
                </p>
              )}
              <div className="mt-2 space-y-1">
                {cl.reasons.map((reason, ri) => (
                  <div key={ri} className="flex items-start gap-1.5 text-xs">
                    <svg className="w-3 h-3 text-red-500 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01" />
                    </svg>
                    <span className="text-red-700/80">{reason}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Expandable full list for non-critical links */}
      {nonCriticalCount > 0 && (
        <div className="mt-3">
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
            {expanded ? "Weitere Links ausblenden" : `${nonCriticalCount} weitere Links anzeigen`}
          </button>

          {expanded && (
            <div className="mt-2.5 space-y-1.5 max-h-80 overflow-y-auto">
              {links.map((link: any) => {
                const isCritical = stats.criticalLinks.some((cl) => cl.link.id === link.id);
                if (isCritical) return null;

                const tags: string[] = [];
                if (link.is_tracking_heavy) tags.push("Tracking");
                if (link.is_safelink) tags.push("SafeLink");
                if (link.is_shortener) tags.push("Shortener");

                const verdict = link.verdict;
                if (verdict === "unknown" || verdict === "not_checked") tags.push("Nicht geprüft");
                else if (verdict === "partially_analyzed") tags.push("Teilweise geprüft");

                return (
                  <div key={link.id} className={`px-3 py-2 rounded-lg border-l-2 ${
                    verdict === "clean" ? "bg-gray-50 border-emerald-400/50"
                    : verdict === "unknown" || verdict === "not_checked" ? "bg-gray-50 border-gray-300/50"
                    : "bg-gray-50 border-amber-300/50"
                  }`}>
                    <p className="text-xs text-text-primary/70 break-all font-mono">{link.normalized_url}</p>
                    {tags.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {tags.map((t) => (
                          <span key={t} className="px-1.5 py-0.5 rounded text-[10px] font-medium badge-gray">{t}</span>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
