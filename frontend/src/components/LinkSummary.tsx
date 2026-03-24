"use client";

import { useState } from "react";
import type { LinkStats, CriticalLink } from "../lib/classifyEvidence";

type Props = {
  links: any[];
  stats: LinkStats;
};

export default function LinkSummary({ links, stats }: Props) {
  const [expanded, setExpanded] = useState(false);

  if (links.length === 0) return null;

  const hasCritical = stats.criticalLinks.length > 0;
  const nonCriticalCount = links.length - stats.criticalLinks.length;

  return (
    <div className="card">
      <p className="text-xs text-text-secondary uppercase tracking-wider font-semibold mb-3">Link-Analyse</p>

      {/* Compact summary bar */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
        <span className="font-medium text-text-primary">{stats.total} Links geprüft</span>
        <span className="text-text-tertiary">&middot;</span>
        <span className={stats.malicious > 0 ? "text-red-600 font-semibold" : "text-text-secondary"}>
          {stats.malicious} maliziös
        </span>
        <span className="text-text-tertiary">&middot;</span>
        <span className={stats.suspicious > 0 ? "text-amber-600 font-semibold" : "text-text-secondary"}>
          {stats.suspicious} verdächtig
        </span>
        {stats.scansFailed > 0 && (
          <>
            <span className="text-text-tertiary">&middot;</span>
            <span className="text-text-tertiary">{stats.scansFailed} Scans fehlgeschlagen</span>
          </>
        )}
      </div>

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
              {/* Explicit reasons WHY this link is critical */}
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
            {expanded ? "Unauffällige Links ausblenden" : `${nonCriticalCount} unauffällige Links anzeigen`}
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

                return (
                  <div key={link.id} className="px-3 py-2 rounded-lg bg-gray-50 border-l-2 border-emerald-400/50">
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
