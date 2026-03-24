"use client";

import { useState } from "react";
import type { LinkStats } from "../lib/classifyEvidence";

type Props = {
  links: any[];
  stats: LinkStats;
};

export default function LinkSummary({ links, stats }: Props) {
  const [expanded, setExpanded] = useState(false);

  if (links.length === 0) return null;

  const hasCritical = stats.criticalLinks.length > 0;

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

      {/* Critical links shown directly */}
      {hasCritical && (
        <div className="mt-3 space-y-2">
          {stats.criticalLinks.map((link: any) => {
            const flags: string[] = [];
            if (link.is_ip_literal) flags.push("IP-Literal");
            if (link.is_punycode) flags.push("Punycode");
            if (link.is_shortener) flags.push("Shortener");
            if (link.has_display_mismatch) flags.push("Display-Mismatch");
            if (link.is_suspicious_tld) flags.push("Verd. TLD");

            return (
              <div key={link.id} className="px-3 py-2.5 rounded-xl border-l-[3px] border-red-500 bg-red-50/50">
                <p className="text-xs text-text-primary break-all font-mono leading-relaxed">{link.normalized_url}</p>
                {flags.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mt-1.5">
                    {flags.map((f) => (
                      <span key={f} className="px-2 py-0.5 rounded-md text-[11px] font-medium badge-amber">{f}</span>
                    ))}
                  </div>
                )}
                {link.external_checks?.map((c: any, ci: number) => (
                  <div key={ci} className="mt-1 text-xs text-text-secondary">
                    <span className="font-semibold">{c.service}:</span>{" "}
                    {c.status === "completed"
                      ? `${c.malicious_count} malicious, ${c.suspicious_count} suspicious`
                      : c.status}
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      )}

      {/* Expandable full list */}
      {links.length > stats.criticalLinks.length && (
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
            {expanded ? "Alle Links ausblenden" : `Alle ${links.length} Links anzeigen`}
          </button>

          {expanded && (
            <div className="mt-2.5 space-y-1.5 max-h-80 overflow-y-auto">
              {links.map((link: any) => {
                const isCritical = stats.criticalLinks.some((cl: any) => cl.id === link.id);
                if (isCritical) return null; // already shown above

                const flags: string[] = [];
                if (link.is_tracking_heavy) flags.push("Tracking");
                if (link.is_safelink) flags.push("SafeLink");
                if (link.is_shortener) flags.push("Shortener");

                return (
                  <div key={link.id} className="px-3 py-2 rounded-lg bg-gray-50 border-l-2 border-emerald-400/50">
                    <p className="text-xs text-text-primary/70 break-all font-mono">{link.normalized_url}</p>
                    {flags.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {flags.map((f) => (
                          <span key={f} className="px-1.5 py-0.5 rounded text-[10px] font-medium badge-gray">{f}</span>
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
