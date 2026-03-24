"use client";

import { useState } from "react";
import Accordion from "./Accordion";

type Props = {
  result: any;
  onDownload: () => void;
};

const classColors: Record<string, string> = {
  phishing: "badge-red",
  suspicious: "badge-amber",
  advertising: "badge-blue",
  legitimate: "badge-green",
  unknown: "badge-gray",
};

const classLabels: Record<string, string> = {
  phishing: "Phishing",
  suspicious: "Verdächtig",
  advertising: "Werbung",
  legitimate: "Legitim",
  unknown: "Unbekannt",
};

const classIcons: Record<string, string> = {
  phishing: "M12 9v2m0 4h.01M12 3l9.5 16.5H2.5L12 3z",
  suspicious: "M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
  advertising: "M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z",
  legitimate: "M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z",
  unknown: "M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01",
};

const actionLabels: Record<string, string> = {
  delete: "E-Mail löschen",
  open_ticket: "Sicherheitsticket eröffnen",
  verify_via_known_channel: "Absender über bekannten Kanal verifizieren",
  allow: "Zulassen",
  manual_review: "Manuelle Prüfung erforderlich",
};

function scoreColor(score: number): string {
  if (score <= 25) return "bg-emerald-500";
  if (score <= 55) return "bg-amber-500";
  return "bg-red-500";
}

function scoreTextColor(score: number): string {
  if (score <= 25) return "text-emerald-600";
  if (score <= 55) return "text-amber-600";
  return "text-red-600";
}

function severityBadge(sev: string): string {
  if (sev === "critical") return "badge-red";
  if (sev === "warning") return "badge-amber";
  return "badge-blue";
}

export default function ResultView({ result, onDownload }: Props) {
  const a = result.assessment;
  const [maskEmails, setMaskEmails] = useState(false);

  const mask = (val: string | null | undefined) => {
    if (!val) return "\u2014";
    if (!maskEmails) return val;
    return val.replace(/([a-zA-Z0-9._%+-]+)@/g, "***@");
  };

  return (
    <div className="space-y-5">
      {/* Service badges */}
      <div className="flex flex-wrap gap-2">
        {[
          { label: "VirusTotal", active: result.enable_virustotal },
          { label: "urlscan", active: result.enable_urlscan },
          { label: "LLM", active: result.enable_llm },
        ].map((svc) => (
          <span
            key={svc.label}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium transition-all
              ${svc.active ? "bg-emerald-50 text-emerald-700 border border-emerald-200" : "bg-gray-50 text-gray-400 border border-gray-200"}`}
          >
            <span className={`w-1.5 h-1.5 rounded-full ${svc.active ? "bg-emerald-500" : "bg-gray-300"}`} />
            {svc.label}
          </span>
        ))}
        {a?.is_deterministic_fallback && (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium badge-amber">
            Deterministische Bewertung
          </span>
        )}
      </div>

      {/* Top verdict card */}
      {a && (
        <div className="card relative overflow-hidden">
          {/* Subtle gradient accent line */}
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-red-500 via-red-400 to-red-600" />

          <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-6 mb-6 pt-2">
            <div>
              <p className="text-xs text-text-secondary uppercase tracking-wider font-medium mb-2">Klassifikation</p>
              <div className="flex items-center gap-2.5">
                <div className={`w-10 h-10 rounded-xl flex items-center justify-center
                  ${a.classification === "phishing" ? "bg-red-100" : ""}
                  ${a.classification === "suspicious" ? "bg-amber-100" : ""}
                  ${a.classification === "advertising" ? "bg-blue-100" : ""}
                  ${a.classification === "legitimate" ? "bg-emerald-100" : ""}
                  ${a.classification === "unknown" ? "bg-gray-100" : ""}
                `}>
                  <svg className={`w-5 h-5
                    ${a.classification === "phishing" ? "text-red-600" : ""}
                    ${a.classification === "suspicious" ? "text-amber-600" : ""}
                    ${a.classification === "advertising" ? "text-blue-600" : ""}
                    ${a.classification === "legitimate" ? "text-emerald-600" : ""}
                    ${a.classification === "unknown" ? "text-gray-500" : ""}
                  `} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d={classIcons[a.classification] || classIcons.unknown} />
                  </svg>
                </div>
                <span className={`inline-block px-3.5 py-1.5 rounded-xl text-base font-bold ${classColors[a.classification] || "badge-gray"}`}>
                  {classLabels[a.classification] || a.classification}
                </span>
              </div>
            </div>
            <div className="text-left sm:text-right">
              <p className="text-xs text-text-secondary uppercase tracking-wider font-medium mb-2">Risiko-Score</p>
              <div className="flex items-baseline gap-1">
                <span className={`text-4xl font-bold tabular-nums tracking-tight ${scoreTextColor(a.risk_score)}`}>
                  {a.risk_score}
                </span>
                <span className="text-text-tertiary text-lg font-medium">/100</span>
              </div>
            </div>
          </div>

          {/* Score bar */}
          <div className="w-full h-2.5 bg-gray-100 rounded-full mb-6">
            <div className={`score-bar ${scoreColor(a.risk_score)}`} style={{ width: `${a.risk_score}%` }} />
          </div>

          {/* Action & Confidence */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="bg-gray-50 rounded-xl px-4 py-3">
              <p className="text-xs text-text-secondary mb-0.5 font-medium">Handlungsempfehlung</p>
              <p className="text-sm font-semibold text-text-primary">{actionLabels[a.recommended_action] || a.recommended_action}</p>
            </div>
            <div className="bg-gray-50 rounded-xl px-4 py-3">
              <p className="text-xs text-text-secondary mb-0.5 font-medium">Konfidenz</p>
              <p className="text-sm font-semibold text-text-primary">{a.confidence}%</p>
            </div>
          </div>

          {/* Rationale */}
          {a.rationale && (
            <div className="mt-5 pt-5 border-t border-gray-100">
              <p className="text-xs text-text-secondary font-medium mb-1.5">Begründung</p>
              <p className="text-sm text-text-primary/80 leading-relaxed">{a.rationale}</p>
            </div>
          )}

          {a.analyst_summary && (
            <div className="mt-4">
              <p className="text-xs text-text-secondary font-medium mb-1.5">Zusammenfassung</p>
              <p className="text-sm text-text-primary/80 leading-relaxed">{a.analyst_summary}</p>
            </div>
          )}

          {a.evidence?.length > 0 && (
            <div className="mt-4">
              <p className="text-xs text-text-secondary font-medium mb-2">Evidenz</p>
              <ul className="text-sm text-text-primary/70 space-y-1.5">
                {a.evidence.map((e: string, i: number) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-accent mt-2 shrink-0" />
                    {e}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Warnings */}
      {result.warnings?.length > 0 && (
        <div className="card border border-amber-200 bg-amber-50/30">
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 rounded-full bg-amber-100 flex items-center justify-center shrink-0">
              <svg className="w-4 h-4 text-amber-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M12 3l9.5 16.5H2.5L12 3z" />
              </svg>
            </div>
            <div>
              <p className="text-sm font-semibold text-amber-800 mb-1">Warnungen ({result.warnings.length})</p>
              {result.warnings.map((w: string, i: number) => (
                <p key={i} className="text-sm text-amber-700/70 leading-relaxed">{w}</p>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Sender info */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <p className="text-xs text-text-secondary uppercase tracking-wider font-semibold">Absender-Information</p>
          <button
            onClick={() => setMaskEmails(!maskEmails)}
            className="inline-flex items-center gap-1.5 text-xs text-text-secondary hover:text-accent transition-colors font-medium px-2.5 py-1 rounded-lg hover:bg-red-50"
          >
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              {maskEmails
                ? <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                : <path strokeLinecap="round" strokeLinejoin="round" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M3 3l18 18" />
              }
            </svg>
            {maskEmails ? "Anzeigen" : "Maskieren"}
          </button>
        </div>
        <div className="space-y-2.5">
          {[
            { label: "Betreff", value: result.subject || "\u2014" },
            { label: "Von", value: mask(result.sender?.from_address) },
            { label: "Reply-To", value: mask(result.sender?.reply_to) },
            { label: "Return-Path", value: mask(result.sender?.return_path) },
            { label: "An", value: mask(result.sender?.to) },
            { label: "Datum", value: result.sender?.date || "\u2014" },
          ].map((field) => (
            <div key={field.label} className="flex items-start text-sm">
              <span className="text-text-secondary w-28 shrink-0 font-medium">{field.label}</span>
              <span className="text-text-primary break-all">{field.value}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Deterministic scores */}
      {result.deterministic_scores && (
        <div className="card">
          <p className="text-xs text-text-secondary uppercase tracking-wider font-semibold mb-4">Deterministische Scores</p>
          <div className="space-y-4">
            {[
              { label: "Phishing", score: result.deterministic_scores.phishing_likelihood_score, color: "bg-red-500", bgLight: "bg-red-50" },
              { label: "Werbung", score: result.deterministic_scores.advertising_likelihood_score, color: "bg-blue-500", bgLight: "bg-blue-50" },
              { label: "Legitimität", score: result.deterministic_scores.legitimacy_likelihood_score, color: "bg-emerald-500", bgLight: "bg-emerald-50" },
            ].map((item) => (
              <div key={item.label}>
                <div className="flex justify-between text-sm mb-1.5">
                  <span className="text-text-secondary font-medium">{item.label}</span>
                  <span className="text-text-primary font-semibold tabular-nums">{item.score}/100</span>
                </div>
                <div className="w-full h-2 bg-gray-100 rounded-full">
                  <div className={`score-bar ${item.color}`} style={{ width: `${item.score}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Header findings */}
      {result.header_findings?.length > 0 && (
        <div className="card">
          <p className="text-xs text-text-secondary uppercase tracking-wider font-semibold mb-4">Header-Befunde</p>
          <div className="space-y-3">
            {result.header_findings.map((f: any, i: number) => (
              <div key={i} className="flex items-start gap-3 text-sm">
                <span className={`px-2 py-0.5 rounded-lg text-xs font-semibold shrink-0 mt-0.5 ${severityBadge(f.severity)}`}>
                  {f.severity}
                </span>
                <div>
                  <p className="text-text-primary font-medium">{f.title}</p>
                  <p className="text-text-secondary text-xs mt-0.5 leading-relaxed">{f.detail}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Links */}
      {result.links?.length > 0 && (
        <div className="card">
          <p className="text-xs text-text-secondary uppercase tracking-wider font-semibold mb-4">
            Gefundene Links ({result.links.length})
          </p>
          <div className="space-y-2.5">
            {result.links.map((link: any) => {
              const flags: string[] = [];
              if (link.is_ip_literal) flags.push("IP-Literal");
              if (link.is_punycode) flags.push("Punycode");
              if (link.is_shortener) flags.push("Shortener");
              if (link.has_display_mismatch) flags.push("Display-Mismatch");
              if (link.is_suspicious_tld) flags.push("Verd. TLD");
              if (link.is_tracking_heavy) flags.push("Tracking");
              if (link.is_safelink) flags.push("SafeLink");
              const isSuspicious = flags.length > 0 && !flags.every((f) => f === "Tracking" || f === "SafeLink");

              return (
                <div key={link.id} className={`px-4 py-3 rounded-xl border-l-[3px] transition-all
                  ${isSuspicious ? "border-red-500 bg-red-50/50" : "border-emerald-400 bg-gray-50"}`}>
                  <p className="text-xs text-text-primary break-all font-mono leading-relaxed">{link.normalized_url}</p>
                  {link.original_url !== link.normalized_url && (
                    <p className="text-[11px] text-text-tertiary break-all mt-1">Original: {link.original_url}</p>
                  )}
                  {flags.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 mt-2">
                      {flags.map((f) => (
                        <span key={f} className="px-2 py-0.5 rounded-md text-[11px] font-medium badge-amber">{f}</span>
                      ))}
                    </div>
                  )}
                  {link.external_checks?.map((c: any, ci: number) => (
                    <div key={ci} className="mt-1.5 text-xs text-text-secondary">
                      <span className="font-semibold">{c.service}:</span>{" "}
                      {c.status === "completed"
                        ? <span>{c.malicious_count} malicious, {c.suspicious_count} suspicious</span>
                        : <span className="text-text-tertiary">{c.status}</span>}
                    </div>
                  ))}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Accordion sections */}
      <Accordion title="Technische Details">
        <div className="text-xs text-text-secondary space-y-2.5">
          <p><strong className="text-text-primary">Authentication-Results:</strong> {result.authentication_results || "\u2014"}</p>
          <p><strong className="text-text-primary">Received-Kette ({result.received_chain?.length || 0}):</strong></p>
          {result.received_chain?.map((r: string, i: number) => (
            <p key={i} className="pl-3 border-l-2 border-gray-200 text-text-tertiary">{r}</p>
          ))}
          {result.attachment_metadata?.length > 0 && (
            <>
              <p><strong className="text-text-primary">Anhänge:</strong></p>
              {result.attachment_metadata.map((att: any, i: number) => (
                <p key={i} className="pl-3">{att.filename} ({att.content_type}, {att.size} bytes)</p>
              ))}
            </>
          )}
        </div>
      </Accordion>

      <Accordion title="Raw Headers">
        <pre className="text-xs text-text-tertiary whitespace-pre-wrap break-all max-h-96 overflow-y-auto leading-relaxed">
          {result.raw_headers || "Keine Raw Headers verfügbar."}
        </pre>
      </Accordion>

      {/* Download */}
      <div className="flex justify-center pt-2 pb-4">
        <button
          onClick={onDownload}
          className="inline-flex items-center gap-2 px-6 py-2.5 bg-white border border-gray-200 rounded-xl text-sm font-medium text-text-primary hover:bg-gray-50 hover:border-gray-300 active:scale-[0.98] transition-all shadow-sm"
        >
          <svg className="w-4 h-4 text-text-secondary" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
          </svg>
          Analyse als JSON exportieren
        </button>
      </div>
    </div>
  );
}
