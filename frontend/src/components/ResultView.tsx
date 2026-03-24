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
        <span className={`px-2 py-0.5 rounded text-xs font-medium ${result.enable_virustotal ? "badge-green" : "badge-gray"}`}>
          VT {result.enable_virustotal ? "aktiv" : "deaktiviert"}
        </span>
        <span className={`px-2 py-0.5 rounded text-xs font-medium ${result.enable_urlscan ? "badge-green" : "badge-gray"}`}>
          urlscan {result.enable_urlscan ? "aktiv" : "deaktiviert"}
        </span>
        <span className={`px-2 py-0.5 rounded text-xs font-medium ${result.enable_llm ? "badge-green" : "badge-gray"}`}>
          LLM {result.enable_llm ? "aktiv" : "deaktiviert"}
        </span>
        {a?.is_deterministic_fallback && (
          <span className="px-2 py-0.5 rounded text-xs font-medium badge-amber">
            Deterministische Bewertung
          </span>
        )}
      </div>

      {/* Top verdict */}
      {a && (
        <div className="card">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
            <div>
              <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Klassifikation</p>
              <span className={`inline-block px-3 py-1 rounded-lg text-lg font-bold ${classColors[a.classification] || "badge-gray"}`}>
                {classLabels[a.classification] || a.classification}
              </span>
            </div>
            <div className="text-right">
              <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Risiko-Score</p>
              <span className="text-3xl font-bold tabular-nums">{a.risk_score}</span>
              <span className="text-slate-500">/100</span>
            </div>
          </div>

          <div className="w-full h-2 bg-slate-800 rounded-full mb-4">
            <div className={`score-bar ${scoreColor(a.risk_score)}`} style={{ width: `${a.risk_score}%` }} />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <p className="text-xs text-slate-500 mb-1">Handlungsempfehlung</p>
              <p className="text-sm font-medium text-slate-200">{actionLabels[a.recommended_action] || a.recommended_action}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500 mb-1">Konfidenz</p>
              <p className="text-sm font-medium text-slate-200">{a.confidence}%</p>
            </div>
          </div>

          {a.rationale && (
            <div className="mt-4 pt-4 border-t border-border">
              <p className="text-xs text-slate-500 mb-1">Begründung</p>
              <p className="text-sm text-slate-300">{a.rationale}</p>
            </div>
          )}

          {a.analyst_summary && (
            <div className="mt-3">
              <p className="text-xs text-slate-500 mb-1">Zusammenfassung</p>
              <p className="text-sm text-slate-300">{a.analyst_summary}</p>
            </div>
          )}

          {a.evidence?.length > 0 && (
            <div className="mt-3">
              <p className="text-xs text-slate-500 mb-1">Evidenz</p>
              <ul className="text-sm text-slate-400 space-y-1 list-disc list-inside">
                {a.evidence.map((e: string, i: number) => <li key={i}>{e}</li>)}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Warnings */}
      {result.warnings?.length > 0 && (
        <div className="card border-amber-500/30">
          <p className="text-sm font-medium text-amber-400 mb-2">Warnungen ({result.warnings.length})</p>
          {result.warnings.map((w: string, i: number) => (
            <p key={i} className="text-sm text-amber-300/70">{w}</p>
          ))}
        </div>
      )}

      {/* Sender info */}
      <div className="card">
        <div className="flex items-center justify-between mb-3">
          <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold">Absender-Information</p>
          <button
            onClick={() => setMaskEmails(!maskEmails)}
            className="text-xs text-slate-500 hover:text-slate-300 transition"
          >
            {maskEmails ? "E-Mails anzeigen" : "E-Mails maskieren"}
          </button>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
          <div><span className="text-slate-500">Betreff: </span><span className="text-slate-200">{result.subject || "\u2014"}</span></div>
          <div><span className="text-slate-500">Von: </span><span className="text-slate-200">{mask(result.sender?.from_address)}</span></div>
          <div><span className="text-slate-500">Reply-To: </span><span className="text-slate-200">{mask(result.sender?.reply_to)}</span></div>
          <div><span className="text-slate-500">Return-Path: </span><span className="text-slate-200">{mask(result.sender?.return_path)}</span></div>
          <div><span className="text-slate-500">An: </span><span className="text-slate-200">{mask(result.sender?.to)}</span></div>
          <div><span className="text-slate-500">Datum: </span><span className="text-slate-200">{result.sender?.date || "\u2014"}</span></div>
        </div>
      </div>

      {/* Deterministic scores */}
      {result.deterministic_scores && (
        <div className="card">
          <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-3">Deterministische Scores</p>
          <div className="space-y-3">
            {[
              { label: "Phishing", score: result.deterministic_scores.phishing_likelihood_score, color: "bg-red-500" },
              { label: "Werbung", score: result.deterministic_scores.advertising_likelihood_score, color: "bg-blue-500" },
              { label: "Legitimität", score: result.deterministic_scores.legitimacy_likelihood_score, color: "bg-emerald-500" },
            ].map((item) => (
              <div key={item.label}>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-slate-400">{item.label}</span>
                  <span className="text-slate-300 font-medium">{item.score}/100</span>
                </div>
                <div className="w-full h-1.5 bg-slate-800 rounded-full">
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
          <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-3">Header-Befunde</p>
          <div className="space-y-2">
            {result.header_findings.map((f: any, i: number) => (
              <div key={i} className="flex items-start gap-3 text-sm">
                <span className={`px-1.5 py-0.5 rounded text-xs font-medium shrink-0 mt-0.5 ${severityBadge(f.severity)}`}>
                  {f.severity}
                </span>
                <div>
                  <p className="text-slate-200 font-medium">{f.title}</p>
                  <p className="text-slate-400 text-xs">{f.detail}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Links */}
      {result.links?.length > 0 && (
        <div className="card">
          <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-3">
            Gefundene Links ({result.links.length})
          </p>
          <div className="space-y-3">
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
                <div key={link.id} className={`p-3 rounded-lg bg-bg-secondary border-l-2 ${isSuspicious ? "border-red-500" : "border-emerald-500/50"}`}>
                  <p className="text-xs text-slate-200 break-all font-mono">{link.normalized_url}</p>
                  {link.original_url !== link.normalized_url && (
                    <p className="text-xs text-slate-500 break-all mt-0.5">Original: {link.original_url}</p>
                  )}
                  {flags.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {flags.map((f) => (
                        <span key={f} className="px-1.5 py-0.5 rounded text-xs badge-amber">{f}</span>
                      ))}
                    </div>
                  )}
                  {link.external_checks?.map((c: any, ci: number) => (
                    <div key={ci} className="mt-1.5 text-xs text-slate-400">
                      <span className="font-medium">{c.service}:</span>{" "}
                      {c.status === "completed"
                        ? `${c.malicious_count} malicious, ${c.suspicious_count} suspicious`
                        : c.status}
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
        <div className="text-xs text-slate-400 space-y-2">
          <p><strong>Authentication-Results:</strong> {result.authentication_results || "\u2014"}</p>
          <p><strong>Received-Kette ({result.received_chain?.length || 0}):</strong></p>
          {result.received_chain?.map((r: string, i: number) => (
            <p key={i} className="pl-3 border-l border-border text-slate-500">{r}</p>
          ))}
          {result.attachment_metadata?.length > 0 && (
            <>
              <p><strong>Anhänge:</strong></p>
              {result.attachment_metadata.map((att: any, i: number) => (
                <p key={i} className="pl-3">{att.filename} ({att.content_type}, {att.size} bytes)</p>
              ))}
            </>
          )}
        </div>
      </Accordion>

      <Accordion title="Raw Headers">
        <pre className="text-xs text-slate-500 whitespace-pre-wrap break-all max-h-96 overflow-y-auto">
          {result.raw_headers || "Keine Raw Headers verfügbar."}
        </pre>
      </Accordion>

      {/* Download */}
      <div className="flex justify-center">
        <button
          onClick={onDownload}
          className="px-6 py-2 bg-bg-card border border-border rounded-lg text-sm text-slate-300 hover:bg-slate-800 transition"
        >
          Analyse als JSON exportieren
        </button>
      </div>
    </div>
  );
}
