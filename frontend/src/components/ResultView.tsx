"use client";

import { useMemo } from "react";
import DecisionHeader from "./DecisionHeader";
import DecisionFactors from "./DecisionFactors";
import EvidenceGroups from "./EvidenceGroups";
import IdentityBlock from "./IdentityBlock";
import LinkSummary from "./LinkSummary";
import SenderInfo from "./SenderInfo";
import ScoreDetails from "./ScoreDetails";
import Accordion from "./Accordion";
import { analyzeResult } from "../lib/analysis";
import type { AnalysisSummary } from "../lib/analysis";

type Props = {
  result: any;
  onDownload: (summary: AnalysisSummary) => void;
};

export default function ResultView({ result, onDownload }: Props) {
  const a = result.assessment;

  // Single pipeline call — all views derived from one analysis
  const analysis = useMemo(() => analyzeResult(result), [result]);

  return (
    <div className="space-y-4">
      {/* Service status badges */}
      <div className="flex flex-wrap gap-2">
        {[
          { label: "VirusTotal", active: result.enable_virustotal },
          { label: "urlscan", active: result.enable_urlscan },
          { label: "LLM", active: result.enable_llm },
        ].map((svc) => (
          <span
            key={svc.label}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium
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

      {/* ── 1. DECISION ──────────────────────────────────────── */}
      <DecisionHeader assessment={a} actionDecision={analysis.actionDecision} />

      {/* ── 2. RATIONALE (compact, one block) ────────────────── */}
      {a && (a.analyst_summary || analysis.explanation || a.rationale) && (
        <div className="card py-3">
          <p className="text-xs text-text-secondary uppercase tracking-wider font-semibold mb-1.5">Kurzbegründung</p>
          {a.analyst_summary && (
            <p className="text-sm text-text-primary leading-relaxed">{a.analyst_summary}</p>
          )}
          {analysis.explanation && (
            <p className={`text-sm leading-relaxed ${a.analyst_summary ? "text-text-primary/60 mt-1" : "text-text-primary"}`}>
              {analysis.explanation}
            </p>
          )}
          {a.rationale && a.rationale !== a.analyst_summary && !analysis.explanation && !a.analyst_summary && (
            <p className="text-sm text-text-primary/70 leading-relaxed">{a.rationale}</p>
          )}
        </div>
      )}

      {/* ── 3. DECISION FACTORS (belastend / entlastend) ─────── */}
      <DecisionFactors factors={analysis.decisionFactors} conflict={analysis.conflict} />

      {/* ── 4. IDENTITY & AUTH ───────────────────────────────── */}
      <IdentityBlock identity={analysis.identity} />

      {/* ── 5. SUPPORTING EVIDENCE (collapsed, deduplicated) ── */}
      <EvidenceGroups groups={analysis.evidenceGroups} promotedKeys={analysis.decisionFactors.promotedKeys} />

      {/* Warnings */}
      {result.warnings?.length > 0 && (
        <div className="card border border-amber-200 bg-amber-50/30 py-3">
          <div className="flex items-start gap-3">
            <div className="w-6 h-6 rounded-full bg-amber-100 flex items-center justify-center shrink-0">
              <svg className="w-3 h-3 text-amber-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M12 3l9.5 16.5H2.5L12 3z" />
              </svg>
            </div>
            <div>
              <p className="text-sm font-semibold text-amber-800 mb-0.5">Warnungen ({result.warnings.length})</p>
              {result.warnings.map((w: string, i: number) => (
                <p key={i} className="text-sm text-amber-700/70 leading-relaxed">{w}</p>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── 6. SENDER DETAILS ────────────────────────────────── */}
      <SenderInfo result={result} />

      {/* ── 7. LINK SUMMARY ──────────────────────────────────── */}
      <LinkSummary links={result.links || []} stats={analysis.linkStats} />

      {/* ── 8. SCORES (secondary, collapsed) ─────────────────── */}
      {result.deterministic_scores && (
        <ScoreDetails scores={result.deterministic_scores} drivers={analysis.scoreDrivers} />
      )}

      {/* ── 9. TECHNICAL DETAILS (collapsed) ─────────────────── */}
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

      {/* Export */}
      <div className="flex justify-center pt-2 pb-4">
        <button
          onClick={() => onDownload(analysis.summary)}
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
