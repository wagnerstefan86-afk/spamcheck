"use client";

import type { DecisionFactors as DecisionFactorsType } from "../lib/analysis";
import type { ConflictAssessment } from "../lib/analysis";

type Props = {
  factors: DecisionFactorsType;
  conflict: ConflictAssessment;
};

export default function DecisionFactors({ factors, conflict }: Props) {
  const hasNeg = factors.negative.length > 0;
  const hasPos = factors.positive.length > 0;
  if (!hasNeg && !hasPos) return null;

  return (
    <div className="card">
      <p className="text-xs text-text-secondary uppercase tracking-wider font-semibold mb-3">Entscheidungsfaktoren</p>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {/* Negative / belastend */}
        {hasNeg && (
          <div className="rounded-lg bg-red-50/50 border border-red-200/70 px-3.5 py-2.5">
            <p className="text-[11px] font-semibold text-red-600 uppercase tracking-wider mb-2">Belastend</p>
            <ul className="space-y-1.5">
              {factors.negative.map((s) => (
                <li key={s.key} className="flex items-start gap-2 text-[13px] text-text-primary/80 leading-snug">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-500 mt-1.5 shrink-0" />
                  {s.label}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Positive / entlastend */}
        {hasPos && (
          <div className="rounded-lg bg-emerald-50/50 border border-emerald-200/70 px-3.5 py-2.5">
            <p className="text-[11px] font-semibold text-emerald-600 uppercase tracking-wider mb-2">Entlastend</p>
            <ul className="space-y-1.5">
              {factors.positive.map((s) => (
                <li key={s.key} className="flex items-start gap-2 text-[13px] text-text-primary/80 leading-snug">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 mt-1.5 shrink-0" />
                  {s.label}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Integrated conflict/dominance hint — replaces the old separate ConflictExplanation */}
      {conflict.hasConflict && conflict.explanation && (
        <div className={`mt-3 flex items-start gap-2 px-3.5 py-2.5 rounded-lg border ${
          conflict.dominantSignal?.tier === 5 && conflict.dominantSignal?.direction === "negative"
            ? "bg-red-50/30 border-red-200/50"
            : conflict.bulkDowngradeApplied
            ? "bg-blue-50/30 border-blue-200/50"
            : "bg-amber-50/30 border-amber-200/50"
        }`}>
          <svg className={`w-3.5 h-3.5 shrink-0 mt-0.5 ${
            conflict.dominantSignal?.tier === 5 && conflict.dominantSignal?.direction === "negative"
              ? "text-red-400" : conflict.bulkDowngradeApplied ? "text-blue-400" : "text-amber-400"
          }`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
          <p className="text-xs text-text-primary/70 leading-relaxed">
            {conflict.explanation}
            {conflict.bulkDowngradeBlocked && conflict.bulkDowngradeBlockReason && (
              <span className="text-text-tertiary italic"> ({conflict.bulkDowngradeBlockReason})</span>
            )}
          </p>
        </div>
      )}
    </div>
  );
}
