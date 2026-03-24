"use client";

import type { ConflictAssessment } from "../lib/analysis";

type Props = {
  conflict: ConflictAssessment;
};

export default function ConflictExplanation({ conflict }: Props) {
  if (!conflict.hasConflict || !conflict.explanation) return null;

  // Determine visual style based on dominant signal
  const isDominantHard = conflict.dominantSignal?.tier === 5;
  const isDominantNegative = conflict.dominantSignal?.direction === "negative";

  const borderColor = isDominantHard && isDominantNegative
    ? "border-red-300"
    : conflict.bulkDowngradeApplied
    ? "border-blue-300"
    : "border-amber-300";

  const bgColor = isDominantHard && isDominantNegative
    ? "bg-red-50/40"
    : conflict.bulkDowngradeApplied
    ? "bg-blue-50/40"
    : "bg-amber-50/40";

  const iconColor = isDominantHard && isDominantNegative
    ? "text-red-500"
    : conflict.bulkDowngradeApplied
    ? "text-blue-500"
    : "text-amber-500";

  const labelColor = isDominantHard && isDominantNegative
    ? "text-red-700"
    : conflict.bulkDowngradeApplied
    ? "text-blue-700"
    : "text-amber-700";

  return (
    <div className={`rounded-xl border ${borderColor} ${bgColor} px-4 py-3`}>
      <div className="flex items-start gap-2.5">
        <svg className={`w-4 h-4 ${iconColor} shrink-0 mt-0.5`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
        <div>
          <p className={`text-xs font-semibold ${labelColor} uppercase tracking-wider mb-1`}>
            Signalgewichtung
          </p>
          <p className="text-sm text-text-primary/80 leading-relaxed">
            {conflict.explanation}
          </p>
          {/* Dominant signal badge */}
          {conflict.dominantSignal && isDominantHard && isDominantNegative && (
            <div className="flex items-center gap-1.5 mt-2">
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-red-100 text-red-700">
                <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 15l7-7 7 7" />
                </svg>
                Dominiert: {conflict.dominantSignal.label}
              </span>
            </div>
          )}
          {/* Bulk downgrade blocked notice */}
          {conflict.bulkDowngradeBlocked && conflict.bulkDowngradeBlockReason && (
            <p className="text-xs text-text-tertiary mt-1.5 italic">
              {conflict.bulkDowngradeBlockReason}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
