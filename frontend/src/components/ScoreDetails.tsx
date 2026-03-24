"use client";

import { useState } from "react";

type Props = {
  scores: {
    phishing_likelihood_score: number;
    advertising_likelihood_score: number;
    legitimacy_likelihood_score: number;
  };
};

export default function ScoreDetails({ scores }: Props) {
  const [expanded, setExpanded] = useState(false);

  const items = [
    { label: "Phishing", score: scores.phishing_likelihood_score, color: "bg-red-500", bgTrack: "bg-red-100" },
    { label: "Werbung", score: scores.advertising_likelihood_score, color: "bg-blue-500", bgTrack: "bg-blue-100" },
    { label: "Legitimität", score: scores.legitimacy_likelihood_score, color: "bg-emerald-500", bgTrack: "bg-emerald-100" },
  ];

  // Determine the dominant category
  const dominant = [...items].sort((a, b) => b.score - a.score)[0];

  return (
    <div className="card">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between"
      >
        <div className="flex items-center gap-3">
          <p className="text-xs text-text-secondary uppercase tracking-wider font-semibold">Score-Details</p>
          <span className="text-xs text-text-tertiary">
            Dominant: <span className="font-medium text-text-primary">{dominant.label}</span> ({dominant.score}/100)
          </span>
        </div>
        <svg
          className={`w-4 h-4 text-text-tertiary transition-transform duration-200 ${expanded ? "rotate-180" : ""}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Compact inline bars always visible */}
      <div className="flex gap-2 mt-3">
        {items.map((item) => (
          <div key={item.label} className="flex-1">
            <div className="flex justify-between text-[11px] mb-1">
              <span className="text-text-tertiary">{item.label}</span>
              <span className="text-text-secondary font-medium tabular-nums">{item.score}</span>
            </div>
            <div className={`w-full h-1.5 ${item.bgTrack} rounded-full`}>
              <div className={`score-bar ${item.color}`} style={{ width: `${item.score}%` }} />
            </div>
          </div>
        ))}
      </div>

      {/* Expanded detail view */}
      {expanded && (
        <div className="mt-4 pt-4 border-t border-gray-100 space-y-3">
          {items.map((item) => (
            <div key={item.label}>
              <div className="flex justify-between text-sm mb-1.5">
                <span className="text-text-secondary font-medium">{item.label}</span>
                <span className="text-text-primary font-semibold tabular-nums">{item.score}/100</span>
              </div>
              <div className={`w-full h-2.5 ${item.bgTrack} rounded-full`}>
                <div className={`score-bar ${item.color}`} style={{ width: `${item.score}%` }} />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
