"use client";

import { useState } from "react";
import type { ScoreDriver } from "../lib/classifyEvidence";

type Props = {
  scores: {
    phishing_likelihood_score: number;
    advertising_likelihood_score: number;
    legitimacy_likelihood_score: number;
  };
  drivers: ScoreDriver[];
};

export default function ScoreDetails({ scores, drivers }: Props) {
  const [expanded, setExpanded] = useState(false);

  const items = [
    { label: "Phishing", score: scores.phishing_likelihood_score, color: "bg-red-500", bgTrack: "bg-red-100", textColor: "text-red-600" },
    { label: "Werbung", score: scores.advertising_likelihood_score, color: "bg-blue-500", bgTrack: "bg-blue-100", textColor: "text-blue-600" },
    { label: "Legitimität", score: scores.legitimacy_likelihood_score, color: "bg-emerald-500", bgTrack: "bg-emerald-100", textColor: "text-emerald-600" },
  ];

  return (
    <div className="card">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between"
      >
        <p className="text-xs text-text-secondary uppercase tracking-wider font-semibold">Score-Details</p>
        <div className="flex items-center gap-3">
          {/* Ultra-compact inline score preview */}
          <div className="hidden sm:flex items-center gap-2 text-[11px] text-text-tertiary">
            {items.map((item) => (
              <span key={item.label}>
                {item.label.charAt(0)}: <span className="font-medium tabular-nums text-text-secondary">{item.score}</span>
              </span>
            ))}
          </div>
          <svg
            className={`w-4 h-4 text-text-tertiary transition-transform duration-200 ${expanded ? "rotate-180" : ""}`}
            fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>

      {expanded && (
        <div className="mt-4 pt-3 border-t border-gray-100">
          {/* Score bars */}
          <div className="flex gap-2 mb-4">
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

          {/* Score drivers */}
          {drivers.length > 0 && (
            <div className="space-y-1.5">
              <p className="text-[11px] text-text-tertiary uppercase tracking-wider font-semibold mb-1.5">Einflussfaktoren</p>
              {drivers.map((driver, i) => (
                <div key={i} className="flex items-start gap-2 text-xs">
                  <span className={`w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${
                    driver.direction === "positive" ? "bg-emerald-500" :
                    driver.direction === "negative" ? "bg-red-500" : "bg-gray-400"
                  }`} />
                  <span className="text-text-primary/80 leading-relaxed">{driver.label}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
