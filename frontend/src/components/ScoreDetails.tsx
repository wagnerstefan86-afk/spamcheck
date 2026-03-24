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

function interpretScore(score: number, label: string): string {
  if (label === "Legitimität") {
    if (score >= 70) return "Stark legitimierend";
    if (score >= 45) return "Neutral";
    if (score >= 20) return "Gering";
    return "Sehr gering";
  }
  // Phishing / Werbung: higher = more likely
  if (score >= 70) return "Hoch";
  if (score >= 45) return "Moderat";
  if (score >= 20) return "Gering";
  return "Sehr gering";
}

export default function ScoreDetails({ scores, drivers }: Props) {
  const [expanded, setExpanded] = useState(false);

  const items = [
    { label: "Phishing", score: scores.phishing_likelihood_score, color: "bg-red-500", bgTrack: "bg-red-100", textColor: "text-red-600" },
    { label: "Werbung", score: scores.advertising_likelihood_score, color: "bg-blue-500", bgTrack: "bg-blue-100", textColor: "text-blue-600" },
    { label: "Legitimität", score: scores.legitimacy_likelihood_score, color: "bg-emerald-500", bgTrack: "bg-emerald-100", textColor: "text-emerald-600" },
  ];

  const dominant = [...items].sort((a, b) => b.score - a.score)[0];
  const hasDrivers = drivers.length > 0;

  return (
    <div className="card">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between"
      >
        <div className="flex items-center gap-3">
          <p className="text-xs text-text-secondary uppercase tracking-wider font-semibold">Score-Details</p>
          <span className="text-xs text-text-tertiary">
            Dominant: <span className={`font-semibold ${dominant.textColor}`}>{dominant.label}</span> ({dominant.score}/100)
          </span>
        </div>
        <svg
          className={`w-4 h-4 text-text-tertiary transition-transform duration-200 ${expanded ? "rotate-180" : ""}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Compact inline bars — always visible */}
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

      {/* Expanded: score interpretation + drivers */}
      {expanded && (
        <div className="mt-4 pt-4 border-t border-gray-100">
          {/* Score interpretation */}
          <div className="grid grid-cols-3 gap-3 mb-4">
            {items.map((item) => (
              <div key={item.label} className="text-center">
                <div className={`text-2xl font-bold tabular-nums ${item.textColor}`}>{item.score}</div>
                <div className="text-[11px] text-text-tertiary mt-0.5">{item.label}</div>
                <div className="text-[11px] text-text-secondary font-medium">{interpretScore(item.score, item.label)}</div>
              </div>
            ))}
          </div>

          {/* Score drivers from deterministic_findings */}
          {hasDrivers && (
            <div className="space-y-1.5">
              <p className="text-[11px] text-text-tertiary uppercase tracking-wider font-semibold mb-2">Einflussfaktoren</p>
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

          {!hasDrivers && (
            <p className="text-xs text-text-tertiary italic">
              Keine detaillierten Einflussfaktoren verfügbar. Die Scores basieren auf der Gesamtanalyse von Header-Befunden und Link-Reputation.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
