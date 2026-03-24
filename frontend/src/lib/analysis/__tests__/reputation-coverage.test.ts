import { describe, it, expect } from "vitest";
import { summarizeLinks } from "../links";
import { normalizeSignals, toPrioritizedSignals } from "../normalize";
import { assessIdentity } from "../identity";
import { analyzeResult, extractDecisionFactors } from "../decision";

// ─── Helpers ────────────────────────────────────────────────────────────────

function makeResult(overrides: any = {}) {
  return {
    sender: { from_address: "user@example.com", reply_to: null, return_path: null, to: null, date: null, message_id: null },
    authentication_results: "spf=pass; dkim=pass; dmarc=pass",
    header_findings: [],
    deterministic_findings: [],
    links: [],
    structured_headers: {},
    assessment: { classification: "legitimate", evidence: [], ...overrides.assessment },
    ...overrides,
  };
}

function makeLink(overrides: any = {}) {
  return {
    id: `link-${Math.random().toString(36).slice(2, 8)}`,
    normalized_url: "https://example.com",
    hostname: "example.com",
    display_text: "example.com",
    is_ip_literal: false,
    is_punycode: false,
    has_display_mismatch: false,
    is_suspicious_tld: false,
    is_shortener: false,
    is_tracking_heavy: false,
    is_safelink: false,
    verdict: "unknown",
    external_checks: [],
    ...overrides,
  };
}

function makeCheck(overrides: any = {}) {
  return {
    service: "virustotal",
    status: "completed",
    scan_status: "completed_clean",
    malicious_count: 0,
    suspicious_count: 0,
    result_summary: {},
    result_fetched: true,
    ...overrides,
  };
}

// ─── summarizeLinks: Reputation Coverage ────────────────────────────────────

describe("summarizeLinks reputation coverage", () => {
  it("no links => coverage 'none'", () => {
    const stats = summarizeLinks([]);
    expect(stats.reputationCoverage).toBe("none");
    expect(stats.resultFetchedCount).toBe(0);
  });

  it("all links clean with result_fetched => coverage 'clean'", () => {
    const links = [
      makeLink({
        verdict: "clean",
        external_checks: [makeCheck({ result_fetched: true, scan_status: "completed_clean" })],
      }),
      makeLink({
        verdict: "clean",
        external_checks: [makeCheck({ result_fetched: true, scan_status: "completed_clean" })],
      }),
    ];
    const stats = summarizeLinks(links);
    expect(stats.reputationCoverage).toBe("clean");
    expect(stats.resultFetchedCount).toBe(2);
    expect(stats.verdicts.clean).toBe(2);
  });

  it("no malicious + no suspicious + no result_fetched => NOT clean", () => {
    const links = [
      makeLink({
        verdict: "unknown",
        external_checks: [makeCheck({
          result_fetched: false,
          status: "timeout",
          scan_status: "timeout",
          malicious_count: 0,
          suspicious_count: 0,
        })],
      }),
    ];
    const stats = summarizeLinks(links);
    expect(stats.reputationCoverage).not.toBe("clean");
    expect(stats.reputationCoverage).toBe("unknown");
    expect(stats.malicious).toBe(0);
    expect(stats.suspicious).toBe(0);
  });

  it("partial provider results => 'partially_analyzed'", () => {
    const links = [
      makeLink({
        verdict: "clean",
        external_checks: [makeCheck({ result_fetched: true, scan_status: "completed_clean" })],
      }),
      makeLink({
        verdict: "unknown",
        external_checks: [makeCheck({
          result_fetched: false,
          status: "timeout",
          scan_status: "timeout",
        })],
      }),
    ];
    const stats = summarizeLinks(links);
    expect(stats.reputationCoverage).toBe("partially_analyzed");
    expect(stats.resultFetchedCount).toBe(1);
  });

  it("all not_checked => coverage 'not_checked'", () => {
    const links = [
      makeLink({ verdict: "not_checked", external_checks: [] }),
      makeLink({ verdict: "not_checked", external_checks: [] }),
    ];
    const stats = summarizeLinks(links);
    expect(stats.reputationCoverage).toBe("not_checked");
  });

  it("malicious link with result_fetched does not get 'clean' coverage", () => {
    const links = [
      makeLink({
        verdict: "malicious",
        external_checks: [makeCheck({ result_fetched: true, malicious_count: 3, scan_status: "completed_malicious" })],
      }),
    ];
    const stats = summarizeLinks(links);
    expect(stats.malicious).toBe(3);
    // Coverage is about how many links were verified, not about the outcome
    expect(stats.resultFetchedCount).toBe(1);
  });
});

// ─── Signal generation: clean only when verified ────────────────────────────

describe("normalize: reputation signals", () => {
  it("verified clean links produce 'links:clean' signal", () => {
    const result = makeResult({
      links: [
        makeLink({
          verdict: "clean",
          external_checks: [makeCheck({ result_fetched: true, scan_status: "completed_clean" })],
        }),
      ],
    });
    const identity = assessIdentity(result);
    const linkStats = summarizeLinks(result.links);
    const signals = normalizeSignals(result, identity, linkStats, false);

    const clean = signals.find((s) => s.key === "links:clean");
    expect(clean).toBeDefined();
    expect(clean!.label).toBe("Keine negativen Reputationstreffer erkannt");
    expect(clean!.severity).toBe("positive");
    expect(clean!.tier).toBe(2);
  });

  it("unknown links produce 'links:unknown' signal, NOT 'links:clean'", () => {
    const result = makeResult({
      links: [
        makeLink({
          verdict: "unknown",
          external_checks: [makeCheck({
            result_fetched: false,
            status: "timeout",
            scan_status: "timeout",
          })],
        }),
      ],
    });
    const identity = assessIdentity(result);
    const linkStats = summarizeLinks(result.links);
    const signals = normalizeSignals(result, identity, linkStats, false);

    expect(signals.find((s) => s.key === "links:clean")).toBeUndefined();
    const unknown = signals.find((s) => s.key === "links:unknown");
    expect(unknown).toBeDefined();
    expect(unknown!.label).toBe("Reputationsbewertung nicht belastbar");
    expect(unknown!.direction).toBe("negative");
  });

  it("partially analyzed links produce 'links:partial' signal", () => {
    const result = makeResult({
      links: [
        makeLink({
          verdict: "clean",
          external_checks: [makeCheck({ result_fetched: true })],
        }),
        makeLink({
          verdict: "unknown",
          external_checks: [makeCheck({ result_fetched: false, status: "timeout", scan_status: "timeout" })],
        }),
      ],
    });
    const identity = assessIdentity(result);
    const linkStats = summarizeLinks(result.links);
    const signals = normalizeSignals(result, identity, linkStats, false);

    expect(signals.find((s) => s.key === "links:clean")).toBeUndefined();
    const partial = signals.find((s) => s.key === "links:partial");
    expect(partial).toBeDefined();
    expect(partial!.label).toContain("unvollständig");
  });

  it("not_checked links produce 'links:not_checked' signal", () => {
    const result = makeResult({
      links: [makeLink({ verdict: "not_checked", external_checks: [] })],
    });
    const identity = assessIdentity(result);
    const linkStats = summarizeLinks(result.links);
    const signals = normalizeSignals(result, identity, linkStats, false);

    expect(signals.find((s) => s.key === "links:clean")).toBeUndefined();
    const notChecked = signals.find((s) => s.key === "links:not_checked");
    expect(notChecked).toBeDefined();
    expect(notChecked!.label).toBe("Keine belastbare Reputationsbewertung verfügbar");
    expect(notChecked!.direction).toBe("negative");
  });

  it("'Alle Links reputationsmäßig unauffällig' text never appears", () => {
    // Even in clean case, the old text should be gone
    const result = makeResult({
      links: [
        makeLink({
          verdict: "clean",
          external_checks: [makeCheck({ result_fetched: true })],
        }),
      ],
    });
    const identity = assessIdentity(result);
    const linkStats = summarizeLinks(result.links);
    const signals = normalizeSignals(result, identity, linkStats, false);

    const allLabels = signals.map((s) => s.label);
    expect(allLabels).not.toContain("Alle Links reputationsmäßig unauffällig");
  });
});

// ─── High-risk content + reputation: no false exoneration ───────────────────

describe("high-risk content + reputation interaction", () => {
  it("high-risk content + clean reputation => links:clean demoted, not dominant positive", () => {
    const result = makeResult({
      sender: { from_address: "user@example.com", reply_to: null, return_path: null, subject: "Konto gesperrt - sofort handeln", to: null, date: null, message_id: null },
      links: [
        makeLink({
          verdict: "clean",
          external_checks: [makeCheck({ result_fetched: true })],
        }),
      ],
      assessment: { classification: "phishing", evidence: ["Passwort erneuern erforderlich"] },
    });
    const analysis = analyzeResult(result);

    // links:clean should be demoted (tier 1, context, not promotable)
    const cleanSignal = analysis.normalized.find((s) => s.key === "links:clean");
    if (cleanSignal) {
      expect(cleanSignal.tier).toBe(1);
      expect(cleanSignal.severity).toBe("context");
      expect(cleanSignal.promotable).toBe(false);
    }

    // links:clean should NOT appear in positive decision factors
    const positiveKeys = analysis.decisionFactors.positive.map((s) => s.key);
    expect(positiveKeys).not.toContain("links:clean");
  });

  it("high-risk content + unknown reputation => no clean entlastung at all", () => {
    const result = makeResult({
      sender: { from_address: "user@example.com", reply_to: null, return_path: null, subject: "Konto gesperrt - sofort handeln", to: null, date: null, message_id: null },
      links: [
        makeLink({
          verdict: "unknown",
          external_checks: [makeCheck({
            result_fetched: false,
            status: "timeout",
            scan_status: "timeout",
          })],
        }),
      ],
      assessment: { classification: "phishing", evidence: ["Account suspended - verify now"] },
    });
    const analysis = analyzeResult(result);

    // No links:clean signal at all
    expect(analysis.normalized.find((s) => s.key === "links:clean")).toBeUndefined();

    // Positive factors should not contain any link reputation entlastung
    const positiveKeys = analysis.decisionFactors.positive.map((s) => s.key);
    expect(positiveKeys).not.toContain("links:clean");
    expect(positiveKeys).not.toContain("links:unknown");
  });

  it("phishing case does not get strong reputation-entlastung", () => {
    const result = makeResult({
      sender: { from_address: "user@example.com", reply_to: null, return_path: null, subject: "Ihre Zahlung fehlgeschlagen - Konto gesperrt", to: null, date: null, message_id: null },
      links: [
        makeLink({
          verdict: "unknown",
          external_checks: [makeCheck({
            result_fetched: false,
            status: "error",
            scan_status: "api_error",
          })],
        }),
      ],
      assessment: { classification: "phishing", evidence: [] },
    });
    const analysis = analyzeResult(result);

    // No positive decision factor for links
    const positiveLabels = analysis.decisionFactors.positive.map((s) => s.label);
    for (const label of positiveLabels) {
      expect(label).not.toMatch(/unauffällig|clean|sauber/i);
    }
  });
});

// ─── Newsletter case with incomplete reputation ─────────────────────────────

describe("newsletter with incomplete reputation", () => {
  it("newsletter with partial reputation does not claim clean", () => {
    const result = makeResult({
      structured_headers: { "list-unsubscribe": "<mailto:unsub@newsletter.com>" },
      links: [
        makeLink({
          verdict: "clean",
          external_checks: [makeCheck({ result_fetched: true })],
        }),
        makeLink({
          verdict: "unknown",
          external_checks: [makeCheck({ result_fetched: false, status: "timeout", scan_status: "timeout" })],
        }),
        makeLink({
          verdict: "not_checked",
          external_checks: [],
        }),
      ],
    });
    const identity = assessIdentity(result);
    const linkStats = summarizeLinks(result.links);
    const signals = normalizeSignals(result, identity, linkStats, true);

    // Should NOT have a clean signal
    expect(signals.find((s) => s.key === "links:clean")).toBeUndefined();

    // Should have partial signal
    const partial = signals.find((s) => s.key === "links:partial");
    expect(partial).toBeDefined();
  });
});

// ─── Decision factors: correct entlastung rules ────────────────────────────

describe("decision factors respect reputation coverage", () => {
  it("clean only appears as positive factor when verified", () => {
    // Use minimal auth (only SPF) so links:clean isn't pushed out by MAX_FACTORS
    const result = makeResult({
      authentication_results: "spf=pass",
      links: [
        makeLink({
          verdict: "clean",
          external_checks: [makeCheck({ result_fetched: true })],
        }),
      ],
    });
    const analysis = analyzeResult(result);
    const positiveKeys = analysis.decisionFactors.positive.map((s) => s.key);
    // links:clean should be in positive factors (verified clean, no content risk)
    expect(positiveKeys).toContain("links:clean");
  });

  it("unknown/not_checked never appears as positive factor", () => {
    const result = makeResult({
      links: [
        makeLink({
          verdict: "unknown",
          external_checks: [makeCheck({ result_fetched: false, status: "timeout", scan_status: "timeout" })],
        }),
      ],
    });
    const analysis = analyzeResult(result);
    const positiveKeys = analysis.decisionFactors.positive.map((s) => s.key);
    expect(positiveKeys).not.toContain("links:clean");
    expect(positiveKeys).not.toContain("links:unknown");
    // links:unknown should appear as negative (direction: negative)
    const negativeKeys = analysis.decisionFactors.negative.map((s) => s.key);
    expect(negativeKeys).toContain("links:unknown");
  });
});

// ─── Coverage computation edge cases ────────────────────────────────────────

describe("coverage edge cases", () => {
  it("link with no external_checks and no verdict defaults to unknown", () => {
    const links = [{ ...makeLink(), verdict: undefined, external_checks: [] }];
    const stats = summarizeLinks(links);
    expect(stats.verdicts.unknown).toBe(1);
    expect(stats.reputationCoverage).toBe("unknown");
  });

  it("link with result_fetched from one provider but not another", () => {
    const links = [
      makeLink({
        verdict: "partially_analyzed",
        external_checks: [
          makeCheck({ service: "virustotal", result_fetched: true }),
          makeCheck({ service: "urlscan", result_fetched: false, status: "timeout", scan_status: "timeout" }),
        ],
      }),
    ];
    const stats = summarizeLinks(links);
    expect(stats.resultFetchedCount).toBe(1);
    expect(stats.verdicts.partially_analyzed).toBe(1);
    expect(stats.reputationCoverage).toBe("partially_analyzed");
  });
});
