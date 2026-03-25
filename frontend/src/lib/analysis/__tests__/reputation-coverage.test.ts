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

// ─── Link-Level vs Provider-Level separation ────────────────────────────────

describe("link-level coverage classification", () => {
  it("link with ALL providers successful => fully analyzed", () => {
    const links = [
      makeLink({
        verdict: "clean",
        external_checks: [
          makeCheck({ service: "virustotal", result_fetched: true, scan_status: "completed_clean" }),
          makeCheck({ service: "urlscan", result_fetched: true, scan_status: "completed_clean" }),
        ],
      }),
    ];
    const stats = summarizeLinks(links);
    expect(stats.linksFullyAnalyzed).toBe(1);
    expect(stats.linksPartiallyAnalyzed).toBe(0);
    expect(stats.linksWithoutResult).toBe(0);
  });

  it("link with only ONE provider successful => partially analyzed", () => {
    const links = [
      makeLink({
        verdict: "partially_analyzed",
        external_checks: [
          makeCheck({ service: "virustotal", result_fetched: true, scan_status: "completed_clean" }),
          makeCheck({ service: "urlscan", result_fetched: false, scan_status: "timeout", status: "timeout" }),
        ],
      }),
    ];
    const stats = summarizeLinks(links);
    expect(stats.linksFullyAnalyzed).toBe(0);
    expect(stats.linksPartiallyAnalyzed).toBe(1);
    expect(stats.linksWithoutResult).toBe(0);
  });

  it("link with NO provider result => without result", () => {
    const links = [
      makeLink({
        verdict: "unknown",
        external_checks: [
          makeCheck({ service: "virustotal", result_fetched: false, scan_status: "timeout", status: "timeout" }),
          makeCheck({ service: "urlscan", result_fetched: false, scan_status: "api_error", status: "failed" }),
        ],
      }),
    ];
    const stats = summarizeLinks(links);
    expect(stats.linksFullyAnalyzed).toBe(0);
    expect(stats.linksPartiallyAnalyzed).toBe(0);
    expect(stats.linksWithoutResult).toBe(1);
  });

  it("link with only skipped providers => without result", () => {
    const links = [
      makeLink({
        verdict: "not_checked",
        external_checks: [
          makeCheck({ service: "virustotal", result_fetched: false, scan_status: "skipped" }),
          makeCheck({ service: "urlscan", result_fetched: false, scan_status: "not_executed" }),
        ],
      }),
    ];
    const stats = summarizeLinks(links);
    expect(stats.linksFullyAnalyzed).toBe(0);
    expect(stats.linksPartiallyAnalyzed).toBe(0);
    expect(stats.linksWithoutResult).toBe(1);
  });
});

describe("provider-level scan counting", () => {
  it("counts provider scans independently from link count", () => {
    const links = [
      makeLink({
        verdict: "clean",
        external_checks: [
          makeCheck({ service: "virustotal", result_fetched: true }),
          makeCheck({ service: "urlscan", result_fetched: true }),
        ],
      }),
      makeLink({
        verdict: "unknown",
        external_checks: [
          makeCheck({ service: "virustotal", result_fetched: false, scan_status: "timeout", status: "timeout" }),
          makeCheck({ service: "urlscan", result_fetched: false, scan_status: "api_error", status: "failed" }),
        ],
      }),
    ];
    const stats = summarizeLinks(links);

    // 2 links, 4 provider scans
    expect(stats.total).toBe(2);
    expect(stats.providerScansTotal).toBe(4);
    expect(stats.providerScansSuccessful).toBe(2);
    expect(stats.providerScansFailed).toBe(2);
    expect(stats.providerScansSkipped).toBe(0);

    // Link-level
    expect(stats.linksFullyAnalyzed).toBe(1);
    expect(stats.linksWithoutResult).toBe(1);
  });

  it("newsletter with 47 links and 2 providers: 47/94 scans successful", () => {
    // Simulates: 47 links, VT succeeds for all, urlscan fails for all
    const links = Array.from({ length: 47 }, (_, i) =>
      makeLink({
        id: `link-${i}`,
        verdict: "partially_analyzed",
        external_checks: [
          makeCheck({ service: "virustotal", result_fetched: true, scan_status: "completed_clean" }),
          makeCheck({ service: "urlscan", result_fetched: false, scan_status: "rate_limited", status: "failed" }),
        ],
      })
    );
    const stats = summarizeLinks(links);

    expect(stats.total).toBe(47);
    expect(stats.providerScansTotal).toBe(94);
    expect(stats.providerScansSuccessful).toBe(47);
    expect(stats.providerScansFailed).toBe(47);
    expect(stats.coveragePercent).toBe(50);

    // All links are partially analyzed (1 of 2 providers returned)
    expect(stats.linksFullyAnalyzed).toBe(0);
    expect(stats.linksPartiallyAnalyzed).toBe(47);
    expect(stats.linksWithoutResult).toBe(0);

    // Coverage is partial, not clean
    expect(stats.reputationCoverage).toBe("partially_analyzed");
  });

  it("skipped providers not counted in coverage percent", () => {
    const links = [
      makeLink({
        verdict: "clean",
        external_checks: [
          makeCheck({ service: "virustotal", result_fetched: true }),
          makeCheck({ service: "urlscan", result_fetched: false, scan_status: "not_executed" }),
        ],
      }),
    ];
    const stats = summarizeLinks(links);
    // 1 attempted (VT), 1 skipped (urlscan) → only VT counts
    expect(stats.providerScansSkipped).toBe(1);
    expect(stats.coveragePercent).toBe(100); // 1/1 attempted = 100%
    // Link is fully analyzed because the only non-skipped provider returned
    expect(stats.linksFullyAnalyzed).toBe(1);
  });
});

// ─── Reputation coverage aggregation ────────────────────────────────────────

describe("summarizeLinks reputation coverage", () => {
  it("no links => coverage 'none'", () => {
    const stats = summarizeLinks([]);
    expect(stats.reputationCoverage).toBe("none");
  });

  it("all links fully analyzed => coverage 'clean'", () => {
    const links = [
      makeLink({
        verdict: "clean",
        external_checks: [makeCheck({ result_fetched: true })],
      }),
      makeLink({
        verdict: "clean",
        external_checks: [makeCheck({ result_fetched: true })],
      }),
    ];
    const stats = summarizeLinks(links);
    expect(stats.reputationCoverage).toBe("clean");
    expect(stats.linksFullyAnalyzed).toBe(2);
  });

  it("no malicious + no suspicious + no result_fetched => NOT clean", () => {
    const links = [
      makeLink({
        verdict: "unknown",
        external_checks: [makeCheck({
          result_fetched: false, status: "timeout", scan_status: "timeout",
        })],
      }),
    ];
    const stats = summarizeLinks(links);
    expect(stats.reputationCoverage).not.toBe("clean");
    expect(stats.reputationCoverage).toBe("unknown");
  });

  it("mix of fully and without result => 'partially_analyzed'", () => {
    const links = [
      makeLink({
        verdict: "clean",
        external_checks: [makeCheck({ result_fetched: true })],
      }),
      makeLink({
        verdict: "unknown",
        external_checks: [makeCheck({
          result_fetched: false, status: "timeout", scan_status: "timeout",
        })],
      }),
    ];
    const stats = summarizeLinks(links);
    expect(stats.reputationCoverage).toBe("partially_analyzed");
  });

  it("all not_checked => coverage 'not_checked'", () => {
    const links = [
      makeLink({ verdict: "not_checked", external_checks: [] }),
      makeLink({ verdict: "not_checked", external_checks: [] }),
    ];
    const stats = summarizeLinks(links);
    expect(stats.reputationCoverage).toBe("not_checked");
  });
});

// ─── Signal generation: labels and precision ────────────────────────────────

describe("normalize: reputation signals", () => {
  it("verified clean links produce 'links:clean' signal", () => {
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

    const clean = signals.find((s) => s.key === "links:clean");
    expect(clean).toBeDefined();
    expect(clean!.label).toBe("Keine negativen Reputationstreffer erkannt");
    expect(clean!.severity).toBe("positive");
    expect(clean!.tier).toBe(2);
  });

  it("unknown links produce 'links:unknown' with provider-level detail", () => {
    const result = makeResult({
      links: [
        makeLink({
          verdict: "unknown",
          external_checks: [
            makeCheck({ result_fetched: false, status: "timeout", scan_status: "timeout" }),
            makeCheck({ service: "urlscan", result_fetched: false, scan_status: "api_error", status: "failed" }),
          ],
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
    // Evidence text should reference provider scan counts
    expect(unknown!.evidenceText).toMatch(/Provider-Scans fehlgeschlagen/);
  });

  it("partially analyzed links signal includes link-level counts", () => {
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

    const partial = signals.find((s) => s.key === "links:partial");
    expect(partial).toBeDefined();
    expect(partial!.label).toContain("unvollständig");
    // Evidence should contain link-level + provider-level detail
    expect(partial!.evidenceText).toMatch(/vollständig geprüft/);
    expect(partial!.evidenceText).toMatch(/Provider-Scans/);
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
    expect(notChecked!.direction).toBe("negative");
  });

  it("'Alle Links reputationsmäßig unauffällig' never appears", () => {
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

  it("'mit belastbarem Ergebnis geprüft' not in signal labels for partial coverage", () => {
    const result = makeResult({
      links: [
        makeLink({
          verdict: "clean",
          external_checks: [makeCheck({ result_fetched: true })],
        }),
        makeLink({
          verdict: "unknown",
          external_checks: [makeCheck({ result_fetched: false, scan_status: "timeout", status: "timeout" })],
        }),
      ],
    });
    const identity = assessIdentity(result);
    const linkStats = summarizeLinks(result.links);
    const signals = normalizeSignals(result, identity, linkStats, false);
    const allLabels = signals.map((s) => s.label);
    for (const label of allLabels) {
      expect(label).not.toContain("mit belastbarem Ergebnis geprüft");
    }
  });
});

// ─── High-risk content + reputation: no false exoneration ───────────────────

describe("high-risk content + reputation interaction", () => {
  it("high-risk content + clean reputation => links:clean demoted", () => {
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

    const cleanSignal = analysis.normalized.find((s) => s.key === "links:clean");
    if (cleanSignal) {
      expect(cleanSignal.tier).toBe(1);
      expect(cleanSignal.severity).toBe("context");
      expect(cleanSignal.promotable).toBe(false);
    }
    const positiveKeys = analysis.decisionFactors.positive.map((s) => s.key);
    expect(positiveKeys).not.toContain("links:clean");
  });

  it("phishing case with unknown reputation => no entlastung", () => {
    const result = makeResult({
      sender: { from_address: "user@example.com", reply_to: null, return_path: null, subject: "Ihre Zahlung fehlgeschlagen - Konto gesperrt", to: null, date: null, message_id: null },
      links: [
        makeLink({
          verdict: "unknown",
          external_checks: [makeCheck({
            result_fetched: false, status: "error", scan_status: "api_error",
          })],
        }),
      ],
      assessment: { classification: "phishing", evidence: [] },
    });
    const analysis = analyzeResult(result);
    const positiveLabels = analysis.decisionFactors.positive.map((s) => s.label);
    for (const label of positiveLabels) {
      expect(label).not.toMatch(/unauffällig|clean|sauber/i);
    }
  });
});

// ─── Newsletter case with incomplete reputation ─────────────────────────────

describe("newsletter with incomplete reputation", () => {
  it("newsletter with 47/94 successful scans => partial, not clean", () => {
    const links = Array.from({ length: 47 }, (_, i) =>
      makeLink({
        id: `link-${i}`,
        verdict: "partially_analyzed",
        external_checks: [
          makeCheck({ service: "virustotal", result_fetched: true }),
          makeCheck({ service: "urlscan", result_fetched: false, scan_status: "rate_limited", status: "failed" }),
        ],
      })
    );
    const result = makeResult({
      structured_headers: { "list-unsubscribe": "<mailto:unsub@newsletter.com>" },
      links,
    });
    const identity = assessIdentity(result);
    const linkStats = summarizeLinks(result.links);
    const signals = normalizeSignals(result, identity, linkStats, true);

    expect(signals.find((s) => s.key === "links:clean")).toBeUndefined();
    const partial = signals.find((s) => s.key === "links:partial");
    expect(partial).toBeDefined();
    expect(partial!.label).toContain("unvollständig");

    // Verify link-level counts
    expect(linkStats.linksPartiallyAnalyzed).toBe(47);
    expect(linkStats.linksFullyAnalyzed).toBe(0);
    expect(linkStats.coveragePercent).toBe(50);
  });
});

// ─── Decision factors respect coverage ──────────────────────────────────────

describe("decision factors respect reputation coverage", () => {
  it("clean only appears as positive factor when fully verified", () => {
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
    expect(positiveKeys).toContain("links:clean");
  });

  it("partial coverage produces hedged text, not strong positive", () => {
    const result = makeResult({
      authentication_results: "spf=pass",
      links: [
        makeLink({
          verdict: "clean",
          external_checks: [makeCheck({ result_fetched: true })],
        }),
        makeLink({
          verdict: "unknown",
          external_checks: [makeCheck({ result_fetched: false, scan_status: "timeout", status: "timeout" })],
        }),
      ],
    });
    const analysis = analyzeResult(result);
    // Should NOT have links:clean as positive factor (coverage is partial)
    const positiveKeys = analysis.decisionFactors.positive.map((s) => s.key);
    expect(positiveKeys).not.toContain("links:clean");
    // partial signal should exist but as context
    const partial = analysis.normalized.find((s) => s.key === "links:partial");
    expect(partial).toBeDefined();
    expect(partial!.severity).toBe("context");
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
    const negativeKeys = analysis.decisionFactors.negative.map((s) => s.key);
    expect(negativeKeys).toContain("links:unknown");
  });
});

// ─── Edge cases ─────────────────────────────────────────────────────────────

describe("coverage edge cases", () => {
  it("link with no external_checks defaults to without_result", () => {
    const links = [{ ...makeLink(), verdict: undefined, external_checks: [] }];
    const stats = summarizeLinks(links);
    expect(stats.verdicts.unknown).toBe(1);
    expect(stats.linksWithoutResult).toBe(1);
    expect(stats.reputationCoverage).toBe("unknown");
  });

  it("link with one fetched + one failed provider => partially analyzed", () => {
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
    expect(stats.linksPartiallyAnalyzed).toBe(1);
    expect(stats.linksFullyAnalyzed).toBe(0);
    expect(stats.providerScansSuccessful).toBe(1);
    expect(stats.providerScansFailed).toBe(1);
    expect(stats.reputationCoverage).toBe("partially_analyzed");
  });

  it("coveragePercent is null when no scans attempted", () => {
    const links = [makeLink({ verdict: "not_checked", external_checks: [] })];
    const stats = summarizeLinks(links);
    expect(stats.coveragePercent).toBeNull();
  });

  it("coveragePercent excludes skipped scans from denominator", () => {
    const links = [
      makeLink({
        verdict: "clean",
        external_checks: [
          makeCheck({ service: "virustotal", result_fetched: true }),
          makeCheck({ service: "urlscan", result_fetched: false, scan_status: "skipped" }),
        ],
      }),
    ];
    const stats = summarizeLinks(links);
    // Only VT counted (urlscan skipped), so 1/1 = 100%
    expect(stats.coveragePercent).toBe(100);
  });
});
