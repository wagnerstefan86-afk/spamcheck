import { describe, it, expect } from "vitest";
import { analyzeResult, computeActionDecision } from "../decision";
import { summarizeLinks } from "../links";
import { normalizeSignals, toPrioritizedSignals } from "../normalize";
import { assessIdentity } from "../identity";
import { assessConflict } from "../priority";
import { detectContentRisks, assessContentRiskLevel } from "../content";

// ─── Helpers ────────────────────────────────────────────────────────────────

function makeResult(overrides: any = {}) {
  return {
    sender: { from_address: "user@example.com", reply_to: null, return_path: null, to: null, date: null, message_id: null, subject: null },
    authentication_results: "spf=pass; dkim=pass; dmarc=pass",
    header_findings: [],
    deterministic_findings: [],
    links: [],
    structured_headers: {},
    assessment: { classification: "legitimate", evidence: [], risk_score: 10, confidence: 85, recommended_action: "allow", ...overrides.assessment },
    ...overrides,
  };
}

function makeLink(overrides: any = {}) {
  return {
    id: `link-${Math.random().toString(36).slice(2, 8)}`,
    normalized_url: "https://example.com",
    hostname: "example.com",
    display_text: "example.com",
    is_ip_literal: false, is_punycode: false, has_display_mismatch: false,
    is_suspicious_tld: false, is_shortener: false, is_tracking_heavy: false,
    is_safelink: false, verdict: "unknown", external_checks: [],
    ...overrides,
  };
}

function makeCheck(overrides: any = {}) {
  return {
    service: "virustotal", status: "completed", scan_status: "completed_clean",
    malicious_count: 0, suspicious_count: 0, result_summary: {}, result_fetched: true,
    ...overrides,
  };
}

// ─── Legitimate cases → "open" ──────────────────────────────────────────────

describe("action decision: open", () => {
  it("legitimate newsletter with good auth → open", () => {
    const result = makeResult({
      structured_headers: { "list-unsubscribe": "<mailto:unsub@news.com>" },
      authentication_results: "spf=pass; dkim=pass; dmarc=pass",
      links: [
        makeLink({
          verdict: "clean",
          external_checks: [makeCheck({ result_fetched: true })],
        }),
      ],
    });
    const analysis = analyzeResult(result);
    expect(analysis.actionDecision.action).toBe("open");
    expect(analysis.actionDecision.label).toBe("Öffnen");
  });

  it("normal business mail with consistent identity and clean reputation → open", () => {
    const result = makeResult({
      sender: { from_address: "colleague@company.com", reply_to: null, return_path: "colleague@company.com", to: null, date: null, message_id: null, subject: "Meeting morgen" },
      authentication_results: "spf=pass; dkim=pass; dmarc=pass",
      links: [
        makeLink({
          verdict: "clean",
          external_checks: [makeCheck({ result_fetched: true })],
        }),
      ],
    });
    const analysis = analyzeResult(result);
    expect(analysis.actionDecision.action).toBe("open");
  });

  it("mail without links and good auth → open", () => {
    const result = makeResult({
      authentication_results: "spf=pass; dkim=pass; dmarc=pass",
      links: [],
    });
    const analysis = analyzeResult(result);
    expect(analysis.actionDecision.action).toBe("open");
  });
});

// ─── Phishing / dangerous cases → "do_not_open" ────────────────────────────

describe("action decision: do_not_open", () => {
  it("clear phishing with credential lure → do_not_open", () => {
    const result = makeResult({
      sender: { from_address: "security@bank-alert.com", reply_to: null, return_path: null, to: null, date: null, message_id: null, subject: "Konto gesperrt - sofort handeln" },
      assessment: { classification: "phishing", evidence: ["Passwort erneuern erforderlich"], risk_score: 85, confidence: 90, recommended_action: "delete" },
    });
    const analysis = analyzeResult(result);
    expect(analysis.actionDecision.action).toBe("do_not_open");
    expect(analysis.actionDecision.label).toBe("Nicht öffnen");
  });

  it("account threat content → do_not_open", () => {
    const result = makeResult({
      sender: { from_address: "no-reply@service.com", reply_to: null, return_path: null, to: null, date: null, message_id: null, subject: "Account suspended - verify now" },
      assessment: { classification: "phishing", evidence: ["Account suspended"], risk_score: 80, confidence: 85, recommended_action: "delete" },
    });
    const analysis = analyzeResult(result);
    expect(analysis.actionDecision.action).toBe("do_not_open");
  });

  it("payment lure + urgency → do_not_open", () => {
    const result = makeResult({
      sender: { from_address: "billing@service.com", reply_to: null, return_path: null, to: null, date: null, message_id: null, subject: "Zahlung fehlgeschlagen - sofort bestätigen" },
      assessment: { classification: "suspicious", evidence: [], risk_score: 70, confidence: 75, recommended_action: "manual_review" },
    });
    const analysis = analyzeResult(result);
    expect(analysis.actionDecision.action).toBe("do_not_open");
  });

  it("spoofing detected → do_not_open", () => {
    const result = makeResult({
      header_findings: [
        { id: "HDR-SPOOF", severity: "critical", title: "Display-Name-Inkonsistenz / Spoofing", detail: "CEO name used with external domain" },
      ],
    });
    const analysis = analyzeResult(result);
    expect(analysis.actionDecision.action).toBe("do_not_open");
  });

  it("malicious link detected → do_not_open", () => {
    const result = makeResult({
      links: [
        makeLink({
          verdict: "malicious",
          external_checks: [makeCheck({ result_fetched: true, malicious_count: 5, scan_status: "completed_malicious" })],
        }),
      ],
    });
    const analysis = analyzeResult(result);
    expect(analysis.actionDecision.action).toBe("do_not_open");
  });

  it("high-risk content NOT overridden by clean auth", () => {
    const result = makeResult({
      sender: { from_address: "user@example.com", reply_to: null, return_path: null, to: null, date: null, message_id: null, subject: "Ihr Passwort ist abgelaufen - jetzt handeln" },
      authentication_results: "spf=pass; dkim=pass; dmarc=pass",
      links: [
        makeLink({
          verdict: "clean",
          external_checks: [makeCheck({ result_fetched: true })],
        }),
      ],
    });
    const analysis = analyzeResult(result);
    // Content risk is high → do_not_open, even with perfect auth/reputation
    expect(analysis.actionDecision.action).toBe("do_not_open");
  });
});

// ─── Unclear / mixed cases → "manual_review" ───────────────────────────────

describe("action decision: manual_review", () => {
  it("partial reputation + no hard signals → manual_review", () => {
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
    const analysis = analyzeResult(result);
    expect(analysis.actionDecision.action).toBe("manual_review");
  });

  it("unknown reputation coverage → manual_review", () => {
    const result = makeResult({
      links: [
        makeLink({
          verdict: "unknown",
          external_checks: [makeCheck({ result_fetched: false, scan_status: "api_error", status: "failed" })],
        }),
      ],
    });
    const analysis = analyzeResult(result);
    expect(analysis.actionDecision.action).toBe("manual_review");
  });

  it("suspicious link → manual_review (not do_not_open)", () => {
    const result = makeResult({
      links: [
        makeLink({
          verdict: "suspicious",
          external_checks: [makeCheck({ result_fetched: true, suspicious_count: 2, scan_status: "completed_suspicious" })],
        }),
      ],
    });
    const analysis = analyzeResult(result);
    // Suspicious links lead to manual_review via tier-3 negative signal
    expect(analysis.actionDecision.action).toBe("manual_review");
  });

  it("auth failure without identity spoofing → manual_review", () => {
    const result = makeResult({
      authentication_results: "spf=fail; dkim=pass; dmarc=pass",
    });
    const analysis = analyzeResult(result);
    expect(analysis.actionDecision.action).toBe("manual_review");
  });
});

// ─── Summary integration ────────────────────────────────────────────────────

describe("action decision in summary", () => {
  it("summary contains actionDecision with correct fields", () => {
    const result = makeResult();
    const analysis = analyzeResult(result);

    expect(analysis.summary.actionDecision).toBeDefined();
    expect(analysis.summary.actionDecision.action).toBe(analysis.actionDecision.action);
    expect(analysis.summary.actionDecision.label).toBe(analysis.actionDecision.label);
    expect(analysis.summary.actionDecision.reason).toBe(analysis.actionDecision.reason);
    expect(typeof analysis.summary.actionDecision.action).toBe("string");
  });

  it("summary is JSON-serializable with actionDecision", () => {
    const result = makeResult();
    const analysis = analyzeResult(result);

    const json = JSON.stringify(analysis.summary);
    const parsed = JSON.parse(json);
    expect(parsed.actionDecision).toBeDefined();
    expect(parsed.actionDecision.action).toBe(analysis.actionDecision.action);
  });
});

// ─── Edge cases ─────────────────────────────────────────────────────────────

describe("action decision edge cases", () => {
  it("no assessment (deterministic fallback) still produces decision", () => {
    const result = makeResult({ assessment: null });
    const analysis = analyzeResult(result);
    expect(analysis.actionDecision).toBeDefined();
    expect(["open", "manual_review", "do_not_open"]).toContain(analysis.actionDecision.action);
  });

  it("reason is always a non-empty string", () => {
    const scenarios = [
      makeResult(), // legitimate
      makeResult({ sender: { from_address: "x@y.com", reply_to: null, return_path: null, to: null, date: null, message_id: null, subject: "Konto gesperrt - sofort handeln" }, assessment: { classification: "phishing", evidence: ["Account threat"], risk_score: 85, confidence: 90, recommended_action: "delete" } }),
    ];
    for (const r of scenarios) {
      const analysis = analyzeResult(r);
      expect(analysis.actionDecision.reason.length).toBeGreaterThan(0);
    }
  });
});
