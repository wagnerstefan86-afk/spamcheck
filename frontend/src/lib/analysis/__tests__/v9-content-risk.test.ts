import { describe, it, expect } from "vitest";
import { analyzeResult } from "../decision";
import { detectContentRisks, assessContentRiskLevel } from "../content";

// ─── Helpers ────────────────────────────────────────────────────────────────

function makeResult(overrides: any = {}) {
  return {
    sender: { from_address: "noreply@example.com", reply_to: null, return_path: null, to: null, date: null, message_id: null, subject: "" },
    authentication_results: "spf=pass; dkim=pass; dmarc=pass",
    header_findings: [],
    deterministic_findings: [],
    links: [],
    structured_headers: {},
    assessment: { classification: "legitimate", evidence: [], ...overrides.assessment },
    subject: "",
    body_preview: "",
    ...overrides,
  };
}

// ─── Content Risk Detection ─────────────────────────────────────────────────

describe("Content risk detection", () => {
  it("detects account_threat in subject", () => {
    const result = makeResult({ subject: "Ihr Konto wurde gesperrt" });
    const risks = detectContentRisks(result);
    expect(risks.some((r) => r.type === "account_threat")).toBe(true);
    expect(risks.find((r) => r.type === "account_threat")!.source).toBe("subject");
  });

  it("detects urgent_action in body", () => {
    const result = makeResult({ body_preview: "Bitte handeln Sie sofort, um Ihr Konto zu bestätigen." });
    const risks = detectContentRisks(result);
    expect(risks.some((r) => r.type === "urgent_action")).toBe(true);
  });

  it("detects credential_lure", () => {
    const result = makeResult({ subject: "Ihr Passwort ist abgelaufen - jetzt erneuern" });
    const risks = detectContentRisks(result);
    expect(risks.some((r) => r.type === "credential_lure")).toBe(true);
  });

  it("detects payment_lure", () => {
    const result = makeResult({ subject: "Zahlung fehlgeschlagen - Konto eingeschränkt" });
    const risks = detectContentRisks(result);
    expect(risks.some((r) => r.type === "payment_lure")).toBe(true);
    expect(risks.some((r) => r.type === "account_threat")).toBe(true);
  });

  it("detects deletion_threat", () => {
    const result = makeResult({ body_preview: "Ihre Fotos und Videos werden in 24 Stunden gelöscht." });
    const risks = detectContentRisks(result);
    expect(risks.some((r) => r.type === "deletion_threat")).toBe(true);
  });

  it("detects generic_branding", () => {
    const result = makeResult({ body_preview: "Sehr geehrter Kunde, bitte bestätigen Sie Ihre Daten." });
    const risks = detectContentRisks(result);
    expect(risks.some((r) => r.type === "generic_branding")).toBe(true);
  });

  it("detects English patterns", () => {
    const result = makeResult({ subject: "Your account has been suspended - immediate action required" });
    const risks = detectContentRisks(result);
    expect(risks.some((r) => r.type === "account_threat")).toBe(true);
    expect(risks.some((r) => r.type === "urgent_action")).toBe(true);
  });

  it("returns empty for legitimate content", () => {
    const result = makeResult({ subject: "Monatsreport Februar 2025", body_preview: "Hier ist der aktuelle Bericht." });
    const risks = detectContentRisks(result);
    expect(risks.length).toBe(0);
  });

  it("detects from LLM classification", () => {
    const result = makeResult({ assessment: { classification: "phishing", evidence: [] } });
    const risks = detectContentRisks(result);
    expect(risks.some((r) => r.type === "credential_lure")).toBe(true);
  });
});

describe("Content risk level assessment", () => {
  it("returns 'high' for account_threat + urgent_action", () => {
    const level = assessContentRiskLevel([
      { type: "account_threat", source: "subject", matchedText: "" },
      { type: "urgent_action", source: "body", matchedText: "" },
    ]);
    expect(level).toBe("high");
  });

  it("returns 'high' for single strong signal (account_threat)", () => {
    const level = assessContentRiskLevel([
      { type: "account_threat", source: "subject", matchedText: "" },
    ]);
    expect(level).toBe("high");
  });

  it("returns 'low' for only generic_branding", () => {
    const level = assessContentRiskLevel([
      { type: "generic_branding", source: "body", matchedText: "" },
    ]);
    expect(level).toBe("low");
  });

  it("returns 'none' for empty", () => {
    expect(assessContentRiskLevel([])).toBe("none");
  });
});

// ─── Auth Reweighting ───────────────────────────────────────────────────────

describe("Auth reweighting on high content risk", () => {
  it("demotes auth:*:pass to context tier when content risk is high", () => {
    const result = makeResult({
      subject: "Ihr Konto wurde gesperrt - sofort handeln",
      body_preview: "Klicken Sie hier um Ihr Passwort zu bestätigen",
    });
    const { normalized, contentRiskLevel } = analyzeResult(result);

    expect(contentRiskLevel).toBe("high");

    // Auth signals should be demoted to context
    const authPass = normalized.filter((s) => s.key.startsWith("auth:") && s.key.endsWith(":pass"));
    for (const s of authPass) {
      expect(s.severity).toBe("context");
      expect(s.tier).toBe(1);
      expect(s.promotable).toBe(false);
    }
  });

  it("keeps auth:*:pass as positive when content risk is none", () => {
    const result = makeResult({ subject: "Monatsreport" });
    const { normalized, contentRiskLevel } = analyzeResult(result);

    expect(contentRiskLevel).toBe("none");

    const authPass = normalized.filter((s) => s.key.startsWith("auth:") && s.key.endsWith(":pass"));
    for (const s of authPass) {
      expect(s.severity).toBe("positive");
      expect(s.tier).toBe(2);
    }
  });

  it("demoted auth signals are NOT in decision factors", () => {
    const result = makeResult({
      subject: "Account suspended - confirm your identity now",
    });
    const { decisionFactors, contentRiskLevel } = analyzeResult(result);

    expect(contentRiskLevel).toBe("high");

    // Auth pass should not appear as positive decision factor
    const authInPositive = decisionFactors.positive.filter((s) => s.domain === "auth");
    expect(authInPositive.length).toBe(0);
  });

  it("content risk signals appear as negative decision factors", () => {
    const result = makeResult({
      subject: "Konto gesperrt - jetzt Passwort erneuern",
    });
    const { decisionFactors } = analyzeResult(result);

    const contentFactors = decisionFactors.negative.filter((s) => s.domain === "content");
    expect(contentFactors.length).toBeGreaterThan(0);
  });
});

// ─── Reputation Unknown ─────────────────────────────────────────────────────

describe("Reputation unknown signal", () => {
  it("creates links:unknown when scans fail and no result_fetched", () => {
    const result = makeResult({
      links: [{
        id: 1, normalized_url: "http://example.com", hostname: "example.com",
        is_ip_literal: false, is_punycode: false, has_display_mismatch: false,
        is_suspicious_tld: false, is_shortener: false, is_tracking_heavy: false,
        is_safelink: false, verdict: "unknown",
        external_checks: [
          { status: "error", service: "VT", result_fetched: false, scan_status: "api_error" },
          { status: "timeout", service: "urlscan", result_fetched: false, scan_status: "timeout" },
        ],
      }],
    });
    const { normalized } = analyzeResult(result);
    const unknown = normalized.find((s) => s.key === "links:unknown");
    expect(unknown).toBeDefined();
    expect(unknown!.severity).toBe("noteworthy");
    expect(unknown!.sourceType).toBe("link_analysis");
  });

  it("links:unknown is present when combined with high content risk", () => {
    const result = makeResult({
      subject: "Konto gesperrt - sofort handeln",
      links: [{
        id: 1, normalized_url: "http://suspicious.com", hostname: "suspicious.com",
        is_ip_literal: false, is_punycode: false, has_display_mismatch: false,
        is_suspicious_tld: false, is_shortener: false, is_tracking_heavy: false,
        is_safelink: false, verdict: "unknown",
        external_checks: [{ status: "error", service: "VT", result_fetched: false, scan_status: "api_error" }],
      }],
    });
    const { normalized, contentRiskLevel } = analyzeResult(result);

    expect(contentRiskLevel).toBe("high");
    // links:unknown should exist — no clean entlastung possible
    const unknown = normalized.find((s) => s.key === "links:unknown");
    expect(unknown).toBeDefined();
    expect(unknown!.direction).toBe("negative");
  });

  it("links:clean is demoted when content risk is high", () => {
    const result = makeResult({
      subject: "Ihr Passwort ist abgelaufen",
      links: [{
        id: 1, normalized_url: "http://clean.com", hostname: "clean.com",
        is_ip_literal: false, is_punycode: false, has_display_mismatch: false,
        is_suspicious_tld: false, is_shortener: false, is_tracking_heavy: false,
        is_safelink: false, verdict: "clean",
        external_checks: [
          { status: "completed", service: "VT", malicious_count: 0, suspicious_count: 0, result_fetched: true, scan_status: "completed_clean" },
        ],
      }],
    });
    const { normalized, contentRiskLevel } = analyzeResult(result);

    expect(contentRiskLevel).toBe("high");
    const clean = normalized.find((s) => s.key === "links:clean");
    expect(clean).toBeDefined();
    expect(clean!.severity).toBe("context");
    expect(clean!.promotable).toBe(false);
  });

  it("no reputation:unknown when all scans complete", () => {
    const result = makeResult({
      links: [{
        id: 1, normalized_url: "http://safe.com", hostname: "safe.com",
        is_ip_literal: false, is_punycode: false, has_display_mismatch: false,
        is_suspicious_tld: false, is_shortener: false, is_tracking_heavy: false,
        is_safelink: false,
        external_checks: [
          { status: "completed", service: "VT", malicious_count: 0, suspicious_count: 0 },
        ],
      }],
    });
    const { normalized } = analyzeResult(result);
    expect(normalized.find((s) => s.key === "reputation:unknown")).toBeUndefined();
  });
});

// ─── Decision Override ──────────────────────────────────────────────────────

describe("Decision override for phishing content", () => {
  it("overrides when content risk is high (even with valid auth)", () => {
    const result = makeResult({
      subject: "Ihr Konto wurde gesperrt",
      body_preview: "Bestätigen Sie sofort Ihre Identität",
      authentication_results: "spf=pass; dkim=pass; dmarc=pass",
    });
    const { overrideApplied, contentRiskLevel } = analyzeResult(result);

    expect(contentRiskLevel).toBe("high");
    expect(overrideApplied).toBe(true);
  });

  it("does NOT override for legitimate content", () => {
    const result = makeResult({ subject: "Monatsreport Februar" });
    const { overrideApplied } = analyzeResult(result);
    expect(overrideApplied).toBe(false);
  });

  it("does NOT override for low content risk", () => {
    const result = makeResult({ body_preview: "Sehr geehrter Kunde" });
    const { overrideApplied, contentRiskLevel } = analyzeResult(result);
    expect(contentRiskLevel).toBe("low");
    expect(overrideApplied).toBe(false);
  });

  it("override is reflected in summary", () => {
    const result = makeResult({
      subject: "Account suspended - verify now",
      body_preview: "Click here to confirm your password",
    });
    const { summary } = analyzeResult(result);
    expect(summary.overrideApplied).toBe(true);
    expect(summary.contentRiskLevel).toBe("high");
  });
});

// ─── UI Evidence Fix: no false critical ─────────────────────────────────────

describe("Evidence severity fix for negated statements", () => {
  it('"keine bösartigen Ergebnisse" is classified as positive, not critical', () => {
    const result = makeResult({
      assessment: {
        classification: "legitimate",
        evidence: ["Keine bösartigen oder verdächtigen Ergebnisse in den Link-Scans."],
      },
    });
    const { evidenceGroups } = analyzeResult(result);

    // Should be in positive, NOT in critical
    const allCritical = evidenceGroups.critical.map((i) => i.text);
    const allPositive = evidenceGroups.positive.map((i) => i.text);
    expect(allCritical.some((t) => /keine.*bösartig/i.test(t))).toBe(false);
    expect(allPositive.some((t) => /keine.*bösartig/i.test(t))).toBe(true);
  });

  it('"no malicious results" is classified as positive, not critical', () => {
    const result = makeResult({
      assessment: {
        classification: "legitimate",
        evidence: ["No malicious or suspicious results found."],
      },
    });
    const { evidenceGroups } = analyzeResult(result);

    const allCritical = evidenceGroups.critical.map((i) => i.text);
    expect(allCritical.some((t) => /no malicious/i.test(t))).toBe(false);
  });
});

// ─── Newsletter/Bulk case still works ───────────────────────────────────────

describe("Newsletter/bulk case unaffected", () => {
  it("legitimate newsletter stays clean — no content risk, no override", () => {
    const result = makeResult({
      subject: "Ihr wöchentlicher Newsletter",
      body_preview: "Neuigkeiten aus dem Februar...",
      authentication_results: "spf=pass; dkim=pass; dmarc=pass",
      structured_headers: { "list-unsubscribe": "<mailto:unsub@newsletter.com>" },
      assessment: { classification: "advertising", evidence: [] },
    });
    const { contentRiskLevel, overrideApplied, normalized } = analyzeResult(result);

    expect(contentRiskLevel).toBe("none");
    expect(overrideApplied).toBe(false);
    // Bulk detected and auth all pass — clean newsletter
    expect(normalized.some((s) => s.key === "bulk:detected")).toBe(true);
    const authPass = normalized.filter((s) => s.key.endsWith(":pass") && s.domain === "auth");
    expect(authPass.every((s) => s.severity === "positive")).toBe(true);
  });

  it("bulk:detected appears as decision factor in newsletter case", () => {
    const result = makeResult({
      subject: "Newsletter Februar",
      authentication_results: "spf=pass; dkim=pass; dmarc=pass",
      sender: {
        from_address: "news@company.com",
        reply_to: "bounce@mailer.company.com",
        return_path: null,
        to: null, date: null, message_id: null,
      },
      structured_headers: { "list-unsubscribe": "<mailto:unsub@company.com>" },
    });
    const { decisionFactors } = analyzeResult(result);

    // Bulk context should be in positive factors
    const bulkFactor = decisionFactors.positive.find((s) => s.key === "bulk:detected");
    expect(bulkFactor).toBeDefined();
  });
});

// ─── Explanation reflects new logic ─────────────────────────────────────────

describe("Explanation reflects content risk", () => {
  it("explanation mentions content risk for phishing case", () => {
    const result = makeResult({
      subject: "Konto gesperrt - Passwort erneuern",
      authentication_results: "spf=pass; dkim=pass; dmarc=pass",
    });
    const { explanation } = analyzeResult(result);

    expect(explanation).toBeTruthy();
    expect(explanation).toContain("Risikomerkmale");
    // Auth should be qualified, not presented as exonerating
    expect(explanation).toContain("belegt aber nicht die Gutartigkeit");
  });

  it("explanation mentions reputation unknown", () => {
    const result = makeResult({
      links: [{
        id: 1, normalized_url: "http://x.com", hostname: "x.com",
        is_ip_literal: false, is_punycode: false, has_display_mismatch: false,
        is_suspicious_tld: false, is_shortener: false, is_tracking_heavy: false,
        is_safelink: false,
        external_checks: [{ status: "error", service: "VT" }],
      }],
    });
    const { explanation } = analyzeResult(result);

    expect(explanation).toBeTruthy();
    expect(explanation).toContain("nicht belastbar");
  });
});
