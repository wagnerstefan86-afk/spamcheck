import { describe, it, expect } from "vitest";
import { normalizeSignals, toPrioritizedSignals, toEvidenceGroups } from "../normalize";
import { assessIdentity } from "../identity";
import { summarizeLinks } from "../links";
import { assessConflict } from "../priority";
import { analyzeResult } from "../decision";

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

// ─── End-to-end pipeline via analyzeResult ──────────────────────────────────

describe("analyzeResult — central pipeline", () => {
  it("produces all views from one call", () => {
    const result = makeResult({
      authentication_results: "spf=pass; dkim=fail; dmarc=pass",
      header_findings: [
        { id: "HDR-001", severity: "critical", title: "DKIM fehlgeschlagen", detail: "Signatur ungültig" },
      ],
    });
    const analysis = analyzeResult(result);

    // Signals
    expect(analysis.signals.find((s) => s.key === "auth:spf:pass")).toBeDefined();
    expect(analysis.signals.find((s) => s.key === "auth:dkim:fail")).toBeDefined();

    // Conflict
    expect(analysis.conflict.hasConflict).toBe(true);
    expect(analysis.conflict.dominantSignal?.key).toBe("auth:dkim:fail");

    // Decision factors
    expect(analysis.decisionFactors.promotedKeys.has("auth:dkim:fail")).toBe(true);
    expect(analysis.decisionFactors.promotedKeys.has("auth:spf:pass")).toBe(true);

    // Evidence groups
    expect(analysis.evidenceGroups.critical.find((i) => i.key === "auth:dkim:fail")).toBeDefined();

    // Summary
    expect(analysis.summary.version).toBe(1);
    expect(analysis.summary.signals.length).toBeGreaterThan(0);

    // Explanation
    expect(analysis.explanation).toBeTruthy();
  });

  it("conflict dominance uses normalized tier values", () => {
    const result = makeResult({
      authentication_results: "spf=pass; dkim=pass; dmarc=pass",
      links: [{
        id: 1, normalized_url: "http://evil.com", hostname: "evil.com",
        is_ip_literal: false, is_punycode: false, has_display_mismatch: false,
        is_suspicious_tld: false, is_shortener: false, is_tracking_heavy: false,
        is_safelink: false,
        external_checks: [{ status: "completed", service: "VT", malicious_count: 5, suspicious_count: 0 }],
      }],
    });
    const { conflict } = analyzeResult(result);

    expect(conflict.hasConflict).toBe(true);
    expect(conflict.dominantSignal?.domain).toBe("links");
    expect(conflict.dominantSignal?.tier).toBe(5);
  });

  it("bulk downgrade works through pipeline", () => {
    const result = makeResult({
      authentication_results: "spf=pass; dkim=pass; dmarc=pass",
      sender: {
        from_address: "news@company.com",
        reply_to: "bounce@mailer.company.com",
        return_path: null,
        to: null, date: null, message_id: null,
      },
      structured_headers: { "list-unsubscribe": "<mailto:unsub@company.com>" },
    });
    const { conflict } = analyzeResult(result);

    expect(conflict.bulkDowngradeApplied).toBe(true);
    expect(conflict.bulkDowngradeBlocked).toBe(false);
  });

  it("bulk downgrade blocked when hard critical present", () => {
    const result = makeResult({
      authentication_results: "spf=fail; dkim=pass; dmarc=pass",
      sender: {
        from_address: "news@company.com",
        reply_to: "bounce@mailer.company.com",
        return_path: null,
        to: null, date: null, message_id: null,
      },
      structured_headers: { "list-unsubscribe": "<mailto:unsub@company.com>" },
    });
    const { conflict } = analyzeResult(result);

    expect(conflict.bulkDowngradeBlocked).toBe(true);
    expect(conflict.bulkDowngradeApplied).toBe(false);
  });
});

// ─── Source references ──────────────────────────────────────────────────────

describe("Improved source references", () => {
  it("identity signals reference involved domains", () => {
    const result = makeResult({
      sender: { from_address: "a@x.com", reply_to: "b@y.com", return_path: null, to: null, date: null, message_id: null },
    });
    const { normalized } = analyzeResult(result);
    const idSignal = normalized.find((s) => s.key === "identity:mismatch" && s.sourceType === "identity_derived");
    expect(idSignal).toBeDefined();
    expect(idSignal!.sourceRef).toContain("x.com");
    expect(idSignal!.sourceRef).toContain("y.com");
  });

  it("link malicious signals reference URLs", () => {
    const result = makeResult({
      links: [{
        id: 1, normalized_url: "http://evil.com/phish", hostname: "evil.com",
        is_ip_literal: false, is_punycode: false, has_display_mismatch: false,
        is_suspicious_tld: false, is_shortener: false, is_tracking_heavy: false,
        is_safelink: false,
        external_checks: [{ status: "completed", service: "VT", malicious_count: 3, suspicious_count: 0 }],
      }],
    });
    const { normalized } = analyzeResult(result);
    const linkSignal = normalized.find((s) => s.key.startsWith("links:malicious") && s.sourceType === "link_analysis");
    expect(linkSignal).toBeDefined();
    expect(linkSignal!.sourceRef).toContain("evil.com");
  });

  it("bulk detection signals reference source", () => {
    const result = makeResult({
      structured_headers: { "list-unsubscribe": "<mailto:unsub@x.com>" },
    });
    const { normalized } = analyzeResult(result);
    const bulk = normalized.find((s) => s.key === "bulk:detected");
    expect(bulk).toBeDefined();
    expect(bulk!.sourceRef).toBe("header:list-unsubscribe");
  });

  it("bulk from classification references source", () => {
    const result = makeResult({
      assessment: { classification: "advertising", evidence: [] },
    });
    const { normalized } = analyzeResult(result);
    const bulk = normalized.find((s) => s.key === "bulk:detected");
    expect(bulk).toBeDefined();
    expect(bulk!.sourceRef).toBe("classification:advertising");
  });

  it("clean links reference verified and total count", () => {
    const result = makeResult({
      links: [{
        id: 1, normalized_url: "http://safe.com", hostname: "safe.com",
        is_ip_literal: false, is_punycode: false, has_display_mismatch: false,
        is_suspicious_tld: false, is_shortener: false, is_tracking_heavy: false,
        is_safelink: false, verdict: "clean",
        external_checks: [{ status: "completed", service: "VT", malicious_count: 0, suspicious_count: 0, result_fetched: true, scan_status: "completed_clean" }],
      }],
    });
    const { normalized } = analyzeResult(result);
    const clean = normalized.find((s) => s.key === "links:clean");
    expect(clean).toBeDefined();
    expect(clean!.sourceRef).toContain("fully:1");
    expect(clean!.sourceRef).toContain("total:1");
  });
});

// ─── AnalysisSummary as product artifact ────────────────────────────────────

describe("AnalysisSummary product artifact", () => {
  it("is JSON-serializable with version field", () => {
    const result = makeResult();
    const { summary } = analyzeResult(result);

    const json = JSON.stringify(summary);
    const parsed = JSON.parse(json);

    expect(parsed.version).toBe(1);
    expect(Array.isArray(parsed.signals)).toBe(true);
    expect(Array.isArray(parsed.promotedKeys)).toBe(true);
    expect(typeof parsed.conflict).toBe("object");
    expect(typeof parsed.decisionFactors).toBe("object");
  });

  it("contains classification and analystSummary from backend", () => {
    const result = makeResult({
      assessment: {
        classification: "suspicious",
        analyst_summary: "This looks suspicious due to auth issues.",
        evidence: [],
      },
    });
    const { summary } = analyzeResult(result);

    expect(summary.classification).toBe("suspicious");
    expect(summary.analystSummary).toBe("This looks suspicious due to auth issues.");
  });

  it("contains decision explanation derived from signals", () => {
    const result = makeResult({
      authentication_results: "spf=pass; dkim=fail; dmarc=pass",
    });
    const { summary } = analyzeResult(result);

    expect(summary.explanation).toBeTruthy();
    // Explanation should mention auth
    expect(summary.explanation).toContain("fehlgeschlagen");
  });

  it("explanation is null when analyst_summary present and no conflict", () => {
    const result = makeResult({
      assessment: {
        classification: "legitimate",
        analyst_summary: "Everything looks fine.",
        evidence: [],
      },
    });
    const { summary } = analyzeResult(result);

    // No conflict (all auth pass, no negative signals) → no generated explanation
    expect(summary.explanation).toBeNull();
    expect(summary.analystSummary).toBe("Everything looks fine.");
  });

  it("all promoted keys from summary match decisionFactors", () => {
    const result = makeResult({
      authentication_results: "spf=pass; dkim=fail; dmarc=pass",
      header_findings: [
        { id: "HDR-001", severity: "critical", title: "DKIM fehlgeschlagen", detail: "fail" },
      ],
    });
    const { summary, decisionFactors } = analyzeResult(result);

    for (const key of Array.from(decisionFactors.promotedKeys)) {
      expect(summary.promotedKeys).toContain(key);
    }
  });

  it("conflict info matches assessConflict output", () => {
    const result = makeResult({
      authentication_results: "spf=pass; dkim=fail; dmarc=pass",
    });
    const { summary, conflict } = analyzeResult(result);

    expect(summary.conflict.hasConflict).toBe(conflict.hasConflict);
    expect(summary.conflict.dominantSignalKey).toBe(conflict.dominantSignal?.key || null);
    expect(summary.conflict.bulkDowngradeApplied).toBe(conflict.bulkDowngradeApplied);
  });

  it("all signals have valid sourceType", () => {
    const result = makeResult({
      authentication_results: "spf=pass; dkim=pass; dmarc=pass",
      header_findings: [{ id: "HDR-001", severity: "info", title: "SPF bestanden", detail: "pass" }],
      deterministic_findings: [{ factor: "bulk_headers", impact: "", detail: "Bulk headers" }],
      assessment: { classification: "legitimate", evidence: ["All auth passed."] },
    });
    const { summary } = analyzeResult(result);
    const validSourceTypes = ["auth_result", "header_finding", "det_finding", "link_analysis", "identity_derived", "llm_evidence", "bulk_detection"];

    for (const s of summary.signals) {
      expect(s.sourceType).toBeTruthy();
      expect(validSourceTypes).toContain(s.sourceType);
    }
  });
});

// ─── Decision explanation consistency ───────────────────────────────────────

describe("Decision explanation consistency", () => {
  it("explanation reflects auth signals from normalized data", () => {
    const result = makeResult({
      authentication_results: "spf=pass; dkim=pass; dmarc=pass",
    });
    const { explanation } = analyzeResult(result);

    // All auth pass, no negatives → explanation mentions valid auth
    expect(explanation).toContain("valide");
  });

  it("explanation reflects auth failure from normalized data", () => {
    const result = makeResult({
      authentication_results: "spf=fail; dkim=pass; dmarc=pass",
    });
    const { explanation } = analyzeResult(result);

    expect(explanation).toContain("fehlgeschlagen");
    expect(explanation).toContain("SPF");
  });

  it("explanation reflects malicious links", () => {
    const result = makeResult({
      links: [{
        id: 1, normalized_url: "http://evil.com", hostname: "evil.com",
        is_ip_literal: false, is_punycode: false, has_display_mismatch: false,
        is_suspicious_tld: false, is_shortener: false, is_tracking_heavy: false,
        is_safelink: false,
        external_checks: [{ status: "completed", service: "VT", malicious_count: 2, suspicious_count: 0 }],
      }],
    });
    const { explanation } = analyzeResult(result);

    expect(explanation).toContain("maliziös");
  });

  it("explanation reflects bulk downgrade context", () => {
    const result = makeResult({
      authentication_results: "spf=pass; dkim=pass; dmarc=pass",
      sender: {
        from_address: "news@company.com",
        reply_to: "bounce@mailer.company.com",
        return_path: null,
        to: null, date: null, message_id: null,
      },
      structured_headers: { "list-unsubscribe": "<mailto:unsub@company.com>" },
    });
    const { explanation } = analyzeResult(result);

    expect(explanation).toContain("Newsletter");
  });
});

// ─── Promotion / dedup regression ───────────────────────────────────────────

describe("Promotion/dedup regression (via analyzeResult)", () => {
  it("promoted keys match evidence keys exactly", () => {
    const result = makeResult({
      header_findings: [
        { id: "HDR-001", severity: "info", title: "SPF bestanden", detail: "pass" },
        { id: "HDR-002", severity: "info", title: "DKIM bestanden", detail: "pass" },
      ],
    });
    const { decisionFactors, evidenceGroups } = analyzeResult(result);
    const allItems = [...evidenceGroups.critical, ...evidenceGroups.noteworthy, ...evidenceGroups.positive, ...evidenceGroups.context];

    expect(decisionFactors.promotedKeys.has("auth:spf:pass")).toBe(true);

    const spfEvidence = allItems.find((i) => i.key === "auth:spf:pass");
    expect(spfEvidence).toBeDefined();
    expect(decisionFactors.promotedKeys.has(spfEvidence!.key)).toBe(true);
  });

  it("unmapped findings NOT promoted", () => {
    const result = makeResult({
      header_findings: [{ id: "HDR-099", severity: "info", title: "Unbekannter Befund", detail: "x" }],
    });
    const { decisionFactors } = analyzeResult(result);
    expect(decisionFactors.promotedKeys.has("header:HDR-099")).toBe(false);
  });

  it("free-text evidence NOT promoted", () => {
    const result = makeResult({
      assessment: { classification: "legitimate", evidence: ["Some text."] },
    });
    const { decisionFactors } = analyzeResult(result);
    expect(decisionFactors.promotedKeys.has("evidence:0")).toBe(false);
  });
});
