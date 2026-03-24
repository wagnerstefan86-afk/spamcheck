import { describe, it, expect } from "vitest";
import { normalizeSignals, toPrioritizedSignals, toEvidenceGroups } from "../normalize";
import { assessIdentity } from "../identity";
import { summarizeLinks } from "../links";
import { assessConflict } from "../priority";
import { extractDecisionFactors, buildAnalysisSummary } from "../decision";

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

function runPipeline(result: any) {
  const identity = assessIdentity(result);
  const linkStats = summarizeLinks(result.links || []);
  const normalized = normalizeSignals(result, identity, linkStats, identity.isBulkSender);
  const signals = toPrioritizedSignals(normalized);
  const conflict = assessConflict(signals, identity);
  const factors = extractDecisionFactors(signals);
  const evidenceGroups = toEvidenceGroups(normalized);
  const summary = buildAnalysisSummary(normalized, factors, conflict);
  return { identity, linkStats, normalized, signals, conflict, factors, evidenceGroups, summary };
}

// ─── End-to-end pipeline: no collectSignals needed ──────────────────────────

describe("Consolidated pipeline (no collectSignals)", () => {
  it("produces consistent signals, conflict, factors, and evidence from one path", () => {
    const result = makeResult({
      authentication_results: "spf=pass; dkim=fail; dmarc=pass",
      header_findings: [
        { id: "HDR-001", severity: "critical", title: "DKIM fehlgeschlagen", detail: "Signatur ungültig" },
      ],
    });
    const { signals, conflict, factors, evidenceGroups } = runPipeline(result);

    // Signals derived from normalized pipeline
    expect(signals.find((s) => s.key === "auth:spf:pass")).toBeDefined();
    expect(signals.find((s) => s.key === "auth:dkim:fail")).toBeDefined();

    // Conflict assessment works on the same signals
    expect(conflict.hasConflict).toBe(true);
    expect(conflict.dominantSignal?.key).toBe("auth:dkim:fail");

    // Decision factors from same signals
    expect(factors.promotedKeys.has("auth:dkim:fail")).toBe(true);
    expect(factors.promotedKeys.has("auth:spf:pass")).toBe(true);

    // Evidence groups from same normalized signals
    const criticalItems = evidenceGroups.critical;
    expect(criticalItems.find((i) => i.key === "auth:dkim:fail")).toBeDefined();
  });

  it("conflict dominance uses normalized tier values", () => {
    const result = makeResult({
      authentication_results: "spf=pass; dkim=pass; dmarc=pass",
      links: [
        {
          id: 1, normalized_url: "http://evil.com", hostname: "evil.com",
          is_ip_literal: false, is_punycode: false, has_display_mismatch: false,
          is_suspicious_tld: false, is_shortener: false, is_tracking_heavy: false,
          is_safelink: false,
          external_checks: [{ status: "completed", service: "VT", malicious_count: 5, suspicious_count: 0 }],
        },
      ],
    });
    const { conflict } = runPipeline(result);

    expect(conflict.hasConflict).toBe(true);
    // Malicious links (tier 5) dominate over auth pass (tier 2)
    expect(conflict.dominantSignal?.domain).toBe("links");
    expect(conflict.dominantSignal?.tier).toBe(5);
  });

  it("bulk downgrade works through normalized pipeline", () => {
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
    const { conflict } = runPipeline(result);

    // Should have conflict (identity mismatch vs auth pass) but bulk downgrade applied
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
    const { conflict } = runPipeline(result);

    // SPF fail is tier 5 → blocks bulk downgrade
    expect(conflict.bulkDowngradeBlocked).toBe(true);
    expect(conflict.bulkDowngradeApplied).toBe(false);
  });
});

// ─── Source references improved ─────────────────────────────────────────────

describe("Improved source references", () => {
  it("identity signals reference involved domains", () => {
    const result = makeResult({
      sender: {
        from_address: "a@x.com",
        reply_to: "b@y.com",
        return_path: null,
        to: null, date: null, message_id: null,
      },
    });
    const { normalized } = runPipeline(result);
    const idSignal = normalized.find((s) => s.key === "identity:mismatch" && s.sourceType === "identity_derived");
    expect(idSignal).toBeDefined();
    expect(idSignal!.sourceRef).toContain("x.com");
    expect(idSignal!.sourceRef).toContain("y.com");
  });

  it("link malicious signals reference URLs when available", () => {
    const result = makeResult({
      links: [
        {
          id: 1, normalized_url: "http://evil.com/phish", hostname: "evil.com",
          is_ip_literal: false, is_punycode: false, has_display_mismatch: false,
          is_suspicious_tld: false, is_shortener: false, is_tracking_heavy: false,
          is_safelink: false,
          external_checks: [{ status: "completed", service: "VT", malicious_count: 3, suspicious_count: 0 }],
        },
      ],
    });
    const { normalized } = runPipeline(result);
    const linkSignal = normalized.find((s) => s.key.startsWith("links:malicious") && s.sourceType === "link_analysis");
    expect(linkSignal).toBeDefined();
    expect(linkSignal!.sourceRef).toContain("evil.com");
  });

  it("link structural signals reference affected URLs", () => {
    const result = makeResult({
      links: [
        {
          id: 1, normalized_url: "http://xn--exmple-cua.com", hostname: "xn--exmple-cua.com",
          is_ip_literal: false, is_punycode: true, has_display_mismatch: false,
          is_suspicious_tld: false, is_shortener: false, is_tracking_heavy: false,
          is_safelink: false, external_checks: [],
        },
      ],
    });
    const { normalized } = runPipeline(result);
    const structural = normalized.find((s) => s.key === "links:structural");
    expect(structural).toBeDefined();
    expect(structural!.sourceRef).toContain("xn--exmple-cua.com");
  });

  it("bulk detection signals reference detection source", () => {
    const result = makeResult({
      structured_headers: { "list-unsubscribe": "<mailto:unsub@x.com>" },
    });
    const { normalized } = runPipeline(result);
    const bulk = normalized.find((s) => s.key === "bulk:detected");
    expect(bulk).toBeDefined();
    expect(bulk!.sourceRef).toBe("header:list-unsubscribe");
  });

  it("bulk detection from classification references source", () => {
    const result = makeResult({
      assessment: { classification: "advertising", evidence: [] },
    });
    const identity = assessIdentity(result);
    const linkStats = summarizeLinks(result.links || []);
    const normalized = normalizeSignals(result, identity, linkStats, identity.isBulkSender);
    const bulk = normalized.find((s) => s.key === "bulk:detected");
    expect(bulk).toBeDefined();
    expect(bulk!.sourceRef).toBe("classification:advertising");
  });

  it("clean links reference total count", () => {
    const result = makeResult({
      links: [
        {
          id: 1, normalized_url: "http://safe.com", hostname: "safe.com",
          is_ip_literal: false, is_punycode: false, has_display_mismatch: false,
          is_suspicious_tld: false, is_shortener: false, is_tracking_heavy: false,
          is_safelink: false, external_checks: [],
        },
      ],
    });
    const { normalized } = runPipeline(result);
    const clean = normalized.find((s) => s.key === "links:clean");
    expect(clean).toBeDefined();
    expect(clean!.sourceRef).toBe("total:1");
  });
});

// ─── AnalysisSummary in export ──────────────────────────────────────────────

describe("AnalysisSummary for export", () => {
  it("is fully JSON-serializable", () => {
    const result = makeResult({
      authentication_results: "spf=pass; dkim=pass; dmarc=pass",
      header_findings: [
        { id: "HDR-001", severity: "info", title: "SPF bestanden", detail: "pass" },
      ],
    });
    const { summary } = runPipeline(result);

    // Must not throw
    const json = JSON.stringify(summary);
    const parsed = JSON.parse(json);

    // Verify structure
    expect(Array.isArray(parsed.signals)).toBe(true);
    expect(Array.isArray(parsed.promotedKeys)).toBe(true);
    expect(typeof parsed.conflict).toBe("object");
    expect(typeof parsed.decisionFactors).toBe("object");
  });

  it("contains all promoted keys", () => {
    const result = makeResult({
      authentication_results: "spf=pass; dkim=fail; dmarc=pass",
      header_findings: [
        { id: "HDR-001", severity: "critical", title: "DKIM fehlgeschlagen", detail: "fail" },
      ],
    });
    const { summary, factors } = runPipeline(result);

    for (const key of factors.promotedKeys) {
      expect(summary.promotedKeys).toContain(key);
    }
  });

  it("conflict info matches assessConflict output", () => {
    const result = makeResult({
      authentication_results: "spf=pass; dkim=fail; dmarc=pass",
    });
    const { summary, conflict } = runPipeline(result);

    expect(summary.conflict.hasConflict).toBe(conflict.hasConflict);
    expect(summary.conflict.dominantSignalKey).toBe(conflict.dominantSignal?.key || null);
    expect(summary.conflict.explanation).toBe(conflict.explanation);
    expect(summary.conflict.bulkDowngradeApplied).toBe(conflict.bulkDowngradeApplied);
  });

  it("all signals have non-null sourceType", () => {
    const result = makeResult({
      authentication_results: "spf=pass; dkim=pass; dmarc=pass",
      header_findings: [
        { id: "HDR-001", severity: "info", title: "SPF bestanden", detail: "pass" },
      ],
      deterministic_findings: [
        { factor: "bulk_headers", impact: "", detail: "Bulk headers detected" },
      ],
      assessment: { classification: "legitimate", evidence: ["All auth passed."] },
    });
    const { summary } = runPipeline(result);

    for (const s of summary.signals) {
      expect(s.sourceType).toBeTruthy();
      expect(["auth_result", "header_finding", "det_finding", "link_analysis", "identity_derived", "llm_evidence", "bulk_detection"]).toContain(s.sourceType);
    }
  });
});

// ─── No regression: promotion / dedup ───────────────────────────────────────

describe("Promotion/dedup regression (consolidated)", () => {
  it("promoted keys from pipeline match evidence keys exactly", () => {
    const result = makeResult({
      header_findings: [
        { id: "HDR-001", severity: "info", title: "SPF bestanden", detail: "pass" },
        { id: "HDR-002", severity: "info", title: "DKIM bestanden", detail: "pass" },
      ],
    });
    const { factors, evidenceGroups } = runPipeline(result);
    const allItems = [...evidenceGroups.critical, ...evidenceGroups.noteworthy, ...evidenceGroups.positive, ...evidenceGroups.context];

    expect(factors.promotedKeys.has("auth:spf:pass")).toBe(true);
    expect(factors.promotedKeys.has("auth:dkim:pass")).toBe(true);

    const spfEvidence = allItems.find((i) => i.key === "auth:spf:pass");
    expect(spfEvidence).toBeDefined();
    expect(factors.promotedKeys.has(spfEvidence!.key)).toBe(true);
  });

  it("unmapped header findings are NOT promoted", () => {
    const result = makeResult({
      header_findings: [
        { id: "HDR-099", severity: "info", title: "Unbekannter Befund", detail: "details" },
      ],
    });
    const { factors, evidenceGroups } = runPipeline(result);
    const allItems = [...evidenceGroups.critical, ...evidenceGroups.noteworthy, ...evidenceGroups.positive, ...evidenceGroups.context];

    const item = allItems.find((i) => i.key === "header:HDR-099");
    expect(item).toBeDefined();
    expect(factors.promotedKeys.has("header:HDR-099")).toBe(false);
  });

  it("free-text evidence without mapping is not promoted", () => {
    const result = makeResult({
      assessment: {
        classification: "legitimate",
        evidence: ["Some unstructured analysis text."],
      },
    });
    const { factors, evidenceGroups } = runPipeline(result);
    const allItems = [...evidenceGroups.critical, ...evidenceGroups.noteworthy, ...evidenceGroups.positive, ...evidenceGroups.context];

    const item = allItems.find((i) => i.key === "evidence:0");
    expect(item).toBeDefined();
    expect(factors.promotedKeys.has("evidence:0")).toBe(false);
  });
});
