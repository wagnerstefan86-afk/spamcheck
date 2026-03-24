import { describe, it, expect } from "vitest";
import { normalizeSignals, toPrioritizedSignals, toEvidenceGroups, deriveCanonicalKey } from "../normalize";
import { assessIdentity } from "../identity";
import { summarizeLinks } from "../links";
import { extractDecisionFactors, buildAnalysisSummary, analyzeResult } from "../decision";
import { assessConflict } from "../priority";

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

// ─── Canonical Key ──────────────────────────────────────────────────────────

describe("deriveCanonicalKey", () => {
  it("strips status qualifier from auth keys", () => {
    expect(deriveCanonicalKey("auth:spf:pass")).toBe("auth:spf");
    expect(deriveCanonicalKey("auth:dkim:fail")).toBe("auth:dkim");
    expect(deriveCanonicalKey("auth:dmarc:none")).toBe("auth:dmarc");
  });

  it("strips count from link keys", () => {
    expect(deriveCanonicalKey("links:malicious:3")).toBe("links:malicious");
    expect(deriveCanonicalKey("links:suspicious:1")).toBe("links:suspicious");
  });

  it("preserves keys without qualifiers", () => {
    expect(deriveCanonicalKey("identity:mismatch")).toBe("identity:mismatch");
    expect(deriveCanonicalKey("bulk:detected")).toBe("bulk:detected");
    expect(deriveCanonicalKey("links:clean")).toBe("links:clean");
    expect(deriveCanonicalKey("links:structural")).toBe("links:structural");
  });

  it("preserves header fallback keys", () => {
    expect(deriveCanonicalKey("header:HDR-001")).toBe("header:HDR-001");
  });
});

// ─── NormalizedSignal production ────────────────────────────────────────────

describe("normalizeSignals", () => {
  it("produces signals from auth results with source references", () => {
    const result = makeResult({ authentication_results: "spf=pass; dkim=fail; dmarc=none" });
    const identity = assessIdentity(result);
    const linkStats = summarizeLinks(result.links);
    const signals = normalizeSignals(result, identity, linkStats, false);

    const spf = signals.find((s) => s.key === "auth:spf:pass");
    expect(spf).toBeDefined();
    expect(spf!.sourceType).toBe("auth_result");
    expect(spf!.sourceRef).toBe("auth:spf");
    expect(spf!.canonicalKey).toBe("auth:spf");
    expect(spf!.promotable).toBe(true);
    expect(spf!.direction).toBe("positive");

    const dkim = signals.find((s) => s.key === "auth:dkim:fail");
    expect(dkim).toBeDefined();
    expect(dkim!.sourceType).toBe("auth_result");
    expect(dkim!.tier).toBe(5);
    expect(dkim!.direction).toBe("negative");
  });

  it("produces identity signal with source type", () => {
    const result = makeResult({
      sender: { from_address: "a@x.com", reply_to: "b@y.com", return_path: null, to: null, date: null, message_id: null },
    });
    const identity = assessIdentity(result);
    const linkStats = summarizeLinks(result.links);
    const signals = normalizeSignals(result, identity, linkStats, false);

    const id = signals.find((s) => s.key === "identity:mismatch");
    expect(id).toBeDefined();
    expect(id!.sourceType).toBe("identity_derived");
    expect(id!.category).toBe("identity_consistency");
    expect(id!.downgradeEligible).toBe(true);
  });

  it("produces header finding signals with source ref", () => {
    const result = makeResult({
      header_findings: [
        { id: "HDR-005", severity: "critical", title: "SPF fehlgeschlagen", detail: "hardfail for domain.com" },
      ],
    });
    const identity = assessIdentity(result);
    const linkStats = summarizeLinks(result.links);
    const signals = normalizeSignals(result, identity, linkStats, false);

    const hdr = signals.find((s) => s.key === "auth:spf:fail" && s.sourceType === "header_finding");
    expect(hdr).toBeDefined();
    expect(hdr!.sourceRef).toBe("HDR-005");
    expect(hdr!.evidenceText).toContain("SPF fehlgeschlagen");
  });

  it("produces deterministic finding signals with factor as sourceRef", () => {
    const result = makeResult({
      deterministic_findings: [
        { factor: "vt_malicious", impact: "phishing+30", detail: "VirusTotal: 3 engines flagged" },
      ],
    });
    const identity = assessIdentity(result);
    const linkStats = summarizeLinks(result.links);
    const signals = normalizeSignals(result, identity, linkStats, false);

    const vt = signals.find((s) => s.key === "links:malicious" && s.sourceType === "det_finding");
    expect(vt).toBeDefined();
    expect(vt!.sourceRef).toBe("vt_malicious");
    expect(vt!.category).toBe("link_reputation");
  });

  it("produces LLM evidence signals with evidence index as sourceRef", () => {
    const result = makeResult({
      assessment: {
        classification: "legitimate",
        evidence: ["SPF bestanden für domain.com", "Unbekannte Analyse"],
      },
    });
    const identity = assessIdentity(result);
    const linkStats = summarizeLinks(result.links);
    const signals = normalizeSignals(result, identity, linkStats, false);

    const mapped = signals.find((s) => s.key === "auth:spf:pass" && s.sourceType === "llm_evidence");
    expect(mapped).toBeDefined();
    expect(mapped!.sourceRef).toBe("evidence:0");

    const unmapped = signals.find((s) => s.key === "evidence:1");
    expect(unmapped).toBeDefined();
    expect(unmapped!.sourceRef).toBe("evidence:1");
    expect(unmapped!.promotable).toBe(false);
  });

  it("marks bulk context signals correctly", () => {
    const result = makeResult({
      structured_headers: { "list-unsubscribe": "<mailto:unsub@x.com>" },
    });
    const identity = assessIdentity(result);
    const linkStats = summarizeLinks(result.links);
    const signals = normalizeSignals(result, identity, linkStats, true);

    const bulk = signals.find((s) => s.key === "bulk:detected");
    expect(bulk).toBeDefined();
    expect(bulk!.sourceType).toBe("bulk_detection");
    expect(bulk!.category).toBe("bulk_context");
  });

  it("sets downgradeEligible only for soft-critical signals", () => {
    const result = makeResult({
      header_findings: [
        { id: "HDR-010", severity: "critical", title: "From / Reply-To Mismatch", detail: "different domains" },
        { id: "HDR-011", severity: "critical", title: "SPF fehlgeschlagen", detail: "fail" },
      ],
    });
    const identity = assessIdentity(result);
    const linkStats = summarizeLinks(result.links);
    const signals = normalizeSignals(result, identity, linkStats, false);

    const mismatch = signals.find((s) => s.sourceRef === "HDR-010");
    expect(mismatch).toBeDefined();
    expect(mismatch!.downgradeEligible).toBe(true);

    const spfFail = signals.find((s) => s.sourceRef === "HDR-011");
    expect(spfFail).toBeDefined();
    expect(spfFail!.downgradeEligible).toBe(false);
  });
});

// ─── Projection: PrioritizedSignals ─────────────────────────────────────────

describe("toPrioritizedSignals", () => {
  it("only includes promotable signals", () => {
    const result = makeResult({
      assessment: { classification: "legitimate", evidence: ["Unbekannter Text"] },
    });
    const identity = assessIdentity(result);
    const linkStats = summarizeLinks(result.links);
    const normalized = normalizeSignals(result, identity, linkStats, false);
    const prioritized = toPrioritizedSignals(normalized);

    expect(prioritized.find((s) => s.key === "evidence:0")).toBeUndefined();
    expect(prioritized.find((s) => s.key === "auth:spf:pass")).toBeDefined();
  });

  it("deduplicates by key", () => {
    const result = makeResult({
      authentication_results: "spf=pass",
      assessment: { classification: "legitimate", evidence: ["SPF bestanden"] },
    });
    const identity = assessIdentity(result);
    const linkStats = summarizeLinks(result.links);
    const normalized = normalizeSignals(result, identity, linkStats, false);
    const prioritized = toPrioritizedSignals(normalized);

    const spfSignals = prioritized.filter((s) => s.key === "auth:spf:pass");
    expect(spfSignals.length).toBe(1);
  });
});

// ─── Projection: EvidenceGroups ─────────────────────────────────────────────

describe("toEvidenceGroups", () => {
  it("only includes signals with evidenceText", () => {
    const result = makeResult({
      header_findings: [
        { id: "HDR-001", severity: "info", title: "SPF bestanden", detail: "pass" },
      ],
    });
    const identity = assessIdentity(result);
    const linkStats = summarizeLinks(result.links);
    const normalized = normalizeSignals(result, identity, linkStats, false);
    const groups = toEvidenceGroups(normalized);

    const all = [...groups.critical, ...groups.noteworthy, ...groups.positive, ...groups.context];
    expect(all.find((i) => i.key === "auth:spf:pass")).toBeDefined();
  });
});

// ─── AnalysisSummary via analyzeResult ──────────────────────────────────────

describe("buildAnalysisSummary (via analyzeResult)", () => {
  it("produces a serializable summary with all fields", () => {
    const result = makeResult({
      authentication_results: "spf=pass; dkim=pass; dmarc=pass",
      header_findings: [
        { id: "HDR-001", severity: "info", title: "SPF bestanden", detail: "pass" },
      ],
    });
    const { summary } = analyzeResult(result);

    const json = JSON.stringify(summary);
    expect(json).toBeDefined();
    const parsed = JSON.parse(json);

    expect(parsed.version).toBe(1);
    expect(parsed.signals.length).toBeGreaterThan(0);
    expect(parsed.decisionFactors.positive.length).toBeGreaterThan(0);
    expect(Array.isArray(parsed.promotedKeys)).toBe(true);
    expect(typeof parsed.conflict.hasConflict).toBe("boolean");

    const spfSignal = parsed.signals.find((s: any) => s.key === "auth:spf:pass" && s.sourceType === "auth_result");
    expect(spfSignal).toBeDefined();
    expect(spfSignal.sourceRef).toBe("auth:spf");
    expect(spfSignal.canonicalKey).toBe("auth:spf");
  });

  it("includes downgradeEligible flag in summary", () => {
    const result = makeResult({
      sender: { from_address: "a@x.com", reply_to: "b@y.com", return_path: null, to: null, date: null, message_id: null },
    });
    const { summary } = analyzeResult(result);
    const mismatch = summary.signals.find((s) => s.key === "identity:mismatch");
    expect(mismatch).toBeDefined();
    expect(mismatch!.downgradeEligible).toBe(true);
  });

  it("includes classification and analystSummary", () => {
    const result = makeResult({
      assessment: { classification: "phishing", analyst_summary: "Clearly malicious.", evidence: [] },
    });
    const { summary } = analyzeResult(result);
    expect(summary.classification).toBe("phishing");
    expect(summary.analystSummary).toBe("Clearly malicious.");
  });
});

// ─── Canonical key dedup grouping ───────────────────────────────────────────

describe("Canonical key grouping", () => {
  it("groups auth:spf:pass and auth:spf:fail under auth:spf", () => {
    const result = makeResult({
      authentication_results: "spf=fail",
      header_findings: [
        { id: "HDR-001", severity: "critical", title: "SPF fehlgeschlagen", detail: "fail" },
      ],
      assessment: { classification: "suspicious", evidence: ["SPF fehlgeschlagen"] },
    });
    const identity = assessIdentity(result);
    const linkStats = summarizeLinks(result.links);
    const normalized = normalizeSignals(result, identity, linkStats, false);

    const spfSignals = normalized.filter((s) => s.canonicalKey === "auth:spf");
    expect(spfSignals.length).toBeGreaterThanOrEqual(2);
    const canonicals = new Set(spfSignals.map((s) => s.canonicalKey));
    expect(canonicals.size).toBe(1);
  });
});

// ─── No regression: promotion still works ───────────────────────────────────

describe("Promotion/dedup regression", () => {
  it("promoted keys from normalized pipeline match evidence keys", () => {
    const result = makeResult({
      header_findings: [
        { id: "HDR-001", severity: "info", title: "SPF bestanden", detail: "pass" },
        { id: "HDR-002", severity: "info", title: "DKIM bestanden", detail: "pass" },
      ],
    });
    const { decisionFactors, evidenceGroups } = analyzeResult(result);

    expect(decisionFactors.promotedKeys.has("auth:spf:pass")).toBe(true);
    expect(decisionFactors.promotedKeys.has("auth:dkim:pass")).toBe(true);

    const allItems = [...evidenceGroups.critical, ...evidenceGroups.noteworthy, ...evidenceGroups.positive, ...evidenceGroups.context];
    const spfEvidence = allItems.find((i) => i.key === "auth:spf:pass");
    expect(spfEvidence).toBeDefined();
    expect(decisionFactors.promotedKeys.has(spfEvidence!.key)).toBe(true);
  });
});
