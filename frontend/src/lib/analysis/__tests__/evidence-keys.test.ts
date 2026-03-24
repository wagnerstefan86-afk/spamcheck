import { describe, it, expect } from "vitest";
import { normalizeSignals, toPrioritizedSignals, toEvidenceGroups } from "../normalize";
import { assessIdentity } from "../identity";
import { summarizeLinks } from "../links";
import { extractDecisionFactors } from "../decision";
import type { EvidenceItem, EvidenceGroups, PrioritizedSignal } from "../types";

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

function allItems(groups: EvidenceGroups): EvidenceItem[] {
  return [...groups.critical, ...groups.noteworthy, ...groups.positive, ...groups.context];
}

function analyze(result: any) {
  const identity = assessIdentity(result);
  const linkStats = summarizeLinks(result.links || []);
  const normalized = normalizeSignals(result, identity, linkStats, identity.isBulkSender);
  const signals = toPrioritizedSignals(normalized);
  const groups = toEvidenceGroups(normalized);
  const factors = extractDecisionFactors(signals);
  return { identity, signals, groups, factors };
}

// ─── Key Stability ──────────────────────────────────────────────────────────

describe("Evidence key assignment", () => {
  it("assigns auth signal keys to header findings about SPF pass", () => {
    const result = makeResult({
      header_findings: [
        { id: "HDR-001", severity: "info", title: "SPF bestanden", detail: "sender.example.com" },
      ],
    });
    const { groups } = analyze(result);
    const spfItem = allItems(groups).find((i) => i.key === "auth:spf:pass");
    expect(spfItem).toBeDefined();
    expect(spfItem!.source).toBe("header_finding");
  });

  it("assigns auth signal keys to header findings about DKIM fail", () => {
    const result = makeResult({
      authentication_results: "spf=pass; dkim=fail; dmarc=pass",
      header_findings: [
        { id: "HDR-002", severity: "critical", title: "DKIM fehlgeschlagen", detail: "Signatur ungültig" },
      ],
    });
    const { groups } = analyze(result);
    const dkimItem = allItems(groups).find((i) => i.key === "auth:dkim:fail");
    expect(dkimItem).toBeDefined();
    expect(dkimItem!.severity).toBe("critical");
  });

  it("assigns det factor key for deterministic findings", () => {
    const result = makeResult({
      deterministic_findings: [
        { factor: "vt_malicious", impact: "phishing+30", detail: "VirusTotal: 3 malicious" },
      ],
    });
    const { groups } = analyze(result);
    const vtItem = allItems(groups).find((i) => i.key === "links:malicious");
    expect(vtItem).toBeDefined();
  });

  it("assigns fallback key when no signal mapping exists", () => {
    const result = makeResult({
      header_findings: [
        { id: "HDR-099", severity: "info", title: "Unbekannter Befund", detail: "irgendwas" },
      ],
    });
    const { groups } = analyze(result);
    const item = allItems(groups).find((i) => i.key === "header:HDR-099");
    expect(item).toBeDefined();
    expect(item!.text).toContain("Unbekannter Befund");
  });

  it("assigns index-based key for evidence strings without signal mapping", () => {
    const result = makeResult({
      assessment: {
        classification: "legitimate",
        evidence: ["Die E-Mail enthält allgemeine Informationen."],
      },
    });
    const { groups } = analyze(result);
    const item = allItems(groups).find((i) => i.key === "evidence:0");
    expect(item).toBeDefined();
  });
});

// ─── Promotion / Dedup ──────────────────────────────────────────────────────

describe("Promotion and dedup via keys", () => {
  it("promoted signal key matches evidence item key exactly", () => {
    const result = makeResult({
      header_findings: [
        { id: "HDR-001", severity: "info", title: "SPF bestanden", detail: "pass" },
        { id: "HDR-002", severity: "info", title: "DKIM bestanden", detail: "pass" },
      ],
    });
    const { signals, factors, groups } = analyze(result);

    const spfSignal = signals.find((s: PrioritizedSignal) => s.key === "auth:spf:pass");
    expect(spfSignal).toBeDefined();
    expect(factors.promotedKeys.has("auth:spf:pass")).toBe(true);

    const spfEvidence = allItems(groups).find((i) => i.key === "auth:spf:pass");
    expect(spfEvidence).toBeDefined();
    expect(factors.promotedKeys.has(spfEvidence!.key)).toBe(true);
  });

  it("similar but non-identical text does NOT cause false match", () => {
    const result = makeResult({
      header_findings: [
        { id: "HDR-010", severity: "warning", title: "SPF-Header-Analyse", detail: "Detailbericht" },
      ],
    });
    const { factors, groups } = analyze(result);
    const item = allItems(groups).find((i) => i.text.includes("SPF-Header-Analyse"));
    expect(item).toBeDefined();
    expect(item!.key).toBe("header:HDR-010");
    expect(factors.promotedKeys.has(item!.key)).toBe(false);
  });

  it("non-promoted evidence stays fully visible", () => {
    const result = makeResult({
      header_findings: [
        { id: "HDR-020", severity: "warning", title: "Lange Received-Kette", detail: "8 Hops" },
      ],
    });
    const { factors, groups } = analyze(result);
    const item = allItems(groups).find((i) => i.text.includes("Received-Kette"));
    expect(item).toBeDefined();
    expect(item!.severity).toBe("context");
    expect(factors.promotedKeys.has(item!.key)).toBe(false);
  });
});

// ─── Signal Key Stability ───────────────────────────────────────────────────

describe("PrioritizedSignal keys (via normalized pipeline)", () => {
  it("auth signals have deterministic keys", () => {
    const result = makeResult({ authentication_results: "spf=pass; dkim=fail; dmarc=none" });
    const { signals } = analyze(result);
    expect(signals.find((s: PrioritizedSignal) => s.key === "auth:spf:pass")).toBeDefined();
    expect(signals.find((s: PrioritizedSignal) => s.key === "auth:dkim:fail")).toBeDefined();
    expect(signals.find((s: PrioritizedSignal) => s.key === "auth:dmarc:none")).toBeDefined();
  });

  it("identity consistency signal has deterministic key", () => {
    const result = makeResult({
      sender: { from_address: "user@example.com", reply_to: "user@other.com", return_path: null, to: null, date: null, message_id: null },
    });
    const { signals } = analyze(result);
    expect(signals.find((s: PrioritizedSignal) => s.key === "identity:mismatch")).toBeDefined();
  });

  it("link signals have deterministic keys", () => {
    const result = makeResult({
      links: [{
        id: 1, normalized_url: "http://evil.com", hostname: "evil.com",
        is_ip_literal: false, is_punycode: true, has_display_mismatch: false,
        is_suspicious_tld: false, is_shortener: false, is_tracking_heavy: false,
        is_safelink: false, external_checks: [],
      }],
    });
    const { signals } = analyze(result);
    expect(signals.find((s: PrioritizedSignal) => s.key === "links:structural")).toBeDefined();
  });

  it("bulk detection signal has deterministic key", () => {
    const result = makeResult({
      structured_headers: { "list-unsubscribe": "<mailto:unsub@example.com>" },
    });
    const { signals } = analyze(result);
    expect(signals.find((s: PrioritizedSignal) => s.key === "bulk:detected")).toBeDefined();
  });
});

// ─── Promotion visibility rules ─────────────────────────────────────────────

describe("Promoted item visibility rules", () => {
  it("critical promoted items appear as dimmed (not hidden)", () => {
    const result = makeResult({
      authentication_results: "spf=fail; dkim=pass; dmarc=pass",
      header_findings: [
        { id: "HDR-003", severity: "critical", title: "SPF fehlgeschlagen", detail: "hardfail" },
      ],
    });
    const { factors, groups } = analyze(result);
    const criticalItem = groups.critical.find((i) => i.key === "auth:spf:fail");
    expect(criticalItem).toBeDefined();
    expect(factors.promotedKeys.has("auth:spf:fail")).toBe(true);
  });

  it("non-critical promoted items are excluded by key match", () => {
    const result = makeResult({
      header_findings: [
        { id: "HDR-001", severity: "info", title: "SPF bestanden", detail: "pass" },
      ],
    });
    const { factors, groups } = analyze(result);
    const positiveItem = groups.positive.find((i) => i.key === "auth:spf:pass");
    expect(positiveItem).toBeDefined();
    expect(factors.promotedKeys.has("auth:spf:pass")).toBe(true);
  });
});
