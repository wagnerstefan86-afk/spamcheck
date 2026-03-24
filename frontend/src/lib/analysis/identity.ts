/**
 * Identity and authentication assessment.
 *
 * Extracts domains, parses auth results, evaluates consistency.
 */

import type { AuthSignal, IdentityAssessment } from "./types";

export function extractDomain(email: string | null | undefined): string | null {
  if (!email) return null;
  const match = email.match(/@([a-zA-Z0-9.-]+)/);
  return match ? match[1].toLowerCase() : null;
}

function normalizeAuthStatus(raw: string): AuthSignal["status"] {
  const s = raw.toLowerCase();
  if (s === "pass") return "pass";
  if (s === "fail" || s === "hardfail") return "fail";
  if (s === "softfail") return "softfail";
  if (s === "none") return "none";
  if (s === "neutral") return "neutral";
  return "unknown";
}

export function parseAuthResults(authResults: string | null): AuthSignal[] {
  if (!authResults) return [];
  const signals: AuthSignal[] = [];
  const spf = authResults.match(/spf\s*=\s*(\w+)/i);
  if (spf) signals.push({ protocol: "SPF", status: normalizeAuthStatus(spf[1]) });
  const dkim = authResults.match(/dkim\s*=\s*(\w+)/i);
  if (dkim) signals.push({ protocol: "DKIM", status: normalizeAuthStatus(dkim[1]) });
  const dmarc = authResults.match(/dmarc\s*=\s*(\w+)/i);
  if (dmarc) signals.push({ protocol: "DMARC", status: normalizeAuthStatus(dmarc[1]) });
  return signals;
}

/**
 * Detect whether this is a bulk/marketing mail.
 * Used as input for priority logic, NOT as sole basis for downgrade.
 */
export function detectBulkMail(result: any): boolean {
  const findings: any[] = result.header_findings || [];
  for (const f of findings) {
    if (/massen|marketing|bulk/i.test(f.title)) return true;
    if (/list.?unsubscribe/i.test(f.title) || /list.?unsubscribe/i.test(f.detail || "")) return true;
  }
  const headers = result.structured_headers || {};
  if (headers["list-unsubscribe"] || headers["List-Unsubscribe"]) return true;
  if (headers["precedence"] === "bulk" || headers["Precedence"] === "bulk") return true;
  if (result.assessment?.classification === "advertising") return true;
  return false;
}

export function assessIdentity(result: any): IdentityAssessment {
  const fromDomain = extractDomain(result.sender?.from_address);
  const replyToDomain = extractDomain(result.sender?.reply_to);
  const returnPathDomain = extractDomain(result.sender?.return_path);
  const authSignals = parseAuthResults(result.authentication_results);
  const isBulk = detectBulkMail(result);

  let consistency: IdentityAssessment["consistency"] = "consistent";
  let consistencyDetail = "Alle Absender-Domains stimmen überein.";
  const domains = [fromDomain, replyToDomain, returnPathDomain].filter(Boolean) as string[];
  const uniqueDomains = Array.from(new Set(domains));

  if (uniqueDomains.length > 1) {
    // Domain mismatch: evaluate in context (priority logic handles downgrade guard)
    const hasAuthFailure = authSignals.some((s) => s.status === "fail");
    if (hasAuthFailure) {
      consistency = "suspicious";
      consistencyDetail = "Abweichende Domains bei fehlgeschlagener Authentifizierung.";
    } else if (isBulk) {
      consistency = "partial_mismatch";
      consistencyDetail = "Abweichende Domains — typisch für Mailing-Dienste.";
    } else {
      consistency = "partial_mismatch";
      consistencyDetail = "Abweichende Domains — manuelle Prüfung empfohlen.";
    }
  } else if (domains.length === 0) {
    consistency = "partial_mismatch";
    consistencyDetail = "Keine Absender-Domain extrahierbar.";
  }

  return {
    fromDomain,
    replyToDomain,
    returnPathDomain,
    authSignals,
    consistency,
    consistencyDetail,
    isBulkSender: isBulk,
  };
}
