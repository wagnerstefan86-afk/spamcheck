/**
 * Content risk signal detection.
 *
 * Extracts phishing-indicative signals from subject, body preview,
 * and LLM evidence without requiring LLM processing.
 *
 * These signals are used for:
 * - Auth reweighting (auth pass is less valuable when content is risky)
 * - Decision overrides (phishing content should not be classified as "allow")
 * - UI display (risk factors in decision panel)
 */

export type ContentRiskType =
  | "account_threat"    // "Konto gesperrt", "account suspended"
  | "urgent_action"     // "jetzt handeln", "sofort bestätigen"
  | "credential_lure"   // "Passwort erneuern", "Login bestätigen"
  | "payment_lure"      // "Zahlung fehlgeschlagen", "Rechnung"
  | "generic_branding"  // generic "Sehr geehrter Kunde" without real identity
  | "deletion_threat";  // "Ihre Daten werden gelöscht"

export type ContentRiskMatch = {
  type: ContentRiskType;
  /** Which text field matched */
  source: "subject" | "body" | "evidence";
  /** The matched pattern (for debugging) */
  matchedText: string;
};

// ─── Pattern Tables ─────────────────────────────────────────────────────────
// Each pattern is bilingual (DE/EN) and designed for low false-positive rates.
// Patterns require compound matches — single common words are excluded.

const CONTENT_RISK_PATTERNS: Array<{ type: ContentRiskType; pattern: RegExp }> = [
  // Account threats
  { type: "account_threat", pattern: /konto.{0,20}(gesperrt|deaktiviert|eingeschränkt|suspendiert|geschlossen)/i },
  { type: "account_threat", pattern: /account.{0,20}(suspended|locked|disabled|restricted|closed|terminated)/i },
  { type: "account_threat", pattern: /(sperrung|deaktivierung|einschränkung).{0,20}(ihres?|your).{0,20}(konto|account)/i },

  // Urgent action demands
  { type: "urgent_action", pattern: /(sofort|umgehend|dringend|innerhalb von \d+).{0,30}(handeln|bestätigen|reagieren|erneuern|verifizieren|aktualisieren)/i },
  { type: "urgent_action", pattern: /(immediate|urgent|within \d+).{0,30}(action|verify|confirm|renew|update|respond)/i },
  { type: "urgent_action", pattern: /letzte (mahnung|warnung|aufforderung|erinnerung)/i },
  { type: "urgent_action", pattern: /(final|last) (warning|notice|reminder)/i },

  // Credential lures
  { type: "credential_lure", pattern: /(passwort|kennwort|password).{0,20}(abgelaufen|erneuern|bestätigen|zurücksetzen|ändern|expired|renew|confirm|reset)/i },
  { type: "credential_lure", pattern: /(login|anmeldung|identität|identity).{0,20}(bestätigen|verifizieren|confirm|verify)/i },
  { type: "credential_lure", pattern: /klicken sie.{0,30}(bestätigen|verifizieren|einloggen|anmelden)/i },
  { type: "credential_lure", pattern: /click.{0,30}(verify|confirm|sign.?in|log.?in)/i },

  // Payment lures
  { type: "payment_lure", pattern: /(zahlung|payment|transaktion|transaction).{0,20}(fehlgeschlagen|abgelehnt|ausstehend|failed|declined|pending)/i },
  { type: "payment_lure", pattern: /(rechnung|invoice|abbuchung).{0,20}(überfällig|offen|unbezahlt|overdue|outstanding)/i },

  // Deletion threats
  { type: "deletion_threat", pattern: /(daten|fotos|dateien|files|photos|videos|account).{0,30}(gelöscht|werden gelöscht|permanently deleted|will be deleted)/i },
  { type: "deletion_threat", pattern: /(löschung|deletion).{0,20}(ihrer|your|aller)/i },

  // Generic branding (weak individual — needs combination with other signals)
  { type: "generic_branding", pattern: /sehr geehrte[rs]? (kunde|kundin|nutzer|nutzerin|mitglied|user)/i },
  { type: "generic_branding", pattern: /dear (customer|user|member|valued|account holder)/i },
];

// ─── Detection ──────────────────────────────────────────────────────────────

/**
 * Scans subject, body preview, and LLM evidence for phishing-indicative content.
 * Returns all matched risk signals.
 */
export function detectContentRisks(result: any): ContentRiskMatch[] {
  const matches: ContentRiskMatch[] = [];
  const seen = new Set<ContentRiskType>();

  const subject: string = result.sender?.subject || result.subject || "";
  const bodyPreview: string = result.body_preview || result.body_text?.substring(0, 500) || "";
  const evidence: string[] = result.assessment?.evidence || [];

  // Scan subject
  for (const { type, pattern } of CONTENT_RISK_PATTERNS) {
    if (!seen.has(type) && pattern.test(subject)) {
      matches.push({ type, source: "subject", matchedText: subject.substring(0, 100) });
      seen.add(type);
    }
  }

  // Scan body preview
  if (bodyPreview) {
    for (const { type, pattern } of CONTENT_RISK_PATTERNS) {
      if (!seen.has(type) && pattern.test(bodyPreview)) {
        matches.push({ type, source: "body", matchedText: bodyPreview.substring(0, 100) });
        seen.add(type);
      }
    }
  }

  // Scan LLM evidence (often contains useful summaries)
  for (const e of evidence) {
    for (const { type, pattern } of CONTENT_RISK_PATTERNS) {
      if (!seen.has(type) && pattern.test(e)) {
        matches.push({ type, source: "evidence", matchedText: e.substring(0, 100) });
        seen.add(type);
      }
    }
  }

  // Also check LLM classification as phishing
  const classification = result.assessment?.classification;
  if (classification === "phishing" || classification === "scam") {
    if (!seen.has("credential_lure")) {
      matches.push({ type: "credential_lure", source: "evidence", matchedText: `classification: ${classification}` });
    }
  }

  return matches;
}

/**
 * Determines the overall content risk level from individual matches.
 * Returns "high" if strong phishing indicators are present.
 */
export function assessContentRiskLevel(matches: ContentRiskMatch[]): "none" | "low" | "high" {
  if (matches.length === 0) return "none";

  const types = new Set(matches.map((m) => m.type));
  const strongTypes: ContentRiskType[] = ["account_threat", "credential_lure", "payment_lure", "deletion_threat"];
  const hasStrong = strongTypes.some((t) => types.has(t));
  const hasUrgent = types.has("urgent_action");

  // High risk: any strong signal + urgency, or 2+ strong signals
  if (hasStrong && hasUrgent) return "high";
  if (strongTypes.filter((t) => types.has(t)).length >= 2) return "high";
  // Single strong signal is still high (account_threat alone is bad enough)
  if (hasStrong) return "high";

  return "low";
}
