# Architektur: E-Mail-Sicherheitsanalyse-Service

## Zielarchitektur

Das System wird von einer eigenstaendigen Webanwendung zu einem **technischen Analyse-Service** umgebaut, der primaer als Tool fuer einen Microsoft Copilot Studio Agent in Teams dient.

```
┌─────────────┐    ┌───────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│  Benutzer    │    │  Copilot Studio   │    │  REST/OpenAPI    │    │  Analyse-Backend    │
│  in Teams    │───>│  Agent (LLM)      │───>│  Tool-Connector  │───>│  (deterministisch)  │
│              │<───│  formuliert       │<───│                  │<───│                     │
│              │    │  Antworten        │    │                  │    │  analysis_summary   │
└─────────────┘    └───────────────────┘    └──────────────────┘    └─────────────────────┘
                          │                                                   │
                    Einziges LLM                                   Strukturiertes Ergebnis
                    im System                                      (kein LLM intern)
```

## Rolle des Backends

Das Backend ist die **einzige Quelle der Wahrheit** fuer die E-Mail-Sicherheitsanalyse.

**Eingabe:** `.eml`- oder `.msg`-Dateien per Upload.

**Deterministische Analyse-Pipeline:**
1. E-Mail-Parsing (Header, Body, Anhaenge)
2. Header-Analyse (SPF, DKIM, DMARC, Routing)
3. Link-Extraktion und Normalisierung
4. Reputationspruefungen (VirusTotal, urlscan.io)
5. Pre-Scoring und Signalaggregation
6. Decision Engine (regelbasierte Entscheidung)

**Ausgabe:** Ein strukturiertes `analysis_summary`-Objekt als zentrales Ergebnis.

Kein internes LLM. Alle Intelligenz basiert auf deterministischen Regeln.

## Rolle von Copilot Studio (Zielzustand)

- Empfaengt das strukturierte Analyseergebnis via REST-Connector
- Formuliert natuerlichsprachliche Antworten fuer den Endbenutzer
- Steuert den Gespraechsverlauf und die Benutzerinteraktion
- Ist das **einzige LLM** im Gesamtsystem

## API-Endpunkte

| Endpunkt | Methode | Beschreibung |
|---|---|---|
| `/api/upload` | POST | `.eml`/`.msg`-Datei einreichen, gibt Job-ID zurueck |
| `/api/jobs/{id}` | GET | Job-Status abfragen (pending, processing, done, error) |
| `/api/jobs/{id}/result` | GET | Vollstaendiges Analyseergebnis (Legacy, UI-orientiert) |
| `/api/jobs/{id}/summary` | GET | Copilot-optimierte strukturierte Zusammenfassung |
| `/api/jobs/{id}/trace` | GET | Interner Pipeline-Trace (nur fuer Analysten/Debugging) |
| `/api/health` | GET | Service-Health-Check |

**Primaerer Copilot-Endpunkt:** `/api/jobs/{id}/summary` liefert das `analysis_summary`-Objekt direkt.

## analysis_summary — Zentrales Ergebnisobjekt

Das `analysis_summary` ist der **primaere Datenvertrag** mit Copilot Studio.

```json
{
  "version": 2,
  "action_decision": {
    "action": "do_not_open",
    "label": "Nicht öffnen",
    "reason": "Die E-Mail zeigt starke Hinweise auf Phishing.",
    "primary_driver": "content:credential_lure"
  },
  "action_label": "Nicht öffnen",
  "action_reason": "Die E-Mail zeigt starke Hinweise auf Phishing.",
  "classification": "phishing",
  "risk_score": 85,
  "confidence": 80,
  "content_risk_level": "high",
  "decision_factors": {
    "negative": [{"key": "auth:spf:fail", "label": "SPF fehlgeschlagen", "tier": 5}],
    "positive": []
  },
  "identity_summary": {
    "from_domain": "example.com",
    "consistency": "suspicious",
    "is_bulk_sender": false,
    "auth_spf": "fail", "auth_dkim": "none", "auth_dmarc": "fail"
  },
  "reputation_summary": {
    "total_links": 2, "malicious": 1, "suspicious": 0, "clean": 0,
    "coverage": "partially_analyzed", "coverage_percent": 50
  },
  "signals": [
    {"key": "auth:spf:fail", "label": "SPF fehlgeschlagen", "severity": "critical",
     "tier": 5, "direction": "negative", "domain": "auth", "category": "authentication"}
  ],
  "escalation_hint": "Weiterleitung an IT-Sicherheit empfohlen.",
  "override_applied": true
}
```

Alle Felder sind JSON-safe und selbstbeschreibend. Die `signals`-Liste enthaelt normalisierte Signale mit Severity-Tiers (1-5). `action_decision.action` hat drei Stufen: `open`, `manual_review`, `do_not_open`. Der `escalation_hint` ist ein optionaler Hinweis fuer den Copilot-Agenten zur Weiterleitung.

## LLM-Richtlinie

- **Kein internes LLM.** Die Analyse ist vollstaendig deterministisch.
- Ein Legacy-LLM-Pfad existiert im Code, ist aber standardmaessig deaktiviert (`enable_llm=False`).
- In der Zielarchitektur stellt **ausschliesslich Copilot Studio** LLM-Faehigkeiten bereit.
- Das Backend liefert strukturierte Daten; Copilot formuliert daraus natuerlichsprachliche Antworten.

## Standalone-Fallback

Die bestehende Web-UI funktioniert weiterhin fuer eigenstaendige Nutzung:

```
┌────────────┐     ┌─────────────────────┐
│  Web-UI    │────>│  Analyse-Backend    │
│  (Browser) │<────│  /api/jobs/{id}/    │
└────────────┘     │  result             │
                   └─────────────────────┘
```

Das Backend bedient sowohl die Web-UI (`/result`) als auch den Copilot-Connector (`/summary`). Beide Wege nutzen dieselbe Analyse-Pipeline.

## Datenaufbewahrung

- Jobs haben eine **konfigurierbare TTL** (Time-to-Live).
- Trace-Daten und Roh-Header sind nur fuer internen/Analysten-Gebrauch bestimmt.
- Das `analysis_summary` ist der primaere Datenvertrag mit externen Konsumenten.
- Sensible E-Mail-Inhalte werden nach Ablauf der TTL automatisch bereinigt.
