# MailScope — Email Security Analysis

Analysiert E-Mail-Dateien (.eml/.msg) auf Phishing, Spoofing und andere Sicherheitsrisiken.

## Features

- **File Upload**: Drag & Drop für .eml und .msg Dateien
- **Email Parsing**: Vollständiges Header- und Body-Parsing (Standard-Library + python-oxmsg)
- **Header-Analyse**: SPF/DKIM/DMARC, From/Reply-To/Return-Path Mismatches, Bulk-Header, Spam-Indikatoren
- **URL-Extraction & Normalisierung**: SafeLinks-Unwrapping, HTML-Entity-Decoding, UTM-Stripping, Redirect-Unwrapping
- **Link-Heuristiken**: IP-Literal, Punycode, Shortener, Display-Mismatch, verdächtige TLDs, Tracking-Erkennung
- **VirusTotal & urlscan.io**: URL-Reputationsprüfung mit async Polling
- **Deterministische Pre-Scoring**: Phishing/Advertising/Legitimacy Scores vor LLM
- **LLM-Assessment**: Strukturierte KI-Bewertung mit Guardrails und Fallback
- **Async Job Processing**: Background-Tasks mit Polling, kein Blocking beim Upload
- **Export**: Strukturierter JSON-Export der Analyseergebnisse
- **Privacy**: E-Mail-Adressen-Maskierung, keine externen Uploads von Volltext/Anhängen

## Schnellstart

### Mit Docker Compose

```bash
cp .env.example .env
# Optional: API-Keys eintragen
docker compose up --build
```

- Frontend: http://localhost:3000
- Backend: http://localhost:8000

### Manuell

**Backend:**

```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

**Frontend:**

```bash
cd frontend
npm install
npm run dev
```

## Konfiguration

Alle Einstellungen über Umgebungsvariablen (siehe `.env.example`):

| Variable | Default | Beschreibung |
|---|---|---|
| `OPENAI_API_KEY` | - | OpenAI API Key für LLM-Assessment |
| `VIRUSTOTAL_API_KEY` | - | VirusTotal API Key |
| `URLSCAN_API_KEY` | - | urlscan.io API Key |
| `ENABLE_VIRUSTOTAL` | `true` | VT-Prüfung aktivieren/deaktivieren |
| `ENABLE_URLSCAN` | `true` | urlscan-Prüfung aktivieren/deaktivieren |
| `ENABLE_LLM` | `true` | LLM-Bewertung aktivieren/deaktivieren |
| `URLSCAN_VISIBILITY` | `private` | Sichtbarkeit der urlscan-Submissions |
| `LLM_MODEL` | `gpt-4o` | OpenAI-Modell |
| `MAX_POLL_SECONDS` | `120` | Max. Wartezeit für externe Checks |
| `POLL_INTERVAL_SECONDS` | `5` | Polling-Intervall |

## Testen ohne externe Services

```bash
# Alle externen Services deaktivieren
ENABLE_VIRUSTOTAL=false ENABLE_URLSCAN=false ENABLE_LLM=false uvicorn app.main:app --reload

# Nur VT aktivieren
ENABLE_VIRUSTOTAL=true ENABLE_URLSCAN=false ENABLE_LLM=false VIRUSTOTAL_API_KEY=your_key uvicorn app.main:app --reload

# Nur LLM (deterministic + LLM, keine externen URL-Checks)
ENABLE_VIRUSTOTAL=false ENABLE_URLSCAN=false ENABLE_LLM=true OPENAI_API_KEY=your_key uvicorn app.main:app --reload
```

Bei deaktivierten Services: Parser + Header-Heuristiken + Link-Heuristiken + deterministisches Pre-Scoring laufen immer. Das Ergebnis enthält dann eine deterministische Bewertung statt LLM-Assessment.

## API

### `POST /api/upload`

Upload einer .eml/.msg Datei. Gibt Job-ID zurück.

```bash
curl -X POST http://localhost:8000/api/upload -F "file=@suspicious.eml"
```

### `GET /api/jobs/{job_id}`

Job-Status abfragen (queued, parsing, extracting_links, checking_reputation, llm_assessment, completed, completed_with_warnings, failed).

```bash
curl http://localhost:8000/api/jobs/{job_id}
```

### `GET /api/jobs/{job_id}/result`

Vollständiges Analyseergebnis.

```bash
curl http://localhost:8000/api/jobs/{job_id}/result
```

### `GET /api/jobs/{job_id}/export`

Strukturierter JSON-Export.

```bash
curl http://localhost:8000/api/jobs/{job_id}/export -o analysis.json
```

### `GET /api/health`

```bash
curl http://localhost:8000/api/health
```

## Datenschutz

- Nur extrahierte URLs werden an externe Services (VT, urlscan) gesendet
- Vollständige E-Mail-Inhalte und Anhänge werden **niemals** extern übertragen
- urlscan-Submissions sind standardmäßig `private`
- E-Mail-Adressen können in der UI maskiert werden
- Externe Services sind einzeln deaktivierbar

## Bekannte Einschränkungen

- .msg-Parsing über python-oxmsg deckt nicht alle .msg-Varianten ab
- Kein Attachment-Scanning (nur Metadaten)
- Keine persistente Datenbank über Container-Neustarts (SQLite im Container)
- Rate-Limiting für VT/urlscan muss vom API-Key-Kontingent abgedeckt werden

## Tech Stack

- **Backend:** Python 3.12, FastAPI, SQLAlchemy, Pydantic, httpx
- **Frontend:** Next.js 14, TypeScript, Tailwind CSS
- **Deployment:** Docker Compose
