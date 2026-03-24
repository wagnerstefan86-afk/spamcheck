# MailScope — Email Security Analysis

Analysiert E-Mail-Quelltexte auf Phishing, Spoofing und andere Sicherheitsrisiken.

## Features

- **SPF/DKIM/DMARC** Header-Validierung
- **URL-Scanning** auf Phishing-Muster (IP-basierte URLs, verdächtige TLDs, URL-Shortener, Homograph-Angriffe)
- **Absender-Analyse** (Freemail-Erkennung, Domain-Spoofing)
- **Risiko-Score** (0–100) mit gewichteter Berechnung
- **Input-Sanitization** gegen XSS/Injection

## Schnellstart

### Mit Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

- Frontend: http://localhost:3000
- Backend: http://localhost:8000

### Manuell

**Backend:**

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

**Frontend:**

```bash
cd frontend
npm install
npm run dev
```

## API

### `GET /api/health`

```json
{ "status": "ok", "service": "mailscope" }
```

### `POST /api/analyze`

**Request:**

```json
{
  "email_text": "From: sender@example.com\nSubject: Test\n\nHello World"
}
```

**Response:**

```json
{
  "risk_score": 40,
  "risk_level": "mittel",
  "summary": "Risiko-Bewertung: Mittel (40/100). 3 Warnung(en) erkannt.",
  "headers": {
    "spf": "not found",
    "spf_pass": false,
    "dkim": "not found",
    "dkim_pass": false,
    "dmarc": "not found",
    "dmarc_pass": false,
    "from_address": "sender@example.com",
    "return_path": "",
    "received_chain": []
  },
  "urls": [],
  "sender": {
    "address": "sender@example.com",
    "is_freemail": false,
    "domain": "example.com",
    "spoofing_indicators": []
  },
  "warnings": [
    "SPF-Prüfung nicht bestanden oder nicht vorhanden",
    "DKIM-Prüfung nicht bestanden oder nicht vorhanden",
    "DMARC-Prüfung nicht bestanden oder nicht vorhanden"
  ]
}
```

## Tech Stack

- **Backend:** Python 3.12, FastAPI, Pydantic
- **Frontend:** React 18, Vite, Axios
- **Deployment:** Docker Compose
