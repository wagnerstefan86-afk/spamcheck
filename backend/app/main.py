from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .analyzer import analyze_email
from .models import AnalysisResult, EmailInput

app = FastAPI(
    title="MailScope Email Security Analysis",
    version="1.0.0",
    description="Analysiert E-Mails auf Phishing, Spoofing und andere Sicherheitsrisiken.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "mailscope"}


@app.post("/api/analyze", response_model=AnalysisResult)
async def analyze(email_input: EmailInput):
    return analyze_email(email_input.email_text)
