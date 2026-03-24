from pydantic import BaseModel, Field, field_validator
from typing import Optional
import html


class EmailInput(BaseModel):
    email_text: str = Field(..., min_length=1, max_length=50000)

    @field_validator("email_text")
    @classmethod
    def sanitize_input(cls, v: str) -> str:
        return html.escape(v.strip())


class HeaderAnalysis(BaseModel):
    spf: str = "not found"
    spf_pass: bool = False
    dkim: str = "not found"
    dkim_pass: bool = False
    dmarc: str = "not found"
    dmarc_pass: bool = False
    from_address: str = ""
    return_path: str = ""
    received_chain: list[str] = []


class UrlAnalysis(BaseModel):
    url: str
    is_suspicious: bool = False
    reasons: list[str] = []


class SenderAnalysis(BaseModel):
    address: str = ""
    is_freemail: bool = False
    domain: str = ""
    spoofing_indicators: list[str] = []


class AnalysisResult(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    summary: str
    headers: HeaderAnalysis
    urls: list[UrlAnalysis] = []
    sender: SenderAnalysis
    warnings: list[str] = []
