"""LLM client for email security assessment."""

import json
import logging
from pathlib import Path

import httpx

from ..config import get_settings

logger = logging.getLogger(__name__)

PROMPT_TEMPLATE = (Path(__file__).parent.parent / "prompts" / "assessment.txt").read_text()

REPAIR_PROMPT = """Deine vorherige Antwort war kein valides JSON. Bitte korrigiere deine Antwort.
Antworte NUR mit dem JSON-Objekt, ohne Markdown-Codeblöcke oder anderen Text.
Vorherige Antwort:
{previous}

Korrigiere zu validem JSON mit den Feldern: classification, risk_score, confidence, recommended_action, rationale, evidence, analyst_summary."""

VALID_CLASSIFICATIONS = {"phishing", "advertising", "legitimate", "suspicious", "unknown"}
VALID_ACTIONS = {"delete", "open_ticket", "verify_via_known_channel", "allow", "manual_review"}


def _build_prompt(
    parsed: dict,
    header_findings: list[dict],
    links: list[dict],
    external_results: list[dict],
    scores: dict,
) -> str:
    body_text = parsed.get("body_text", "")
    body_summary = body_text[:500] if body_text else "(kein Text-Body)"

    link_lines = []
    for link in links:
        flags = []
        if link.get("is_ip_literal"):
            flags.append("IP-Literal")
        if link.get("is_punycode"):
            flags.append("Punycode")
        if link.get("is_shortener"):
            flags.append("Shortener")
        if link.get("has_display_mismatch"):
            flags.append("Display-Mismatch")
        if link.get("is_suspicious_tld"):
            flags.append("Verdächtige TLD")
        if link.get("is_tracking_heavy"):
            flags.append("Tracking")
        flag_str = f" [{', '.join(flags)}]" if flags else ""
        link_lines.append(f"- {link.get('normalized_url', link.get('original_url', ''))}{flag_str}")

    ext_lines = []
    for r in external_results:
        ext_lines.append(
            f"- {r.get('service', '?')}: Status={r.get('status', '?')}, "
            f"Malicious={r.get('malicious_count', 0)}, Suspicious={r.get('suspicious_count', 0)}"
        )

    hdr_lines = [f"- [{f['severity']}] {f['title']}: {f['detail']}" for f in header_findings]
    det_lines = [f"- {f['detail']} ({f['impact']})" for f in scores.get("findings", [])]

    return PROMPT_TEMPLATE.format(
        subject=parsed.get("subject", ""),
        **{"from": parsed.get("from", "")},
        reply_to=parsed.get("reply_to", ""),
        return_path=parsed.get("return_path", ""),
        to=parsed.get("to", ""),
        date=parsed.get("date", ""),
        phishing_score=scores.get("phishing_likelihood_score", 0),
        advertising_score=scores.get("advertising_likelihood_score", 0),
        legitimacy_score=scores.get("legitimacy_likelihood_score", 50),
        header_findings="\n".join(hdr_lines) or "Keine Befunde",
        deterministic_findings="\n".join(det_lines) or "Keine Befunde",
        link_analysis="\n".join(link_lines) or "Keine Links gefunden",
        external_results="\n".join(ext_lines) or "Keine externen Prüfungen durchgeführt",
        body_summary=body_summary,
    )


def _parse_llm_json(text: str) -> dict | None:
    text = text.strip()
    # Try to extract JSON from markdown code blocks
    if "```" in text:
        parts = text.split("```")
        for part in parts:
            part = part.strip()
            if part.startswith("json"):
                part = part[4:].strip()
            try:
                return json.loads(part)
            except json.JSONDecodeError:
                continue

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to find JSON object in text
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                return None
    return None


def _validate_assessment(data: dict) -> dict | None:
    required = ["classification", "risk_score", "confidence", "recommended_action", "rationale", "evidence", "analyst_summary"]
    for key in required:
        if key not in data:
            return None

    if data["classification"] not in VALID_CLASSIFICATIONS:
        return None
    if data["recommended_action"] not in VALID_ACTIONS:
        return None

    data["risk_score"] = max(0, min(100, int(data["risk_score"])))
    data["confidence"] = max(0, min(100, int(data["confidence"])))

    if not isinstance(data["evidence"], list):
        data["evidence"] = [str(data["evidence"])]

    return data


async def _call_openai(messages: list[dict]) -> str | None:
    settings = get_settings()
    if not settings.openai_api_key:
        logger.warning("OpenAI API key not configured")
        return None

    async with httpx.AsyncClient(timeout=60) as client:
        try:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {settings.openai_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": settings.llm_model,
                    "messages": messages,
                    "temperature": 0.2,
                    "max_tokens": 1500,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]
        except httpx.HTTPStatusError as e:
            logger.error("OpenAI API HTTP error %s: %s – Body: %s", e.response.status_code, e, e.response.text[:500])
            raise RuntimeError(f"OpenAI API HTTP {e.response.status_code}: {e.response.text[:200]}")
        except httpx.TimeoutException as e:
            logger.error("OpenAI API timeout: %s", e)
            raise RuntimeError(f"OpenAI API Timeout nach 60s")
        except Exception as e:
            logger.error("OpenAI API call failed: %s", e)
            raise RuntimeError(f"OpenAI API Fehler: {e}")


async def get_assessment(
    parsed: dict,
    header_findings: list[dict],
    links: list[dict],
    external_results: list[dict],
    scores: dict,
) -> dict | None:
    """Get LLM assessment. Returns validated dict or None on failure."""
    prompt = _build_prompt(parsed, header_findings, links, external_results, scores)

    messages = [
        {"role": "system", "content": "Du bist ein IT-Sicherheitsanalyst. Antworte ausschließlich mit validem JSON."},
        {"role": "user", "content": prompt},
    ]

    response = await _call_openai(messages)
    if not response:
        return None

    data = _parse_llm_json(response)
    if data:
        validated = _validate_assessment(data)
        if validated:
            return validated

    # Retry with repair prompt
    logger.warning("LLM returned invalid JSON, retrying with repair prompt")
    messages.append({"role": "assistant", "content": response})
    messages.append({"role": "user", "content": REPAIR_PROMPT.format(previous=response[:500])})

    response2 = await _call_openai(messages)
    if not response2:
        return None

    data2 = _parse_llm_json(response2)
    if data2:
        return _validate_assessment(data2)

    return None
