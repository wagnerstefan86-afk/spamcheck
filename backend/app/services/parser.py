"""Parse .eml and .msg email files."""

import email
import email.policy
import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_eml(raw_bytes: bytes) -> dict[str, Any]:
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    return _extract(msg)


def parse_msg(raw_bytes: bytes) -> dict[str, Any]:
    import oxmsg
    import io

    msg_file = oxmsg.Message(io.BytesIO(raw_bytes))

    result: dict[str, Any] = {
        "subject": msg_file.subject or "",
        "from": msg_file.sender or "",
        "reply_to": "",
        "return_path": "",
        "to": ", ".join(r.email_address for r in msg_file.recipients) if msg_file.recipients else "",
        "date": str(msg_file.sent_date) if msg_file.sent_date else "",
        "message_id": "",
        "authentication_results": "",
        "received_chain": [],
        "raw_headers": "",
        "structured_headers": {},
        "body_text": msg_file.body or "",
        "body_html": msg_file.html_body if hasattr(msg_file, "html_body") else "",
        "attachment_metadata": [],
    }

    if hasattr(msg_file, "attachments") and msg_file.attachments:
        for att in msg_file.attachments:
            result["attachment_metadata"].append({
                "filename": getattr(att, "filename", "unknown"),
                "content_type": getattr(att, "content_type", "application/octet-stream"),
                "size": getattr(att, "size", 0),
            })

    return result


def _extract(msg: email.message.EmailMessage) -> dict[str, Any]:
    headers_dict = {}
    raw_header_lines = []
    for key, value in msg.items():
        raw_header_lines.append(f"{key}: {value}")
        if key in headers_dict:
            if isinstance(headers_dict[key], list):
                headers_dict[key].append(value)
            else:
                headers_dict[key] = [headers_dict[key], value]
        else:
            headers_dict[key] = value

    received = msg.get_all("Received") or []

    body_text = ""
    body_html = ""
    attachment_metadata = []

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            if "attachment" in cd:
                attachment_metadata.append({
                    "filename": part.get_filename() or "unknown",
                    "content_type": ct,
                    "size": len(part.get_payload(decode=True) or b""),
                })
                continue
            if ct == "text/plain" and not body_text:
                payload = part.get_payload(decode=True)
                if payload:
                    body_text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            elif ct == "text/html" and not body_html:
                payload = part.get_payload(decode=True)
                if payload:
                    body_html = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
    else:
        ct = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            text = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
            if ct == "text/html":
                body_html = text
            else:
                body_text = text

    return {
        "subject": msg.get("Subject", ""),
        "from": msg.get("From", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", "").strip("<>"),
        "to": msg.get("To", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "authentication_results": msg.get("Authentication-Results", ""),
        "received_chain": [r.strip() for r in received],
        "raw_headers": "\n".join(raw_header_lines),
        "structured_headers": headers_dict,
        "body_text": body_text,
        "body_html": body_html,
        "attachment_metadata": attachment_metadata,
    }


def parse_email_file(filename: str, raw_bytes: bytes) -> dict[str, Any]:
    lower = filename.lower()
    if lower.endswith(".msg"):
        return parse_msg(raw_bytes)
    return parse_eml(raw_bytes)
