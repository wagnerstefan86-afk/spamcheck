import { useState } from "react";
import axios from "axios";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

const PLACEHOLDER = `Füge hier den vollständigen Email-Quelltext ein (inkl. Header)…

Beispiel:
From: sender@example.com
To: recipient@example.com
Subject: Wichtige Nachricht
Received-SPF: pass
Authentication-Results: mx.example.com; dkim=pass; spf=pass; dmarc=pass
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; ...

Hallo, dies ist eine Test-Email mit einem Link: https://example.com`;

export default function App() {
  const [emailText, setEmailText] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const analyze = async () => {
    if (!emailText.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const { data } = await axios.post(`${API_URL}/api/analyze`, {
        email_text: emailText,
      });
      setResult(data);
    } catch (err) {
      const msg =
        err.response?.data?.detail?.[0]?.msg ||
        err.response?.data?.detail ||
        "Verbindung zum Server fehlgeschlagen.";
      setError(typeof msg === "string" ? msg : JSON.stringify(msg));
    } finally {
      setLoading(false);
    }
  };

  const scoreColor = (level) => {
    if (level === "niedrig") return "var(--green)";
    if (level === "mittel") return "var(--yellow)";
    return "var(--red)";
  };

  return (
    <>
      <header>
        <h1>
          Mail<span>Scope</span>
        </h1>
        <p>Email Security Analysis</p>
      </header>

      <div className="card">
        <textarea
          value={emailText}
          onChange={(e) => setEmailText(e.target.value)}
          placeholder={PLACEHOLDER}
          spellCheck={false}
        />
        <button
          className="analyze-btn"
          onClick={analyze}
          disabled={loading || !emailText.trim()}
        >
          {loading && <span className="spinner" />}
          {loading ? "Analysiere…" : "Email analysieren"}
        </button>
      </div>

      {error && <p className="error-msg">{error}</p>}

      {result && (
        <>
          {/* Risk Score */}
          <div className="card">
            <div className="section-title">Risiko-Bewertung</div>
            <div className={`risk-badge ${result.risk_level}`}>
              {result.risk_score}/100 —{" "}
              {result.risk_level.charAt(0).toUpperCase() +
                result.risk_level.slice(1)}
            </div>
            <div className="score-bar-track">
              <div
                className="score-bar-fill"
                style={{
                  width: `${result.risk_score}%`,
                  background: scoreColor(result.risk_level),
                }}
              />
            </div>
            <p style={{ marginTop: "0.75rem", fontSize: "0.9rem" }}>
              {result.summary}
            </p>
          </div>

          {/* Warnings */}
          {result.warnings.length > 0 && (
            <div className="card">
              <div className="section-title">Warnungen</div>
              <ul className="warning-list">
                {result.warnings.map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Header Analysis */}
          <div className="card">
            <div className="section-title">Header-Analyse</div>
            <div className="detail-row">
              <span className="label">SPF</span>
              <span className={result.headers.spf_pass ? "badge-pass" : "badge-fail"}>
                {result.headers.spf_pass ? "PASS" : "FAIL"}
              </span>
            </div>
            <div className="detail-row">
              <span className="label">DKIM</span>
              <span className={result.headers.dkim_pass ? "badge-pass" : "badge-fail"}>
                {result.headers.dkim_pass ? "PASS" : "FAIL"}
              </span>
            </div>
            <div className="detail-row">
              <span className="label">DMARC</span>
              <span className={result.headers.dmarc_pass ? "badge-pass" : "badge-fail"}>
                {result.headers.dmarc_pass ? "PASS" : "FAIL"}
              </span>
            </div>
            {result.headers.from_address && (
              <div className="detail-row">
                <span className="label">From</span>
                <span>{result.headers.from_address}</span>
              </div>
            )}
            {result.headers.return_path && (
              <div className="detail-row">
                <span className="label">Return-Path</span>
                <span>{result.headers.return_path}</span>
              </div>
            )}
          </div>

          {/* Sender */}
          <div className="card">
            <div className="section-title">Absender-Analyse</div>
            <div className="detail-row">
              <span className="label">Adresse</span>
              <span>{result.sender.address || "—"}</span>
            </div>
            <div className="detail-row">
              <span className="label">Domain</span>
              <span>{result.sender.domain || "—"}</span>
            </div>
            <div className="detail-row">
              <span className="label">Freemail</span>
              <span className={result.sender.is_freemail ? "badge-fail" : "badge-pass"}>
                {result.sender.is_freemail ? "Ja" : "Nein"}
              </span>
            </div>
            {result.sender.spoofing_indicators.length > 0 && (
              <div style={{ marginTop: "0.5rem" }}>
                {result.sender.spoofing_indicators.map((s, i) => (
                  <div key={i} className="url-reason">
                    {s}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* URLs */}
          {result.urls.length > 0 && (
            <div className="card">
              <div className="section-title">
                Gefundene URLs ({result.urls.length})
              </div>
              {result.urls.map((u, i) => (
                <div
                  key={i}
                  className={`url-item ${u.is_suspicious ? "suspicious" : "safe"}`}
                >
                  <div>{u.url}</div>
                  {u.reasons.map((r, j) => (
                    <div key={j} className="url-reason">
                      {r}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </>
  );
}
