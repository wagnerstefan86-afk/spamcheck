"use client";

import { useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import axios, { AxiosError } from "axios";

export default function UploadPage() {
  const router = useRouter();
  const [file, setFile] = useState<File | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState("");

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    const f = e.dataTransfer.files[0];
    if (f && (f.name.endsWith(".eml") || f.name.endsWith(".msg"))) {
      setFile(f);
      setError("");
    } else {
      setError("Nur .eml und .msg Dateien werden unterstützt.");
    }
  }, []);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) {
      setFile(f);
      setError("");
    }
  };

  const removeFile = () => {
    setFile(null);
    setError("");
    // Reset file input so the same file can be re-selected
    const input = document.getElementById("file-input") as HTMLInputElement;
    if (input) input.value = "";
  };

  const submit = async () => {
    if (!file) return;
    setUploading(true);
    setError("");

    try {
      const formData = new FormData();
      formData.append("file", file);

      console.log("[upload] Starting upload:", file.name, `(${(file.size / 1024).toFixed(1)} KB)`);

      const { data } = await axios.post("/api/upload", formData);

      console.log("[upload] Success, job ID:", data.id);
      router.push(`/jobs/${data.id}`);
    } catch (err) {
      const axiosErr = err as AxiosError<{ detail?: string }>;

      // Extract the most specific error message available
      const errorMessage = classifyUploadError(axiosErr);

      console.error("[upload] Failed:", {
        status: axiosErr.response?.status,
        detail: axiosErr.response?.data?.detail,
        message: axiosErr.message,
        code: axiosErr.code,
      });

      setError(errorMessage);
      setUploading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      {/* Privacy notice */}
      <div className="card border border-amber-200 bg-amber-50/50">
        <div className="flex gap-3">
          <div className="w-8 h-8 rounded-full bg-amber-100 flex items-center justify-center shrink-0">
            <svg className="w-4 h-4 text-amber-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M12 3l9.5 16.5H2.5L12 3z" />
            </svg>
          </div>
          <div className="text-sm text-amber-900/80">
            <p className="font-semibold text-amber-800 mb-1">Datenschutzhinweis</p>
            <p className="leading-relaxed">
              Diese Anwendung kann extrahierte URLs an externe Reputationsdienste
              (VirusTotal, urlscan.io) übermitteln. Die vollständige E-Mail und Anhänge
              werden <strong>nicht</strong> extern gesendet.
              Verwenden Sie keine vertraulichen internen E-Mails ohne vorherige Genehmigung.
            </p>
          </div>
        </div>
      </div>

      {/* Upload area */}
      <div className="card">
        <h2 className="text-xl font-semibold text-text-primary mb-5">E-Mail-Datei hochladen</h2>
        <div
          className={`border-2 border-dashed rounded-2xl p-14 text-center transition-all duration-200 cursor-pointer
            ${dragActive ? "border-accent bg-red-50/50 scale-[1.01]" : "border-gray-300 hover:border-gray-400 hover:bg-gray-50/50"}
            ${file ? "border-emerald-400 bg-emerald-50/50" : ""}`}
          onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
          onDragLeave={() => setDragActive(false)}
          onDrop={handleDrop}
          onClick={() => !file && document.getElementById("file-input")?.click()}
        >
          <input
            id="file-input"
            type="file"
            accept=".eml,.msg"
            className="hidden"
            onChange={handleFileSelect}
          />
          {file ? (
            <div>
              <div className="w-14 h-14 rounded-full bg-emerald-100 flex items-center justify-center mx-auto mb-3">
                <svg className="w-7 h-7 text-emerald-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <p className="text-text-primary font-semibold text-lg">{file.name}</p>
              <p className="text-text-secondary text-sm mt-1">
                {(file.size / 1024).toFixed(1)} KB
              </p>
              <button
                type="button"
                onClick={(e) => { e.stopPropagation(); removeFile(); }}
                className="mt-3 text-sm text-text-secondary hover:text-red-600 underline underline-offset-2 transition-colors"
              >
                Andere Datei wählen
              </button>
            </div>
          ) : (
            <div>
              <div className="w-14 h-14 rounded-full bg-gray-100 flex items-center justify-center mx-auto mb-3">
                <svg className="w-7 h-7 text-text-tertiary" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                </svg>
              </div>
              <p className="text-text-primary font-medium text-lg">
                .eml oder .msg Datei hierher ziehen
              </p>
              <p className="text-text-secondary text-sm mt-1">oder klicken zum Auswählen</p>
            </div>
          )}
        </div>

        {error && (
          <div className="flex items-center gap-2 mt-3 text-sm text-red-600">
            <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            {error}
          </div>
        )}

        <button
          onClick={submit}
          disabled={!file || uploading}
          className="w-full mt-5 py-3.5 bg-accent hover:bg-accent-hover active:scale-[0.98] disabled:opacity-40 disabled:cursor-not-allowed
            rounded-xl font-semibold text-white transition-all duration-200 shadow-sm hover:shadow-md"
        >
          {uploading ? (
            <span className="flex items-center justify-center gap-2">
              <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Wird hochgeladen...
            </span>
          ) : "Analyse starten"}
        </button>
      </div>
    </div>
  );
}


/**
 * Classify an upload error into a specific, user-facing message.
 * Replaces the old generic "Upload fehlgeschlagen."
 */
function classifyUploadError(err: AxiosError<{ detail?: string }>): string {
  // Backend returned a structured error
  if (err.response?.data?.detail) {
    return err.response.data.detail;
  }

  const status = err.response?.status;

  // HTTP status-based classification
  if (status === 413) {
    return "Datei zu groß. Maximum: 25 MB.";
  }
  if (status === 400) {
    return "Ungültige Anfrage. Bitte prüfen Sie das Dateiformat (.eml oder .msg).";
  }
  if (status === 502) {
    return "Backend nicht erreichbar. Bitte prüfen Sie, ob der Analyse-Service läuft.";
  }
  if (status === 503) {
    return "Service vorübergehend nicht verfügbar. Bitte versuchen Sie es in wenigen Sekunden erneut.";
  }
  if (status && status >= 500) {
    return `Serverfehler (HTTP ${status}). Bitte versuchen Sie es erneut.`;
  }

  // Network-level errors (no response received)
  if (err.code === "ERR_NETWORK" || err.code === "ECONNREFUSED") {
    return "Keine Verbindung zum Server. Bitte prüfen Sie Ihre Netzwerkverbindung.";
  }
  if (err.code === "ECONNABORTED") {
    return "Upload-Timeout. Die Verbindung wurde unterbrochen.";
  }

  // Fallback — include error code for debugging
  return `Upload fehlgeschlagen${err.code ? ` (${err.code})` : ""}. Bitte versuchen Sie es erneut.`;
}
