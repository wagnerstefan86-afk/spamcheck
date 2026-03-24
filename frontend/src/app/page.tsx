"use client";

import { useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import axios from "axios";

const API = "";

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

  const submit = async () => {
    if (!file) return;
    setUploading(true);
    setError("");
    try {
      const formData = new FormData();
      formData.append("file", file);
      const { data } = await axios.post(`${API}/api/upload`, formData);
      router.push(`/jobs/${data.id}`);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Upload fehlgeschlagen.");
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
          onClick={() => document.getElementById("file-input")?.click()}
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
