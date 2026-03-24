"use client";

import { useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import axios from "axios";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

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
      <div className="card border-amber-500/30 bg-amber-500/5">
        <div className="flex gap-3">
          <div className="text-amber-400 text-lg mt-0.5">!</div>
          <div className="text-sm text-amber-200/80">
            <p className="font-medium text-amber-300 mb-1">Datenschutzhinweis</p>
            <p>
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
        <h2 className="text-lg font-semibold mb-4">E-Mail-Datei hochladen</h2>
        <div
          className={`border-2 border-dashed rounded-xl p-12 text-center transition cursor-pointer
            ${dragActive ? "border-accent bg-accent/5" : "border-border hover:border-slate-600"}
            ${file ? "border-emerald-500/50 bg-emerald-500/5" : ""}`}
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
              <div className="text-emerald-400 text-3xl mb-2">&#10003;</div>
              <p className="text-slate-200 font-medium">{file.name}</p>
              <p className="text-slate-500 text-sm mt-1">
                {(file.size / 1024).toFixed(1)} KB
              </p>
            </div>
          ) : (
            <div>
              <div className="text-slate-500 text-4xl mb-3">&#8682;</div>
              <p className="text-slate-300">
                .eml oder .msg Datei hierher ziehen
              </p>
              <p className="text-slate-500 text-sm mt-1">oder klicken zum Auswählen</p>
            </div>
          )}
        </div>

        {error && <p className="text-red-400 text-sm mt-3">{error}</p>}

        <button
          onClick={submit}
          disabled={!file || uploading}
          className="w-full mt-4 py-3 bg-accent hover:bg-indigo-600 disabled:opacity-40 disabled:cursor-not-allowed
            rounded-lg font-semibold text-white transition"
        >
          {uploading ? "Wird hochgeladen..." : "Analyse starten"}
        </button>
      </div>
    </div>
  );
}
