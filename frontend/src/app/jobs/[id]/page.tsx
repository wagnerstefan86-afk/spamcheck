"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import axios from "axios";
import StatusView from "@/components/StatusView";
import ResultView from "@/components/ResultView";
import type { AnalysisSummary } from "@/lib/analysis";

type JobStatus = {
  id: string;
  filename: string;
  status: string;
  warnings: string[];
  error_message?: string;
};

export default function JobPage() {
  const params = useParams();
  const jobId = params.id as string;
  const [status, setStatus] = useState<JobStatus | null>(null);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState("");

  const pollStatus = useCallback(async () => {
    try {
      const { data } = await axios.get(`/api/jobs/${jobId}`);
      setStatus(data);
      return data.status;
    } catch (err) {
      console.error("[poll] Status fetch failed:", err);
      setError("Job-Status konnte nicht abgerufen werden. Backend möglicherweise nicht erreichbar.");
      return "failed";
    }
  }, [jobId]);

  const fetchResult = useCallback(async () => {
    try {
      const { data } = await axios.get(`/api/jobs/${jobId}/result`);
      setResult(data);
    } catch (err) {
      console.error("[result] Result fetch failed:", err);
      setError("Ergebnis konnte nicht geladen werden.");
    }
  }, [jobId]);

  useEffect(() => {
    let active = true;
    const poll = async () => {
      while (active) {
        const s = await pollStatus();
        if (!active) break;
        if (s === "completed" || s === "completed_with_warnings" || s === "failed") {
          if (s !== "failed") await fetchResult();
          break;
        }
        await new Promise((r) => setTimeout(r, 2000));
      }
    };
    poll();
    return () => { active = false; };
  }, [pollStatus, fetchResult]);

  const downloadExport = async (summary: AnalysisSummary) => {
    try {
      const { data: rawBackend } = await axios.get(`/api/jobs/${jobId}/export`);

      const exportData = {
        analysis_summary: summary,
        raw_backend_result: rawBackend,
      };

      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `mailscope-${jobId.slice(0, 8)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      setError("Export fehlgeschlagen.");
    }
  };

  if (error && !status) {
    return <div className="text-center py-12 text-red-400">{error}</div>;
  }

  if (!status) {
    return <div className="text-center py-12 text-slate-500">Lade...</div>;
  }

  const isComplete = status.status === "completed" || status.status === "completed_with_warnings";

  return (
    <div className="space-y-6">
      {!isComplete && status.status !== "failed" && <StatusView status={status} />}
      {status.status === "failed" && (
        <div className="card border-red-500/30">
          <h2 className="text-lg font-semibold text-red-400">Analyse fehlgeschlagen</h2>
          <p className="text-slate-400 mt-2">{status.error_message || "Unbekannter Fehler"}</p>
        </div>
      )}
      {isComplete && result && (
        <ResultView result={result} onDownload={downloadExport} />
      )}
      {error && <p className="text-red-400 text-sm text-center">{error}</p>}
    </div>
  );
}
