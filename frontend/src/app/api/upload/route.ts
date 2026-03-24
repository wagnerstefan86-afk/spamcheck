/**
 * Route Handler for file upload.
 *
 * Bypasses Next.js rewrite proxy which can silently fail on
 * multipart/form-data bodies (body-buffering limits, missing
 * content-length forwarding).  Reads the raw body and forwards
 * it to the backend with the original Content-Type intact.
 */

import { NextRequest, NextResponse } from "next/server";

const BACKEND = process.env.BACKEND_URL || "http://backend:8000";

// Max body size: 30 MB (backend allows 25 MB, leave headroom for multipart overhead)
const MAX_BODY_BYTES = 30 * 1024 * 1024;

export async function POST(request: NextRequest) {
  const contentType = request.headers.get("content-type") || "";

  if (!contentType.includes("multipart/form-data")) {
    return NextResponse.json(
      { detail: "Content-Type muss multipart/form-data sein." },
      { status: 400 },
    );
  }

  let body: ArrayBuffer;
  try {
    body = await request.arrayBuffer();
  } catch {
    return NextResponse.json(
      { detail: "Request-Body konnte nicht gelesen werden." },
      { status: 400 },
    );
  }

  if (body.byteLength > MAX_BODY_BYTES) {
    const sizeMB = (body.byteLength / 1024 / 1024).toFixed(1);
    return NextResponse.json(
      { detail: `Datei zu groß (${sizeMB} MB). Maximum: 25 MB.` },
      { status: 413 },
    );
  }

  try {
    const backendResponse = await fetch(`${BACKEND}/api/upload`, {
      method: "POST",
      headers: { "content-type": contentType },
      body: body,
    });

    let data: unknown;
    try {
      data = await backendResponse.json();
    } catch {
      return NextResponse.json(
        { detail: `Backend-Antwort konnte nicht verarbeitet werden (HTTP ${backendResponse.status}).` },
        { status: 502 },
      );
    }

    return NextResponse.json(data, { status: backendResponse.status });
  } catch (err) {
    console.error("[upload-proxy] Backend unreachable:", err);
    return NextResponse.json(
      { detail: "Backend nicht erreichbar. Bitte prüfen Sie, ob der Backend-Service läuft." },
      { status: 502 },
    );
  }
}
