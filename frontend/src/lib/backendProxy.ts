/**
 * Shared helper for proxying GET requests to the backend.
 * Used by Route Handlers to avoid duplicating proxy logic.
 */

import { NextResponse } from "next/server";

const BACKEND = process.env.BACKEND_URL || "http://backend:8000";

export async function proxyGet(path: string): Promise<NextResponse> {
  try {
    const response = await fetch(`${BACKEND}${path}`, {
      method: "GET",
      headers: { accept: "application/json" },
    });

    let data: unknown;
    try {
      data = await response.json();
    } catch {
      return NextResponse.json(
        { detail: `Backend-Antwort ungültig (HTTP ${response.status}).` },
        { status: 502 },
      );
    }

    return NextResponse.json(data, { status: response.status });
  } catch (err) {
    console.error(`[proxy] Backend unreachable for ${path}:`, err);
    return NextResponse.json(
      { detail: "Backend nicht erreichbar." },
      { status: 502 },
    );
  }
}
