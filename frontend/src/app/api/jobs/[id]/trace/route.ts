import { proxyGet } from "@/lib/backendProxy";

export async function GET(
  _request: Request,
  { params }: { params: { id: string } },
) {
  return proxyGet(`/api/jobs/${params.id}/trace`);
}
