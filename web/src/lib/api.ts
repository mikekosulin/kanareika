// The server's API: GET for data, POST (with the CSRF token) for what changes something.
import { CSRF } from "./i18n";

export class APIError extends Error {
  status: number;
  body: any;
  constructor(message: string, status: number, body: any) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

async function answer(r: Response) {
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new APIError(body.error || r.statusText, r.status, body);
  return body;
}

/** qs: a query string of the set values. */
export const qs = (o: Record<string, unknown>) =>
  Object.entries(o)
    .filter(([, v]) => v !== "" && v != null && v !== false)
    .map(([k, v]) => k + "=" + encodeURIComponent(String(v)))
    .join("&");

export async function api<T = any>(path: string, signal?: AbortSignal): Promise<T> {
  return answer(await fetch(path, { cache: "no-store", signal }));
}

export async function post<T = any>(path: string, data?: unknown): Promise<T> {
  return answer(
    await fetch(path, {
      method: "POST",
      cache: "no-store",
      headers: { "Content-Type": "application/json", "X-Kanareika-CSRF": CSRF },
      body: JSON.stringify(data || {}),
    }),
  );
}
