// Dates, counts and sizes as the page shows them.
import { LANG, t } from "./i18n";

export const today = () => new Date().toISOString().slice(0, 10);
export const days = (d: string) =>
  Math.round((new Date(d + "T00:00:00Z").getTime() - new Date(today() + "T00:00:00Z").getTime()) / 864e5);
export const fmtDay = (d: string) =>
  new Date(d + "T00:00:00Z").toLocaleDateString(LANG, { day: "numeric", month: "short", timeZone: "UTC" });
export const dueText = (d?: string) => {
  if (!d) return "";
  const n = days(d);
  return n < 0 ? t("{n} d late", { n: -n }) : n < 14 ? t("in {n} d", { n }) : fmtDay(d);
};
export const pct = (e: number) =>
  e >= 0.1 ? Math.round(e * 100) + "%" : e >= 0.01 ? (e * 100).toFixed(1) + "%" : e > 0 ? "<1%" : "";
export const ago = (iso?: string) => {
  if (!iso) return t("never");
  const h = (Date.now() - new Date(iso).getTime()) / 36e5;
  return h < 1 ? t("just now") : h < 48 ? t("{n} h ago", { n: Math.round(h) }) : t("{n} d ago", { n: Math.round(h / 24) });
};
export const fmtN = (n?: number | null) => (n ?? 0).toLocaleString(LANG);
export const runLabel = (id?: string) =>
  id === "current" ? t("Current state") : String(id || "").replace("_", " ").replace(/(\d\d)(\d\d)(\d\d)$/, "$1:$2");
export const tsShort = (v?: string) => (v || "").replace("T", " ").slice(0, 16);
export const took = (a?: string, b?: string) => {
  if (!a || !b) return "";
  const s = Math.max(0, (new Date(b).getTime() - new Date(a).getTime()) / 1000);
  return s < 60 ? Math.round(s) + " s" : s < 3600 ? Math.round(s / 60) + " min" : (s / 3600).toFixed(1) + " h";
};
export const bytes = (n: number) =>
  n >= 1e9 ? (n / 1e9).toFixed(1) + " GB" : n >= 1e6 ? Math.round(n / 1e6) + " MB" : n > 0 ? Math.max(1, Math.round(n / 1e3)) + " KB" : "?";
/** runIso: a run id (2026-11-02_110000) as a time. */
export const runIso = (id?: string) =>
  /^\d{4}-\d\d-\d\d_\d{6}$/.test(id || "") ? id!.replace(/^(\d{4}-\d\d-\d\d)_(\d\d)(\d\d)(\d\d)$/, "$1T$2:$3:$4Z") : "";
/** webURL: a link from the vulnerability DB, http(s) only: no javascript: or data: URL becomes clickable. */
export const webURL = (u?: string) => (/^https?:\/\//i.test(String(u || "")) ? String(u) : "");
/** narrow: the window is too narrow for the details beside the list (they open over it). */
export const narrow = () => matchMedia("(max-width: 1240px)").matches;
