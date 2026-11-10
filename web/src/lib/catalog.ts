// Finding and action texts in the page's language: the server's message catalog (/api/i18n), by key; English as
// sent when there is no key or the page is in English.
import { LANG } from "./i18n";

export type Catalog = Record<string, Record<string, string>>;

export function makeL(cat: Catalog | undefined) {
  const msgOf = (key: string) => (cat?.[key] && (cat[key][LANG] || cat[key].en)) || key;
  /** L: a finding's (or action's) title, or another of its texts (field + "_msg" / "_args"). */
  const L = (o: any, field = "title"): string => {
    const key = field === "title" ? o.msg : o[field + "_msg"];
    const m = key && cat?.[key];
    if (!m || LANG === "en") return o[field] || "";
    const a: Record<string, any> = { ...((field === "title" ? o.args : o[field + "_args"]) || {}) };
    for (const k of Object.keys(a)) {
      if (k.endsWith("_keys") && Array.isArray(a[k])) a[k.slice(0, -5)] = a[k].map(msgOf).join(", ");
      else if (k.endsWith("_key") && cat?.[a[k]]) a[k.slice(0, -4)] = msgOf(a[k]);
    }
    return (m[LANG] || m.en).replace(/\{(\w+)\}/g, (_: string, k: string) => a[k] ?? `{${k}}`);
  };
  const catMsg = (key: string, fb?: string) => (cat?.[key] && (cat[key][LANG] || cat[key].en)) || fb || key;
  const problemText = (n: any) => (n?.problem_msg ? L({ msg: n.problem_msg, args: n.problem_args, title: n.problem }) : n?.problem || "");
  return { L, catMsg, problemText };
}

export const deniedKey = (x: string) => (String(x).startsWith("denied.") ? x : "denied." + x);
