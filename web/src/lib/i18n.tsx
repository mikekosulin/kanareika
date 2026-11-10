// Interface strings: English in the code, the other languages from the server (window.KANAREIKA.ui, keyed by
// the English text). t() gives text; tx() gives React nodes, for strings whose {args} are elements (<code>).
import { Fragment, type ReactNode } from "react";
import { local } from "./local";

type UI = Record<string, Record<string, string>>;
declare global {
  interface Window {
    KANAREIKA: { csrf: string; ui: UI; names: Record<string, string> };
  }
}

const K = window.KANAREIKA ?? { csrf: "", ui: {}, names: {} };
export const CSRF = K.csrf;
export const LANG_NAMES = K.names;
export const LANG = new URLSearchParams(location.search).get("lang") || local.get("lang", "en");

const tr = (s: string) => K.ui[LANG]?.[s] || s;

/** t: the string in the page's language, {name} replaced by args (as text). */
export const t = (s: string, args?: Record<string, string | number | null | undefined>) => {
  let out = tr(s);
  if (args) for (const [k, v] of Object.entries(args)) out = out.replaceAll("{" + k + "}", String(v ?? ""));
  return out;
};

/** tx: t() with args that are elements: the translation split around them. */
export function tx(s: string, args: Record<string, ReactNode>): ReactNode {
  const parts = tr(s).split(/(\{\w+\})/);
  return parts.map((p, i) => {
    const m = /^\{(\w+)\}$/.exec(p);
    return <Fragment key={i}>{m && m[1] in args ? args[m[1]] : p}</Fragment>;
  });
}
