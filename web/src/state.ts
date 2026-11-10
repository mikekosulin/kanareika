// The page's state: where it is (view, org, env, run), how the lists are grouped and filtered, what is open and
// selected. The address bar mirrors it (/servers?org=…&env=…), so a link or a reload lands in the same place.
import { create } from "zustand";
import { useShallow } from "zustand/react/shallow";
import { local } from "./lib/local";

export type View = "servers" | "todo" | "history" | "setup";
export type By = "fix" | "cve" | "host";
export const TREE_VIEWS: View[] = ["servers", "todo"];
export const isTree = (v: View) => v === "servers" || v === "todo";

export type Item = { kind: "host"; name: string } | { kind: "run" | "job" | "exc"; [k: string]: any };

export interface State {
  view: View;
  org: string;
  env: string;
  run: string;
  theme: string;
  // tree views: Servers and ToDo keep their own grouping
  tby: By;
  sby: By;
  flt: Set<string>;
  q: string;
  backport: boolean;
  accepted: boolean;
  lens: string;
  p4: boolean;
  open: Set<string>;
  cur: string | null; // the node (or server row) whose details show
  stack: { id: string; label: string }[]; // the details panel's way back
  sel: Set<string>; // nodes in the task for an agent
  wantHost: string; // a server to show once Servers has its rows (from the address, or a link)
  // History
  vq: string;
  vsel: string;
  vitem: Item | null;
  vstack: Item[];
  detailOpen: boolean; // the details panel over the list on a narrow window
  sideOpen: boolean;
  palOpen: boolean;
  toast: { text: string; at: number } | null;
}

const by = (v: string | null, d: By): By => (v === "fix" || v === "cve" || v === "host" ? v : d);

export const useApp = create<State>(() => ({
  view: "servers",
  org: local.get("org", ""),
  env: local.get("env", ""),
  run: "current",
  theme: local.get("theme", "system"),
  tby: by(local.get("by", "fix"), "fix"),
  sby: by(local.get("sby", "host"), "host"),
  flt: new Set(),
  q: "",
  backport: false,
  accepted: false,
  lens: "priorities",
  p4: false,
  open: new Set(),
  cur: null,
  stack: [],
  sel: new Set(),
  wantHost: "",
  vq: "",
  vsel: "",
  vitem: null,
  vstack: [],
  detailOpen: false,
  sideOpen: false,
  palOpen: false,
  toast: null,
}));
export const set = useApp.setState;
/** useS: several fields of the state at once (drawn again only when one of them changes). */
export const useS = <T extends object>(f: (s: State) => T): T => useApp(useShallow(f));
export const get = useApp.getState;

/** grouping: what the open tree view groups by. */
export const grouping = (s: State): By => (s.view === "servers" ? s.sby : s.tby);
/** serverList: Servers grouped by server (the server list and its lenses), not a tree of fixes. */
export const serverList = (s: State) => s.view === "servers" && s.sby === "host";

export const toast = (text: string) => set({ toast: { text, at: Date.now() } });

/** go: another view; a tree view's filters, query and open rows stay with the view they were set in. */
export function go(view: View, q?: string) {
  const s = get();
  const patch: Partial<State> = { view, sideOpen: false, detailOpen: false };
  if (view !== s.view) {
    Object.assign(patch, { vq: "", vsel: "", vitem: null, vstack: [] });
    if (isTree(view) && isTree(s.view)) Object.assign(patch, { open: new Set(), cur: null, stack: [], q: "", flt: new Set() });
  }
  if (q != null) patch.q = q;
  set(patch);
  syncURL(true);
}

/** setBy: the grouping of the view open, regrouped in place (Servers and ToDo each keep their own). */
export function setBy(b: By) {
  const s = get();
  if (!isTree(s.view)) {
    local.set("by", b);
    set({ tby: b });
    go("todo");
    return;
  }
  if (s.view === "servers") {
    local.set("sby", b);
    set({ sby: b });
  } else {
    local.set("by", b);
    set({ tby: b });
  }
  set({ open: new Set(), cur: null, stack: [] });
  syncURL();
}

/** openServer: a server's card, on Servers. */
export function openServer(name: string) {
  const s = get();
  set({ wantHost: name, q: "", flt: new Set(), sby: "host", lens: s.view === "servers" ? s.lens : "priorities" });
  if (s.view !== "servers") go("servers");
  else syncURL();
}

export function setScope(patch: { org?: string; env?: string; run?: string }) {
  if (patch.org != null) local.set("org", patch.org);
  if (patch.env != null) local.set("env", patch.env);
  set({ ...patch, cur: null, stack: [], open: new Set(), vitem: null, vsel: "", vstack: [] });
  syncURL();
}

// the address: /servers?org=…&env=…&run=…&by=…&show=…&f=accepted&host=…&lang=…
export function syncURL(push = false) {
  const s = get();
  if (s.view === "setup") return;
  const keep = new URLSearchParams(location.search).get("lang");
  const host = s.view === "servers" ? s.wantHost || cardHost(s) : s.view === "history" && s.vitem?.kind === "host" ? s.vitem.name : "";
  const show = s.view === "servers" && s.lens !== "priorities" ? s.lens : "";
  const f = s.view === "todo" && s.accepted ? "accepted" : "";
  const b = s.view === "todo" && s.tby !== "fix" ? s.tby : s.view === "servers" && s.sby !== "host" ? s.sby : "";
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries({ org: s.org, env: s.env, run: s.run !== "current" ? s.run : "", by: b, show, f, host, lang: keep || "" }))
    if (v) p.set(k, v);
  const u = "/" + s.view + (p.size ? "?" + p : "");
  if (u !== location.pathname + location.search) history[push ? "pushState" : "replaceState"](null, "", u);
}
const cardHost = (s: State) => (serverList(s) && s.cur?.startsWith("h:") && !s.cur.includes("/") ? s.cur.slice(2) : "");

export function readURL() {
  const p = new URLSearchParams(location.search);
  const v = location.pathname.replace(/^\/+|\/+$/g, "").split("/")[0];
  const view: View = v === "servers" || v === "todo" || v === "history" ? v : v === "setup" ? "setup" : "servers";
  const patch: Partial<State> = { view, lens: p.get("show") || "priorities", accepted: view === "todo" && p.get("f") === "accepted" };
  if (p.get("org")) patch.org = p.get("org")!;
  if (p.get("env")) patch.env = p.get("env")!;
  patch.run = p.get("run") || "current";
  patch.wantHost = view === "servers" || view === "history" ? p.get("host") || "" : "";
  if (view === "todo" && p.get("by")) patch.tby = by(p.get("by"), get().tby);
  if (view === "servers") patch.sby = p.get("by") === "fix" || p.get("by") === "cve" ? (p.get("by") as By) : "host";
  set(patch);
}

export function setTheme(theme: string) {
  local.set("theme", theme);
  set({ theme });
  applyTheme();
}
const darkMQ = matchMedia("(prefers-color-scheme: dark)");
export function applyTheme() {
  const th = get().theme;
  document.documentElement.dataset.theme = th === "system" ? (darkMQ.matches ? "dark" : "light") : th;
}
darkMQ.addEventListener("change", applyTheme);

/** toggle: a set with one value added or removed (a new set: the store sees the change). */
export const toggle = <T,>(xs: Set<T>, x: T) => {
  const n = new Set(xs);
  if (n.has(x)) n.delete(x);
  else n.add(x);
  return n;
};
