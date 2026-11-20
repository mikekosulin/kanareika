// Pieces of the frame (Frame.tsx lays it out): language and theme, scan limits, a newer release, the running scan's
// banner, the page for an environment never scanned, the ⌘K palette.
import { useEffect, useMemo, useRef, useState } from "react";
import { LANG, LANG_NAMES, t } from "../lib/i18n";
import { local } from "../lib/local";
import { api, post, qs } from "../lib/api";
import { useQuery } from "@tanstack/react-query";
import { webURL } from "../lib/format";
import { go, isTree, openServer, set, setBy, setTheme, syncURL, toast, useApp, useS, type View } from "../state";
import { client, useEnv, useJobs, useSession } from "../queries";
import { Icon } from "../components/ui";

// the places the palette goes to (Frame's tabs; Overview is reached from the tabs)
const PLACES: [View, string][] = [
  ["todo", "Fixes"],
  ["servers", "Servers"],
  ["history", "History"],
];

export async function startScan(org: string, env: string, hosts?: string[]) {
  try {
    const r = await post("/api/scan", { org, env, hosts });
    toast(t("Scan started"));
    client.invalidateQueries({ queryKey: ["jobs"] });
    return r.id as string;
  } catch (e: any) {
    toast(e.message);
    return null;
  }
}

export function Prefs() {
  const theme = useApp((s) => s.theme);
  return (
    <>
      <label className="langw" title={t("Language")}>
        <select
          aria-label={t("Language")}
          value={LANG}
          onChange={(e) => {
            local.set("lang", e.target.value);
            const u = new URL(location.href);
            u.searchParams.delete("lang");
            location.href = u.toString();
          }}
        >
          {Object.entries(LANG_NAMES).map(([k, n]) => (
            <option key={k} value={k}>
              {n}
            </option>
          ))}
        </select>
        <span className="lv">{LANG.toUpperCase()}</span>
        <Icon name="chev" />
      </label>
      <div className="seg3" role="radiogroup" aria-label={t("Theme")}>
        {[
          ["light", "sun", "Light"],
          ["system", "monitor", "System"],
          ["dark", "moon", "Dark"],
        ].map(([v, i, l]) => (
          <button key={v} role="radio" aria-checked={theme === v} title={t(l)} aria-label={t(l)} onClick={() => setTheme(v)}>
            <Icon name={i} />
          </button>
        ))}
      </div>
    </>
  );
}

type Limit = { value: number; source: "default" | "settings" | "org" | "flag" };

/** ScanLimits: how many hosts a scan reads at once (SSH) and how many trivy matches run at once (memory). Saved in
 * the install's settings; an org file's or a flag's value is shown, not edited here. */
/** Newer: a newer kanareika release, linked to its page. */
export function Newer({ v, link }: { v: string; link?: string }) {
  const url = webURL(link);
  return url ? (
    <div className="row">
      <span className="dot warn" />
      <a href={url} target="_blank" rel="noreferrer">
        {t("Update: {v}", { v })}
      </a>
    </div>
  ) : null;
}

export function ScanLimits({ org, env }: { org: string; env: string }) {
  const [open, setOpen] = useState(false);
  const o = useQuery({
    queryKey: ["scanopts", org, env],
    queryFn: ({ signal }) =>
      api<{ limits: Record<"parallel" | "trivy_parallel", Limit>; limits_max: number }>("/api/scan-options?" + qs({ org, env }), signal),
  });
  const l = o.data?.limits;
  if (!l) return null;
  const save = async (k: "parallel" | "trivy_parallel", v: number) => {
    try {
      await post("/api/settings/scan", { [k]: v });
      client.invalidateQueries({ queryKey: ["scanopts"] });
    } catch (e: any) {
      toast(e.message);
    }
  };
  const field = (k: "parallel" | "trivy_parallel", label: string) => {
    const x = l[k],
      fixed = x.source === "org" || x.source === "flag";
    return (
      <label className="lim" title={fixed ? t(x.source === "org" ? "Set in the org file" : "Set by a flag") : undefined}>
        <span>{label}</span>
        <input
          type="number"
          min={1}
          max={o.data!.limits_max}
          defaultValue={x.value}
          key={x.value + x.source}
          disabled={fixed}
          onBlur={(e) => {
            const v = Math.round(+e.target.value);
            if (v >= 1 && v <= o.data!.limits_max && v !== x.value) save(k, v);
          }}
          onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLInputElement).blur()}
        />
      </label>
    );
  };
  return (
    <div className="lims">
      <button className="row lrow" aria-expanded={open} onClick={() => setOpen(!open)}>
        <Icon name="chev" />
        <span>{t("At once: {h} hosts, {n} trivy", { h: l.parallel.value, n: l.trivy_parallel.value })}</span>
      </button>
      {open && (
        <div className="limf">
          {field("parallel", t("Hosts"))}
          {field("trivy_parallel", "trivy")}
        </div>
      )}
    </div>
  );
}

/** Banner: the scan of this environment that is running, its last line, a way to stop it. */
export function Banner() {
  const { org, env } = useS((s) => ({ org: s.org, env: s.env }));
  const jobs = useJobs().data || [];
  const j = jobs.find((x: any) => x.state === "running" && x.request.org === org && x.request.env === env);
  if (!j) return null;
  return (
    <div className="banner">
      <Icon name="scan" />
      <span>
        <b>{t("Scanning {env}", { env })}</b> · {(j.output || []).slice(-1)[0] || ""}
      </span>
      <button
        className="btn ghost"
        onClick={async () => {
          try {
            await post(`/api/jobs/${j.id}/cancel`);
          } catch (e: any) {
            toast(e.message);
          }
        }}
      >
        {t("Cancel")}
      </button>
    </div>
  );
}

export function NoRuns() {
  const { org, env } = useS((s) => ({ org: s.org, env: s.env }));
  const scans = useSession().data?.scans;
  return (
    <>
      <Banner />
      <div className="onb">
        <h2>{t("No scans of {env} yet", { env })}</h2>
        <p>{t("Kanareika connects to the servers over SSH, reads what is installed and how they are set up, and changes nothing.")}</p>
        {scans ? (
          <div className="actions">
            <button className="btn primary" onClick={() => startScan(org, env)}>
              <Icon name="scan" />
              {t("Start the first scan")}
            </button>
          </div>
        ) : (
          <p className="note">{t("Scans are started where kanareika web runs on localhost (or with a token).")}</p>
        )}
      </div>
    </>
  );
}

type PalItem = { g: string; label: string; hint: string; go: () => void };

/** Palette: ⌘K: jump to a fix, a server, a view; a command. */
export function Palette() {
  const { palOpen, view, org, env } = useS((s) => ({ palOpen: s.palOpen, view: s.view, org: s.org, env: s.env }));
  const [q, setQ] = useState("");
  const [pi, setPi] = useState(0);
  const inRef = useRef<HTMLInputElement>(null);
  const envd = useEnv().data;
  const scans = useSession().data?.scans;
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        set({ palOpen: true });
      }
    };
    addEventListener("keydown", k);
    return () => removeEventListener("keydown", k);
  }, []);
  const [was, setWas] = useState(palOpen);
  if (palOpen !== was) {
    // opened: a new search
    setWas(palOpen);
    if (palOpen) {
      setQ("");
      setPi(0);
    }
  }
  useEffect(() => {
    if (palOpen) setTimeout(() => inRef.current?.focus());
  }, [palOpen]);
  const items = useMemo(() => {
    if (!palOpen) return [];
    const it: PalItem[] = [];
    // the fixes of the tree on screen (its top rows and what is open under them)
    const trees = client.getQueriesData<any>({ queryKey: ["tree"] });
    const last = trees.length ? trees[trees.length - 1][1] : null;
    const tr = last?.pages ? { nodes: last.pages.flatMap((pg: any) => pg.nodes || []) } : last; // the pages loaded so far
    const walk = (ns: any[], depth: number) =>
      ns.forEach((n) => {
        if (n.kind !== "section")
          it.push({
            g: depth ? t("Inside") : t("Fixes"),
            label: `${n.priority} · ${n.label}${n.fixed ? " → " + n.fixed : ""}`,
            hint: n.hosts ? t("{n} hosts", { n: n.hosts }) : "",
            go: () => {
              if (!isTree(view)) go("todo");
              set({ cur: n.id });
            },
          });
        if (depth < 2) walk(n.kids || [], depth + 1);
      });
    if (view !== "servers") walk(tr?.nodes || [], 0);
    PLACES.forEach(([v, l]) => it.push({ g: t("Go to"), label: t(l), hint: "/" + v, go: () => go(v) }));
    [
      ["priorities", "Priorities"],
      ["logins", "Logins"],
      ["network", "Network"],
      ["health", "Health"],
    ].forEach(([id, l]) =>
      it.push({
        g: t("Go to"),
        label: t(l),
        hint: "/servers?show=" + id,
        go: () => {
          set({ lens: id, sby: "host" });
          if (view !== "servers") go("servers");
          else syncURL();
        },
      }),
    );
    it.push({
      g: t("Go to"),
      label: t("Accepted risks"),
      hint: "/todo?f=accepted",
      go: () => {
        set({ accepted: true });
        if (view !== "todo") go("todo");
        else syncURL();
      },
    });
    (envd?.hosts || []).forEach((h) => it.push({ g: t("Servers"), label: h.name, hint: h.group || "", go: () => openServer(h.name) }));
    (
      [
        ["fix", "Group by fix"],
        ["cve", "Group by CVE"],
      ] as const
    ).forEach(([k, l]) => it.push({ g: t("Commands"), label: t(l), hint: "/todo", go: () => setBy(k) }));
    if (scans && env) it.push({ g: t("Commands"), label: t("Scan {env}", { env }), hint: "", go: () => startScan(org, env) });
    if (scans) it.push({ g: t("Commands"), label: t("Add servers…"), hint: "", go: () => set({ view: "setup" }) });
    const qq = q.trim().toLowerCase();
    return (
      qq ? it.filter((x) => x.label.toLowerCase().includes(qq)) : it.filter((x) => x.g !== t("Inside") && x.g !== t("Servers"))
    ).slice(0, 50);
  }, [palOpen, q, view, envd, scans, org, env]);
  const pick = (x?: PalItem) => {
    set({ palOpen: false });
    x?.go();
  };
  let g = "";
  return (
    <div
      className={"pal" + (palOpen ? " on" : "")}
      role="dialog"
      aria-label="Command palette"
      onClick={(e) => e.target === e.currentTarget && set({ palOpen: false })}
    >
      <div className="box">
        <input
          ref={inRef}
          placeholder="Jump to a fix, CVE, host or view…"
          autoComplete="off"
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setPi(0);
          }}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") {
              e.preventDefault();
              setPi((i) => Math.min(i + 1, items.length - 1));
            } else if (e.key === "ArrowUp") {
              e.preventDefault();
              setPi((i) => Math.max(0, i - 1));
            } else if (e.key === "Enter") pick(items[pi]);
            else if (e.key === "Escape") set({ palOpen: false });
          }}
        />
        <ul role="listbox">
          {items.length ? (
            items.map((x, i) => {
              const head = x.g !== g ? (g = x.g) : null;
              return <PalRow key={i} head={head} x={x} on={i === pi} onPick={() => pick(x)} />;
            })
          ) : (
            <div className="grp">{t("Nothing found")}</div>
          )}
        </ul>
      </div>
    </div>
  );
}

function PalRow({ head, x, on, onPick }: { head: string | null; x: PalItem; on: boolean; onPick: () => void }) {
  const ref = useRef<HTMLLIElement>(null);
  useEffect(() => {
    if (on) ref.current?.scrollIntoView({ block: "nearest" });
  }, [on]);
  return (
    <>
      {head && <div className="grp">{head}</div>}
      <li ref={ref} role="option" aria-selected={on} onClick={onPick}>
        {x.label}
        <small>{x.hint}</small>
      </li>
    </>
  );
}
