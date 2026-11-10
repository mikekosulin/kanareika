// The frame around the views: the sidebar (org, environment, data; the views; the data's age; language and
// theme), the running scan's banner, the page for an environment never scanned, the ⌘K palette.
import { useEffect, useMemo, useRef, useState } from "react";
import { LANG, LANG_NAMES, t } from "../lib/i18n";
import { local } from "../lib/local";
import { post } from "../lib/api";
import { ago, runLabel } from "../lib/format";
import { go, isTree, openServer, set, setBy, setScope, setTheme, syncURL, toast, useApp, useS, type View } from "../state";
import { client, useDB, useEnv, useJobs, useOrgs, useRunData, useSession } from "../queries";
import { Icon } from "../components/ui";

const NAV: [View, string, string][] = [
  ["servers", "Servers", "server"],
  ["todo", "ToDo", "list"],
  ["history", "History", "clock"],
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

function Sel(p: { id: string; label: string; opts: [string, string][]; value: string; onChange: (v: string) => void }) {
  return (
    <label className="srow">
      <span className="sl">{p.label}</span>
      <select id={p.id} aria-label={p.label} value={p.value} onChange={(e) => p.onChange(e.target.value)}>
        {p.opts.map(([v, txt]) => (
          <option key={v} value={v}>
            {txt}
          </option>
        ))}
      </select>
      <Icon name="chev" />
    </label>
  );
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
        {[["light", "sun", "Light"], ["system", "monitor", "System"], ["dark", "moon", "Dark"]].map(([v, i, l]) => (
          <button key={v} role="radio" aria-checked={theme === v} title={t(l)} aria-label={t(l)} onClick={() => setTheme(v)}>
            <Icon name={i} />
          </button>
        ))}
      </div>
    </>
  );
}

export function Sidebar() {
  const s = useS((s) => ({ view: s.view, org: s.org, env: s.env, run: s.run, sideOpen: s.sideOpen }));
  const orgs = useOrgs().data?.orgs || [];
  const env = useEnv().data;
  const scans = useSession().data?.scans;
  const db = useDB().data;
  const rd = useRunData(isTree(s.view) || s.view === "history").data;
  const o = orgs.find((x) => x.id === s.org), e = o?.envs.find((x) => x.env === s.env);
  const orgOpts: [string, string][] = orgs.map((x) => [x.id, x.name || x.id]);
  if (scans) orgOpts.push(["__new", "+ " + t("Add servers…")]);
  const runs = env?.runs || [];
  const dbOld = db && (db.dbs || []).some((d: any) => d.outdated), feedsOld = db?.feeds_outdated;
  const dbAt = db && (db.dbs || []).map((d: any) => d.updated).filter(Boolean).sort()[0];
  const off = !orgs.length || (s.view === "setup" && !e?.last);
  const href = (v: View) => "/" + v + "?" + new URLSearchParams({ org: s.org, env: s.env });
  const fixes = rd?.totals?.fixes;
  return (
    <aside className={"side" + (s.sideOpen ? " open" : "")} id="side" aria-label="Navigation">
      <div className="brand">
        <img src="/logo.webp" alt="" /> kanareika
        <button className="btn ghost" style={{ marginLeft: "auto", height: 26, padding: "0 6px" }} aria-label="Command palette" onClick={() => set({ palOpen: true })}>
          <kbd>⌘K</kbd>
        </button>
      </div>
      <div className="scope2">
        {orgs.length > 0 && (
          <>
            <Sel
              id="org" label={t("Org")} opts={orgOpts} value={s.org}
              onChange={(v) => {
                if (v === "__new") {
                  set({ view: "setup" });
                  return;
                }
                setScope({ org: v, env: orgs.find((x) => x.id === v)?.envs[0]?.env || "", run: "current" });
              }}
            />
            <Sel id="env" label={t("Env")} value={s.env}
              opts={(o?.envs || []).map((x) => [x.env, `${x.env} · ${x.hosts}${x.last ? "" : " · " + t("no scans")}`])}
              onChange={(v) => setScope({ env: v, run: "current" })} />
            <Sel id="run" label={t("Data")} value={s.run}
              opts={[["current", t("Current state")], ...runs.slice(-20).reverse().map((r: any): [string, string] => [r.run_id, runLabel(r.run_id) + (r.partial ? " · " + t("partial") : "")])]}
              onChange={(v) => setScope({ run: v })} />
          </>
        )}
      </div>
      <nav className="nav">
        {off ? (
          <>
            {NAV.map(([v, l, i]) => (
              <a key={v} className="off" aria-disabled="true" title={t("Available after the first scan")}>
                <Icon name={i} />
                {t(l)}
              </a>
            ))}
            <div className="navnote">{t("Available after the first scan")}</div>
          </>
        ) : (
          NAV.map(([v, l, i]) => (
            <a
              key={v}
              href={href(v)}
              aria-current={s.view === v ? "page" : undefined}
              onClick={(ev) => {
                if (ev.metaKey || ev.ctrlKey || ev.shiftKey) return;
                ev.preventDefault();
                go(v);
              }}
            >
              <Icon name={i} />
              {t(l)}
              {v === "servers" && e ? <span className="n">{e.hosts}</span> : v === "todo" && fixes != null ? <span className="n hot">{fixes}</span> : null}
            </a>
          ))
        )}
      </nav>
      <div className="status">
        {e && (
          <div className="row">
            <span className={"dot " + (e.last ? "" : "warn")} />
            <span>
              {t("Data")} <b>{e.last ? ago(e.last.finished) : t("none yet")}</b>
              {e.last ? ` · ${e.last.hosts_total - (e.last.hosts_failed || 0)}/${e.last.hosts_total} ${t("hosts")}` : ""}
            </span>
          </div>
        )}
        {db && (
          <div className="row">
            <span className={"dot " + (dbOld || feedsOld ? "warn" : "")} />
            <span>
              {t("Vulnerability list")} <b>{db.updating ? t("downloading…") : dbAt ? ago(dbAt) : t("not downloaded")}</b>
              {feedsOld && dbAt ? " · " + t("exploit data old") : ""}
            </span>
          </div>
        )}
        {scans && e && s.view !== "setup" && (
          <button className="btn" onClick={() => startScan(s.org, s.env)}>
            <Icon name="scan" />
            {t("Scan {env}…", { env: s.env })}
          </button>
        )}
        <div className="foot2">
          <Prefs />
        </div>
      </div>
    </aside>
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
  useEffect(() => {
    if (palOpen) {
      setQ("");
      setPi(0);
      setTimeout(() => inRef.current?.focus());
    }
  }, [palOpen]);
  const items = useMemo(() => {
    if (!palOpen) return [];
    const it: PalItem[] = [];
    // the fixes of the tree on screen (its top rows and what is open under them)
    const trees = client.getQueriesData<any>({ queryKey: ["tree"] });
    const tr = trees.length ? trees[trees.length - 1][1] : null;
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
    NAV.forEach(([v, l]) => it.push({ g: t("Go to"), label: t(l), hint: v === "todo" ? "/" : "/" + v, go: () => go(v) }));
    [["priorities", "Priorities"], ["logins", "Logins"], ["network", "Network"], ["health", "Health"]].forEach(([id, l]) =>
      it.push({ g: t("Go to"), label: t(l), hint: "/servers?show=" + id, go: () => { set({ lens: id, sby: "host" }); if (view !== "servers") go("servers"); else syncURL(); } }),
    );
    it.push({ g: t("Go to"), label: t("Accepted risks"), hint: "/todo?f=accepted", go: () => { set({ accepted: true }); if (view !== "todo") go("todo"); else syncURL(); } });
    (envd?.hosts || []).forEach((h) => it.push({ g: t("Servers"), label: h.name, hint: h.group || "", go: () => openServer(h.name) }));
    ([["fix", "Group by fix"], ["cve", "Group by CVE"]] as const).forEach(([k, l]) => it.push({ g: t("Commands"), label: t(l), hint: "/todo", go: () => setBy(k) }));
    if (scans && env) it.push({ g: t("Commands"), label: t("Scan {env}", { env }), hint: "", go: () => startScan(org, env) });
    if (scans) it.push({ g: t("Commands"), label: t("Add servers…"), hint: "", go: () => set({ view: "setup" }) });
    const qq = q.trim().toLowerCase();
    return (qq ? it.filter((x) => x.label.toLowerCase().includes(qq)) : it.filter((x) => x.g !== t("Inside") && x.g !== t("Servers"))).slice(0, 50);
  }, [palOpen, q, view, envd, scans, org, env]);
  const pick = (x?: PalItem) => {
    set({ palOpen: false });
    x?.go();
  };
  let g = "";
  return (
    <div className={"pal" + (palOpen ? " on" : "")} role="dialog" aria-label="Command palette" onClick={(e) => e.target === e.currentTarget && set({ palOpen: false })}>
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
              return (
                <PalRow key={i} head={head} x={x} on={i === pi} onPick={() => pick(x)} />
              );
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
