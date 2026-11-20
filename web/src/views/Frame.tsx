// The frame around the views: the top bar (where the data stands, ⌘K, settings), the tab bar (the places and the
// scan), and the left rail: which organization, environment and data, then the filters of the place shown.
import { useEffect, useRef, useState } from "react";
import { t } from "../lib/i18n";
import { post } from "../lib/api";
import { ago, runLabel } from "../lib/format";
import { go, set, setScope, toast, toggle, toggleMini, useApp, useS, type View } from "../state";
import { client, useDB, useEnv, useOrgs, useRunData, useSession, useTree, useVersion } from "../queries";
import { Icon } from "../components/ui";
import { Newer, Prefs, ScanLimits, startScan } from "./Shell";
import { useMemoParams } from "./Todo";
import type { Org } from "../types";

/** scopes: every org/env there is; Overview is a place only when there is more than one. */
export const scopes = (orgs: Org[]) => orgs.flatMap((o) => o.envs.map((e) => ({ org: o, env: e })));

const TABS: [View, string, string][] = [
  ["overview", "Overview", "grid"],
  ["todo", "Fixes", "plan"],
  ["servers", "Servers", "server"],
  ["history", "History", "clock"],
];

/** usePopover: open state for a menu that closes on Escape or a click outside it. */
function usePopover() {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    const esc = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    addEventListener("mousedown", away);
    addEventListener("keydown", esc);
    return () => {
      removeEventListener("mousedown", away);
      removeEventListener("keydown", esc);
    };
  }, [open]);
  return [open, setOpen, ref] as const;
}

/** TopBar: the brand, how old the data and the vulnerability list are, a newer release, ⌘K and the settings. */
export function TopBar() {
  const s = useS((s) => ({ org: s.org, env: s.env, sideOpen: s.sideOpen }));
  const e = useOrgs()
    .data?.orgs.find((o) => o.id === s.org)
    ?.envs.find((x) => x.env === s.env);
  const db = useDB().data;
  const newer = useVersion().data;
  const dbOld = db && (db.dbs || []).some((d: any) => d.outdated);
  const dbAt =
    db &&
    ((db.dbs || [])
      .map((d: any) => d.updated)
      .filter(Boolean)
      .sort()[0] as string | undefined);
  const [gearOpen, setGearOpen, gearRef] = usePopover();
  return (
    <header className="topbar">
      <button
        className="btn icon ghost menubtn"
        aria-label={t("Filters")}
        aria-controls="side"
        aria-expanded={s.sideOpen}
        onClick={() => (matchMedia("(max-width: 860px)").matches ? set({ sideOpen: !s.sideOpen }) : toggleMini())}
      >
        <Icon name="menu" />
      </button>
      <span className="brand2">
        <img src="/logo.webp" alt="" /> kanareika
      </span>
      <span className="tstat">
        {e && (
          <span className="tsi" title={e.last ? e.last.finished : ""}>
            <span className={"dot " + (e.last ? "" : "warn")} />
            {e.last ? t("scanned {age}", { age: ago(e.last.finished) }) : t("not scanned yet")}
          </span>
        )}
        {db && (
          <span className="tsi">
            <span className={"dot " + (dbOld || db.feeds_outdated ? "warn" : "")} />
            {db.updating ? t("downloading…") : dbAt ? t("DB {age}", { age: ago(dbAt) }) : t("not downloaded")}
          </span>
        )}
        {newer?.latest && <Newer v={newer.latest} link={newer.url} />}
      </span>
      <button className="btn ghost palbtn" aria-label={t("Command palette")} onClick={() => set({ palOpen: true })}>
        <kbd>⌘K</kbd>
      </button>
      <div className="pop" ref={gearRef}>
        <button className="btn icon ghost" aria-label={t("Settings")} aria-expanded={gearOpen} onClick={() => setGearOpen(!gearOpen)}>
          <Icon name="gear" />
        </button>
        {gearOpen && (
          <div className="menu right" role="dialog" aria-label={t("Settings")}>
            <div className="foot2">
              <Prefs />
            </div>
            {s.org && s.env && <ScanLimits org={s.org} env={s.env} />}
          </div>
        )}
      </div>
    </header>
  );
}

/** TabBar: the places (Overview only with more than one org/env) and the scan of what is shown, or of more. */
export function TabBar() {
  const s = useS((s) => ({ view: s.view, org: s.org, env: s.env }));
  const orgs = useOrgs().data?.orgs || [];
  const o = orgs.find((x) => x.id === s.org),
    e = o?.envs.find((x) => x.env === s.env);
  const rd = useRunData(s.view === "todo" || s.view === "servers" || s.view === "history").data;
  const multi = scopes(orgs).length > 1;
  const off = !orgs.length || !e?.last;
  const href = (v: View) => "/" + v + "?" + new URLSearchParams({ org: s.org, env: s.env });
  const fixes = rd?.totals?.fixes;
  return (
    <nav className="tabbar" aria-label={t("Places")}>
      {TABS.filter(([v]) => v !== "overview" || multi).map(([v, l, i]) => (
        <a
          key={v}
          href={href(v)}
          className={off && v !== "overview" ? "off" : ""}
          aria-current={s.view === v ? "page" : undefined}
          onClick={(ev) => {
            if (ev.metaKey || ev.ctrlKey || ev.shiftKey) return;
            ev.preventDefault();
            go(v);
          }}
        >
          <Icon name={i} />
          <span>{t(l)}</span>
          {v === "servers" && e ? (
            <span className="n">{e.hosts}</span>
          ) : v === "todo" && fixes != null ? (
            <span className="n hot">{fixes}</span>
          ) : null}
        </a>
      ))}
      <ScanMenu />
    </nav>
  );
}

/** ScanMenu: scan the environment shown; its ▾ scans every environment of the org, or of every org, one after
 * another. */
function ScanMenu() {
  const s = useS((s) => ({ org: s.org, env: s.env, view: s.view }));
  const scans = useSession().data?.scans;
  const orgs = useOrgs().data?.orgs || [];
  const o = orgs.find((x) => x.id === s.org);
  const [menuOpen, setMenuOpen, menuRef] = usePopover();
  if (!scans || !o || !s.env || s.view === "setup") return null;
  const all = async (org: string) => {
    setMenuOpen(false);
    try {
      const r = await post("/api/scan/all", org ? { org } : {});
      const n = (r.ids || []).length;
      toast(n ? t("Scans queued: {n}", { n }) : t("Nothing to scan: every environment is being scanned already"));
      client.invalidateQueries({ queryKey: ["jobs"] });
    } catch (err: any) {
      toast(err.message);
    }
  };
  const several = o.envs.length > 1,
    many = orgs.length > 1;
  return (
    <div className="pop scanbtn" ref={menuRef}>
      <button className="btn primary" onClick={() => startScan(s.org, s.env)}>
        <Icon name="scan" />
        {t("Scan {env}", { env: s.env })}
      </button>
      {(several || many) && (
        <button className="btn primary more" aria-label={t("More scans")} aria-expanded={menuOpen} onClick={() => setMenuOpen(!menuOpen)}>
          <Icon name="chev" />
        </button>
      )}
      {menuOpen && (
        <div className="menu right" role="menu">
          {several && (
            <button role="menuitem" onClick={() => all(o.id)}>
              {t("Every environment of {org}", { org: o.name || o.id })}
            </button>
          )}
          {many && (
            <button role="menuitem" onClick={() => all("")}>
              {t("Everything")}
            </button>
          )}
        </div>
      )}
    </div>
  );
}

/** Rail: which organization, environment and data the places show, then the filters of the place shown. */
export function Rail() {
  const s = useS((s) => ({ view: s.view, org: s.org, env: s.env, run: s.run, sideOpen: s.sideOpen }));
  const orgs = useOrgs().data?.orgs || [];
  const scans = useSession().data?.scans;
  const runs = useEnv().data?.runs || [];
  const o = orgs.find((x) => x.id === s.org);
  return (
    <aside className={"side rail" + (s.sideOpen ? " open" : "")} id="side" aria-label={t("Filters")}>
      {orgs.length > 0 && (
        <div className="rsec scope3">
          <label>
            <span>{t("Organization")}</span>
            <select
              value={s.org}
              onChange={(ev) => {
                const v = ev.target.value;
                if (v === "__new") return set({ view: "setup" });
                setScope({ org: v, env: orgs.find((x) => x.id === v)?.envs[0]?.env || "", run: "current" });
              }}
            >
              {orgs.map((x) => (
                <option key={x.id} value={x.id}>
                  {x.name || x.id}
                </option>
              ))}
              {scans && <option value="__new">+ {t("Add servers…")}</option>}
            </select>
          </label>
          <label>
            <span>{t("Environment")}</span>
            <select value={s.env} onChange={(ev) => setScope({ env: ev.target.value, run: "current" })}>
              {(o?.envs || []).map((x) => (
                <option key={x.env} value={x.env}>
                  {x.env} · {x.hosts}
                  {x.last ? "" : " · " + t("no scans")}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span>{t("Data as of")}</span>
            <select value={s.run} onChange={(ev) => setScope({ run: ev.target.value })}>
              <option value="current">{t("Current state")}</option>
              {runs
                .slice(-20)
                .reverse()
                .map((r: any) => (
                  <option key={r.run_id} value={r.run_id}>
                    {runLabel(r.run_id)}
                    {r.partial ? " · " + t("partial") : ""}
                  </option>
                ))}
            </select>
          </label>
        </div>
      )}
      {s.view === "todo" && <FixFilters />}
      {s.view === "servers" && <ServerFilters />}
      <button className="lnk railhide" onClick={toggleMini}>
        {t("Hide filters")}
      </button>
    </aside>
  );
}

const RISK: [string, string][] = [
  ["kev", "KEV"],
  ["rce", "pre-auth RCE"],
  ["epss", "EPSS ≥ 10%"],
  ["front", "Public"],
];
const STATE: [string, string][] = [
  ["ready", "fix ready"],
  ["nofix", "no fix yet"],
  ["overdue", "overdue"],
];

/** Check: one filter: its box, its name and how many fixes it would leave. */
function Check({ k, label, n }: { k: string; label: string; n?: number }) {
  const on = useApp((s) => s.flt.has(k));
  return (
    <label className={"fck" + (n === 0 && !on ? " zero" : "")}>
      <input type="checkbox" checked={on} onChange={() => set((st) => ({ flt: toggle(st.flt, k) }))} />
      <span>{label}</span>
      {n != null && <span className="n">{n}</span>}
    </label>
  );
}

/** FixFilters: Fixes' filters with the count each would leave: priorities (any of those chosen), risk, state;
 * accepted risks and backported findings are lists of their own. */
function FixFilters() {
  const s = useS((s) => ({ flt: s.flt, accepted: s.accepted, backport: s.backport }));
  const tr = useTree(useApp(useMemoParams)).data;
  const fc = tr?.facets || {};
  const active = s.flt.size + (s.accepted ? 1 : 0) + (s.backport ? 1 : 0);
  return (
    <div className="rsec">
      <div className="rhead">
        <span>{t("Filters")}</span>
        {active > 0 && (
          <button className="lnk" onClick={() => set({ flt: new Set(), accepted: false, backport: false, cur: null })}>
            {t("Clear {n}", { n: active })}
          </button>
        )}
      </div>
      {!s.accepted && (
        <>
          <h4>{t("Priority")}</h4>
          <div className="pills" role="group" aria-label={t("Priority")}>
            {["P1", "P2", "P3", "P4"].map((p) => {
              const k = p.toLowerCase();
              return (
                <button key={p} aria-pressed={s.flt.has(k)} onClick={() => set((st) => ({ flt: toggle(st.flt, k) }))}>
                  <b className={"pc " + k}>{p}</b>
                  <span>{fc[k] ?? ""}</span>
                </button>
              );
            })}
          </div>
          <h4>{t("Risk")}</h4>
          {RISK.map(([k, l]) => (
            <Check key={k} k={k} label={t(l)} n={fc[k]} />
          ))}
          <h4>{t("State")}</h4>
          {STATE.map(([k, l]) => (
            <Check key={k} k={k} label={t(l)} n={fc[k]} />
          ))}
        </>
      )}
      <label className="fck">
        <input
          type="checkbox"
          checked={s.accepted}
          onChange={() => set((st) => ({ accepted: !st.accepted, cur: null, vitem: null, vsel: "" }))}
        />
        <span>{t("accepted")}</span>
      </label>
      {!s.accepted && (s.backport || !!tr?.hidden_backported) && (
        <label className="fck" title={t("Already fixed by a backport: the package's changelog lists the CVE as fixed")}>
          <input type="checkbox" checked={s.backport} onChange={() => set((st) => ({ backport: !st.backport }))} />
          <span>{t("backported")}</span>
          {!s.backport && tr?.hidden_backported ? <span className="n">{tr.hidden_backported}</span> : null}
        </label>
      )}
    </div>
  );
}

/** ServerFilters: Servers' filters (what is under each server); P4 shown or not in the priority columns. */
function ServerFilters() {
  const s = useS((s) => ({ flt: s.flt, p4: s.p4, lens: s.lens }));
  if (s.lens !== "priorities") return null;
  return (
    <div className="rsec">
      <div className="rhead">
        <span>{t("Filters")}</span>
        {s.flt.size > 0 && (
          <button className="lnk" onClick={() => set({ flt: new Set() })}>
            {t("Clear {n}", { n: s.flt.size })}
          </button>
        )}
      </div>
      <h4>{t("Risk")}</h4>
      <Check k="kev" label="KEV" />
      <Check k="front" label={t("Public")} />
      <h4>{t("State")}</h4>
      <Check k="overdue" label={t("overdue")} />
      <label className="fck">
        <input type="checkbox" checked={s.p4} onChange={() => set((st) => ({ p4: !st.p4 }))} />
        <span>{t("Show P4")}</span>
      </label>
    </div>
  );
}
