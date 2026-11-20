// The frame around the views (B2): the top bar (which organization and environment, where the data stands, ⌘K,
// settings), the tab bar (the places and the scan), and the left rail with the filters of the place shown. On a
// narrow window the organization and environment are one button opening a sheet, and the rail is a sheet too.
import { useEffect, useRef, useState } from "react";
import { t } from "../lib/i18n";
import { post } from "../lib/api";
import { ago, runLabel } from "../lib/format";
import { go, set, setScope, toast, toggle, useApp, useS, type View } from "../state";
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

const NARROW = "(max-width: 860px)";

/** useNarrow: the rail is a sheet over the page, not a column beside it. */
export function useNarrow() {
  const [n, setN] = useState(() => matchMedia(NARROW).matches);
  useEffect(() => {
    const m = matchMedia(NARROW);
    const f = () => setN(m.matches);
    m.addEventListener("change", f);
    return () => m.removeEventListener("change", f);
  }, []);
  return n;
}

/** TopBar: the brand, which org and environment (two pickers; one button and a sheet on a narrow window), how old
 * the data and the vulnerability list are, a newer release, ⌘K, the scan on a phone, and the settings. */
export function TopBar() {
  const s = useS((s) => ({ org: s.org, env: s.env, run: s.run, scopeOpen: s.scopeOpen }));
  const o = useOrgs().data?.orgs.find((o) => o.id === s.org);
  const e = o?.envs.find((x) => x.env === s.env);
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
      <span className="brand2">
        <img src="/logo.webp" alt="" /> <span className="bn">kanareika</span>
      </span>
      {o && (
        <>
          <span className="crumbs">
            <OrgPicker />
            <span className="sep">/</span>
            <EnvPicker />
          </span>
          <button className="scopebtn2" aria-haspopup="dialog" aria-expanded={s.scopeOpen} onClick={() => set({ scopeOpen: true })}>
            <span className="so">{o.name || o.id}</span>
            <span className="sep">/</span>
            <span className="se">{s.env}</span>
            {s.run !== "current" && <span className="runb">{runLabel(s.run)}</span>}
            <Icon name="chev" />
          </button>
        </>
      )}
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
      <ScanMenu compact />
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
      {s.scopeOpen && <ScopeSheet />}
    </header>
  );
}

/** OrgPicker: the organization shown, and the others to switch to (or to add servers to a new one). */
function OrgPicker() {
  const org = useApp((s) => s.org);
  const orgs = useOrgs().data?.orgs || [];
  const scans = useSession().data?.scans;
  const o = orgs.find((x) => x.id === org);
  const [open, setOpen, ref] = usePopover();
  const name = o ? o.name || o.id : org;
  if (orgs.length < 2 && !scans) return <span className="pickbtn still">{name}</span>;
  return (
    <div className="pop" ref={ref}>
      <button
        className="pickbtn"
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-label={t("Organization") + ": " + name}
        onClick={() => setOpen(!open)}
      >
        {name}
        <Icon name="chev" />
      </button>
      {open && (
        <div className="menu left pickmenu" role="dialog" aria-label={t("Organization")}>
          <OrgOpts done={() => setOpen(false)} />
        </div>
      )}
    </div>
  );
}

/** EnvPicker: the environment shown with its servers, the others, and the data as of a past run. */
function EnvPicker() {
  const s = useS((s) => ({ org: s.org, env: s.env, run: s.run }));
  const o = useOrgs().data?.orgs.find((x) => x.id === s.org);
  const e = o?.envs.find((x) => x.env === s.env);
  const [open, setOpen, ref] = usePopover();
  return (
    <div className="pop" ref={ref}>
      <button
        className="pickbtn"
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-label={t("Environment") + ": " + s.env}
        onClick={() => setOpen(!open)}
      >
        {s.env}
        {e && <span className="n">{e.hosts}</span>}
        {s.run !== "current" && <span className="runb">{runLabel(s.run)}</span>}
        <Icon name="chev" />
      </button>
      {open && (
        <div className="menu left pickmenu" role="dialog" aria-label={t("Environment")}>
          <EnvOpts done={() => setOpen(false)} />
          <h4>{t("Data as of")}</h4>
          <RunOpts done={() => setOpen(false)} />
        </div>
      )}
    </div>
  );
}

/** ScopeSheet: the organization, environment and data on a narrow window: lists to tap, then Done. */
function ScopeSheet() {
  const s = useS((s) => ({ org: s.org, env: s.env }));
  const orgs = useOrgs().data?.orgs || [];
  const scans = useSession().data?.scans;
  const close = () => set({ scopeOpen: false });
  return (
    <div className="sheet ssheet open" role="dialog" aria-label={t("Organization") + " / " + t("Environment")}>
      <div className="shead">
        <b>{t("Organization")}</b>
        <button className="btn icon ghost" aria-label={t("Close")} onClick={close}>
          <Icon name="x" />
        </button>
      </div>
      <div className="sbody">
        {(orgs.length > 1 || scans) && <OrgOpts />}
        {orgs.length < 2 && !scans && (
          <div className="choices">
            <Opt on label={orgs.find((x) => x.id === s.org)?.name || s.org} onPick={close} />
          </div>
        )}
        <h4>{t("Environment")}</h4>
        <EnvOpts />
        <h4>{t("Data as of")}</h4>
        <RunOpts fold />
      </div>
      <div className="sheetfoot">
        <button className="btn primary" onClick={close}>
          {t("Done")}
        </button>
      </div>
    </div>
  );
}

/** Opt: one choice of a list where one is chosen: a line big enough for a finger on a phone. */
function Opt(p: { on: boolean; label: string; n?: number | string; note?: string; onPick: () => void }) {
  return (
    <button className="choice" role="radio" aria-checked={p.on} onClick={p.onPick}>
      <i className="rd" />
      <span className="l">{p.label}</span>
      {p.note && <span className="z">{p.note}</span>}
      {p.n != null && <span className="n">{p.n}</span>}
    </button>
  );
}

/** OrgOpts: the organizations, each with its servers; adding servers starts the setup. */
function OrgOpts({ done }: { done?: () => void }) {
  const org = useApp((s) => s.org);
  const orgs = useOrgs().data?.orgs || [];
  const scans = useSession().data?.scans;
  return (
    <div className="choices" role="radiogroup" aria-label={t("Organization")}>
      {orgs.map((x) => (
        <Opt
          key={x.id}
          on={x.id === org}
          label={x.name || x.id}
          n={x.envs.reduce((a, e) => a + (e.hosts || 0), 0)}
          onPick={() => {
            if (x.id !== org) setScope({ org: x.id, env: x.envs[0]?.env || "", run: "current" });
            done?.();
          }}
        />
      ))}
      {scans && (
        <button className="choice add" onClick={() => set({ view: "setup", scopeOpen: false })}>
          <Icon name="plus" />
          <span className="l">{t("Add servers…")}</span>
        </button>
      )}
    </div>
  );
}

/** EnvOpts: the organization's environments, each with its servers. */
function EnvOpts({ done }: { done?: () => void }) {
  const s = useS((s) => ({ org: s.org, env: s.env }));
  const o = useOrgs().data?.orgs.find((x) => x.id === s.org);
  return (
    <div className="choices" role="radiogroup" aria-label={t("Environment")}>
      {(o?.envs || []).map((x) => (
        <Opt
          key={x.env}
          on={x.env === s.env}
          label={x.env}
          note={x.last ? "" : t("no scans")}
          n={x.hosts}
          onPick={() => {
            if (x.env !== s.env) setScope({ env: x.env, run: "current" });
            done?.();
          }}
        />
      ))}
    </div>
  );
}

/** RunOpts: the current state or the data as of a past run; folded to the one chosen until asked for. */
function RunOpts({ done, fold = false }: { done?: () => void; fold?: boolean }) {
  const cur = useApp((s) => s.run);
  const runs: any[] = useEnv().data?.runs || [];
  const [open, setOpen] = useState(!fold || cur !== "current");
  const pick = (run: string) => {
    if (run !== cur) setScope({ run });
    done?.();
  };
  if (!open)
    return (
      <div className="choices">
        <button className="choice pick" aria-expanded={false} onClick={() => setOpen(true)}>
          <span className="l">{t("Current state")}</span>
          <Icon name="chev" />
        </button>
      </div>
    );
  return (
    <div className="choices runs" role="radiogroup" aria-label={t("Data as of")}>
      <Opt on={cur === "current"} label={t("Current state")} onPick={() => pick("current")} />
      {runs
        .slice(-20)
        .reverse()
        .map((r) => (
          <Opt
            key={r.run_id}
            on={cur === r.run_id}
            label={runLabel(r.run_id)}
            note={r.partial ? t("partial") : ""}
            onPick={() => pick(r.run_id)}
          />
        ))}
    </div>
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
function ScanMenu({ compact = false }: { compact?: boolean }) {
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
    <div className={"pop scanbtn" + (compact ? " compact" : "")} ref={menuRef}>
      <button
        className="btn primary"
        aria-label={compact ? t("Scan {env}", { env: s.env }) : undefined}
        title={compact ? t("Scan {env}", { env: s.env }) : undefined}
        onClick={() => startScan(s.org, s.env)}
      >
        <Icon name="scan" />
        {!compact && t("Scan {env}", { env: s.env })}
      </button>
      {(several || many) && !compact && (
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

/** Rail: the filters of the place shown; on a narrow window a sheet with Done. */
export function Rail() {
  const s = useS((s) => ({ view: s.view, sideOpen: s.sideOpen }));
  const narrow = useNarrow();
  return (
    <aside className={"side rail" + (s.sideOpen ? " open" : "")} id="side" aria-label={t("Filters")}>
      {s.view === "todo" && <FixFilters />}
      {s.view === "servers" && <ServerFilters />}
      {narrow && (
        <div className="sheetfoot">
          <button className="btn primary" onClick={() => set({ sideOpen: false })}>
            {t("Done")}
          </button>
        </div>
      )}
    </aside>
  );
}

/** RHead: "Filters", how many are on (a click clears them), and on a narrow window the sheet's close. */
function RHead({ n, clear }: { n: number; clear: () => void }) {
  const narrow = useNarrow();
  return (
    <div className="rhead">
      <span>{t("Filters")}</span>
      {n > 0 && (
        <button className="lnk" onClick={clear}>
          {t("Clear {n}", { n })}
        </button>
      )}
      {narrow && (
        <button className="btn icon ghost rclose" aria-label={t("Close")} onClick={() => set({ sideOpen: false })}>
          <Icon name="x" />
        </button>
      )}
    </div>
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
      <RHead n={active} clear={() => set({ flt: new Set(), accepted: false, backport: false, cur: null })} />
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
      <RHead n={s.flt.size} clear={() => set({ flt: new Set() })} />
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
