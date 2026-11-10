// The page: the sidebar and the view the address names; setup when there is nothing yet.
import { useEffect, useRef } from "react";
import { t } from "./lib/i18n";
import { local } from "./lib/local";
import { readURL, set, syncURL, toast, useApp, useS } from "./state";
import { refresh, useEnv, useJobs, useOrgs } from "./queries";
import { Icon, Toast } from "./components/ui";
import { Palette, Sidebar } from "./views/Shell";
import { Servers } from "./views/Servers";
import { Todo } from "./views/Todo";
import { History } from "./views/History";
import { Setup } from "./views/Setup";

export function App() {
  const s = useS((s) => ({ view: s.view, org: s.org, env: s.env, run: s.run, sideOpen: s.sideOpen, sby: s.sby }));
  const orgs = useOrgs();
  const env = useEnv();
  useBoot();
  useScanDone();
  useEffect(() => {
    if (orgs.data?.errors?.length) toast(t("Config errors") + ": " + orgs.data.errors[0]);
  }, [orgs.data?.errors?.length]); // eslint-disable-line react-hooks/exhaustive-deps
  // the org and environment: the remembered ones if they still exist, else the first
  useEffect(() => {
    const os = orgs.data?.orgs;
    if (!os) return;
    const st = useApp.getState();
    const o = os.find((x) => x.id === st.org) || os[0];
    const e = o?.envs.find((x) => x.env === st.env) || o?.envs[0];
    if ((o?.id || "") !== st.org || (e?.env || "") !== st.env) {
      set({ org: o?.id || "", env: e?.env || "" });
      syncURL();
    }
    if (!os.length && st.view !== "setup") set({ view: "setup" });
  }, [orgs.data]);
  // a run in the address that is not there any more: the current state
  useEffect(() => {
    const runs = env.data?.runs;
    if (runs && s.run !== "current" && !runs.some((r: any) => r.run_id === s.run)) {
      set({ run: "current" });
      syncURL();
    }
  }, [env.data, s.run]);
  useEffect(() => {
    if (s.org) local.set("org", s.org);
    if (s.env) local.set("env", s.env);
  }, [s.org, s.env]);
  const setup = s.view === "setup" || (orgs.data && !orgs.data.orgs.length);
  if (!orgs.data) return <div className="app" />;
  return (
    <div className={"app" + (setup ? " setupmode" : "")}>
      <Sidebar />
      <div className={"scrim" + (s.sideOpen ? " on" : "")} onClick={() => set({ sideOpen: false })} />
      <main>
        <div className="mbar">
          <button
            className="btn icon ghost"
            aria-label="Menu"
            aria-controls="side"
            aria-expanded={s.sideOpen}
            onClick={() => set({ sideOpen: !s.sideOpen })}
          >
            <Icon name="menu" />
          </button>
          <b>kanareika</b>
        </div>
        <div style={{ display: "contents" }}>
          {setup ? (
            <Setup />
          ) : s.view === "history" ? (
            <History key={s.org + "|" + s.env} />
          ) : s.view === "servers" && s.sby === "host" ? (
            <Servers key={s.org + "|" + s.env + "|" + s.run} />
          ) : (
            <Todo key={s.view + "|" + s.org + "|" + s.env + "|" + s.run} />
          )}
        </div>
      </main>
      <Palette />
      <Toast />
    </div>
  );
}

function useBoot() {
  useEffect(() => {
    const pop = () => {
      if (location.pathname.startsWith("/setup")) return;
      readURL();
      set({ vitem: null, cur: null });
    };
    addEventListener("popstate", pop);
    const esc = (e: KeyboardEvent) => {
      if (e.key === "Escape" && useApp.getState().sideOpen) set({ sideOpen: false });
    };
    addEventListener("keydown", esc);
    return () => {
      removeEventListener("popstate", pop);
      removeEventListener("keydown", esc);
    };
  }, []);
}

/** useScanDone: when the scans running here finish, the environment's data is asked again. */
function useScanDone() {
  const jobs = useJobs().data;
  const was = useRef(false);
  useEffect(() => {
    const running = (jobs || []).some((j: any) => j.state === "running");
    if (was.current && !running) refresh();
    was.current = running;
  }, [jobs]);
}
