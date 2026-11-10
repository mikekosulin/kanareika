// History: the environment's runs and the scans started here; a run's details: what it found, what changed
// against the full run before it, its log.
import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { t } from "../lib/i18n";
import { api, qs } from "../lib/api";
import { ago, fmtN, narrow, runLabel, tsShort, took } from "../lib/format";
import { set, setScope, useApp, useS } from "../state";
import { useEnv, useJobs, useSession } from "../queries";
import { Empty, DetailClose, Icon, Kv, Search, Sec, Skeleton, Spin } from "../components/ui";
import { DataTable, type Col } from "../components/DataTable";
import { Banner, startScan } from "./Shell";

const JOBST: Record<string, [string, string]> = {
  running: ["run", "running"],
  done: ["ok", "done"],
  failed: ["bad", "finished with errors"],
  cancelled: ["mut", "cancelled"],
  stale: ["wn", "not responding"],
};

function RunState({ x }: { x: any }) {
  const s = JOBST[x.state] || ["mut", x.state];
  if (s[0] === "run")
    return (
      <span className="st">
        <Spin />
        {t(s[1])}
      </span>
    );
  return (
    <span className={"st " + s[0]} title={x.kind === "job" && x.code ? t("exit code {n}", { n: x.code }) : undefined}>
      {t(s[1])}
    </span>
  );
}

function runScope(x: any) {
  const r = x.selection || x.request || {};
  const parts = [r.hosts?.join(", "), r.groups?.join(", "), r.modules?.join("+"), r.dry_run ? t("dry run") : ""]
    .filter(Boolean)
    .join(" · ");
  return x.kind === "job" ? parts || t("full") : x.partial ? parts : t("full");
}

const pcount = (n: number | undefined, p: string) => (n ? <span className={"c" + p}>{fmtN(n)}</span> : <span className="z">0</span>);

export function History() {
  const { org, env, run, vq, vsel, vitem, detailOpen } = useS((s) => ({
    org: s.org,
    env: s.env,
    run: s.run,
    vq: s.vq,
    vsel: s.vsel,
    vitem: s.vitem,
    detailOpen: s.detailOpen,
  }));
  const envd = useEnv();
  const jobs = useJobs().data;
  const scrollRef = useRef<HTMLDivElement>(null);
  const [text, setText] = useState(vq);
  useEffect(() => {
    const id = setTimeout(() => set({ vq: text }), 150);
    return () => clearTimeout(id);
  }, [text]);
  const all = useMemo(
    () => [
      ...(jobs || []).filter((j: any) => j.request?.org === org && j.request?.env === env).map((j: any) => ({ ...j, kind: "job" })),
      ...[...(envd.data?.runs || [])].reverse().map((r: any) => ({ ...r, kind: "run" })),
    ],
    [jobs, envd.data, org, env],
  );
  const items = useMemo(() => {
    const q = vq.trim().toLowerCase();
    return all.filter(
      (x) => !q || `${x.run_id || ""} ${x.state} ${JSON.stringify(x.selection || x.request || {})}`.toLowerCase().includes(q),
    );
  }, [all, vq]);
  const key = (x: any) => x.id || x.run_id;
  const open = (x: any) => set({ vsel: key(x), vitem: x, detailOpen: narrow() });
  // the item shown follows its row (a running job's output grows)
  const shown = vitem ? all.find((x) => key(x) === key(vitem)) || vitem : null;
  const wide = useApp((s) => s.detailWide);
  const done = (envd.data?.runs || []).filter((r: any) => r.state === "done");
  const cols: Col<any>[] = [
    {
      l: t("Run"),
      w: "minmax(128px, 1fr)",
      c: "m",
      s: (x) => x.run_id || x.started,
      v: (x) =>
        x.kind === "job" ? (
          <>
            {tsShort(x.started)} <span className="z">· {t("started here")}</span>
          </>
        ) : (
          <>
            {runLabel(x.run_id)}
            {x.run_id === run && <span className="z"> · {t("shown")}</span>}
          </>
        ),
    },
    { l: t("State"), w: "112px", v: (x) => <RunState x={x} />, s: (x) => x.state },
    { l: t("Kind"), w: "minmax(0, .8fr)", k: 3, c: "d", v: (x) => runScope(x) },
    { l: t("Took"), w: "64px", k: 3, c: "r", v: (x) => took(x.started, x.finished) },
    {
      l: t("Hosts"),
      w: "72px",
      k: 2,
      c: "r",
      v: (x) =>
        x.hosts_total ? (
          <>
            {x.hosts_total - (x.hosts_failed || 0)}
            <span className="z">/{x.hosts_total}</span>
          </>
        ) : null,
    },
    ...(["P1", "P2", "P3"] as const).map((p, i): Col<any> => ({
      l: p,
      w: "40px",
      k: (i ? i + 1 : 1) as 1 | 2 | 3,
      c: "r",
      d0: -1,
      v: (x) => (x.totals || x.plan_counts ? pcount((x.totals || x.plan_counts)[p], p) : null),
      s: (x) => (x.totals || x.plan_counts)?.[p] || 0,
    })),
  ];
  return (
    <>
      <Banner />
      <div className={"work" + (shown ? "" : " solo") + (wide ? " wide" : "")}>
        <div className="listcol">
          <div className="work-top">
            <div className="hdr">
              <div style={{ minWidth: 0 }}>
                <h1>{t("History")}</h1>
                <div className="sub">
                  {done.length ? t("{n} runs · last {ago}", { n: done.length, ago: ago(done.at(-1).finished) }) : ""}
                </div>
              </div>
            </div>
          </div>
          <div className="bar2 vbar">
            <Search value={text} onChange={setText} placeholder={t("Filter")} />
          </div>
          <div className="scroll" ref={scrollRef}>
            {!envd.data ? (
              <Skeleton />
            ) : !items.length ? (
              <Empty title={all.length ? t("Nothing matches") : t("No data")}>
                {all.length ? (
                  <button className="btn ghost" onClick={() => setText("")}>
                    {t("Clear filters")}
                  </button>
                ) : null}
              </Empty>
            ) : (
              <DataTable id="history" cols={cols} items={items} rowKey={key} sel={vsel} onOpen={open} scrollRef={scrollRef} />
            )}
          </div>
        </div>
        <aside className={"detail" + (detailOpen ? " open" : "")} aria-label={t("Details")}>
          {shown ? <RunDetail x={shown} /> : <div className="nodetail">{t("Pick a row")}</div>}
        </aside>
      </div>
    </>
  );
}

function RunDetail({ x }: { x: any }) {
  const { org, env, run } = useS((s) => ({ org: s.org, env: s.env, run: s.run }));
  const scans = useSession().data?.scans;
  const c = x.totals || x.plan_counts,
    job = x.kind === "job";
  const failed: string[] = !job && scans ? x.failed || [] : [];
  const full = !job && x.state === "done" && !x.partial;
  const log = useQuery({
    queryKey: ["log", org, env, x.run_id],
    queryFn: ({ signal }) =>
      api<{ lines: string[] }>("/api/log?" + qs({ org, env, run: x.run_id }), signal).catch((e) => ({ lines: [], error: e.message })),
    enabled: !job && x.state !== "running",
  });
  const chg = useQuery({
    queryKey: ["run", org, env, x.run_id],
    queryFn: ({ signal }) => api("/api/run?" + qs({ org, env, run: x.run_id }), signal).catch((e) => ({ error: e.message })),
    enabled: full,
  });
  const logRef = useRef<HTMLPreElement>(null);
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [log.data]);
  return (
    <>
      <div className="dh">
        <DetailClose />
        <div className="meta">
          <RunState x={x} />
        </div>
        <div className="bigmono">{job ? tsShort(x.started) : runLabel(x.run_id)}</div>
        <div className="vers">{runScope(x)}</div>
        {c && (
          <div className="kpis2">
            {["P1", "P2", "P3", "P4"].map((p) => (
              <div key={p}>
                <b className={c[p] ? "c" + p : "z"}>{fmtN(c[p])}</b>
                {p}
              </div>
            ))}
            <div>
              <b>{fmtN(c.cves)}</b>CVE
            </div>
          </div>
        )}
      </div>
      <Sec title={t("Run")}>
        <Kv k={t("Started")}>
          <code>{tsShort(x.started)}</code>
        </Kv>
        <Kv k={t("Finished")}>
          {x.finished ? (
            <>
              <code>{tsShort(x.finished)}</code> <span className="z">· {took(x.started, x.finished)}</span>
            </>
          ) : null}
        </Kv>
        <Kv k={t("Hosts")}>
          {x.hosts_total ? (
            <>
              {x.hosts_total - (x.hosts_failed || 0)} / {x.hosts_total}
              {x.hosts_failed ? <span className="bad"> · {t("{n} unreachable", { n: x.hosts_failed })}</span> : null}
              {(x.failed || []).length > 0 && <code className="hostlist">{x.failed.join(", ")}</code>}
            </>
          ) : null}
        </Kv>
        {job && x.code ? (
          <Kv k={t("Exit code")}>
            <code className="bad">{x.code}</code>
          </Kv>
        ) : null}
      </Sec>
      {job ? (
        <Sec title={t("Output")}>
          <pre className="term">{(x.dropped ? `… ${x.dropped}\n` : "") + (x.output || []).join("\n") || " "}</pre>
        </Sec>
      ) : (
        <>
          {full && (
            <Sec title={t("Changes")}>
              <Changes d={chg.data} loading={chg.isLoading} />
            </Sec>
          )}
          <Sec title={t("Log")}>
            <pre className="term" ref={logRef}>
              {x.state === "running" ? (
                t("The scan is running.")
              ) : !log.data ? (
                <Spin />
              ) : log.data.lines.length ? (
                log.data.lines.join("\n")
              ) : (
                (log.data as any).error || t("No log.")
              )}
            </pre>
          </Sec>
        </>
      )}
      {!job && ((x.state === "done" && x.run_id !== run) || failed.length > 0) && (
        <div className="dfoot">
          {x.state === "done" && x.run_id !== run && (
            <button className="btn primary" onClick={() => setScope({ run: x.run_id })}>
              {t("Show this run's data")}
            </button>
          )}
          {failed.length > 0 && (
            <button className="btn" onClick={() => startScan(org, env, failed)}>
              <Icon name="scan" />
              {t("Retry {n} unreachable", { n: failed.length })}
            </button>
          )}
        </div>
      )}
    </>
  );
}

// what changed in a run against the full run before it: new and resolved, the most urgent first
function Changes({ d, loading }: { d: any; loading: boolean }) {
  if (loading || !d) return <Spin />;
  if (!d.new) return <div className="dnote">{d.error || t("No previous full run.")}</div>;
  const part = (rows: any[], plus: boolean) => <ChangeList rows={rows} plus={plus} />;
  const nw = d.new.rows || [],
    rs = d.resolved?.rows || [];
  return (
    <>
      <div className="dnote" style={{ margin: "0 0 6px" }}>
        {t("vs. the full run {run}", { run: runLabel(d.prev) })} · <span className="bad">+{nw.length}</span> ·{" "}
        <span className="ok">−{rs.length}</span>
      </div>
      {nw.length > 0 && part(nw, true)}
      {rs.length > 0 && part(rs, false)}
      {!nw.length && !rs.length && <div className="dnote">{t("Nothing changed")}</div>}
    </>
  );
}

/** ChangeList: a run's new or resolved fixes; a line opens its CVEs, the rest of the list opens on +N more. */
function ChangeList({ rows, plus }: { rows: any[]; plus: boolean }) {
  const [all, setAll] = useState(false);
  const [open, setOpen] = useState<number | null>(null);
  const shown = all ? rows : rows.slice(0, 20);
  return (
    <>
      <div className="lis">
        {shown.map((r, i) => {
          const ids: string[] = r.ids || [];
          const line = (
            <>
              <span className={"mk " + (plus ? "bad" : "ok")}>{plus ? "+" : "−"}</span>
              <span>
                {r.priority && <span className={"pb " + r.priority}>{r.priority}</span>} <code>{r.pkg}</code>{" "}
                <span className="z">{r.host}</span>
              </span>
              <span>{r.count ? fmtN(r.count) + " CVE" : ""}</span>
            </>
          );
          if (!ids.length)
            return (
              <div key={i} className="li">
                {line}
              </div>
            );
          const flip = () => setOpen(open === i ? null : i);
          return (
            <Fragment key={i}>
              <div
                className={"li more" + (open === i ? " open" : "")}
                role="button"
                tabIndex={0}
                aria-expanded={open === i}
                onClick={flip}
                onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), flip())}
              >
                {line}
                <Icon name="chev" />
              </div>
              {open === i && <pre className="li-more">{ids.join(", ")}</pre>}
            </Fragment>
          );
        })}
      </div>
      {!all && rows.length > 20 && (
        <button className="lnk dnote" onClick={() => setAll(true)}>
          {t("+{n} more", { n: rows.length - 20 })}
        </button>
      )}
    </>
  );
}
