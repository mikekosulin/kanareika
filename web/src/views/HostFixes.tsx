// A server's fixes on its page: every package update, image rebuild and setting open on it (/api/host), each opening
// in place with what it closes on this server: its CVEs, why its priority, what inside an image needs it and the
// command for this server's OS (/api/node with by=host). Nothing sends you to another place to read about one server.
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { t } from "../lib/i18n";
import { api, qs } from "../lib/api";
import { dueText, days, pct, runLabel, webURL } from "../lib/format";
import { useS } from "../state";
import type { CVE, NodeDetail as ND, TreeNode } from "../types";
import { Flags, noFixTxt, Prio } from "../components/cells";
import { copy, Icon, Sec } from "../components/ui";
import { whyText } from "./NodeDetail";

interface HostAnswer {
  id: string;
  node?: TreeNode;
  fixes: TreeNode[];
}

/** useHostFixes: one server's fixes in the run shown; empty for a server with nothing open. */
export function useHostFixes(host: string) {
  const { org, env, run } = useS((s) => ({ org: s.org, env: s.env, run: s.run }));
  return useQuery({
    queryKey: ["host", org, env, run, host],
    queryFn: ({ signal }) => api<HostAnswer>("/api/host?" + qs({ org, env, run, host }), signal),
    enabled: !!org && !!env && !!host,
    staleTime: 60_000,
  });
}

/** HostFixes: the section, the most urgent first; nothing when nothing is open on the server. */
export function HostFixes({ host }: { host: string }) {
  const fixes = useHostFixes(host).data?.fixes || [];
  const [all, setAll] = useState(false);
  if (!fixes.length) return null;
  const shown = all ? fixes : fixes.slice(0, 15);
  return (
    <Sec title={t("Fixes")}>
      <div className="lis">
        {shown.map((n) => (
          <FixRow key={n.id} n={n} host={host} />
        ))}
      </div>
      {!all && fixes.length > shown.length && (
        <button className="lnk dnote" onClick={() => setAll(true)}>
          {t("+{n} more", { n: fixes.length - shown.length })}
        </button>
      )}
    </Sec>
  );
}

const late = (n: TreeNode) => !!n.due && days(n.due) < 0 && n.priority !== "P4";

/** FixRow: one fix, its details fetched when it is opened. */
function FixRow({ n, host }: { n: TreeNode; host: string }) {
  const [open, setOpen] = useState(false);
  const flip = () => setOpen(!open);
  return (
    <>
      <div
        className={"li more" + (open ? " open" : "")}
        role="button"
        tabIndex={0}
        aria-expanded={open}
        onClick={flip}
        onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), flip())}
      >
        <Prio p={n.priority} />
        <span>
          <FixLabel n={n} />
          <span className="z">
            {" · "}
            {n.cves} CVE{n.epss >= 0.01 ? " · EPSS " + pct(n.epss) : ""}
          </span>{" "}
          <Flags n={n} />
        </span>
        <span className={late(n) ? "late" : ""}>{dueText(n.due)}</span>
        <Icon name="chev" />
      </div>
      {open && <FixMore n={n} host={host} />}
    </>
  );
}

/** FixLabel: what the fix is: a package from its version to the fixed one, an image to rebuild, a setting. */
function FixLabel({ n }: { n: TreeNode }) {
  if (n.kind === "image")
    return (
      <>
        <code title={n.label}>{n.label.replace(/^.*\//, "")}</code> <span className="z">{t("rebuild the image")}</span>
      </>
    );
  if (n.kind === "pkg")
    return (
      <>
        <code>{n.label}</code> <span className="z">{n.installed} →</span>{" "}
        {n.fixed ? <code>{n.fixed}</code> : <span className="z">{noFixTxt(n.no_fix)}</span>}
      </>
    );
  return <>{n.title ? `${n.label}` : n.label}</>;
}

/** FixMore: the opened fix: why, the CVEs it closes, what inside an image needs it, the command for this server. */
function FixMore({ n, host }: { n: TreeNode; host: string }) {
  const { org, env, run } = useS((s) => ({ org: s.org, env: s.env, run: s.run }));
  const p = { org, env, run, by: "host" };
  const d = useQuery({
    queryKey: ["node", p, n.id],
    queryFn: ({ signal }) => api<ND>("/api/node?" + qs({ ...p, id: n.id }), signal),
    staleTime: 60_000,
  }).data;
  if (!d) return <div className="li-more box note">…</div>;
  const parts = (n.kids || []).filter((k) => k.kind === "part");
  const task = async () => {
    const r = await api<{ text: string }>("/api/prompt?" + qs({ ...p, nodes: n.id, host }));
    copy(r.text, t("Task copied: paste it into your agent"));
  };
  return (
    <div className="li-more box">
      {d.why.length > 0 && <div className="note">{d.why.map(whyText).join(" · ")}</div>}
      {d.cves.length > 0 && (
        <table className="tbl" style={{ marginTop: 8 }}>
          <tbody>
            {d.cves.map((c) => (
              <CveRow key={c.id} c={c} />
            ))}
          </tbody>
        </table>
      )}
      {d.cves_more > 0 && <div className="dnote">{t("+{n} more", { n: d.cves_more })}</div>}
      {parts.length > 0 && (
        <>
          <div className="note" style={{ margin: "10px 0 4px" }}>
            {t("Inside the image")}
          </div>
          {parts.map((k) => (
            <div key={k.id} style={{ font: "12.5px var(--mono)" }}>
              {k.label} <span className="z">{k.installed} →</span> {k.fixed || noFixTxt(k.no_fix)}
              {k.path && <span className="z"> · {k.path}</span>}
            </div>
          ))}
        </>
      )}
      {(d.apply || []).map((s, i) => (
        <div key={i} className="cmd" style={{ marginTop: 10 }}>
          <code>{s.command}</code>
          <button className="btn ghost icon" aria-label={t("Copy")} title={t("Copy")} onClick={() => copy(s.command)}>
            <Icon name="copy" />
          </button>
        </div>
      ))}
      <div style={{ marginTop: 10 }}>
        <button className="btn" onClick={task}>
          <Icon name="copy" />
          {t("Copy task for agent")}
        </button>
      </div>
    </div>
  );
}

/** CveRow: a CVE in the opened fix: its id (linked to its advisory), title, severity, KEV and EPSS. */
function CveRow({ c }: { c: CVE }) {
  const url = webURL(c.url);
  return (
    <tr>
      <td style={{ font: "12.5px var(--mono)", whiteSpace: "nowrap" }}>
        {url ? (
          <a href={url} target="_blank" rel="noopener noreferrer">
            {c.id}
          </a>
        ) : (
          c.id
        )}
      </td>
      <td className="note">{c.title}</td>
      <td>
        <span className={"sevw sev-" + c.severity}>{c.severity}</span> <Flags n={c} />
      </td>
      <td className="r" style={{ font: "12.5px var(--mono)" }}>
        {pct(c.epss || 0)}
      </td>
    </tr>
  );
}

interface HostChange {
  pkg: string;
  target: string;
  priority: string;
  kev?: boolean;
  ids: string[];
}
interface HostRun {
  run_id: string;
  state: string; // ok, failed
  new: HostChange[];
  resolved: HostChange[];
}

/** HostHistory: the server's runs that changed something on it (+ appeared, − went) or did not reach it, newest first;
 * quiet runs are left out, and so is the section when every run was quiet. */
export function HostHistory({ host }: { host: string }) {
  const { org, env } = useS((s) => ({ org: s.org, env: s.env }));
  const runs =
    useQuery({
      queryKey: ["hosthistory", org, env, host],
      queryFn: ({ signal }) => api<{ runs: HostRun[] }>("/api/host/history?" + qs({ org, env, host }), signal),
      enabled: !!org && !!env && !!host,
      staleTime: 60_000,
    }).data?.runs || [];
  const [all, setAll] = useState(false);
  const rows = runs.filter((r) => r.state !== "ok" || r.new.length || r.resolved.length);
  if (!rows.length) return null;
  const shown = all ? rows : rows.slice(0, 8);
  const ch = (x: HostChange, sign: string) => (
    <span key={sign + x.target + x.pkg} title={x.ids.join(", ")} style={{ marginLeft: 8, whiteSpace: "nowrap" }}>
      {sign}
      <code>{x.pkg}</code>
      {x.priority && <span className="z"> {x.priority}</span>}
    </span>
  );
  return (
    <Sec title={t("History")}>
      <div className="lis">
        {shown.map((r) => (
          <div key={r.run_id} className="li">
            {r.state === "failed" ? (
              <span className="mk bad">!</span>
            ) : r.new.length ? (
              <span className="mk wn">+</span>
            ) : (
              <span className="mk ok">✓</span>
            )}
            <span>
              <span style={{ font: "12.5px var(--mono)" }}>{runLabel(r.run_id)}</span>
              {r.state === "failed" && <span className="bad"> · {t("not reached")}</span>}
              <span className="bad">{r.new.map((x) => ch(x, "+"))}</span>
              <span className="ok">{r.resolved.map((x) => ch(x, "−"))}</span>
            </span>
            <span />
          </div>
        ))}
      </div>
      {!all && rows.length > shown.length && (
        <button className="lnk dnote" onClick={() => setAll(true)}>
          {t("+{n} more", { n: rows.length - shown.length })}
        </button>
      )}
    </Sec>
  );
}
