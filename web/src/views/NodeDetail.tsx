// A fix's (or CVE's, or group's) details: why its priority, when it is due, what it closes, where it is and the
// command that fixes it; the way back to the node it was opened from; adding it to the task for an agent.
import { t } from "../lib/i18n";
import { fmtDay, pct, webURL } from "../lib/format";
import { set, toggle, useS } from "../state";
import type { CVE, NodeDetail as ND } from "../types";
import { Flags, NOFIX, noFixTxt, Prio, StateCell } from "../components/cells";
import { copy, Icon } from "../components/ui";

const WHY: Record<string, string> = {
  kev: "Exploited in the wild: listed in CISA KEV",
  rce: "Remote code execution without logging in",
  preauth: "Reachable without logging in",
  epss: "EPSS {epss}: likely to be exploited in the next 30 days",
  front: "{n} of {of} hosts are internet-facing",
  nofix: "{n} hosts: no fixed package in the repositories yet",
  reboot: "{n} hosts have the fix installed and wait for a reboot",
  severity: "Severity {severity}",
};
const WHY_ICON: Record<string, string> = {
  kev: "alert", rce: "flame", preauth: "globe", epss: "chart", front: "globe", nofix: "clock", reboot: "server", severity: "shield",
};
const DUEWHY: Record<string, string> = {
  first_seen: "first seen {d}",
  fix_available: "fix available since {d}",
  published: "published {d}",
  scan: "from the scan of {d}",
  escalated: "priority raised on {d}",
  exception_ended: "exception ended {d}",
  kev: "CISA KEV due date",
  no_fix: "no date until a fix is available",
};

export function whyText(r: { code: string; args?: Record<string, any> }) {
  if (r.code === "nofix") {
    const nf: Record<string, number> = {};
    Object.keys(NOFIX).forEach((k) => {
      if (r.args?.[k]) nf[k] = r.args[k];
    });
    return t("{n} hosts: nothing to install", { n: r.args?.n ?? "" }) + (Object.keys(nf).length ? ": " + noFixTxt(nf) : "");
  }
  return t(WHY[r.code] || r.code, { ...r.args, epss: pct(r.args?.epss || 0) });
}

function DueBlock({ d }: { d: ND["due"] }) {
  if (!d.date) return d.why === "no_fix" ? <p className="desc">{t(DUEWHY.no_fix)}</p> : null;
  const from = d.why === "kev" ? t(DUEWHY.kev) + (d.kev_due ? " · " + fmtDay(d.kev_due) : "") : t(DUEWHY[d.why || ""] || "{d}", { d: d.clock_start ? fmtDay(d.clock_start) : "" });
  return (
    <div className="duebox">
      <div>
        <span className="big">{fmtDay(d.date)}</span>{" "}
        {d.overdue ? <b className="late">{t("{n} d overdue", { n: d.overdue })}</b> : <b>{t("in {n} d", { n: d.in })}</b>}
      </div>
      <div className="note">
        {from}
        {d.first_seen && d.why !== "first_seen" ? " · " + t("first seen {d}", { d: fmtDay(d.first_seen) }) : ""}
      </div>
    </div>
  );
}

const AV: Record<string, string> = { N: "Network", A: "Adjacent", L: "Local", P: "Physical" };
const LV: Record<string, string> = { L: "Low", H: "High", N: "None", R: "Required" };
// CVSS 3 metrics and the letters each may take: anything else (from the vulnerability DB) is shown as the raw vector
const CVSS3: Record<string, string> = { AV: "NALP", AC: "LH", PR: "NLH", UI: "NR", S: "UC", C: "NLH", I: "NLH", A: "NLH" };

function Vector({ v }: { v?: string }) {
  if (!v) return null;
  const m: Record<string, string> = {};
  const ok =
    /^CVSS:3\.[01]$/.test(v.split("/")[0]) &&
    v.split("/").slice(1).every((x) => {
      const [k, l, ...rest] = x.split(":");
      if (rest.length || !l || l.length !== 1) return false;
      if (CVSS3[k]) {
        if (!CVSS3[k].includes(l)) return false;
        m[k] = l;
      }
      return true;
    }) &&
    Object.keys(CVSS3).every((k) => m[k]);
  if (!ok) return <code className="note">{v}</code>;
  const c = (lab: string, val: string, bad: boolean) => (
    <div className={bad ? "bad" : ""}>
      {t(lab)}
      <b>{t(val)}</b>
    </div>
  );
  return (
    <>
      <div className="vec">
        {c("Attack from", AV[m.AV], m.AV === "N")}
        {c("Complexity", LV[m.AC], m.AC === "L")}
        {c("Privileges", LV[m.PR], m.PR === "N")}
        {c("User action", LV[m.UI], m.UI === "N")}
        {c("Scope", m.S === "C" ? "Changed" : "Unchanged", m.S === "C")}
        {c("Impact C/I/A", [m.C, m.I, m.A].join(" / "), [m.C, m.I, m.A].includes("H"))}
      </div>
      <div className="note" style={{ marginTop: 6 }}>
        <code>{v}</code>
      </div>
    </>
  );
}

function CveFull({ c }: { c: CVE }) {
  const url = webURL(c.url);
  return (
    <>
      <p className="desc">{c.description || ""}</p>
      <div className="kpis2">
        <div>
          <b>{c.cvss ?? "—"}</b>CVSS
        </div>
        <div>
          <b>{pct(c.epss || 0) || "—"}</b>EPSS
        </div>
        <div>
          <b>{c.kev ? "KEV" : "—"}</b>
          {t("exploited")}
        </div>
        <div>
          <b>{c.published ? fmtDay(c.published) : "—"}</b>
          {t("published")}
        </div>
      </div>
      <h4 style={{ marginTop: 14 }}>{t("What an attacker needs")}</h4>
      <Vector v={c.vector} />
      {url && (
        <div className="dlinks">
          <a href={url} target="_blank" rel="noopener noreferrer">
            {t("Advisory")}
          </a>
        </div>
      )}
    </>
  );
}

/** context: the node as text to paste into an agent chat. */
export function context(d: ND, org: string, env: string) {
  const n = d.node;
  const lines = [
    `Kanareika ${org}/${env}: ${n.kind} ${n.label}${n.installed ? ` ${n.installed} -> ${n.fixed || "no fix yet"}` : ""}`,
    `priority ${n.priority}, due ${d.due.date || "-"}${d.due.overdue ? ` (${d.due.overdue} d overdue)` : ""}; ${n.hosts} hosts, ${n.cves} CVE`,
    `why: ${d.why.map(whyText).join("; ")}`,
    `where: ${d.where.map((w) => `${w.group} (${w.hosts.join(", ")})`).join("; ")}`,
  ];
  if (d.cves.length) lines.push(`CVE: ${d.cves.map((c) => `${c.id} ${c.severity}${c.kev ? " KEV" : ""}${c.epss ? " EPSS " + pct(c.epss) : ""}`).join(", ")}`);
  (d.apply || []).forEach((s) => lines.push(`apply on ${s.hosts.join(", ")}: ${s.command}`));
  lines.push(`MCP: get_fix org=${org} env=${env} id=${n.id}`);
  return lines.join("\n");
}

export function NodeDetail({ d, onGo, onBack }: { d: ND; onGo: (id: string) => void; onBack: () => void }) {
  const { stack, sel, org, env } = useS((s) => ({ stack: s.stack, sel: s.sel, org: s.org, env: s.env }));
  const n = d.node;
  const inTask = sel.has(n.id);
  const parts = (n.kids || []).filter((k) => k.kind === "part");
  return (
    <>
      <div className="dh">
        <button className="btn ghost back" onClick={() => set({ detailOpen: false })}>
          <Icon name="left" />
          {t("Back")}
        </button>
        {stack.length > 0 && (
          <div className="crumb">
            <button onClick={onBack}>
              <Icon name="left" /> {stack[stack.length - 1].label}
            </button>
          </div>
        )}
        <div className="meta">
          <Prio p={n.priority} />
          {n.runtime && <span className="imgb">{n.runtime}</span>}
          <Flags n={n} />
        </div>
        <div className="bigmono" style={{ wordBreak: "break-all" }}>
          {n.label}
        </div>
        {n.kind === "pkg" || n.kind === "part" ? (
          <>
            <div className="vers">
              {n.installed} → {n.fixed ? <b>{n.fixed}</b> : noFixTxt(n.no_fix)}
            </div>
            {!!n.pkgs?.length && (
              <div className="note" style={{ marginTop: 4 }}>
                {t("binary packages")}: <code>{n.pkgs.join(", ")}</code>
              </div>
            )}
          </>
        ) : n.title && n.kind === "cve" ? (
          <div>{n.title}</div>
        ) : null}
        <div className="kpis2">
          <div>
            <b>{n.cves}</b>CVE
          </div>
          <div>
            <b>{n.hosts}</b>
            {t("hosts")}
          </div>
          <div>
            <b>{(n.groups || []).length}</b>
            {t("groups")}
          </div>
          {!!n.epss && (
            <div>
              <b>{pct(n.epss)}</b>
              {t("max EPSS")}
            </div>
          )}
        </div>
      </div>
      <div className="sec">
        <h4>{t("Why {p}", { p: n.priority })}</h4>
        <ul className="why">
          {d.why.map((r, i) => (
            <li key={i} className={["kev", "rce", "epss"].includes(r.code) ? "hot" : ""}>
              <Icon name={WHY_ICON[r.code] || "shield"} />
              <span>{whyText(r)}</span>
            </li>
          ))}
        </ul>
      </div>
      <div className="sec">
        <h4>{t("Due")}</h4>
        <DueBlock d={d.due} />
      </div>
      {n.kind === "image" && (
        <div className="sec">
          <h4>{t("Inside the image")}</h4>
          <table className="tbl">
            <tbody>
              {parts.map((c) => (
                <tr key={c.id}>
                  <td>
                    <code>{c.label}</code>
                    <div className="note">{c.path ? <code>{c.path}</code> : t("OS package of the base image")}</div>
                  </td>
                  <td style={{ font: "12.5px var(--mono)" }}>
                    {c.installed} → <span style={{ color: "var(--ok)" }}>{c.fixed || "—"}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="note" style={{ marginTop: 8 }}>
            {t("One rebuild fixes it everywhere it runs.")}
          </div>
        </div>
      )}
      {d.cves.length > 0 && (
        <div className="sec">
          <h4>{n.kind === "cve" ? t("Vulnerability") : t("Closes")}</h4>
          {n.kind === "cve" && d.cves[0] ? (
            <CveFull c={d.cves[0]} />
          ) : (
            <table className="tbl">
              <tbody>
                {d.cves.map((c) => (
                  <tr key={c.id} className="link" onClick={() => onGo("cve:" + c.id)}>
                    <td>
                      <code>{c.id}</code>
                      <div className="note">{c.title}</div>
                    </td>
                    <td>
                      <span className={"sevw sev-" + c.severity}>{c.severity}</span>
                      <div className="flags" style={{ marginTop: 4 }}>
                        <Flags n={c} />
                      </div>
                    </td>
                    <td className="r" style={{ font: "12.5px var(--mono)" }}>
                      {pct(c.epss || 0)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
      {d.where.length > 0 && (
        <div className="sec">
          <h4>{t("Where")}</h4>
          <table className="tbl">
            <thead>
              <tr>
                <th>{t("Group")}</th>
                <th>{t("Hosts")}</th>
                <th>OS</th>
                <th className="r">{t("State")}</th>
              </tr>
            </thead>
            <tbody>
              {d.where.map((w) => (
                <tr key={w.group}>
                  <td style={{ fontFamily: "var(--mono)", color: "var(--host)" }}>{w.group}</td>
                  <td style={{ font: "12.5px var(--mono)" }}>
                    {w.hosts.length}
                    {w.hosts.length <= 3 && <span className="note"> {w.hosts.join(", ")}</span>}
                  </td>
                  <td className="note">{w.os}</td>
                  <td className="r">
                    <StateCell st={w.states} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {!!d.apply?.length && (
        <div className="sec">
          <h4>{t("Apply")}</h4>
          {d.apply.map((s, i) => (
            <div key={i}>
              <div className="note" style={{ margin: "8px 0 4px" }}>
                {t("{n} hosts", { n: s.hosts.length })} · {s.os}
                {s.reboot ? " · " + t("then reboot") : ""}
              </div>
              <div className="cmd">
                <code>{s.command}</code>
                <button className="btn ghost icon" aria-label={t("Copy")} onClick={() => copy(s.command)}>
                  <Icon name="copy" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
      <div className="dfoot">
        <button className="btn primary" onClick={() => set((s) => ({ sel: toggle(s.sel, n.id) }))}>
          {inTask ? (
            <>
              <Icon name="check" />
              {t("In the task")}
            </>
          ) : (
            t("Add to task")
          )}
        </button>
        <button className="btn" title={t("What, where, why and how, to paste into an agent chat")} onClick={() => copy(context(d, org, env), t("Context copied: paste it into your agent"))}>
          <Icon name="copy" />
          {t("Copy context")}
        </button>
      </div>
    </>
  );
}
