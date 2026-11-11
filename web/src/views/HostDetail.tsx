// A server's card: what to fix there, how it is logged into, what it exposes, how it is doing, its accepted
// risks; from the run's view (/api/run), as the TUI's host card and MCP get_host show it.
import { useState, type ReactNode } from "react";
import { t, tx } from "../lib/i18n";
import { api, qs } from "../lib/api";
import { ago, days, dueText, fmtN, runIso, tsShort } from "../lib/format";
import { deniedKey, makeL } from "../lib/catalog";
import { go, openServer, toast, useS } from "../state";
import { useCatalog, useEnv, useSession } from "../queries";
import { startScan } from "./Shell";
import type { TreeNode } from "../types";
import { DetailClose, Icon, Kv, Sec } from "../components/ui";

export const Hcell = ({ n }: { n: string }) => (
  <span className="h" title={n}>
    {n}
  </span>
);

export const useText = () => makeL(useCatalog().data);

const Mk = ({ cls }: { cls: "ok" | "wn" | "bad" | "mut" }) => (
  <span className={"mk " + cls}>{{ ok: "✓", wn: "!", bad: "!", mut: "–" }[cls]}</span>
);

/** srvMark: the state slot: ✓ clean, ✗ not reached, – not scanned, ! partly checked with nothing found; a server with
 * fixes: its priority (a partly checked one too: why is said beside its name). */
export function SrvMark({ n }: { n: TreeNode }) {
  const { problemText } = useText();
  const why = problemText(n);
  const m = (
    {
      clean: ["ok", "✓", t("nothing to fix")],
      failed: ["bad", "✗", why || t("unreachable")],
      partial: ["wn", "!", why || t("partly checked")],
      not_scanned: ["mut", "–", why || t("not scanned yet")],
    } as Record<string, string[]>
  )[n.state === "partial" && n.priority ? "" : n.state || ""];
  if (!m) return n.priority ? <span className={"pb " + n.priority}>{n.priority}</span> : <span />;
  return (
    <span className={"pb st " + m[0]} title={m[2]} aria-label={m[2]}>
      {m[1]}
    </span>
  );
}

// a line of the card; one with more to it (keys, addresses, ports, disks, why) opens it below on a click or Enter
const Li = ({ mark, text, right, more }: { mark: ReactNode; text: ReactNode; right?: ReactNode; more?: ReactNode }) => {
  const [open, setOpen] = useState(false);
  if (!more)
    return (
      <div className="li">
        {mark}
        <span>{text}</span>
        <span>{right}</span>
      </div>
    );
  const flip = (e: React.SyntheticEvent) => {
    if ((e.target as HTMLElement).closest("button, a")) return; // the line's own button (rules) does its own thing
    e.preventDefault();
    setOpen(!open);
  };
  return (
    <>
      <div
        className={"li more" + (open ? " open" : "")}
        role="button"
        tabIndex={0}
        aria-expanded={open}
        onClick={flip}
        onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && flip(e)}
      >
        {mark}
        <span>{text}</span>
        <span>{right}</span>
        <Icon name="chev" />
      </div>
      {open && (typeof more === "string" ? <pre className="li-more">{more}</pre> : <div className="li-more box">{more}</div>)}
    </>
  );
};
/** Tbl: what a card line collected, as a table: a heading per column, a row per item. */
const Tbl = ({ head, rows, r = [] }: { head: string[]; rows: ReactNode[][]; r?: number[] }) => (
  <table className="tbl">
    <thead>
      <tr>
        {head.map((h, i) => (
          <th key={i} className={r.includes(i) ? "r" : ""}>
            {h}
          </th>
        ))}
      </tr>
    </thead>
    <tbody>
      {rows.map((row, i) => (
        <tr key={i}>
          {row.map((c, j) => (
            <td key={j} className={r.includes(j) ? "r" : ""}>
              {c}
            </td>
          ))}
        </tr>
      ))}
    </tbody>
  </table>
);
const Lis = ({ rows }: { rows: ReactNode[] }) => {
  const xs = rows.filter(Boolean);
  return xs.length ? <div className="lis">{xs}</div> : null;
};

export function hostState(rd: any, n: string): ["ok" | "bad" | "wn" | "mut", string] {
  const m = rd.meta;
  if (!(m.hosts_scanned || []).includes(n)) return rd.hosts?.[n] ? ["ok", t("answered")] : ["mut", t("not scanned")];
  if (m.hosts_failed?.[n]) return ["bad", m.hosts_failed[n]];
  if (m.module_errors?.[n]) return ["wn", m.module_errors[n].join("\n")];
  return ["ok", t("answered")];
}
const lastScan = (rd: any, n: string) => {
  const src = rd.meta.sources?.[n];
  return src ? (Object.values(src) as string[]).sort().at(-1) : rd.meta.run_id;
};
export const lastAttack = (lg: any) =>
  [lg?.failed_last, ...(lg?.attackers || []).map((a: any) => a.last)].filter(Boolean).sort().at(-1) || "";
export function fwState(fw: any): ["ok" | "bad" | "mut", string, string] {
  if (!fw || !fw.readable) return ["mut", t("no access"), ""];
  const parts = [
    fw.firewalld === "running" && "firewalld",
    fw.ufw_active && "ufw",
    fw.iptables_input_policy && `INPUT ${fw.iptables_input_policy}`,
    fw.docker_rules && "docker",
  ].filter(Boolean);
  return fw.has_input_filtering ? ["ok", parts[0] || t("filtering"), parts.join(" · ")] : ["bad", t("no filtering"), parts.join(" · ")];
}
export function timeState(x: any): ["ok" | "wn" | "bad" | "mut", string, string] {
  const tm = x.time;
  if (!tm) return x.ntp_synced === "yes" ? ["ok", t("synced"), ""] : x.ntp_synced === "no" ? ["wn", t("not synced"), ""] : ["mut", "?", ""];
  const off = tm.offset_s,
    offTxt = off == null ? "" : Math.abs(off) < 1 ? `${Math.round(off * 1000)} ms` : `${off.toFixed(1)} s`;
  const tip = [
    `${t("synchronized")}: ${tm.synced ?? "?"}`,
    `${t("service")}: ${tm.service || "?"}`,
    tm.source && `${t("source")}: ${tm.source}`,
    offTxt && `${t("offset")}: ${offTxt}`,
    tm.skew_s != null && `${t("clock skew")}: ${tm.skew_s.toFixed(1)} s`,
  ]
    .filter(Boolean)
    .join("\n");
  const bad = tm.synced === "no" || (tm.skew_s != null && Math.abs(tm.skew_s) > 30);
  const warn = !bad && ((off != null && Math.abs(off) > 1) || (tm.skew_s != null && Math.abs(tm.skew_s) > 2) || !tm.service_active);
  return [bad ? "bad" : warn ? "wn" : "ok", offTxt || (tm.synced === "yes" ? t("synced") : tm.synced || "?"), tip];
}
export const maxUse = (rows: any[]) => (rows?.length ? rows.reduce((a, b) => (b.use > a.use ? b : a)) : null);

export function HostDetail({ rd, name, srv }: { rd: any; name: string; srv?: TreeNode }) {
  const env = useEnv();
  const { L, catMsg, problemText } = useText();
  const { org, envName, run } = useS((s) => ({ org: s.org, envName: s.env, run: s.run }));
  const scans = useSession().data?.scans;
  const [rules, setRules] = useState<string | null>(null);
  const [allFixes, setAllFixes] = useState(false);
  const n = name;
  const eh: any = (env.data?.hosts || []).find((h) => h.name === n) || {};
  const f = rd.facts?.[n] || {},
    c = rd.hosts?.[n] || {},
    s = hostState(rd, n),
    last = runIso(lastScan(rd, n)) || rd.meta.finished;
  const pk = (rd.plan || [])
    .filter((p: any) => p.host === n)
    .sort((a: any, b: any) => (a.priority || "P9").localeCompare(b.priority || "P9") || (a.due || "").localeCompare(b.due || ""));
  const A = rd.access?.[n],
    E = rd.exposure?.[n],
    H = rd.health?.[n];
  const other = (rd.other || []).filter((o: any) => o.host === n),
    mod = (m: string) => other.filter((o: any) => o.module === m);
  const rest = [
    ...other.filter((o: any) => !["access", "exposure", "health"].includes(o.module)),
    ...(rd.inventory || []).filter((o: any) => o.host === n && o.module !== "access"),
  ];
  const ex = (rd.exceptions || []).filter((x: any) => x.host === n);
  const pb = (p?: string) => (p ? <span className={"pb " + p}>{p}</span> : <Mk cls="wn" />);
  const due = (d?: string, p?: string) => (d ? <span className={days(d) < 0 && p !== "P4" ? "late" : ""}>{dueText(d)}</span> : null);
  const denied = (x: any) =>
    x?.denied?.length ? (
      <Li
        mark={<Mk cls="mut" />}
        text={
          <span className="z">{t("no access to {what}", { what: x.denied.map((d: string) => catMsg(deniedKey(d), d)).join(", ") })}</span>
        }
      />
    ) : null;
  const pcs = ["P1", "P2", "P3", "P4"].filter((p) => c[p]);
  const meta = [eh.address, f.os, eh.group && t("group {g}", { g: eh.group }), (eh.exposure === 1 || eh.public) && t("Public")].filter(
    Boolean,
  );
  const reboot = pk.some((p: any) => p.fix_state === "reboot");
  const probl = srv && ["failed", "partial", "not_scanned"].includes(srv.state || "") ? problemText(srv) : "";
  const scannedAt = srv?.last_scan || (s[0] === "mut" ? "" : last);
  const k = (key: string) => key;

  const fixRows = [
    ...pk.map((p: any, i: number) => (
      <Li
        key={k("p" + i)}
        mark={pb(p.priority)}
        more={`${p.installed} → ${p.fixed || ""}`}
        right={due(p.due, p.priority)}
        text={
          <>
            <code>{p.pkg}</code> <span className="z">→</span>{" "}
            {p.fixed || p.repo_version ? <code>{p.repo_version || p.fixed}</code> : <span className="z">{t("no fix yet")}</span>}
            {p.kev && (
              <>
                {" "}
                <span className="fl kev">KEV</span>
              </>
            )}
          </>
        }
      />
    )),
    ...rest
      .filter((o: any) => o.priority)
      .map((o: any, i: number) => <Li key={k("o" + i)} mark={pb(o.priority)} text={L(o)} right={due(o.due, o.priority)} more={o.target} />),
  ];

  let access: ReactNode = null;
  if (A) {
    const lg = A.logins || {},
      keys = A.keys || [],
      acc = lg.accepted || [],
      la = lastAttack(lg);
    access = (
      <Lis
        rows={[
          ...mod("access").map((o: any, i: number) => <Li key={"a" + i} mark={pb(o.priority)} text={L(o)} right={o.priority} />),
          A.password_auth == null ? (
            <Li key="pw" mark={<Mk cls="mut" />} text={t("password login: unknown")} />
          ) : A.password_auth ? (
            mod("access").length ? null : (
              <Li key="pw" mark={<Mk cls={A.users_with_password?.length ? "bad" : "wn"} />} text={t("sshd: password login enabled")} />
            )
          ) : (
            <Li key="pw" mark={<Mk cls="ok" />} text={t("password login off")} />
          ),
          A.sshd?.permitrootlogin === "yes" ? <Li key="root" mark={<Mk cls="bad" />} text={t("sshd: root login allowed")} /> : null,
          A.sshd && Object.keys(A.sshd).length ? (
            <Li
              key="sshd"
              mark={<Mk cls="mut" />}
              text={t("sshd settings")}
              right={A.sshd_source || ""}
              more={
                <Tbl
                  head={[t("Setting"), t("Value")]}
                  rows={Object.entries(A.sshd).map(([k2, v]) => [<code key="k">{k2}</code>, String(v)])}
                />
              }
            />
          ) : null,
          A.login_users?.length ? (
            <Li
              key="lu"
              mark={<Mk cls="mut" />}
              text={
                <>
                  {t("users with a shell")} <code>{A.login_users.join(", ")}</code>
                </>
              }
              more={A.uid0?.length > 1 ? `uid 0: ${A.uid0.join(", ")}` : undefined}
            />
          ) : null,
          (A.last || []).length ? (
            <Li key="last" mark={<Mk cls="mut" />} text={t("last sessions ({n})", { n: A.last.length })} more={A.last.join("\n")} />
          ) : null,
          A.users_with_password?.length ? (
            <Li
              key="up"
              mark={<Mk cls="bad" />}
              text={tx("password set for {users}", { users: <code>{A.users_with_password.join(", ")}</code> })}
            />
          ) : null,
          <Li
            key="keys"
            mark={<Mk cls="ok" />}
            more={
              keys.length ? (
                <Tbl
                  head={[t("User"), t("Type"), t("Comment"), t("Fingerprint"), t("File")]}
                  rows={keys.map((x: any) => [
                    x.user,
                    x.type,
                    x.comment || "—",
                    <code key="fp">{x.fp}</code>,
                    <code key="f">{x.file}</code>,
                  ])}
                />
              ) : undefined
            }
            text={
              <>
                {t("keys: {n} · users: {u}", { n: keys.length, u: new Set(keys.map((x: any) => x.user)).size })}
                {keys.some((x: any) => x.user === "root") && <span className="z"> · root</span>}
              </>
            }
          />,
          acc.length ? (
            <Li
              key="acc"
              mark={<Mk cls="mut" />}
              more={
                <Tbl
                  head={[t("User"), t("Address"), t("Logins"), t("Last"), t("First"), t("Method")]}
                  r={[2]}
                  rows={[...acc]
                    .sort((a: any, b: any) => String(b.last).localeCompare(String(a.last)))
                    .map((x: any) => [
                      x.user,
                      <code key="ip">{x.ip}</code>,
                      fmtN(x.count),
                      tsShort(x.last),
                      tsShort(x.first),
                      x.method || "—",
                    ])}
                />
              }
              text={t("{n} logins from {m} addresses, 30 d", {
                n: fmtN(acc.reduce((m: number, x: any) => m + x.count, 0)),
                m: new Set(acc.map((x: any) => x.ip)).size,
              })}
            />
          ) : null,
          lg.failed_total ? (
            <Li
              key="fail"
              mark={<Mk cls="wn" />}
              text={t("{n} failed logins from {m} addresses", { n: fmtN(lg.failed_total), m: fmtN(lg.failed_ips) })}
              right={la ? ago(la) : ""}
              more={<FailedLogins lg={lg} />}
            />
          ) : null,
          denied(A) && <span key="den">{denied(A)}</span>,
        ]}
      />
    );
  }
  let net: ReactNode = null;
  if (E) {
    const fw = fwState(E.firewall),
      pub = [...new Set<number>((E.listen || []).filter((y: any) => y.public).map((y: any) => y.port))].sort((a, b) => a - b);
    const fwTxt = `${t("firewall")} ${fw[1]}`;
    net = (
      <>
        <Lis
          rows={[
            ...mod("exposure").map((o: any, i: number) => (
              <Li key={"e" + i} mark={pb(o.priority)} text={L(o)} right={due(o.due, o.priority)} more={o.target} />
            )),
            <Li
              key="fw"
              mark={<Mk cls={fw[0] === "bad" ? "bad" : "ok"} />}
              more={fw[2]}
              text={
                pub.length ? (
                  <>
                    <code>{pub.map((p) => ":" + p).join(" ")}</code> {t("open")} · {fwTxt}
                  </>
                ) : (
                  <>
                    {t("nothing open to the outside")} · {fwTxt}
                  </>
                )
              }
              right={
                E.firewall?.readable ? (
                  <button
                    className="lnk"
                    onClick={() =>
                      api("/api/hostfile?" + qs({ org, env: envName, run, host: n, name: "exposure" }))
                        .then((x: any) =>
                          setRules(
                            Object.entries(x.firewall_raw || {})
                              .filter(([, v]) => v)
                              .map(([k2, v]) => `## ${k2}\n${v}`)
                              .join("\n\n") || t("No rules."),
                          ),
                        )
                        .catch((er) => toast(er.message))
                    }
                  >
                    {t("rules")}
                  </button>
                ) : null
              }
            />,
            E.public?.length ? (
              <Li
                key="pub"
                mark={<Mk cls={E.unlisted_public?.length ? "bad" : "mut"} />}
                more={E.unlisted_public?.length ? t("not in the organization config") : ""}
                text={
                  <>
                    {t("public IP")} <code>{E.public.join(" ")}</code>
                  </>
                }
              />
            ) : null,
            <Li
              key="in"
              mark={<Mk cls="mut" />}
              text={t("{n} listening inside", { n: (E.listen || []).filter((y: any) => !y.public).length })}
              more={
                (E.listen || []).length ? (
                  <Tbl
                    head={[t("Port"), t("Address"), t("Process"), ""]}
                    rows={[...(E.listen || [])]
                      .sort((a: any, b: any) => Number(b.public) - Number(a.public) || a.port - b.port)
                      .map((y: any) => [
                        <code key="p">{`${y.port}/${y.proto}`}</code>,
                        <code key="a">{y.addr}</code>,
                        y.process || "?",
                        y.public ? t("open") : "",
                      ])}
                  />
                ) : undefined
              }
            />,
            denied(E) && <span key="den">{denied(E)}</span>,
          ]}
        />
        {rules != null && <pre className="term">{rules}</pre>}
      </>
    );
  }
  let hl: ReactNode = null;
  if (H) {
    const d = maxUse(H.disks),
      tm = timeState(H),
      memFree = H.mem ? Math.round((100 * H.mem.available_mb) / H.mem.total_mb) : null;
    const sum = [
      d && `${t("disk")} ${d.mount} ${d.use}%`,
      memFree != null && t("mem {n}% free", { n: memFree }),
      H.load && `load ${H.load.load15}/${H.load.cpus}`,
    ]
      .filter(Boolean)
      .join(" · ");
    hl = (
      <>
        <Lis
          rows={[
            ...mod("health").map((o: any, i: number) => (
              <Li key={"h" + i} mark={pb(o.priority)} text={L(o)} right={due(o.due, o.priority)} more={o.target} />
            )),
            <Li
              key="sum"
              mark={<Mk cls={d && d.use >= 95 ? "bad" : d && d.use >= 85 ? "wn" : "ok"} />}
              text={sum}
              more={
                (H.disks || []).length ? (
                  <Tbl
                    head={[t("Mount"), t("Used"), "inodes"]}
                    r={[1, 2]}
                    rows={(H.disks || []).map((r: any) => {
                      const ino = (H.inodes || []).find((x: any) => x.mount === r.mount);
                      return [<code key="m">{r.mount}</code>, `${r.use}%`, ino ? `${ino.use}%` : "—"];
                    })}
                  />
                ) : undefined
              }
            />,
            ...(H.disks || [])
              .filter((r: any) => r !== d && r.use >= 85)
              .map((r: any, i: number) => <Li key={"d" + i} mark={<Mk cls="wn" />} text={`${t("disk")} ${r.mount} ${r.use}%`} />),
            ...(H.inodes || [])
              .filter((r: any) => r.use >= 85)
              .map((r: any, i: number) => <Li key={"i" + i} mark={<Mk cls="wn" />} text={`inodes ${r.mount} ${r.use}%`} />),
            H.failed_units?.length ? (
              <Li
                key="fu"
                mark={<Mk cls="wn" />}
                text={
                  <>
                    {t("failed units")} <code>{H.failed_units.join(", ")}</code>
                  </>
                }
              />
            ) : null,
            H.readonly_mounts?.length ? (
              <Li
                key="ro"
                mark={<Mk cls="bad" />}
                text={
                  <>
                    {t("read-only")} <code>{H.readonly_mounts.join(", ")}</code>
                  </>
                }
              />
            ) : null,
            <Li
              key="tm"
              mark={<Mk cls={tm[0]} />}
              more={tm[2]}
              text={
                <>
                  {t("time")} {tm[1]}
                  {H.time && <span className="z"> · {[H.time.service, H.time.timezone].filter(Boolean).join(" · ")}</span>}
                </>
              }
            />,
            ...Object.values(H.dmesg?.classes || {}).map((x: any, i: number) => (
              <Li key={"k" + i} mark={<Mk cls="wn" />} text={`${t("kernel")}: ${catMsg(x.key, x.title)}`} right={x.count} more={x.last} />
            )),
            H.journal?.errors_7d ? (
              <Li key="j" mark={<Mk cls="mut" />} text={t("{n} journal errors, 7 d", { n: fmtN(H.journal.errors_7d) })} />
            ) : null,
            denied(H) && <span key="den">{denied(H)}</span>,
          ]}
        />
        {(H.dmesg?.tail || []).length > 0 && <pre className="term">{H.dmesg.tail.slice(-20).join("\n")}</pre>}
      </>
    );
  }
  const oth = (
    <Lis
      rows={rest
        .filter((o: any) => !o.priority)
        .map((o: any, i: number) => (
          <Li key={i} mark={<Mk cls="mut" />} text={L(o)} more={o.target} />
        ))}
    />
  );
  const exc = (
    <Lis
      rows={ex.map((x: any, i: number) => (
        <Li
          key={i}
          mark={<Mk cls={x.exception?.expired || x.exception?.fix_available ? "bad" : "ok"} />}
          text={
            <>
              <code>{x.pkg}</code> <span className="z">{x.id}</span>
            </>
          }
          right={x.exception?.review_by}
        />
      ))}
    />
  );
  const fixes = fixRows.length ? (
    <>
      <div className="lis">{allFixes ? fixRows : fixRows.slice(0, 12)}</div>
      {!allFixes && fixRows.length > 12 && (
        <button className="lnk dnote" onClick={() => setAllFixes(true)}>
          {t("+{n} more", { n: fixRows.length - 12 })}
        </button>
      )}
    </>
  ) : null;
  return (
    <>
      <div className="dh">
        <DetailClose />
        <div className="meta">
          {probl && srv && (
            <>
              <SrvMark n={srv} />
              <span>
                {srv.state === "failed" ? t("not reached") : srv.state === "partial" ? t("partly checked") : t("not scanned yet")}
              </span>
            </>
          )}
        </div>
        <div className="bigmono hn" title={n}>
          {n}
        </div>
        <div className="dmeta">{meta.join(" · ")}</div>
        <div className="dkv">
          <Kv k={t("To fix")}>
            {pcs.length ? (
              pcs.map((p, i) => (
                <span key={p}>
                  {i > 0 && <span className="z"> • </span>}
                  <span className={"c" + p}>
                    {p} {c[p]}
                  </span>
                </span>
              ))
            ) : (
              <span className="ok">{t("nothing to fix")}</span>
            )}
          </Kv>
          <Kv k={t("Scanned")}>
            {!scannedAt ? (
              <span className="z">{t("not scanned yet")}</span>
            ) : (
              <>
                {ago(scannedAt)}
                {eh.user && <span className="z"> · {t("as {user}", { user: eh.user })}</span>}
              </>
            )}
          </Kv>
          {probl && srv ? (
            <Kv k={srv.state === "failed" ? t("Not reached") : srv.state === "partial" ? t("Partly checked") : t("Not scanned")}>
              <span className={srv.state === "failed" ? "bad" : srv.state === "partial" ? "wn" : "z"}>{probl}</span>
            </Kv>
          ) : s[0] === "bad" || s[0] === "wn" ? (
            <Kv k={s[0] === "bad" ? t("Not reached") : t("Errors")}>
              <span className={s[0]}>{s[1]}</span>
            </Kv>
          ) : null}
          <Kv k={t("Reboot")}>{reboot ? <span className="wn">{t("pending")}</span> : t("not pending")}</Kv>
          {H?.uptime_s ? <Kv k={t("Uptime")}>{t("{n} d", { n: Math.floor(H.uptime_s / 86400) })}</Kv> : null}
          {f.kernel?.length ? (
            <Kv k={t("Kernel")}>
              <code>{f.kernel.join(", ")}</code>
            </Kv>
          ) : null}
        </div>
      </div>
      <Sec title={t("Fixes")}>{fixes}</Sec>
      <Sec title={t("Access")}>{access}</Sec>
      <Sec title={t("Network")}>{net}</Sec>
      <Sec title={t("Health")}>{hl}</Sec>
      <Sec title={t("Other")}>{oth}</Sec>
      <Sec title={t("Exceptions")}>{exc}</Sec>
      <div className="dfoot">
        <button className="btn primary" onClick={() => go("todo", n)}>
          {t("Its fixes in ToDo")}
        </button>
        {scans && (
          <button className="btn" onClick={() => startScan(org, envName, [n])}>
            <Icon name="scan" />
            {t("Rescan")}
          </button>
        )}
      </div>
    </>
  );
}

const stl = (cls: string, txt: string, title?: string) => (
  <span className={"st " + cls} title={title || undefined}>
    {txt}
  </span>
);

export function ExcDetail({ x }: { x: any }) {
  const e = x.exception || {};
  return (
    <>
      <div className="dh">
        <DetailClose />
        <div className="meta">
          {e.fix_available
            ? stl("bad", t("fix in the repositories: back in the plan"))
            : e.expired
              ? stl("bad", t("expired: back in the plan"))
              : stl("ok", t("accepted"))}
        </div>
        <div className="bigmono">{x.pkg}</div>
        <div className="vers">{x.id}</div>
      </div>
      <div className="sec">
        <h4>{t("Exception")}</h4>
        <Kv k={t("Host")}>
          <button className="lnk" style={{ fontFamily: "var(--mono)", color: "var(--host)" }} onClick={() => openServer(x.host)}>
            {x.host}
          </button>
        </Kv>
        <Kv k={t("Until")}>
          <code className={e.expired ? "bad" : ""}>{e.review_by}</code>
        </Kv>
        <Kv k={t("Who")}>{e.owner}</Kv>
        <Kv k={t("Reason")}>{e.reason}</Kv>
      </div>
    </>
  );
}

/** FailedLogins: who tried and failed (the addresses that tried most, with the names they tried), which names, and when. */
function FailedLogins({ lg }: { lg: any }) {
  const att: any[] = [...(lg.attackers || [])].sort((a, b) => b.n - a.n);
  const users: [string, number][] = lg.failed_top_users || [];
  const daily = Object.entries(lg.failed_daily || {}) as [string, number][];
  const peak = Math.max(1, ...daily.map(([, n]) => n));
  const [all, setAll] = useState(false);
  const shown = all ? att : att.slice(0, 15);
  return (
    <>
      {att.length > 0 && (
        <Tbl
          head={[t("Address"), t("Attempts"), t("When"), t("Names tried")]}
          r={[1]}
          rows={shown.map((x) => [
            <code key="ip">{x.ip}</code>,
            fmtN(x.n),
            x.first === x.last
              ? tsShort(x.first)
              : `${tsShort(x.first)} – ${tsShort(x.last).slice(String(x.first).slice(0, 10) === String(x.last).slice(0, 10) ? -5 : 0)}`,
            (x.users || []).map((u: [string, number]) => u[0]).join(", "),
          ])}
        />
      )}
      {att.length > shown.length && (
        <button className="lnk" onClick={() => setAll(true)}>
          {t("+{n} more", { n: att.length - shown.length })}
        </button>
      )}
      {users.length > 0 && (
        <p className="li-note">
          {t("Names tried most")}: <code>{users.map(([u, n]) => `${u} ${fmtN(n)}`).join(", ")}</code>
        </p>
      )}
      {daily.length > 0 && (
        <div className="days" aria-label={t("Failed logins by day")}>
          {daily.map(([d, n]) => (
            <div key={d} className="day">
              <span>{d.slice(5)}</span>
              <i style={{ width: `${Math.max(2, (100 * n) / peak)}%` }} />
              <span>{fmtN(n)}</span>
            </div>
          ))}
        </div>
      )}
    </>
  );
}
