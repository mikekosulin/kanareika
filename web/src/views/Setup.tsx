// Setup: one window, as on the banner. Step 1: whose servers, which, how to log in (one form for a few personal
// servers, a client's, a company's fleet). Step 2: one login per server, grouped by outcome. Step 3: the first
// scan's output. The vulnerability list is offered at the top, downloaded only on a click.
import { Fragment, useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { t, tx } from "../lib/i18n";
import { api, post, qs } from "../lib/api";
import { bytes, today } from "../lib/format";
import { local } from "../lib/local";
import { set, setScope, syncURL, toast, useApp } from "../state";
import { client, useDB, useJobs, useOrgs, useSession } from "../queries";
import { copy, Icon, Spin, useNow } from "../components/ui";
import { Prefs } from "./Shell";

type Kind = "add" | "personal" | "client" | "company";
interface Form {
  hosts: string;
  user: string;
  key: string;
  sudo: boolean;
  name: string;
  consent: string;
  env: string;
  jump: string;
  confirmed: boolean;
}
interface Found {
  user: string;
  keys: string[];
  agent_keys: number;
  hosts: { alias: string; hostname?: string; user?: string; port?: string; jump?: string }[];
}
interface Check {
  ok: boolean;
  error?: string;
  hint?: string;
  system?: string;
}
interface Host {
  name: string;
  address: string;
  user?: string;
  jump?: string;
  login: string;
}

const STEP_PATH: Record<number, string> = { 1: "/setup", 2: "/setup/connect", 3: "/setup/scan" };

const useFound = () =>
  useQuery({
    queryKey: ["discover"],
    queryFn: () => api<Found>("/api/setup/discover").catch(() => ({ user: "", keys: [], agent_keys: 0, hosts: [] }) as Found),
    staleTime: Infinity,
  });

export function Setup() {
  const scans = useSession().data?.scans;
  const orgs = useOrgs().data?.orgs || [];
  const cur = useApp((s) => s.org);
  const [step, setStep] = useState(1);
  const [kind, setKind] = useState<Kind>("personal");
  const [org, setOrg] = useState("");
  const [env, setEnv] = useState("");
  const [file, setFile] = useState("");
  const [only, setOnly] = useState<string[] | null>(null);
  const [skipped, setSkipped] = useState<string[]>([]);
  const [job, setJob] = useState("");
  useEffect(() => {
    const p = STEP_PATH[step] || "/setup";
    if (location.pathname !== p) history.replaceState(null, "", p + location.search);
  }, [step]);
  if (!scans)
    return (
      <div className="onb">
        <h2>{t("Read-only dashboard")}</h2>
        <p>
          {t(
            "Organizations are added where kanareika web runs on localhost (or with a token). On that machine: kanareika org new <ORG_ID>.",
          )}
        </p>
      </div>
    );
  const close = () => {
    set({ view: "servers" });
    history.replaceState(null, "", "/" + location.search);
    syncURL();
  };
  return (
    <div className="setup">
      <section className="sbrand">
        <img src="/logo.webp" alt="" width={40} height={40} />
        <h1>kanareika</h1>
        <p>
          {t("Security audit of your servers over SSH.")}
          <em>{t("What to patch first.")}</em>
        </p>
        <p className="facts">
          {[t("read-only"), t("agentless"), t("local")].map((x, i) => (
            <Fragment key={x}>
              {i > 0 && <i aria-hidden="true">·</i>}
              <span>{x}</span>
            </Fragment>
          ))}
        </p>
        <div className="sprefs">
          <Prefs />
        </div>
      </section>
      <section className="win" aria-label={t("Setup")}>
        <header className="wt">
          <span className="dots" aria-hidden="true">
            <i />
            <i />
            <i />
          </span>
          ~ kanareika setup
          {orgs.length > 0 && (
            <button className="lnk close" aria-label={t("Close")} onClick={close}>
              <Icon name="x" />
            </button>
          )}
        </header>
        <div className="wtop">
          <nav className="stabs" aria-label={t("Setup steps")}>
            {["Servers", "Connect", "First scan"].map((l, i) => {
              const n = i + 1,
                st = n < step ? "done" : n === step ? "on" : "";
              return (
                <Fragment key={l}>
                  {i > 0 && <i aria-hidden="true">›</i>}
                  <span className={st} aria-current={n === step ? "step" : undefined}>
                    {n < step ? "✓ " : ""}
                    {t(l)}
                  </span>
                </Fragment>
              );
            })}
          </nav>
          <DBLine />
        </div>
        <div className="wbody">
          {step === 1 ? (
            <ServersForm
              kind={kind}
              setKind={setKind}
              cur={orgs.find((o) => o.id === cur)}
              onDone={(r) => {
                setOrg(r.org);
                setEnv(r.env);
                setFile(r.file);
                setOnly(r.only);
                setSkipped(r.skipped);
                setStep(2);
              }}
            />
          ) : step === 2 ? (
            <CheckView
              org={org}
              env={env}
              only={only}
              skipped={skipped}
              file={file}
              onBack={() => setStep(1)}
              onScan={async (hosts) => {
                setScope({ org, env, run: "current" });
                try {
                  const r = await post("/api/scan", { org, env, hosts });
                  setJob(r.id);
                  client.invalidateQueries({ queryKey: ["jobs"] });
                  setStep(3);
                } catch (e: any) {
                  toast(e.message);
                }
              }}
            />
          ) : (
            <ScanView
              job={job}
              onDone={() => {
                client.invalidateQueries();
                close();
              }}
            />
          )}
        </div>
        <StatusBar org={orgs.find((o) => o.id === org)} env={env} />
      </section>
    </div>
  );
}

function StatusBar({ org, env }: { org?: { id: string; name: string }; env: string }) {
  const f = useFound().data;
  return (
    <footer className="sbar">
      <span>
        <b>{org ? org.name || org.id : t("setup")}</b>
        {env ? " · " + env : ""}
      </span>
      {f && (
        <span>
          ssh-agent <b>{f.agent_keys ? t("{n} keys", { n: f.agent_keys }) : t("none")}</b>
        </span>
      )}
      <span className="r">{location.host}</span>
    </footer>
  );
}

type DBSize = { sizes: Record<string, number>; need: string[]; total: number };
const useDBSize = () =>
  useQuery({
    queryKey: ["dbsize"],
    queryFn: () => api<DBSize>("/api/db/size").catch((): DBSize => ({ sizes: {}, need: [], total: 0 })),
    staleTime: Infinity,
  });

/** DBLine: the vulnerability list: its size, a download on a click, its progress. */
function DBLine() {
  const z = useDBSize().data;
  const db = useDB().data || {};
  const [asked, setAsked] = useState(false);
  const [started, setStarted] = useState(0); // when this page asked for the download (0: asked elsewhere)
  const now = useNow(!!db.updating);
  const was = useRef(false);
  useEffect(() => {
    if (db.updating) {
      was.current = true;
      return;
    }
    if (was.current) {
      was.current = false;
      client.invalidateQueries({ queryKey: ["dbsize"] });
    }
  }, [db.updating]); // eslint-disable-line react-hooks/exhaustive-deps
  const start = async () => {
    setAsked(true);
    try {
      await post("/api/db/update", {});
    } catch (er: any) {
      if (!/already running/.test(er.message)) {
        toast(er.message);
        return;
      }
    }
    setStarted(Date.now());
    client.invalidateQueries({ queryKey: ["db"] });
  };
  if (!z) return <div className="dlline" />;
  if (db.updating)
    return (
      <div className="dlline busy">
        <span className="lbl">{t("vulnerability list")}</span>
        <span className="bar">
          <i />
        </span>
        <span className="mut">{started ? Math.max(0, Math.round((now - started) / 1000)) + " s" : ""}</span>
      </div>
    );
  if (db.error && asked)
    return (
      <div className="dlline bad">
        <span className="lbl">{t("vulnerability list")}</span>
        <span className="err" title={db.error}>
          {t("failed")}
        </span>
        <button className="dlbtn" onClick={start}>
          {t("retry")}
        </button>
      </div>
    );
  if (!z.need.length)
    return (
      <div className="dlline ok">
        <span className="lbl">{t("vulnerability list")}</span>
        <span className="okc">✓ {t("ready")}</span>
      </div>
    );
  // what the total is made of: on hover, not on the page (less text)
  const part = (keys: string[]) => keys.filter((k) => z.need.includes(k)).reduce((n, k) => n + (z.sizes[k] || 0), 0);
  const tip = (
    [
      [t("Linux packages and libraries"), part(["db"])],
      [t("IP locations"), part(["dbip-city", "dbip-asn"])],
      [t("exploit data (KEV, EPSS)"), part(["kev", "epss"])],
    ] as [string, number][]
  )
    .filter(([, n]) => n)
    .map(([l, n]) => `${l}: ${bytes(n)}`)
    .concat(z.sizes["java-db"] ? [t("Java libraries: {size}, only if a scan finds .jar files", { size: bytes(z.sizes["java-db"]) })] : [])
    .join("\n");
  return (
    <div className="dlline">
      <span className="lbl">{t("vulnerability list")}</span>
      <span className="mut tipped" title={tip} tabIndex={0}>
        {bytes(z.total)}
      </span>
      <button className="dlbtn" onClick={start}>
        ↓ {t("download")}
      </button>
    </div>
  );
}

// step 1: whose servers, which, how to log in
function ServersForm(p: {
  kind: Kind;
  setKind: (k: Kind) => void;
  cur?: { id: string; name: string };
  onDone: (r: { org: string; env: string; file: string; only: string[] | null; skipped: string[] }) => void;
}) {
  const orgs = useOrgs().data?.orgs || [];
  const d = useFound().data || { hosts: [], keys: [], agent_keys: 0, user: "" };
  const [f, setF] = useState<Form>({
    hosts: "",
    user: "",
    key: "",
    sudo: false,
    name: "",
    consent: "",
    env: "production",
    jump: "",
    confirmed: false,
  });
  const [loginOpen, setLoginOpen] = useState(false);
  const [errs, setErrs] = useState<string[]>([]);
  const [pick, setPick] = useState(false);
  const upd = (patch: Partial<Form>) => setF((x) => ({ ...x, ...patch }));
  const { kind } = p;
  const kinds: [Kind, string][] = [
    ...(p.cur && p.cur.id !== "servers" ? [["add", t("Add to {org}", { org: p.cur.name || p.cur.id })] as [Kind, string]] : []),
    ["personal", t("Personal")],
    ["client", t("Client")],
    ["company", t("Company")],
  ];
  const freeId = (base: string) => {
    let id = base,
      i = 2;
    while (orgs.some((o) => o.id === id)) id = base + "-" + i++;
    return id;
  };
  const addHosts = async (org: { id: string }, body: object) => {
    try {
      const r = await post("/api/setup/add", { org: org.id, ...body });
      await client.invalidateQueries({ queryKey: ["orgs"] });
      const fresh = (client.getQueryData<any>(["orgs"])?.orgs || []).find((x: any) => x.id === org.id);
      const st = useApp.getState();
      p.onDone({
        org: org.id,
        env: (fresh?.envs.find((e: any) => e.env === st.env) || fresh?.envs[0])?.env || "production",
        file: "",
        only: r.added,
        skipped: r.skipped || [],
      });
    } catch (e: any) {
      setErrs(e.body?.errors || [e.message]);
    }
  };
  const createOrg = async (body: any) => {
    try {
      const r = await post("/api/setup", body);
      await client.invalidateQueries({ queryKey: ["orgs"] });
      p.onDone({ org: r.org, env: body.env, file: r.path, only: null, skipped: r.skipped || [] });
    } catch (e: any) {
      setErrs(e.body?.errors || [e.message]);
    }
  };
  const submit = () => {
    const err = (m: string) => setErrs([m]);
    if (!f.hosts.trim()) return err(t("Paste at least one server."));
    if (kind !== "personal" && kind !== "add" && !f.name) return err(kind === "client" ? t("Name the client.") : t("Name the company."));
    if (kind !== "personal" && kind !== "add" && !f.consent) return err(t("Say where the permission is documented."));
    if (!f.confirmed) return err(t("Confirm that you are allowed to audit these servers."));
    // the key the Login line shows: the agent's keys, else the first key in ~/.ssh
    const key = f.key || (d.agent_keys ? "" : d.keys[0] || "");
    const base = {
      user: f.user || d.user || "root",
      privilege: f.sudo ? "sudo" : "none",
      key,
      hosts: f.hosts,
      internet: false,
      confirmed: f.confirmed,
    };
    if (kind === "add") return addHosts(p.cur!, { hosts: f.hosts, user: f.user });
    if (kind === "personal") {
      const mine = orgs.find((o) => o.id === "servers");
      if (mine) return addHosts(mine, { hosts: f.hosts, user: f.user });
      return createOrg({
        ...base,
        id: "servers",
        name: t("Personal"),
        env: "production",
        consent: t("Confirmed in the setup on {d}", { d: today() }),
      });
    }
    const id = freeId(
      f.name
        .toLowerCase()
        .normalize("NFKD")
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "") || kind,
    );
    return createOrg({
      ...base,
      id,
      name: f.name,
      env: kind === "company" ? f.env || "production" : "production",
      jump: f.jump,
      consent: f.consent,
    });
  };
  const keyOpts: [string, string][] = [
    ["", d.agent_keys ? t("ssh-agent ({n} keys)", { n: d.agent_keys }) : t("ssh-agent")],
    ...d.keys.map((k): [string, string] => [k, k]),
  ];
  return (
    <form
      id="setupform"
      autoComplete="off"
      noValidate
      onSubmit={(e) => {
        e.preventDefault();
        setErrs([]);
        submit();
      }}
    >
      <div className="q">
        <h3>{t("Whose servers?")}</h3>
        <div className="opts">
          {kinds.map(([k, l]) => (
            <label key={k} className="opt">
              <input type="radio" name="kind" value={k} checked={kind === k} onChange={() => p.setKind(k)} />
              <span>{l}</span>
            </label>
          ))}
        </div>
        {(kind === "client" || kind === "company") && (
          <div className="fields">
            <label>
              <span>{kind === "client" ? t("Client") : t("Company")}</span>
              <input value={f.name} required placeholder="ACME" onChange={(e) => upd({ name: e.target.value })} />
            </label>
            <label>
              <span>{kind === "client" ? t("Their permission") : t("Permission")}</span>
              <input
                value={f.consent}
                required
                placeholder={kind === "client" ? t("contract, ticket, e-mail") : t("ticket, policy")}
                onChange={(e) => upd({ consent: e.target.value })}
              />
            </label>
          </div>
        )}
      </div>
      <div className="q">
        <h3>{t("Servers")}</h3>
        <p className="qn">{tx("One per line: {a}, an {b} command, ssh config, CSV", { a: <code>user@host</code>, b: <code>ssh</code> })}</p>
        <Editor text={f.hosts} user={f.user || d.user || "root"} onChange={(hosts) => upd({ hosts })} />
        {d.hosts.length > 0 && (
          <button type="button" className="lnk" onClick={() => setPick(true)}>
            + ~/.ssh/config ({d.hosts.length})
          </button>
        )}
      </div>
      <div className="q">
        <h3>{t("Login")}</h3>
        {loginOpen ? (
          <div className="fields">
            <label>
              <span>{t("User")}</span>
              <input value={f.user} placeholder={d.user || "root"} autoFocus onChange={(e) => upd({ user: e.target.value })} />
            </label>
            <label>
              <span>{t("Key")}</span>
              <select value={f.key} onChange={(e) => upd({ key: e.target.value })}>
                {keyOpts.map(([v, l]) => (
                  <option key={v} value={v}>
                    {l}
                  </option>
                ))}
              </select>
            </label>
            {kind === "company" && (
              <>
                <label>
                  <span>{t("Environment")}</span>
                  <input value={f.env} onChange={(e) => upd({ env: e.target.value })} />
                </label>
                <label>
                  <span>{t("Jump host")}</span>
                  <input value={f.jump} placeholder="bastion" onChange={(e) => upd({ jump: e.target.value })} />
                </label>
              </>
            )}
            <label className="chk wide">
              <input type="checkbox" checked={f.sudo} onChange={(e) => upd({ sudo: e.target.checked })} />
              <span>{t("passwordless sudo: also check passwords, keys and the firewall")}</span>
            </label>
          </div>
        ) : (
          <p className="qn mono">
            {d.agent_keys ? (
              <>
                ssh-agent · <b>{t("{n} keys", { n: d.agent_keys })}</b>
              </>
            ) : d.keys.length ? (
              <b>{d.keys[0]}</b>
            ) : (
              <span className="bad">{t("no SSH key found")}</span>
            )}{" "}
            · {t("user")} <b>{f.user || d.user || "root"}</b>{" "}
            <button type="button" className="lnk" onClick={() => setLoginOpen(true)}>
              {t("change")}
            </button>
          </p>
        )}
      </div>
      <label className="chk">
        <input type="checkbox" checked={f.confirmed} onChange={(e) => upd({ confirmed: e.target.checked })} />
        <span>{t("I’m allowed to audit these servers")}</span>
      </label>
      <div id="formerr">
        {errs.map((x, i) => (
          <p key={i} className="ferr">
            {x}
          </p>
        ))}
      </div>
      <div className="go">
        <button className="btn primary" type="submit">
          {t("Check connection")}
        </button>
      </div>
      {pick && (
        <SSHPicker
          hosts={d.hosts}
          onClose={() => setPick(false)}
          onAdd={(aliases) => {
            setPick(false);
            if (aliases.length) upd({ hosts: (f.hosts.trim() ? f.hosts.trim() + "\n" : "") + aliases.join("\n") }); // aliases resolve on the server
          }}
        />
      )}
    </form>
  );
}

// the servers' editor: line numbers | the text | what each line becomes, on the same row; empty: one plain field
function Editor({ text, user, onChange }: { text: string; user: string; onChange: (s: string) => void }) {
  const n = Math.max(3, text.split("\n").length + (text.endsWith("\n") ? 0 : 1));
  const [parsed, setParsed] = useState<{ text: string; r?: any; err?: string } | null>(null);
  useEffect(() => {
    if (!text.trim()) return; // an answer for other text is not drawn (parsed.text === text below)
    const id = setTimeout(async () => {
      try {
        const r = await post("/api/setup/parse", { text });
        setParsed({ text, r });
      } catch (e: any) {
        setParsed({ text, err: e.message });
      }
    }, 250);
    return () => clearTimeout(id);
  }, [text]);
  const rows: React.ReactNode[] = [];
  const loose: React.ReactNode[] = [];
  if (parsed?.r && parsed.text === text) {
    parsed.r.hosts.forEach((h: any) => {
      if (h.line)
        rows[h.line] = (
          <div key={"h" + h.line}>
            <span className="dn">{h.line}</span>
            <span className="arr">→</span> <span className="h">{(h.user || user) + "@" + h.address}</span>
            {h.jump && <span className="mut"> via {h.jump}</span>}
            {h.from && <span className="mut"> {t("from ssh config")}</span>}
          </div>
        );
    });
    parsed.r.errors.forEach((x: string, i: number) => {
      const m = x.match(/^line (\d+): (?:"[^"]*"(?::\s*|\s+))?(.*)$/);
      const msg = (
        <div key={"e" + i}>
          {m && <span className="dn">{m[1]}</span>}
          <span className="arr">→</span> <span className="wn">{m ? m[2] : x}</span>
          <span className="mut"> · {t("skipped")}</span>
        </div>
      );
      if (m && !rows[+m[1]]) rows[+m[1]] = msg;
      else loose.push(msg);
    });
  }
  const lines = text.split("\n").length;
  return (
    <div className={"ed " + (text.trim() ? "" : "blank")}>
      <div className="ln">
        {Array.from({ length: n }, (_, i) => (
          <span key={i}>
            {i > 0 && <br />}
            {i + 1}
          </span>
        ))}
      </div>
      <textarea
        spellCheck={false}
        wrap="off"
        rows={n}
        value={text}
        placeholder={"admin@192.0.2.10\nssh -p 2222 deploy@203.0.113.7\nnas"}
        aria-label={t("Servers")}
        onChange={(e) => onChange(e.target.value)}
      />
      <div className="dx" aria-live="polite">
        {parsed?.err ? (
          <div className="bad">{parsed.err}</div>
        ) : text.trim() && parsed?.r ? (
          <>
            {Array.from(
              { length: lines },
              (_, i) =>
                rows[i + 1] || (
                  <div key={"g" + i} className="gap">
                    &nbsp;
                  </div>
                ),
            )}
            {loose}
          </>
        ) : null}
      </div>
    </div>
  );
}

function SSHPicker({ hosts, onClose, onAdd }: { hosts: Found["hosts"]; onClose: () => void; onAdd: (aliases: string[]) => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const [q, setQ] = useState("");
  const [on, setOn] = useState<Set<number>>(new Set());
  useEffect(() => {
    ref.current?.showModal();
  }, []);
  const qq = q.toLowerCase();
  return (
    <dialog ref={ref} onClose={onClose}>
      <header>
        <h3>~/.ssh/config</h3>
      </header>
      <div className="body">
        <input className="pickq" placeholder={t("Filter")} autoComplete="off" autoFocus value={q} onChange={(e) => setQ(e.target.value)} />
        <div className="picklist">
          {hosts.map((h, i) => {
            const addr = (h.user ? h.user + "@" : "") + (h.hostname || h.alias) + (h.port ? ":" + h.port : "");
            const hidden = qq && !h.alias.toLowerCase().includes(qq) && !addr.toLowerCase().includes(qq);
            return (
              <label key={i} className="pick" hidden={!!hidden}>
                <input
                  type="checkbox"
                  checked={on.has(i)}
                  onChange={() =>
                    setOn((s) => {
                      const n = new Set(s);
                      if (n.has(i)) n.delete(i);
                      else n.add(i);
                      return n;
                    })
                  }
                />{" "}
                <b>{h.alias}</b>{" "}
                <span className="note">
                  {addr}
                  {h.jump ? " · via " + h.jump : ""}
                </span>
              </label>
            );
          })}
        </div>
      </div>
      <footer>
        <button type="button" className="btn ghost" onClick={() => ref.current?.close()}>
          {t("Cancel")}
        </button>
        <button type="button" className="btn primary" onClick={() => onAdd([...on].map((i) => hosts[i].alias))}>
          {t("Add")}
        </button>
      </footer>
    </dialog>
  );
}

// step 2: one login per server, eight at a time; rows grouped by outcome: one cause, its hosts, the fix
function CheckView(p: {
  org: string;
  env: string;
  only: string[] | null;
  skipped: string[];
  file: string;
  onBack: () => void;
  onScan: (hosts?: string[]) => void;
}) {
  const [hosts, setHosts] = useState<Host[] | null>(null);
  const [res, setRes] = useState<Record<string, Check>>({});
  const [started, setStarted] = useState(() => Date.now());
  const dbs = useDBSize().data,
    db = useDB().data;
  const run = async (hs: Host[], onlyFailed: boolean, prev: Record<string, Check>) => {
    const todo = hs.filter((h) => !onlyFailed || (prev[h.name] && !prev[h.name].ok));
    setRes((r) => {
      const n = { ...r };
      todo.forEach((h) => delete n[h.name]);
      return n;
    });
    setStarted(Date.now());
    let i = 0;
    const worker = async () => {
      while (i < todo.length) {
        const h = todo[i++];
        let r: Check;
        try {
          const x = await post("/api/setup/check", { org: p.org, env: p.env, hosts: [h.name] });
          r = x.results[0] || { ok: false, error: t("no answer") };
        } catch (e: any) {
          r = { ok: false, error: e.message };
        }
        setRes((m) => ({ ...m, [h.name]: r }));
      }
    };
    await Promise.all(Array.from({ length: Math.min(8, todo.length) }, worker));
  };
  useEffect(() => {
    (async () => {
      let hs: Host[] = [];
      try {
        const e = await api("/api/env?" + qs({ org: p.org, env: p.env }));
        hs = (e.hosts || [])
          .filter((h: any) => !p.only || p.only.includes(h.name))
          .map((h: any) => ({
            name: h.name,
            address: h.address,
            user: h.user,
            jump: h.jump,
            login: (h.user ? h.user + "@" : "") + h.address,
          }));
      } catch {
        /* none */
      }
      setHosts(hs);
      run(hs, false, {});
    })();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps
  const all = hosts || [];
  const ok = all.filter((h) => res[h.name]?.ok),
    bad = all.filter((h) => res[h.name] && !res[h.name].ok),
    waiting = all.filter((h) => !res[h.name]);
  const now = useNow(waiting.length > 0);
  const secs = Math.max(0, Math.round((now - started) / 1000));
  const who = (h: Host) => h.login || h.address || h.name;
  const Row = ({ mark, h, note }: { mark: React.ReactNode; h: Host; note: string }) => (
    <div className="hr">
      {mark}
      <span className="h">{who(h)}</span>
      <span className="mut">{note}</span>
    </div>
  );
  const causes: Record<string, { r: Check; hosts: Host[] }> = {};
  bad.forEach((h) => {
    const r = res[h.name],
      k = r.hint || r.error || "";
    (causes[k] ||= { r, hosts: [] }).hosts.push(h);
  });
  const fixFor = (c: { r: Check; hosts: Host[] }) =>
    /authenticat|permission denied|publickey|refused the login/i.test((c.r.error || "") + (c.r.hint || ""))
      ? c.hosts.slice(0, 3).map((h) => {
          const [host, port] = (h.address || "").split(/:(?=\d+$)/);
          return (
            <code key={h.name}>
              ssh-copy-id{port ? " -p " + port : ""} {(h.user ? h.user + "@" : "") + host}
            </code>
          );
        })
      : null;
  const strip = (s?: string) => (s || "").replace(/^[^:]+:\s*/, "");
  const dl =
    dbs && dbs.need.length > 0 && !db?.updating ? (
      <span className="mut">{t("downloads the vuln list first ({size})", { size: bytes(dbs.total) })}</span>
    ) : null;
  const recheck = () =>
    run(
      all,
      Object.values(res).some((r) => !r.ok),
      res,
    );
  return (
    <>
      <div className="q">
        <h3>{t("Connecting")}</h3>
        <p className="qn">{tx("One login per server, {cmd}, log out. Nothing is changed.", { cmd: <code>uname -sr</code> })}</p>
      </div>
      <div className="groups">
        {!hosts ? (
          <Spin />
        ) : (
          <>
            {waiting.length > 0 && (
              <div className="grp">
                <div className="gh">
                  <Spin />
                  {t("{n} connecting", { n: waiting.length })}
                  <span className="mut"> · {secs} s</span>
                </div>
                {waiting.map((h) => (
                  <Row key={h.name} mark={<Spin />} h={h} note={h.jump ? "via " + h.jump : ""} />
                ))}
              </div>
            )}
            {Object.entries(causes).map(([k, c]) => {
              const same = c.hosts.every((h) => strip(res[h.name].error) === strip(c.r.error)); // one error for all: said once
              const fx = fixFor(c);
              return (
                <div key={k} className="grp">
                  <div className="gh">
                    <span className="bad">✗</span>
                    {c.r.hint || c.r.error}
                  </div>
                  {c.hosts.map((h) => (
                    <Row
                      key={h.name}
                      mark={<span className="bad">✗</span>}
                      h={h}
                      note={c.r.hint && !same ? strip(res[h.name].error) : ""}
                    />
                  ))}
                  {fx && <div className="fix">{fx}</div>}
                </div>
              );
            })}
            {ok.length > 0 && (
              <div className="grp">
                <div className="gh">
                  <span className="ok">✓</span>
                  {t("{n} answered", { n: ok.length })}
                </div>
                {ok.map((h) => (
                  <Row key={h.name} mark={<span className="ok">✓</span>} h={h} note={res[h.name].system || ""} />
                ))}
              </div>
            )}
            {p.skipped.length > 0 && (
              <div className="grp">
                <div className="gh">
                  <span className="wn">!</span>
                  {t("{n} skipped", { n: p.skipped.length })}
                </div>
                {p.skipped.map((x, i) => (
                  <div key={i} className="hr">
                    <span />
                    <span className="mut">{x}</span>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
      {p.file && (
        <p className="qn">
          {tx("Saved in {file}", {
            file: (
              <code className="copyable" title={p.file} onClick={() => copy(p.file, t("Path copied"))}>
                {p.file.split(/[\\/]/).pop()}
              </code>
            ),
          })}
        </p>
      )}
      <div className="go">
        {hosts &&
          !waiting.length &&
          (ok.length ? (
            <>
              <button
                className="btn primary"
                onClick={() => p.onScan(ok.length < all.length || p.only ? ok.map((h) => h.name) : undefined)}
              >
                {bad.length ? t("Scan the {n} that answered", { n: ok.length }) : t("Start the first scan")}
              </button>
              {bad.length > 0 && (
                <button className="btn" onClick={recheck}>
                  {t("Check again")}
                </button>
              )}
              {dl}
            </>
          ) : (
            <>
              <button className="btn primary" onClick={recheck}>
                {t("Check again")}
              </button>
              <button className="btn ghost" onClick={p.onBack}>
                {t("Back")}
              </button>
            </>
          ))}
      </div>
    </>
  );
}

// step 3: the scan's own output, as a terminal shows it
function ScanView({ job, onDone }: { job: string; onDone: () => void }) {
  const jobs = useJobs().data || [];
  const j = jobs.find((x: any) => x.id === job);
  const lines = (j?.output || []).slice(-16);
  useEffect(() => {
    local.set("org", useApp.getState().org);
  }, []);
  return (
    <>
      <div className="q">
        <h3>{t("First scan")}</h3>
        <p className="qn">{t("A few minutes. You can close the page; the scan goes on.")}</p>
      </div>
      <pre className="term">{lines.length ? lines.join("\n") : <Spin />}</pre>
      <div className="go">
        {j && j.state !== "running" ? (
          <>
            <button className="btn primary" onClick={onDone}>
              {t("See the results")}
            </button>
            {j.code ? <span className="bad">{t("finished with errors")}</span> : null}
          </>
        ) : (
          <span className="mut">
            <Spin /> {t(j ? j.state : "starting")}
          </span>
        )}
      </div>
    </>
  );
}
