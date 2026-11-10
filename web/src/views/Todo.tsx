// ToDo (and Servers grouped by fix or CVE): what to do, grouped by fix, CVE or server, most urgent first; the
// details of the row picked beside it; rows picked for a task an agent can take.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { t, tx } from "../lib/i18n";
import { api, qs } from "../lib/api";
import { LANG } from "../lib/i18n";
import { fmtN, narrow } from "../lib/format";
import { grouping, set, setBy, setSort, syncURL, toast, toggle, useApp, useS, type By } from "../state";
import { client, fullTree, treeParams, useNode, useRunData, useTree } from "../queries";
import type { TreeNode } from "../types";
import { Chips, copy, Empty, Icon, Search, Seg, Skeleton, SortHead } from "../components/ui";
import { DataTable, type Col } from "../components/DataTable";
import { TreeRows, useRows, useTreeKeys, type Row } from "./TreeList";
import { NodeDetail } from "./NodeDetail";
import { ExcDetail, Hcell } from "./HostDetail";
import { Banner, NoRuns } from "./Shell";

export const FILTERS: [string, string][] = [
  ["kev", "KEV"], ["rce", "pre-auth RCE"], ["epss", "EPSS ≥ 10%"], ["front", "Public"], ["ready", "fix ready"], ["nofix", "no fix yet"], ["overdue", "overdue"],
];
export const GROUPS: [By, string][] = [["host", "server"], ["fix", "fix"], ["cve", "CVE"]];

/** useQueryInput: the filter field, asked of the server a moment after the typing stops. */
export function useQueryInput() {
  const q = useApp((s) => s.q);
  const [text, setText] = useState(q);
  useEffect(() => setText(q), [q]);
  useEffect(() => {
    if (text === useApp.getState().q) return;
    const id = setTimeout(() => set({ q: text }), 200);
    return () => clearTimeout(id);
  }, [text]);
  return [text, setText] as const;
}

export function Todo() {
  const s = useS((s) => ({ sort: s.tsort, view: s.view, accepted: s.accepted, flt: s.flt, by: grouping(s), backport: s.backport, sel: s.sel, open: s.open, org: s.org, env: s.env, run: s.run }));
  const p = useApp(useMemoParams);
  const tree = useTree(p);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [text, setText] = useQueryInput();
  const nodes = tree.data?.nodes || [];
  const loadedRows = useRows(nodes, p);
  // the rows of pages not loaded yet stand in for them: the scrollbar has its length from the start
  const rest = Math.max(0, (tree.data?.rows ?? nodes.length) - nodes.length);
  const rows = useMemo(
    () => (rest ? [...loadedRows, ...Array.from({ length: rest }, (_, i): Row => ({ type: "page", depth: 0, key: "page/" + i }))] : loadedRows),
    [loadedRows, rest],
  );
  const show = useCallback((id: string) => set({ cur: id, stack: [], detailOpen: narrow() }), []);
  useTreeKeys(rows, show, s.view === "todo");
  // the first row's details on a wide window, when nothing is picked (or what was picked is gone)
  const cur = useApp((s) => s.cur);
  useEffect(() => {
    if (!tree.data || tree.isPlaceholderData || s.accepted) return;
    if (!cur && nodes[0] && !narrow()) set({ cur: nodes[0].id });
  }, [tree.data, tree.isPlaceholderData]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => syncURL(), [s.by, s.accepted]);

  if (tree.error && (tree.error as any).status === 404) return <NoRuns />;
  const tr = tree.data;
  const filtered = s.flt.size > 0 || !!p.q;
  return (
    <>
      <Banner />
      <div className="work">
        <div className="listcol">
          <div className="work-top">
            <div className="hdr">
              <div>
                <h1>{t(s.view === "servers" ? "Servers" : "ToDo")}</h1>
                <div className="sub">
                  {s.accepted ? <AcceptedSub /> : tr && (
                    <>
                      {t("{f} fixes · {c} CVE · {h} hosts", { f: tr.fixes, c: tr.cves, h: tr.hosts })}
                      {tr.no_fix ? " · " + t("{n} with nothing to install yet", { n: tr.no_fix }) : ""}
                    </>
                  )}
                </div>
              </div>
              <div className="counts">
                {!s.accepted &&
                  ["P1", "P2", "P3", "P4"].map((pp) => (
                    <span key={pp} className="cnt">
                      <i style={{ background: `var(--${pp.toLowerCase()})` }} />
                      <b>{tr?.counts?.[pp] || 0}</b> {pp}
                    </span>
                  ))}
              </div>
            </div>
          </div>
          <div className="bar2">
            <Seg label={t("group")} aria={t("Group by")} items={GROUPS.map(([k, l]) => [k, t(l)])} value={s.by} onPick={setBy} />
            <Search value={text} onChange={setText} placeholder={t("Package, CVE, host or group")} />
            <Chips items={s.accepted ? [] : FILTERS.map(([k, l]) => [k, t(l)])} on={s.flt} onToggle={(k) => set((st) => ({ flt: toggle(st.flt, k) }))}>
              {s.view === "todo" && (
                <button
                  className="chip"
                  aria-pressed={s.accepted}
                  onClick={() => {
                    set((st) => ({ accepted: !st.accepted, cur: null, vitem: null, vsel: "" }));
                    syncURL();
                  }}
                >
                  {t("accepted")}
                </button>
              )}
              {!s.accepted && (s.backport || !!tr?.hidden_backported) && (
                <button
                  className="chip"
                  aria-pressed={s.backport}
                  title={t("Already fixed by a backport: the package's changelog lists the CVE as fixed")}
                  onClick={() => set((st) => ({ backport: !st.backport }))}
                >
                  + {t("backported")}
                  {!s.backport && tr?.hidden_backported ? " " + fmtN(tr.hidden_backported) : ""}
                </button>
              )}
            </Chips>
          </div>
          <div className="scroll" ref={scrollRef}>
            {s.accepted ? (
              <Accepted scrollRef={scrollRef} />
            ) : (
              <>
                <div className="thead">
                  <AllButton nodes={nodes} />
                  <span />
                  <SortHead k="pri" asc sort={s.sort} onSort={setSort}>{t("Pri")}</SortHead>
                  <SortHead k="name" asc sort={s.sort} onSort={setSort}>{s.by === "fix" ? t("Fix") : s.by === "cve" ? t("Vulnerability") : t("Group / host")}</SortHead>
                  <SortHead k="hosts" className="c-h" sort={s.sort} onSort={setSort}>{t("Hosts")}</SortHead>
                  <SortHead k="cve" className="num c-cve" sort={s.sort} onSort={setSort}>CVE</SortHead>
                  <SortHead k="epss" className="num c-ep" sort={s.sort} onSort={setSort}>EPSS</SortHead>
                  <span className="c-fl">{t("Flags")}</span>
                  <span className="c-st">{t("State")}</span>
                  <SortHead k="due" asc className="dd" sort={s.sort} onSort={setSort}>{t("Due")}</SortHead>
                </div>
                {!tr ? (
                  <Skeleton />
                ) : !nodes.length ? (
                  <Empty title={filtered ? t("Nothing matches") : t("Nothing to do")}>
                    {filtered ? (
                      <button className="btn ghost" onClick={() => set({ flt: new Set(), q: "" })}>
                        {t("Clear filters")}
                      </button>
                    ) : (
                      t("No open findings in this environment.")
                    )}
                  </Empty>
                ) : (
                  <div className={tree.isPlaceholderData ? "stale" : ""}>
                    <TreeRows rows={rows} scrollRef={scrollRef} selectable={s.view === "todo"} onShow={show} onEnd={tree.more} />
                  </div>
                )}
                <div className="end" />
                {s.view === "todo" && <SelBar />}
              </>
            )}
          </div>
        </div>
        <Detail accepted={s.accepted} waiting={!tr || tree.isPlaceholderData} />
      </div>
    </>
  );
}

// the tree's question, as one object that changes only when the question does
let lastP: ReturnType<typeof treeParams> | null = null;
function useMemoParams(s: Parameters<typeof treeParams>[0]) {
  const p = treeParams(s);
  if (lastP && JSON.stringify(lastP) === JSON.stringify(p)) return lastP;
  lastP = p;
  return p;
}

/** AllButton: the header's expand / collapse all (expand: the whole tree, every level, once). */
function AllButton({ nodes }: { nodes: TreeNode[] }) {
  const open = useApp((s) => s.open);
  const p = useApp(useMemoParams);
  const any = open.size > 0;
  return (
    <button
      className="tw"
      aria-expanded={any}
      title={any ? t("Collapse all") : t("Expand all")}
      onClick={async () => {
        if (any) {
          set({ open: new Set() });
          return;
        }
        let ns = nodes;
        if (nodes.some((n) => n.more)) {
          try {
            const full = await fullTree(p);
            ns = full.nodes || [];
            client.setQueryData(["tree", p, false], { pages: [{ ...full, rows: ns.length }], pageParams: [0] }); // every row, as one page
          } catch (e: any) {
            toast(e.message);
            return;
          }
        }
        const ids = new Set<string>();
        const all = (xs: TreeNode[]) => xs.forEach((n) => {
          if ((n.kids || []).length) {
            ids.add(n.id);
            all(n.kids!);
          }
        });
        all(ns);
        set({ open: ids });
      }}
    >
      <Icon name="chev" />
    </button>
  );
}

function SelBar() {
  const sel = useApp((s) => s.sel);
  const n = sel.size;
  return (
    <div className={"selbar " + (n ? "on" : "")}>
      <div className="what">
        <b>{t("{n} selected", { n })}</b>
      </div>
      <div className="acts">
        <button className="btn ghost" onClick={() => set({ sel: new Set() })}>
          {t("Clear")}
        </button>
        <button
          className="btn primary"
          onClick={async () => {
            const s = useApp.getState();
            try {
              const r = await api("/api/prompt?" + qs({ org: s.org, env: s.env, run: s.run, lang: LANG, nodes: [...s.sel].join(",") }));
              copy(r.text, t("Task copied: paste it into your agent"));
            } catch (e: any) {
              toast(e.message);
            }
          }}
        >
          <Icon name="copy" />
          {t("Copy task for agent")}
        </button>
      </div>
    </div>
  );
}

/** Detail: the panel beside the list: the picked node's details (or, for accepted risks, the exception's). */
// waiting: the list is being regrouped or filtered; the details shown stay (dimmed) until it picks its first row
function Detail({ accepted, waiting }: { accepted: boolean; waiting: boolean }) {
  const { cur, detailOpen, vitem } = useS((s) => ({ cur: s.cur, detailOpen: s.detailOpen, vitem: s.vitem }));
  const p = useApp(useMemoParams);
  const node = useNode(p, accepted ? null : cur);
  const ref = useRef<HTMLElement>(null);
  useEffect(() => {
    ref.current?.scrollTo(0, 0);
  }, [node.data?.node.id]);
  const goTo = (id: string) => {
    const s = useApp.getState(), d = node.data;
    set({ stack: d ? [...s.stack, { id: d.node.id, label: d.node.label }] : s.stack, cur: id });
  };
  const back = () => {
    const s = useApp.getState(), pr = s.stack[s.stack.length - 1];
    if (pr) set({ cur: pr.id, stack: s.stack.slice(0, -1) });
  };
  return (
    <aside ref={ref} className={"detail" + (detailOpen ? " open" : "")} aria-label={t("Details")}>
      {accepted ? (
        vitem?.kind === "exc" ? <ExcDetail x={vitem} /> : null
      ) : !cur && !(waiting && node.data) ? null : node.error ? (
        <div className="nodetail">{(node.error as Error).message}</div>
      ) : !node.data ? (
        <Skeleton kind="detail" />
      ) : (
        <div className={node.isPlaceholderData || !cur ? "stale" : ""}>
          <NodeDetail d={node.data} onGo={goTo} onBack={back} />
        </div>
      )}
    </aside>
  );
}

// accepted risks: the org file's exceptions, until when, whose, why
function AcceptedSub() {
  const rd = useRunData();
  const ex: any[] = rd.data?.exceptions || [];
  return <>{t("{n} accepted · {e} expired", { n: ex.length, e: ex.filter((f) => f.exception?.expired || f.exception?.fix_available).length })}</>;
}

function Accepted({ scrollRef }: { scrollRef: React.RefObject<HTMLDivElement | null> }) {
  const rd = useRunData();
  const { q, vsel } = useS((s) => ({ q: s.q, vsel: s.vsel }));
  const ex: any[] = rd.data?.exceptions || [];
  const rows = useMemo(() => {
    const qq = q.trim().toLowerCase();
    return ex.filter((f) => !qq || `${f.host} ${f.pkg} ${f.id} ${f.exception?.owner || ""} ${f.exception?.reason || ""}`.toLowerCase().includes(qq));
  }, [ex, q]);
  const key = (f: any) => `${f.host}/${f.id}`;
  const open = (x: any) => set({ vsel: key(x), vitem: { ...x, kind: "exc" }, detailOpen: narrow() });
  useEffect(() => {
    if (rows[0] && !vsel && !narrow()) open(rows[0]);
  }, [rows]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!rd.data) return <Skeleton />;
  const cols: Col<any>[] = [
    {
      l: "", w: "28px",
      v: (x) => {
        const e = x.exception || {};
        return e.fix_available || e.expired ? (
          <span className="mk bad" title={e.expired ? t("expired: back in the plan") : t("fix in the repositories: back in the plan")}>!</span>
        ) : (
          <span className="mk ok" title={t("accepted")}>✓</span>
        );
      },
    },
    { l: t("Package"), w: "minmax(0, .8fr)", c: "pk", v: (x) => x.pkg, s: (x) => x.pkg },
    { l: t("Server"), w: "minmax(84px, .7fr)", v: (x) => <Hcell n={x.host} />, s: (x) => x.host },
    { l: "ID", w: "minmax(0, .8fr)", k: 3, c: "m d", v: (x) => x.id, s: (x) => x.id },
    { l: t("Until"), w: "96px", c: "m", v: (x) => <span className={x.exception?.expired ? "bad" : ""}>{x.exception?.review_by}</span>, s: (x) => x.exception?.review_by || "" },
    { l: t("Who"), w: "minmax(0, .5fr)", k: 2, c: "d", v: (x) => x.exception?.owner, s: (x) => x.exception?.owner || "" },
  ];
  if (!rows.length)
    return (
      <Empty title={ex.length ? t("Nothing matches") : t("No accepted risks")}>
        {ex.length ? null : tx("They live in {section} of the organization file.", { section: <code>exceptions</code> })}
      </Empty>
    );
  return <DataTable id="accepted" cols={cols} items={rows} rowKey={key} sel={vsel} onOpen={open} scrollRef={scrollRef} />;
}

