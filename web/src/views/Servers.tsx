// Servers: every server of the environment, the most urgent first, clean ones last; a server's fixes under it;
// other columns for every server (lenses: logins, network, health); the server's card beside.
import { useCallback, useEffect, useMemo, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { t } from "../lib/i18n";
import { ago, days, dueText, narrow, pct } from "../lib/format";
import { set, setBy, syncURL, toggle, useApp, useS } from "../state";
import { client, treeParams, useEnv, useKids, useLens, useNode, useRunData, useTree, type TreeParams } from "../queries";
import type { Tree, TreeNode } from "../types";
import { Chips, Empty, Icon, Search, Seg, Skeleton } from "../components/ui";
import { DataTable, type Col } from "../components/DataTable";
import { MainText } from "../components/cells";
import { GROUPS, useQueryInput } from "./Todo";
import { Hcell, HostDetail, SrvMark, useText } from "./HostDetail";
import { NodeDetail } from "./NodeDetail";
import { Banner, NoRuns } from "./Shell";

const SFILT: [string, string][] = [["front", "Public"], ["kev", "KEV"], ["overdue", "overdue"]];
const LENS_DEFAULT = [["priorities", "Priorities"], ["logins", "Logins"], ["network", "Network"], ["health", "Health"]].map(([id, title]) => ({ id, title }));

let lastP: TreeParams | null = null;
const params = (s: Parameters<typeof treeParams>[0]) => {
  const p = { ...treeParams(s), by: "host" as const };
  if (lastP && JSON.stringify(lastP) === JSON.stringify(p)) return lastP;
  return (lastP = p);
};

type SRow = { n: TreeNode; depth: number };

export function Servers() {
  const s = useS((s) => ({ lens: s.lens, flt: s.flt, p4: s.p4, q: s.q, open: s.open, cur: s.cur, wantHost: s.wantHost }));
  const p = useApp(params);
  const tree = useTree(p, true);
  const lens = useLens(s.lens);
  const env = useEnv();
  const [text, setText] = useQueryInput();
  const scrollRef = useRef<HTMLDivElement>(null);
  const tr = tree.data;
  const list = useMemo(() => serverList(tr, env.data?.hosts), [tr, env.data]);
  const byName = useMemo(() => new Map(list.map((n) => [n.label, n])), [list]);
  const lenses = (lens.data?.lenses?.length ? lens.data.lenses : LENS_DEFAULT) as { id: string; title: string }[];

  // the card: the server in the address, the one picked, or the first on a wide window
  useEffect(() => {
    if (!tr || tree.isPlaceholderData) return;
    const st = useApp.getState();
    if (st.wantHost) {
      set({ cur: "h:" + st.wantHost, wantHost: "", detailOpen: narrow() });
      syncURL();
    } else if (!st.cur && list[0] && !narrow()) set({ cur: list[0].id });
  }, [tr, tree.isPlaceholderData]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => syncURL(), [s.lens]);

  if (tree.error && (tree.error as any).status === 404) return <NoRuns />;
  return (
    <>
      <Banner />
      <div className="work">
        <div className="listcol">
          <div className="work-top">
            <div className="hdr">
              <div style={{ minWidth: 0 }}>
                <h1>{t("Servers")}</h1>
                <div className="sub">{tr && <ServersSub tr={tr} list={list} />}</div>
              </div>
            </div>
          </div>
          <div className="bar2 vbar">
            <Seg label={t("group")} aria={t("Group by")} items={GROUPS.map(([k, l]) => [k, t(l)])} value="host" onPick={setBy} />
            <Seg label={t("show")} aria={t("Show")} items={lenses.map((l) => [l.id, t(l.title)])} value={s.lens} onPick={(id) => set({ lens: id, vsel: "" })} />
            {s.lens === "priorities" && (
              <Chips items={SFILT.map(([k, l]) => [k, t(l)])} on={s.flt} onToggle={(k) => set((st) => ({ flt: toggle(st.flt, k) }))}>
                <button className="chip" aria-pressed={s.p4} onClick={() => set((st) => ({ p4: !st.p4 }))}>
                  + P4
                </button>
              </Chips>
            )}
            <Search value={text} onChange={setText} placeholder={t("Filter")} />
          </div>
          <div className="scroll" ref={scrollRef}>
            {s.lens === "priorities" ? (
              <>
                <div className="svh">
                  <span />
                  <span />
                  <span>{t("Server")}</span>
                  <span>{t("Priorities")}</span>
                  <span className="r c-fx">{t("Fixes")}</span>
                  <span className="r c-sc">{t("Scanned")}</span>
                </div>
                {!tr ? (
                  <Skeleton />
                ) : !list.length ? (
                  <Empty title={s.flt.size || s.q ? t("Nothing matches") : t("No servers")}>
                    {s.flt.size || s.q ? (
                      <button className="btn ghost" onClick={() => set({ flt: new Set(), q: "" })}>
                        {t("Clear filters")}
                      </button>
                    ) : (
                      t("No server in this environment has been scanned.")
                    )}
                  </Empty>
                ) : (
                  <div className={tree.isPlaceholderData ? "stale" : ""}>
                    <ServerRows list={list} p={p} scrollRef={scrollRef} />
                  </div>
                )}
              </>
            ) : (
              <LensTable lens={lens} q={s.q} byName={byName} scrollRef={scrollRef} />
            )}
            <div className="end" />
          </div>
        </div>
        <ServerDetail byName={byName} p={p} />
      </div>
    </>
  );
}

// the backend's rows as they come: servers (with their state and problem) and org-level targets (a cluster)
function serverList(tr: Tree | undefined, hosts?: { name: string }[]) {
  const out: (TreeNode & { target?: boolean })[] = [];
  const walk = (ns: TreeNode[]) => ns.forEach((n) => (n.kind === "host" ? out.push(n) : walk(n.kids || [])));
  walk(tr?.nodes || []);
  const known = new Set((hosts || []).map((h) => h.name));
  return out.map((n) => ({ ...n, target: known.size > 0 && !known.has(n.label) }));
}

function ServersSub({ tr, list }: { tr: Tree; list: (TreeNode & { target?: boolean })[] }) {
  const c = tr.counts || {}, sv = tr.servers || {};
  const servers = list.filter((n) => !n.target).length;
  const st = ([["clean", "ok", "✓", "nothing to fix"], ["failed", "bad", "✗", "not reached"], ["partial", "wn", "◐", "partly checked"], ["not_scanned", "z", "–", "not scanned yet"]] as const).filter(([k]) => sv[k]);
  return (
    <span className="mono">
      <span title={t("servers")}>{servers}</span> ·{" "}
      {["P1", "P2", "P3", "P4"].map((p, i) => (
        <span key={p}>
          {i > 0 && <span className="z"> • </span>}
          <b className={"c" + p}>
            {p} {c[p] || 0}
          </b>
        </span>
      ))}
      {st.map(([k, cls, m, l]) => (
        <span key={k}>
          {" · "}
          <span className={cls} title={t(l)}>
            {sv[k]} {m}
          </span>
        </span>
      ))}
    </span>
  );
}

function ServerRows({ list, p, scrollRef }: { list: (TreeNode & { target?: boolean })[]; p: TreeParams; scrollRef: React.RefObject<HTMLDivElement | null> }) {
  const { open, p4, cur } = useS((s) => ({ open: s.open, p4: s.p4, cur: s.cur }));
  const kp = useMemo(() => ({ ...p, all: 1 }) as TreeParams, [p]);
  // the rows open at any depth (a server, an image in it) whose kids came without them: asked for once each
  const ids: string[] = [];
  const rows: SRow[] = [];
  const walk = (n: TreeNode, depth: number) => {
    rows.push({ n, depth });
    if (!open.has(n.id)) return;
    const kids = n.kids || client.getQueryData<TreeNode[]>(["kids", kp, n.id]);
    if (!kids) {
      if (n.more) ids.push(n.id);
      return;
    }
    kids.filter((k) => k.kind !== "section" && (p4 || k.priority !== "P4")).forEach((k) => walk(k, depth + 1));
  };
  list.forEach((n) => walk(n, 0));
  useKids(kp, ids);
  const listRef = useRef<HTMLDivElement>(null);
  const v = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: (i) => (rows[i].depth ? 35 : 41),
    overscan: 16,
    scrollMargin: listRef.current?.offsetTop ?? 0,
    getItemKey: (i) => rows[i].n.id,
  });
  const show = useCallback((id: string) => set({ cur: id, stack: [], detailOpen: narrow() }), []);
  // j/k move, l/h open and close, Enter shows
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement).matches?.("input, select, textarea") || useApp.getState().palOpen || e.metaKey || e.ctrlKey) return;
      const s = useApp.getState(), i = rows.findIndex((r) => r.n.id === s.cur), n = rows[i]?.n;
      if (e.key === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        if (rows[i + 1]) show(rows[i + 1].n.id);
      } else if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        if (rows[i - 1]) show(rows[i - 1].n.id);
      } else if ((e.key === "l" || e.key === "ArrowRight") && n) set({ open: new Set(s.open).add(n.id) });
      else if ((e.key === "h" || e.key === "ArrowLeft") && n && s.open.has(n.id)) set({ open: toggle(s.open, n.id) });
      else if (e.key === "Escape") set({ detailOpen: false });
    };
    addEventListener("keydown", k);
    return () => removeEventListener("keydown", k);
  }, [rows, show]);
  useEffect(() => {
    const i = rows.findIndex((r) => r.n.id === cur);
    if (i >= 0) v.scrollToIndex(i, { align: "auto" });
  }, [cur]); // eslint-disable-line react-hooks/exhaustive-deps
  const margin = v.options.scrollMargin;
  return (
    <div ref={listRef} role="tree" id="tree" className="vlist" style={{ height: v.getTotalSize() }}>
      {v.getVirtualItems().map((it) => {
        const { n, depth } = rows[it.index];
        return (
          <div key={it.key} className="vrow-wrap" data-index={it.index} ref={v.measureElement} style={{ transform: `translateY(${it.start - margin}px)` }}>
            <ServerRow n={n} depth={depth} open={open.has(n.id)} cur={cur === n.id} hasKids={!!(n.more || (n.kids || []).some((k) => k.kind !== "section" && (p4 || k.priority !== "P4")))} onShow={show} />
          </div>
        );
      })}
    </div>
  );
}

function ServerRow({ n, depth, open, cur, hasKids, onShow }: { n: TreeNode & { target?: boolean }; depth: number; open: boolean; cur: boolean; hasKids: boolean; onShow: (id: string) => void }) {
  const { problemText } = useText();
  let name, pri, fx = "", sc;
  if (n.kind === "host") {
    const c = n.counts || {}, why = problemText(n), sub = n.state === "failed" || n.state === "partial" || n.state === "not_scanned" ? why : n.os_short || n.os || "";
    name = (
      <>
        <span className="hostn" title={n.label}>
          {n.label}
        </span>
        {n.target ? (
          <span className="tgt">{t(n.label.startsWith("k8s:") ? "cluster" : "target")}</span>
        ) : (
          <span className={"os " + (sub === why && why ? "prob" : "")} title={sub}>
            {sub}
          </span>
        )}
        {(n.exposure === 1 || n.public) && (
          <span className="inet" title={t("reachable from the internet: its findings rank higher")}>
            {t("Public")}
          </span>
        )}
      </>
    );
    pri =
      n.state === "clean" ? t("nothing to fix")
      : !n.fixes && (n.state === "failed" || n.state === "not_scanned") ? t("not checked")
      : ["P1", "P2", "P3", "P4"].map((p, i) => (
          <span key={p}>
            {i > 0 && <i>•</i>}
            {c[p] ? <b className={"c" + p}>{c[p]}</b> : "0"}
          </span>
        ));
    fx = n.fixes ? String(n.fixes) : "";
    sc = n.last_scan ? (
      <span className={n.state === "failed" ? "bad" : ""} title={n.last_scan}>
        {ago(n.last_scan)}
      </span>
    ) : "—";
  } else {
    name = (
      <>
        <span style={{ width: (depth - 1) * 20 }} />
        <MainText n={n} />
      </>
    );
    pri = [n.cves ? `${n.cves} CVE` : "", n.kev ? "KEV" : "", n.kind === "cve" && n.epss ? "EPSS " + pct(n.epss) : ""].filter(Boolean).join(" · ");
    sc = n.due ? (
      <span className={days(n.due) < 0 ? "late" : ""} title={n.due}>
        {dueText(n.due)}
      </span>
    ) : null;
  }
  return (
    <div
      className={"sv " + (depth ? "kid" : n.state || "")}
      style={depth ? ({ "--d": depth } as React.CSSProperties) : undefined}
      role="treeitem"
      aria-level={depth + 1}
      aria-expanded={hasKids ? open : undefined}
      aria-selected={cur}
      onClick={() => onShow(n.id)}
    >
      {hasKids ? (
        <button
          className="tw"
          aria-expanded={open}
          aria-label={open ? t("Collapse") : t("Expand")}
          onClick={(e) => {
            e.stopPropagation();
            set((s) => ({ open: toggle(s.open, n.id) }));
          }}
        >
          <Icon name="chev" />
        </button>
      ) : (
        <span />
      )}
      {n.kind === "host" ? <SrvMark n={n} /> : n.priority ? <span className={"pb " + n.priority}>{n.priority}</span> : <span />}
      <span className="nm">{name}</span>
      <span className="pcs">{pri}</span>
      <span className="r c-fx">{fx}</span>
      <span className="r c-sc">{sc}</span>
    </div>
  );
}

/** LensTable: other columns for every server, as /api/lens describes them (a new lens needs no change here). */
function LensTable({ lens, q, byName, scrollRef }: { lens: ReturnType<typeof useLens>; q: string; byName: Map<string, TreeNode>; scrollRef: React.RefObject<HTMLDivElement | null> }) {
  const cur = useApp((s) => s.cur);
  const d = lens.data;
  const rows = useMemo(() => {
    const qq = q.trim().toLowerCase();
    return ((d?.rows || []) as any[]).filter((r) => !qq || r.host.toLowerCase().includes(qq));
  }, [d, q]);
  if (!d) return <Skeleton />;
  if (!rows.length) return <Empty title={t("Nothing matches")} />;
  const LV: Record<string, string> = { warn: "wn", bad: "bad" };
  const cols: Col<any>[] = [
    {
      l: "", w: "28px",
      v: (r) => {
        const n = byName.get(r.host);
        return n && n.state !== "todo" ? <SrvMark n={n} /> : n?.priority ? <span className={"pb " + n.priority}>{n.priority}</span> : null;
      },
    },
    { l: t("Server"), w: "minmax(96px, 1fr)", v: (r) => <Hcell n={r.host} />, s: (r) => r.host },
    ...((d.lens?.columns || []) as any[]).map((c): Col<any> => ({
      l: t(c.title),
      w: c.width_hint ? (typeof c.width_hint === "number" ? c.width_hint + "px" : c.width_hint) : c.kind === "text" ? "minmax(0, 1fr)" : "80px",
      k: c.drop >= 2 ? 3 : c.drop === 1 ? 2 : 1,
      c: c.align === "right" ? "r" : c.kind === "text" ? "d" : "",
      v: (r) => {
        const x = r.cells?.[c.key];
        if (!x) return <span className="z">—</span>;
        return (
          <span className={LV[x.level] || ""} title={x.note || undefined}>
            {x.s ?? (x.v == null ? "—" : x.v + (c.unit || ""))}
          </span>
        );
      },
      s: c.sortable === false ? undefined : (r) => r.cells?.[c.key]?.v ?? "",
      d0: c.align === "right" ? -1 : 1,
    })),
  ];
  return (
    <div className={lens.isPlaceholderData ? "stale" : ""}>
      <DataTable id={"lens/" + (d.lens?.id || "")} cols={cols} items={rows} rowKey={(r) => r.host} sel={cur?.startsWith("h:") ? cur.slice(2) : ""}
        onOpen={(r) => set({ cur: "h:" + r.host, detailOpen: narrow() })} scrollRef={scrollRef} />
    </div>
  );
}

/** ServerDetail: a server's card, or a fix's details for a row under it. */
function ServerDetail({ byName, p }: { byName: Map<string, TreeNode>; p: TreeParams }) {
  const { cur, detailOpen } = useS((s) => ({ cur: s.cur, detailOpen: s.detailOpen }));
  const host = cur?.startsWith("h:") && !cur.includes("/") ? cur.slice(2) : "";
  const rd = useRunData();
  const np = useMemo(() => ({ ...p, all: 1 }) as TreeParams, [p]);
  const node = useNode(np, cur && !host ? cur : null);
  const ref = useRef<HTMLElement>(null);
  useEffect(() => {
    ref.current?.scrollTo(0, 0);
  }, [cur]);
  return (
    <aside ref={ref} className={"detail" + (detailOpen ? " open" : "")} aria-label={t("Details")}>
      {!cur ? null : host ? (
        rd.error ? (
          <div className="nodetail">{(rd.error as Error).message}</div>
        ) : !rd.data ? (
          <Skeleton kind="detail" />
        ) : (
          <HostDetail rd={rd.data} name={host} srv={byName.get(host)} />
        )
      ) : node.error ? (
        <div className="nodetail">{(node.error as Error).message}</div>
      ) : !node.data ? (
        <Skeleton kind="detail" />
      ) : (
        <NodeDetail
          d={node.data}
          onGo={(id) => {
            const s = useApp.getState(), d = node.data!;
            set({ stack: [...s.stack, { id: d.node.id, label: d.node.label }], cur: id });
          }}
          onBack={() => {
            const s = useApp.getState(), pr = s.stack[s.stack.length - 1];
            if (pr) set({ cur: pr.id, stack: s.stack.slice(0, -1) });
          }}
        />
      )}
    </aside>
  );
}
