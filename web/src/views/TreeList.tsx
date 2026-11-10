// The tree of fixes (ToDo; Servers grouped by fix or CVE): rows a level at a time, an open row's kids asked for
// when it opens, only the rows on screen in the page (a CVE grouping has tens of thousands).
import { useEffect, useMemo, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { t } from "../lib/i18n";
import { closeDetail, set, toggle, useApp, useS } from "../state";
import { client, useKids, type TreeParams } from "../queries";
import type { TreeNode } from "../types";
import { Due, EPSS, Flags, HostsCell, KindSlot, MainText, Prio, ST, StateCell } from "../components/cells";
import { Icon, Skeleton } from "../components/ui";

export type Row =
  | { type: "node"; n: TreeNode; depth: number }
  | { type: "sec"; n: TreeNode; depth: number }
  | { type: "cloud"; kids: TreeNode[]; depth: number; key: string }
  | { type: "wait"; depth: number; key: string }
  | { type: "page"; depth: 0; key: string }; // a top row of a page not loaded yet (the list has its full length)

/** kidsOf: a row's kids, as the tree came (expand all) or as asked for. */
const kidsOf = (n: TreeNode, got: Map<string, TreeNode[]>) => n.kids || got.get(n.id);

/** flatten: the rows on screen, open rows' kids under them. */
export function flatten(nodes: TreeNode[], open: Set<string>, got: Map<string, TreeNode[]>): Row[] {
  const out: Row[] = [];
  const walk = (ns: TreeNode[], depth: number) => {
    for (const n of ns) {
      if (n.kind === "section") {
        out.push({ type: "sec", n, depth });
        continue;
      }
      out.push({ type: "node", n, depth });
      if (!open.has(n.id)) continue;
      const kids = kidsOf(n, got);
      if (!kids) {
        if (n.more) out.push({ type: "wait", depth: depth + 1, key: n.id + "/…" });
        continue;
      }
      // a group's hosts with nothing under them: one row of names
      if (n.kind === "group" && kids.length && kids.every((k) => k.kind === "host" && !(k.kids || []).length && !k.more))
        out.push({ type: "cloud", kids, depth: depth + 1, key: n.id + "/hosts" });
      else walk(kids, depth + 1);
    }
  };
  walk(nodes, 0);
  return out;
}

/** wanted: the open rows whose kids have not come. */
export function wanted(nodes: TreeNode[], open: Set<string>, got: Map<string, TreeNode[]>) {
  const out: string[] = [];
  const walk = (ns: TreeNode[]) => {
    for (const n of ns) {
      if (!open.has(n.id)) continue;
      const kids = kidsOf(n, got);
      if (kids) walk(kids);
      else if (n.more) out.push(n.id);
    }
  };
  walk(nodes);
  return out;
}

export function useRows(nodes: TreeNode[], p: TreeParams) {
  const open = useApp((s) => s.open);
  // the kids asked for so far, from the cache; useKids asks for the rest and draws again when they come, so open
  // rows inside them are asked for on the next round
  const ids = wanted(nodes, open, cached(p));
  const got = useKids(p, ids);
  return useMemo(() => flatten(nodes, open, cached(p)), [nodes, open, got, p]); // eslint-disable-line react-hooks/exhaustive-deps
}

/** cached: the kids the cache holds for p, by row. */
function cached(p: TreeParams) {
  const out = new Map<string, TreeNode[]>();
  for (const [key, data] of client.getQueriesData<TreeNode[]>({ queryKey: ["kids", p] })) if (data) out.set(key[2] as string, data);
  return out;
}

export function TreeRows(p: {
  rows: Row[];
  scrollRef: React.RefObject<HTMLDivElement | null>;
  selectable: boolean;
  onShow: (id: string) => void;
  onEnd?: () => void; // the list is shown near (or past) its last loaded row: the next page
}) {
  const { cur, sel, open } = useS((s) => ({ cur: s.cur, sel: s.sel, open: s.open }));
  const listRef = useRef<HTMLDivElement>(null);
  const v = useVirtualizer({
    count: p.rows.length,
    getScrollElement: () => p.scrollRef.current,
    estimateSize: (i) => (p.rows[i].type === "sec" ? 27 : p.rows[i].depth ? 35 : 41),
    overscan: 16,
    scrollMargin: listRef.current?.offsetTop ?? 0,
    getItemKey: (i) => {
      const r = p.rows[i];
      return r.type === "cloud" || r.type === "wait" || r.type === "page" ? r.key : r.n.id + (r.type === "sec" ? "#" + i : "");
    },
  });
  // the row under the cursor stays on screen (keys, a jump from the palette)
  useEffect(() => {
    if (!cur) return;
    const i = p.rows.findIndex((r) => r.type === "node" && r.n.id === cur);
    if (i >= 0) v.scrollToIndex(i, { align: "auto" });
  }, [cur]); // eslint-disable-line react-hooks/exhaustive-deps
  const items = v.getVirtualItems();
  const margin = v.options.scrollMargin;
  const lastShown = items.length ? items[items.length - 1].index : -1;
  useEffect(() => {
    if (!p.onEnd) return;
    const loaded = p.rows.findIndex((r) => r.type === "page");
    if (lastShown >= (loaded < 0 ? p.rows.length : loaded) - 60) p.onEnd();
  }, [lastShown, p.rows.length, p.onEnd]); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <div ref={listRef} role="tree" id="tree" className="vlist" style={{ height: v.getTotalSize() }}>
      {items.map((it) => {
        const r = p.rows[it.index];
        return (
          <div
            key={it.key}
            className="vrow-wrap"
            data-index={it.index}
            ref={v.measureElement}
            style={{ transform: `translateY(${it.start - margin}px)` }}
          >
            {r.type === "node" ? (
              <NodeRow
                n={r.n}
                depth={r.depth}
                open={open.has(r.n.id)}
                cur={cur === r.n.id}
                sel={sel.has(r.n.id)}
                selectable={p.selectable}
                onShow={p.onShow}
              />
            ) : r.type === "sec" ? (
              <div className="node sec">
                <span />
                <span />
                <span />
                <span className="main" style={{ paddingLeft: r.depth * 20 }}>
                  <span className="kd" />
                  <MainText n={r.n} />
                </span>
              </div>
            ) : r.type === "cloud" ? (
              <div className="node cloud">
                <span />
                <span />
                <span />
                <span className="main" style={{ paddingLeft: r.depth * 20 + 60 }}>
                  {r.kids.map((k) => {
                    const st = Object.keys(k.states || {})[0] || "available";
                    return (
                      <button key={k.id} className={"hc " + st} aria-pressed={cur === k.id} title={k.os} onClick={() => p.onShow(k.id)}>
                        {k.label}
                        {st !== "available" && st !== "other" && <small>{t(ST[st])}</small>}
                      </button>
                    );
                  })}
                </span>
              </div>
            ) : r.type === "page" ? (
              <div className="node pagewait" aria-hidden="true">
                <i className="sk w60" />
              </div>
            ) : (
              <div style={{ paddingLeft: r.depth * 20 }}>
                <Skeleton rows={2} />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function NodeRow(p: {
  n: TreeNode;
  depth: number;
  open: boolean;
  cur: boolean;
  sel: boolean;
  selectable: boolean;
  onShow: (id: string) => void;
}) {
  const { n, depth } = p;
  const has = !!((n.kids && n.kids.length) || n.more);
  return (
    <div
      className={"node " + (depth ? "kid" : "")}
      role="treeitem"
      aria-level={depth + 1}
      aria-expanded={has ? p.open : undefined}
      aria-selected={p.cur}
      onClick={() => p.onShow(n.id)}
    >
      {has ? (
        <button
          className="tw"
          aria-expanded={p.open}
          aria-label={p.open ? t("Collapse") : t("Expand")}
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
      {p.selectable ? (
        <input
          type="checkbox"
          className="cb2"
          checked={p.sel}
          aria-label={t("Select")}
          onClick={(e) => e.stopPropagation()}
          onChange={() => set((s) => ({ sel: toggle(s.sel, n.id) }))}
        />
      ) : (
        <span />
      )}
      <Prio p={n.priority} />
      <span className="main" style={{ paddingLeft: depth * 20 }}>
        <KindSlot n={n} />
        <MainText n={n} />
      </span>
      <span className="hcell c-h">{depth && n.kind === "host" ? null : <HostsCell n={n} />}</span>
      <span className="num c-cve">{n.cves || ""}</span>
      <span className="c-ep">
        <EPSS e={n.epss} />
      </span>
      <span className="flags c-fl">
        <Flags n={n} />
      </span>
      <span className="c-st">{n.kind === "other" ? null : <StateCell st={n.states} />}</span>
      <Due due={n.due} />
    </div>
  );
}

/** treeKeys: j/k (arrows) move, l/h open and close, Enter shows, x (space) selects. */
export function useTreeKeys(rows: Row[], onShow: (id: string) => void, selectable: boolean) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      const tgt = e.target as HTMLElement;
      if (tgt.matches?.("input, select, textarea") || e.metaKey || e.ctrlKey) return;
      const s = useApp.getState();
      if (s.palOpen) return;
      const flat = rows.filter((r): r is Extract<Row, { type: "node" }> => r.type === "node").map((r) => r.n);
      const i = flat.findIndex((n) => n.id === s.cur);
      const n = flat[i];
      if (e.key === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        if (flat[i + 1]) onShow(flat[i + 1].id);
      } else if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        if (flat[i - 1]) onShow(flat[i - 1].id);
      } else if ((e.key === "l" || e.key === "ArrowRight") && n && ((n.kids || []).length || n.more)) {
        set({ open: new Set(s.open).add(n.id) });
      } else if ((e.key === "h" || e.key === "ArrowLeft") && n && s.open.has(n.id)) {
        set({ open: toggle(s.open, n.id) });
      } else if (e.key === "Enter" && n) {
        e.preventDefault();
        onShow(n.id);
      } else if ((e.key === "x" || e.key === " ") && n && selectable) {
        e.preventDefault();
        set({ sel: toggle(s.sel, n.id) });
      } else if (e.key === "Escape") closeDetail();
    };
    addEventListener("keydown", k);
    return () => removeEventListener("keydown", k);
  }, [rows, onShow, selectable]);
}
