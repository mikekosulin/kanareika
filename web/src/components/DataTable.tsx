// A table of rows (History, accepted risks, the server lenses): columns that drop out on a narrow list, sorting
// by a column, only the rows on screen in the page, j/k to move.
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { closeDetail, useApp } from "../state";

export interface Col<T> {
  l: string; // label
  w: string; // grid width
  k?: 1 | 2 | 3; // shown from: 1 always, 2 from 620px of list, 3 from 900px
  c?: string; // class
  v: (x: T) => ReactNode;
  s?: (x: T) => string | number | boolean; // sort value
  d0?: 1 | -1; // first sort direction
}

const sorts = new Map<string, { i: number; d: number }>(); // per table, for the page's life

export function DataTable<T>(p: {
  id: string; // what the sort is remembered by
  cols: Col<T>[];
  items: T[];
  rowKey: (x: T) => string;
  sel: string;
  onOpen: (x: T) => void;
  scrollRef: React.RefObject<HTMLDivElement | null>;
}) {
  const [sort, setSort] = useState(() => sorts.get(p.id));
  useEffect(() => setSort(sorts.get(p.id)), [p.id]);
  const xs = useMemo(() => {
    if (!sort) return p.items;
    const c = p.cols[sort.i];
    if (!c?.s) return p.items;
    const f = c.s,
      d = sort.d;
    return [...p.items].sort((a, b) => {
      const x = f(a),
        y = f(b);
      return (x < y ? -1 : x > y ? 1 : 0) * d;
    });
  }, [p.items, p.cols, sort]);
  const tpl = (lv: number) =>
    p.cols
      .filter((c) => (c.k || 1) <= lv)
      .map((c) => c.w)
      .join(" ");
  const cls = (c: Col<T>) => `${c.c || ""} ${c.k === 2 ? "k2" : c.k === 3 ? "k3" : ""}`;
  const listRef = useRef<HTMLDivElement>(null);
  const v = useVirtualizer({
    count: xs.length,
    getScrollElement: () => p.scrollRef.current,
    estimateSize: () => 39,
    overscan: 16,
    scrollMargin: listRef.current?.offsetTop ?? 0,
    getItemKey: (i) => p.rowKey(xs[i]),
  });
  // j/k (arrows): the next or previous row; Esc puts the details away
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement).matches?.("input, select, textarea") || useApp.getState().palOpen) return;
      if (e.key === "Escape") return closeDetail();
      const step = e.key === "j" || e.key === "ArrowDown" ? 1 : e.key === "k" || e.key === "ArrowUp" ? -1 : 0;
      if (!step || !xs.length) return;
      e.preventDefault();
      const i = xs.findIndex((x) => p.rowKey(x) === p.sel);
      const n = Math.max(0, Math.min(xs.length - 1, i + step));
      p.onOpen(xs[n]);
      v.scrollToIndex(n, { align: "auto" });
    };
    addEventListener("keydown", k);
    return () => removeEventListener("keydown", k);
  }, [xs, p.sel]); // eslint-disable-line react-hooks/exhaustive-deps
  const margin = v.options.scrollMargin;
  return (
    <div className="vt" role="table" style={{ "--c1": tpl(3), "--c2": tpl(2), "--c3": tpl(1) } as React.CSSProperties}>
      <div className="vhead" role="row">
        {p.cols.map((c, i) => (
          <span key={i} className={cls(c)} role="columnheader">
            {c.s ? (
              <button
                aria-sort={sort?.i === i ? (sort.d > 0 ? "ascending" : "descending") : undefined}
                onClick={() => {
                  const n = { i, d: sort?.i === i ? -sort.d : c.d0 || 1 };
                  sorts.set(p.id, n);
                  setSort(n);
                }}
              >
                {c.l}
                {sort?.i === i ? (sort.d > 0 ? " ↑" : " ↓") : ""}
              </button>
            ) : (
              c.l
            )}
          </span>
        ))}
      </div>
      <div ref={listRef} className="vlist" style={{ height: v.getTotalSize() }}>
        {v.getVirtualItems().map((it) => {
          const x = xs[it.index];
          return (
            <div
              key={it.key}
              data-index={it.index}
              ref={v.measureElement}
              className="vrow vrow-wrap"
              role="row"
              tabIndex={-1}
              aria-selected={p.rowKey(x) === p.sel}
              style={{ transform: `translateY(${it.start - margin}px)` }}
              onClick={() => p.onOpen(x)}
            >
              {p.cols.map((c, i) => (
                <span key={i} className={cls(c)}>
                  {c.v(x)}
                </span>
              ))}
            </div>
          );
        })}
      </div>
    </div>
  );
}
