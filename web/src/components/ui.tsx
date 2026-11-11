// The small pieces every view uses: icons, segmented switches, filter chips, the search field, skeleton rows,
// the empty state, key/value lines and the toast.
import { useEffect, useRef, useState, type ReactNode } from "react";
import { t } from "../lib/i18n";
import { closeDetail, set, toast as say, toggleWide, useApp } from "../state";

export const Icon = ({ name }: { name: string }) => (
  <svg className="i" aria-hidden="true">
    <use href={"#i-" + name} />
  </svg>
);

/** DetailClose: the details panel's way out: Back over the list on a narrow window, × beside it on a wide one. */
export const DetailClose = () => {
  const wide = useApp((s) => s.detailWide);
  const label = wide ? t("Beside the list") : t("Full width");
  return (
    <>
      <button className="btn ghost back" onClick={closeDetail}>
        <Icon name="left" />
        {t("Back")}
      </button>
      <button className="lnk dwide" aria-label={label} aria-pressed={wide} title={label} onClick={toggleWide}>
        <Icon name={wide ? "narrow" : "wide"} />
      </button>
      <button className="lnk dclose" aria-label={t("Close")} title={t("Close")} onClick={closeDetail}>
        <Icon name="x" />
      </button>
    </>
  );
};

export const Spin = () => <i className="spin" />;

/** Seg: a labelled row of buttons, one pressed. */
export function Seg<K extends string>(p: { label: string; aria: string; items: [K, string][]; value: K; onPick: (k: K) => void }) {
  return (
    <div className="seg2" role="group" aria-label={p.aria}>
      {p.label && <span className="lbl">{p.label}</span>}
      {p.items.map(([k, l]) => (
        <button key={k} aria-pressed={p.value === k} onClick={() => p.onPick(k)}>
          {l}
        </button>
      ))}
    </div>
  );
}

/** Chips: filter toggles. */
export function Chips(p: { items: [string, string][]; on: Set<string>; onToggle: (k: string) => void; children?: ReactNode }) {
  return (
    <div className="chips">
      {p.items.map(([k, l]) => (
        <button key={k} className="chip" aria-pressed={p.on.has(k)} onClick={() => p.onToggle(k)}>
          {l}
        </button>
      ))}
      {p.children}
    </div>
  );
}

/** Search: the filter field ("/" focuses it, Esc leaves it). */
export function Search(p: { value: string; onChange: (v: string) => void; placeholder: string }) {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if (e.key === "/" && !(e.target as HTMLElement).matches?.("input, select, textarea")) {
        e.preventDefault();
        ref.current?.focus();
      }
    };
    addEventListener("keydown", k);
    return () => removeEventListener("keydown", k);
  }, []);
  return (
    <label className="search">
      <Icon name="search" />
      <span className="sr">{t("Filter")}</span>
      <input
        ref={ref}
        placeholder={p.placeholder}
        value={p.value}
        autoComplete="off"
        onChange={(e) => p.onChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key !== "Escape") return;
          if (p.value) p.onChange("");
          else e.currentTarget.blur();
        }}
      />
      {p.value ? (
        <button type="button" className="clr" title={t("Clear filters")} aria-label={t("Clear filters")} onClick={() => p.onChange("")}>
          <Icon name="x" />
        </button>
      ) : (
        <kbd>/</kbd>
      )}
    </label>
  );
}

/** Skeleton: grey rows in the shape of what is coming (lists), or of a details panel. */
export function Skeleton({ rows = 12, kind = "rows" }: { rows?: number; kind?: "rows" | "detail" }) {
  if (kind === "detail")
    return (
      <div className="skel-detail" aria-busy="true">
        <i className="sk w30" />
        <i className="sk w70 big" />
        <i className="sk w50" />
        <div className="sk-kpis">
          <i className="sk" />
          <i className="sk" />
          <i className="sk" />
        </div>
        {Array.from({ length: 6 }, (_, i) => (
          <i key={i} className={"sk w" + [90, 80, 85, 60, 75, 40][i]} />
        ))}
      </div>
    );
  return (
    <div className="skel-rows" aria-busy="true">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="skel-row">
          <i className="sk pill" />
          <i className={"sk w" + [60, 45, 70, 50, 65, 40, 55][i % 7]} />
          <i className="sk w20" />
          <i className="sk w10" />
        </div>
      ))}
    </div>
  );
}

export function Empty(p: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <h3>{p.title}</h3>
      {p.children}
    </div>
  );
}

export const Kv = ({ k, children }: { k: string; children: ReactNode }) =>
  children === "" || children == null || children === false ? null : (
    <div className="kv">
      <span>{k}</span>
      <span>{children}</span>
    </div>
  );

export const Sec = ({ title, children }: { title: string; children: ReactNode }) =>
  !children ? null : (
    <div className="sec">
      <h4>{title}</h4>
      {children}
    </div>
  );

export function Toast() {
  const toast = useApp((s) => s.toast);
  useEffect(() => {
    if (!toast) return;
    const id = setTimeout(() => set({ toast: null }), 2600);
    return () => clearTimeout(id);
  }, [toast]);
  return (
    <div className={"toast" + (toast ? " on" : "")} role="status" aria-live="polite">
      {toast?.text}
    </div>
  );
}

export async function copy(text: string, what?: string) {
  try {
    await navigator.clipboard.writeText(text);
    say(what || t("Copied"));
  } catch {
    say(t("Copy failed: select and copy by hand"));
  }
}

/** SortHead: a column heading that orders the rows by it (asc: its first order is A to Z, earliest, most urgent);
 * again: the other way; a third time: back to priority. */
export function SortHead(p: {
  k: string;
  sort: string;
  onSort: (k: string) => void;
  asc?: boolean;
  className?: string;
  children: ReactNode;
}) {
  const first = p.sort === p.k,
    other = p.sort === "-" + p.k;
  const up = (first && p.asc) || (other && !p.asc);
  return (
    <span className={p.className} aria-sort={first || other ? (up ? "ascending" : "descending") : undefined}>
      <button type="button" className="sorth" onClick={() => p.onSort(p.k)}>
        {p.children}
        {first || other ? (up ? " ↑" : " ↓") : ""}
      </button>
    </span>
  );
}

/** useNow: the time, a second fresh while active (a timer on screen); the time of the first draw otherwise. */
export function useNow(active: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [active]);
  return now;
}
