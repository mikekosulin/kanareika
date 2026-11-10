// The cells of a tree row (ToDo, Servers grouped by fix or CVE): what it is, where, how urgent, in what state.
import { t } from "../lib/i18n";
import { days, dueText, pct } from "../lib/format";
import type { TreeNode } from "../types";

export const ST: Record<string, string> = {
  available: "fix ready",
  reboot: "reboot pending",
  vendor: "no fix yet",
  backported: "fixed (backport)",
  other: "",
};
export const NOFIX: Record<string, string> = {
  pending: "no fix released yet",
  repos: "released, not in this host's repositories",
  esm: "only with Ubuntu Pro (ESM)",
  deferred: "deferred by the vendor",
  wontfix: "won't be fixed",
};

/** noFixTxt: why there is nothing to install; several reasons each with its host count. */
export function noFixTxt(nf?: Record<string, number>) {
  const ks = Object.keys(nf || {}).filter((k) => NOFIX[k]);
  if (!ks.length) return t("no fix in the repositories yet");
  return ks.length === 1 ? t(NOFIX[ks[0]]) : ks.map((k) => `${t(NOFIX[k])} (${nf![k]})`).join(", ");
}

export function KindSlot({ n }: { n: TreeNode }) {
  const k =
    n.kind === "image" || n.kind === "where"
      ? [n.runtime, "img"]
      : n.kind === "pkg" || n.kind === "part"
        ? [n.path ? "lib" : "os", "mut"]
        : n.kind === "other"
          ? [n.title, "mut"]
          : n.kind === "cve"
            ? [(n.severity || "").slice(0, 4).toLowerCase(), "sev-" + n.severity]
            : ["", ""];
  return <span className={"kd " + k[1]}>{k[0]}</span>;
}

export function MainText({ n }: { n: TreeNode }) {
  const ver = n.fixed ? (
    <>
      <code className="from" title={n.installed}>
        {n.installed}
      </code>
      <code className="arr">→</code>
      <code className="to">{n.fixed}</code>
    </>
  ) : n.installed ? (
    <>
      <code className="from">{n.installed}</code>
      <span className="ttl">{noFixTxt(n.no_fix)}</span>
    </>
  ) : null;
  switch (n.kind) {
    case "pkg":
    case "part":
      return (
        <>
          <code className="pkg">{n.label}</code>
          {ver}
          {n.path && (
            <code className="kind path" title={n.path}>
              {n.path}
            </code>
          )}
        </>
      );
    case "image":
      return (
        <>
          <code className="pkg">{n.label.replace(/^.*\//, "")}</code>
          <span className="ttl" title={n.label}>
            {t("rebuild the image")}
          </span>
        </>
      );
    case "where":
      return (
        <span className="ttl" style={{ color: "var(--ink)" }}>
          {n.label}
        </span>
      );
    case "cve":
      return (
        <>
          <span className="cveid">{n.label}</span>
          <span className="ttl">{n.title}</span>
        </>
      );
    case "group":
      return (
        <>
          <span className="hostn" style={{ color: "var(--ink)" }}>
            {n.label}
          </span>
          <span className="kind">
            {n.hosts} {t("hosts")}
            {n.os ? " · " + n.os : ""}
          </span>
        </>
      );
    case "host":
      return (
        <>
          <span className="hostn">{n.label}</span>
          <span className="kind">
            {n.os}
            {n.exposure === 1 ? " · " + t("Public") : ""}
          </span>
        </>
      );
    case "other":
      return (
        <span className="pkg" style={{ fontWeight: 500 }}>
          {n.label}
        </span>
      );
    case "section":
      return <span className="secl">{n.label === "parts" ? t("inside the image") : t("runs on")}</span>;
  }
  return <>{n.label}</>;
}

export function HostsCell({ n }: { n: TreeNode }) {
  if (!n.hosts) return null;
  const groups = (n.groups || []).map((g) => `${g.name} ${g.n}`);
  const txt = n.host_list && n.host_list.length <= 2 ? n.host_list.join(", ") : groups.join(" · ");
  return (
    <>
      <b>{n.hosts}</b>
      <span title={groups.join(", ")}>{txt}</span>
    </>
  );
}

export function StateCell({ st }: { st?: Record<string, number> }) {
  const ks = Object.keys(st || {}).filter((k) => k !== "other");
  if (!ks.length) return null;
  if (ks.length === 1) return <span className={"st " + ks[0]}>{t(ST[ks[0]])}</span>;
  ks.sort((a, b) => st![b] - st![a]);
  const txt = ks.map((k) => `${st![k]} ${t(ST[k])}`);
  return (
    <span className="st mixed" title={txt.join(", ")}>
      {txt.join(" · ")}
    </span>
  );
}

export const Flags = ({ n }: { n: { kev?: boolean; rce?: boolean; preauth?: boolean } }) => (
  <>
    {n.kev && <span className="fl kev">KEV</span>}
    {n.rce ? <span className="fl rce">RCE</span> : n.preauth ? <span className="fl pre">pre-auth</span> : null}
  </>
);

export const EPSS = ({ e }: { e: number }) =>
  e ? (
    <span className={"epss " + (e >= 0.1 ? "hi" : "")}>
      <i>
        <b style={{ width: Math.max(4, e * 100) + "%" }} />
      </i>
      <span>{pct(e)}</span>
    </span>
  ) : null;

export const Due = ({ due }: { due?: string }) => (
  <span className={"dd " + (due && days(due) <= 7 ? "soon" : "")} title={due || ""}>
    {dueText(due)}
  </span>
);

export const Prio = ({ p }: { p?: string }) => (p ? <span className={"pb " + p}>{p}</span> : <span />);
