// Overview: every organization and environment on one page (a place only when there is more than one): its servers,
// its fixes by priority, when it was last scanned and how many servers that scan could not reach; a row opens its
// fixes. "Scan everything" queues a scan of each environment, one after another.
import { useState } from "react";
import { t } from "../lib/i18n";
import { post } from "../lib/api";
import { ago, fmtN } from "../lib/format";
import { go, setScope, toast } from "../state";
import { client, useOrgs, useSession } from "../queries";
import { Icon } from "../components/ui";
import { scopes } from "./Frame";

export function Overview() {
  const orgs = useOrgs().data?.orgs || [];
  const scans = useSession().data?.scans;
  const rows = scopes(orgs);
  const [ask, setAsk] = useState(false);
  const servers = rows.reduce((a, r) => a + r.env.hosts, 0);
  const everything = async () => {
    setAsk(false);
    try {
      const r = await post("/api/scan/all", {});
      const n = (r.ids || []).length;
      toast(n ? t("Scans queued: {n}", { n }) : t("Nothing to scan: every environment is being scanned already"));
      client.invalidateQueries({ queryKey: ["jobs"] });
    } catch (e: any) {
      toast(e.message);
    }
  };
  return (
    <div className="ovw">
      <div className="hdr">
        <div>
          <h1>{t("Overview")}</h1>
          <div className="sub">{t("{e} environments · {s} servers", { e: rows.length, s: fmtN(servers) })}</div>
        </div>
        {scans &&
          (ask ? (
            <div className="ask">
              <span>{t("Scan {e} environments, {s} servers, one after another?", { e: rows.length, s: fmtN(servers) })}</span>
              <button className="btn primary" onClick={everything}>
                {t("Start")}
              </button>
              <button className="btn ghost" onClick={() => setAsk(false)}>
                {t("Cancel")}
              </button>
            </div>
          ) : (
            <button className="btn primary" onClick={() => setAsk(true)}>
              <Icon name="scan" />
              {t("Scan everything…")}
            </button>
          ))}
      </div>
      <div className="tblwrap">
        <table className="tbl ovt">
          <thead>
            <tr>
              <th>{t("Organization")}</th>
              <th>{t("Environment")}</th>
              <th className="r">{t("Servers")}</th>
              {["P1", "P2", "P3", "P4"].map((p) => (
                <th key={p} className="r">
                  {p}
                </th>
              ))}
              <th>{t("Last scan")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(({ org, env }) => {
              const last = env.last,
                tot = last?.totals || {};
              const open = () => {
                setScope({ org: org.id, env: env.env, run: "current" });
                go("todo");
              };
              return (
                <tr key={org.id + "/" + env.env}>
                  <td>
                    <button className="lnk" onClick={open}>
                      {org.name || org.id}
                    </button>
                  </td>
                  <td>{env.env}</td>
                  <td className="r" data-l={t("Servers")}>
                    {env.hosts}
                  </td>
                  {["P1", "P2", "P3", "P4"].map((p) => (
                    <td key={p} className={"r" + (tot[p] && p !== "P4" ? " pc " + p.toLowerCase() : "")} data-l={p}>
                      {last ? tot[p] || 0 : "—"}
                    </td>
                  ))}
                  <td>
                    {last ? (
                      <>
                        {ago(last.finished)}
                        {last.hosts_failed ? <span className="bad"> · {t("{n} not reached", { n: last.hosts_failed })}</span> : null}
                      </>
                    ) : (
                      <span className="z">{t("never")}</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
