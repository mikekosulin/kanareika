// What the page reads from the server, as cached queries: one request per question however many components ask,
// the previous answer kept on screen while the next one loads, and an answer no one waits for any more cancelled.
import { keepPreviousData, useQuery, useQueries, QueryClient } from "@tanstack/react-query";
import { api, qs } from "./lib/api";
import { LANG } from "./lib/i18n";
import { useShallow } from "zustand/react/shallow";
import { get, grouping, useApp, type State } from "./state";
import type { Tree, TreeNode, NodeDetail, RunData, EnvData, Org } from "./types";

export const client = new QueryClient({
  defaultOptions: { queries: { staleTime: 5_000, retry: false, refetchOnWindowFocus: false } },
});

export const useSession = () =>
  useQuery({ queryKey: ["session"], queryFn: () => api<{ scans: boolean }>("/api/session").catch(() => ({ scans: false })), staleTime: Infinity });

export const useOrgs = () =>
  useQuery({ queryKey: ["orgs"], queryFn: () => api<{ orgs: Org[]; errors?: string[] }>("/api/orgs"), staleTime: 10_000 });

export function useEnv() {
  const { org, env } = useApp(useShallow((s) => ({ org: s.org, env: s.env })));
  return useQuery({
    queryKey: ["env", org, env],
    queryFn: ({ signal }) => api<EnvData>("/api/env?" + qs({ org, env }), signal),
    enabled: !!org && !!env,
  });
}

const scope = (s: State) => ({ org: s.org, env: s.env, run: s.run });

/** treeParams: the question a tree view asks (/api/tree, /api/node). */
export const treeParams = (s: State) => ({
  ...scope(s),
  by: grouping(s),
  f: [...s.flt].sort().join(","),
  q: s.q.trim(),
  backported: s.backport ? 1 : "",
});
export type TreeParams = ReturnType<typeof treeParams>;

/** useTree: the top rows (levels=0) of a grouping; all=1 for the server list. */
export function useTree(p: TreeParams, all = false) {
  return useQuery({
    queryKey: ["tree", p, all],
    queryFn: ({ signal }) => api<Tree>("/api/tree?" + qs({ ...p, all: all ? 1 : "", levels: 0 }), signal),
    enabled: !!p.org && !!p.env,
    placeholderData: keepPreviousData,
  });
}

/** useKids: the kids of the open rows that came without them, each asked for once. */
export function useKids(p: TreeParams, ids: string[]) {
  const rs = useQueries({
    queries: ids.map((id) => ({
      queryKey: ["kids", p, id],
      queryFn: ({ signal }: { signal: AbortSignal }) =>
        api<Tree>("/api/tree?" + qs({ ...p, under: id, levels: 0 }), signal).then((r) => r.nodes || []),
      staleTime: 60_000,
    })),
  });
  const out = new Map<string, TreeNode[]>();
  ids.forEach((id, i) => {
    const d = rs[i].data;
    if (d) out.set(id, d);
  });
  return out;
}

export async function fullTree(p: TreeParams) {
  return api<Tree>("/api/tree?" + qs(p));
}

export function useNode(p: TreeParams, id: string | null) {
  return useQuery({
    queryKey: ["node", p, id],
    queryFn: async ({ signal }) => {
      try {
        return await api<NodeDetail>("/api/node?" + qs({ ...p, id }), signal);
      } catch (e) {
        // a CVE from a fix's details: look it up in the CVE grouping
        if (!id!.startsWith("cve:")) throw e;
        return api<NodeDetail>("/api/node?" + qs({ org: p.org, env: p.env, run: p.run, by: "cve", id }), signal);
      }
    },
    enabled: !!id && !!p.org && !!p.env,
    placeholderData: keepPreviousData,
  });
}

// the message catalog: finding and action texts in the page's language
export const useCatalog = () =>
  useQuery({
    queryKey: ["i18n"],
    queryFn: () => api<{ messages: Record<string, Record<string, string>> }>("/api/i18n").then((r) => r.messages || {}).catch(() => ({})),
    enabled: LANG !== "en",
    staleTime: Infinity,
  });

/** useRunData: the run shown (Data in the sidebar), its full view. */
export function useRunData(enabled = true) {
  const { org, env, run } = useApp(useShallow(scope));
  useCatalog();
  return useQuery({
    queryKey: ["run", org, env, run],
    queryFn: ({ signal }) => api<RunData>("/api/run?" + qs({ org, env, run }), signal),
    enabled: enabled && !!org && !!env,
    staleTime: 30_000,
  });
}

export function useLens(id: string) {
  const { org, env, run } = useApp(useShallow(scope));
  return useQuery({
    queryKey: ["lens", org, env, run, id],
    queryFn: ({ signal }) => api<any>("/api/lens?" + qs({ org, env, run, id }), signal),
    enabled: !!org && !!env && id !== "priorities",
    placeholderData: keepPreviousData,
  });
}

export function useJobs() {
  return useQuery({
    queryKey: ["jobs"],
    queryFn: () => api<{ jobs: any[] }>("/api/jobs").then((r) => r.jobs || []),
    refetchInterval: (q) => ((q.state.data || []).some((j: any) => j.state === "running") ? 1500 : 15_000),
  });
}

export function useDB() {
  return useQuery({
    queryKey: ["db"],
    queryFn: () => api<any>("/api/db"),
    refetchInterval: (q) => (q.state.data?.updating ? 1000 : false),
  });
}

/** refresh: everything about the environment's data asked again (a scan finished). */
export function refresh() {
  for (const k of ["orgs", "env", "tree", "kids", "node", "run", "lens"]) client.invalidateQueries({ queryKey: [k] });
}
export const scopeKey = () => {
  const s = get();
  return [s.org, s.env, s.run].join("|");
};
