// The shapes the API answers with (internal/tree, internal/server). Only what the page reads is typed; the run's
// view (RunData) is large and read in a few places, so it stays loose.

export interface Count {
  name: string;
  n: number;
}

export interface TreeNode {
  id: string;
  kind: string; // pkg, image, part, where, cve, group, host, other, section
  label: string;
  installed?: string;
  fixed?: string;
  pkgs?: string[];
  parts?: string[];
  path?: string;
  runtime?: string;
  title?: string;
  severity?: string;
  os?: string;
  exposure?: number;
  priority: string;
  due?: string;
  due_why?: string;
  hosts: number;
  groups?: Count[];
  host_list?: string[];
  cves: number;
  epss: number;
  kev?: boolean;
  rce?: boolean;
  preauth?: boolean;
  states?: Record<string, number>;
  no_fix?: Record<string, number>;
  // server rows (Servers)
  state?: string;
  problem?: string;
  problem_msg?: string;
  problem_args?: Record<string, unknown>;
  last_scan?: string;
  os_short?: string;
  fixes?: number;
  counts?: Record<string, number>;
  overdue?: boolean;
  public?: boolean;
  kids?: TreeNode[];
  more?: number;
}

export interface Tree {
  by: string;
  nodes: TreeNode[] | null;
  counts: Record<string, number>;
  fixes: number;
  no_fix: number;
  cves: number;
  hosts: number;
  hidden_backported: number;
  servers?: Record<string, number>;
  rows?: number;
}

export interface CVE {
  id: string;
  title: string;
  severity: string;
  cvss?: number;
  vector?: string;
  epss?: number;
  kev?: boolean;
  kev_due?: string;
  preauth?: boolean;
  rce?: boolean;
  published?: string;
  description?: string;
  url?: string;
  hosts: number;
}

export interface NodeDetail {
  node: TreeNode;
  why: { code: string; args?: Record<string, any> }[];
  due: { date?: string; why?: string; overdue?: number; in?: number; clock_start?: string; kev_due?: string; first_seen?: string };
  cves: CVE[];
  where: { group: string; os: string; exposure: number; hosts: string[]; states: Record<string, number> }[];
  apply?: { os: string; hosts: string[]; command: string; reboot?: boolean; unsafe?: string[] }[];
  actions: string[];
}

export interface Org {
  id: string;
  name: string;
  envs: { env: string; hosts: number; last: any; running: any }[];
}

export interface EnvData {
  hosts: { name: string; address: string; user?: string; jump?: string; group?: string; exposure?: number; public?: boolean }[];
  runs: any[];
}

export type RunData = any;
