// local: the browser's own settings (theme, language, last org and environment, groupings); private windows and
// blocked storage just forget them.
export const local = {
  get(k: string, d: string): string {
    try {
      return localStorage.getItem("kanareika." + k) ?? d;
    } catch {
      return d;
    }
  },
  set(k: string, v: string) {
    try {
      localStorage.setItem("kanareika." + k, v);
    } catch {
      /* not kept */
    }
  },
};
