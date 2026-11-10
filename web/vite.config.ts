import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";

const out = "../assets/web";

// gzip: the built page is minified code, not for reading: the binary embeds it compressed (index.html.gz) and
// the server unpacks it once at start.
const gzip = (): Plugin => ({
  name: "kanareika-gzip",
  apply: "build",
  closeBundle() {
    const page = `${out}/index.html`;
    writeFileSync(page + ".gz", gzipSync(readFileSync(page), { level: 9 }));
    rmSync(page);
  },
});

// The page is one file, scripts and styles inlined: the Go binary embeds it (no Node at run time), and the server
// fills in its placeholders (window.KANAREIKA).
export default defineConfig({
  plugins: [react(), viteSingleFile({ removeViteModuleLoader: true }), gzip()],
  build: {
    outDir: out,
    emptyOutDir: false, // the logos live there too
    target: "es2022",
    reportCompressedSize: false,
  },
  server: {
    proxy: { "/api": "http://127.0.0.1:8088" },
  },
});
