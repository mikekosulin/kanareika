import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";

// The page is one file, assets/web/index.html, scripts and styles inlined: the Go binary embeds it as before
// (no Node at run time), and the server fills in its placeholders (window.KANAREIKA).
export default defineConfig({
  plugins: [react(), viteSingleFile({ removeViteModuleLoader: true })],
  build: {
    outDir: "../assets/web",
    emptyOutDir: false, // the logos live there too
    target: "es2022",
    reportCompressedSize: false,
  },
  server: {
    proxy: { "/api": "http://127.0.0.1:8088" },
  },
});
