import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import wasm from "vite-plugin-wasm";
import { fileURLToPath, URL } from "node:url";

// Popup build: a normal ES-module HTML page (WASM allowed via the
// 'wasm-unsafe-eval' CSP in manifest.json). The background service worker and
// content script are built separately (vite.background.config.ts and
// vite.content.config.ts) as self-contained IIFE bundles, since MV3 workers
// and content scripts cannot import extension chunks at runtime.
export default defineConfig({
  plugins: [react(), tailwindcss(), wasm()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    rollupOptions: {
      input: fileURLToPath(new URL("./popup.html", import.meta.url)),
      output: {
        entryFileNames: "popup.js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },
});
