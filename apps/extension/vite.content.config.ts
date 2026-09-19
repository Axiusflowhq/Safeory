import { defineConfig } from "vite";
import { fileURLToPath, URL } from "node:url";

// Content script: self-contained IIFE, no WASM (content scripts never touch
// the vault). It only talks to the background worker via chrome.runtime.
export default defineConfig({
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  build: {
    outDir: "dist",
    emptyOutDir: false,
    lib: {
      entry: fileURLToPath(new URL("./src/content.ts", import.meta.url)),
      formats: ["iife"],
      name: "SafeoryContent",
    },
    rollupOptions: {
      output: {
        entryFileNames: "content.js",
        codeSplitting: false,
      },
    },
  },
});
