import { defineConfig } from "vite";
import wasm from "vite-plugin-wasm";
import { fileURLToPath, URL } from "node:url";

// Background service worker. MV3 supports module workers (manifest
// "background.type": "module"), so we emit a single-file ES module. That keeps
// `import.meta` (used by the WASM loader) valid while inlining all chunks.
export default defineConfig({
  plugins: [wasm()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  build: {
    outDir: "dist",
    emptyOutDir: false,
    lib: {
      entry: fileURLToPath(new URL("./src/background.ts", import.meta.url)),
      formats: ["es"],
      name: "SafeoryBackground",
    },
    rollupOptions: {
      output: {
        entryFileNames: "background.js",
        codeSplitting: false,
      },
    },
  },
});
