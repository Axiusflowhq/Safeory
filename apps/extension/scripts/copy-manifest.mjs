// Copies static extension runtime files into dist/ after the Vite bundles.
import { copyFile, mkdir } from "node:fs/promises";
import { fileURLToPath, URL } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
await mkdir(fileURLToPath(new URL("../dist", import.meta.url)), {
  recursive: true,
});
await copyFile(
  fileURLToPath(new URL("../manifest.json", import.meta.url)),
  fileURLToPath(new URL("../dist/manifest.json", import.meta.url)),
);
await copyFile(
  fileURLToPath(
    new URL(
      "../../../crates/vault-wasm/pkg/vault_wasm_bg.wasm",
      import.meta.url,
    ),
  ),
  fileURLToPath(new URL("../dist/vault_wasm_bg.wasm", import.meta.url)),
);
console.log("manifest.json + vault_wasm_bg.wasm -> dist/");
