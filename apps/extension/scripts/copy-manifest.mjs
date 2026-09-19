// Copies manifest.json into dist/ so the built extension is loadable.
import { copyFile, mkdir } from "node:fs/promises";
import { fileURLToPath, URL } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
await mkdir(fileURLToPath(new URL("../dist", import.meta.url)), { recursive: true });
await copyFile(
  fileURLToPath(new URL("../manifest.json", import.meta.url)),
  fileURLToPath(new URL("../dist/manifest.json", import.meta.url)),
);
console.log("manifest.json -> dist/");
