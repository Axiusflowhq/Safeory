import { existsSync, readFileSync, readdirSync } from "node:fs";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";

const workspaceRoot = fileURLToPath(new URL("../", import.meta.url));
const allowedPackages = new Set([
  "@hugeicons/core-free-icons",
  "@hugeicons/react",
  "@solar-icons/react",
]);
const iconLike =
  /(icon|lucide|phosphor|remix|fontawesome|heroicons|tabler|feather|material-icons|bootstrap-icons|mdi)/i;
const sourceExtensions = new Set([".js", ".jsx", ".ts", ".tsx"]);
const ignoredDirectories = new Set(["node_modules", "dist", "target", ".git"]);
const errors = [];

function walk(directory) {
  if (!existsSync(directory)) return [];
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    if (ignoredDirectories.has(entry.name)) return [];
    const path = join(directory, entry.name);
    return entry.isDirectory() ? walk(path) : [path];
  });
}

for (const root of [
  join(workspaceRoot, "apps"),
  join(workspaceRoot, "packages"),
]) {
  for (const file of walk(root)) {
    if (file.endsWith("package.json")) {
      const packageJson = JSON.parse(readFileSync(file, "utf8"));
      for (const groupName of [
        "dependencies",
        "devDependencies",
        "peerDependencies",
      ]) {
        for (const packageName of Object.keys(packageJson[groupName] ?? {})) {
          if (iconLike.test(packageName) && !allowedPackages.has(packageName)) {
            errors.push(
              `Disallowed icon dependency in ${file}: ${packageName}`,
            );
          }
        }
      }
      continue;
    }

    if (!sourceExtensions.has(extname(file))) continue;
    const source = readFileSync(file, "utf8");
    for (const match of source.matchAll(/from\s+["']([^"']+)["']/g)) {
      const moduleName = match[1];
      if (iconLike.test(moduleName) && !allowedPackages.has(moduleName)) {
        errors.push(`Disallowed icon import in ${file}: ${moduleName}`);
      }
    }
  }
}

const shadcnConfigPath = join(
  workspaceRoot,
  "apps",
  "web",
  "components.json",
);
const shadcnConfig = JSON.parse(readFileSync(shadcnConfigPath, "utf8"));
if (shadcnConfig.iconLibrary !== "hugeicons") {
  errors.push(
    `apps/web/components.json must keep iconLibrary as "hugeicons"; found ${JSON.stringify(shadcnConfig.iconLibrary)}`,
  );
}

if (errors.length > 0) {
  console.error(errors.join("\n"));
  process.exit(1);
}

console.log("Icon policy OK: Solar Icons and Hugeicons only.");
