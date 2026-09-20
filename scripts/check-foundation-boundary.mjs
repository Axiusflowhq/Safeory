import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const manifestPath = path.join(root, "docs", "provenance", "foundation-seed.json");

function fail(message) {
  console.error("foundation-boundary: " + message);
  process.exitCode = 1;
}

const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));

if (manifest.decision !== "bitwarden-oss") {
  fail("foundation decision must be bitwarden-oss");
}

const clientSource = manifest.sources?.clients;
if (!clientSource?.repository || !clientSource?.canonical_import_commit) {
  fail("missing pinned repository/canonical_import_commit for clients");
}

for (const source of ["server", "sdk"]) {
  const entry = manifest.sources?.[source];
  if (!entry?.repository || !entry?.commit) {
    fail("missing pinned repository/commit for " + source);
  }
}

const foundationRoot = path.join(root, "foundation");
const forbiddenPaths = new Set(manifest.forbidden_foundation_paths ?? []);
const forbiddenDependencies = manifest.forbidden_foundation_dependencies ?? [];

function walk(directory) {
  if (!fs.existsSync(directory)) return;

  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.name === ".git" || entry.name === "node_modules" || entry.name === "target") {
      continue;
    }

    const full = path.join(directory, entry.name);
    if (forbiddenPaths.has(entry.name)) {
      fail("forbidden imported path: " + path.relative(root, full));
      continue;
    }

    if (entry.isDirectory()) {
      walk(full);
      continue;
    }

    if (!entry.isFile()) continue;

    if (entry.name === "package.json" || entry.name === "package-lock.json") {
      const body = fs.readFileSync(full, "utf8");
      for (const dependency of forbiddenDependencies) {
        if (body.includes(dependency)) {
          fail(
            "forbidden foundation dependency " +
              dependency +
              " in " +
              path.relative(root, full),
          );
        }
      }
    }
  }
}

walk(foundationRoot);

if (!process.exitCode) {
  console.log("foundation-boundary: OK");
}
