import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const safeoryRoot = path.resolve(scriptDir, "..");
const seed = JSON.parse(
  fs.readFileSync(
    path.join(safeoryRoot, "docs", "provenance", "foundation-seed.json"),
    "utf8",
  ),
);

const rawArgs = process.argv.slice(2);
const sourceOnly = rawArgs.includes("--source-only");
const positional = rawArgs.filter((arg) => !arg.startsWith("--"));
if (positional.length > 1) {
  console.error(
    "usage: node scripts/check-foundation-provenance.mjs [generated-dir] [--source-only]",
  );
  process.exit(2);
}

const root = path.resolve(
  positional[0] ?? path.join(safeoryRoot, "docs", "provenance", "generated"),
);
let failed = false;

function fail(message) {
  failed = true;
  console.error(`check-foundation-provenance: ${message}`);
}

function readJson(relative) {
  const file = path.join(root, relative);
  if (!fs.existsSync(file) || fs.statSync(file).size === 0) {
    fail(`missing or empty artifact: ${relative}`);
    return null;
  }
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    fail(`invalid JSON in ${relative}: ${error.message}`);
    return null;
  }
}

for (const relative of [
  "THIRD_PARTY_NOTICES.md",
  "license-inventory.json",
  "restricted-removals.json",
  "generation-summary.json",
  "source-manifests/sdk.json",
  "source-manifests/server.json",
  "source-manifests/clients.json",
  "sbom/sdk.cdx.json",
]) {
  const file = path.join(root, relative);
  if (!fs.existsSync(file) || fs.statSync(file).size === 0) {
    fail(`missing or empty artifact: ${relative}`);
  }
}
if (!sourceOnly) {
  const serverSbom = path.join(root, "sbom", "server.cdx.json");
  if (!fs.existsSync(serverSbom) || fs.statSync(serverSbom).size === 0) {
    fail("missing or empty artifact: sbom/server.cdx.json");
  }
}

const expectedCommits = {
  sdk: seed.sources.sdk.commit,
  server: seed.sources.server.commit,
  clients: seed.sources.clients.canonical_import_commit,
};
for (const source of ["sdk", "server", "clients"]) {
  const manifest = readJson(`source-manifests/${source}.json`);
  if (!manifest) continue;
  if (manifest.commit !== expectedCommits[source]) {
    fail(`${source} source manifest commit does not match the pinned seed`);
  }
  if (!Array.isArray(manifest.files)) {
    fail(`${source} source manifest has no files array`);
    continue;
  }
  if (source === "clients" && manifest.files.length !== 0) {
    fail(
      "clients source manifest must remain empty until a reviewed non-UI import is selected",
    );
  }
  const seenPaths = new Set();
  for (const entry of manifest.files) {
    if (
      !entry?.path ||
      typeof entry.sha256 !== "string" ||
      !/^[0-9a-f]{64}$/.test(entry.sha256)
    ) {
      fail(`${source} source manifest contains a malformed file entry`);
      break;
    }
    if (seenPaths.has(entry.path)) {
      fail(`${source} source manifest contains duplicate path ${entry.path}`);
      break;
    }
    seenPaths.add(entry.path);
    if (entry.path.split("/").includes("bitwarden_license")) {
      fail(`${source} source manifest contains restricted path ${entry.path}`);
      break;
    }
  }
  if (manifest.retained_tracked_file_count !== manifest.files.length) {
    fail(`${source} retained file count does not match its manifest`);
  }
}

const forbiddenFragments = [
  "@bitwarden/commercial-sdk-internal",
  "commercial-sdk-internal",
  "bitwarden-commercial-vault",
  "Commercial.Core",
  "Commercial.Infrastructure.EntityFramework",
  "/bitwarden_license/",
  "\\bitwarden_license\\",
];

function checkSbom(relative, expectedVersion) {
  const bom = readJson(relative);
  if (!bom) return 0;
  if (
    bom.bomFormat !== "CycloneDX" ||
    bom.specVersion !== "1.6" ||
    bom.version !== 1
  ) {
    fail(`${relative} is not the expected CycloneDX 1.6 document`);
  }
  if (bom.metadata?.component?.version !== expectedVersion) {
    fail(`${relative} metadata is not bound to the pinned source commit`);
  }
  if (!Array.isArray(bom.components)) {
    fail(`${relative} has no components array`);
    return 0;
  }
  const seen = new Set();
  for (const component of bom.components) {
    const serialized = JSON.stringify(component);
    for (const fragment of forbiddenFragments) {
      if (serialized.includes(fragment)) {
        fail(`${relative} contains restricted component evidence: ${fragment}`);
        return bom.components.length;
      }
    }
    if (!component?.purl || !component?.name || !component?.version) {
      fail(`${relative} contains an incomplete component`);
      return bom.components.length;
    }
    if (seen.has(component.purl)) {
      fail(`${relative} contains duplicate purl ${component.purl}`);
      return bom.components.length;
    }
    seen.add(component.purl);
  }
  return bom.components.length;
}

const sdkComponentCount = checkSbom(
  "sbom/sdk.cdx.json",
  seed.sources.sdk.commit,
);
const serverComponentCount = sourceOnly
  ? 0
  : checkSbom("sbom/server.cdx.json", seed.sources.server.commit);

const inventory = readJson("license-inventory.json");
if (inventory) {
  if (!Array.isArray(inventory.packages)) {
    fail("license inventory has no packages array");
  } else {
    if (inventory.package_count !== inventory.packages.length) {
      fail("license inventory package_count does not match packages array");
    }
    const actualUnknown = inventory.packages.filter(
      (entry) => entry.license === "UNKNOWN",
    ).length;
    if (inventory.unknown_license_count !== actualUnknown) {
      fail("license inventory unknown_license_count is inconsistent");
    }
    for (const entry of inventory.packages) {
      const serialized = JSON.stringify(entry);
      for (const fragment of forbiddenFragments) {
        if (serialized.includes(fragment)) {
          fail(
            `license inventory contains restricted component evidence: ${fragment}`,
          );
          break;
        }
      }
    }
  }
}

const removals = readJson("restricted-removals.json");
if (removals) {
  for (const [source, commit] of Object.entries(expectedCommits)) {
    if (removals.source_commits?.[source] !== commit) {
      fail(`restricted-removals.json has the wrong ${source} commit`);
    }
  }
  for (const forbidden of seed.forbidden_foundation_paths) {
    if (!removals.forbidden_paths?.includes(forbidden)) {
      fail(`restricted-removals.json omits forbidden path ${forbidden}`);
    }
  }
  for (const forbidden of seed.forbidden_foundation_dependencies) {
    if (!removals.forbidden_dependencies?.includes(forbidden)) {
      fail(`restricted-removals.json omits forbidden dependency ${forbidden}`);
    }
  }
}

const summary = readJson("generation-summary.json");
if (summary) {
  if (summary.sdk_components !== sdkComponentCount) {
    fail("generation summary SDK component count does not match the SBOM");
  }
  if (summary.server_components !== serverComponentCount) {
    fail("generation summary server component count does not match the SBOM");
  }
  if (Boolean(summary.source_only) !== sourceOnly) {
    fail("generation summary source_only flag does not match validation mode");
  }
}

if (failed) process.exit(1);
console.log(
  `check-foundation-provenance: OK (${sdkComponentCount} SDK components, ${serverComponentCount} server components)`,
);
