import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const safeoryRoot = path.resolve(scriptDir, "..");
const seedPath = path.join(
  safeoryRoot,
  "docs",
  "provenance",
  "foundation-seed.json",
);
const seed = JSON.parse(fs.readFileSync(seedPath, "utf8"));

function fail(message) {
  console.error(`generate-foundation-provenance: ${message}`);
  process.exit(1);
}

const rawArgs = process.argv.slice(2);
const sourceOnly = rawArgs.includes("--source-only");
const positional = rawArgs.filter((arg) => !arg.startsWith("--"));
if (positional.length < 2 || positional.length > 3) {
  fail(
    "usage: node scripts/generate-foundation-provenance.mjs <prepared-sdk-checkout> <prepared-server-checkout> [output-dir] [--source-only]",
  );
}

const sdkRoot = path.resolve(positional[0]);
const serverRoot = path.resolve(positional[1]);
const outputRoot = path.resolve(
  positional[2] ?? path.join(safeoryRoot, "docs", "provenance", "generated"),
);

function run(command, args, options = {}) {
  return execFileSync(command, args, {
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
    ...options,
  }).trim();
}

function runChecker(scriptName, checkout, extraArgs = []) {
  execFileSync(
    process.execPath,
    [path.join(scriptDir, scriptName), checkout, ...extraArgs],
    {
      cwd: safeoryRoot,
      stdio: "inherit",
    },
  );
}

runChecker("check-bitwarden-sdk-proof.mjs", sdkRoot);
runChecker(
  "check-bitwarden-server-proof.mjs",
  serverRoot,
  sourceOnly ? [] : ["--require-restored"],
);

fs.rmSync(outputRoot, { recursive: true, force: true });
fs.mkdirSync(outputRoot, { recursive: true });

function sha256File(file) {
  return crypto
    .createHash("sha256")
    .update(fs.readFileSync(file))
    .digest("hex");
}

function writeJson(relative, value) {
  const file = path.join(outputRoot, relative);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function trackedSourceManifest(root, source, expectedCommit) {
  const head = run("git", ["-C", root, "rev-parse", "HEAD"]);
  if (head !== expectedCommit) {
    fail(
      `${source} checkout ${head} does not match pinned commit ${expectedCommit}`,
    );
  }

  const tracked = run("git", ["-C", root, "ls-files", "-z"])
    .split("\0")
    .filter(Boolean);
  const files = [];
  for (const relative of tracked) {
    const absolute = path.join(root, relative);
    if (!fs.existsSync(absolute) || !fs.statSync(absolute).isFile()) continue;
    files.push({
      path: relative.replaceAll("\\", "/"),
      bytes: fs.statSync(absolute).size,
      sha256: sha256File(absolute),
    });
  }
  files.sort((a, b) => a.path.localeCompare(b.path));
  return {
    source,
    repository: seed.sources[source].repository,
    commit: head,
    retained_tracked_file_count: files.length,
    files,
  };
}

function gitCleanupDiff(root) {
  const body = run("git", ["-C", root, "diff", "--name-status"]);
  return body
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => {
      const [status, ...names] = line.split("\t");
      return { status, paths: names.map((name) => name.replaceAll("\\", "/")) };
    });
}

const sdkSourceManifest = trackedSourceManifest(
  sdkRoot,
  "sdk",
  seed.sources.sdk.commit,
);
const serverSourceManifest = trackedSourceManifest(
  serverRoot,
  "server",
  seed.sources.server.commit,
);
writeJson("source-manifests/sdk.json", sdkSourceManifest);
writeJson("source-manifests/server.json", serverSourceManifest);
writeJson("source-manifests/clients.json", {
  source: "clients",
  repository: seed.sources.clients.repository,
  commit: seed.sources.clients.canonical_import_commit,
  retained_tracked_file_count: 0,
  files: [],
  note: "Phase 0.1 selected no Bitwarden client/frontend source for permanent import.",
});

writeJson("restricted-removals.json", {
  schema_version: 1,
  source_commits: {
    clients: seed.sources.clients.canonical_import_commit,
    sdk: seed.sources.sdk.commit,
    server: seed.sources.server.commit,
  },
  forbidden_paths: seed.forbidden_foundation_paths,
  forbidden_dependencies: seed.forbidden_foundation_dependencies,
  clients: {
    selected_for_import: [],
    removed_or_rejected: [
      "bitwarden_license/**",
      "@bitwarden/commercial-sdk-internal",
      "Bitwarden web/browser frontend applications, route trees, product shell, branding, and design system",
    ],
  },
  sdk_cleanup_diff: gitCleanupDiff(sdkRoot),
  server_cleanup_diff: gitCleanupDiff(serverRoot),
});

function cargoComponents() {
  const metadata = JSON.parse(
    run("cargo", ["metadata", "--locked", "--format-version", "1"], {
      cwd: sdkRoot,
    }),
  );
  return metadata.packages.map((pkg) => ({
    ecosystem: "cargo",
    name: pkg.name,
    version: pkg.version,
    purl: `pkg:cargo/${encodeURIComponent(pkg.name)}@${encodeURIComponent(pkg.version)}`,
    license:
      pkg.license ??
      (pkg.license_file ? `SEE-FILE:${pkg.license_file}` : "UNKNOWN"),
    evidence: pkg.source ?? pkg.manifest_path,
  }));
}

function inferNpmName(lockKey, info) {
  if (info.name) return info.name;
  const normalized = lockKey.replaceAll("\\", "/");
  const marker = normalized.lastIndexOf("node_modules/");
  if (marker === -1) return null;
  const tail = normalized.slice(marker + "node_modules/".length);
  const parts = tail.split("/");
  return tail.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
}

function npmPurl(name, version) {
  const encodedName = name.startsWith("@")
    ? `%40${name.slice(1).split("/").map(encodeURIComponent).join("/")}`
    : encodeURIComponent(name);
  return `pkg:npm/${encodedName}@${encodeURIComponent(version)}`;
}

function npmComponentsFromLock(lockFile, label) {
  if (!fs.existsSync(lockFile)) return [];
  const lock = JSON.parse(fs.readFileSync(lockFile, "utf8"));
  const components = [];
  for (const [lockKey, info] of Object.entries(lock.packages ?? {})) {
    if (!lockKey || !info?.version || info.link) continue;
    const name = inferNpmName(lockKey, info);
    if (!name) continue;
    components.push({
      ecosystem: "npm",
      name,
      version: info.version,
      purl: npmPurl(name, info.version),
      license: info.license ?? "UNKNOWN",
      evidence: `${label}:${lockKey.replaceAll("\\", "/")}`,
    });
  }
  return components;
}

function walk(directory, predicate, output = []) {
  if (!fs.existsSync(directory)) return output;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if ([".git", "bin", "node_modules", "target"].includes(entry.name))
      continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      walk(full, predicate, output);
    } else if (entry.isFile() && predicate(full)) {
      output.push(full);
    }
  }
  return output;
}

function decodeXml(value) {
  return value
    .replaceAll("&amp;", "&")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&quot;", '"')
    .replaceAll("&apos;", "'");
}

const nugetPackagesRoot =
  process.env.NUGET_PACKAGES ?? path.join(os.homedir(), ".nuget", "packages");

function nugetLicense(name, version) {
  const packageDir = path.join(
    nugetPackagesRoot,
    name.toLowerCase(),
    version.toLowerCase(),
  );
  if (!fs.existsSync(packageDir))
    return { value: "UNKNOWN", evidence: "package-cache-missing" };
  const nuspec = fs
    .readdirSync(packageDir)
    .find((entry) => entry.toLowerCase().endsWith(".nuspec"));
  if (!nuspec) return { value: "UNKNOWN", evidence: "nuspec-missing" };
  const file = path.join(packageDir, nuspec);
  const body = fs.readFileSync(file, "utf8");
  const expression = body.match(
    /<license\s+type=["']expression["'][^>]*>([^<]+)<\/license>/i,
  )?.[1];
  if (expression)
    return { value: decodeXml(expression.trim()), evidence: file };
  const licenseFile = body.match(
    /<license\s+type=["']file["'][^>]*>([^<]+)<\/license>/i,
  )?.[1];
  if (licenseFile)
    return {
      value: `SEE-FILE:${decodeXml(licenseFile.trim())}`,
      evidence: file,
    };
  const licenseUrl = body.match(/<licenseUrl>([^<]+)<\/licenseUrl>/i)?.[1];
  if (licenseUrl)
    return { value: decodeXml(licenseUrl.trim()), evidence: file };
  return { value: "UNKNOWN", evidence: file };
}

function nugetComponents() {
  const assetFiles = walk(serverRoot, (file) =>
    file.replaceAll("\\", "/").endsWith("/obj/project.assets.json"),
  );
  if (!sourceOnly && assetFiles.length === 0) {
    fail(
      "no restored server project.assets.json files found; restore the retained server composition first",
    );
  }
  const components = [];
  for (const assetFile of assetFiles) {
    const assets = JSON.parse(fs.readFileSync(assetFile, "utf8"));
    for (const [key, info] of Object.entries(assets.libraries ?? {})) {
      if (info?.type !== "package") continue;
      const split = key.lastIndexOf("/");
      if (split <= 0) continue;
      const name = key.slice(0, split);
      const version = key.slice(split + 1);
      const license = nugetLicense(name, version);
      components.push({
        ecosystem: "nuget",
        name,
        version,
        purl: `pkg:nuget/${encodeURIComponent(name)}@${encodeURIComponent(version)}`,
        license: license.value,
        evidence: license.evidence,
      });
    }
  }
  return components;
}

function dedupeComponents(components) {
  const byPurl = new Map();
  for (const component of components) {
    const existing = byPurl.get(component.purl);
    if (!existing || existing.license === "UNKNOWN")
      byPurl.set(component.purl, component);
  }
  return [...byPurl.values()].sort((a, b) => a.purl.localeCompare(b.purl));
}

const sdkComponents = dedupeComponents([
  ...cargoComponents(),
  ...npmComponentsFromLock(path.join(sdkRoot, "package-lock.json"), "sdk-root"),
  ...npmComponentsFromLock(
    path.join(
      sdkRoot,
      "crates",
      "bitwarden-wasm-internal",
      "npm",
      "package-lock.json",
    ),
    "sdk-wasm-npm",
  ),
]);
const serverComponents = sourceOnly ? [] : dedupeComponents(nugetComponents());

function cyclonedxComponent(component) {
  const result = {
    type: "library",
    "bom-ref": component.purl,
    name: component.name,
    version: component.version,
    purl: component.purl,
    properties: [
      { name: "safeory:ecosystem", value: component.ecosystem },
      { name: "safeory:license-evidence", value: component.evidence },
    ],
  };
  if (component.license !== "UNKNOWN") {
    result.licenses = [{ license: { name: component.license } }];
  }
  return result;
}

function makeBom(name, version, components) {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    metadata: {
      component: {
        type: "application",
        name,
        version,
      },
      properties: [
        {
          name: "safeory:generated-from",
          value: "pinned cleaned proof checkout",
        },
      ],
    },
    components: components.map(cyclonedxComponent),
  };
}

writeJson(
  "sbom/sdk.cdx.json",
  makeBom("safeory-foundation-sdk", seed.sources.sdk.commit, sdkComponents),
);
if (!sourceOnly) {
  writeJson(
    "sbom/server.cdx.json",
    makeBom(
      "safeory-foundation-server",
      seed.sources.server.commit,
      serverComponents,
    ),
  );
}

const licenseRows = [...sdkComponents, ...serverComponents].map(
  (component) => ({
    ecosystem: component.ecosystem,
    package: component.name,
    version: component.version,
    license: component.license,
    evidence: component.evidence,
  }),
);
const unknownLicenseCount = licenseRows.filter(
  (row) => row.license === "UNKNOWN",
).length;
writeJson("license-inventory.json", {
  schema_version: 1,
  source_only: sourceOnly,
  package_count: licenseRows.length,
  unknown_license_count: unknownLicenseCount,
  packages: licenseRows,
});

const sourceLicenseFiles = {
  sdk: ["LICENSE", "LICENSE_GPL.txt", "LICENSE_SDK.txt", "DISCLAIMER.md"],
  server: [
    "LICENSE.txt",
    "LICENSE_AGPL.txt",
    "LICENSE_BITWARDEN.txt",
    "LICENSE_FAQ.md",
    "TRADEMARK_GUIDELINES.md",
  ],
};
for (const [source, files] of Object.entries(sourceLicenseFiles)) {
  const root = source === "sdk" ? sdkRoot : serverRoot;
  for (const relative of files) {
    const from = path.join(root, relative);
    if (!fs.existsSync(from))
      fail(`${source} notice file is missing: ${relative}`);
    const to = path.join(outputRoot, "licenses", source, relative);
    fs.mkdirSync(path.dirname(to), { recursive: true });
    fs.copyFileSync(from, to);
  }
}

const notices = `# Safeory foundation third-party notices

This bundle is generated from the pinned, cleaned foundation proof checkouts. It
is an automated provenance artifact and is not a substitute for qualified legal
review.

## Upstream sources

- Bitwarden SDK: ${seed.sources.sdk.repository} at \`${seed.sources.sdk.commit}\`.
- Bitwarden server: ${seed.sources.server.repository} at \`${seed.sources.server.commit}\`.
- Bitwarden clients reference: ${seed.sources.clients.repository} at
  \`${seed.sources.clients.canonical_import_commit}\`; Phase 0.1 selected **no
  client/frontend source for permanent import**.

## Restricted-source cleanup

- \`bitwarden_license/**\` is physically absent from the prepared SDK/server
  proof checkouts.
- \`@bitwarden/commercial-sdk-internal\` is not part of the selected foundation.
- Exact cleanup diffs are recorded in \`restricted-removals.json\`.
- Exact retained tracked source files and SHA-256 hashes are recorded under
  \`source-manifests/\`.

## License evidence

- SDK repository license/notices are copied under \`licenses/sdk/\`.
- Server repository license/notices are copied under \`licenses/server/\`.
- Dependency license evidence is recorded in \`license-inventory.json\`.
- SDK dependency SBOM: \`sbom/sdk.cdx.json\`.
${sourceOnly ? "- Server dependency SBOM was intentionally omitted by source-only generation.\n" : "- Server dependency SBOM: `sbom/server.cdx.json`.\n"}

Automated inventory contains ${unknownLicenseCount} package entr${unknownLicenseCount === 1 ? "y" : "ies"} with unknown license metadata. Any unknown or non-standard license evidence must be resolved or explicitly reviewed before the public-distribution gate is closed.
`;
fs.writeFileSync(path.join(outputRoot, "THIRD_PARTY_NOTICES.md"), notices);

writeJson("generation-summary.json", {
  schema_version: 1,
  source_only: sourceOnly,
  sdk_commit: seed.sources.sdk.commit,
  server_commit: seed.sources.server.commit,
  clients_reference_commit: seed.sources.clients.canonical_import_commit,
  sdk_retained_files: sdkSourceManifest.retained_tracked_file_count,
  server_retained_files: serverSourceManifest.retained_tracked_file_count,
  sdk_components: sdkComponents.length,
  server_components: serverComponents.length,
  unknown_license_count: unknownLicenseCount,
});

console.log(
  `generate-foundation-provenance: OK (${sdkComponents.length} SDK components, ${serverComponents.length} server components, ${unknownLicenseCount} unknown licenses)`,
);
