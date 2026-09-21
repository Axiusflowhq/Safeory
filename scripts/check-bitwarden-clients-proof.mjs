import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const forbiddenDependency = "@bitwarden/commercial-sdk-internal";
const forbiddenPath = "bitwarden_license";
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const safeoryRoot = path.resolve(scriptDir, "..");
const provenance = readJson(
  path.join(safeoryRoot, "docs", "provenance", "foundation-seed.json"),
);
const expectedCommit = provenance.sources?.clients?.canonical_import_commit;
let failed = false;

function fail(message) {
  failed = true;
  console.error(`check-bitwarden-clients-proof: ${message}`);
}

function read(file) {
  return fs.readFileSync(file, "utf8");
}

function readJson(file) {
  return JSON.parse(read(file));
}

const checkoutArg = process.argv[2];
const requireInstalled = process.argv.includes("--require-installed");
if (!checkoutArg) {
  console.error(
    "usage: node scripts/check-bitwarden-clients-proof.mjs <prepared-clients-checkout> [--require-installed]",
  );
  process.exit(2);
}

const checkout = path.resolve(checkoutArg);
if (
  !fs.existsSync(path.join(checkout, ".git")) ||
  !fs.existsSync(path.join(checkout, "package.json"))
) {
  fail(`not a Bitwarden clients git checkout: ${checkout}`);
}

if (!expectedCommit) {
  fail("missing clients canonical_import_commit in provenance manifest");
} else {
  try {
    const actualCommit = execFileSync(
      "git",
      ["-C", checkout, "rev-parse", "HEAD"],
      {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      },
    ).trim();
    if (actualCommit !== expectedCommit) {
      fail(
        `checkout is ${actualCommit}; expected pinned commit ${expectedCommit}`,
      );
    }
  } catch (error) {
    fail(`could not resolve checkout commit: ${error.message}`);
  }
}

if (fs.existsSync(path.join(checkout, forbiddenPath))) {
  fail("restricted bitwarden_license source tree still exists");
}

const packageFiles = [];
function collectPackageFiles(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if ([".git", "node_modules", "dist", "build"].includes(entry.name))
      continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      collectPackageFiles(full);
    } else if (entry.isFile() && entry.name === "package.json") {
      packageFiles.push(full);
    }
  }
}
collectPackageFiles(checkout);

for (const packageFile of packageFiles) {
  const packageJson = readJson(packageFile);
  for (const section of [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
  ]) {
    if (packageJson[section]?.[forbiddenDependency]) {
      fail(
        `${path.relative(checkout, packageFile)} still depends on ${forbiddenDependency}`,
      );
    }
  }
}

const lockBody = read(path.join(checkout, "package-lock.json"));
if (lockBody.includes(forbiddenDependency)) {
  fail(`package-lock.json still contains ${forbiddenDependency}`);
}

const nodeModulesRoot = path.join(checkout, "node_modules");
if (requireInstalled && !fs.existsSync(nodeModulesRoot)) {
  fail("--require-installed was supplied but node_modules is missing");
}
if (
  fs.existsSync(
    path.join(nodeModulesRoot, "@bitwarden", "commercial-sdk-internal"),
  )
) {
  fail(`installed dependencies still contain ${forbiddenDependency}`);
}

const configFiles = [
  "angular.json",
  "jest.config.js",
  "tsconfig.json",
  "tsconfig.base.json",
  "tsconfig.eslint.json",
  "clients.code-workspace",
  ".storybook/main.ts",
  "apps/web/package.json",
  "apps/web/project.json",
  "apps/web/tailwind.config.js",
  "apps/web/Dockerfile",
  "apps/browser/package.json",
  "apps/browser/project.json",
  "apps/browser/tailwind.config.js",
  "apps/cli/package.json",
  "apps/cli/project.json",
];

for (const relative of configFiles) {
  const file = path.join(checkout, relative);
  const body = read(file);
  if (
    body.includes(`${forbiddenPath}/`) ||
    body.includes(forbiddenDependency)
  ) {
    fail(`${relative} still references restricted source or dependency`);
  }
}

for (const app of ["web", "browser", "cli"]) {
  const relative = path.join("apps", app, "project.json");
  const project = readJson(path.join(checkout, relative));
  for (const [targetName, target] of Object.entries(project.targets ?? {})) {
    for (const configurationName of Object.keys(target?.configurations ?? {})) {
      if (configurationName.startsWith("commercial")) {
        fail(
          `${relative} target ${targetName} still has commercial configuration ${configurationName}`,
        );
      }
    }
  }
}

const browserEnvironment = read(
  path.join(
    checkout,
    "apps",
    "browser",
    "src",
    "platform",
    "services",
    "browser-environment.service.ts",
  ),
);
if (
  !browserEnvironment.includes(
    "class BrowserSelfHostedEnvironment extends SelfHostedEnvironment",
  )
) {
  fail("browser environment is not self-hosted-first");
}
if (!browserEnvironment.includes("return this.selfHostedRegions;")) {
  fail("browser still exposes upstream hosted regions by default");
}

const browserBackground = read(
  path.join(
    checkout,
    "apps",
    "browser",
    "src",
    "background",
    "main.background.ts",
  ),
);
for (const constructor of [
  "new PhishingDataService(",
  "new PhishingDetectionService(",
]) {
  if (browserBackground.includes(constructor)) {
    fail(`browser still initializes hosted remote service: ${constructor}`);
  }
}

for (const manifest of ["manifest.json", "manifest.v3.json"]) {
  const manifestBody = read(
    path.join(checkout, "apps", "browser", "src", manifest),
  );
  if (manifestBody.includes('"update_url"')) {
    fail(`${manifest} still declares an upstream update channel`);
  }
}

const angularConfig = readJson(path.join(checkout, "angular.json"));
if (angularConfig.cli?.analytics !== false) {
  fail("Angular analytics must remain disabled in the cleaned proof");
}
if (angularConfig.projects?.["bit-web"]) {
  fail("angular.json still contains the licensed bit-web project");
}

if (failed) {
  process.exit(1);
}

console.log(
  `check-bitwarden-clients-proof: OK (${packageFiles.length} package manifests scanned, pinned commit verified${
    fs.existsSync(nodeModulesRoot)
      ? ", installed dependency boundary verified"
      : ""
  })`,
);
