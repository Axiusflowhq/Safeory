import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const safeoryRoot = path.resolve(scriptDir, "..");
const provenance = JSON.parse(
  fs.readFileSync(
    path.join(safeoryRoot, "docs", "provenance", "foundation-seed.json"),
    "utf8",
  ),
);
const expectedCommit = provenance.sources?.server?.commit;
const requireRestored = process.argv.includes("--require-restored");
let failed = false;

function fail(message) {
  failed = true;
  console.error(`check-bitwarden-server-proof: ${message}`);
}

function walk(directory, predicate, output = []) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if ([".git", "bin", "node_modules"].includes(entry.name)) continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      walk(full, predicate, output);
    } else if (entry.isFile() && predicate(full)) {
      output.push(full);
    }
  }
  return output;
}

const checkoutArg = process.argv[2];
if (!checkoutArg) {
  console.error(
    "usage: node scripts/check-bitwarden-server-proof.mjs <prepared-server-checkout> [--require-restored]",
  );
  process.exit(2);
}

const checkout = path.resolve(checkoutArg);
if (
  !fs.existsSync(path.join(checkout, ".git")) ||
  !fs.existsSync(path.join(checkout, "bitwarden-server.slnx"))
) {
  fail(`not a Bitwarden server git checkout: ${checkout}`);
}

if (!expectedCommit) {
  fail("missing server commit in provenance manifest");
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

if (fs.existsSync(path.join(checkout, "bitwarden_license"))) {
  fail("restricted bitwarden_license source tree still exists");
}

const directoryBuildProps = fs.readFileSync(
  path.join(checkout, "Directory.Build.props"),
  "utf8",
);
if (
  !directoryBuildProps.includes(
    "<DefineConstants>$(DefineConstants);OSS</DefineConstants>",
  )
) {
  fail("cleaned server checkout does not force the OSS compilation constant");
}

const rustSdkCargo = fs.readFileSync(
  path.join(checkout, "util", "RustSdk", "rust", "Cargo.toml"),
  "utf8",
);
if (!/^\[workspace\]\s*$/m.test(rustSdkCargo)) {
  fail(
    "standalone util/RustSdk Cargo package is not isolated from the host repository workspace",
  );
}

const buildFiles = walk(
  checkout,
  (file) =>
    file.endsWith(".csproj") ||
    file.endsWith(".slnx") ||
    file.endsWith(".proj"),
);
for (const file of buildFiles) {
  const body = fs.readFileSync(file, "utf8");
  if (body.includes("bitwarden_license")) {
    fail(`${path.relative(checkout, file)} still references bitwarden_license`);
  }
}

const solutionBody = fs.readFileSync(
  path.join(checkout, "bitwarden-server.slnx"),
  "utf8",
);
if (solutionBody.includes("Bitwarden License")) {
  fail("solution still contains Bitwarden License project groups");
}

const billingStartup = fs.readFileSync(
  path.join(checkout, "src", "Billing", "Startup.cs"),
  "utf8",
);
if (
  billingStartup.includes("Bit.Commercial") ||
  billingStartup.includes("AddCommercialCoreServices")
) {
  fail("Billing still initializes commercial-only services");
}
if (!billingStartup.includes("services.AddOosServices();")) {
  fail("Billing does not install upstream OSS/no-op services");
}

const seederStartup = fs.readFileSync(
  path.join(checkout, "util", "SeederApi", "Startup.cs"),
  "utf8",
);
if (
  seederStartup.includes("Bit.Commercial") ||
  seederStartup.includes("AddSecretsManagerEfRepositories")
) {
  fail("SeederApi still initializes commercial-only repositories");
}
if (!seederStartup.includes("services.AddOosServices();")) {
  fail("SeederApi does not install upstream OSS/no-op services");
}

const appHostBuilder = fs.readFileSync(
  path.join(checkout, "AppHost", "BuilderExtensions.cs"),
  "utf8",
);
for (const forbiddenProject of ["Projects.Scim", "Projects.Sso"]) {
  if (appHostBuilder.includes(forbiddenProject)) {
    fail(`AppHost still includes licensed service ${forbiddenProject}`);
  }
}

if (requireRestored) {
  const assets = walk(checkout, (file) =>
    file.endsWith(path.join("obj", "project.assets.json")),
  );
  if (assets.length === 0) {
    fail(
      "--require-restored was supplied but no project.assets.json files were found",
    );
  }
  for (const file of assets) {
    const body = fs.readFileSync(file, "utf8");
    for (const forbidden of [
      "bitwarden_license",
      "Commercial.Core/",
      "Commercial.Infrastructure.EntityFramework/",
    ]) {
      if (body.includes(forbidden)) {
        fail(
          `${path.relative(checkout, file)} contains restored restricted dependency ${forbidden}`,
        );
      }
    }
  }
}

if (failed) {
  process.exit(1);
}

console.log(
  `check-bitwarden-server-proof: OK (pinned commit, OSS-only build graph${
    requireRestored ? ", and restored dependency assets" : ""
  } verified)`,
);
