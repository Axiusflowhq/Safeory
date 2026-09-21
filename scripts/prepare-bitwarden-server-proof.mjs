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

function fail(message) {
  console.error(`prepare-bitwarden-server-proof: ${message}`);
  process.exit(1);
}

function readNormalized(file) {
  return fs.readFileSync(file, "utf8").replaceAll("\r\n", "\n");
}

function replaceExact(file, before, after) {
  const body = readNormalized(file);
  if (!body.includes(before)) {
    fail(
      `expected source fragment not found in ${path.relative(checkout, file)}`,
    );
  }
  fs.writeFileSync(file, body.replace(before, after));
}

function replaceOnce(file, pattern, after) {
  const body = readNormalized(file);
  const matches = body.match(pattern);
  if (!matches || matches.length !== 1) {
    fail(
      `expected exactly one cleanup match in ${path.relative(checkout, file)}`,
    );
  }
  fs.writeFileSync(file, body.replace(pattern, after));
}

const checkoutArg = process.argv[2];
if (!checkoutArg) {
  fail(
    "usage: node scripts/prepare-bitwarden-server-proof.mjs <fresh-server-checkout>",
  );
}
if (!expectedCommit) {
  fail("missing server commit in provenance manifest");
}

const checkout = path.resolve(checkoutArg);
if (
  !fs.existsSync(path.join(checkout, ".git")) ||
  !fs.existsSync(path.join(checkout, "bitwarden-server.slnx"))
) {
  fail(`not a Bitwarden server git checkout: ${checkout}`);
}

const actualCommit = execFileSync(
  "git",
  ["-C", checkout, "rev-parse", "HEAD"],
  {
    encoding: "utf8",
  },
).trim();
if (actualCommit !== expectedCommit) {
  fail(`checkout is ${actualCommit}; expected pinned commit ${expectedCommit}`);
}

const status = execFileSync("git", ["-C", checkout, "status", "--porcelain"], {
  encoding: "utf8",
}).trim();
if (status) {
  fail("checkout must be fresh and clean before preparation");
}

const licensedRoot = path.join(checkout, "bitwarden_license");
if (!fs.existsSync(licensedRoot)) {
  fail("expected restricted bitwarden_license tree is missing before cleanup");
}
fs.rmSync(licensedRoot, { recursive: true, force: false });

// Upstream builds util/RustSdk/rust as a standalone Cargo package. Because our
// disposable checkout lives under Safeory's repository, Cargo would otherwise
// walk upward and accidentally adopt Safeory's root workspace. Make that
// standalone boundary explicit without changing the package or its dependencies.
const rustSdkCargo = path.join(
  checkout,
  "util",
  "RustSdk",
  "rust",
  "Cargo.toml",
);
replaceExact(
  rustSdkCargo,
  "[profile.release]\ncodegen-units = 1\nlto = true\nopt-level = 3\n",
  "[profile.release]\ncodegen-units = 1\nlto = true\nopt-level = 3\n\n[workspace]\n",
);

const directoryBuildProps = path.join(checkout, "Directory.Build.props");
replaceExact(
  directoryBuildProps,
  "    <TargetFramework>net10.0</TargetFramework>\n",
  "    <TargetFramework>net10.0</TargetFramework>\n    <DefineConstants>$(DefineConstants);OSS</DefineConstants>\n",
);

for (const relative of ["src/Admin/Admin.csproj", "src/Api/Api.csproj"]) {
  replaceOnce(
    path.join(checkout, relative),
    /\n  <Choose>\n    <When Condition="!\$\(DefineConstants\.Contains\('OSS'\)\)">[\s\S]*?\n  <\/Choose>\n/,
    "\n",
  );
}

replaceExact(
  path.join(checkout, "src", "Billing", "Billing.csproj"),
  '    <ProjectReference Include="..\\..\\bitwarden_license\\src\\Commercial.Core\\Commercial.Core.csproj" />\n',
  "",
);
replaceExact(
  path.join(checkout, "src", "Billing", "Startup.cs"),
  "using Bit.Commercial.Core.Utilities;\n",
  "",
);
replaceExact(
  path.join(checkout, "src", "Billing", "Startup.cs"),
  "        services.AddCommercialCoreServices();\n",
  "        services.AddOosServices();\n",
);

replaceExact(
  path.join(checkout, "util", "SeederApi", "SeederApi.csproj"),
  '      <ProjectReference Include="..\\..\\bitwarden_license\\src\\Commercial.Infrastructure.EntityFramework\\Commercial.Infrastructure.EntityFramework.csproj" />\n',
  "",
);
replaceExact(
  path.join(checkout, "util", "SeederApi", "Startup.cs"),
  "using Bit.Commercial.Infrastructure.EntityFramework.SecretsManager;\n",
  "",
);
replaceExact(
  path.join(checkout, "util", "SeederApi", "Startup.cs"),
  "        services.AddSecretsManagerEfRepositories();\n",
  "        services.AddOosServices();\n",
);

const appHostProject = path.join(checkout, "AppHost", "AppHost.csproj");
replaceExact(
  appHostProject,
  '    <ProjectReference Include="..\\bitwarden_license\\src\\Scim\\Scim.csproj"/>\n',
  "",
);
replaceExact(
  appHostProject,
  '    <ProjectReference Include="..\\bitwarden_license\\src\\Sso\\Sso.csproj"/>\n',
  "",
);
const appHostBuilder = path.join(checkout, "AppHost", "BuilderExtensions.cs");
replaceExact(
  appHostBuilder,
  '            ["scim"] = builder.AddBitwardenService<Projects.Scim>(db, secretsSetup, mail, "scim"),\n',
  "",
);
replaceExact(
  appHostBuilder,
  '            ["sso"] = builder.AddBitwardenService<Projects.Sso>(db, secretsSetup, mail, "sso")\n',
  "",
);

const solution = path.join(checkout, "bitwarden-server.slnx");
replaceOnce(
  solution,
  /  <Folder Name="\/src - Bitwarden License\/">[\s\S]*?  <\/Folder>\n/,
  "",
);
replaceOnce(
  solution,
  /  <Folder Name="\/test - Bitwarden License\/">[\s\S]*?  <\/Folder>\n/,
  "",
);

console.log(`prepare-bitwarden-server-proof: prepared ${checkout}`);
console.log(`prepare-bitwarden-server-proof: pinned commit ${actualCommit}`);
