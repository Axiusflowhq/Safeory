import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const safeoryRoot = path.resolve(scriptDir, "..");
const provenancePath = path.join(safeoryRoot, "docs", "provenance", "foundation-seed.json");
const provenance = JSON.parse(fs.readFileSync(provenancePath, "utf8"));
const expectedCommit = provenance.sources?.clients?.canonical_import_commit;

function fail(message) {
  console.error(`prepare-bitwarden-clients-proof: ${message}`);
  process.exit(1);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function removeBitScripts(packagePath) {
  const packageJson = readJson(packagePath);
  if (!packageJson.scripts) return;

  for (const name of Object.keys(packageJson.scripts)) {
    if (name.split(":").includes("bit")) {
      delete packageJson.scripts[name];
    }
  }

  writeJson(packagePath, packageJson);
}

function removeCommercialConfigurations(projectPath) {
  const project = readJson(projectPath);
  for (const target of Object.values(project.targets ?? {})) {
    if (!target?.configurations) continue;
    for (const name of Object.keys(target.configurations)) {
      if (name.startsWith("commercial")) {
        delete target.configurations[name];
      }
    }
  }
  writeJson(projectPath, project);
}

function removeMatchingLines(file, matcher) {
  const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
  const filtered = lines.filter((line) => !matcher(line));
  fs.writeFileSync(file, `${filtered.join("\n").replace(/\n+$/, "")}\n`);
}

function replaceExact(file, before, after) {
  const body = fs.readFileSync(file, "utf8");
  if (!body.includes(before)) {
    fail(`expected source fragment not found in ${path.relative(checkout, file)}`);
  }
  fs.writeFileSync(file, body.replace(before, after));
}

const checkoutArg = process.argv[2];
const licensedTreeAlreadyRemoved = process.argv.includes("--licensed-tree-removed");
if (!checkoutArg) {
  fail("usage: node scripts/prepare-bitwarden-clients-proof.mjs <fresh-clients-checkout>");
}

if (!expectedCommit) {
  fail("missing clients canonical_import_commit in provenance manifest");
}

const checkout = path.resolve(checkoutArg);
const checkoutPackage = path.join(checkout, "package.json");
const licensedRoot = path.join(checkout, "bitwarden_license");

if (!fs.existsSync(path.join(checkout, ".git")) || !fs.existsSync(checkoutPackage)) {
  fail(`not a Bitwarden clients git checkout: ${checkout}`);
}

const actualCommit = execFileSync("git", ["-C", checkout, "rev-parse", "HEAD"], {
  encoding: "utf8",
}).trim();
if (actualCommit !== expectedCommit) {
  fail(`checkout is ${actualCommit}; expected pinned commit ${expectedCommit}`);
}

const status = execFileSync("git", ["-C", checkout, "status", "--porcelain"], {
  encoding: "utf8",
}).trimEnd();
if (!licensedTreeAlreadyRemoved && status) {
  fail("checkout must be fresh and clean before preparation");
}

if (licensedTreeAlreadyRemoved) {
  if (fs.existsSync(licensedRoot)) {
    fail("--licensed-tree-removed was supplied but bitwarden_license still exists");
  }
  const unexpectedChanges = status
    .split(/\r?\n/)
    .filter(Boolean)
    .filter((line) => !line.slice(3).replaceAll("\\", "/").startsWith("bitwarden_license/"));
  if (unexpectedChanges.length > 0) {
    fail(`checkout has changes outside the removed licensed tree: ${unexpectedChanges[0]}`);
  }
} else {
  if (!fs.existsSync(licensedRoot) || path.basename(licensedRoot) !== "bitwarden_license") {
    fail("expected bitwarden_license tree is missing before cleanup");
  }
  fs.rmSync(licensedRoot, { recursive: true, force: false });
}

const rootPackage = readJson(checkoutPackage);
delete rootPackage.dependencies?.["@bitwarden/commercial-sdk-internal"];
delete rootPackage.scripts?.["lint:sdk-internal-versions"];
writeJson(checkoutPackage, rootPackage);

const lockPath = path.join(checkout, "package-lock.json");
const lock = readJson(lockPath);
delete lock.packages?.[""]?.dependencies?.["@bitwarden/commercial-sdk-internal"];
for (const key of Object.keys(lock.packages ?? {})) {
  if (key === "node_modules/@bitwarden/commercial-sdk-internal" ||
      key.startsWith("node_modules/@bitwarden/commercial-sdk-internal/")) {
    delete lock.packages[key];
  }
}
writeJson(lockPath, lock);

for (const app of ["web", "browser", "cli"]) {
  removeBitScripts(path.join(checkout, "apps", app, "package.json"));
  removeCommercialConfigurations(path.join(checkout, "apps", app, "project.json"));
}

const angularPath = path.join(checkout, "angular.json");
const angular = readJson(angularPath);
delete angular.projects?.["bit-web"];
writeJson(angularPath, angular);

const tsconfigPath = path.join(checkout, "tsconfig.json");
const tsconfig = readJson(tsconfigPath);
tsconfig.include = (tsconfig.include ?? []).filter((entry) => !entry.startsWith("bitwarden_license/"));
writeJson(tsconfigPath, tsconfig);

const tsconfigBasePath = path.join(checkout, "tsconfig.base.json");
const tsconfigBase = readJson(tsconfigBasePath);
delete tsconfigBase.compilerOptions?.paths?.["@bitwarden/bit-common/*"];
writeJson(tsconfigBasePath, tsconfigBase);

const tsconfigEslintPath = path.join(checkout, "tsconfig.eslint.json");
const tsconfigEslint = readJson(tsconfigEslintPath);
tsconfigEslint.include = (tsconfigEslint.include ?? []).filter(
  (entry) => !entry.includes("bitwarden_license"),
);
writeJson(tsconfigEslintPath, tsconfigEslint);

removeMatchingLines(path.join(checkout, "jest.config.js"), (line) =>
  line.includes("<rootDir>/bitwarden_license/"),
);
removeMatchingLines(path.join(checkout, ".storybook", "main.ts"), (line) =>
  line.includes("../bitwarden_license/"),
);
removeMatchingLines(path.join(checkout, "apps", "web", "tailwind.config.js"), (line) =>
  line.includes("../../bitwarden_license/"),
);
removeMatchingLines(path.join(checkout, "apps", "browser", "tailwind.config.js"), (line) =>
  line.includes("../../bitwarden_license/"),
);
removeMatchingLines(path.join(checkout, "apps", "web", "Dockerfile"), (line) =>
  line.includes("@bitwarden/commercial-sdk-internal"),
);

const workspacePath = path.join(checkout, "clients.code-workspace");
const workspaceLines = fs.readFileSync(workspacePath, "utf8").split(/\r?\n/);
const cleanedWorkspaceLines = [];
for (let index = 0; index < workspaceLines.length; index += 1) {
  if (workspaceLines[index].trim() === "{") {
    const block = [];
    let cursor = index;
    for (; cursor < workspaceLines.length; cursor += 1) {
      block.push(workspaceLines[cursor]);
      if (workspaceLines[cursor].trim() === "},") break;
    }
    if (block.some((line) => line.includes('"path": "bitwarden_license/'))) {
      index = cursor;
      continue;
    }
  }
  if (workspaceLines[index].includes('"web vault (bit)"')) continue;
  cleanedWorkspaceLines.push(workspaceLines[index]);
}
fs.writeFileSync(
  workspacePath,
  `${cleanedWorkspaceLines.join("\n").replace(/\n+$/, "")}\n`,
);

for (const script of [
  path.join(checkout, "scripts", "material-icons", "migrate-icon-names.ts"),
  path.join(checkout, "scripts", "material-icons", "reverse-migrate-icon-names.ts"),
]) {
  let body = fs.readFileSync(script, "utf8");
  body = body.replace(
    'const SEARCH_PATHS = ["apps/", "libs/", "bitwarden_license/"];',
    'const SEARCH_PATHS = ["apps/", "libs/"];',
  );
  fs.writeFileSync(script, body);
}

const sdkVersionScript = path.join(checkout, "scripts", "sdk-internal-versions.ts");
if (fs.existsSync(sdkVersionScript)) {
  fs.rmSync(sdkVersionScript);
}

// The upstream OSS browser still defaults to Bitwarden-hosted cloud regions.
// Keep the proof self-hosted-first: custom/managed URLs remain supported, while
// an unconfigured browser has no hosted service fallback.
const browserEnvironmentPath = path.join(
  checkout,
  "apps",
  "browser",
  "src",
  "platform",
  "services",
  "browser-environment.service.ts",
);
replaceExact(
  browserEnvironmentPath,
  'import { firstValueFrom } from "rxjs";',
  'import { firstValueFrom, map } from "rxjs";',
);
replaceExact(
  browserEnvironmentPath,
  'import { Region, RegionConfig } from "@bitwarden/common/platform/abstractions/environment.service";',
  `import {
  Region,
  RegionConfig,
  Urls,
} from "@bitwarden/common/platform/abstractions/environment.service";`,
);
replaceExact(
  browserEnvironmentPath,
  'import { DefaultEnvironmentService } from "@bitwarden/common/platform/services/default-environment.service";',
  `import {
  DefaultEnvironmentService,
  SelfHostedEnvironment,
} from "@bitwarden/common/platform/services/default-environment.service";`,
);
replaceExact(
  browserEnvironmentPath,
  "export class BrowserEnvironmentService extends DefaultEnvironmentService {\n",
  "export class BrowserEnvironmentService extends DefaultEnvironmentService {\n  private readonly selfHostedRegions: RegionConfig[];\n\n",
);
replaceExact(
  browserEnvironmentPath,
  "    super(stateProvider, accountService, additionalRegionConfigs);\n  }\n\n  async hasManagedEnvironment()",
  `    super(stateProvider, accountService, additionalRegionConfigs);
    this.selfHostedRegions = additionalRegionConfigs;
    this.cloudWebVaultUrl$ = this.environment$.pipe(map((environment) => environment.getWebVaultUrl()));
  }

  override availableRegions(): RegionConfig[] {
    return this.selfHostedRegions;
  }

  protected override buildEnvironment(_region: Region, urls: Urls) {
    return new BrowserSelfHostedEnvironment(urls ?? {});
  }

  async hasManagedEnvironment()`,
);
replaceExact(
  browserEnvironmentPath,
  "\n}\n",
  `
}

class BrowserSelfHostedEnvironment extends SelfHostedEnvironment {
  override getWebVaultUrl() {
    return this.urls.webVault ?? this.urls.base ?? "";
  }

  override getApiUrl() {
    return this.urls.api ?? (this.urls.base ? \`${"${this.urls.base}"}/api\` : "");
  }

  override getIdentityUrl() {
    return this.urls.identity ?? (this.urls.base ? \`${"${this.urls.base}"}/identity\` : "");
  }

  override getIconsUrl() {
    return this.urls.icons ?? (this.urls.base ? \`${"${this.urls.base}"}/icons\` : "");
  }

  override getNotificationsUrl() {
    return this.urls.notifications ?? (this.urls.base ? \`${"${this.urls.base}"}/notifications\` : "");
  }

  override getEventsUrl() {
    return this.urls.events ?? (this.urls.base ? \`${"${this.urls.base}"}/events\` : "");
  }

  override getScimUrl() {
    return this.urls.scim ?? (this.getWebVaultUrl() ? \`${"${this.getWebVaultUrl()}"}/scim/v2\` : "");
  }

  override getSendUrl() {
    if (this.urls.send) {
      return this.urls.send.endsWith("/#/send/") ? this.urls.send : \`${"${this.urls.send}"}/#/send/\`;
    }
    return this.getWebVaultUrl() ? \`${"${this.getWebVaultUrl()}"}/#/send/\` : "";
  }
}
`,
);

// The OSS background process constructs Bitwarden's remotely-fed phishing
// updater even for a self-hosted build. Omit that optional service from this
// proof; generic password-manager/autofill behavior remains intact.
const browserBackgroundPath = path.join(
  checkout,
  "apps",
  "browser",
  "src",
  "background",
  "main.background.ts",
);
for (const fragment of [
  'import { PhishingDataService } from "../dirt/phishing-detection/services/phishing-data.service";\n',
  'import { PhishingDetectionService } from "../dirt/phishing-detection/services/phishing-detection.service";\n',
  "  private phishingDataService: PhishingDataService;\n",
  "  private phishingDetectionService: PhishingDetectionService;\n",
  `    this.phishingDataService = new PhishingDataService(
      this.apiService,
      this.taskSchedulerService,
      this.globalStateProvider,
      this.logService,
      this.platformUtilsService,
    );

`,
  `    this.phishingDetectionService = new PhishingDetectionService(
      this.logService,
      this.phishingDataService,
      this.phishingDetectionSettingsService,
      messageListener,
      this.eventCollectionService,
      this.organizationService,
      this.accountService,
    );

`,
]) {
  replaceExact(browserBackgroundPath, fragment, "");
}

console.log(`prepare-bitwarden-clients-proof: prepared ${checkout}`);
console.log(`prepare-bitwarden-clients-proof: pinned commit ${actualCommit}`);
