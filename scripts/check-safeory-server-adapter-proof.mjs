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
let failed = false;

function fail(message) {
  failed = true;
  console.error(`check-safeory-server-adapter-proof: ${message}`);
}

const checkoutArg = process.argv[2];
if (!checkoutArg) {
  console.error(
    "usage: node scripts/check-safeory-server-adapter-proof.mjs <adapted-server-checkout>",
  );
  process.exit(2);
}

const checkout = path.resolve(checkoutArg);
const target = path.join(
  checkout,
  "src",
  "SharedWeb",
  "Utilities",
  "ServiceCollectionExtensions.cs",
);

try {
  const actualCommit = execFileSync(
    "git",
    ["-C", checkout, "rev-parse", "HEAD"],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  ).trim();
  if (actualCommit !== expectedCommit) {
    fail(
      `checkout is ${actualCommit}; expected pinned commit ${expectedCommit}`,
    );
  }
} catch (error) {
  fail(`could not resolve checkout commit: ${error.message}`);
}

if (!fs.existsSync(target)) {
  fail("adapted server authentication source is missing");
} else {
  const body = fs.readFileSync(target, "utf8");
  const requirements = [
    "OnTokenValidated = async (context) =>",
    "FindFirst(Claims.Device)",
    "FindFirst(JwtClaimTypes.Subject)",
    "GetRequiredService<IDeviceRepository>()",
    "GetByIdentifierAsync(deviceIdentifier, userId)",
    "device == null || !device.Active",
    'context.Fail("Device is inactive.")',
  ];
  for (const requirement of requirements) {
    if (!body.includes(requirement)) {
      fail(`missing inactive-device JWT guard fragment: ${requirement}`);
    }
  }
}

if (failed) {
  process.exit(1);
}

console.log(
  "check-safeory-server-adapter-proof: OK (device-bound JWTs are rejected when the server device is absent or inactive)",
);
