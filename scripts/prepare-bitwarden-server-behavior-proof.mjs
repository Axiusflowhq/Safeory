import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const safeoryRoot = path.resolve(scriptDir, "..");
const checkoutArg = process.argv[2];

if (!checkoutArg) {
  console.error(
    "usage: node scripts/prepare-bitwarden-server-behavior-proof.mjs <prepared-server-checkout>",
  );
  process.exit(2);
}

const checkout = path.resolve(checkoutArg);
const source = path.join(safeoryRoot, "tests", "foundation", "server-behavior");
const destination = path.join(
  checkout,
  "test",
  "Safeory.Foundation.ServerBehavior",
);
const sharedFixtures = path.join(
  safeoryRoot,
  "tests",
  "foundation",
  "fixtures",
);

if (
  !fs.existsSync(
    path.join(
      checkout,
      "test",
      "Api.IntegrationTest",
      "Api.IntegrationTest.csproj",
    ),
  )
) {
  console.error(
    "prepare-bitwarden-server-behavior-proof: prepared Bitwarden server checkout is missing",
  );
  process.exit(1);
}

fs.rmSync(destination, { recursive: true, force: true });
fs.cpSync(source, destination, { recursive: true });
if (fs.existsSync(sharedFixtures)) {
  fs.cpSync(sharedFixtures, path.join(destination, "fixtures"), {
    recursive: true,
  });
}

console.log(
  `prepare-bitwarden-server-behavior-proof: copied Safeory harness to ${destination}`,
);
