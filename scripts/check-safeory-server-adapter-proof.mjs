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
const authTarget = path.join(
  checkout,
  "src",
  "SharedWeb",
  "Utilities",
  "ServiceCollectionExtensions.cs",
);
const attachmentTarget = path.join(
  checkout,
  "src",
  "Core",
  "Vault",
  "Services",
  "Implementations",
  "LocalAttachmentStorageService.cs",
);
const cipherControllerTarget = path.join(
  checkout,
  "src",
  "Api",
  "Vault",
  "Controllers",
  "CiphersController.cs",
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

if (!fs.existsSync(authTarget)) {
  fail("adapted server authentication source is missing");
} else {
  const body = fs.readFileSync(authTarget, "utf8");
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

if (!fs.existsSync(attachmentTarget)) {
  fail("adapted local attachment storage source is missing");
} else {
  const body = fs.readFileSync(attachmentTarget, "utf8");
  const canSeekCount = body.match(/if \(stream\.CanSeek\)/g)?.length ?? 0;
  if (canSeekCount !== 2) {
    fail(
      `expected 2 non-seekable attachment stream guards, found ${canSeekCount}`,
    );
  }
  if (
    body.includes(
      "stream.Seek(0, SeekOrigin.Begin);\n            await stream.CopyToAsync(fs);",
    )
  ) {
    fail("unguarded local attachment stream seek remains");
  }
}

if (!fs.existsSync(cipherControllerTarget)) {
  fail("adapted cipher controller source is missing");
} else {
  const body = fs.readFileSync(cipherControllerTarget, "utf8");
  const requirements = [
    "Request.EnableBuffering();",
    "Request.Body.Position = 0;",
    "cipher.IsDataBlobEncrypted()",
    "new Cipher { Data = model.Data }",
    "Cannot overwrite a blob-encrypted item with legacy field-level data.",
  ];
  for (const requirement of requirements) {
    if (!body.includes(requirement)) {
      fail(`missing blob downgrade guard fragment: ${requirement}`);
    }
  }
  const bufferingCount =
    body.match(/Request\.EnableBuffering\(\);/g)?.length ?? 0;
  const rewindCount = body.match(/Request\.Body\.Position = 0;/g)?.length ?? 0;
  if (bufferingCount !== 2 || rewindCount !== 2) {
    fail(
      `expected 2 multipart buffering/rewind guards, found buffering=${bufferingCount}, rewind=${rewindCount}`,
    );
  }
}

if (failed) {
  process.exit(1);
}

console.log(
  "check-safeory-server-adapter-proof: OK (inactive-device JWT rejection + multipart rewind + non-seekable local attachments + blob downgrade rejection)",
);
