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
  console.error(`prepare-safeory-server-adapter-proof: ${message}`);
  process.exit(1);
}

const checkoutArg = process.argv[2];
if (!checkoutArg) {
  fail(
    "usage: node scripts/prepare-safeory-server-adapter-proof.mjs <prepared-server-checkout>",
  );
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

if (!fs.existsSync(authTarget) || !fs.existsSync(attachmentTarget)) {
  fail(`prepared Bitwarden server checkout is missing: ${checkout}`);
}

const actualCommit = execFileSync(
  "git",
  ["-C", checkout, "rev-parse", "HEAD"],
  { encoding: "utf8" },
).trim();
if (actualCommit !== expectedCommit) {
  fail(`checkout is ${actualCommit}; expected pinned commit ${expectedCommit}`);
}

if (fs.existsSync(path.join(checkout, "bitwarden_license"))) {
  fail("server must be cleaned before Safeory adapter preparation");
}

const body = fs.readFileSync(authTarget, "utf8").replaceAll("\r\n", "\n");
const before = `                options.Events = new JwtBearerEvents
                {
                    OnMessageReceived = (context) =>
                    {
                        context.Token = TokenRetrieval.FromAuthorizationHeaderOrQueryString()(context.Request);
                        return Task.CompletedTask;
                    }
                };
`;
const after = `                options.Events = new JwtBearerEvents
                {
                    OnMessageReceived = (context) =>
                    {
                        context.Token = TokenRetrieval.FromAuthorizationHeaderOrQueryString()(context.Request);
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = async (context) =>
                    {
                        var deviceIdentifier = context.Principal?.FindFirst(Claims.Device)?.Value;
                        if (string.IsNullOrWhiteSpace(deviceIdentifier))
                        {
                            return;
                        }

                        var subject = context.Principal?.FindFirst(JwtClaimTypes.Subject)?.Value;
                        if (!Guid.TryParse(subject, out var userId))
                        {
                            context.Fail("Invalid subject for device-bound token.");
                            return;
                        }

                        var deviceRepository = context.HttpContext.RequestServices.GetRequiredService<IDeviceRepository>();
                        var device = await deviceRepository.GetByIdentifierAsync(deviceIdentifier, userId);
                        if (device == null || !device.Active)
                        {
                            context.Fail("Device is inactive.");
                        }
                    }
                };
`;

if (!body.includes(before)) {
  fail("expected JWT bearer event block was not found exactly once");
}
if (body.indexOf(before) !== body.lastIndexOf(before)) {
  fail("JWT bearer event block matched more than once");
}

fs.writeFileSync(authTarget, body.replace(before, after));

const attachmentBody = fs
  .readFileSync(attachmentTarget, "utf8")
  .replaceAll("\r\n", "\n");
const seekBefore = `            stream.Seek(0, SeekOrigin.Begin);
            await stream.CopyToAsync(fs);
`;
const seekAfter = `            if (stream.CanSeek)
            {
                stream.Seek(0, SeekOrigin.Begin);
            }
            await stream.CopyToAsync(fs);
`;
const seekMatches = attachmentBody.split(seekBefore).length - 1;
if (seekMatches !== 2) {
  fail(`expected exactly 2 local attachment seek sites, found ${seekMatches}`);
}
fs.writeFileSync(
  attachmentTarget,
  attachmentBody.replaceAll(seekBefore, seekAfter),
);

console.log(
  "prepare-safeory-server-adapter-proof: installed inactive-device JWT rejection and non-seekable local attachment support",
);
