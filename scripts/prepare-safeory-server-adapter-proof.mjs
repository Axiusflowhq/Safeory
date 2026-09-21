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
const target = path.join(
  checkout,
  "src",
  "SharedWeb",
  "Utilities",
  "ServiceCollectionExtensions.cs",
);

if (!fs.existsSync(target)) {
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

const body = fs.readFileSync(target, "utf8").replaceAll("\r\n", "\n");
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

fs.writeFileSync(target, body.replace(before, after));

console.log(
  `prepare-safeory-server-adapter-proof: installed inactive-device JWT rejection in ${path.relative(checkout, target)}`,
);
