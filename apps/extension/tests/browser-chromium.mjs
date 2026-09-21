import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

const here = dirname(fileURLToPath(import.meta.url));
const extensionPath = join(here, "..", "dist");

function loginHtml(title) {
  return `<!doctype html>
<html>
  <head><meta charset="utf-8"><title>${title}</title></head>
  <body>
    <main>
      <form id="login-form">
        <label>Email <input id="username" name="email" type="email" autocomplete="username"></label>
        <label>Password <input id="password" name="password" type="password" autocomplete="current-password"></label>
        <button id="submit" type="submit">Sign in</button>
      </form>
    </main>
    <script>
      document.querySelector('#login-form').addEventListener('submit', event => event.preventDefault());
    </script>
  </body>
</html>`;
}

async function startLoginServer(title) {
  const server = createServer((_request, response) => {
    response.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    });
    response.end(loginHtml(title));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("test server did not bind");
  return {
    url: `http://127.0.0.1:${address.port}/login`,
    close: () =>
      new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}

async function extensionWorker(context) {
  const existing = context
    .serviceWorkers()
    .find((worker) => worker.url().startsWith("chrome-extension://"));
  if (existing) return existing;
  return await context.waitForEvent("serviceworker", {
    predicate: (worker) => worker.url().startsWith("chrome-extension://"),
  });
}

const profile = await mkdtemp(join(tmpdir(), "safeory-chromium-profile-"));
const target = await startLoginServer("Target Login");
const wrongOrigin = await startLoginServer("Wrong Origin");
let context;

try {
  context = await chromium.launchPersistentContext(profile, {
    channel: "chromium",
    headless: true,
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`,
    ],
  });

  const worker = await extensionWorker(context);
  worker.on("console", (message) =>
    console.error(`[extension-worker:${message.type()}] ${message.text()}`),
  );
  const extensionId = new URL(worker.url()).hostname;
  assert.match(extensionId, /^[a-p]{32}$/);

  const popup = await context.newPage();
  popup.on("console", (message) =>
    console.error(`[extension-popup:${message.type()}] ${message.text()}`),
  );
  popup.on("pageerror", (error) =>
    console.error(`[extension-popup:pageerror] ${error.message}`),
  );
  await popup.goto(`chrome-extension://${extensionId}/popup.html`);
  const passphrase = popup.getByLabel("Master passphrase");
  try {
    await passphrase.waitFor({ timeout: 10_000 });
  } catch (error) {
    console.error(
      `[extension-popup:body] ${await popup.locator("body").innerText()}`,
    );
    throw error;
  }
  await passphrase.fill("correct horse battery staple");
  await popup.getByRole("button", { name: "Create vault" }).click();
  await popup.getByText("0 credentials.").waitFor();

  const page = await context.newPage();
  await page.goto(target.url);
  const saveButton = page.getByRole("button", {
    name: "Save or update this login in Safeory",
  });
  const fillButton = page.getByRole("button", { name: "Fill with Safeory" });
  await saveButton.waitFor();

  await page.locator("#username").fill("alice@example.com");
  await page.locator("#password").fill("first-password");
  await saveButton.click();
  await page
    .getByRole("button", { name: "Save new credential in Safeory" })
    .click();
  await page.getByText("Safeory saved this credential.").waitFor();

  // The background intentionally throttles exact-origin lookups to one per second.
  await page.waitForTimeout(1_100);
  await page.locator("#password").fill("updated-password");
  await saveButton.click();
  await page
    .getByRole("button", { name: "Update Target Login in Safeory" })
    .click();
  await page.getByText("Safeory updated this credential.").waitFor();

  await page.waitForTimeout(1_100);
  await page.locator("#username").fill("");
  await page.locator("#password").fill("");
  await fillButton.click();
  await page
    .getByRole("button", { name: "Fill Target Login for alice@example.com" })
    .click();
  assert.equal(
    await page.locator("#username").inputValue(),
    "alice@example.com",
  );
  assert.equal(
    await page.locator("#password").inputValue(),
    "updated-password",
  );

  await page.goto(wrongOrigin.url);
  await page.getByRole("button", { name: "Fill with Safeory" }).click();
  await page.getByText("No Safeory credentials found for this site.").waitFor();
  assert.equal(await page.locator("#username").inputValue(), "");
  assert.equal(await page.locator("#password").inputValue(), "");

  console.log("Chromium extension behavior proof: PASS");
} finally {
  await context?.close();
  await Promise.allSettled([target.close(), wrongOrigin.close()]);
  await rm(profile, { recursive: true, force: true });
}
