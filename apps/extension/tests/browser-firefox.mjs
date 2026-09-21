import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Builder, By, until } from "selenium-webdriver";
import * as firefoxDriver from "selenium-webdriver/firefox.js";
import { firefox as playwrightFirefox } from "playwright";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const { getBinaryPaths } = require("selenium-webdriver/common/driverFinder");
const extensionPath = join(here, "..", "dist");
const geckoExtensionId = "safeory@safeory.local";
const extensionUuid = "d2d7467d-4f87-4b49-9d24-6c6337d58d10";

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
  if (address === null || typeof address === "string") {
    throw new Error("test server did not bind");
  }
  return {
    url: `http://127.0.0.1:${address.port}/login`,
    close: () =>
      new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}

async function waitForText(driver, text, timeout = 10_000) {
  await driver.wait(
    async () =>
      (await driver.findElement(By.tagName("body")).getText()).includes(text),
    timeout,
  );
}

async function clickByText(driver, text, timeout = 10_000) {
  const element = await driver.wait(
    until.elementLocated(
      By.xpath(
        `//button[contains(normalize-space(.), ${JSON.stringify(text)})]`,
      ),
    ),
    timeout,
  );
  await driver.wait(until.elementIsVisible(element), timeout);
  await element.click();
}

const target = await startLoginServer("Target Login");
const wrongOrigin = await startLoginServer("Wrong Origin");
const options = new firefoxDriver.Options()
  .setBinary(playwrightFirefox.executablePath())
  .addArguments("-headless")
  .setPreference(
    "extensions.webextensions.uuids",
    JSON.stringify({ [geckoExtensionId]: extensionUuid }),
  );
const { driverPath } = getBinaryPaths(options);
const service = new firefoxDriver.ServiceBuilder(driverPath).addArguments(
  "--allow-system-access",
);

const driver = await new Builder()
  .forBrowser("firefox")
  .setFirefoxOptions(options)
  .setFirefoxService(service)
  .build();

try {
  const installedId = await driver.installAddon(extensionPath, true);
  assert.equal(installedId, geckoExtensionId);

  await driver.setContext(firefoxDriver.Context.CHROME);
  await driver.executeScript(
    `
      const principal = Services.scriptSecurityManager.getSystemPrincipal();
      const uri = Services.io.newURI(arguments[0]);
      gBrowser.selectedBrowser.loadURI(uri, { triggeringPrincipal: principal });
      return true;
    `,
    `moz-extension://${extensionUuid}/popup.html`,
  );
  await driver.setContext(firefoxDriver.Context.CONTENT);
  await driver.wait(
    async () =>
      (await driver.getCurrentUrl()).startsWith(
        `moz-extension://${extensionUuid}/`,
      ),
    10_000,
  );
  const passphrase = await driver.wait(
    until.elementLocated(By.id("safeory-extension-passphrase")),
    10_000,
  );
  await passphrase.sendKeys("correct horse battery staple");
  await clickByText(driver, "Create vault");
  await waitForText(driver, "0 credentials.");

  await driver.get(target.url);
  await driver.wait(
    until.elementLocated(
      By.css('button[aria-label="Save or update this login in Safeory"]'),
    ),
    10_000,
  );
  await driver.findElement(By.id("username")).sendKeys("alice@example.com");
  await driver.findElement(By.id("password")).sendKeys("first-password");
  await driver
    .findElement(
      By.css('button[aria-label="Save or update this login in Safeory"]'),
    )
    .click();
  await clickByText(driver, "Save new credential");
  await waitForText(driver, "Safeory saved this credential.");

  await driver.sleep(1_100);
  const password = await driver.findElement(By.id("password"));
  await password.clear();
  await password.sendKeys("updated-password");
  await driver
    .findElement(
      By.css('button[aria-label="Save or update this login in Safeory"]'),
    )
    .click();
  await clickByText(driver, "Update Target Login");
  await waitForText(driver, "Safeory updated this credential.");

  await driver.sleep(1_100);
  const username = await driver.findElement(By.id("username"));
  await username.clear();
  await password.clear();
  await driver
    .findElement(By.css('button[aria-label="Fill with Safeory"]'))
    .click();
  const fillChoice = await driver.wait(
    until.elementLocated(
      By.css('button[aria-label="Fill Target Login for alice@example.com"]'),
    ),
    10_000,
  );
  await fillChoice.click();
  assert.equal(await username.getAttribute("value"), "alice@example.com");
  assert.equal(await password.getAttribute("value"), "updated-password");

  await driver.get(wrongOrigin.url);
  await driver.wait(
    until.elementLocated(By.css('button[aria-label="Fill with Safeory"]')),
    10_000,
  );
  await driver
    .findElement(By.css('button[aria-label="Fill with Safeory"]'))
    .click();
  await waitForText(driver, "No Safeory credentials found for this site.");
  assert.equal(
    await driver.findElement(By.id("username")).getAttribute("value"),
    "",
  );
  assert.equal(
    await driver.findElement(By.id("password")).getAttribute("value"),
    "",
  );

  console.log("Firefox extension behavior proof: PASS");
} finally {
  await driver.quit();
  await Promise.allSettled([target.close(), wrongOrigin.close()]);
}
