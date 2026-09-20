import { spawnSync } from "node:child_process"
import { mkdtempSync, rmSync } from "node:fs"
import { createRequire } from "node:module"
import { tmpdir } from "node:os"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

const output = mkdtempSync(join(tmpdir(), "safeory-contract-tests-"))
const node = process.execPath
const packageDir = fileURLToPath(new URL("..", import.meta.url))
const require = createRequire(import.meta.url)
const tsc = join(dirname(require.resolve("typescript")), "..", "bin", "tsc")

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: packageDir,
    stdio: "inherit",
    shell: false,
  })
  if (result.error) throw result.error
  if (result.status !== 0) process.exitCode = result.status ?? 1
  return result.status === 0
}

try {
  const compiled = run(node, [
    tsc,
    "--ignoreConfig",
    "src/persistence.ts",
    "src/device-keys.ts",
    "src/session.ts",
    "src/sync-compatibility.ts",
    "src/sync-client.ts",
    "src/sync-coordinator.ts",
    "src/sync-credentials.ts",
    "src/sync-error.ts",
    "src/sync-queue.ts",
    "src/sync-pull.ts",
    "src/sync-domain.ts",
    "src/sync-vault-item.ts",
    "src/sync-vault-acceptance.ts",
    "src/sync-bootstrap.ts",
    "tests/device-keys.test.ts",
    "tests/session-durability.test.ts",
    "tests/sync-compatibility.test.ts",
    "tests/sync-client.test.ts",
    "tests/sync-coordinator.test.ts",
    "tests/sync-credentials.test.ts",
    "tests/sync-queue.test.ts",
    "tests/sync-pull.test.ts",
    "tests/sync-domain.test.ts",
    "tests/sync-vault-item.test.ts",
    "tests/sync-vault-acceptance.test.ts",
    "tests/sync-bootstrap.test.ts",
    "--outDir",
    output,
    "--module",
    "commonjs",
    "--target",
    "ES2022",
    "--lib",
    "ES2022,DOM",
    "--types",
    "node",
    "--esModuleInterop",
    "--strict",
    "--skipLibCheck",
  ])

  if (compiled) {
    run(node, [
      "--test",
      join(output, "tests", "device-keys.test.js"),
      join(output, "tests", "session-durability.test.js"),
      join(output, "tests", "sync-compatibility.test.js"),
      join(output, "tests", "sync-client.test.js"),
      join(output, "tests", "sync-coordinator.test.js"),
      join(output, "tests", "sync-credentials.test.js"),
      join(output, "tests", "sync-queue.test.js"),
      join(output, "tests", "sync-pull.test.js"),
      join(output, "tests", "sync-domain.test.js"),
      join(output, "tests", "sync-vault-item.test.js"),
      join(output, "tests", "sync-vault-acceptance.test.js"),
      join(output, "tests", "sync-bootstrap.test.js"),
    ])
  }
} finally {
  rmSync(output, { recursive: true, force: true })
}
