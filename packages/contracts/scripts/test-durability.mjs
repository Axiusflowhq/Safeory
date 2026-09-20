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
    "tests/device-keys.test.ts",
    "tests/session-durability.test.ts",
    "tests/sync-compatibility.test.ts",
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
    ])
  }
} finally {
  rmSync(output, { recursive: true, force: true })
}
