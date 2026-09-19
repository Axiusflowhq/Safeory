import { createHash } from "node:crypto"
import { readdir, readFile, writeFile } from "node:fs/promises"
import { dirname, join, relative } from "node:path"
import { fileURLToPath } from "node:url"

const appDir = dirname(dirname(fileURLToPath(import.meta.url)))
const outDir = join(appDir, "out")
const templatePath = join(appDir, "Caddyfile")
const outputPath = join(outDir, "Caddyfile")
const placeholder = "__SAFEORY_SCRIPT_HASHES__"

async function htmlFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true })
  const files = []

  for (const entry of entries) {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) {
      files.push(...(await htmlFiles(path)))
    } else if (entry.isFile() && entry.name.endsWith(".html")) {
      files.push(path)
    }
  }

  return files
}

function inlineScriptBodies(html) {
  const scripts = []
  const expression = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi
  let match

  while ((match = expression.exec(html)) !== null) {
    const attributes = match[1] ?? ""
    const body = match[2] ?? ""
    if (/\bsrc\s*=/i.test(attributes) || body.length === 0) continue
    scripts.push(body)
  }

  return scripts
}

function sha256Source(body) {
  const digest = createHash("sha256").update(body, "utf8").digest("base64")
  return `'sha256-${digest}'`
}

const files = await htmlFiles(outDir)
const hashes = new Set()

for (const file of files) {
  const html = await readFile(file, "utf8")
  for (const body of inlineScriptBodies(html)) {
    hashes.add(sha256Source(body))
  }
}

if (hashes.size === 0) {
  throw new Error("No inline Next.js scripts were found; refusing to generate an empty CSP hash set")
}

const template = await readFile(templatePath, "utf8")
if (!template.includes(placeholder)) {
  throw new Error(`Caddyfile is missing ${placeholder}`)
}

const scriptSources = [...hashes].sort().join(" ")
const generated = template.replace(placeholder, scriptSources)
await writeFile(outputPath, generated, "utf8")

for (const file of files) {
  const html = await readFile(file, "utf8")
  for (const body of inlineScriptBodies(html)) {
    const source = sha256Source(body)
    if (!generated.includes(source)) {
      throw new Error(`Generated CSP omitted ${source} required by ${relative(outDir, file)}`)
    }
  }
}

console.log(`Generated strict static CSP with ${hashes.size} inline-script SHA-256 hashes.`)
