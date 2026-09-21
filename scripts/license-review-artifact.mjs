import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const HEADLINE_ARTIFACT_FILES = Object.freeze([
  "generation-summary.json",
  "license-inventory.json",
  "LEGAL_REVIEW_SUMMARY.md",
  "QUALIFIED_LICENSE_REVIEW_CHECKLIST.md",
  "nuget-license-review-evidence.json",
  "review-sensitive-dependency-scope.json",
]);

export function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

export function listArtifactFiles(directory, prefix = "") {
  const results = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    const relative = path.posix.join(prefix, entry.name);
    if (entry.isDirectory()) {
      results.push(...listArtifactFiles(absolute, relative));
    } else if (entry.isFile()) {
      results.push(relative);
    }
  }
  return results.sort();
}

export function artifactManifestSha256(directory) {
  const lines = listArtifactFiles(directory).map((relative) => {
    const file = path.join(directory, ...relative.split("/"));
    return `${relative}\0${sha256(fs.readFileSync(file))}`;
  });
  return sha256(Buffer.from(`${lines.join("\n")}\n`, "utf8"));
}

export function headlineArtifactHashes(directory) {
  return Object.fromEntries(
    HEADLINE_ARTIFACT_FILES.map((relative) => {
      const file = path.join(directory, relative);
      if (!fs.existsSync(file)) {
        throw new Error(`artifact is missing ${relative}`);
      }
      return [relative, sha256(fs.readFileSync(file))];
    }),
  );
}
