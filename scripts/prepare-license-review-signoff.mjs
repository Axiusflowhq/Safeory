import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { execFileSync } from "node:child_process";
import {
  artifactManifestSha256,
  headlineArtifactHashes,
} from "./license-review-artifact.mjs";

const [artifactArg, runId, artifactId, outputArg] = process.argv.slice(2);
if (!artifactArg || !runId || !artifactId) {
  console.error(
    "usage: node scripts/prepare-license-review-signoff.mjs <provenance-artifact-dir> <github-run-id> <artifact-id> [output-json]",
  );
  process.exit(2);
}
if (!/^\d+$/.test(runId) || !/^\d+$/.test(artifactId)) {
  console.error("run ID and artifact ID must be decimal integers");
  process.exit(2);
}

const repoRoot = process.cwd();
const artifactRoot = path.resolve(artifactArg);
if (!fs.existsSync(artifactRoot) || !fs.statSync(artifactRoot).isDirectory()) {
  console.error(`artifact directory does not exist: ${artifactRoot}`);
  process.exit(1);
}

const summaryPath = path.join(artifactRoot, "generation-summary.json");
if (!fs.existsSync(summaryPath)) {
  console.error("artifact is missing generation-summary.json");
  process.exit(1);
}
const summary = JSON.parse(fs.readFileSync(summaryPath, "utf8"));
if (summary.source_only !== false) {
  console.error("qualified review draft requires a full provenance artifact");
  process.exit(1);
}

const head = execFileSync("git", ["rev-parse", "HEAD"], {
  cwd: repoRoot,
  encoding: "utf8",
}).trim();
if (!/^[0-9a-f]{40}$/.test(summary.safeory_commit ?? "")) {
  console.error("artifact generation-summary.json has no valid safeory_commit");
  process.exit(1);
}
try {
  execFileSync(
    "git",
    ["merge-base", "--is-ancestor", summary.safeory_commit, head],
    { cwd: repoRoot, stdio: "ignore" },
  );
} catch {
  console.error(
    `artifact Safeory commit ${summary.safeory_commit} is not an ancestor of current HEAD ${head}`,
  );
  process.exit(1);
}

const record = {
  schema_version: 1,
  reviewer: {
    name: "REPLACE_WITH_QUALIFIED_REVIEWER",
    organization: "REPLACE_WITH_REVIEW_ORGANIZATION",
    qualification: "REPLACE_WITH_REVIEWER_QUALIFICATION",
  },
  reviewed_at: "REPLACE_WITH_ISO_8601_TIMESTAMP",
  safeory_commit: summary.safeory_commit,
  github_actions_run_id: runId,
  provenance_artifact_id: artifactId,
  provenance_artifact_name: "safeory-foundation-provenance",
  artifact_summary: {
    sdk_components: summary.sdk_components,
    server_components: summary.server_components,
    unknown_license_count: summary.unknown_license_count,
    review_sensitive_license_count: summary.review_sensitive_license_count,
  },
  artifact_manifest_sha256: artifactManifestSha256(artifactRoot),
  artifact_hashes: headlineArtifactHashes(artifactRoot),
  conclusion: "REPLACE_WITH_REVIEW_CONCLUSION",
  conditions: [],
  notes: "REPLACE_WITH_REVIEW_NOTES",
};

const output = outputArg
  ? path.resolve(outputArg)
  : path.join(
      repoRoot,
      "docs",
      "provenance",
      "generated",
      "LICENSE_REVIEW_SIGNOFF.draft.json",
    );
fs.mkdirSync(path.dirname(output), { recursive: true });
fs.writeFileSync(output, `${JSON.stringify(record, null, 2)}\n`);
console.log(
  `prepare-license-review-signoff: wrote draft ${path.relative(repoRoot, output)} for reviewed commit ${summary.safeory_commit} (current HEAD ${head})`,
);
