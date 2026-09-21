import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { execFileSync } from "node:child_process";
import {
  artifactManifestSha256,
  HEADLINE_ARTIFACT_FILES,
  sha256,
} from "./license-review-artifact.mjs";
import {
  reviewClosureViolations,
  worktreeReviewClosureViolations,
} from "./license-review-git-scope.mjs";
import {
  assertGitHubArtifactMetadata,
  downloadGitHubArtifactArchive,
  extractGitHubArtifactArchive,
  fetchGitHubArtifactMetadata,
} from "./license-review-github.mjs";

function fail(message) {
  console.error(`check-qualified-license-review: ${message}`);
  process.exitCode = 1;
}

const rawArgs = process.argv.slice(2);
const verifyGitHub = rawArgs.includes("--verify-github");
const positional = rawArgs.filter((arg) => arg !== "--verify-github");
const [signoffArg, artifactArg] = positional;
if (!signoffArg || !artifactArg || positional.length !== 2) {
  console.error(
    "usage: node scripts/check-qualified-license-review.mjs <review-signoff.json> <provenance-artifact-dir> [--verify-github]",
  );
  process.exit(2);
}

const repoRoot = process.cwd();
const signoffPath = path.resolve(signoffArg);
const artifactRoot = path.resolve(artifactArg);

if (!fs.existsSync(signoffPath)) {
  fail(`sign-off record does not exist: ${signoffPath}`);
}
if (!fs.existsSync(artifactRoot) || !fs.statSync(artifactRoot).isDirectory()) {
  fail(`provenance artifact directory does not exist: ${artifactRoot}`);
}
if (process.exitCode) process.exit(process.exitCode);

let signoff;
try {
  signoff = JSON.parse(fs.readFileSync(signoffPath, "utf8"));
} catch (error) {
  fail(`invalid sign-off JSON: ${error.message}`);
  process.exit(process.exitCode);
}

const requiredStrings = [
  ["reviewer.name", signoff.reviewer?.name],
  ["reviewer.organization", signoff.reviewer?.organization],
  ["reviewer.qualification", signoff.reviewer?.qualification],
  ["reviewed_at", signoff.reviewed_at],
  ["safeory_commit", signoff.safeory_commit],
  ["github_repository", signoff.github_repository],
  ["github_actions_run_id", signoff.github_actions_run_id],
  ["provenance_artifact_id", signoff.provenance_artifact_id],
  ["provenance_artifact_name", signoff.provenance_artifact_name],
  ["notes", signoff.notes],
];

if (signoff.schema_version !== 1) fail("schema_version must be 1");
for (const [field, value] of requiredStrings) {
  if (
    typeof value !== "string" ||
    value.trim() === "" ||
    value.includes("REPLACE_WITH")
  ) {
    fail(`${field} must be a completed non-placeholder string`);
  }
}

if (
  !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(
    signoff.reviewed_at ?? "",
  )
) {
  fail("reviewed_at must be an ISO-8601 UTC timestamp ending in Z");
} else if (Number.isNaN(Date.parse(signoff.reviewed_at))) {
  fail("reviewed_at must be a valid ISO-8601 timestamp");
} else if (Date.parse(signoff.reviewed_at) > Date.now() + 5 * 60 * 1000) {
  fail("reviewed_at cannot be in the future");
}
if (!/^[0-9a-f]{40}$/.test(signoff.safeory_commit ?? "")) {
  fail("safeory_commit must be a full 40-character lowercase Git SHA");
}
if (signoff.provenance_artifact_name !== "safeory-foundation-provenance") {
  fail("provenance_artifact_name must be safeory-foundation-provenance");
}
if (!/^[^/\s]+\/[^/\s]+$/.test(signoff.github_repository ?? "")) {
  fail("github_repository must be owner/repository");
}
if (!/^\d+$/.test(signoff.github_actions_run_id ?? "")) {
  fail("github_actions_run_id must be a decimal GitHub Actions run ID");
}
if (!/^\d+$/.test(signoff.provenance_artifact_id ?? "")) {
  fail("provenance_artifact_id must be a decimal GitHub Actions artifact ID");
}
if (!/^[0-9a-f]{64}$/.test(signoff.artifact_manifest_sha256 ?? "")) {
  fail("artifact_manifest_sha256 must be a lowercase SHA-256");
} else {
  const actualManifest = artifactManifestSha256(artifactRoot);
  if (actualManifest !== signoff.artifact_manifest_sha256) {
    fail(
      `artifact manifest hash ${actualManifest} does not match sign-off ${signoff.artifact_manifest_sha256}`,
    );
  }
}

const head = execFileSync("git", ["rev-parse", "HEAD"], {
  cwd: repoRoot,
  encoding: "utf8",
}).trim();
try {
  execFileSync(
    "git",
    ["merge-base", "--is-ancestor", signoff.safeory_commit, head],
    { cwd: repoRoot, stdio: "ignore" },
  );
} catch {
  fail(
    `reviewed commit ${signoff.safeory_commit} is not an ancestor of current HEAD ${head}`,
  );
}
if (signoff.safeory_commit !== head) {
  const changedAfterReview = execFileSync(
    "git",
    ["diff", "--name-only", `${signoff.safeory_commit}..${head}`],
    { cwd: repoRoot, encoding: "utf8" },
  )
    .split(/\r?\n/)
    .filter(Boolean);
  const committedViolations = reviewClosureViolations(changedAfterReview);
  for (const changed of committedViolations) {
    fail(
      `reviewed foundation changed after sign-off subject commit: ${changed}`,
    );
  }
}

for (const changed of worktreeReviewClosureViolations(repoRoot)) {
  fail(`uncommitted review-closure scope contains unrelated path: ${changed}`);
}

const generationSummaryPath = path.join(
  artifactRoot,
  "generation-summary.json",
);
if (!fs.existsSync(generationSummaryPath)) {
  fail("artifact is missing generation-summary.json");
} else {
  const summary = JSON.parse(fs.readFileSync(generationSummaryPath, "utf8"));
  if (summary.source_only !== false) {
    fail(
      "qualified review must bind to a full provenance artifact, not source-only output",
    );
  }
  if (summary.safeory_commit !== signoff.safeory_commit) {
    fail(
      `generation-summary safeory_commit ${summary.safeory_commit} does not match sign-off ${signoff.safeory_commit}`,
    );
  }
  if (summary.github_repository !== signoff.github_repository) {
    fail(
      `generation-summary github_repository ${summary.github_repository} does not match sign-off ${signoff.github_repository}`,
    );
  }
  if (summary.github_actions_run_id !== signoff.github_actions_run_id) {
    fail(
      `generation-summary github_actions_run_id ${summary.github_actions_run_id} does not match sign-off ${signoff.github_actions_run_id}`,
    );
  }
  for (const field of [
    "sdk_components",
    "server_components",
    "unknown_license_count",
    "review_sensitive_license_count",
  ]) {
    const expected = signoff.artifact_summary?.[field];
    if (!Number.isInteger(expected) || expected < 0) {
      fail(`artifact_summary.${field} must be a non-negative integer`);
      continue;
    }
    if (summary[field] !== expected) {
      fail(
        `generation-summary ${field}=${summary[field]} does not match sign-off ${expected}`,
      );
    }
  }
}

for (const relative of HEADLINE_ARTIFACT_FILES) {
  const expected = signoff.artifact_hashes?.[relative];
  if (typeof expected !== "string" || !/^[0-9a-f]{64}$/.test(expected)) {
    fail(
      `artifact_hashes[${JSON.stringify(relative)}] must be a lowercase SHA-256`,
    );
    continue;
  }
  const file = path.join(artifactRoot, relative);
  if (!fs.existsSync(file)) {
    fail(`reviewed artifact is missing ${relative}`);
    continue;
  }
  const actual = sha256(fs.readFileSync(file));
  if (actual !== expected) {
    fail(`${relative} hash ${actual} does not match sign-off ${expected}`);
  }
}

if (verifyGitHub) {
  let extracted;
  try {
    const artifact = fetchGitHubArtifactMetadata(
      signoff.github_repository,
      signoff.provenance_artifact_id,
    );
    assertGitHubArtifactMetadata(artifact, {
      artifactId: signoff.provenance_artifact_id,
      artifactName: signoff.provenance_artifact_name,
      runId: signoff.github_actions_run_id,
      headSha: signoff.safeory_commit,
    });
    if (Date.parse(signoff.reviewed_at) < Date.parse(artifact.created_at)) {
      fail(
        `review timestamp ${signoff.reviewed_at} predates GitHub artifact creation ${artifact.created_at}`,
      );
    }
    const archive = await downloadGitHubArtifactArchive(artifact);
    extracted = extractGitHubArtifactArchive(archive);
    const officialManifest = artifactManifestSha256(extracted.root);
    const reviewedManifest = artifactManifestSha256(artifactRoot);
    if (officialManifest !== reviewedManifest) {
      fail(
        `official GitHub artifact manifest ${officialManifest} does not match reviewed directory ${reviewedManifest}`,
      );
    }
    if (officialManifest !== signoff.artifact_manifest_sha256) {
      fail(
        `official GitHub artifact manifest ${officialManifest} does not match sign-off ${signoff.artifact_manifest_sha256}`,
      );
    }
  } catch (error) {
    fail(`GitHub artifact verification failed: ${error.message}`);
  } finally {
    extracted?.cleanup();
  }
}

if (!Array.isArray(signoff.conditions)) {
  fail("conditions must be an array");
} else {
  for (const [index, condition] of signoff.conditions.entries()) {
    if (
      !condition?.id ||
      !condition?.description ||
      condition?.status !== "satisfied" ||
      !condition?.evidence
    ) {
      fail(
        `conditions[${index}] must contain id, description, status=satisfied, and evidence`,
      );
    }
  }
}

if (
  !new Set(["approved", "approved_with_conditions"]).has(signoff.conclusion)
) {
  fail(
    "conclusion must be approved or approved_with_conditions; blocking issues cannot pass",
  );
}
if (
  signoff.conclusion === "approved_with_conditions" &&
  signoff.conditions?.length === 0
) {
  fail(
    "approved_with_conditions requires at least one satisfied condition record",
  );
}
if (signoff.conclusion === "approved" && signoff.conditions?.length !== 0) {
  fail("approved must not carry unresolved/conditional condition records");
}

if (process.exitCode) process.exit(process.exitCode);
console.log(
  `check-qualified-license-review: OK (${signoff.reviewer.name}, ${signoff.conclusion}, commit ${signoff.safeory_commit})`,
);
