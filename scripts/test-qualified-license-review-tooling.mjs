import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { execFileSync, spawnSync } from "node:child_process";
import {
  assertGitHubArtifactMetadata,
  assertSafeArtifactArchiveListing,
} from "./license-review-github.mjs";
import { reviewClosureViolations } from "./license-review-git-scope.mjs";

const artifactArg = process.argv[2];
if (!artifactArg) {
  console.error(
    "usage: node scripts/test-qualified-license-review-tooling.mjs <full-provenance-artifact-dir>",
  );
  process.exit(2);
}

const repoRoot = process.cwd();
const artifactRoot = path.resolve(artifactArg);
const tempRoot = fs.mkdtempSync(
  path.join(os.tmpdir(), "safeory-license-review-"),
);

function runNode(script, args) {
  return execFileSync(process.execPath, [script, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function expectFailure(script, args, pattern, label) {
  const result = spawnSync(process.execPath, [script, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  if (result.status === 0) {
    throw new Error(`${label} unexpectedly passed`);
  }
  const combined = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  if (!pattern.test(combined)) {
    throw new Error(`${label} failed for an unexpected reason:\n${combined}`);
  }
}

try {
  const syntheticMetadata = {
    id: 1,
    name: "safeory-foundation-provenance",
    expired: false,
    digest: `sha256:${"0".repeat(64)}`,
    created_at: "2026-09-21T00:00:00Z",
    archive_download_url:
      "https://api.github.com/repos/Axiusflowhq/Safeory/actions/artifacts/1/zip",
    workflow_run: {
      id: 1,
      head_sha: "a".repeat(40),
    },
  };
  assertGitHubArtifactMetadata(syntheticMetadata, {
    artifactId: "1",
    artifactName: "safeory-foundation-provenance",
    runId: "1",
    headSha: "a".repeat(40),
  });
  try {
    assertGitHubArtifactMetadata(syntheticMetadata, {
      artifactId: "1",
      artifactName: "safeory-foundation-provenance",
      runId: "2",
      headSha: "a".repeat(40),
    });
    throw new Error("GitHub metadata mismatch unexpectedly passed");
  } catch (error) {
    if (!/workflow run/.test(error.message)) throw error;
  }
  assertSafeArtifactArchiveListing(
    "generation-summary.json\nsbom/sdk.cdx.json\nlicenses/server/LICENSE.txt\n",
  );
  try {
    assertSafeArtifactArchiveListing("../escape.txt\n");
    throw new Error("unsafe archive path unexpectedly passed");
  } catch (error) {
    if (!/unsafe path/.test(error.message)) throw error;
  }

  const allowedScope = reviewClosureViolations([
    "PLAN.md",
    "docs/provenance/QUALIFIED_LICENSE_REVIEW_SIGNOFF.json",
  ]);
  if (allowedScope.length !== 0) {
    throw new Error(
      `allowed review-closure scope was rejected: ${allowedScope}`,
    );
  }
  const disallowedScope = reviewClosureViolations([
    "PLAN.md",
    "src/Foundation/changed.rs",
  ]);
  if (
    disallowedScope.length !== 1 ||
    disallowedScope[0] !== "src/Foundation/changed.rs"
  ) {
    throw new Error(
      `review-closure scope failed to reject unrelated changes: ${disallowedScope}`,
    );
  }

  const draft = path.join(tempRoot, "draft.json");
  runNode("scripts/prepare-license-review-signoff.mjs", [
    artifactRoot,
    "1",
    draft,
  ]);

  const record = JSON.parse(fs.readFileSync(draft, "utf8"));
  record.reviewer = {
    name: "Synthetic verifier test",
    organization: "Safeory CI",
    qualification: "Synthetic tooling fixture — not legal approval",
  };
  record.reviewed_at = "2026-09-21T00:00:00Z";
  record.conclusion = "approved";
  record.conditions = [];
  record.notes =
    "Synthetic CI verifier exercise only; not qualified legal approval.";

  const approved = path.join(tempRoot, "approved.json");
  fs.writeFileSync(approved, `${JSON.stringify(record, null, 2)}\n`);
  runNode("scripts/check-qualified-license-review.mjs", [
    approved,
    artifactRoot,
  ]);

  const futureReview = structuredClone(record);
  futureReview.reviewed_at = new Date(
    Date.now() + 10 * 60 * 1000,
  ).toISOString();
  const futureReviewPath = path.join(tempRoot, "future-review.json");
  fs.writeFileSync(
    futureReviewPath,
    `${JSON.stringify(futureReview, null, 2)}\n`,
  );
  expectFailure(
    "scripts/check-qualified-license-review.mjs",
    [futureReviewPath, artifactRoot],
    /reviewed_at cannot be in the future/,
    "future-review timestamp case",
  );

  const wrongRun = structuredClone(record);
  wrongRun.github_actions_run_id =
    wrongRun.github_actions_run_id === "1" ? "2" : "1";
  const wrongRunPath = path.join(tempRoot, "wrong-run.json");
  fs.writeFileSync(wrongRunPath, `${JSON.stringify(wrongRun, null, 2)}\n`);
  expectFailure(
    "scripts/check-qualified-license-review.mjs",
    [wrongRunPath, artifactRoot],
    /generation-summary github_actions_run_id .* does not match sign-off/,
    "workflow-run mismatch case",
  );

  const wrongRepository = structuredClone(record);
  wrongRepository.github_repository = "example/not-safeory";
  const wrongRepositoryPath = path.join(tempRoot, "wrong-repository.json");
  fs.writeFileSync(
    wrongRepositoryPath,
    `${JSON.stringify(wrongRepository, null, 2)}\n`,
  );
  expectFailure(
    "scripts/check-qualified-license-review.mjs",
    [wrongRepositoryPath, artifactRoot],
    /generation-summary github_repository .* does not match sign-off/,
    "repository mismatch case",
  );

  const conditional = structuredClone(record);
  conditional.conclusion = "approved_with_conditions";
  conditional.conditions = [
    {
      id: "synthetic-notice",
      description: "Synthetic satisfied condition for verifier coverage",
      status: "satisfied",
      evidence: "Synthetic CI fixture only",
    },
  ];
  const conditionalPath = path.join(tempRoot, "conditional.json");
  fs.writeFileSync(
    conditionalPath,
    `${JSON.stringify(conditional, null, 2)}\n`,
  );
  runNode("scripts/check-qualified-license-review.mjs", [
    conditionalPath,
    artifactRoot,
  ]);

  const unsatisfied = structuredClone(conditional);
  unsatisfied.conditions[0].status = "pending";
  const unsatisfiedPath = path.join(tempRoot, "unsatisfied.json");
  fs.writeFileSync(
    unsatisfiedPath,
    `${JSON.stringify(unsatisfied, null, 2)}\n`,
  );
  expectFailure(
    "scripts/check-qualified-license-review.mjs",
    [unsatisfiedPath, artifactRoot],
    /status=satisfied/,
    "unsatisfied-condition case",
  );

  const tampered = structuredClone(record);
  tampered.artifact_manifest_sha256 = "0".repeat(64);
  const tamperedPath = path.join(tempRoot, "tampered.json");
  fs.writeFileSync(tamperedPath, `${JSON.stringify(tampered, null, 2)}\n`);
  expectFailure(
    "scripts/check-qualified-license-review.mjs",
    [tamperedPath, artifactRoot],
    /artifact manifest hash .* does not match sign-off/,
    "artifact-manifest tamper case",
  );

  const blocking = structuredClone(record);
  blocking.conclusion = "blocking_issue";
  const blockingPath = path.join(tempRoot, "blocking.json");
  fs.writeFileSync(blockingPath, `${JSON.stringify(blocking, null, 2)}\n`);
  expectFailure(
    "scripts/check-qualified-license-review.mjs",
    [blockingPath, artifactRoot],
    /conclusion must be approved or approved_with_conditions/,
    "blocking-conclusion case",
  );

  console.log(
    "test-qualified-license-review-tooling: OK (approval/conditions pass; future review, run/repo mismatch, unsatisfied conditions, tampering, and blocking conclusions fail)",
  );
} finally {
  fs.rmSync(tempRoot, { recursive: true, force: true });
}
