import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { execFileSync, spawnSync } from "node:child_process";
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
  const allowedScope = reviewClosureViolations([
    "PLAN.md",
    "docs/provenance/QUALIFIED_LICENSE_REVIEW_SIGNOFF.json",
  ]);
  if (allowedScope.length !== 0) {
    throw new Error(`allowed review-closure scope was rejected: ${allowedScope}`);
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
    "test-qualified-license-review-tooling: OK (synthetic approval passes; tampering/blocking conclusions fail)",
  );
} finally {
  fs.rmSync(tempRoot, { recursive: true, force: true });
}
