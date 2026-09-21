import { execFileSync } from "node:child_process";

export const REVIEW_CLOSURE_ALLOWED_PATHS = Object.freeze(
  new Set([
    "PLAN.md",
    "docs/provenance/QUALIFIED_LICENSE_REVIEW_SIGNOFF.json",
  ]),
);

export function normalizeGitPath(value) {
  return value.replaceAll("\\", "/");
}

export function reviewClosureViolations(paths) {
  return [...new Set(paths.map(normalizeGitPath).filter(Boolean))]
    .filter((file) => !REVIEW_CLOSURE_ALLOWED_PATHS.has(file))
    .sort();
}

function gitLines(repoRoot, args) {
  return execFileSync("git", args, {
    cwd: repoRoot,
    encoding: "utf8",
  })
    .split(/\r?\n/)
    .filter(Boolean);
}

export function worktreeReviewClosureViolations(repoRoot) {
  const paths = [
    ...gitLines(repoRoot, ["diff", "--name-only"]),
    ...gitLines(repoRoot, ["diff", "--cached", "--name-only"]),
    ...gitLines(repoRoot, ["ls-files", "--others", "--exclude-standard"]),
  ];
  return reviewClosureViolations(paths);
}
