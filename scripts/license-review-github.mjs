import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { sha256 } from "./license-review-artifact.mjs";

const MAX_ARTIFACT_ARCHIVE_BYTES = 128 * 1024 * 1024;

export function fetchGitHubArtifactMetadata(repository, artifactId) {
  try {
    const response = execFileSync(
      "gh",
      ["api", `repos/${repository}/actions/artifacts/${artifactId}`],
      {
        encoding: "utf8",
        maxBuffer: 16 * 1024 * 1024,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    return JSON.parse(response);
  } catch (error) {
    const detail = error?.stderr?.toString?.().trim() || error.message;
    throw new Error(`could not query GitHub artifact metadata: ${detail}`);
  }
}

export function assertGitHubArtifactMetadata(
  artifact,
  { artifactId, artifactName, runId, headSha },
) {
  if (String(artifact.id) !== String(artifactId)) {
    throw new Error(
      `GitHub artifact ID ${artifact.id} does not match ${artifactId}`,
    );
  }
  if (artifact.name !== artifactName) {
    throw new Error(
      `GitHub artifact name ${artifact.name} does not match ${artifactName}`,
    );
  }
  if (artifact.expired === true) {
    throw new Error("GitHub provenance artifact is expired");
  }
  if (String(artifact.workflow_run?.id) !== String(runId)) {
    throw new Error(
      `GitHub artifact workflow run ${artifact.workflow_run?.id} does not match ${runId}`,
    );
  }
  if (artifact.workflow_run?.head_sha !== headSha) {
    throw new Error(
      `GitHub artifact head SHA ${artifact.workflow_run?.head_sha} does not match ${headSha}`,
    );
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(artifact.digest ?? "")) {
    throw new Error(`GitHub artifact has invalid digest ${artifact.digest}`);
  }
  if (Number.isNaN(Date.parse(artifact.created_at ?? ""))) {
    throw new Error(
      `GitHub artifact has invalid created_at ${artifact.created_at}`,
    );
  }
  try {
    const archiveUrl = new URL(artifact.archive_download_url);
    if (
      archiveUrl.protocol !== "https:" ||
      archiveUrl.hostname !== "api.github.com"
    ) {
      throw new Error();
    }
  } catch {
    throw new Error(
      `GitHub artifact has invalid archive_download_url ${artifact.archive_download_url}`,
    );
  }
}

export async function downloadGitHubArtifactArchive(artifact) {
  let token;
  try {
    token = execFileSync("gh", ["auth", "token"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch (error) {
    const detail = error?.stderr?.toString?.().trim() || error.message;
    throw new Error(`could not read GitHub auth token: ${detail}`);
  }
  const response = await fetch(artifact.archive_download_url, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
    },
    redirect: "follow",
  });
  if (!response.ok) {
    throw new Error(
      `GitHub artifact download failed: HTTP ${response.status} ${response.statusText}`,
    );
  }
  const advertisedLength = Number(response.headers.get("content-length"));
  if (
    Number.isFinite(advertisedLength) &&
    advertisedLength > MAX_ARTIFACT_ARCHIVE_BYTES
  ) {
    throw new Error(
      `GitHub artifact archive is too large: ${advertisedLength} bytes`,
    );
  }
  const reader = response.body?.getReader();
  if (!reader) {
    throw new Error("GitHub artifact download returned no response body");
  }
  const chunks = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > MAX_ARTIFACT_ARCHIVE_BYTES) {
      await reader.cancel();
      throw new Error(
        `GitHub artifact archive exceeded ${MAX_ARTIFACT_ARCHIVE_BYTES} bytes`,
      );
    }
    chunks.push(Buffer.from(value));
  }
  const archive = Buffer.concat(chunks, length);
  const actualDigest = `sha256:${sha256(archive)}`;
  if (actualDigest !== artifact.digest) {
    throw new Error(
      `downloaded artifact digest ${actualDigest} does not match GitHub ${artifact.digest}`,
    );
  }
  return archive;
}

export function assertSafeArtifactArchiveListing(listing) {
  for (const raw of listing.split(/\r?\n/).filter(Boolean)) {
    const name = raw.replaceAll("\\", "/");
    const segments = name.split("/").filter(Boolean);
    if (
      name.startsWith("/") ||
      /^[A-Za-z]:\//.test(name) ||
      segments.some((segment) => segment === "..")
    ) {
      throw new Error(`GitHub artifact ZIP contains unsafe path: ${raw}`);
    }
  }
}

export function extractGitHubArtifactArchive(archive) {
  const tempRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "safeory-github-artifact-"),
  );
  const zipPath = path.join(tempRoot, "artifact.zip");
  const extractedRoot = path.join(tempRoot, "artifact");
  fs.writeFileSync(zipPath, archive);
  fs.mkdirSync(extractedRoot, { recursive: true });
  try {
    const listing = execFileSync("tar", ["-tf", zipPath], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    assertSafeArtifactArchiveListing(listing);
    execFileSync("tar", ["-xf", zipPath, "-C", extractedRoot], {
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error) {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    const detail = error?.stderr?.toString?.().trim() || error.message;
    throw new Error(
      `could not extract GitHub artifact ZIP with tar: ${detail}`,
    );
  }
  return {
    root: extractedRoot,
    cleanup() {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    },
  };
}
