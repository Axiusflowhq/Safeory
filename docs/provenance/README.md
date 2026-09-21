# Foundation provenance contract

`foundation-seed.json` is the authoritative source pin for the Bitwarden OSS
foundation proof. The production Safeory frontend remains Safeory-owned; the
Bitwarden clients repository is reference-only unless a later reviewed phase
selects a specific isolated non-UI file.

## Reproducible proof inputs

The disposable checkouts under `.proof/` are never committed. Recreate them from
the commits in `foundation-seed.json`, then prepare them with:

```text
node scripts/prepare-bitwarden-sdk-proof.mjs <sdk-checkout>
node scripts/prepare-bitwarden-server-proof.mjs <server-checkout>
```

The corresponding `check-*` scripts fail closed if a pinned commit, restricted
source path, restricted dependency, licensed project edge, or cleaned build graph
does not match the expected OSS boundary.

## Generated evidence bundle

After restoring the retained server composition, generate the full evidence
bundle with:

```text
node scripts/generate-foundation-provenance.mjs <sdk-checkout> <server-checkout> docs/provenance/generated
```

The generated directory is intentionally ignored by Git. CI publishes it as the
`safeory-foundation-provenance` artifact and includes:

- `sbom/sdk.cdx.json` — CycloneDX 1.6 components derived from locked Cargo/npm
  metadata.
- `sbom/server.cdx.json` — CycloneDX 1.6 components derived from restored NuGet
  assets for the retained server composition.
- `license-inventory.json` — package/version/license evidence, including explicit
  `UNKNOWN` entries where package metadata is insufficient.
- `nuget-license-review-evidence.json` — version-bound upstream evidence for
  unresolved NuGet metadata. Candidate licenses in this file are review aids;
  the corresponding inventory rows remain `UNKNOWN` until qualified review.
- `licenses/` — upstream repository-level license, disclaimer, FAQ, and trademark
  notice files kept verbatim for review.
- `source-manifests/` — every retained tracked upstream file with its SHA-256
  digest, bound to the pinned commit.
- `restricted-removals.json` — the exact prepared-checkout cleanup diff plus the
  forbidden path/dependency policy.
- `LEGAL_REVIEW_SUMMARY.md` — reviewer-facing pinned-input summary plus every
  dependency entry whose generated license metadata is `UNKNOWN`, plus
  GPL/LGPL/EULA-sensitive dependency metadata surfaced for explicit review.
- `QUALIFIED_LICENSE_REVIEW_CHECKLIST.md` — the exact tracked review/sign-off
  checklist copied into the artifact so counsel/reviewers can work from a
  self-contained evidence bundle.
- `LICENSE_REVIEW_SIGNOFF.example.json` — machine-readable sign-off template.
  Prepare a hash-bound draft with
  `bun run prepare:license-review -- <artifact-dir> <artifact-id> <draft-json>`;
  the GitHub run ID and repository are read from the artifact itself.
  After qualified review, save the completed record as
  `docs/provenance/QUALIFIED_LICENSE_REVIEW_SIGNOFF.json` and validate it with
  `bun run check:license-review -- <signoff> <artifact-dir> --verify-github` when
  authenticated `gh` access is available. Omit `--verify-github` only for offline
  integrity validation.
- `THIRD_PARTY_NOTICES.md` — generated provenance/notices index for the bundle.
- `generation-summary.json` — the generating Safeory commit plus source/component,
  GitHub repository/run identity when generated in CI, unresolved-license, and
  review-sensitive counts.

`scripts/check-foundation-provenance.mjs` validates the generated bundle before
CI uploads it. It verifies the pinned commits, source-manifest hashes/shape,
CycloneDX version and component uniqueness, inventory counts, and rejects known
restricted paths/packages if they reappear in the generated evidence.

For Windows/local validation where the pinned .NET SDK is unavailable, the
generator supports `--source-only`. That mode still proves source boundaries and
the SDK dependency/license inventory, but deliberately omits the server NuGet
SBOM. It is not a substitute for the full Linux CI artifact.

## Distribution gate

These scripts collect evidence; they do not make a legal determination. Unknown
or non-standard license metadata must be resolved or explicitly reviewed, and the
qualified-license-review item in `PLAN.md` must remain open until that review is
actually completed.

The sign-off verifier validates artifact/commit integrity, required fields,
conclusion shape, and condition status. It does **not** authenticate that the named
reviewer is legally qualified; that remains an external human/organizational
control. During Phase 0 closure it also requires committed and uncommitted review
scope to contain only `PLAN.md` and
`docs/provenance/QUALIFIED_LICENSE_REVIEW_SIGNOFF.json`; unrelated staged,
unstaged, or untracked files invalidate the closure check.

With `--verify-github`, the verifier additionally queries the artifact ID in the
recorded repository, checks artifact name/run/head SHA and expiry, downloads the
official artifact ZIP, verifies GitHub's published SHA-256 digest, rejects unsafe
archive paths before extraction, and requires the official extracted all-file
manifest to match the reviewed directory and sign-off. Artifact downloads are
bounded to 128 MiB. Review timestamps cannot be future-dated, and online
verification also requires the review to occur on or after GitHub created the
artifact.
