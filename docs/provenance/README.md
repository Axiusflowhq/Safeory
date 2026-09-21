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
- `licenses/` — upstream repository-level license, disclaimer, FAQ, and trademark
  notice files kept verbatim for review.
- `source-manifests/` — every retained tracked upstream file with its SHA-256
  digest, bound to the pinned commit.
- `restricted-removals.json` — the exact prepared-checkout cleanup diff plus the
  forbidden path/dependency policy.
- `THIRD_PARTY_NOTICES.md` — generated provenance/notices index for the bundle.
- `generation-summary.json` — source/component counts and unresolved-license
  count.

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
