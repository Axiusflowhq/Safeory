# Qualified foundation license review checklist

This checklist is a handoff for a qualified license reviewer. It does **not**
record legal approval by itself and does not replace review of the generated
provenance bundle.

## Review scope

- Safeory foundation SDK input:
  `7fd530e4852639d7391d062760891631ee9c15c1`
  (`https://github.com/bitwarden/sdk-internal.git`).
- Safeory foundation server input:
  `6fcd3b71f5f2eb0881dd4a3b587fa8afe5957da1`
  (`https://github.com/bitwarden/server.git`).
- Bitwarden clients repository is reference-only for Phase 0. No Bitwarden
  frontend/client application source is selected for production import.
- Restricted `bitwarden_license/**` source and
  `@bitwarden/commercial-sdk-internal` are excluded by fail-closed proof checks.
- Review the `safeory-foundation-provenance` CI artifact generated from the exact
  commit being approved. Do not substitute an older artifact.

## Required artifact checks

- [ ] `generation-summary.json` matches the pinned SDK/server commits above.
- [ ] `source-manifests/` match the retained source hashes and client manifest is
      empty.
- [ ] `restricted-removals.json` shows the expected restricted source/dependency
      cleanup.
- [ ] `sbom/sdk.cdx.json` and `sbom/server.cdx.json` are present and validated.
- [ ] `license-inventory.json` is reviewed together with
      `LEGAL_REVIEW_SUMMARY.md`.
- [ ] `nuget-license-review-evidence.json` matches the tracked review evidence and
      is treated as evidence only, not as an automatic legal determination.
- [ ] Repository-level files under `licenses/sdk/` and `licenses/server/` are
      reviewed, including GPL/AGPL, Bitwarden-specific license/FAQ, disclaimer,
      and trademark materials.
- [ ] `THIRD_PARTY_NOTICES.md` is reviewed for distribution obligations.

## Unresolved NuGet metadata requiring an explicit determination

The package metadata for these exact versions omits standard NuGet license
fields. Safeory intentionally keeps their generated inventory status as
`UNKNOWN` until qualified review:

- [ ] `AspNetCoreRateLimit@5.0.0` — upstream review evidence points to MIT text at
      repository commit `4a7b74e0bc0b6678190dfe4388f6079e44eafee9`,
      `LICENSE.md`, SHA-256
      `03a4322bc1f9e2ee5fd1711ff728fc8f13cdf408992be942c46e9290fed81ef3`.
- [ ] `AspNetCoreRateLimit.Redis@2.0.0` — same upstream repository/commit/license
      evidence as the package above.
- [ ] `Braintree@5.36.0` — upstream `5.36.0` release resolves to commit
      `8d310daad99279661680f49e7dfdfe14331786fb`; `LICENSE` is MIT text with
      SHA-256
      `6f33a91d81f1d0dd8293859462f77ed2a28416847a3de15da89ef7eabf6ae102`.

For each entry, record whether the upstream evidence is sufficient to resolve the
package for Safeory's intended distribution model and what notice/attribution
obligations apply.

## Review-sensitive dependency expressions

The generated legal summary must enumerate the current technically sensitive
set. The completed Phase 0 inventory contained these categories and they require
explicit reviewer attention even when an alternative permissive license may be
available:

- [ ] `GPL-3.0-only` Bitwarden Server SDK packages.
- [ ] `LGPL-3.0-or-later` (`ansi_colours`).
- [ ] `r-efi` expressions offering `MIT OR Apache-2.0 OR LGPL-2.1-or-later`.
- [ ] `AdaptiveCards` package metadata pointing to `EULA-Windows.txt`.
- [ ] Any additional `UNKNOWN`, GPL, LGPL, EULA, custom, or non-standard entry
      appearing in the artifact being approved.

## Distribution-model questions for counsel/reviewer

- [ ] Confirm obligations for distributing Safeory desktop/browser/client
      binaries that include or link retained SDK dependencies.
- [ ] Confirm obligations for distributing or operating the retained server
      foundation, including AGPL/GPL and Bitwarden-specific terms.
- [ ] Confirm whether any source-offer, source-availability, attribution, notice,
      or modification-disclosure requirements apply to Safeory's planned delivery
      model.
- [ ] Confirm trademark/name/logo restrictions relevant to retained notices and
      product presentation.
- [ ] Confirm whether the planned removal of commercial/enterprise code changes
      any obligations or required notices.
- [ ] Record any conditions that must be implemented before public distribution.

## Sign-off record

Complete this section only after qualified review of the exact generated artifact.

- Reviewer / organization:
- Review date:
- Safeory commit reviewed:
- GitHub Actions run ID:
- `safeory-foundation-provenance` artifact ID/hash:
- Conclusion: `approved` / `approved with conditions` / `blocking issue`
- Conditions or blockers:
- Required notice/source/distribution actions:
- Follow-up review trigger (for example upstream version/import-boundary change):

The Phase 0 legal/provenance gate in `PLAN.md` may be checked only when this
review concludes there is no blocking issue and all required conditions for the
current distribution stage are recorded.
