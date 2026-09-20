import assert from "node:assert/strict"
import test from "node:test"

import {
  CURRENT_SYNC_COMPATIBILITY,
  SyncCompatibilityError,
  fetchSyncCompatibility,
  negotiateSyncCompatibility,
  parseSyncCompatibilityAdvertisement,
} from "../src/sync-compatibility"

test("current client contract negotiates the current API advertisement", () => {
  assert.deepEqual(
    negotiateSyncCompatibility(
      CURRENT_SYNC_COMPATIBILITY,
      parseSyncCompatibilityAdvertisement(CURRENT_SYNC_COMPATIBILITY),
    ),
    {
      protocol_version: 1,
      object_header_version: 1,
      envelope_version: 1,
    },
  )
})

test("negotiation selects the highest common independent versions", () => {
  assert.deepEqual(
    negotiateSyncCompatibility(
      {
        format_version: 1,
        protocol_versions: { minimum: 1, maximum: 3 },
        object_header_versions: { minimum: 1, maximum: 2 },
        envelope_versions: { minimum: 1, maximum: 4 },
      },
      {
        format_version: 1,
        protocol_versions: { minimum: 2, maximum: 4 },
        object_header_versions: { minimum: 1, maximum: 1 },
        envelope_versions: { minimum: 2, maximum: 3 },
      },
    ),
    {
      protocol_version: 3,
      object_header_version: 1,
      envelope_version: 3,
    },
  )
})

test("unknown fields, malformed ranges, and incompatible versions fail closed", () => {
  assert.throws(
    () =>
      parseSyncCompatibilityAdvertisement({
        ...CURRENT_SYNC_COMPATIBILITY,
        future_required_field: true,
      }),
    (error: unknown) =>
      error instanceof SyncCompatibilityError && error.code === "invalid_response",
  )
  assert.throws(
    () =>
      parseSyncCompatibilityAdvertisement({
        ...CURRENT_SYNC_COMPATIBILITY,
        protocol_versions: { minimum: 2, maximum: 1 },
      }),
    (error: unknown) =>
      error instanceof SyncCompatibilityError && error.code === "invalid_range",
  )
  assert.throws(
    () =>
      negotiateSyncCompatibility(CURRENT_SYNC_COMPATIBILITY, {
        ...CURRENT_SYNC_COMPATIBILITY,
        protocol_versions: { minimum: 2, maximum: 2 },
      }),
    (error: unknown) =>
      error instanceof SyncCompatibilityError && error.code === "no_common_version",
  )
})

test("fetch uses the bounded public endpoint and refuses oversized responses", async () => {
  let requestedUrl = ""
  const fetcher: typeof fetch = async (input) => {
    requestedUrl = String(input)
    return new Response(JSON.stringify(CURRENT_SYNC_COMPATIBILITY), {
      status: 200,
      headers: { "content-type": "application/json" },
    })
  }
  assert.deepEqual(
    await fetchSyncCompatibility("https://sync.example.test/api", { fetcher }),
    {
      protocol_version: 1,
      object_header_version: 1,
      envelope_version: 1,
    },
  )
  assert.equal(requestedUrl, "https://sync.example.test/api/v1/compatibility")

  const oversizedFetcher: typeof fetch = async () =>
    new Response("{}", {
      status: 200,
      headers: { "content-length": "9000" },
    })
  await assert.rejects(
    fetchSyncCompatibility("https://sync.example.test", {
      fetcher: oversizedFetcher,
    }),
    (error: unknown) =>
      error instanceof SyncCompatibilityError && error.code === "invalid_response",
  )
})
