const COMPATIBILITY_FORMAT_VERSION = 1
const MAX_VERSION = 65_535
const MAX_COMPATIBILITY_RESPONSE_CHARS = 8_192

export interface VersionRangeV1 {
  minimum: number
  maximum: number
}

export interface CompatibilityAdvertisementV1 {
  format_version: number
  protocol_versions: VersionRangeV1
  object_header_versions: VersionRangeV1
  envelope_versions: VersionRangeV1
}

export interface NegotiatedCompatibility {
  protocol_version: number
  object_header_version: number
  envelope_version: number
}

export const CURRENT_SYNC_COMPATIBILITY: CompatibilityAdvertisementV1 = {
  format_version: COMPATIBILITY_FORMAT_VERSION,
  protocol_versions: { minimum: 1, maximum: 1 },
  object_header_versions: { minimum: 1, maximum: 1 },
  envelope_versions: { minimum: 1, maximum: 1 },
}

export class SyncCompatibilityError extends Error {
  constructor(
    readonly code:
      | "invalid_response"
      | "unsupported_format"
      | "invalid_range"
      | "no_common_version"
      | "request_failed",
    message: string,
  ) {
    super(message)
    this.name = "SyncCompatibilityError"
  }
}

export function parseSyncCompatibilityAdvertisement(
  value: unknown,
): CompatibilityAdvertisementV1 {
  const record = exactRecord(value, [
    "format_version",
    "protocol_versions",
    "object_header_versions",
    "envelope_versions",
  ])
  const formatVersion = version(record.format_version, "format_version")
  if (formatVersion !== COMPATIBILITY_FORMAT_VERSION) {
    throw new SyncCompatibilityError(
      "unsupported_format",
      "The server uses an unsupported compatibility format.",
    )
  }

  return {
    format_version: formatVersion,
    protocol_versions: versionRange(record.protocol_versions),
    object_header_versions: versionRange(record.object_header_versions),
    envelope_versions: versionRange(record.envelope_versions),
  }
}

export function negotiateSyncCompatibility(
  local: CompatibilityAdvertisementV1,
  remote: CompatibilityAdvertisementV1,
): NegotiatedCompatibility {
  const validLocal = parseSyncCompatibilityAdvertisement(local)
  const validRemote = parseSyncCompatibilityAdvertisement(remote)
  return {
    protocol_version: highestCommon(
      validLocal.protocol_versions,
      validRemote.protocol_versions,
    ),
    object_header_version: highestCommon(
      validLocal.object_header_versions,
      validRemote.object_header_versions,
    ),
    envelope_version: highestCommon(
      validLocal.envelope_versions,
      validRemote.envelope_versions,
    ),
  }
}

export async function fetchSyncCompatibility(
  apiBaseUrl: string,
  options: {
    fetcher?: typeof fetch
    signal?: AbortSignal
  } = {},
): Promise<NegotiatedCompatibility> {
  const fetcher = options.fetcher ?? globalThis.fetch
  const base = apiBaseUrl.endsWith("/") ? apiBaseUrl : `${apiBaseUrl}/`
  let endpoint: URL
  try {
    endpoint = new URL("v1/compatibility", base)
  } catch {
    throw new SyncCompatibilityError("request_failed", "The API URL is invalid.")
  }

  let response: Response
  try {
    const request: RequestInit = {
      method: "GET",
      headers: { Accept: "application/json" },
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
    }
    if (options.signal !== undefined) {
      request.signal = options.signal
    }
    response = await fetcher(endpoint, request)
  } catch {
    throw new SyncCompatibilityError(
      "request_failed",
      "The sync compatibility request failed.",
    )
  }
  if (!response.ok) {
    throw new SyncCompatibilityError(
      "request_failed",
      "The sync compatibility endpoint returned an error.",
    )
  }
  const declaredLength = response.headers.get("content-length")
  if (
    declaredLength !== null &&
    (!/^\d+$/.test(declaredLength) ||
      Number(declaredLength) > MAX_COMPATIBILITY_RESPONSE_CHARS)
  ) {
    throw new SyncCompatibilityError(
      "invalid_response",
      "The sync compatibility response is too large.",
    )
  }
  const text = await response.text()
  if (text.length > MAX_COMPATIBILITY_RESPONSE_CHARS) {
    throw new SyncCompatibilityError(
      "invalid_response",
      "The sync compatibility response is too large.",
    )
  }
  let value: unknown
  try {
    value = JSON.parse(text) as unknown
  } catch {
    throw new SyncCompatibilityError(
      "invalid_response",
      "The sync compatibility response is not valid JSON.",
    )
  }
  return negotiateSyncCompatibility(
    CURRENT_SYNC_COMPATIBILITY,
    parseSyncCompatibilityAdvertisement(value),
  )
}

function versionRange(value: unknown): VersionRangeV1 {
  const record = exactRecord(value, ["minimum", "maximum"])
  const minimum = version(record.minimum, "minimum")
  const maximum = version(record.maximum, "maximum")
  if (minimum === 0 || maximum < minimum) {
    throw new SyncCompatibilityError(
      "invalid_range",
      "A compatibility version range is empty or reversed.",
    )
  }
  return { minimum, maximum }
}

function version(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > MAX_VERSION) {
    throw new SyncCompatibilityError(
      "invalid_response",
      `${label} is not a supported integer.`,
    )
  }
  return value as number
}

function highestCommon(left: VersionRangeV1, right: VersionRangeV1): number {
  const minimum = Math.max(left.minimum, right.minimum)
  const maximum = Math.min(left.maximum, right.maximum)
  if (maximum < minimum) {
    throw new SyncCompatibilityError(
      "no_common_version",
      "The client and server have no common sync version.",
    )
  }
  return maximum
}

function exactRecord(
  value: unknown,
  expectedKeys: readonly string[],
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new SyncCompatibilityError(
      "invalid_response",
      "The sync compatibility response has an invalid shape.",
    )
  }
  const record = value as Record<string, unknown>
  const keys = Object.keys(record)
  if (
    keys.length !== expectedKeys.length ||
    expectedKeys.some((key) => !Object.hasOwn(record, key))
  ) {
    throw new SyncCompatibilityError(
      "invalid_response",
      "The sync compatibility response has unknown or missing fields.",
    )
  }
  return record
}
