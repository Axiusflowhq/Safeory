const SYNC_CONFIG_KEY = "safeory:sync-connection:v1"
const SYNC_CONFIG_FORMAT = 1
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const NIL_UUID = "00000000-0000-0000-0000-000000000000"

export interface BrowserSyncConfiguration {
  format: number
  apiBaseUrl: string
  accountId: string
  deviceId: string
}

interface StorageLike {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
}

export function browserSyncApiBaseUrl(locationValue: Pick<Location, "origin"> = location): string {
  return normalizeApiBaseUrl(new URL("/api/", locationValue.origin).href)
}

export function loadBrowserSyncConfiguration(
  storage: StorageLike = localStorage
): BrowserSyncConfiguration | null {
  const encoded = storage.getItem(SYNC_CONFIG_KEY)
  if (encoded === null) return null
  try {
    return parseConfiguration(JSON.parse(encoded) as unknown)
  } catch {
    throw new Error("The saved sync connection is invalid.")
  }
}

export function saveBrowserSyncConfiguration(
  value: BrowserSyncConfiguration,
  storage: StorageLike = localStorage
): BrowserSyncConfiguration {
  const configuration = parseConfiguration(value)
  storage.setItem(SYNC_CONFIG_KEY, JSON.stringify(configuration))
  return configuration
}

export function clearBrowserSyncConfiguration(storage: StorageLike = localStorage): void {
  storage.removeItem(SYNC_CONFIG_KEY)
}

function parseConfiguration(value: unknown): BrowserSyncConfiguration {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("invalid sync configuration")
  }
  const record = value as Record<string, unknown>
  const keys = Object.keys(record)
  if (
    keys.length !== 4 ||
    !["format", "apiBaseUrl", "accountId", "deviceId"].every((key) =>
      Object.hasOwn(record, key)
    ) ||
    record.format !== SYNC_CONFIG_FORMAT ||
    typeof record.apiBaseUrl !== "string"
  ) {
    throw new Error("invalid sync configuration")
  }
  return {
    format: SYNC_CONFIG_FORMAT,
    apiBaseUrl: normalizeApiBaseUrl(record.apiBaseUrl),
    accountId: uuid(record.accountId, "account ID"),
    deviceId: uuid(record.deviceId, "device ID"),
  }
}

function normalizeApiBaseUrl(value: string): string {
  let url: URL
  try {
    url = new URL(value.endsWith("/") ? value : `${value}/`)
  } catch {
    throw new Error("The sync API URL is invalid.")
  }
  const local =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "[::1]"
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) {
    throw new Error("Device credentials require HTTPS except on the local development host.")
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("The sync API URL contains unsupported components.")
  }
  return url.href
}

function uuid(value: unknown, label: string): string {
  if (typeof value !== "string" || !UUID.test(value) || value.toLowerCase() === NIL_UUID) {
    throw new Error(`The saved sync ${label} is invalid.`)
  }
  return value.toLowerCase()
}
