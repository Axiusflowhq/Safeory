const SYNC_CONFIG_KEY = "safeory.sync.connection.v1";
const SYNC_CONFIG_FORMAT = 1;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NIL_UUID = "00000000-0000-0000-0000-000000000000";

export const DEFAULT_EXTENSION_SYNC_API_URL = "http://127.0.0.1:8080/api/";

export interface ExtensionSyncConfiguration {
  format: number;
  apiBaseUrl: string;
  accountId: string;
  deviceId: string;
}

export interface ExtensionStorageArea {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(key: string): Promise<void>;
}

export async function loadExtensionSyncConfiguration(
  storage: ExtensionStorageArea = chrome.storage.local,
): Promise<ExtensionSyncConfiguration | null> {
  const stored = (await storage.get(SYNC_CONFIG_KEY))[SYNC_CONFIG_KEY];
  if (stored === undefined) return null;
  try {
    return parseExtensionSyncConfiguration(stored);
  } catch {
    throw new Error("The saved extension sync connection is invalid.");
  }
}

export async function saveExtensionSyncConfiguration(
  value: ExtensionSyncConfiguration,
  storage: ExtensionStorageArea = chrome.storage.local,
): Promise<ExtensionSyncConfiguration> {
  const configuration = parseExtensionSyncConfiguration(value);
  await storage.set({ [SYNC_CONFIG_KEY]: configuration });
  return configuration;
}

export async function clearExtensionSyncConfiguration(
  storage: ExtensionStorageArea = chrome.storage.local,
): Promise<void> {
  await storage.remove(SYNC_CONFIG_KEY);
}

export function normalizeExtensionSyncApiBaseUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value.endsWith("/") ? value : `${value}/`);
  } catch {
    throw new Error("The sync API URL is invalid.");
  }
  const local =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) {
    throw new Error("Device credentials require HTTPS except on the local development host.");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("The sync API URL contains unsupported components.");
  }
  return url.href;
}

export function parseExtensionSyncConfiguration(value: unknown): ExtensionSyncConfiguration {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("invalid sync configuration");
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (
    keys.length !== 4 ||
    !["format", "apiBaseUrl", "accountId", "deviceId"].every((key) =>
      Object.hasOwn(record, key),
    ) ||
    record.format !== SYNC_CONFIG_FORMAT ||
    typeof record.apiBaseUrl !== "string"
  ) {
    throw new Error("invalid sync configuration");
  }
  return {
    format: SYNC_CONFIG_FORMAT,
    apiBaseUrl: normalizeExtensionSyncApiBaseUrl(record.apiBaseUrl),
    accountId: uuid(record.accountId, "account ID"),
    deviceId: uuid(record.deviceId, "device ID"),
  };
}

function uuid(value: unknown, label: string): string {
  if (typeof value !== "string" || !UUID.test(value) || value.toLowerCase() === NIL_UUID) {
    throw new Error(`The saved sync ${label} is invalid.`);
  }
  return value.toLowerCase();
}
