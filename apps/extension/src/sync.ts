import { WasmDeviceIdentity } from "vault-wasm";
import {
  BrowserDeviceKeyStore,
  BrowserSyncCredentialStore,
  SyncClient,
  connectSingleOwnerVaultSync,
  resumeSingleOwnerVaultSync,
  type ConnectedSingleOwnerVaultSync,
  type VaultSyncSession,
  type WasmDeviceIdentityLike,
} from "@safeory/contracts";

import {
  loadExtensionSyncConfiguration,
  normalizeExtensionSyncApiBaseUrl,
  saveExtensionSyncConfiguration,
} from "./sync-configuration";

const SYNC_CONFIG_FORMAT = 1;

const deviceKeyStore = new BrowserDeviceKeyStore({
  generate: (deviceId: string) =>
    WasmDeviceIdentity.generate(deviceId) as unknown as WasmDeviceIdentityLike,
  fromPrivateKeyBytes: (deviceId: string, privateKeyBytes: Uint8Array) =>
    WasmDeviceIdentity.fromPrivateKeyBytes(
      deviceId,
      privateKeyBytes,
    ) as unknown as WasmDeviceIdentityLike,
});

export async function enrollExtensionVaultSync(
  session: VaultSyncSession,
  registrationToken: string,
  apiBaseUrlValue: string,
  signal?: AbortSignal,
): Promise<ConnectedSingleOwnerVaultSync> {
  const apiBaseUrl = normalizeExtensionSyncApiBaseUrl(apiBaseUrlValue);
  const registration = await deviceKeyStore.createIdentity(crypto.randomUUID());
  let accountCreated = false;
  try {
    const credentials = await SyncClient.createAccount(
      apiBaseUrl,
      registrationToken,
      registration,
      signal === undefined ? {} : { signal },
    );
    accountCreated = true;
    await saveExtensionSyncConfiguration({
      format: SYNC_CONFIG_FORMAT,
      apiBaseUrl,
      accountId: credentials.account_id,
      deviceId: credentials.device_id,
    });
    const credentialStore = new BrowserSyncCredentialStore();
    await credentialStore.save(apiBaseUrl, credentials);
    const client = await SyncClient.connect(
      apiBaseUrl,
      credentials.account_id,
      credentials.device_token,
      {
        deviceId: credentials.device_id,
        ...(signal === undefined ? {} : { signal }),
      },
    );
    return await connectSingleOwnerVaultSync(
      client,
      apiBaseUrl,
      session,
      signal === undefined ? {} : { signal },
    );
  } catch (error) {
    if (!accountCreated) {
      await deviceKeyStore.deleteIdentity(registration.device_id).catch(() => undefined);
    }
    throw error;
  }
}

export async function resumeExtensionVaultSync(
  session: VaultSyncSession,
  signal?: AbortSignal,
): Promise<ConnectedSingleOwnerVaultSync | null> {
  const configuration = await loadExtensionSyncConfiguration();
  if (configuration === null) return null;
  const connected = await resumeSingleOwnerVaultSync(
    configuration.apiBaseUrl,
    configuration.accountId,
    session,
    signal === undefined ? {} : { signal },
  );
  if (connected === null) {
    throw new Error("This extension no longer has the wrapped credential for its saved sync account.");
  }
  if (connected.client.deviceId !== configuration.deviceId) {
    throw new Error("The saved sync connection changed its extension device identity.");
  }
  return connected;
}
