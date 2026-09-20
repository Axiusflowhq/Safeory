import { WasmDeviceIdentity, WasmVault } from "vault-wasm";
import {
  BrowserDeviceKeyStore,
  BrowserSyncCredentialStore,
  DurableSyncOutbox,
  SyncClient,
  connectSingleOwnerVaultSync,
  prepareAccountBootstrapMutation,
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
import type { ExtensionVaultSyncSession } from "./sync-session";

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
  session: ExtensionVaultSyncSession,
  enrollment: {
    registrationToken: string;
    masterPassphrase: string;
    accountSecretCode: string;
  },
  apiBaseUrlValue: string,
  signal?: AbortSignal,
): Promise<ConnectedSingleOwnerVaultSync> {
  await session.verifyMasterPassphrase(enrollment.masterPassphrase);
  if (!WasmVault.validateAccountSecret(enrollment.accountSecretCode)) {
    throw new Error("The Account Secret is invalid.");
  }
  const apiBaseUrl = normalizeExtensionSyncApiBaseUrl(apiBaseUrlValue);
  const registration = await deviceKeyStore.createIdentity(crypto.randomUUID());
  const credentialStore = new BrowserSyncCredentialStore();
  let createdAccountId: string | null = null;
  let configurationSaved = false;
  try {
    const credentials = await SyncClient.createAccount(
      apiBaseUrl,
      enrollment.registrationToken,
      registration,
      signal === undefined ? {} : { signal },
    );
    createdAccountId = credentials.account_id;
    const client = await SyncClient.connect(
      apiBaseUrl,
      credentials.account_id,
      credentials.device_token,
      {
        deviceId: credentials.device_id,
        ...(signal === undefined ? {} : { signal }),
      },
    );
    const wrappedRoot = await session.exportRemoteAccountRootWrap(
      enrollment.masterPassphrase,
      enrollment.accountSecretCode,
      credentials.account_id,
    );
    const prepared = await prepareAccountBootstrapMutation(
      wrappedRoot,
      credentials.account_id,
      crypto.randomUUID(),
      null,
    );
    const outbox = new DurableSyncOutbox(credentials.account_id);
    if (!(await outbox.enqueue(prepared.mutation, prepared.ciphertext))) {
      throw new Error("The account bootstrap publication operation already exists.");
    }
    await credentialStore.save(apiBaseUrl, credentials);
    await saveExtensionSyncConfiguration({
      format: SYNC_CONFIG_FORMAT,
      apiBaseUrl,
      accountId: credentials.account_id,
      deviceId: credentials.device_id,
    });
    configurationSaved = true;
    await outbox.flush(
      client,
      signal === undefined ? {} : { signal },
    );
    return await connectSingleOwnerVaultSync(
      client,
      apiBaseUrl,
      session,
      {
        runtimeDependencies: { outbox },
        ...(signal === undefined ? {} : { signal }),
      },
    );
  } catch (error) {
    if (!configurationSaved) {
      if (createdAccountId !== null) {
        await credentialStore.delete(apiBaseUrl, createdAccountId).catch(() => undefined);
      }
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
