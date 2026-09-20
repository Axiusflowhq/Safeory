import {
  BrowserSyncCredentialStore,
  SyncClient,
  connectSingleOwnerVaultSync,
  resumeSingleOwnerVaultSync,
  type ConnectedSingleOwnerVaultSync,
  type VaultSession,
} from "@safeory/contracts"

import { newId } from "./items"
import {
  browserSyncApiBaseUrl,
  loadBrowserSyncConfiguration,
  saveBrowserSyncConfiguration,
} from "./sync-configuration"
import { browserDeviceKeyStore } from "./vault"

const SYNC_CONFIG_FORMAT = 1

export {
  browserSyncApiBaseUrl,
  clearBrowserSyncConfiguration,
  loadBrowserSyncConfiguration,
  saveBrowserSyncConfiguration,
} from "./sync-configuration"
export type { BrowserSyncConfiguration } from "./sync-configuration"

export async function enrollBrowserVaultSync(
  session: VaultSession,
  registrationToken: string
): Promise<ConnectedSingleOwnerVaultSync> {
  const apiBaseUrl = browserSyncApiBaseUrl()
  const registration = await browserDeviceKeyStore.createIdentity(newId())
  let accountCreated = false
  try {
    const credentials = await SyncClient.createAccount(
      apiBaseUrl,
      registrationToken,
      registration
    )
    accountCreated = true
    saveBrowserSyncConfiguration({
      format: SYNC_CONFIG_FORMAT,
      apiBaseUrl,
      accountId: credentials.account_id,
      deviceId: credentials.device_id,
    })
    const credentialStore = new BrowserSyncCredentialStore()
    await credentialStore.save(apiBaseUrl, credentials)
    const client = await SyncClient.connect(
      apiBaseUrl,
      credentials.account_id,
      credentials.device_token,
      { deviceId: credentials.device_id }
    )
    return await connectSingleOwnerVaultSync(client, apiBaseUrl, session)
  } catch (error) {
    if (!accountCreated) {
      await browserDeviceKeyStore.deleteIdentity(registration.device_id).catch(() => undefined)
    }
    throw error
  }
}

export async function resumeBrowserVaultSync(
  session: VaultSession
): Promise<ConnectedSingleOwnerVaultSync | null> {
  const configuration = loadBrowserSyncConfiguration()
  if (configuration === null) return null
  const connected = await resumeSingleOwnerVaultSync(
    configuration.apiBaseUrl,
    configuration.accountId,
    session
  )
  if (connected === null) {
    throw new Error("This browser no longer has the wrapped credential for its saved sync account.")
  }
  if (connected.client.deviceId !== configuration.deviceId) {
    throw new Error("The saved sync connection changed its browser device identity.")
  }
  return connected
}
