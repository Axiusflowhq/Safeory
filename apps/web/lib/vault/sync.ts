import {
  BrowserDeviceEnrollmentCoordinator,
  BrowserSyncCredentialStore,
  DurableSyncOutbox,
  SyncClient,
  connectSingleOwnerVaultSync,
  prepareAccountBootstrapMutation,
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
import { browserDeviceKeyStore, wasmStatics } from "./vault"

const SYNC_CONFIG_FORMAT = 1
const credentialStore = new BrowserSyncCredentialStore()
const deviceEnrollmentCoordinator = new BrowserDeviceEnrollmentCoordinator(
  browserDeviceKeyStore,
  credentialStore
)

export {
  browserSyncApiBaseUrl,
  clearBrowserSyncConfiguration,
  loadBrowserSyncConfiguration,
  saveBrowserSyncConfiguration,
} from "./sync-configuration"
export type { BrowserSyncConfiguration } from "./sync-configuration"

export interface BrowserSyncEnrollment {
  registrationToken: string
  masterPassphrase: string
  accountSecretCode: string
}

export async function enrollBrowserVaultSync(
  session: VaultSession,
  enrollment: BrowserSyncEnrollment
): Promise<ConnectedSingleOwnerVaultSync> {
  session.verifyMasterPassphrase(enrollment.masterPassphrase)
  if (!wasmStatics.validateAccountSecret(enrollment.accountSecretCode)) {
    throw new Error("The Account Secret is invalid.")
  }
  const apiBaseUrl = browserSyncApiBaseUrl()
  const registration = await browserDeviceKeyStore.createIdentity(newId())
  let createdAccountId: string | null = null
  let configurationSaved = false
  try {
    const credentials = await SyncClient.createAccount(
      apiBaseUrl,
      enrollment.registrationToken,
      registration
    )
    createdAccountId = credentials.account_id
    const client = await SyncClient.connect(
      apiBaseUrl,
      credentials.account_id,
      credentials.device_token,
      { deviceId: credentials.device_id }
    )
    const wrappedRoot = session.exportRemoteAccountRootWrap(
      enrollment.masterPassphrase,
      enrollment.accountSecretCode,
      credentials.account_id
    )
    const prepared = await prepareAccountBootstrapMutation(
      wrappedRoot,
      credentials.account_id,
      newId(),
      null
    )
    const outbox = new DurableSyncOutbox(credentials.account_id)
    if (!(await outbox.enqueue(prepared.mutation, prepared.ciphertext))) {
      throw new Error("The account bootstrap publication operation already exists.")
    }
    await credentialStore.save(apiBaseUrl, credentials)
    saveBrowserSyncConfiguration({
      format: SYNC_CONFIG_FORMAT,
      apiBaseUrl,
      accountId: credentials.account_id,
      deviceId: credentials.device_id,
    })
    configurationSaved = true
    await outbox.flush(client)
    return await connectSingleOwnerVaultSync(client, apiBaseUrl, session, {
      runtimeDependencies: { outbox },
    })
  } catch (error) {
    if (!configurationSaved) {
      if (createdAccountId !== null) {
        await credentialStore.delete(apiBaseUrl, createdAccountId).catch(() => undefined)
      }
      await browserDeviceKeyStore.deleteIdentity(registration.device_id).catch(() => undefined)
    }
    throw error
  }
}

export async function approveBrowserSyncDevice(
  connected: ConnectedSingleOwnerVaultSync,
  requestJson: string
): Promise<string> {
  const approverDeviceId = connected.client.deviceId
  if (approverDeviceId === null) {
    throw new Error("The active sync connection is missing its device identity.")
  }
  const drafts = await deviceEnrollmentCoordinator.listApprovalDrafts(
    connected.client.apiBaseUrl,
    connected.client.accountId
  )
  const existing = drafts.find((draft) => draft.request_json === requestJson)
  const prepared = existing === undefined
    ? await deviceEnrollmentCoordinator.prepareApproval(
        connected.client,
        approverDeviceId,
        requestJson
      )
    : await deviceEnrollmentCoordinator.resumeApproval(
        connected.client,
        existing.request_id
      )
  return prepared.grant_json
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
