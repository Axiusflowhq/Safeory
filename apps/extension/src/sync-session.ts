import type {
  EncryptedVaultItemV1,
  VaultSyncSession,
} from "@safeory/contracts";

import type { SerializedMutationRunner } from "./mutation";

export interface ExtensionWasmSyncVault {
  verifyMasterPassphrase(passphrase: string): void;
  exportRemoteAccountRootWrapJson(
    passphrase: string,
    accountSecretCode: string,
    accountId: string,
  ): string;
  getEncryptedItemJson(id: string): string | null;
  listEncryptedItemIdsJson(): string;
  encryptedItemIsTombstone(id: string): boolean;
  applyEncryptedItemJson(nextJson: string, expectedJson?: string): void;
}

export interface ExtensionVaultSyncSession extends VaultSyncSession {
  verifyMasterPassphrase(passphrase: string): Promise<void>;
  exportRemoteAccountRootWrap(
    passphrase: string,
    accountSecretCode: string,
    accountId: string,
  ): Promise<string>;
}

/** Bind opaque sync reads and remote CAS writes to extension snapshot durability. */
export function createExtensionVaultSyncSession<State extends ExtensionWasmSyncVault>(
  mutations: SerializedMutationRunner<State>,
): ExtensionVaultSyncSession {
  return {
    verifyMasterPassphrase: (passphrase) =>
      mutations.access((current) => current.verifyMasterPassphrase(passphrase)),
    exportRemoteAccountRootWrap: (passphrase, accountSecretCode, accountId) =>
      mutations.access((current) =>
        current.exportRemoteAccountRootWrapJson(
          passphrase,
          accountSecretCode,
          accountId,
        ),
      ),
    listEncryptedItemIdsForSync: () =>
      mutations.access((current) =>
        JSON.parse(current.listEncryptedItemIdsJson()) as string[],
      ),
    loadEncryptedItemForSync: (objectId) =>
      mutations.access((current) => {
        const encoded = current.getEncryptedItemJson(objectId);
        return encoded === null ? null : JSON.parse(encoded) as EncryptedVaultItemV1;
      }),
    encryptedItemIsTombstoneForSync: (objectId) =>
      mutations.access((current) => current.encryptedItemIsTombstone(objectId)),
    applyRemoteEncryptedItemForSync: (item, expectedLocal) =>
      mutations((current) =>
        current.applyEncryptedItemJson(
          JSON.stringify(item),
          expectedLocal === null ? undefined : JSON.stringify(expectedLocal),
        ),
      ),
  };
}
