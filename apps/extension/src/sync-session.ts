import type {
  EncryptedVaultItemV1,
  VaultSyncSession,
} from "@safeory/contracts";

import type { SerializedMutationRunner } from "./mutation";

export interface ExtensionWasmSyncVault {
  getEncryptedItemJson(id: string): string | null;
  listEncryptedItemIdsJson(): string;
  encryptedItemIsTombstone(id: string): boolean;
  applyEncryptedItemJson(nextJson: string, expectedJson?: string): void;
}

/** Bind opaque sync reads and remote CAS writes to extension snapshot durability. */
export function createExtensionVaultSyncSession<State extends ExtensionWasmSyncVault>(
  mutations: SerializedMutationRunner<State>,
): VaultSyncSession {
  return {
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
