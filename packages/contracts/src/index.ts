export {
  saveSnapshot,
  loadSnapshot,
  clearSnapshot,
  saveAttachmentImport,
  saveAttachmentDelete,
  saveItemPurge,
  loadAttachmentManifest,
  loadAttachmentChunk,
  loadAllAttachmentState,
  loadVaultBackupState,
  replaceVaultFromBackup,
} from "./persistence";
export type {
  LoadedAttachmentManifest,
  PersistedAttachmentManifest,
  PersistedAttachmentChunk,
  PersistedAttachmentState,
  PersistedVaultBackupState,
  ItemPurgeAttachmentWrite,
} from "./persistence";
export { VaultDurabilityError, VaultSession } from "./session";
export type {
  WasmVaultLike,
  WasmStatics,
  VaultFactory,
  ListedItem,
  DeadlineSummary,
  EmergencyCard,
  EmergencyContact,
  TrustedDevice,
  TrustedPrincipal,
  PairingChallengeV1,
  PairingProofV1,
  AttachmentSummary,
  TrashedItemSummary,
} from "./session";
export { BrowserDeviceKeyStore } from "./device-keys";
export type {
  DeviceIdentityFactory,
  DeviceRegistrationV1,
  WasmDeviceIdentityLike,
} from "./device-keys";
export {
  CURRENT_SYNC_COMPATIBILITY,
  SyncCompatibilityError,
  fetchSyncCompatibility,
  negotiateSyncCompatibility,
  parseSyncCompatibilityAdvertisement,
} from "./sync-compatibility";
export type {
  CompatibilityAdvertisementV1,
  NegotiatedCompatibility,
  VersionRangeV1,
} from "./sync-compatibility";
