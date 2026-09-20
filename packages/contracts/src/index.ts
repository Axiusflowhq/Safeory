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
export {
  OPAQUE_OBJECT_CLASSES,
  SyncClient,
  SyncClientError,
  normalizeSyncApiBaseUrl,
  parseOpaqueMutation,
  parseOpaqueObjectHeader,
  parseSyncObjectMetadata,
  parseSyncObjectPage,
  verifyOpaqueCiphertext,
} from "./sync-client";
export {
  decodePulledVaultItem,
  parseEncryptedVaultItem,
  prepareVaultItemMutation,
  reconcilePulledVaultItem,
} from "./sync-vault-item";
export {
  DurableVaultItemAcceptor,
  IndexedDbVaultItemSyncStateStore,
} from "./sync-vault-acceptance";
export {
  BrowserSingleOwnerSyncBootstrap,
  IndexedDbSingleOwnerSyncBootstrapStore,
  createSingleOwnerMigration,
} from "./sync-bootstrap";
export type {
  HouseholdTopologyPublisher,
  SingleOwnerSyncBootstrapState,
  SingleOwnerSyncBootstrapStore,
  SyncBootstrapPublication,
} from "./sync-bootstrap";
export type {
  ApplyRemoteEncryptedItem,
  LoadLocalEncryptedItem,
  VaultItemAcceptanceResult,
  VaultItemConflictCandidate,
  VaultItemSyncState,
  VaultItemSyncStateStore,
} from "./sync-vault-acceptance";
export type {
  DecodedPulledVaultItem,
  EncryptedVaultItemV1,
  PreparedVaultItemMutation,
  VaultItemReconciliation,
} from "./sync-vault-item";
export {
  DurableSyncOutbox,
  IndexedDbSyncOutboxStore,
} from "./sync-queue";
export type {
  QueuedOpaqueMutation,
  SyncFlushResult,
  SyncOutboxStore,
} from "./sync-queue";
export { DurableSyncCoordinator } from "./sync-coordinator";
export type {
  SyncCycleOptions,
  SyncCycleResult,
} from "./sync-coordinator";
export {
  BrowserSyncCredentialStore,
  IndexedDbSyncCredentialStorage,
} from "./sync-credentials";
export type {
  StoredSyncCredentialV1,
  SyncCredentialStorageBackend,
} from "./sync-credentials";
export {
  DurableSyncPuller,
  IndexedDbSyncCursorStore,
} from "./sync-pull";
export {
  MEMBERSHIP_ROLES,
  MEMBERSHIP_STATES,
  SPACE_ACCESS_LEVELS,
  SPACE_KINDS,
  TOPOLOGY_ACTIONS,
  canDeviceAccessScope,
  parseHouseholdTopology,
  parseSingleOwnerMigration,
} from "./sync-domain";
export type {
  AccountV1,
  HouseholdTopologyV1,
  HouseholdV1,
  MembershipRoleV1,
  MembershipStateV1,
  MembershipV1,
  ObjectSpaceAssignmentV1,
  SingleOwnerMigrationV1,
  SpaceAccessV1,
  SpaceKindV1,
  SpaceMemberV1,
  SpaceV1,
  TopologyActionV1,
} from "./sync-domain";
export type {
  AcceptPulledObject,
  PulledOpaqueObject,
  SyncCursorStore,
  SyncPullResult,
} from "./sync-pull";
export type {
  OpaqueMutationV1,
  DeviceCredentialsV1,
  DeviceInventoryEntryV1,
  DeviceInventoryV1,
  OpaqueObjectClassV1,
  OpaqueObjectHeaderV1,
  ObjectScopeV1,
  SyncObjectMetadataV1,
  SyncObjectPageV1,
  WritePreconditionV1,
} from "./sync-client";
