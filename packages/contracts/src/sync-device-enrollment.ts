import { BrowserDeviceKeyStore, type DeviceRegistrationV1 } from "./device-keys"
import {
  SyncClient,
  SyncClientError,
  generateDeviceToken,
  normalizeSyncApiBaseUrl,
  type DeviceCredentialsV1,
  type DeviceEnrollmentV1,
} from "./sync-client"
import { BrowserSyncCredentialStore } from "./sync-credentials"

const DB_NAME = "safeory-device-enrollment-approvals"
const DB_VERSION = 2
const WRAPPING_STORE = "wrapping"
const DRAFT_STORE = "drafts"
const JOIN_REQUEST_STORE = "join-requests"
const WRAPPING_KEY_ID = "device-enrollment-approval-wrap-v1"
const RECORD_FORMAT = 1
const CREDENTIAL_FORMAT = 1
const IV_BYTES = 12
const MAX_PACKAGE_BYTES = 4 * 1024
const MAX_REQUEST_CHARS = 8 * 1024
const MAX_GRANT_CHARS = 16 * 1024
const AAD_DOMAIN = "safeory:browser-device-enrollment-approval:v1"
const ALGORITHM = "x25519-hkdf-sha256+xchacha20poly1305+ed25519"
const TOKEN = /^sfo_dev_v1_[0-9a-f]{64}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

interface EnrollmentRequestContext {
  requestId: string
  accountId: string
  deviceId: string
  encryptionPublicKeyHex: string
  signingPublicKeyHex: string
}

interface EnrollmentGrantContext {
  requestId: string
  accountId: string
  joiningDeviceId: string
  joiningEncryptionPublicKeyHex: string
  joiningSigningPublicKeyHex: string
  approverDeviceId: string
  approverEncryptionPublicKeyHex: string
  approverSigningPublicKeyHex: string
}

export interface StoredDeviceEnrollmentApprovalV1 {
  key: string
  format: number
  apiBaseUrl: string
  accountId: string
  requestId: string
  approverDeviceId: string
  joiningDeviceId: string
  requestJson: string
  grantJson: string
  iv: ArrayBuffer
  ciphertext: ArrayBuffer
}

export interface StoredDeviceEnrollmentJoinRequestV1 {
  key: string
  format: number
  apiBaseUrl: string
  accountId: string
  requestId: string
  joiningDeviceId: string
  requestJson: string
}

export interface DeviceEnrollmentApprovalStorageBackend {
  getOrCreateWrappingKey(): Promise<CryptoKey>
  addDraft(record: StoredDeviceEnrollmentApprovalV1): Promise<void>
  getDraft(key: string): Promise<StoredDeviceEnrollmentApprovalV1 | null>
  listDrafts(): Promise<StoredDeviceEnrollmentApprovalV1[]>
  deleteDraft(key: string): Promise<void>
  addJoinRequest(record: StoredDeviceEnrollmentJoinRequestV1): Promise<void>
  getJoinRequest(key: string): Promise<StoredDeviceEnrollmentJoinRequestV1 | null>
  listJoinRequests(): Promise<StoredDeviceEnrollmentJoinRequestV1[]>
  deleteJoinRequest(key: string): Promise<void>
}

export interface PreparedDeviceEnrollmentApproval {
  enrollment: DeviceEnrollmentV1
  request_json: string
  grant_json: string
}

export interface DeviceEnrollmentApprovalDraft {
  account_id: string
  request_id: string
  approver_device_id: string
  joining_device_id: string
  request_json: string
  grant_json: string
}

export interface DeviceEnrollmentJoinRequest {
  account_id: string
  request_id: string
  joining_device_id: string
  request_json: string
}

export interface AcceptedDeviceEnrollment {
  credentials: DeviceCredentialsV1
  client: SyncClient
}

export class BrowserDeviceEnrollmentCoordinator {
  constructor(
    private readonly deviceKeys: BrowserDeviceKeyStore,
    private readonly credentials: BrowserSyncCredentialStore,
    private readonly storage: DeviceEnrollmentApprovalStorageBackend =
      new IndexedDbDeviceEnrollmentApprovalStorage(),
    private readonly cryptography: Crypto = crypto,
  ) {}

  async createJoinRequest(
    apiBaseUrlValue: string,
    accountIdValue: string,
    joiningDeviceIdValue: string,
  ): Promise<DeviceEnrollmentJoinRequest> {
    const apiBaseUrl = normalizeSyncApiBaseUrl(apiBaseUrlValue)
    const accountId = requireUuid(accountIdValue, "account ID")
    const joiningDeviceId = requireUuid(joiningDeviceIdValue, "joining device ID")
    const requestJson = await this.deviceKeys.createDeviceEnrollmentRequest(
      joiningDeviceId,
      accountId,
    )
    const request = parseRequest(requestJson)
    if (request.accountId !== accountId || request.deviceId !== joiningDeviceId) {
      throw new SyncClientError(
        "invalid_response",
        "The generated enrollment request changed its local identity context.",
      )
    }
    await this.storage.addJoinRequest({
      key: joinRequestKey(apiBaseUrl, accountId, request.requestId),
      format: RECORD_FORMAT,
      apiBaseUrl,
      accountId,
      requestId: request.requestId,
      joiningDeviceId,
      requestJson,
    })
    return joinRequestResponse(request, requestJson)
  }

  async listJoinRequests(
    apiBaseUrlValue: string,
    accountIdValue: string,
  ): Promise<DeviceEnrollmentJoinRequest[]> {
    const apiBaseUrl = normalizeSyncApiBaseUrl(apiBaseUrlValue)
    const accountId = requireUuid(accountIdValue, "account ID")
    return (await this.storage.listJoinRequests())
      .map(validateStoredJoinRequest)
      .filter((record) => record.apiBaseUrl === apiBaseUrl && record.accountId === accountId)
      .map((record) => joinRequestResponse(parseRequest(record.requestJson), record.requestJson))
  }

  async acceptStoredGrant(
    apiBaseUrlValue: string,
    accountIdValue: string,
    requestIdValue: string,
    grantJson: string,
    options: { fetcher?: typeof fetch; signal?: AbortSignal } = {},
  ): Promise<AcceptedDeviceEnrollment> {
    const apiBaseUrl = normalizeSyncApiBaseUrl(apiBaseUrlValue)
    const accountId = requireUuid(accountIdValue, "account ID")
    const requestId = requireUuid(requestIdValue, "enrollment request ID")
    const key = joinRequestKey(apiBaseUrl, accountId, requestId)
    const stored = await this.storage.getJoinRequest(key)
    if (stored === null) {
      throw new SyncClientError("not_found", "The joining-device request was not found.")
    }
    const request = validateStoredJoinRequest(stored)
    const accepted = await this.acceptGrant(
      apiBaseUrl,
      request.joiningDeviceId,
      request.requestJson,
      grantJson,
      options,
    )
    await this.storage.deleteJoinRequest(key)
    return accepted
  }

  async discardJoinRequest(
    apiBaseUrlValue: string,
    accountIdValue: string,
    requestIdValue: string,
  ): Promise<void> {
    const apiBaseUrl = normalizeSyncApiBaseUrl(apiBaseUrlValue)
    const accountId = requireUuid(accountIdValue, "account ID")
    const requestId = requireUuid(requestIdValue, "enrollment request ID")
    await this.storage.deleteJoinRequest(joinRequestKey(apiBaseUrl, accountId, requestId))
  }

  async prepareApproval(
    client: SyncClient,
    approverDeviceIdValue: string,
    requestJson: string,
    options: { signal?: AbortSignal } = {},
  ): Promise<PreparedDeviceEnrollmentApproval> {
    const approverDeviceId = requireUuid(approverDeviceIdValue, "approver device ID")
    if (client.deviceId !== approverDeviceId) {
      throw new SyncClientError(
        "invalid_contract",
        "The approving client does not match the selected device identity.",
      )
    }
    const request = parseRequest(requestJson)
    if (request.accountId !== client.accountId) {
      throw new SyncClientError(
        "invalid_contract",
        "The enrollment request belongs to a different account.",
      )
    }
    const deviceToken = generateDeviceToken()
    const plaintext = encodeCredentialPackage(request, deviceToken)
    try {
      const grantJson = await this.deviceKeys.sealDeviceEnrollmentGrant(
        approverDeviceId,
        requestJson,
        plaintext,
      )
      const grant = parseGrant(grantJson)
      requireGrantContext(grant, request, approverDeviceId)
      await this.persistDraft(client, request, approverDeviceId, requestJson, grantJson, deviceToken)
      const enrollment = await client.prepareDeviceEnrollment(
        request.requestId,
        requestRegistration(request),
        deviceToken,
        options,
      )
      return { enrollment, request_json: requestJson, grant_json: grantJson }
    } finally {
      plaintext.fill(0)
    }
  }

  async resumeApproval(
    client: SyncClient,
    requestIdValue: string,
    options: { signal?: AbortSignal } = {},
  ): Promise<PreparedDeviceEnrollmentApproval> {
    const requestId = requireUuid(requestIdValue, "enrollment request ID")
    const stored = await this.storage.getDraft(draftKey(client.apiBaseUrl, client.accountId, requestId))
    if (stored === null) {
      throw new SyncClientError("not_found", "The enrollment approval draft was not found.")
    }
    const draft = validateStoredDraft(stored)
    if (
      client.deviceId !== draft.approverDeviceId ||
      client.accountId !== draft.accountId ||
      client.apiBaseUrl !== draft.apiBaseUrl
    ) {
      return invalidStoredDraft()
    }
    const request = parseRequest(draft.requestJson)
    const grant = parseGrant(draft.grantJson)
    requireGrantContext(grant, request, draft.approverDeviceId)
    let tokenBytes: Uint8Array | null = null
    try {
      tokenBytes = await this.openDraftToken(draft)
      const deviceToken = decodeToken(tokenBytes)
      const enrollment = await client.prepareDeviceEnrollment(
        request.requestId,
        requestRegistration(request),
        deviceToken,
        options,
      )
      return {
        enrollment,
        request_json: draft.requestJson,
        grant_json: draft.grantJson,
      }
    } finally {
      tokenBytes?.fill(0)
    }
  }

  async listApprovalDrafts(
    apiBaseUrlValue: string,
    accountIdValue: string,
  ): Promise<DeviceEnrollmentApprovalDraft[]> {
    const apiBaseUrl = normalizeSyncApiBaseUrl(apiBaseUrlValue)
    const accountId = requireUuid(accountIdValue, "account ID")
    const records = await this.storage.listDrafts()
    return records.map(validateStoredDraft)
      .filter((record) => record.apiBaseUrl === apiBaseUrl && record.accountId === accountId)
      .map((record) => ({
        account_id: record.accountId,
        request_id: record.requestId,
        approver_device_id: record.approverDeviceId,
        joining_device_id: record.joiningDeviceId,
        request_json: record.requestJson,
        grant_json: record.grantJson,
      }))
  }

  async discardApproval(
    client: SyncClient,
    requestIdValue: string,
    options: { signal?: AbortSignal } = {},
  ): Promise<void> {
    const requestId = requireUuid(requestIdValue, "enrollment request ID")
    try {
      await client.cancelDeviceEnrollment(requestId, options)
    } catch (error) {
      if (
        !(error instanceof SyncClientError) ||
        (error.code !== "not_found" && error.code !== "enrollment_unavailable")
      ) throw error
    }
    await this.storage.deleteDraft(draftKey(client.apiBaseUrl, client.accountId, requestId))
  }

  async acceptGrant(
    apiBaseUrlValue: string,
    joiningDeviceIdValue: string,
    requestJson: string,
    grantJson: string,
    options: { fetcher?: typeof fetch; signal?: AbortSignal } = {},
  ): Promise<AcceptedDeviceEnrollment> {
    const apiBaseUrl = normalizeSyncApiBaseUrl(apiBaseUrlValue)
    const joiningDeviceId = requireUuid(joiningDeviceIdValue, "joining device ID")
    const request = parseRequest(requestJson)
    const grant = parseGrant(grantJson)
    requireGrantContext(grant, request, grant.approverDeviceId)
    if (request.deviceId !== joiningDeviceId) {
      throw new SyncClientError(
        "invalid_contract",
        "The enrollment grant targets a different joining device.",
      )
    }
    let plaintext: Uint8Array | null = null
    try {
      plaintext = await this.deviceKeys.openDeviceEnrollmentGrant(
        joiningDeviceId,
        requestJson,
        grantJson,
      )
      const deviceToken = parseCredentialPackage(plaintext, request)
      const credentials = await SyncClient.activateDeviceEnrollment(
        apiBaseUrl,
        request.requestId,
        request.deviceId,
        deviceToken,
        options,
      )
      const client = await SyncClient.connect(
        apiBaseUrl,
        credentials.account_id,
        credentials.device_token,
        {
          ...options,
          deviceId: credentials.device_id,
        },
      )
      const inventory = await client.listDevices(options)
      const approver = inventory.devices.find(
        (device) => device.device_id === grant.approverDeviceId,
      )
      if (
        approver?.encryption_public_key !== grant.approverEncryptionPublicKeyHex ||
        approver.signing_public_key !== grant.approverSigningPublicKeyHex
      ) {
        throw new SyncClientError(
          "invalid_response",
          "The enrollment grant approver is not an active matching device.",
        )
      }
      await this.credentials.save(apiBaseUrl, credentials)
      return { credentials, client }
    } finally {
      plaintext?.fill(0)
    }
  }

  private async persistDraft(
    client: SyncClient,
    request: EnrollmentRequestContext,
    approverDeviceId: string,
    requestJson: string,
    grantJson: string,
    deviceToken: string,
  ): Promise<void> {
    const metadata = {
      key: draftKey(client.apiBaseUrl, client.accountId, request.requestId),
      format: RECORD_FORMAT,
      apiBaseUrl: client.apiBaseUrl,
      accountId: client.accountId,
      requestId: request.requestId,
      approverDeviceId,
      joiningDeviceId: request.deviceId,
      requestJson,
      grantJson,
    }
    const plaintext = new TextEncoder().encode(deviceToken)
    try {
      const wrappingKey = validateWrappingKey(await this.storage.getOrCreateWrappingKey())
      const iv = this.cryptography.getRandomValues(new Uint8Array(IV_BYTES))
      const ciphertext = await this.cryptography.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: draftAad(metadata) },
        wrappingKey,
        plaintext,
      )
      await this.storage.addDraft({
        ...metadata,
        iv: iv.slice().buffer,
        ciphertext,
      })
    } finally {
      plaintext.fill(0)
    }
  }

  private async openDraftToken(record: StoredDeviceEnrollmentApprovalV1): Promise<Uint8Array> {
    try {
      const wrappingKey = validateWrappingKey(await this.storage.getOrCreateWrappingKey())
      const plaintext = await this.cryptography.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: new Uint8Array(record.iv),
          additionalData: draftAad(record),
        },
        wrappingKey,
        record.ciphertext,
      )
      return new Uint8Array(plaintext)
    } catch {
      return invalidStoredDraft()
    }
  }
}

export class IndexedDbDeviceEnrollmentApprovalStorage
implements DeviceEnrollmentApprovalStorageBackend {
  getOrCreateWrappingKey(): Promise<CryptoKey> {
    return getOrCreateWrappingKey()
  }

  addDraft(record: StoredDeviceEnrollmentApprovalV1): Promise<void> {
    return addDraft(validateStoredDraft(record))
  }

  getDraft(key: string): Promise<StoredDeviceEnrollmentApprovalV1 | null> {
    return readDraft(key)
  }

  listDrafts(): Promise<StoredDeviceEnrollmentApprovalV1[]> {
    return listDrafts()
  }

  deleteDraft(key: string): Promise<void> {
    return deleteDraft(key)
  }

  addJoinRequest(record: StoredDeviceEnrollmentJoinRequestV1): Promise<void> {
    return addJoinRequest(validateStoredJoinRequest(record))
  }

  getJoinRequest(key: string): Promise<StoredDeviceEnrollmentJoinRequestV1 | null> {
    return readJoinRequest(key)
  }

  listJoinRequests(): Promise<StoredDeviceEnrollmentJoinRequestV1[]> {
    return listJoinRequests()
  }

  deleteJoinRequest(key: string): Promise<void> {
    return deleteJoinRequest(key)
  }
}

function joinRequestResponse(
  request: EnrollmentRequestContext,
  requestJson: string,
): DeviceEnrollmentJoinRequest {
  return {
    account_id: request.accountId,
    request_id: request.requestId,
    joining_device_id: request.deviceId,
    request_json: requestJson,
  }
}

function requestRegistration(request: EnrollmentRequestContext): DeviceRegistrationV1 {
  return {
    format_version: 1,
    device_id: request.deviceId,
    encryption_public_key_hex: request.encryptionPublicKeyHex,
    signing_public_key_hex: request.signingPublicKeyHex,
  }
}

function encodeCredentialPackage(
  request: EnrollmentRequestContext,
  deviceToken: string,
): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    format_version: CREDENTIAL_FORMAT,
    account_id: request.accountId,
    device_id: request.deviceId,
    device_token: deviceToken,
  }))
}

function parseCredentialPackage(
  bytes: Uint8Array,
  request: EnrollmentRequestContext,
): string {
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_PACKAGE_BYTES) {
    throw new SyncClientError("invalid_response", "The enrollment credential package is invalid.")
  }
  let value: unknown
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes))
  } catch {
    throw new SyncClientError("invalid_response", "The enrollment credential package is invalid.")
  }
  const record = exactRecord(value, ["format_version", "account_id", "device_id", "device_token"])
  if (
    record.format_version !== CREDENTIAL_FORMAT ||
    record.account_id !== request.accountId ||
    record.device_id !== request.deviceId ||
    typeof record.device_token !== "string" ||
    !TOKEN.test(record.device_token)
  ) {
    throw new SyncClientError("invalid_response", "The enrollment credential package is invalid.")
  }
  return record.device_token
}

function parseRequest(json: string): EnrollmentRequestContext {
  if (typeof json !== "string" || json.length === 0 || json.length > MAX_REQUEST_CHARS) {
    throw new SyncClientError("invalid_contract", "The device enrollment request is invalid.")
  }
  let value: unknown
  try {
    value = JSON.parse(json)
  } catch {
    throw new SyncClientError("invalid_contract", "The device enrollment request is invalid.")
  }
  const record = exactRecord(value, [
    "format_version", "request_id", "account_id", "device_id", "encryption_public",
    "signing_public", "challenge", "signature",
  ])
  if (
    record.format_version !== 1 ||
    !byteArray(record.challenge, 32) ||
    !byteArray(record.signature, 64)
  ) return invalidEnrollmentRequest()
  return {
    requestId: requireUuid(record.request_id, "enrollment request ID"),
    accountId: requireUuid(record.account_id, "account ID"),
    deviceId: requireUuid(record.device_id, "device ID"),
    encryptionPublicKeyHex: byteArrayHex(record.encryption_public, 32),
    signingPublicKeyHex: byteArrayHex(record.signing_public, 32),
  }
}

function parseGrant(json: string): EnrollmentGrantContext {
  if (typeof json !== "string" || json.length === 0 || json.length > MAX_GRANT_CHARS) {
    throw new SyncClientError("invalid_contract", "The device enrollment grant is invalid.")
  }
  let value: unknown
  try {
    value = JSON.parse(json)
  } catch {
    throw new SyncClientError("invalid_contract", "The device enrollment grant is invalid.")
  }
  const record = exactRecord(value, [
    "format_version", "algorithm", "request_id", "account_id", "joining_device_id",
    "joining_encryption_public", "joining_signing_public", "approver_device_id",
    "approver_encryption_public", "approver_signing_public", "ephemeral_public",
    "nonce", "ciphertext", "signature",
  ])
  if (
    record.format_version !== 1 ||
    record.algorithm !== ALGORITHM ||
    !byteArray(record.joining_encryption_public, 32) ||
    !byteArray(record.joining_signing_public, 32) ||
    !byteArray(record.approver_encryption_public, 32) ||
    !byteArray(record.approver_signing_public, 32) ||
    !byteArray(record.ephemeral_public, 32) ||
    !byteArray(record.nonce, 24) ||
    !boundedByteArray(record.ciphertext, MAX_PACKAGE_BYTES + 16) ||
    !byteArray(record.signature, 64)
  ) return invalidEnrollmentGrant()
  return {
    requestId: requireUuid(record.request_id, "enrollment request ID"),
    accountId: requireUuid(record.account_id, "account ID"),
    joiningDeviceId: requireUuid(record.joining_device_id, "joining device ID"),
    joiningEncryptionPublicKeyHex: byteArrayHex(record.joining_encryption_public, 32),
    joiningSigningPublicKeyHex: byteArrayHex(record.joining_signing_public, 32),
    approverDeviceId: requireUuid(record.approver_device_id, "approver device ID"),
    approverEncryptionPublicKeyHex: byteArrayHex(record.approver_encryption_public, 32),
    approverSigningPublicKeyHex: byteArrayHex(record.approver_signing_public, 32),
  }
}

function requireGrantContext(
  grant: EnrollmentGrantContext,
  request: EnrollmentRequestContext,
  approverDeviceId: string,
): void {
  if (
    grant.requestId !== request.requestId ||
    grant.accountId !== request.accountId ||
    grant.joiningDeviceId !== request.deviceId ||
    grant.joiningEncryptionPublicKeyHex !== request.encryptionPublicKeyHex ||
    grant.joiningSigningPublicKeyHex !== request.signingPublicKeyHex ||
    grant.approverDeviceId !== approverDeviceId
  ) {
    throw new SyncClientError("invalid_contract", "The enrollment grant context is inconsistent.")
  }
}

function validateStoredDraft(value: unknown): StoredDeviceEnrollmentApprovalV1 {
  if (typeof value !== "object" || value === null) return invalidStoredDraft()
  const record = value as Partial<StoredDeviceEnrollmentApprovalV1>
  if (
    record.format !== RECORD_FORMAT ||
    typeof record.key !== "string" ||
    typeof record.apiBaseUrl !== "string" ||
    typeof record.requestJson !== "string" ||
    typeof record.grantJson !== "string" ||
    !(record.iv instanceof ArrayBuffer) ||
    record.iv.byteLength !== IV_BYTES ||
    !(record.ciphertext instanceof ArrayBuffer) ||
    record.ciphertext.byteLength <= 16 ||
    record.ciphertext.byteLength > MAX_PACKAGE_BYTES
  ) return invalidStoredDraft()
  let apiBaseUrl: string
  let accountId: string
  let requestId: string
  let approverDeviceId: string
  let joiningDeviceId: string
  try {
    apiBaseUrl = normalizeSyncApiBaseUrl(record.apiBaseUrl)
    accountId = requireUuid(record.accountId, "stored account ID")
    requestId = requireUuid(record.requestId, "stored enrollment request ID")
    approverDeviceId = requireUuid(record.approverDeviceId, "stored approver device ID")
    joiningDeviceId = requireUuid(record.joiningDeviceId, "stored joining device ID")
  } catch {
    return invalidStoredDraft()
  }
  if (record.key !== draftKey(apiBaseUrl, accountId, requestId)) return invalidStoredDraft()
  let request: EnrollmentRequestContext
  let grant: EnrollmentGrantContext
  try {
    request = parseRequest(record.requestJson)
    grant = parseGrant(record.grantJson)
  } catch {
    return invalidStoredDraft()
  }
  if (
    request.accountId !== accountId ||
    request.requestId !== requestId ||
    request.deviceId !== joiningDeviceId
  ) return invalidStoredDraft()
  try {
    requireGrantContext(grant, request, approverDeviceId)
  } catch {
    return invalidStoredDraft()
  }
  return {
    key: record.key,
    format: RECORD_FORMAT,
    apiBaseUrl,
    accountId,
    requestId,
    approverDeviceId,
    joiningDeviceId,
    requestJson: record.requestJson,
    grantJson: record.grantJson,
    iv: record.iv,
    ciphertext: record.ciphertext,
  }
}

function validateStoredJoinRequest(value: unknown): StoredDeviceEnrollmentJoinRequestV1 {
  if (typeof value !== "object" || value === null) return invalidStoredJoinRequest()
  const record = value as Partial<StoredDeviceEnrollmentJoinRequestV1>
  if (
    record.format !== RECORD_FORMAT ||
    typeof record.key !== "string" ||
    typeof record.apiBaseUrl !== "string" ||
    typeof record.requestJson !== "string"
  ) return invalidStoredJoinRequest()
  let apiBaseUrl: string
  let accountId: string
  let requestId: string
  let joiningDeviceId: string
  let request: EnrollmentRequestContext
  try {
    apiBaseUrl = normalizeSyncApiBaseUrl(record.apiBaseUrl)
    accountId = requireUuid(record.accountId, "stored account ID")
    requestId = requireUuid(record.requestId, "stored enrollment request ID")
    joiningDeviceId = requireUuid(record.joiningDeviceId, "stored joining device ID")
    request = parseRequest(record.requestJson)
  } catch {
    return invalidStoredJoinRequest()
  }
  if (
    record.key !== joinRequestKey(apiBaseUrl, accountId, requestId) ||
    request.accountId !== accountId ||
    request.requestId !== requestId ||
    request.deviceId !== joiningDeviceId
  ) return invalidStoredJoinRequest()
  return {
    key: record.key,
    format: RECORD_FORMAT,
    apiBaseUrl,
    accountId,
    requestId,
    joiningDeviceId,
    requestJson: record.requestJson,
  }
}

function draftAad(record: Omit<StoredDeviceEnrollmentApprovalV1, "iv" | "ciphertext">): ArrayBuffer {
  return new TextEncoder().encode([
    AAD_DOMAIN, record.apiBaseUrl, record.accountId, record.requestId,
    record.approverDeviceId, record.joiningDeviceId, record.requestJson, record.grantJson,
  ].join("\0")).slice().buffer
}

function draftKey(apiBaseUrl: string, accountId: string, requestId: string): string {
  return `${apiBaseUrl}\0${accountId}\0${requestId}`
}

function joinRequestKey(apiBaseUrl: string, accountId: string, requestId: string): string {
  return `${apiBaseUrl}\0${accountId}\0${requestId}`
}

function decodeToken(bytes: Uint8Array): string {
  let token: string
  try {
    token = new TextDecoder("utf-8", { fatal: true }).decode(bytes)
  } catch {
    return invalidStoredDraft()
  }
  if (!TOKEN.test(token)) return invalidStoredDraft()
  return token
}

function requireUuid(value: unknown, label: string): string {
  if (typeof value !== "string" || !UUID.test(value)) {
    throw new SyncClientError("invalid_contract", `The ${label} is invalid.`)
  }
  return value.toLowerCase()
}

function byteArray(value: unknown, length: number): value is number[] {
  return Array.isArray(value) && value.length === length && value.every(
    (byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255,
  )
}

function boundedByteArray(value: unknown, maximum: number): value is number[] {
  return Array.isArray(value) && value.length > 0 && value.length <= maximum && value.every(
    (byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255,
  )
}

function byteArrayHex(value: unknown, length: number): string {
  if (!byteArray(value, length)) return invalidEnrollmentRequest()
  return value.map((byte) => byte.toString(16).padStart(2, "0")).join("")
}

function exactRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new SyncClientError("invalid_contract", "The enrollment package is invalid.")
  }
  const record = value as Record<string, unknown>
  const actual = Object.keys(record).sort()
  const expected = [...keys].sort()
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new SyncClientError("invalid_contract", "The enrollment package is invalid.")
  }
  return record
}

function invalidEnrollmentRequest(): never {
  throw new SyncClientError("invalid_contract", "The device enrollment request is invalid.")
}

function invalidEnrollmentGrant(): never {
  throw new SyncClientError("invalid_contract", "The device enrollment grant is invalid.")
}

function invalidStoredDraft(): never {
  throw new SyncClientError("invalid_response", "The persisted enrollment approval is invalid.")
}

function invalidStoredJoinRequest(): never {
  throw new SyncClientError("invalid_response", "The persisted joining-device request is invalid.")
}

function validateWrappingKey(value: unknown): CryptoKey {
  if (typeof value !== "object" || value === null) return invalidStoredDraft()
  const key = value as CryptoKey
  if (
    key.type !== "secret" || key.extractable !== false || key.algorithm?.name !== "AES-GCM" ||
    !key.usages?.includes("encrypt") || !key.usages?.includes("decrypt")
  ) return invalidStoredDraft()
  return key
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)
    request.onupgradeneeded = () => {
      const db = request.result
      if (!db.objectStoreNames.contains(WRAPPING_STORE)) db.createObjectStore(WRAPPING_STORE)
      if (!db.objectStoreNames.contains(DRAFT_STORE)) {
        db.createObjectStore(DRAFT_STORE, { keyPath: "key" })
      }
      if (!db.objectStoreNames.contains(JOIN_REQUEST_STORE)) {
        db.createObjectStore(JOIN_REQUEST_STORE, { keyPath: "key" })
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error("enrollment approval database open failed"))
  })
}

async function getOrCreateWrappingKey(): Promise<CryptoKey> {
  const candidate = validateWrappingKey(await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  ))
  const db = await openDb()
  return new Promise((resolve, reject) => {
    let selected: CryptoKey | null = null
    const tx = db.transaction(WRAPPING_STORE, "readwrite")
    const read = tx.objectStore(WRAPPING_STORE).get(WRAPPING_KEY_ID)
    const fail = (error: unknown) => { db.close(); reject(error) }
    read.onerror = () => fail(read.error)
    read.onsuccess = () => {
      try {
        selected = read.result === undefined ? candidate : validateWrappingKey(read.result)
        if (read.result === undefined) tx.objectStore(WRAPPING_STORE).add(candidate, WRAPPING_KEY_ID)
      } catch (error) {
        try { tx.abort() } catch { /* transaction is already stopping */ }
        fail(error)
      }
    }
    tx.onabort = () => fail(tx.error)
    tx.onerror = () => fail(tx.error)
    tx.oncomplete = () => {
      db.close()
      if (selected === null) reject(new Error("enrollment approval wrapping key is unavailable"))
      else resolve(selected)
    }
  })
}

async function addDraft(record: StoredDeviceEnrollmentApprovalV1): Promise<void> {
  await storeRequest(DRAFT_STORE, "readwrite", (store) => store.add(record))
}

async function readDraft(key: string): Promise<StoredDeviceEnrollmentApprovalV1 | null> {
  const result = await storeRequest<unknown>(DRAFT_STORE, "readonly", (store) => store.get(key))
  return result === undefined ? null : validateStoredDraft(result)
}

async function listDrafts(): Promise<StoredDeviceEnrollmentApprovalV1[]> {
  const result = await storeRequest<unknown[]>(DRAFT_STORE, "readonly", (store) => store.getAll())
  return result.map(validateStoredDraft)
}

async function deleteDraft(key: string): Promise<void> {
  await storeRequest(DRAFT_STORE, "readwrite", (store) => store.delete(key))
}

async function addJoinRequest(record: StoredDeviceEnrollmentJoinRequestV1): Promise<void> {
  await storeRequest(JOIN_REQUEST_STORE, "readwrite", (store) => store.add(record))
}

async function readJoinRequest(key: string): Promise<StoredDeviceEnrollmentJoinRequestV1 | null> {
  const result = await storeRequest<unknown>(
    JOIN_REQUEST_STORE, "readonly", (store) => store.get(key),
  )
  return result === undefined ? null : validateStoredJoinRequest(result)
}

async function listJoinRequests(): Promise<StoredDeviceEnrollmentJoinRequestV1[]> {
  const result = await storeRequest<unknown[]>(
    JOIN_REQUEST_STORE, "readonly", (store) => store.getAll(),
  )
  return result.map(validateStoredJoinRequest)
}

async function deleteJoinRequest(key: string): Promise<void> {
  await storeRequest(JOIN_REQUEST_STORE, "readwrite", (store) => store.delete(key))
}

function storeRequest<T>(
  storeName: string,
  mode: IDBTransactionMode,
  run: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  return openDb().then((db) => new Promise<T>((resolve, reject) => {
    let result: T | undefined
    let succeeded = false
    const tx = db.transaction(storeName, mode)
    const request = run(tx.objectStore(storeName))
    const fail = (error: unknown) => { db.close(); reject(error) }
    request.onerror = () => fail(request.error)
    request.onsuccess = () => { succeeded = true; result = request.result }
    tx.onabort = () => fail(tx.error)
    tx.onerror = () => fail(tx.error)
    tx.oncomplete = () => {
      db.close()
      if (!succeeded) reject(new Error("enrollment approval transaction was incomplete"))
      else resolve(result as T)
    }
  }))
}
