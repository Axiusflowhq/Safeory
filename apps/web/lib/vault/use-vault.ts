"use client"

import { useCallback, useEffect, useRef, useState } from "react"

import {
  VaultDurabilityError,
  type AttachmentSummary,
  type DeadlineSummary,
  type DeviceRegistrationV1,
  type EmergencyCard,
  type EmergencyContact,
  type PairingChallengeV1,
  type PairingProofV1,
  type TrashedItemSummary,
  type TrustedPrincipal,
  type ConnectedSingleOwnerVaultSync,
  type VaultSession,
} from "@safeory/contracts"
import { newId, type VaultItemJson } from "./items"
import {
  clearBrowserSyncConfiguration,
  enrollBrowserVaultSync,
  loadBrowserSyncConfiguration,
  resumeBrowserVaultSync,
  type BrowserSyncEnrollment,
} from "./sync"
import { startBrowserSyncSchedule } from "./sync-scheduler"
import {
  clearSessionResume,
  loadSessionResumeForReload,
  refreshSessionResume,
  resumeSessionFromReload,
} from "./session-resume"
import { browserDeviceKeyStore, loadVaultSession, wasmStatics } from "./vault"

export type VaultPhase = "loading" | "load_error" | "setup" | "unlock" | "open"

/** Redacted list entry: no fields, notes, passwords, or other item plaintext. */
export interface ListedEntry {
  item: { id: string; title: string; kind: string }
  revision: number
}

/** Full plaintext exists in UI state only after the user opens one item. */
export interface EditableEntry {
  item: VaultItemJson
  revision: number
}

export type VaultSyncPhase =
  | "not_configured"
  | "connecting"
  | "ready"
  | "syncing"
  | "error"

export interface VaultSyncStatus {
  phase: VaultSyncPhase
  accountId: string | null
  lastSyncedAt: number | null
  pendingUploads: number
  blockedItems: number
  error: string | null
}

const INITIAL_SYNC_STATUS: VaultSyncStatus = {
  phase: "not_configured",
  accountId: null,
  lastSyncedAt: null,
  pendingUploads: 0,
  blockedItems: 0,
  error: null,
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function localTodayYmd(): string {
  const today = new Date()
  const year = String(today.getFullYear()).padStart(4, "0")
  const month = String(today.getMonth() + 1).padStart(2, "0")
  const day = String(today.getDate()).padStart(2, "0")
  return `${year}-${month}-${day}`
}

export function useVault() {
  const sessionRef = useRef<VaultSession | null>(null)
  const operationTailRef = useRef<Promise<void>>(Promise.resolve())
  const syncConnectionRef = useRef<ConnectedSingleOwnerVaultSync | null>(null)
  const syncPendingRef = useRef<Promise<boolean> | null>(null)
  const syncQueuedRef = useRef(false)
  const performSyncRef = useRef<(
    connection?: ConnectedSingleOwnerVaultSync | null
  ) => Promise<boolean>>(() => Promise.resolve(false))
  const syncGenerationRef = useRef(0)
  const [phase, setPhase] = useState<VaultPhase>("loading")
  const [items, setItems] = useState<ListedEntry[]>([])
  const [trashedItems, setTrashedItems] = useState<TrashedItemSummary[]>([])
  const [error, setError] = useState<string | null>(null)
  const [hasRecoveryKit, setHasRecoveryKit] = useState(false)
  const [generatedSecret, setGeneratedSecret] = useState<string | null>(null)
  const [syncStatus, setSyncStatus] = useState<VaultSyncStatus>(INITIAL_SYNC_STATUS)
  const [emergencyCardSnapshot, setEmergencyCardSnapshot] = useState<{
    card: EmergencyCard
    revision: number
  } | null>(null)

  const refresh = useCallback(() => {
    const session = sessionRef.current
    if (!session || !session.isUnlocked()) {
      setItems([])
      setTrashedItems([])
      setEmergencyCardSnapshot(null)
      return
    }

    const list = session.listItems() as ListedEntry[]
    list.sort((a, b) => a.item.title.localeCompare(b.item.title))
    setItems(list)
    setTrashedItems(session.listTrashedItems())
    setEmergencyCardSnapshot(session.getEmergencyCard())
    setHasRecoveryKit(session.hasRecoveryKit())
  }, [])

  const performSync = useCallback(
    (connection = syncConnectionRef.current): Promise<boolean> => {
      if (connection === null) return Promise.resolve(false)
      if (syncPendingRef.current !== null) {
        syncQueuedRef.current = true
        return syncPendingRef.current
      }
      const generation = syncGenerationRef.current
      setSyncStatus((current) => ({ ...current, phase: "syncing", error: null }))
      const task = connection.runtime
        .syncOnce()
        .then((result) => {
          if (generation !== syncGenerationRef.current) return false
          refresh()
          setSyncStatus((current) => ({
            ...current,
            phase: "ready",
            accountId: connection.client.accountId,
            lastSyncedAt: Date.now(),
            pendingUploads: result.push.remaining,
            blockedItems: result.harvest.blockedObjectIds.length,
            error: null,
          }))
          return true
        })
        .catch((syncError: unknown) => {
          if (generation === syncGenerationRef.current) {
            setSyncStatus((current) => ({
              ...current,
              phase: "error",
              accountId: connection.client.accountId,
              error: errorMessage(syncError),
            }))
          }
          return false
        })
        .finally(() => {
          if (syncPendingRef.current !== task) return
          syncPendingRef.current = null
          if (syncQueuedRef.current && generation === syncGenerationRef.current) {
            syncQueuedRef.current = false
            queueMicrotask(() => void performSyncRef.current(connection))
          }
        })
      syncPendingRef.current = task
      return task
    },
    [refresh]
  )
  performSyncRef.current = performSync

  const stopSync = useCallback(() => {
    syncGenerationRef.current += 1
    syncConnectionRef.current = null
    syncPendingRef.current = null
    syncQueuedRef.current = false
  }, [])

  const startSync = useCallback(
    async (session: VaultSession): Promise<void> => {
      const generation = syncGenerationRef.current + 1
      syncGenerationRef.current = generation
      syncConnectionRef.current = null
      let accountId: string | null = null
      try {
        accountId = loadBrowserSyncConfiguration()?.accountId ?? null
        if (accountId === null) {
          setSyncStatus(INITIAL_SYNC_STATUS)
          return
        }
        setSyncStatus((current) => ({
          ...current,
          phase: "connecting",
          accountId,
          error: null,
        }))
        const connected = await resumeBrowserVaultSync(session)
        if (
          generation !== syncGenerationRef.current ||
          sessionRef.current !== session ||
          !session.isUnlocked()
        ) {
          return
        }
        if (connected === null) {
          setSyncStatus(INITIAL_SYNC_STATUS)
          return
        }
        syncConnectionRef.current = connected
        setSyncStatus((current) => ({
          ...current,
          phase: "ready",
          accountId: connected.client.accountId,
          error: null,
        }))
        await performSync(connected)
      } catch (syncError: unknown) {
        if (generation !== syncGenerationRef.current) return
        setSyncStatus((current) => ({
          ...current,
          phase: "error",
          accountId,
          error: errorMessage(syncError),
        }))
      }
    },
    [performSync]
  )

  useEffect(() => {
    const request = () => void performSync()
    const stopSchedule = startBrowserSyncSchedule(request)
    return () => {
      stopSchedule()
      stopSync()
    }
  }, [performSync, stopSync])

  useEffect(() => {
    let active = true

    loadVaultSession()
      .then(async (session) => {
        if (!active) return
        sessionRef.current = session
        if (!session.isInitialized()) {
          clearSessionResume()
          setPhase("setup")
          return
        }

        const resumePayload = loadSessionResumeForReload()
        if (resumePayload !== null) {
          try {
            await resumeSessionFromReload(session, resumePayload)
          } catch (resumeError) {
            session.lock()
            clearSessionResume()
            if (resumeError instanceof VaultDurabilityError) throw resumeError
            setPhase("unlock")
            return
          }

          try {
            refresh()
          } catch (resumeRefreshError) {
            session.lock()
            clearSessionResume()
            throw resumeRefreshError
          }
          setPhase("open")
          void startSync(session)
          return
        }

        setPhase("unlock")
      })
      .catch((loadError: unknown) => {
        if (!active) return
        sessionRef.current = null
        setError(errorMessage(loadError))
        setPhase("load_error")
      })

    return () => {
      active = false
    }
  }, [refresh, startSync])

  const run = useCallback(
    (
      operation: (session: VaultSession) => void | Promise<void>
    ): Promise<boolean> => {
      const session = sessionRef.current
      if (!session) return Promise.resolve(false)

      setError(null)
      const task = operationTailRef.current
        .then(async () => {
          if (sessionRef.current !== session) return false
          await operation(session)
          refresh()
          void performSync()
          return true
        })
        .catch((operationError: unknown) => {
          if (operationError instanceof VaultDurabilityError) {
            stopSync()
            clearSessionResume()
            sessionRef.current = null
            setItems([])
            setTrashedItems([])
            setEmergencyCardSnapshot(null)
            setHasRecoveryKit(false)
            setGeneratedSecret(null)
            setError(errorMessage(operationError))
            setPhase("load_error")
            return false
          }
          setError(errorMessage(operationError))
          return false
        })
      operationTailRef.current = task.then(
        () => undefined,
        () => undefined
      )
      return task
    },
    [performSync, refresh, stopSync]
  )

  const create = useCallback(
    (passphrase: string) =>
      run(async (session) => {
        await session.create(passphrase)
        await refreshSessionResume(session)
        setPhase("open")
        void startSync(session)
      }),
    [run, startSync]
  )

  const importEncryptedBackup = useCallback(
    (snapshotJson: string, passphrase: string) =>
      run(async (session) => {
        await session.importEncryptedSnapshot(snapshotJson, passphrase)
        await refreshSessionResume(session)
        setPhase("open")
        void startSync(session)
      }),
    [run, startSync]
  )

  const unlock = useCallback(
    (passphrase: string) =>
      run(async (session) => {
        await session.unlock(passphrase)
        await refreshSessionResume(session)
        setPhase("open")
        void startSync(session)
      }),
    [run, startSync]
  )

  const unlockWithRecoveryKit = useCallback(
    (secretHex: string) =>
      run(async (session) => {
        await session.unlockWithRecoveryKit(secretHex)
        await refreshSessionResume(session)
        setPhase("open")
        void startSync(session)
      }),
    [run, startSync]
  )

  const changePassphrase = useCallback(
    (currentPassphrase: string, newPassphrase: string) =>
      run(async (session) => {
        await session.changePassphrase(currentPassphrase, newPassphrase)
        await refreshSessionResume(session)
      }),
    [run]
  )

  const lock = useCallback(() => {
    try {
      if (!clearSessionResume()) {
        setError(
          "Unable to securely clear this tab's reload credential. The vault remains unlocked."
        )
        return
      }
      sessionRef.current?.lock()
      stopSync()
      setItems([])
      setTrashedItems([])
      setEmergencyCardSnapshot(null)
      setPhase("unlock")
    } catch (lockError: unknown) {
      setError(errorMessage(lockError))
    }
  }, [stopSync])

  const enrollSync = useCallback(
    async (enrollment: BrowserSyncEnrollment): Promise<boolean> => {
      const session = sessionRef.current
      if (!session || !session.isUnlocked()) return false
      const generation = syncGenerationRef.current + 1
      syncGenerationRef.current = generation
      syncConnectionRef.current = null
      setSyncStatus((current) => ({
        ...current,
        phase: "connecting",
        error: null,
      }))
      try {
        const connected = await enrollBrowserVaultSync(session, enrollment)
        if (generation !== syncGenerationRef.current || sessionRef.current !== session) {
          return false
        }
        syncConnectionRef.current = connected
        setSyncStatus((current) => ({
          ...current,
          phase: "ready",
          accountId: connected.client.accountId,
          error: null,
        }))
        return await performSync(connected)
      } catch (syncError: unknown) {
        if (generation === syncGenerationRef.current) {
          const configuration = (() => {
            try {
              return loadBrowserSyncConfiguration()
            } catch {
              return null
            }
          })()
          setSyncStatus((current) => ({
            ...current,
            phase: configuration === null ? "not_configured" : "error",
            accountId: configuration?.accountId ?? null,
            error: errorMessage(syncError),
          }))
        }
        return false
      }
    },
    [performSync]
  )

  const generateAccountSecret = useCallback(
    () => wasmStatics.generateAccountSecret(),
    []
  )

  const retrySync = useCallback(async (): Promise<boolean> => {
    const session = sessionRef.current
    if (!session || !session.isUnlocked()) return false
    await startSync(session)
    return syncConnectionRef.current !== null
  }, [startSync])

  const resetInvalidSyncConfiguration = useCallback(() => {
    if (syncStatus.accountId !== null) return false
    try {
      clearBrowserSyncConfiguration()
      stopSync()
      setSyncStatus(INITIAL_SYNC_STATUS)
      return true
    } catch (resetError: unknown) {
      setSyncStatus((current) => ({
        ...current,
        phase: "error",
        error: errorMessage(resetError),
      }))
      return false
    }
  }, [stopSync, syncStatus.accountId])

  const putItem = useCallback(
    (item: VaultItemJson) =>
      run(async (session) => session.putItem(JSON.stringify(item))),
    [run]
  )

  const updateItem = useCallback(
    (item: VaultItemJson, expectedRevision: number) =>
      run(async (session) => {
        await session.updateItem(JSON.stringify(item), expectedRevision)
      }),
    [run]
  )

  const trashItem = useCallback(
    (id: string, expectedRevision: number) =>
      run(async (session) => {
        await session.trashItem(id, expectedRevision, Date.now())
      }),
    [run]
  )

  const restoreItem = useCallback(
    (id: string, expectedRevision: number) =>
      run(async (session) => {
        await session.restoreItem(id, expectedRevision)
      }),
    [run]
  )

  const purgeItem = useCallback(
    (id: string, expectedRevision: number) =>
      run(async (session) => {
        await session.purgeItem(id, expectedRevision)
      }),
    [run]
  )

  const getAttachments = useCallback(
    async (entry: EditableEntry): Promise<AttachmentSummary[]> => {
      const session = sessionRef.current
      if (!session || !session.isUnlocked()) return []
      try {
        setError(null)
        return await session.listAttachments(
          entry.item.id,
          entry.item.attachments
        )
      } catch (attachmentError: unknown) {
        setError(errorMessage(attachmentError))
        return []
      }
    },
    []
  )

  const addAttachment = useCallback(
    async (entry: EditableEntry, file: File): Promise<EditableEntry | null> => {
      let updated: EditableEntry | null = null
      const saved = await run(async (session) => {
        const result = await session.addAttachment(
          entry.item.id,
          entry.revision,
          file
        )
        const item = JSON.parse(session.getItem(entry.item.id)) as VaultItemJson
        updated = { item, revision: result.itemRevision }
      })
      return saved ? updated : null
    },
    [run]
  )

  const deleteAttachment = useCallback(
    async (
      entry: EditableEntry,
      summary: AttachmentSummary
    ): Promise<EditableEntry | null> => {
      let updated: EditableEntry | null = null
      const saved = await run(async (session) => {
        const revision = await session.deleteAttachment(
          entry.item.id,
          entry.revision,
          summary,
          Date.now()
        )
        const item = JSON.parse(session.getItem(entry.item.id)) as VaultItemJson
        updated = { item, revision }
      })
      return saved ? updated : null
    },
    [run]
  )

  const downloadAttachment = useCallback(
    async (
      entry: EditableEntry,
      summary: AttachmentSummary
    ): Promise<{ summary: AttachmentSummary; blob: Blob } | null> => {
      const session = sessionRef.current
      if (!session || !session.isUnlocked()) return null
      try {
        setError(null)
        const downloaded = await session.downloadAttachment(
          entry.item.id,
          summary.id
        )
        if (downloaded.summary.revision !== summary.revision) {
          throw new Error(
            "The attachment changed before it could be downloaded."
          )
        }
        return downloaded
      } catch (attachmentError: unknown) {
        setError(errorMessage(attachmentError))
        return null
      }
    },
    []
  )

  const getItem = useCallback((entry: ListedEntry): EditableEntry | null => {
    const session = sessionRef.current
    if (!session || !session.isUnlocked()) return null

    try {
      const item = JSON.parse(session.getItem(entry.item.id)) as VaultItemJson
      return { item, revision: entry.revision }
    } catch (getError: unknown) {
      setError(errorMessage(getError))
      return null
    }
  }, [])

  const getDeadlines = useCallback((): DeadlineSummary[] => {
    const session = sessionRef.current
    if (!session || !session.isUnlocked()) return []

    try {
      setError(null)
      return session.listDeadlines(localTodayYmd())
    } catch (deadlineError: unknown) {
      setError(errorMessage(deadlineError))
      return []
    }
  }, [])

  const getEmergencyCard = useCallback(
    () => emergencyCardSnapshot,
    [emergencyCardSnapshot]
  )

  const setEmergencyCard = useCallback(
    (card: EmergencyCard) =>
      run(async (session) => {
        await session.setEmergencyCard(card)
      }),
    [run]
  )

  const setEmergencyContacts = useCallback(
    (contacts: EmergencyContact[]) =>
      run(async (session) => {
        const current = session.getEmergencyCard()?.card ?? {
          selected_item_ids: [],
          contacts: [],
          principals: [],
          retired_principal_ids: [],
          retired_device_ids: [],
          retired_signing_public_key_hexes: [],
          instructions: "",
        }
        await session.setEmergencyCard({ ...current, contacts })
      }),
    [run]
  )

  const setEmergencyInstructions = useCallback(
    (instructions: string) =>
      run(async (session) => {
        const current = session.getEmergencyCard()?.card ?? {
          selected_item_ids: [],
          contacts: [],
          principals: [],
          retired_principal_ids: [],
          retired_device_ids: [],
          retired_signing_public_key_hexes: [],
          instructions: "",
        }
        await session.setEmergencyCard({ ...current, instructions })
      }),
    [run]
  )

  const setTrustedPrincipals = useCallback(
    (principals: TrustedPrincipal[]) =>
      run(async (session) => {
        const current = session.getEmergencyCard()?.card ?? {
          selected_item_ids: [],
          contacts: [],
          principals: [],
          retired_principal_ids: [],
          retired_device_ids: [],
          retired_signing_public_key_hexes: [],
          instructions: "",
        }
        await session.setEmergencyCard({ ...current, principals })
      }),
    [run]
  )

  const createTrustedDevicePairingChallenge = useCallback(
    (principalId: string, deviceId: string): PairingChallengeV1 | null => {
      const session = sessionRef.current
      if (!session || !session.isUnlocked()) return null
      try {
        setError(null)
        return session.createTrustedDevicePairingChallenge(principalId, deviceId)
      } catch (pairingError: unknown) {
        setError(errorMessage(pairingError))
        return null
      }
    },
    []
  )

  const completeTrustedDevicePairing = useCallback(
    (proof: PairingProofV1) =>
      run(async (session) => {
        await session.completeTrustedDevicePairing(proof)
      }),
    [run]
  )

  const listBrowserDeviceIdentities = useCallback(async (): Promise<
    DeviceRegistrationV1[]
  > => {
    try {
      setError(null)
      return await browserDeviceKeyStore.listIdentities()
    } catch (deviceError: unknown) {
      setError(errorMessage(deviceError))
      return []
    }
  }, [])

  const createBrowserDeviceIdentity = useCallback(async (): Promise<
    DeviceRegistrationV1 | null
  > => {
    try {
      setError(null)
      return await browserDeviceKeyStore.createIdentity(newId())
    } catch (deviceError: unknown) {
      setError(errorMessage(deviceError))
      return null
    }
  }, [])

  const deleteBrowserDeviceIdentity = useCallback(
    async (deviceId: string): Promise<boolean> => {
      try {
        setError(null)
        await browserDeviceKeyStore.deleteIdentity(deviceId)
        return true
      } catch (deviceError: unknown) {
        setError(errorMessage(deviceError))
        return false
      }
    },
    []
  )

  const answerBrowserPairingChallenge = useCallback(
    async (challenge: PairingChallengeV1): Promise<PairingProofV1 | null> => {
      try {
        setError(null)
        return await browserDeviceKeyStore.answerPairingChallenge(challenge)
      } catch (deviceError: unknown) {
        setError(errorMessage(deviceError))
        return null
      }
    },
    []
  )

  const installRecoveryKit = useCallback(
    () =>
      run(async (session) => {
        const secret = wasmStatics.generateRecoverySecret()
        await session.installRecoveryKit(secret)
        setGeneratedSecret(secret)
      }),
    [run]
  )

  const clearGeneratedSecret = useCallback(() => setGeneratedSecret(null), [])

  const generatePassword = useCallback((length: number) => {
    try {
      return wasmStatics.generatePassword(length)
    } catch (generateError: unknown) {
      setError(errorMessage(generateError))
      return ""
    }
  }, [])

  const exportReadableVault = useCallback((): string | null => {
    const session = sessionRef.current
    if (!session || !session.isUnlocked()) return null

    try {
      setError(null)
      return session.exportReadableVault()
    } catch (exportError: unknown) {
      setError(errorMessage(exportError))
      return null
    }
  }, [])

  const exportEncryptedSnapshot = useCallback(async (): Promise<
    string | null
  > => {
    const session = sessionRef.current
    if (!session || !session.isUnlocked()) return null

    try {
      setError(null)
      return await session.exportEncryptedSnapshot()
    } catch (exportError: unknown) {
      setError(errorMessage(exportError))
      return null
    }
  }, [])

  return {
    phase,
    items,
    trashedItems,
    error,
    hasRecoveryKit,
    generatedSecret,
    syncStatus,
    newId,
    generatePassword,
    exportReadableVault,
    exportEncryptedSnapshot,
    create,
    importEncryptedBackup,
    unlock,
    unlockWithRecoveryKit,
    changePassphrase,
    lock,
    putItem,
    updateItem,
    trashItem,
    restoreItem,
    purgeItem,
    getAttachments,
    addAttachment,
    deleteAttachment,
    downloadAttachment,
    getItem,
    getDeadlines,
    getEmergencyCard,
    setEmergencyCard,
    setEmergencyContacts,
    setEmergencyInstructions,
    setTrustedPrincipals,
    createTrustedDevicePairingChallenge,
    completeTrustedDevicePairing,
    listBrowserDeviceIdentities,
    createBrowserDeviceIdentity,
    deleteBrowserDeviceIdentity,
    answerBrowserPairingChallenge,
    installRecoveryKit,
    clearGeneratedSecret,
    generateAccountSecret,
    enrollSync,
    retrySync,
    resetInvalidSyncConfiguration,
    syncNow: performSync,
  }
}
