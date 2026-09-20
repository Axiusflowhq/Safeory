"use client"

import { useCallback, useEffect, useRef, useState } from "react"

import {
  VaultDurabilityError,
  type AttachmentSummary,
  type DeadlineSummary,
  type EmergencyCard,
  type EmergencyContact,
  type TrashedItemSummary,
  type TrustedPrincipal,
  type VaultSession,
} from "@safeory/contracts"
import { newId, type VaultItemJson } from "./items"
import {
  clearSessionResume,
  loadSessionResumeForReload,
  refreshSessionResume,
  resumeSessionFromReload,
} from "./session-resume"
import { loadVaultSession, wasmStatics } from "./vault"

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
  const [phase, setPhase] = useState<VaultPhase>("loading")
  const [items, setItems] = useState<ListedEntry[]>([])
  const [trashedItems, setTrashedItems] = useState<TrashedItemSummary[]>([])
  const [error, setError] = useState<string | null>(null)
  const [hasRecoveryKit, setHasRecoveryKit] = useState(false)
  const [generatedSecret, setGeneratedSecret] = useState<string | null>(null)
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
  }, [refresh])

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
          return true
        })
        .catch((operationError: unknown) => {
          if (operationError instanceof VaultDurabilityError) {
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
    [refresh]
  )

  const create = useCallback(
    (passphrase: string) =>
      run(async (session) => {
        await session.create(passphrase)
        await refreshSessionResume(session)
        setPhase("open")
      }),
    [run]
  )

  const importEncryptedBackup = useCallback(
    (snapshotJson: string, passphrase: string) =>
      run(async (session) => {
        await session.importEncryptedSnapshot(snapshotJson, passphrase)
        await refreshSessionResume(session)
        setPhase("open")
      }),
    [run]
  )

  const unlock = useCallback(
    (passphrase: string) =>
      run(async (session) => {
        await session.unlock(passphrase)
        await refreshSessionResume(session)
        setPhase("open")
      }),
    [run]
  )

  const unlockWithRecoveryKit = useCallback(
    (secretHex: string) =>
      run(async (session) => {
        await session.unlockWithRecoveryKit(secretHex)
        await refreshSessionResume(session)
        setPhase("open")
      }),
    [run]
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
      setItems([])
      setTrashedItems([])
      setEmergencyCardSnapshot(null)
      setPhase("unlock")
    } catch (lockError: unknown) {
      setError(errorMessage(lockError))
    }
  }, [])

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
    installRecoveryKit,
    clearGeneratedSecret,
  }
}
