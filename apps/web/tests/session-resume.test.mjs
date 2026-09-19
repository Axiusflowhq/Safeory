import assert from "node:assert/strict"
import test from "node:test"

import {
  refreshSessionResume,
  resumeSessionFromReload,
} from "../lib/vault/session-resume.ts"

class MemorySessionStorage {
  #values = new Map()

  getItem(key) {
    return this.#values.get(key) ?? null
  }

  removeItem(key) {
    this.#values.delete(key)
  }

  setItem(key, value) {
    this.#values.set(key, String(value))
  }
}

test("session resume rotation is stored only after async persistence resolves", async () => {
  globalThis.sessionStorage = new MemorySessionStorage()
  let resolveCredential
  const credential = new Promise((resolve) => {
    resolveCredential = resolve
  })

  const refresh = refreshSessionResume({
    createSessionResume: () => credential,
  })

  assert.equal(sessionStorage.getItem("safeory:session-resume:v1"), null)
  resolveCredential('{"format_version":2,"secret":"rotated"}')
  await refresh
  assert.equal(
    sessionStorage.getItem("safeory:session-resume:v1"),
    '{"format_version":2,"secret":"rotated"}'
  )
})

test("durability failure clears stale resume material and propagates", async () => {
  globalThis.sessionStorage = new MemorySessionStorage()
  sessionStorage.setItem("safeory:session-resume:v1", "stale")
  const durabilityError = new Error("Saving the encrypted vault failed")
  durabilityError.name = "VaultDurabilityError"

  await assert.rejects(
    refreshSessionResume({
      createSessionResume: async () => {
        throw durabilityError
      },
    }),
    (error) => error === durabilityError
  )
  assert.equal(sessionStorage.getItem("safeory:session-resume:v1"), null)
})

test("async resume rejection is awaited and prevents credential rotation", async () => {
  globalThis.sessionStorage = new MemorySessionStorage()
  const resumeError = new Error("stale resume credential")
  let rotationCalled = false

  await assert.rejects(
    resumeSessionFromReload(
      {
        unlockWithSessionResume: async () => {
          await Promise.resolve()
          throw resumeError
        },
        createSessionResume: async () => {
          rotationCalled = true
          return "must-not-be-created"
        },
      },
      "stale"
    ),
    (error) => error === resumeError
  )
  assert.equal(rotationCalled, false)
})
