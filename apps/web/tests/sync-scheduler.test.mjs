import assert from "node:assert/strict"
import test from "node:test"

import { startBrowserSyncSchedule } from "../lib/vault/sync-scheduler.ts"

class FakeWindow {
  intervals = new Map()
  listeners = new Set()
  nextId = 1

  setInterval(handler) {
    const id = this.nextId++
    this.intervals.set(id, handler)
    return id
  }

  clearInterval(id) {
    this.intervals.delete(id)
  }

  addEventListener(_type, handler) {
    this.listeners.add(handler)
  }

  removeEventListener(_type, handler) {
    this.listeners.delete(handler)
  }

  online() {
    for (const handler of this.listeners) handler()
  }

  tick() {
    for (const handler of this.intervals.values()) handler()
  }
}

class FakeDocument {
  visibilityState = "hidden"
  listeners = new Set()

  addEventListener(_type, handler) {
    this.listeners.add(handler)
  }

  removeEventListener(_type, handler) {
    this.listeners.delete(handler)
  }

  visible() {
    this.visibilityState = "visible"
    for (const handler of this.listeners) handler()
  }

  hidden() {
    this.visibilityState = "hidden"
    for (const handler of this.listeners) handler()
  }
}

test("sync scheduling responds to interval, connectivity, and visible foreground", () => {
  const windowTarget = new FakeWindow()
  const documentTarget = new FakeDocument()
  let requests = 0
  const stop = startBrowserSyncSchedule(() => { requests += 1 }, {
    windowTarget,
    documentTarget,
  })

  windowTarget.tick()
  windowTarget.online()
  documentTarget.hidden()
  documentTarget.visible()
  assert.equal(requests, 3)

  stop()
  windowTarget.tick()
  windowTarget.online()
  documentTarget.visible()
  assert.equal(requests, 3)
})

test("sync scheduling rejects an accidental hot loop", () => {
  assert.throws(
    () => startBrowserSyncSchedule(() => undefined, {
      windowTarget: new FakeWindow(),
      documentTarget: new FakeDocument(),
      intervalMs: 999,
    }),
    /interval/,
  )
})
