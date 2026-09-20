interface WindowScheduleTarget {
  setInterval(handler: () => void, timeout: number): number
  clearInterval(id: number): void
  addEventListener(type: "online", handler: () => void): void
  removeEventListener(type: "online", handler: () => void): void
}

interface DocumentScheduleTarget {
  readonly visibilityState: DocumentVisibilityState
  addEventListener(type: "visibilitychange", handler: () => void): void
  removeEventListener(type: "visibilitychange", handler: () => void): void
}

/** Schedule bounded best-effort sync while the unlocked page remains alive. */
export function startBrowserSyncSchedule(
  request: () => void,
  options: {
    windowTarget?: WindowScheduleTarget
    documentTarget?: DocumentScheduleTarget
    intervalMs?: number
  } = {}
): () => void {
  const windowTarget = options.windowTarget ?? window
  const documentTarget = options.documentTarget ?? document
  const intervalMs = options.intervalMs ?? 30_000
  if (!Number.isSafeInteger(intervalMs) || intervalMs < 1_000) {
    throw new Error("The browser sync interval is invalid.")
  }
  const onVisible = () => {
    if (documentTarget.visibilityState === "visible") request()
  }
  const interval = windowTarget.setInterval(request, intervalMs)
  windowTarget.addEventListener("online", request)
  documentTarget.addEventListener("visibilitychange", onVisible)
  return () => {
    windowTarget.clearInterval(interval)
    windowTarget.removeEventListener("online", request)
    documentTarget.removeEventListener("visibilitychange", onVisible)
  }
}
