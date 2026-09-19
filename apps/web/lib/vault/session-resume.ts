const SESSION_RESUME_KEY = "safeory:session-resume:v1"
const MAX_SESSION_RESUME_BYTES = 4 * 1024

function isReloadNavigation(): boolean {
  const [entry] = performance.getEntriesByType(
    "navigation"
  ) as PerformanceNavigationTiming[]
  return entry?.type === "reload"
}

/**
 * Return a same-tab reload credential only for an actual document reload.
 * A normal navigation, history restore, or newly opened tab clears stale
 * resume material instead of silently carrying an unlocked vault forward.
 */
export function loadSessionResumeForReload(): string | null {
  try {
    if (!isReloadNavigation()) {
      clearSessionResume()
      return null
    }

    const payload = sessionStorage.getItem(SESSION_RESUME_KEY)
    if (
      payload === null ||
      payload.length === 0 ||
      payload.length > MAX_SESSION_RESUME_BYTES
    ) {
      clearSessionResume()
      return null
    }
    return payload
  } catch {
    return null
  }
}

export function saveSessionResume(payload: string): void {
  try {
    if (payload.length === 0 || payload.length > MAX_SESSION_RESUME_BYTES) {
      throw new Error("invalid browser session resume payload")
    }
    sessionStorage.setItem(SESSION_RESUME_KEY, payload)
  } catch {
    // sessionStorage can be unavailable under restrictive browser policies.
    // The vault remains usable; it simply falls back to requiring unlock on
    // the next reload.
  }
}

export function clearSessionResume(): boolean {
  try {
    sessionStorage.removeItem(SESSION_RESUME_KEY)
    if (sessionStorage.getItem(SESSION_RESUME_KEY) === null) {
      return true
    }
  } catch {
    // Fall through to a tombstone overwrite. This avoids leaving a usable
    // capability behind if removal alone is blocked or transiently fails.
  }

  try {
    sessionStorage.setItem(SESSION_RESUME_KEY, "")
    return sessionStorage.getItem(SESSION_RESUME_KEY) === ""
  } catch {
    return false
  }
}
