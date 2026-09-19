/**
 * Extension persistence: the ciphertext `KVSnapshot` lives in
 * `chrome.storage.local` (survives service-worker restarts). Only ciphertext —
 * never keys or plaintext. Session unlock state is kept in the background
 * worker's memory (and cleared when the worker is torn down), matching the
 * "keys never persist" rule.
 */

const SNAPSHOT_KEY = "safeory.snapshot";

export async function saveSnapshot(snapshotJson: string): Promise<void> {
  await chrome.storage.local.set({ [SNAPSHOT_KEY]: snapshotJson });
}

export async function loadSnapshot(): Promise<string | null> {
  const result = await chrome.storage.local.get(SNAPSHOT_KEY);
  const value = result[SNAPSHOT_KEY];
  return typeof value === "string" ? value : null;
}

export async function clearSnapshot(): Promise<void> {
  await chrome.storage.local.remove(SNAPSHOT_KEY);
}
