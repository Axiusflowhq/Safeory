/** Browser-side adapter between generated `vault-wasm` and VaultSession. */

import init, { WasmVault } from "vault-wasm"
import { VaultSession, type WasmStatics, type WasmVaultLike } from "@safeory/contracts"

let ready: Promise<void> | null = null

/** Initialize the generated WASM module exactly once in the browser bundle. */
export function initVaultWasm(): Promise<void> {
  ready ??= (init as unknown as (arg?: unknown) => Promise<unknown>)().then(
    () => undefined
  )
  return ready
}

/** Construct a fresh vault or restore the existing encrypted snapshot. */
export function wasmVaultFactory(snapshotJson: string | null): WasmVaultLike {
  return snapshotJson === null
    ? (new WasmVault() as unknown as WasmVaultLike)
    : (WasmVault.fromSnapshotJson(snapshotJson) as unknown as WasmVaultLike)
}

export const wasmStatics: WasmStatics = {
  generateRecoverySecret: () => WasmVault.generateRecoverySecret(),
  generatePassword: (length: number) => WasmVault.generatePassword(length),
}

/** Load browser persistence only after the WASM runtime is initialized. */
export async function loadVaultSession(): Promise<VaultSession> {
  await initVaultWasm()
  return VaultSession.load(wasmVaultFactory)
}
