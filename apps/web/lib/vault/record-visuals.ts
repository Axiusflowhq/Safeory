import {
  BankIcon,
  Building03Icon,
  Car01Icon,
  DocumentValidationIcon,
  LockPasswordIcon,
  NoteIcon,
  PackageIcon,
  ReceiptTextIcon,
  RepeatIcon,
  ShieldCheckIcon,
} from "@hugeicons/core-free-icons"

import type { ItemKind } from "@/lib/vault/items"

/**
 * Canonical record-type iconography for the web app.
 *
 * Keep these mappings centralized so the same record is represented by the
 * same Hugeicon in the sidebar, search results, lists, and lifecycle views.
 */
export const ITEM_KIND_ICONS = {
  password: LockPasswordIcon,
  secure_note: NoteIcon,
  document: DocumentValidationIcon,
  insurance: ShieldCheckIcon,
  financial: BankIcon,
  property: Building03Icon,
  vehicle: Car01Icon,
  possession: PackageIcon,
  receipt: ReceiptTextIcon,
  subscription: RepeatIcon,
} satisfies Record<ItemKind, (typeof LockPasswordIcon)>

export function itemKindIcon(kind: string) {
  return ITEM_KIND_ICONS[kind as ItemKind] ?? DocumentValidationIcon
}
