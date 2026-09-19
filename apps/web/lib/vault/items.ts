/**
 * Browser UI helpers for the JSON shape accepted by `vault-wasm`.
 *
 * Keep this module free of React/Next runtime dependencies so item metadata can
 * be imported by either client components or build-time tooling. Browser-only
 * APIs are touched only when `newId()` is actually called.
 */

export type ItemKind =
  | "secure_note"
  | "password"
  | "document"
  | "insurance"
  | "financial"
  | "property"
  | "vehicle"
  | "possession"
  | "receipt"
  | "subscription"

/**
 * Mirrors `vault_models::VaultItem` while allowing forward-compatible fields
 * added by the core to survive a UI edit round-trip.
 */
export interface VaultItemJson {
  id: string
  kind: ItemKind | string
  title: string
  links: string[]
  attachments: string[]
  legacy_disposition: string
  account_closure_plan: { disposition: string; instructions: string }
  fields: Record<string, string>
  notes: string | null
  [key: string]: unknown
}

export const ITEM_KINDS: { kind: ItemKind; label: string }[] = [
  { kind: "password", label: "Credentials" },
  { kind: "secure_note", label: "Secure Notes" },
  { kind: "document", label: "Documents" },
  { kind: "insurance", label: "Insurance" },
  { kind: "financial", label: "Financial" },
  { kind: "property", label: "Property" },
  { kind: "vehicle", label: "Vehicles" },
  { kind: "possession", label: "Possessions" },
  { kind: "receipt", label: "Receipts" },
  { kind: "subscription", label: "Subscriptions" },
]

export function kindLabel(kind: string): string {
  return ITEM_KINDS.find((entry) => entry.kind === kind)?.label ?? kind
}

function baseItem(id: string, kind: ItemKind, title: string): VaultItemJson {
  return {
    id,
    kind,
    title,
    links: [],
    attachments: [],
    legacy_disposition: "unspecified",
    account_closure_plan: { disposition: "unspecified", instructions: "" },
    fields: {},
    notes: null,
  }
}

export function newSecureNote(
  id: string,
  title: string,
  body: string
): VaultItemJson {
  const item = baseItem(id, "secure_note", title)
  item.fields = { body }
  return item
}

export interface FieldSpec {
  key: string
  label: string
  /** "secret" renders masked with a reveal toggle; "date" is a date input. */
  kind?: "text" | "secret" | "date" | "textarea"
  placeholder?: string
}

/** Editable field keys per user-facing record kind. */
export const KIND_FIELDS: Partial<Record<ItemKind, FieldSpec[]>> = {
  password: [
    { key: "username", label: "Username / email" },
    { key: "password", label: "Password", kind: "secret" },
    { key: "website", label: "Website", placeholder: "https://…" },
  ],
  secure_note: [{ key: "body", label: "Contents", kind: "textarea" }],
  document: [
    { key: "document_number", label: "Document number", kind: "secret" },
    { key: "issuer", label: "Issuer" },
    { key: "expiry", label: "Expiry", kind: "date" },
  ],
  insurance: [
    { key: "provider", label: "Provider" },
    { key: "policy_type", label: "Policy type" },
    { key: "policy_number", label: "Policy number", kind: "secret" },
    { key: "renewal", label: "Renewal date", kind: "date" },
  ],
  financial: [
    { key: "institution", label: "Institution" },
    { key: "account_type", label: "Account type" },
    { key: "account_number", label: "Account number", kind: "secret" },
    { key: "currency", label: "Currency" },
  ],
  property: [
    { key: "property_type", label: "Property type" },
    { key: "address", label: "Address" },
    { key: "ownership", label: "Ownership" },
    { key: "property_reference", label: "Reference", kind: "secret" },
  ],
  vehicle: [
    { key: "make", label: "Make" },
    { key: "model", label: "Model" },
    { key: "year", label: "Year" },
    { key: "registration_number", label: "Registration", kind: "secret" },
    { key: "vin", label: "VIN", kind: "secret" },
    { key: "renewal", label: "Renewal date", kind: "date" },
  ],
  possession: [
    { key: "category", label: "Category" },
    { key: "location", label: "Location" },
    { key: "brand", label: "Brand" },
    { key: "model", label: "Model" },
    { key: "serial_number", label: "Serial number", kind: "secret" },
    { key: "purchase_date", label: "Purchase date", kind: "date" },
    { key: "purchase_price", label: "Purchase price" },
    { key: "store", label: "Store" },
    { key: "warranty_expiry", label: "Warranty expiry", kind: "date" },
  ],
  receipt: [
    { key: "merchant", label: "Merchant" },
    { key: "purchase_date", label: "Purchase date", kind: "date" },
    { key: "amount", label: "Amount" },
    { key: "currency", label: "Currency" },
    { key: "receipt_reference", label: "Receipt reference", kind: "secret" },
    { key: "return_by", label: "Return by", kind: "date" },
    { key: "refund_due", label: "Refund due", kind: "date" },
  ],
  subscription: [
    { key: "provider", label: "Provider" },
    { key: "plan", label: "Plan" },
    { key: "amount", label: "Amount" },
    { key: "currency", label: "Currency" },
    { key: "billing_cycle", label: "Billing cycle" },
    { key: "next_renewal", label: "Next renewal", kind: "date" },
  ],
}

/** Construct a new item using the current portable VaultItem defaults. */
export function buildItem(
  id: string,
  kind: ItemKind,
  title: string,
  fields: Record<string, string>,
  notes: string
): VaultItemJson {
  const item = baseItem(id, kind, title)
  item.fields = { ...fields }
  item.notes = notes.length > 0 ? notes : null
  return item
}

/**
 * Patch only fields modeled by the editor while preserving the complete
 * decrypted item. This intentionally retains links, attachments, lifecycle
 * metadata, future top-level properties, and unmodeled fields such as receipt
 * tracking metadata.
 */
export function buildEditedItem(
  existing: VaultItemJson,
  kind: ItemKind,
  title: string,
  fields: Record<string, string>,
  notes: string
): VaultItemJson {
  const nextFields = { ...existing.fields }
  for (const spec of KIND_FIELDS[kind] ?? []) {
    if (Object.hasOwn(fields, spec.key)) {
      nextFields[spec.key] = fields[spec.key] ?? ""
    }
  }

  return {
    ...existing,
    id: existing.id,
    kind,
    title,
    fields: nextFields,
    notes: notes.length > 0 ? notes : null,
  }
}

export function newCredential(
  id: string,
  title: string,
  username: string,
  password: string,
  website: string,
  notes: string
): VaultItemJson {
  const item = baseItem(id, "password", title)
  item.fields = { username, password, website }
  item.notes = notes.length > 0 ? notes : null
  return item
}

/** Generate a UUID v4 using the browser Web Crypto API. */
export function newId(): string {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  bytes[6] = (bytes[6]! & 0x0f) | 0x40
  bytes[8] = (bytes[8]! & 0x3f) | 0x80
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0"))
  return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex
    .slice(6, 8)
    .join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10, 16).join("")}`
}
