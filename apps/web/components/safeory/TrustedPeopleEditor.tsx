"use client"

import { useState } from "react"
import type {
  EmergencyContact,
  TrustedDevice,
  TrustedPrincipal,
} from "@safeory/contracts"
import {
  Delete02Icon,
  UserAdd01Icon,
  UserMultipleIcon,
} from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { newId } from "@/lib/vault/items"

interface TrustedPeopleFieldsProps {
  contacts: EmergencyContact[]
  onChange: (contacts: EmergencyContact[]) => void
}

interface TrustedPeopleEditorProps {
  initialContacts: EmergencyContact[]
  initialPrincipals: TrustedPrincipal[]
  onSaveContacts: (contacts: EmergencyContact[]) => Promise<boolean>
  onSavePrincipals: (principals: TrustedPrincipal[]) => Promise<boolean>
}

const emptyContact: EmergencyContact = {
  name: "",
  relation: "",
  phone: "",
  email: "",
  notes: "",
}

function emptyPrincipal(): TrustedPrincipal {
  return {
    id: newId(),
    name: "",
    relation: "",
    devices: [],
  }
}

function emptyDevice(): TrustedDevice {
  return {
    id: newId(),
    label: "",
    encryption_public_key_hex: "",
    signing_public_key_hex: null,
  }
}

export function TrustedPeopleFields({
  contacts,
  onChange,
}: TrustedPeopleFieldsProps) {
  function updateContact(index: number, patch: Partial<EmergencyContact>) {
    onChange(
      contacts.map((contact, contactIndex) =>
        contactIndex === index ? { ...contact, ...patch } : contact
      )
    )
  }

  function addContact() {
    onChange([...contacts, { ...emptyContact }])
  }

  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-medium">Trusted people</h3>
          <p className="mt-0.5 max-w-[65ch] text-sm text-pretty text-[var(--text-secondary)]">
            Add people who should be contacted or can help carry out your
            continuity plan.
          </p>
        </div>
        {contacts.length > 0 ? (
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={addContact}
          >
            <HugeiconsIcon
              icon={UserAdd01Icon}
              strokeWidth={2}
              data-icon="inline-start"
            />
            Add person
          </Button>
        ) : null}
      </div>

      {contacts.length === 0 ? (
        <div className="rounded-[var(--radius-default)] border border-dashed bg-[var(--surface-secondary)] px-5 py-8 text-center">
          <div className="mx-auto mb-3 flex size-9 items-center justify-center rounded-[var(--radius-large)] bg-[var(--surface-secondary)]">
            <HugeiconsIcon
              icon={UserMultipleIcon}
              strokeWidth={2}
              className="size-4 text-[var(--text-secondary)]"
            />
          </div>
          <p className="text-sm font-medium">No trusted people yet</p>
          <p className="mx-auto mt-1 max-w-[65ch] text-sm text-pretty text-[var(--text-secondary)]">
            Add someone you would want contacted if you could not manage your
            vault yourself.
          </p>
          <Button
            type="button"
            variant="secondary"
            size="sm"
            className="mt-4"
            onClick={addContact}
          >
            <HugeiconsIcon
              icon={UserAdd01Icon}
              strokeWidth={2}
              data-icon="inline-start"
            />
            Add person
          </Button>
        </div>
      ) : (
        <div className="space-y-3">
          {contacts.map((contact, index) => (
            <div
              key={index}
              className="rounded-[var(--radius-default)] border bg-[var(--surface)] p-4 shadow-[var(--fancy-shadow-basic)]"
            >
              <div className="mb-4 flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <p
                    className="truncate text-sm font-medium"
                    title={contact.name.trim() || `Person ${index + 1}`}
                  >
                    {contact.name.trim() || `Person ${index + 1}`}
                  </p>
                  <p className="text-xs text-[var(--text-secondary)]">
                    {contact.relation.trim() || "Relationship not specified"}
                  </p>
                </div>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  aria-label={`Remove person ${index + 1}`}
                  onClick={() =>
                    onChange(
                      contacts.filter(
                        (_, contactIndex) => contactIndex !== index
                      )
                    )
                  }
                >
                  <HugeiconsIcon
                    icon={Delete02Icon}
                    strokeWidth={2}
                    className="text-[var(--danger)]"
                  />
                </Button>
              </div>

              <FieldGroup className="grid gap-4 sm:grid-cols-2">
                <Field>
                  <FieldLabel htmlFor={`safeory-contact-${index}-name`}>
                    Name
                  </FieldLabel>
                  <Input
                    id={`safeory-contact-${index}-name`}
                    value={contact.name}
                    onChange={(event) =>
                      updateContact(index, { name: event.target.value })
                    }
                    placeholder="Full name"
                  />
                </Field>
                <Field>
                  <FieldLabel htmlFor={`safeory-contact-${index}-relation`}>
                    Relationship
                  </FieldLabel>
                  <Input
                    id={`safeory-contact-${index}-relation`}
                    value={contact.relation}
                    onChange={(event) =>
                      updateContact(index, { relation: event.target.value })
                    }
                    placeholder="Partner, sibling, adviser…"
                  />
                </Field>
                <Field>
                  <FieldLabel htmlFor={`safeory-contact-${index}-phone`}>
                    Phone
                  </FieldLabel>
                  <Input
                    id={`safeory-contact-${index}-phone`}
                    type="tel"
                    inputMode="tel"
                    value={contact.phone}
                    onChange={(event) =>
                      updateContact(index, { phone: event.target.value })
                    }
                    placeholder="+1 555 0100"
                  />
                </Field>
                <Field>
                  <FieldLabel htmlFor={`safeory-contact-${index}-email`}>
                    Email
                  </FieldLabel>
                  <Input
                    id={`safeory-contact-${index}-email`}
                    type="email"
                    inputMode="email"
                    value={contact.email}
                    onChange={(event) =>
                      updateContact(index, { email: event.target.value })
                    }
                    placeholder="name@example.com"
                  />
                </Field>
                <Field className="sm:col-span-2">
                  <FieldLabel htmlFor={`safeory-contact-${index}-notes`}>
                    Notes
                  </FieldLabel>
                  <Textarea
                    id={`safeory-contact-${index}-notes`}
                    value={contact.notes}
                    onChange={(event) =>
                      updateContact(index, { notes: event.target.value })
                    }
                    placeholder="Optional context or instructions for this person"
                    rows={3}
                    className="resize-y"
                  />
                </Field>
              </FieldGroup>
            </div>
          ))}
        </div>
      )}
    </section>
  )
}

export function TrustedPeopleEditor({
  initialContacts,
  initialPrincipals,
  onSaveContacts,
  onSavePrincipals,
}: TrustedPeopleEditorProps) {
  const [contacts, setContacts] = useState<EmergencyContact[]>(initialContacts)
  const [principals, setPrincipals] =
    useState<TrustedPrincipal[]>(initialPrincipals)
  const [principalError, setPrincipalError] = useState<string | null>(null)
  const [persistedDeviceIds, setPersistedDeviceIds] = useState(
    () =>
      new Set(
        initialPrincipals.flatMap((principal) =>
          principal.devices.map((device) => device.id)
        )
      )
  )

  function updatePrincipal(index: number, patch: Partial<TrustedPrincipal>) {
    setPrincipals((current) =>
      current.map((principal, principalIndex) =>
        principalIndex === index ? { ...principal, ...patch } : principal
      )
    )
  }

  function updateDevice(
    principalIndex: number,
    deviceIndex: number,
    patch: Partial<TrustedDevice>
  ) {
    setPrincipals((current) =>
      current.map((principal, currentPrincipalIndex) => {
        if (currentPrincipalIndex !== principalIndex) return principal
        return {
          ...principal,
          devices: principal.devices.map((device, currentDeviceIndex) =>
            currentDeviceIndex === deviceIndex ? { ...device, ...patch } : device
          ),
        }
      })
    )
  }

  function normalizedPrincipals(): TrustedPrincipal[] | null {
    const deviceKeys = new Set<string>()
    const normalized: TrustedPrincipal[] = []
    for (const principal of principals) {
      const name = principal.name.trim()
      if (name.length === 0) {
        setPrincipalError("Every access identity needs a name.")
        return null
      }
      const devices: TrustedDevice[] = []
      for (const device of principal.devices) {
        const key = device.encryption_public_key_hex.trim().toLowerCase()
        if (!/^[0-9a-f]{64}$/.test(key) || /^0{64}$/.test(key)) {
          setPrincipalError(
            `${name} has an invalid recipient-encryption key. Use exactly 64 hexadecimal characters.`
          )
          return null
        }
        if (deviceKeys.has(key)) {
          setPrincipalError(
            "The same recipient-encryption key cannot be bound to more than one trusted device."
          )
          return null
        }
        deviceKeys.add(key)
        devices.push({
          ...device,
          label: device.label.trim(),
          encryption_public_key_hex: key,
        })
      }
      normalized.push({
        ...principal,
        name,
        relation: principal.relation.trim(),
        devices,
      })
    }
    setPrincipalError(null)
    return normalized
  }

  return (
    <div className="space-y-10">
      <form
        className="space-y-6"
        onSubmit={async (event) => {
          event.preventDefault()
          const savedContacts = contacts.filter(
            (contact) => contact.name.trim().length > 0
          )
          if (await onSaveContacts(savedContacts)) setContacts(savedContacts)
        }}
      >
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex items-center gap-2">
            <div className="flex size-9 items-center justify-center rounded-[var(--radius-default)] border bg-[var(--surface-secondary)]">
              <HugeiconsIcon
                icon={UserMultipleIcon}
                strokeWidth={1.8}
                className="size-4 text-[var(--icon-active)]"
              />
            </div>
            <div>
              <h2 className="text-lg font-semibold tracking-tight">
                Continuity contacts
              </h2>
              <p className="max-w-[65ch] text-sm text-pretty text-[var(--text-secondary)]">
                People to contact during an emergency, stored inside the
                encrypted Emergency Card.
              </p>
            </div>
          </div>
          <Badge variant="outline">Encrypted</Badge>
        </div>

        <Field>
          <FieldDescription>
            A contact is not an access principal. Adding or removing a contact
            never creates, changes, or revokes an item access rule.
          </FieldDescription>
        </Field>

        <TrustedPeopleFields contacts={contacts} onChange={setContacts} />

        <div className="flex justify-end border-t pt-5">
          <Button type="submit">Save contacts</Button>
        </div>
      </form>

      <form
        className="space-y-6 border-t pt-8"
        onSubmit={async (event) => {
          event.preventDefault()
          const savedPrincipals = normalizedPrincipals()
          if (!savedPrincipals) return
          if (!(await onSavePrincipals(savedPrincipals))) return
          setPersistedDeviceIds(
            new Set(
              savedPrincipals.flatMap((principal) =>
                principal.devices.map((device) => device.id)
              )
            )
          )
          setPrincipals(savedPrincipals)
        }}
      >
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-semibold tracking-tight">
                Access identities
              </h2>
              <Badge variant="outline">Planning only</Badge>
            </div>
            <p className="mt-1 max-w-[65ch] text-sm leading-6 text-pretty text-[var(--text-secondary)]">
              Access rules reference these stable principal IDs. A paired device
              can prove possession of its dedicated signing key and recipient-
              encryption key, but pairing does not release access. Recipient-side
              pairing setup is not available in this browser build yet.
            </p>
          </div>
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={() => setPrincipals((current) => [...current, emptyPrincipal()])}
          >
            <HugeiconsIcon
              icon={UserAdd01Icon}
              strokeWidth={2}
              data-icon="inline-start"
            />
            Add access identity
          </Button>
        </div>

        {principals.length === 0 ? (
          <div className="rounded-[var(--radius-default)] border border-dashed bg-[var(--surface-secondary)] px-5 py-8 text-center">
            <p className="text-sm font-medium">No access identities yet</p>
            <p className="mx-auto mt-1 max-w-[65ch] text-sm text-pretty text-[var(--text-secondary)]">
              Create one explicitly when you are ready to plan item-level access.
              Continuity contacts are never converted automatically.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {principals.map((principal, principalIndex) => (
              <div
                key={principal.id}
                className="rounded-[var(--radius-default)] border bg-[var(--surface)] p-4 shadow-[var(--fancy-shadow-basic)]"
              >
                <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-medium">
                      {principal.name.trim() || `Access identity ${principalIndex + 1}`}
                    </p>
                    <p className="mt-0.5 font-mono text-[11px] text-[var(--text-secondary)]">
                      Principal {principal.id}
                    </p>
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={() =>
                      setPrincipals((current) =>
                        current.filter((_, index) => index !== principalIndex)
                      )
                    }
                  >
                    Remove identity
                  </Button>
                </div>

                <FieldGroup className="grid gap-4 sm:grid-cols-2">
                  <Field>
                    <FieldLabel htmlFor={`safeory-principal-${principal.id}-name`}>
                      Name
                    </FieldLabel>
                    <Input
                      id={`safeory-principal-${principal.id}-name`}
                      value={principal.name}
                      onChange={(event) =>
                        updatePrincipal(principalIndex, { name: event.target.value })
                      }
                      placeholder="Full name"
                    />
                  </Field>
                  <Field>
                    <FieldLabel
                      htmlFor={`safeory-principal-${principal.id}-relation`}
                    >
                      Relationship
                    </FieldLabel>
                    <Input
                      id={`safeory-principal-${principal.id}-relation`}
                      value={principal.relation}
                      onChange={(event) =>
                        updatePrincipal(principalIndex, {
                          relation: event.target.value,
                        })
                      }
                      placeholder="Partner, sibling, adviser…"
                    />
                  </Field>
                </FieldGroup>

                <div className="mt-5 space-y-3 border-t pt-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-medium">Recipient devices</p>
                      <p className="mt-0.5 text-xs text-[var(--text-secondary)]">
                        X25519 keys are for recipient encryption. Pairing adds a
                        separate Ed25519 signing key and proves possession of both
                        keys without verifying the person&apos;s real-world identity.
                      </p>
                    </div>
                    <Button
                      type="button"
                      variant="secondary"
                      size="sm"
                      onClick={() =>
                        updatePrincipal(principalIndex, {
                          devices: [...principal.devices, emptyDevice()],
                        })
                      }
                    >
                      Add device
                    </Button>
                  </div>

                  {principal.devices.length === 0 ? (
                    <p className="text-xs text-[var(--text-secondary)]">
                      No recipient-encryption device is registered. This principal
                      cannot be selected for a new item access rule yet.
                    </p>
                  ) : (
                    principal.devices.map((device, deviceIndex) => (
                      <div
                        key={device.id}
                        className="grid gap-3 rounded-[var(--radius-default)] border bg-[var(--surface-secondary)] p-3 sm:grid-cols-[minmax(0,0.7fr)_minmax(0,1.8fr)_auto] sm:items-end"
                      >
                        <div className="flex items-center gap-2 sm:col-span-3">
                          <Badge variant="outline">
                            {device.signing_public_key_hex ? "Paired device" : "Recipient only"}
                          </Badge>
                          <span className="text-xs text-[var(--text-secondary)]">
                            {device.signing_public_key_hex
                              ? "Dual-key possession proof verified locally."
                              : "No signing-key possession proof is recorded."}
                          </span>
                        </div>
                        <Field>
                          <FieldLabel
                            htmlFor={`safeory-device-${device.id}-label`}
                          >
                            Device label
                          </FieldLabel>
                          <Input
                            id={`safeory-device-${device.id}-label`}
                            value={device.label}
                            onChange={(event) =>
                              updateDevice(principalIndex, deviceIndex, {
                                label: event.target.value,
                              })
                            }
                            placeholder="Phone"
                          />
                        </Field>
                        <Field>
                          <FieldLabel htmlFor={`safeory-device-${device.id}-key`}>
                            Recipient-encryption public key
                          </FieldLabel>
                          <Input
                            id={`safeory-device-${device.id}-key`}
                            value={device.encryption_public_key_hex}
                            onChange={
                              persistedDeviceIds.has(device.id)
                                ? undefined
                                : (event) =>
                                    updateDevice(principalIndex, deviceIndex, {
                                      encryption_public_key_hex: event.target.value,
                                    })
                            }
                            readOnly={persistedDeviceIds.has(device.id)}
                            placeholder="64 hexadecimal characters"
                            spellCheck={false}
                            autoComplete="off"
                            className="font-mono text-xs"
                          />
                          {persistedDeviceIds.has(device.id) ? (
                            <FieldDescription>
                              Saved device keys are immutable. Remove this device
                              and add a new one to rotate the recipient key.
                            </FieldDescription>
                          ) : null}
                        </Field>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          onClick={() =>
                            updatePrincipal(principalIndex, {
                              devices: principal.devices.filter(
                                (_, index) => index !== deviceIndex
                              ),
                            })
                          }
                        >
                          Remove
                        </Button>
                        {persistedDeviceIds.has(device.id) &&
                        !device.signing_public_key_hex ? (
                          <div className="border-t pt-3 text-xs leading-5 text-[var(--text-secondary)] sm:col-span-3">
                            The local dual-key pairing verifier is implemented, but
                            this browser build does not yet ship recipient-side
                            device-key storage and a pairing responder. This device
                            remains recipient-only until that flow exists.
                          </div>
                        ) : null}
                        {device.signing_public_key_hex ? (
                          <div className="space-y-2 border-t pt-3 sm:col-span-3">
                            <p className="text-xs leading-5 text-[var(--text-secondary)]">
                              This proves the paired device possessed its Ed25519
                              signing key and X25519 recipient key at pairing time. It
                              does not verify the human&apos;s identity, grant item access,
                              start a waiting period, notify anyone, or release keys.
                            </p>
                            <p className="break-all font-mono text-[11px] text-[var(--text-secondary)]">
                              Signing key {device.signing_public_key_hex}
                            </p>
                          </div>
                        ) : null}
                      </div>
                    ))
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        <p className="text-xs leading-5 text-[var(--text-secondary)]">
          Removing an identity does not rewrite item policies. Existing rules that
          reference its UUID remain encrypted but unresolved until explicitly
          edited. Device-key rotation should be modeled as remove old device + add
          new device; grants continue to reference the principal UUID.
        </p>

        {principalError ? (
          <p className="text-sm text-[var(--danger)]" role="alert">
            {principalError}
          </p>
        ) : null}

        <div className="flex justify-end border-t pt-5">
          <Button type="submit">Save access identities</Button>
        </div>
      </form>
    </div>
  )
}
