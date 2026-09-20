"use client"

import { useState } from "react"
import type {
  DeviceRegistrationV1,
  EmergencyContact,
  PairingChallengeV1,
  PairingProofV1,
  TrustedDevice,
  TrustedPrincipal,
} from "@safeory/contracts"
import {
  Copy01Icon,
  Delete02Icon,
  DeviceAccessIcon,
  UserAdd01Icon,
  UserKeyIcon,
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
  onCreatePairingChallenge: (
    principalId: string,
    deviceId: string
  ) => PairingChallengeV1 | null
  onCompletePairing: (proof: PairingProofV1) => Promise<boolean>
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

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    value
  )
}

function bytesToHex(bytes: number[]): string {
  if (
    bytes.length !== 32 ||
    bytes.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)
  ) {
    throw new Error("Pairing proof signing key is invalid.")
  }
  return bytes.map((byte) => byte.toString(16).padStart(2, "0")).join("")
}

function parsePairingProof(value: string): PairingProofV1 {
  let parsed: unknown
  try {
    parsed = JSON.parse(value)
  } catch {
    throw new Error("Pairing proof must be valid JSON.")
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    (parsed as { format_version?: unknown }).format_version !== 1 ||
    typeof (parsed as { principal_id?: unknown }).principal_id !== "string" ||
    typeof (parsed as { device_id?: unknown }).device_id !== "string" ||
    !Array.isArray((parsed as { signing_public?: unknown }).signing_public)
  ) {
    throw new Error("Pairing proof format is invalid.")
  }
  return parsed as PairingProofV1
}

function parseDeviceRegistration(value: string): DeviceRegistrationV1 {
  let parsed: unknown
  try {
    parsed = JSON.parse(value)
  } catch {
    throw new Error("Device registration must be valid JSON.")
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("Device registration format is invalid.")
  }
  const registration = parsed as Partial<DeviceRegistrationV1>
  if (
    registration.format_version !== 1 ||
    typeof registration.device_id !== "string" ||
    !isUuid(registration.device_id) ||
    typeof registration.encryption_public_key_hex !== "string" ||
    !/^[0-9a-f]{64}$/i.test(registration.encryption_public_key_hex) ||
    /^0{64}$/i.test(registration.encryption_public_key_hex) ||
    typeof registration.signing_public_key_hex !== "string" ||
    !/^[0-9a-f]{64}$/i.test(registration.signing_public_key_hex)
  ) {
    throw new Error("Device registration format is invalid.")
  }
  return registration as DeviceRegistrationV1
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
  onCreatePairingChallenge,
  onCompletePairing,
}: TrustedPeopleEditorProps) {
  const [contacts, setContacts] = useState<EmergencyContact[]>(initialContacts)
  const [principals, setPrincipals] =
    useState<TrustedPrincipal[]>(initialPrincipals)
  const [principalError, setPrincipalError] = useState<string | null>(null)
  const [pairingChallenges, setPairingChallenges] = useState<Record<string, string>>({})
  const [pairingProofs, setPairingProofs] = useState<Record<string, string>>({})
  const [pairingErrors, setPairingErrors] = useState<Record<string, string>>({})
  const [registrationDrafts, setRegistrationDrafts] = useState<Record<string, string>>({})
  const [registrationErrors, setRegistrationErrors] = useState<Record<string, string>>({})
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
    const deviceIds = new Set<string>()
    const normalized: TrustedPrincipal[] = []
    for (const principal of principals) {
      const name = principal.name.trim()
      if (name.length === 0) {
        setPrincipalError("Every access identity needs a name.")
        return null
      }
      const devices: TrustedDevice[] = []
      for (const device of principal.devices) {
        const deviceId = device.id.trim().toLowerCase()
        if (!isUuid(deviceId)) {
          setPrincipalError(`${name} has an invalid device identifier.`)
          return null
        }
        if (deviceIds.has(deviceId)) {
          setPrincipalError("The same device identifier cannot be registered more than once.")
          return null
        }
        deviceIds.add(deviceId)
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
          id: deviceId,
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
              encryption key, but pairing does not release access. Use the public
              registration bundle from the recipient browser when adding a device.
            </p>
          </div>
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={() => setPrincipals((current) => [...current, emptyPrincipal()])}
          >
            <HugeiconsIcon
              icon={UserKeyIcon}
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
                    <HugeiconsIcon
                      icon={Delete02Icon}
                      strokeWidth={2}
                      data-icon="inline-start"
                    />
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
                      <HugeiconsIcon
                        icon={DeviceAccessIcon}
                        strokeWidth={2}
                        data-icon="inline-start"
                      />
                      Add device
                    </Button>
                  </div>

                  <div className="grid gap-3 rounded-[var(--radius-default)] border border-dashed bg-[var(--surface-secondary)] p-3">
                    <Field>
                      <FieldLabel
                        htmlFor={`safeory-principal-${principal.id}-device-registration`}
                      >
                        Recipient public registration
                      </FieldLabel>
                      <Textarea
                        id={`safeory-principal-${principal.id}-device-registration`}
                        value={registrationDrafts[principal.id] ?? ""}
                        onChange={(event) => {
                          setRegistrationDrafts((current) => ({
                            ...current,
                            [principal.id]: event.target.value,
                          }))
                          setRegistrationErrors((current) => ({
                            ...current,
                            [principal.id]: "",
                          }))
                        }}
                        rows={3}
                        spellCheck={false}
                        autoComplete="off"
                        className="font-mono text-xs"
                        placeholder="Paste the public registration JSON copied from the recipient browser"
                      />
                      <FieldDescription>
                        Safeory imports only the recipient device UUID and X25519
                        encryption key here. The advertised Ed25519 key is ignored
                        until the separate possession proof verifies it.
                      </FieldDescription>
                    </Field>
                    <div className="flex flex-wrap items-center gap-3">
                      <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        disabled={(registrationDrafts[principal.id] ?? "").trim().length === 0}
                        onClick={() => {
                          try {
                            const registration = parseDeviceRegistration(
                              registrationDrafts[principal.id] ?? ""
                            )
                            const normalizedDeviceId = registration.device_id.toLowerCase()
                            const normalizedKey =
                              registration.encryption_public_key_hex.toLowerCase()
                            const duplicate = principals.some((candidatePrincipal) =>
                              candidatePrincipal.devices.some(
                                (candidateDevice) =>
                                  candidateDevice.id.toLowerCase() === normalizedDeviceId ||
                                  candidateDevice.encryption_public_key_hex
                                    .trim()
                                    .toLowerCase() === normalizedKey
                              )
                            )
                            if (duplicate) {
                              throw new Error(
                                "That recipient device ID or encryption key is already registered."
                              )
                            }
                            updatePrincipal(principalIndex, {
                              devices: [
                                ...principal.devices,
                                {
                                  id: normalizedDeviceId,
                                  label: "Recipient browser",
                                  encryption_public_key_hex: normalizedKey,
                                  signing_public_key_hex: null,
                                },
                              ],
                            })
                            setRegistrationDrafts((current) => ({
                              ...current,
                              [principal.id]: "",
                            }))
                            setRegistrationErrors((current) => ({
                              ...current,
                              [principal.id]: "",
                            }))
                          } catch (error) {
                            setRegistrationErrors((current) => ({
                              ...current,
                              [principal.id]:
                                error instanceof Error ? error.message : String(error),
                            }))
                          }
                        }}
                      >
                        Import registered device
                      </Button>
                      {registrationErrors[principal.id] ? (
                        <p className="text-xs text-[var(--danger)]" role="alert">
                          {registrationErrors[principal.id]}
                        </p>
                      ) : null}
                    </div>
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
                          <FieldLabel htmlFor={`safeory-device-${device.id}-id`}>
                            Device ID
                          </FieldLabel>
                          <Input
                            id={`safeory-device-${device.id}-id`}
                            value={device.id}
                            onChange={
                              persistedDeviceIds.has(device.id)
                                ? undefined
                                : (event) =>
                                    updateDevice(principalIndex, deviceIndex, {
                                      id: event.target.value,
                                    })
                            }
                            readOnly={persistedDeviceIds.has(device.id)}
                            spellCheck={false}
                            autoComplete="off"
                            className="font-mono text-xs"
                          />
                        </Field>
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
                          <HugeiconsIcon
                            icon={Delete02Icon}
                            strokeWidth={2}
                            data-icon="inline-start"
                          />
                          Remove
                        </Button>
                        {persistedDeviceIds.has(device.id) &&
                        !device.signing_public_key_hex ? (
                          <div className="space-y-3 border-t pt-3 sm:col-span-3">
                            <p className="text-xs leading-5 text-[var(--text-secondary)]">
                              Generate a one-shot challenge, send it to the recipient
                              browser, then paste the returned proof here. Locking,
                              reloading, or saving the Emergency Card after challenge
                              creation cancels the pending verifier state.
                            </p>
                            <div className="flex flex-wrap gap-2">
                              <Button
                                type="button"
                                variant="secondary"
                                size="sm"
                                onClick={() => {
                                  const challenge = onCreatePairingChallenge(
                                    principal.id,
                                    device.id
                                  )
                                  if (!challenge) return
                                  setPairingChallenges((current) => ({
                                    ...current,
                                    [device.id]: JSON.stringify(challenge),
                                  }))
                                  setPairingProofs((current) => ({
                                    ...current,
                                    [device.id]: "",
                                  }))
                                  setPairingErrors((current) => ({
                                    ...current,
                                    [device.id]: "",
                                  }))
                                }}
                              >
                                Create pairing challenge
                              </Button>
                              {pairingChallenges[device.id] ? (
                                <Button
                                  type="button"
                                  variant="outline"
                                  size="sm"
                                  onClick={() =>
                                    void navigator.clipboard.writeText(
                                      pairingChallenges[device.id]
                                    )
                                  }
                                >
                                  <HugeiconsIcon
                                    icon={Copy01Icon}
                                    strokeWidth={2}
                                    data-icon="inline-start"
                                  />
                                  Copy challenge
                                </Button>
                              ) : null}
                            </div>
                            {pairingChallenges[device.id] ? (
                              <Textarea
                                value={pairingChallenges[device.id]}
                                readOnly
                                rows={4}
                                className="font-mono text-xs"
                              />
                            ) : null}
                            <Field>
                              <FieldLabel
                                htmlFor={`safeory-device-${device.id}-pairing-proof`}
                              >
                                Recipient pairing proof
                              </FieldLabel>
                              <Textarea
                                id={`safeory-device-${device.id}-pairing-proof`}
                                value={pairingProofs[device.id] ?? ""}
                                onChange={(event) =>
                                  setPairingProofs((current) => ({
                                    ...current,
                                    [device.id]: event.target.value,
                                  }))
                                }
                                rows={4}
                                spellCheck={false}
                                autoComplete="off"
                                className="font-mono text-xs"
                                placeholder="Paste the proof JSON returned by the recipient browser"
                              />
                            </Field>
                            <div className="flex flex-wrap items-center gap-3">
                              <Button
                                type="button"
                                size="sm"
                                disabled={(pairingProofs[device.id] ?? "").trim().length === 0}
                                onClick={async () => {
                                  try {
                                    const proof = parsePairingProof(
                                      pairingProofs[device.id] ?? ""
                                    )
                                    if (
                                      proof.principal_id !== principal.id ||
                                      proof.device_id !== device.id
                                    ) {
                                      throw new Error(
                                        "Pairing proof targets a different principal or device."
                                      )
                                    }
                                    if (!(await onCompletePairing(proof))) return
                                    const signingKey = bytesToHex(proof.signing_public)
                                    updateDevice(principalIndex, deviceIndex, {
                                      signing_public_key_hex: signingKey,
                                    })
                                    setPairingChallenges((current) => ({
                                      ...current,
                                      [device.id]: "",
                                    }))
                                    setPairingProofs((current) => ({
                                      ...current,
                                      [device.id]: "",
                                    }))
                                    setPairingErrors((current) => ({
                                      ...current,
                                      [device.id]: "",
                                    }))
                                  } catch (error) {
                                    setPairingErrors((current) => ({
                                      ...current,
                                      [device.id]:
                                        error instanceof Error
                                          ? error.message
                                          : String(error),
                                    }))
                                  }
                                }}
                              >
                                Verify pairing proof
                              </Button>
                              {pairingErrors[device.id] ? (
                                <p className="text-xs text-[var(--danger)]" role="alert">
                                  {pairingErrors[device.id]}
                                </p>
                              ) : null}
                            </div>
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
