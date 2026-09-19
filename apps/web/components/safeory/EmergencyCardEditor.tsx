"use client"

import { useState } from "react"
import type { EmergencyCard, EmergencyContact } from "@safeory/contracts"
import {
  Add01Icon,
  Delete02Icon,
  ShieldKeyIcon,
  UserAdd01Icon,
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
import { Separator } from "@/components/ui/separator"
import { Textarea } from "@/components/ui/textarea"

interface Props {
  initial: EmergencyCard | null
  onSave: (card: EmergencyCard) => void
}

const emptyContact: EmergencyContact = {
  name: "",
  relation: "",
  phone: "",
  email: "",
  notes: "",
}

export function EmergencyCardEditor({ initial, onSave }: Props) {
  const [instructions, setInstructions] = useState(initial?.instructions ?? "")
  const [contacts, setContacts] = useState<EmergencyContact[]>(
    initial?.contacts ?? []
  )

  function updateContact(index: number, patch: Partial<EmergencyContact>) {
    setContacts((previous) =>
      previous.map((contact, contactIndex) =>
        contactIndex === index ? { ...contact, ...patch } : contact
      )
    )
  }

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault()
        onSave({
          selected_item_ids: initial?.selected_item_ids ?? [],
          instructions,
          contacts: contacts.filter(
            (contact) => contact.name.trim().length > 0
          ),
        })
      }}
      className="space-y-6"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <div className="flex size-9 items-center justify-center rounded-lg border bg-muted/40">
              <HugeiconsIcon
                icon={ShieldKeyIcon}
                strokeWidth={1.8}
                className="size-4 text-primary"
              />
            </div>
            <div>
              <h2 className="text-lg font-semibold tracking-tight">
                Emergency Card
              </h2>
              <p className="text-sm text-muted-foreground">
                Private instructions and people to contact in an emergency.
              </p>
            </div>
          </div>
        </div>
        <Badge variant="outline">Encrypted</Badge>
      </div>

      <Field>
        <FieldLabel htmlFor="safeory-emergency-instructions">
          Instructions for trusted people
        </FieldLabel>
        <Textarea
          id="safeory-emergency-instructions"
          value={instructions}
          onChange={(event) => setInstructions(event.target.value)}
          rows={5}
          placeholder="What should happen, who to contact, where important things are…"
          className="min-h-28 resize-y"
        />
        <FieldDescription>
          Keep this concise and actionable. These instructions stay encrypted in
          your vault.
        </FieldDescription>
      </Field>

      <Separator />

      <section className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-medium">Emergency contacts</h3>
            <p className="mt-0.5 text-sm text-muted-foreground">
              Add people who should be contacted or can help carry out your
              plan.
            </p>
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() =>
              setContacts((previous) => [...previous, { ...emptyContact }])
            }
          >
            <HugeiconsIcon
              icon={UserAdd01Icon}
              strokeWidth={2}
              data-icon="inline-start"
            />
            Add contact
          </Button>
        </div>

        {contacts.length === 0 ? (
          <div className="rounded-xl border border-dashed bg-muted/20 px-5 py-8 text-center">
            <div className="mx-auto mb-3 flex size-9 items-center justify-center rounded-full bg-muted">
              <HugeiconsIcon
                icon={Add01Icon}
                strokeWidth={2}
                className="size-4 text-muted-foreground"
              />
            </div>
            <p className="text-sm font-medium">No contacts yet</p>
            <p className="mx-auto mt-1 max-w-sm text-sm text-muted-foreground">
              You can save the card without contacts, or add someone now.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {contacts.map((contact, index) => (
              <div
                key={index}
                className="rounded-xl border bg-card p-4 shadow-xs"
              >
                <div className="mb-4 flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">
                      {contact.name.trim() || `Contact ${index + 1}`}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {contact.relation.trim() || "Relationship not specified"}
                    </p>
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-sm"
                    aria-label={`Remove contact ${index + 1}`}
                    onClick={() =>
                      setContacts((previous) =>
                        previous.filter(
                          (_, contactIndex) => contactIndex !== index
                        )
                      )
                    }
                  >
                    <HugeiconsIcon
                      icon={Delete02Icon}
                      strokeWidth={2}
                      className="text-destructive"
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
                      placeholder="Optional context or instructions for this contact"
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

      <div className="flex justify-end border-t pt-5">
        <Button type="submit">Save emergency card</Button>
      </div>
    </form>
  )
}
