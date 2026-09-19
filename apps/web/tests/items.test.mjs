import assert from "node:assert/strict"
import test from "node:test"

import {
  buildEditedItem,
  buildItem,
  ownerOnlyAccessPolicy,
} from "../lib/vault/items.ts"

test("edited planning preferences preserve access policy and future item fields", () => {
  const existing = {
    id: "00000000-0000-0000-0000-000000000001",
    kind: "password",
    title: "Email",
    links: [],
    attachments: [],
    legacy_disposition: "unspecified",
    account_closure_plan: { disposition: "unspecified", instructions: "" },
    access_policy: {
      owner_only_default: true,
      grants: [],
      private_forever: false,
      destruction: null,
    },
    fields: {
      username: "old@example.com",
      password: "old-password",
      website: "https://example.com",
      future_field: "keep me",
    },
    notes: null,
    future_top_level: { enabled: true },
  }

  const edited = buildEditedItem(
    existing,
    "password",
    "Email account",
    {
      username: "new@example.com",
      password: "new-password",
      website: "https://example.com",
    },
    "Private note",
    {
      legacyDisposition: "private_forever",
      accountClosurePlan: {
        disposition: "review_manually",
        instructions: "Export data first.",
      },
    }
  )

  assert.deepEqual(edited.access_policy, existing.access_policy)
  assert.deepEqual(edited.future_top_level, existing.future_top_level)
  assert.equal(edited.fields.future_field, "keep me")
  assert.equal(edited.legacy_disposition, "private_forever")
  assert.deepEqual(edited.account_closure_plan, {
    disposition: "review_manually",
    instructions: "Export data first.",
  })
})

test("new items carry encrypted planning values in the normal item payload", () => {
  const item = buildItem(
    "00000000-0000-0000-0000-000000000002",
    "password",
    "Hosting",
    { username: "me", password: "secret", website: "https://example.com" },
    "",
    {
      legacyDisposition: "selected_for_legacy",
      accountClosurePlan: {
        disposition: "close_account",
        instructions: "Download invoices first.",
      },
    }
  )

  assert.equal(item.legacy_disposition, "selected_for_legacy")
  assert.deepEqual(item.account_closure_plan, {
    disposition: "close_account",
    instructions: "Download invoices first.",
  })
  assert.deepEqual(item.access_policy, ownerOnlyAccessPolicy())
})

test("item edits persist record access grants without widening hidden policy data", () => {
  const existing = {
    id: "00000000-0000-0000-0000-000000000010",
    kind: "document",
    title: "Will",
    links: [],
    attachments: [],
    legacy_disposition: "unspecified",
    account_closure_plan: { disposition: "unspecified", instructions: "" },
    access_policy: {
      owner_only_default: true,
      grants: [
        {
          trustee_id: "00000000-0000-0000-0000-000000000099",
          what: "legacy-scope",
          permission: "view",
          condition: "emergency",
          wait_period: "one_day",
          duration: "until_revoked",
          approvals_required: 1,
          approver_ids: ["00000000-0000-0000-0000-000000000098"],
        },
      ],
      private_forever: false,
      destruction: null,
      future_policy_field: "keep me",
    },
    fields: { document_number: "A-1", issuer: "State", expiry: "" },
    notes: null,
  }

  const nextPolicy = {
    ...existing.access_policy,
    grants: [
      ...existing.access_policy.grants,
      {
        trustee_id: "00000000-0000-0000-0000-000000000011",
        what: "record",
        permission: "download",
        condition: "incapacity",
        wait_period: "seven_days",
        duration: "one_day",
        approvals_required: 0,
        approver_ids: [],
      },
    ],
  }

  const edited = buildEditedItem(
    existing,
    "document",
    "Will",
    existing.fields,
    "",
    {
      legacyDisposition: "unspecified",
      accountClosurePlan: existing.account_closure_plan,
      accessPolicy: nextPolicy,
    }
  )

  assert.deepEqual(edited.access_policy, nextPolicy)
  assert.equal(edited.access_policy.future_policy_field, "keep me")
  assert.deepEqual(edited.access_policy.grants[0], existing.access_policy.grants[0])
})
