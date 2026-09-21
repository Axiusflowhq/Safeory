import type { CaptureCredentialRequest, ContentResponse } from "./messages";

interface CaptureVault {
  isUnlocked(): boolean;
  getItemJson(id: string): string;
  putItemJson(itemJson: string): void;
  updateItemJson(itemJson: string, expectedRevision: bigint): bigint;
}

interface CredentialItemJson {
  id: string;
  kind: string;
  title: string;
  fields: Record<string, string>;
  links: string[];
  attachments: string[];
  legacy_disposition: string;
  account_closure_plan: { disposition: string; instructions: string };
  notes: unknown;
  [key: string]: unknown;
}

const MAX_TITLE_CHARS = 512;
const MAX_USERNAME_CHARS = 16_384;
const MAX_PASSWORD_CHARS = 16_384;

function captureError(
  error: string,
): Extract<ContentResponse, { type: "capture" }> {
  return { type: "capture", ok: false, error };
}

function validHttpOrigin(origin: string): boolean {
  try {
    const url = new URL(origin);
    return (
      (url.protocol === "http:" || url.protocol === "https:") &&
      url.origin === origin
    );
  } catch {
    return false;
  }
}

function normalizedStoredOrigin(value: string): string | null {
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(value)
      ? value
      : `https://${value}`;
    const url = new URL(withScheme);
    return url.protocol === "http:" || url.protocol === "https:"
      ? url.origin
      : null;
  } catch {
    return null;
  }
}

function validateCandidate(
  request: CaptureCredentialRequest,
): Extract<ContentResponse, { type: "capture" }> | null {
  if (
    typeof request.title !== "string" ||
    typeof request.username !== "string" ||
    typeof request.password !== "string"
  ) {
    return captureError("invalid credential candidate");
  }
  if (request.title.length > MAX_TITLE_CHARS)
    return captureError("credential title is too long");
  if (request.username.length > MAX_USERNAME_CHARS) {
    return captureError("credential username is too long");
  }
  if (request.password.length === 0)
    return captureError("password is required");
  if (request.password.length > MAX_PASSWORD_CHARS) {
    return captureError("credential password is too long");
  }
  if (
    request.existing !== undefined &&
    (typeof request.existing.id !== "string" ||
      !Number.isSafeInteger(request.existing.revision) ||
      request.existing.revision < 0)
  ) {
    return captureError("invalid credential revision");
  }
  return null;
}

export function saveCapturedCredential(
  vault: CaptureVault,
  origin: string,
  request: CaptureCredentialRequest,
  createId: () => string = () => crypto.randomUUID(),
): Extract<ContentResponse, { type: "capture" }> {
  if (!vault.isUnlocked()) return captureError("locked");
  if (!validHttpOrigin(origin)) return captureError("invalid page origin");
  const invalid = validateCandidate(request);
  if (invalid !== null) return invalid;

  if (request.existing !== undefined) {
    let item: CredentialItemJson;
    try {
      item = JSON.parse(
        vault.getItemJson(request.existing.id),
      ) as CredentialItemJson;
    } catch {
      return captureError("credential no longer exists");
    }
    if (item.kind !== "password") return captureError("not a credential");
    if (normalizedStoredOrigin(item.fields["website"] ?? "") !== origin) {
      return captureError("origin mismatch");
    }

    item.fields = {
      ...item.fields,
      username: request.username,
      password: request.password,
      website: origin,
    };
    try {
      vault.updateItemJson(
        JSON.stringify(item),
        BigInt(request.existing.revision),
      );
    } catch {
      return captureError("credential changed; retry from the page");
    }
    return { type: "capture", ok: true, action: "updated" };
  }

  const title = request.title.trim() || new URL(origin).hostname;
  const item: CredentialItemJson = {
    id: createId(),
    kind: "password",
    title,
    links: [],
    attachments: [],
    legacy_disposition: "unspecified",
    account_closure_plan: { disposition: "unspecified", instructions: "" },
    fields: {
      username: request.username,
      password: request.password,
      website: origin,
    },
    notes: null,
  };
  try {
    vault.putItemJson(JSON.stringify(item));
  } catch {
    return captureError("saving credential failed");
  }
  return { type: "capture", ok: true, action: "created" };
}
