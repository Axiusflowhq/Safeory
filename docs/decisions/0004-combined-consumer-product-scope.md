# ADR 0004: Combined Consumer Product Scope

Date: 2026-09-20

## Status

Accepted.

## Context

Safeory's local vault, password-manager extension, household records, recovery,
and Trust Engine were documented across separate plans. Without one explicit
product boundary, “1Password + Trustworthy alternative” could mean anything
from a focused family product to 1Password's enterprise administration and
developer-secrets portfolio. It also left household collaboration, private
spaces, ingestion, reminders, and parity claims underspecified.

## Decision

Safeory targets a zero-knowledge consumer alternative to:

- 1Password Individual/Families credential management; and
- Trustworthy household organization, collaboration, continuity, and legacy
  planning.

The product uses the account -> household -> space -> item model defined in
`docs/architecture/combined-product.md`. Private/shared spaces, credential
records, household records, reminders, files, collaborators, recovery, and
legacy policies share one identity, key, sync, audit, and device architecture.

1Password Business, Enterprise, and Developer parity is outside this decision.
Safeory does not currently target workforce SSO/provisioning, enterprise device
posture, SSH agents, CLI secret injection, or infrastructure-secret automation.

Zero knowledge remains the controlling constraint. Competitor automation that
requires routine server plaintext is replaced with a local/private equivalent,
made explicit opt-in under a separate ADR, or listed as a non-goal.

## Consequences

- Roadmap phases are evaluated against a maintained consumer capability matrix.
- Household/private/shared space architecture precedes production
  collaboration, sync, Travel Mode, and legacy release.
- A high-entropy Account Secret or equivalent enrollment factor requires a
  separate crypto ADR before cloud launch.
- Ordinary SMTP forwarding is not part of the zero-knowledge default.
- Responsive web and the browser extension remain the committed clients.
  Native-only capabilities are not claimed without a later client ADR.
- Marketing must distinguish implemented behavior, Safeory equivalents, later
  work, and explicit non-goals.
