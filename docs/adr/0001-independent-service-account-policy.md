# ADR 0001: Keep Service Accounts independent of Organization and RBAC storage

- Status: accepted
- Date: 2026-08-30

## Context

A service account is an Organization-scoped machine identity with its own
credential lifecycle. Organization Membership answers whether a human may act
inside an Organization. Access Control answers whether that actor may perform a
specific action. Identity Directory owns canonical subjects, and Credential
Issuer owns App credentials.

Putting service-account records into Organization would make machine identity
and secret rotation mandatory Organization behavior. Copying roles or grants
into a service-account schema would create a second authorization truth and
make policy replacement unsafe.

## Decision

Publish two portable roles:

- `lenso.service-account@1` for create/get/list/rotate/revoke;
- `lenso.auth.service-account@1` for secret exchange.

Implement both in one removable PostgreSQL Plugin because they share one
credential lifecycle and one owned consistency boundary. Keep authorization
providers independent:

- management requires exact caller, operation-audienced Auth Actor assertion,
  active Organization Membership, and an Access Control decision;
- authentication uses a distinct exact caller set and durable rate boundary;
- Identity Directory supplies a stable canonical non-human subject;
- Credential Issuer signs the normal bounded App credential.

The Plugin stores no RBAC roles, permissions, grants, Organization membership,
or Auth signing keys. It owns only service-account facts and credential
verification state.

## Secret and transaction decision

Generate an opaque 256-bit credential and persist only an explicit Argon2id
verifier over secret plus a Secrets-provided pepper. Raw secrets appear only in
the first successful create/rotate response. Durable mutation receipts are
encrypted but intentionally contain a null account secret.

Use positive revision CAS for rotate/revoke, organization-scoped unique names,
account-id keyset pagination, and caller/operation/idempotency-key command
records. Rotation transactionally caps every existing live credential before
inserting the new one. Revocation locks the account and invalidates all
credentials.

Before issuing an App credential, exchange verifies the secret, checks
Directory, then transactionally locks and rechecks credential/account validity
and marks the command `issuing`. Credential Issuer 1.1 has no idempotency input,
so ambiguous outcomes remain durably in progress and are never retried.
That durable transition is the linearization point: a later revoke blocks new
admissions but does not cancel an exchange already admitted across the external
Issuer boundary.

## Consequences

- Organization and Access Control remain replaceable and authoritative.
- Removing this Plugin removes machine-login behavior without changing human
  membership or RBAC schemas.
- An App may replace Service Accounts without teaching Kernel or Organization
  a service-account branch.
- Operators must investigate durable issuing seams and perform deliberate
  pepper/key rotations; v1 does not claim automatic recovery for either.
