# Lenso Service Account context

## Outcome

An authorized Organization member can create, inspect, rotate, and revoke a
stable non-human identity. A trusted machine ingress can exchange its opaque
secret for the App's normal bounded credential without learning RBAC storage or
Auth signing authority.

## Ownership

- `lenso.service-account@1` owns management and inspection semantics.
- `lenso.auth.service-account@1` owns secret exchange semantics.
- The PostgreSQL Plugin owns service-account names, status, revisions,
  Argon2id verifiers, rotation overlap, rate state, and command receipts.
- Organization Membership owns membership eligibility. Access Control owns
  scoped permission decisions. Neither policy is copied locally.
- Identity Directory owns canonical subjects. Credential Issuer owns issued
  tokens and revocation semantics.

## Invariants

- Service-account names are unique inside one Organization for their lifetime.
- Raw account secrets appear only in the first successful create or rotate
  response. They are absent from Debug output and durable receipts.
- Credential verification uses Argon2id plus a Secrets-provided pepper.
- Rotation overlap is bounded configuration; revoked or expired credentials
  fail closed as invalid credentials.
- Every mutation uses caller-scoped idempotency and revision CAS. Listing uses
  stable keyset pagination.
- Management authorization requires all four factors: exact caller, verified
  user assertion, active Organization membership, and Access Control allow.
- Authentication has a separate caller allowlist and durable caller rate limit.

## Known seam

Identity Directory 1.1 has no compensating delete after `ensure_identity`.
Failure before the local account commit can leave an unreferenced canonical
subject. It has no local verifier and cannot authenticate through this Plugin;
operator reconciliation is required.

Credential Issuer 1.1 has no idempotency key on `issue`. The Plugin marks a
verified exchange as `issuing` before that external call. An ambiguous failure
remains `operation_in_progress` and is never automatically retried; safe
automated recovery requires an idempotent issuer or durable workflow owner.
