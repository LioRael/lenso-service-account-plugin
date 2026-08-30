# Service Account Plugin card

## Outcome

An authorized Organization member can manage stable machine identities. A
trusted authentication ingress can exchange an opaque service-account secret
for the App's ordinary bounded credential.

## Package and slot

- Package: `lenso-service-account-postgres-plugin`
- Plugin id: `lenso.service-account`
- Root slot: `service-accounts`
- Management Capability: `lenso.service-account@1`
- Authentication Capability: `lenso.auth.service-account@1`

## Provides

- `create`, `get`, `list`, `rotate_secret`, and `revoke`
- `exchange_secret`

All are portable request Operations. List pagination is an account-id keyset;
mutation revisions are positive decimal CAS tokens.

## Requires

- Identity Directory: `ensure_identity` and `read_status`
- Credential Issuer: `issue`
- Organization Membership: `check_membership`
- Access Control: `check_permission`
- Secrets: three distinct references for database URL, credential pepper, and
  receipt encryption key
- verified user Actor assertions for management
- separate immutable management and authentication caller allowlists

## Owned facts

The owned PostgreSQL schema contains organization-scoped unique names, stable
Directory subjects, active/revoked status, revisions, Argon2id verifiers,
credential validity and bounded overlap, use/revocation timestamps,
caller-scoped command state, encrypted sanitized receipts, and durable
per-authentication-caller rate state.

The Plugin does not own Organization membership or Access Control policies. It
does not create roles, grants, permissions, canonical identity status, Auth
signing keys, or issued-session revocation state.

## Authorization

Management succeeds only when all checks pass:

1. the calling Instance is on the exact management allowlist;
2. the Auth Actor assertion is valid, has kind `user`, and is audienced to the
   exact management operation;
3. Organization Membership says the actor is active in the requested
   Organization;
4. Access Control allows `service-account.read` or
   `service-account.manage` on that Organization scope.

Authentication has no user Actor assertion. It accepts only an exact
authentication caller, consumes a durable caller rate slot, verifies Argon2id
with the configured pepper, rechecks Directory status, and transactionally
rechecks credential/account validity before issuance.

## Idempotency and secret-once behavior

Mutation and exchange keys are scoped by exact caller and operation. The stored
intent digest includes the managing actor for mutations. Same-key/different-
intent calls conflict. Concurrent unfinished calls report
`operation_in_progress`.

Create/rotate receipts deliberately contain `secret: null`. The process that
commits a new verifier returns the generated secret once; replay after success
returns no secret. Exchange receipts are AES-256-GCM encrypted and bound to the
caller, operation, and key so a successful external issuance can be replayed
without issuing another credential.

## Lifecycle and removal

`activate` resolves secrets and verifies an already-installed schema. It never
migrates. `ServiceAccountOperator::setup/upgrade` owns migrations.
`deactivate` drops active pepper/key material and closes the pool. There are no
background tasks.

Removing the Plugin Instance, its bindings, and owned schema removes service-
account behavior and local state. Directory subjects and already-issued
credentials remain owned by their providers and follow those providers'
retention/revocation policies.

## Deliberate limits

- v1 has no secret recovery. Losing a create/rotate response requires another
  authorized rotation.
- v1 has no in-place pepper rotation protocol.
- Identity Directory 1.1 exposes `ensure_identity` but no compensating delete.
  A name conflict or crash after Directory ensure and before the local account
  commit can therefore leave an unreferenced subject. It has no local verifier
  and cannot exchange through this Plugin; operators must reconcile these
  subjects until Directory supplies a compensating or transactional workflow.
- Credential Issuer 1.1 has no idempotency key. Any ambiguous outcome after
  the durable `issuing` transition remains `operation_in_progress`; automatic
  retry is intentionally forbidden.
- The transactional `issuing` transition is the exchange admission point.
  Revoke prevents every later admission but does not cancel an already-admitted
  call or revoke an App credential that Credential Issuer already owns.
- HTTP authorization headers, mTLS, IP policy, audit delivery, UI, and periodic
  secret-expiry notifications are separate Plugins or Adapters.
