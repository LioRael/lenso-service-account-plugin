# Lenso Service Account Plugin

`lenso-service-account-plugin` gives a Lenso App removable, organization-scoped
machine identities. An authorized person can create, inspect, rotate, and
revoke a stable service account; a trusted ingress can exchange its opaque
secret for the App's normal, short-lived credential.

This repository contains three public Rust crates:

- `lenso-capability-service-account`: portable `lenso.service-account@1`
  management (`create`, `get`, `list`, `rotate_secret`, and `revoke`);
- `lenso-capability-service-account-auth`: portable
  `lenso.auth.service-account@1` secret exchange;
- `lenso-service-account-postgres-plugin`: the linked PostgreSQL
  implementation with Plugin id `lenso.service-account` and root slot
  `service-accounts`.

The Plugin owns service-account names, stable Directory subjects, status,
revisions, Argon2id credential verifiers, bounded rotation overlap, durable
rate state, and encrypted idempotency receipts. It does not own Organization
membership, RBAC roles, canonical identity status, or issued App credentials.

## Required bindings

- `lenso.secrets@1/resolve` for the database URL, credential pepper, and receipt
  encryption key;
- `lenso.identity.directory@1/ensure_identity` and `read_status` for canonical
  non-human subjects and their active/disabled state;
- `lenso.auth.credential-issuer@1/issue` for bounded App credentials;
- `lenso.organization-membership@1/check_membership` for management eligibility;
- `lenso.access-control@1/check_permission` for independent
  `service-account.read` and `service-account.manage` decisions.

Management also requires an exact configured caller plus a valid `user` Actor
assertion audienced to the exact Capability operation. Authentication has its
own exact caller allowlist and durable per-caller rate boundary. No local RBAC
tables or policy shortcuts are copied into this Plugin.

## Secret lifecycle

Create and rotate generate a 256-bit opaque secret. Only Argon2id plus a
Secrets-provided pepper is stored. The raw secret appears only in the first
successful call's response: idempotent replay returns the same account result
with `secret: null`. Generated request/response Debug output redacts secret or
credential fields, and the encrypted command receipt contains no account
secret.

Rotation bounds old-credential overlap to configuration. Expired and revoked
credentials fail closed. Exchange rechecks Directory status, locks and rechecks
the credential immediately before issuance, and asks Credential Issuer for an
expiry no later than both the configured token TTL and credential expiry.

## Operator-managed PostgreSQL

Runtime activation never migrates. An operator must run
`ServiceAccountOperator::setup(database_url, schema)` for a new instance or
`ServiceAccountOperator::upgrade(database_url, schema)` during a reviewed
deployment. Activation verifies the exact migration ledger and fails closed on
drift. See [PostgreSQL operations](docs/postgresql-operations.md).

Configuration is validated against
[`configuration.schema.json`](crates/lenso-service-account-postgres-plugin/configuration.schema.json).
The three configured secret references must be distinct; pepper and receipt
key values must each contain at least 32 bytes.

## Deliberate issuer seam

Credential Issuer 1.1 has no idempotency input. Before calling it, a verified
exchange is durably marked `issuing`. If the call has an ambiguous runtime or
unknown result, replay returns `operation_in_progress` and does not issue a
second credential. This requires operator investigation; automated recovery
needs an idempotent issuer or a durable workflow owner.

Identity Directory 1.1 also has no compensating delete. A failure after
`ensure_identity` but before the local account transaction commits can leave an
unreferenced canonical subject. It has no service-account verifier and cannot
exchange through this Plugin; operators must reconcile it until a transactional
Directory workflow exists.

## Local validation

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
lenso-contract-codegen check crates/lenso-capability-service-account/capability.json \
  --rust crates/lenso-capability-service-account/src/generated.rs
lenso-contract-codegen check crates/lenso-capability-service-account-auth/capability.json \
  --rust crates/lenso-capability-service-account-auth/src/generated.rs
LENSO_PACKAGE_ALLOW_DIRTY=1 \
  ./scripts/check-public-packages.sh
./scripts/check-repository-boundary.sh
```

The real PostgreSQL suite creates and removes a unique database and proves
restart persistence, caller-scoped idempotency, revision concurrency,
secret-once receipts, durable rate limits, and revoked/expired fail-closed
behavior:

```sh
LENSO_TEST_POSTGRES_ADMIN_URL=postgres://.../postgres \
  cargo test \
  -p lenso-service-account-postgres-plugin \
  restart_concurrency_and_secret_once_acceptance -- --ignored
```

See [the Plugin card](docs/plugin-card.md),
[the architecture decision](docs/adr/0001-independent-service-account-policy.md),
and [the release process](docs/release-process.md).
