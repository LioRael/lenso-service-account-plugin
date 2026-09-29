# Organization machine-identity admission and reconciliation

Service Account remains optional organization-scoped identity. A personal PAT
application does not need this Plugin or a synthetic organization. Management
must first admit a human operators credential, verify deployment eligibility,
and intersect current RBAC permission with the credential/resource ceiling.
Service Account keeps its independent exact caller, signed user assertion,
active Organization membership and `service-account.manage` checks. Its create
and rotate responses belong to a controlled human UI/CLI; no model tool
projection is added for raw secrets.

Caller configuration accepts the Runtime's exact `plugin-id/instance-key` form
and the explicit legacy single-segment form. Empty segments, extra separators
and aliases are rejected. Operation audiences permit the existing `@major`
Capability spelling without converting an audience into permission. Secret
verifiers, rotation overlap, disabled/expired/revoked admission, caller-scoped
receipts and one-time secret exposure are unchanged.

Credential Issuer still has no idempotent issuance/status contract. After
`issuing` has been persisted, a lost response remains `operation_in_progress`.
`ServiceAccountOperator::inspect_command(database_url, schema, caller,
operation, idempotency_key)` reads only sanitized state and timestamps from
this Plugin's owned schema. `requires_issuer_reconciliation()` marks `issuing`.
The operator API never returns a verifier, secret, encrypted receipt, or digest;
it does not retry, reset or compensate issuance. The operator must correlate
external issuer evidence through that owner before any manual recovery.
Directory orphans have no local credential and are not automatically deleted.

The PostgreSQL acceptance test covers persisted unknown state, repeated reads,
caller isolation, replay rejection and no second issuance admission alongside
restart, competing rotation CAS, secret redaction and expiry/revocation.
Preparation verifies the ledger; setup/upgrade remain explicit operator actions.
Native PostgreSQL is qualified here. A complete Workers closure is required
before admitting this optional Plugin there; Auth D1 support alone is insufficient.

The current source candidate pins the coherent Core Rust cohort, including
native macros, to source revision `1dbc6b441ccc5571e2349ab4ae6e23a072a9093e`, which includes the same-role
lowering fix. Codegen remains version 0.10.0 and generated ABI stays unchanged. The public package
verification applies that same immutable patch to extracted crate archives;
consuming App roots must select that same Core revision for their Core source
dependencies until a released macro carries the fix. This is source qualification, not registry publication.
