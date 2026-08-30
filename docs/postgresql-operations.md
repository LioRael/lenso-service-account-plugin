# PostgreSQL operations

The Plugin owns exactly one configured PostgreSQL schema. Runtime activation is
readiness verification, not a migration path.

## Install and upgrade

Use `ServiceAccountOperator::setup(database_url, schema)` once for a new schema.
Use `ServiceAccountOperator::upgrade(database_url, schema)` in an explicit,
reviewed deployment step before starting a Plugin version whose migration
ledger is newer. Both operations use the same immutable `SchemaPlan` embedded
in the crate.

The runtime database principal needs ordinary DML on the owned schema and read
access to its migration ledger. It does not need `CREATE DATABASE`, global DDL,
Organization tables, Identity Directory tables, or Credential Issuer tables.
An operator principal may be broader but should still be scoped to this schema.

## Backups and restores

Back up the owned schema and migration ledger atomically. Treat backups as
sensitive because they contain Argon2id verifiers, encrypted issued-credential
receipts, service-account inventory, and operational rate state. A restore must
preserve all command rows; deleting `issuing` state can cause duplicate
Credential Issuer side effects.

After restore, run exact schema preparation against the target version before
allowing traffic. Do not silently create an empty schema or use an in-memory
fallback.

## Secret rotation

- Database URL: rotate with the database/provider's normal dual-credential
  procedure, then restart the Plugin.
- Receipt key: v1 has no key identifier or keyring. Drain or expire completed
  receipts before changing it, or add a reviewed receipt re-encryption
  migration. Existing unreadable receipts fail closed.
- Credential pepper: v1 has no dual-pepper verifier. Rotate every service-
  account credential under a reviewed dual-pepper migration before removing
  the old pepper.

## Operational signals

Monitor failed activation, migration drift, rate lockouts, revision conflicts,
and command counts by status. `issuing` is intentionally terminal for automated
processing under Credential Issuer 1.1; investigate its external session state
before any manual resolution.

Completed command cleanup is bounded by `receipt_ttl_seconds`. Incomplete
`reserved`, `verifying`, and `issuing` commands are not automatically removed.
