# Security policy

Report suspected vulnerabilities privately to the Lenso maintainers. Do not
open a public issue containing service-account secrets, Argon2id verifiers,
peppers, database URLs, receipt keys, Actor assertions, or issued credentials.

## Security boundary

- Treat callers on both configured allowlists as privileged ingress code.
- Rotate the receipt key only with an explicit receipt-retention migration;
  changing it in place makes completed receipts unreadable and fails closed.
- Pepper rotation is not an in-place configuration edit in v1. Existing
  credentials must be rotated under a reviewed dual-pepper or credential
  replacement migration before the old pepper is removed.
- Back up the owned PostgreSQL schema and its migration ledger together. Store
  backups with the same sensitivity as credential verifiers.
- Monitor durable `issuing` commands. They indicate an ambiguous Credential
  Issuer boundary and must not be reset or replayed casually.
- Keep Auth assertion signing keys, Organization policy, and Credential Issuer
  signing authority outside this repository.

The Plugin does not log request payloads. Downstream ingress, telemetry, and
audit integrations must preserve the generated sensitive-field annotations and
redaction behavior.
