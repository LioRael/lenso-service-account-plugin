# Release process

This repository has three public Rust crates:

1. `lenso-capability-service-account`
2. `lenso-capability-service-account-auth`
3. `lenso-service-account-postgres-plugin`

Publish the two Capability crates before the Plugin. Publication is manual-only
from a clean, reviewed `main` checkout through
`.github/workflows/release-plz.yml`. Pushes to `main` may refresh a Release-plz
PR; merging that PR does not itself publish.

`lenso-capability-access-control` 0.2.0 is an immutable registered dependency.
The package gate verifies its downloaded archive against the primary sparse
index checksum and reuses its normalized manifest. It does not repackage the
Access Control repository under an already published version.

## Trusted Publisher configuration

Trusted Publishing cannot allocate an unowned crates.io name. For the first
release only, allocate each `0.1.0` package name in dependency order using a
temporary crates.io token restricted to new-package publication, then revoke it
immediately. Do not store it in Cargo credentials, GitHub secrets, workflow
logs, or shell history.

Configure a crates.io Trusted Publisher separately for all three crates:

- owner: `LioRael`
- repository: `lenso-service-account-plugin`
- workflow: `release-plz.yml`
- environment: unset

The workflow has no Cargo registry token fallback. Its live job requests a
short-lived crates.io credential through GitHub OIDC and requires `main`,
`live=true`, and literal confirmation `publish`.

## Required gates

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
lenso-contract-codegen check crates/lenso-capability-service-account/capability.json \
  --rust crates/lenso-capability-service-account/src/generated.rs
lenso-contract-codegen check crates/lenso-capability-service-account-auth/capability.json \
  --rust crates/lenso-capability-service-account-auth/src/generated.rs
./scripts/check-public-packages.sh
./scripts/check-repository-boundary.sh
```

The package check verifies both Capability archives, creates the Plugin archive
with temporary source patches for the as-yet-unpublished Capability versions,
then regenerates and verifies the exact consumer dependency graph from the
normalized archives.

The current source cohort also supplies the paired Core SDK dependencies at
`cac6db9d3293197754cce0ec707e909e0bed79a6`. Archive verification retains that
explicit source patch. It proves the source archives with this SDK cohort;
registry-only consumer verification and publication still require the matching
Core package versions to be published separately.

Run real PostgreSQL acceptance before publication:

```sh
LENSO_TEST_POSTGRES_ADMIN_URL=postgres://.../postgres \
  cargo test --locked -p lenso-service-account-postgres-plugin \
  restart_concurrency_and_secret_once_acceptance -- --ignored
```

The test role must be able to create and drop an isolated database. The suite
must prove restart persistence, caller-scoped idempotency, CAS concurrency,
secret-once receipts, durable rate limits, and revoked/expired fail-closed
behavior.
