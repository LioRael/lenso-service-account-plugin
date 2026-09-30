# Release process

This repository has three public Rust crates:

1. `lenso-capability-service-account` 0.1.1
2. `lenso-capability-service-account-auth` 0.1.1
3. `lenso-service-account-postgres-plugin` 0.1.1

Publish the two Capability crates before the Plugin. Publication is manual-only
from a clean, reviewed `main` checkout through
`.github/workflows/release-plz.yml`. The workflow runs only by explicit dispatch;
source pushes do not publish packages, create tags, or open release PRs. Its
default mode is read-only qualification. Live publication requires separate
human approval, the current Main SHA, exact candidate run/attempt and
`mode=publish`, `confirmation=publish`.

Primary already contains all three 0.1.0 versions. Their immutable archives
cannot be replaced: the current generated Rust Roles and PostgreSQL
implementation differ from those archives. Version 0.1.1 carries the current
implementation and generated SDK surface. Capability IDs, Descriptor versions,
wire Schemas, and database schema remain unchanged. The Plugin requires the two
matching Role packages exactly at 0.1.1.

`lenso-capability-access-control` 0.2.0 is an immutable registered dependency.
The package gate verifies its downloaded archive against the primary sparse
index checksum and reuses its normalized manifest. It does not repackage the
Access Control repository under an already published version.

## Exact release evidence

Manual dispatch supplies `source_sha`, `release_set`, `candidate_run_id` and
`candidate_attempt`. The source must be the clean checkout of freshly read
remote Main. The exact `candidate/**` push workflow must have one successful
`check` job for that same SHA and attempt, including the required package and
real PostgreSQL restart/concurrency gates.

The JSON set contains `package_name`/`version` objects and must equal the
registry-derived pending subset of the three 0.1.1 versions above. Other
packages, wrong versions, duplicates or unavailable registry reads are rejected.
Only `.github/release-owner.toml` is selected by pinned release-plz. No unrelated
package is processed and no release-PR command runs.

The default read-only qualification verifies normalized Cargo packages and
clean source VCS/manifests before release-plz dry-run. The live job requires
separate authorization, repeats all source/set/CI/archive guards and then
reconciles actual package records, Primary visibility, exact source tags and
GitHub releases. A partial or unknown result is inspected before any new
dispatch. Neither source landing nor dry-run authorizes publication.

## Trusted Publisher configuration

Trusted Publishing cannot allocate an unowned crates.io name. The three package
names are already allocated by their 0.1.0 releases. For a future new name only,
allocate its first version in dependency order using a
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
registry-only consumer verification must use the matching published Core
versions. A source-cohort archive check does not authorize an Owner package
publication or replace the required registry consumer check.

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
