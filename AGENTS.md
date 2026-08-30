# Agent instructions

This repository owns only organization-scoped service-account identity,
credential rotation, and secret exchange. Read `CONTEXT.md`, local ADRs, and
`docs/release-process.md` before architecture or release work.

Keep Organization membership, RBAC policy, canonical Directory state, issued
tokens, HTTP ingress, and Audit outside this repository. Management requires an
exact caller, an operation-audienced Auth assertion, active Organization
membership, and an independent Access Control decision.

Capability source lives in each crate's `src/contract.rs`. Descriptor, Schemas,
and generated Rust are locked artifacts and must never be hand-edited. Run
Cargo through `/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo`.
Use concise imperative Conventional Commit subjects under 72 characters.
