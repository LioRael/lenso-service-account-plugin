#!/usr/bin/env bash
set -euo pipefail

forbidden='lenso-platform-|lenso-module-auth|HostBuilder|HostLinkedModule|ModuleManifest|lenso module install|platform_core|platform_module'

if rg -n "$forbidden" Cargo.toml crates README.md docs --glob '!**/generated.rs'; then
  echo "legacy Lenso framework dependency or API found in Service Account source" >&2
  exit 1
fi

if rg -n 'CREATE TABLE (users|sessions|organizations|memberships|roles|permissions|grants)' \
  crates/lenso-service-account-postgres-plugin/migrations; then
  echo "Service Account Plugin crossed Identity, Organization, Auth, or Access Control storage" >&2
  exit 1
fi

if rg -n '(println!|eprintln!|dbg!|tracing::[a-z]+!)\([^\n]*(secret|verifier|credential|pepper)' \
  crates/lenso-service-account-postgres-plugin/src --glob '!postgres_tests.rs'; then
  echo "sensitive Service Account material reached a diagnostic macro" >&2
  exit 1
fi

if rg -n 'secret:\s*Some' crates/lenso-service-account-postgres-plugin/src/storage.rs \
  crates/lenso-service-account-postgres-plugin/src/crypto.rs; then
  echo "raw account secret entered durable storage code" >&2
  exit 1
fi

management_lines="$(wc -l < crates/lenso-service-account-postgres-plugin/src/management.rs)"
storage_lines="$(wc -l < crates/lenso-service-account-postgres-plugin/src/storage.rs)"
if (( management_lines > 1000 || storage_lines > 1000 )); then
  echo "Service Account deep-module boundary exceeded 1000 lines" >&2
  exit 1
fi

printf 'repository boundary is service-account-only and vNext-only\n'
