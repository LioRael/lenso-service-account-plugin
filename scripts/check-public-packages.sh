#!/usr/bin/env bash
set -euo pipefail

cargo_bin="${LENSO_CARGO_BIN:-cargo}"
repository_root="$(git rev-parse --show-toplevel)"
package_flags=(--locked)
plugin_package_flags=()
verification_root="$(mktemp -d "${TMPDIR:-/tmp}/lenso-service-account-packages.XXXXXX")"

cleanup() {
  if [[ "${LENSO_KEEP_PACKAGE_TMP:-0}" == "1" ]]; then
    printf 'kept package verification root: %s\n' "$verification_root" >&2
  else
    rm -r "$verification_root"
  fi
}
trap cleanup EXIT

macro_config="$verification_root/native-macro-candidate.toml"
cat > "$macro_config" <<'TOML'
[patch.crates-io]
lenso-native-adapter-macros = { git = "https://github.com/LioRael/lenso", rev = "f707b9f045217d25647fa6c4f2c09500271998bc" }
TOML
cargo_with_runtime_patch() {
  "$cargo_bin" --config "$macro_config" "$@"
}

if [[ "${LENSO_PACKAGE_ALLOW_DIRTY:-0}" == "1" ]]; then
  package_flags+=(--allow-dirty)
  plugin_package_flags+=(--allow-dirty)
fi

for capability in \
  lenso-capability-service-account \
  lenso-capability-service-account-auth; do
  cargo_with_runtime_patch package --quiet "${package_flags[@]}" -p "$capability"
done

metadata="$(cargo_with_runtime_patch metadata --no-deps --format-version=1)"
target_directory="$(python3 -c \
  'import json, sys; print(json.load(sys.stdin)["target_directory"])' \
  <<<"$metadata")"
management_version="$(python3 -c \
  'import json, sys; name = sys.argv[1]; print(next(package["version"] for package in json.load(sys.stdin)["packages"] if package["name"] == name))' \
  lenso-capability-service-account <<<"$metadata")"
authentication_version="$(python3 -c \
  'import json, sys; name = sys.argv[1]; print(next(package["version"] for package in json.load(sys.stdin)["packages"] if package["name"] == name))' \
  lenso-capability-service-account-auth <<<"$metadata")"
plugin_version="$(python3 -c \
  'import json, sys; name = sys.argv[1]; print(next(package["version"] for package in json.load(sys.stdin)["packages"] if package["name"] == name))' \
  lenso-service-account-postgres-plugin <<<"$metadata")"

bootstrap_source="$verification_root/bootstrap-source"
bootstrap_target="$verification_root/bootstrap-target"
mkdir "$bootstrap_source"
cp "$repository_root/Cargo.toml" "$repository_root/Cargo.lock" "$bootstrap_source/"
cp -R "$repository_root/crates" "$bootstrap_source/crates"
management_source="$bootstrap_source/crates/lenso-capability-service-account"
authentication_source="$bootstrap_source/crates/lenso-capability-service-account-auth"
access_control_source="${LENSO_ACCESS_CONTROL_SOURCE:-}"
if [[ -z "$access_control_source" ]]; then
  access_control_checkout="$verification_root/access-control"
  git clone --quiet --filter=blob:none --no-checkout \
    https://github.com/LioRael/lenso-access-control-plugin "$access_control_checkout"
  git -C "$access_control_checkout" checkout --quiet --detach \
    62ed6b9a100242e6932a46cb369b21f1c26ab765
  access_control_source="$access_control_checkout/crates/lenso-capability-access-control"
fi
access_control_root="$(git -C "$access_control_source" rev-parse --show-toplevel)"
access_control_metadata="$(cargo_with_runtime_patch metadata --manifest-path "$access_control_root/Cargo.toml" --no-deps --format-version=1)"
access_control_target="$(python3 -c \
  'import json, sys; print(json.load(sys.stdin)["target_directory"])' \
  <<<"$access_control_metadata")"
access_control_version="$(python3 -c \
  'import json, sys; name = sys.argv[1]; print(next(package["version"] for package in json.load(sys.stdin)["packages"] if package["name"] == name))' \
  lenso-capability-access-control <<<"$access_control_metadata")"
"$cargo_bin" package --quiet --locked \
  --manifest-path "$access_control_root/Cargo.toml" \
  -p lenso-capability-access-control
access_control_archive="$access_control_target/package/lenso-capability-access-control-$access_control_version.crate"
management_source_patch="patch.crates-io.lenso-capability-service-account.path=\"$management_source\""
authentication_source_patch="patch.crates-io.lenso-capability-service-account-auth.path=\"$authentication_source\""
access_control_source_patch="patch.crates-io.lenso-capability-access-control.path=\"$access_control_source\""

# Cargo must resolve both unpublished local Capabilities and the not-yet-published
# Access Control Capability while creating the Plugin archive. This bootstrap
# step intentionally regenerates only the archive-local lockfile; the normalized
# consumer graph is fully checked, tested, and linted below.
cargo_with_runtime_patch \
  --config "$management_source_patch" \
  --config "$authentication_source_patch" \
  --config "$access_control_source_patch" \
  package --quiet "${plugin_package_flags[@]}" --no-verify \
  -p lenso-service-account-postgres-plugin \
  --manifest-path "$bootstrap_source/Cargo.toml" --target-dir "$bootstrap_target"

management_archive="$target_directory/package/lenso-capability-service-account-$management_version.crate"
authentication_archive="$target_directory/package/lenso-capability-service-account-auth-$authentication_version.crate"
plugin_archive="$bootstrap_target/package/lenso-service-account-postgres-plugin-$plugin_version.crate"

tar -xzf "$management_archive" -C "$verification_root"
tar -xzf "$authentication_archive" -C "$verification_root"
tar -xzf "$access_control_archive" -C "$verification_root"
tar -xzf "$plugin_archive" -C "$verification_root"

management_package="$verification_root/lenso-capability-service-account-$management_version"
authentication_package="$verification_root/lenso-capability-service-account-auth-$authentication_version"
access_control_package="$verification_root/lenso-capability-access-control-$access_control_version"
plugin_package="$verification_root/lenso-service-account-postgres-plugin-$plugin_version"

[[ -f "$management_package/Cargo.toml" ]]
[[ -f "$authentication_package/Cargo.toml" ]]
[[ -f "$access_control_package/Cargo.toml" ]]
[[ -f "$plugin_package/Cargo.toml" ]]

management_package_patch="patch.crates-io.lenso-capability-service-account.path=\"$management_package\""
authentication_package_patch="patch.crates-io.lenso-capability-service-account-auth.path=\"$authentication_package\""
access_control_package_patch="patch.crates-io.lenso-capability-access-control.path=\"$access_control_package\""
plugin_manifest="$plugin_package/Cargo.toml"

cargo_with_runtime_patch \
  --config "$management_package_patch" \
  --config "$authentication_package_patch" \
  --config "$access_control_package_patch" \
  generate-lockfile --manifest-path "$plugin_manifest"
cargo_with_runtime_patch \
  --config "$management_package_patch" \
  --config "$authentication_package_patch" \
  --config "$access_control_package_patch" \
  check --quiet --locked --all-targets --manifest-path "$plugin_manifest"
cargo_with_runtime_patch \
  --config "$management_package_patch" \
  --config "$authentication_package_patch" \
  --config "$access_control_package_patch" \
  test --quiet --locked --manifest-path "$plugin_manifest"
"$cargo_bin" clippy \
  --config "$macro_config" \
  --config "$management_package_patch" \
  --config "$authentication_package_patch" \
  --config "$access_control_package_patch" \
  --quiet --locked --all-targets --manifest-path "$plugin_manifest" -- -D warnings
