#!/bin/sh
set -eu

workspace_version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' Cargo.toml | head -n 1)
extension_version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' extension.toml | head -n 1)

if [ -z "$workspace_version" ] || [ -z "$extension_version" ]; then
  echo "Could not read workspace or extension version" >&2
  exit 1
fi

if [ "$workspace_version" != "$extension_version" ]; then
  echo "Version mismatch: Cargo workspace=$workspace_version extension.toml=$extension_version" >&2
  exit 1
fi

if ! grep -q '^version\.workspace = true$' server/Cargo.toml; then
  echo "The companion must inherit the workspace version" >&2
  exit 1
fi

if [ "${1:-}" != "" ]; then
  tag_version=${1#v}
  if [ "$tag_version" != "$workspace_version" ]; then
    echo "Tag ${1} does not match project version $workspace_version" >&2
    exit 1
  fi
fi

echo "$workspace_version"
