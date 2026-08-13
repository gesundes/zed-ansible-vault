#!/bin/sh
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work_directory=$(mktemp -d /tmp/zed-ansible-vault-package.XXXXXX)
trap 'rm -rf "$work_directory"' EXIT HUP INT TERM

cli=${ZED_EXTENSION_CLI:-"$work_directory/zed-extension"}
if [ ! -x "$cli" ]; then
  cli_sha=9ee3c503a4bbbc6b4a0f8a789acca4871d773223
  curl --fail --silent --show-error --location \
    "https://zed-extension-cli.nyc3.digitaloceanspaces.com/$cli_sha/x86_64-unknown-linux-gnu/zed-extension" \
    --output "$cli"
  chmod 0700 "$cli"
fi

"$cli" \
  --scratch-dir "$work_directory/scratch" \
  --source-dir "$repository" \
  --output-dir "$work_directory/output"

version=$("$repository/scripts/check-release-version.sh")
grep -Eq "\"version\"[[:space:]]*:[[:space:]]*\"$version\"" \
  "$work_directory/output/manifest.json" || {
  echo "Packaged manifest version does not match $version" >&2
  exit 1
}

echo "Zed package validation passed for version $version"
