#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: verify-macos-deployment-target.sh <minimum-version>" >&2
  exit 2
fi

expected_version=$1
metadata=$(cat)

if printf '%s\n' "$metadata" | grep -A 3 'LC_BUILD_VERSION' | \
  awk -v expected="$expected_version" '$1 == "minos" && $2 == expected { found = 1 } END { exit !found }'; then
  exit 0
fi

if printf '%s\n' "$metadata" | grep -A 3 'LC_VERSION_MIN_MACOSX' | \
  awk -v expected="$expected_version" '$1 == "version" && $2 == expected { found = 1 } END { exit !found }'; then
  exit 0
fi

echo "expected macOS deployment target $expected_version was not found in Mach-O metadata" >&2
exit 1
