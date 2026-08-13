#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
verifier="$script_directory/verify-macos-deployment-target.sh"

printf '%s\n' \
  '      cmd LC_BUILD_VERSION' \
  '  cmdsize 32' \
  ' platform 1' \
  '    minos 11.0' | "$verifier" 11.0

printf '%s\n' \
  '      cmd LC_VERSION_MIN_MACOSX' \
  '  cmdsize 16' \
  '  version 10.15.7' \
  '      sdk 26.5' | "$verifier" 10.15.7

if printf '%s\n' \
  '      cmd LC_VERSION_MIN_MACOSX' \
  '  cmdsize 16' \
  '  version 10.15.7' \
  '      sdk 26.5' | "$verifier" 11.0 >/dev/null 2>&1; then
  echo 'deployment target verifier accepted the wrong version' >&2
  exit 1
fi

if printf '%s\n' \
  '      cmd LC_VERSION_MIN_MACOSX' \
  '  cmdsize 16' \
  '  version 10x15x7' \
  '      sdk 26.5' | "$verifier" 10.15.7 >/dev/null 2>&1; then
  echo 'deployment target verifier treated version punctuation as a pattern' >&2
  exit 1
fi
