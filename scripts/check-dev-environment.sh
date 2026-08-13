#!/bin/sh
set -eu

target="wasm32-wasip2"

if ! command -v rustup >/dev/null 2>&1; then
  echo "error: rustup is not available in PATH; Zed requires Rust installed through rustup" >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then
  echo "error: cargo and rustc must be available in PATH" >&2
  exit 1
fi

rustup_sysroot=$(rustup run stable rustc --print sysroot)
active_sysroot=$(rustc --print sysroot)
if [ "$active_sysroot" != "$rustup_sysroot" ]; then
  echo "error: rustc does not use the rustup stable sysroot" >&2
  echo "active: $active_sysroot" >&2
  echo "rustup: $rustup_sysroot" >&2
  echo "On Homebrew, run: brew unlink rust && brew link --force rustup" >&2
  exit 1
fi

if ! rustup target list --installed | grep -qx "$target"; then
  echo "error: Rust target $target is not installed" >&2
  echo "run: rustup target add $target" >&2
  exit 1
fi

cargo build --release --target "$target"
echo "Zed dev-extension environment is ready."
