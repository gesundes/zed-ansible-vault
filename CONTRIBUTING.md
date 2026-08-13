# Contributing

## Local verification

Install Rust 1.97.1 with `rustfmt`, `clippy`, and `wasm32-wasip2`, then run:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build -p zed-ansible-vault-extension --release --locked --target wasm32-wasip2
./scripts/check-release-version.sh
```

Install `cargo-deny 0.20.2` and run `cargo deny check`. The official Zed package check can be run on
Linux with `./scripts/check-zed-package.sh`; all of its generated data is kept under `/tmp`.

Tests and fixtures must use synthetic secrets. Never add a real password, decrypted value, private
Vault payload, identifying path, or unsanitized Zed log/screenshot to the repository.

## Manual E2E matrix

Before a release, install the extension from a clean checkout without a local companion override and
test Zed Stable and Preview. Cover macOS Intel/Apple Silicon and Linux x86_64/aarch64 where hardware
is available.

The macOS release metadata must report a minimum OS of 10.15 for Intel and 11.0 for Apple Silicon.
Linux assets must be statically linked musl executables.

- Verify global and project settings precedence.
- Exercise Encrypt File, Decrypt File, Encrypt YAML Value, and Decrypt `!vault` Value.
- Exercise password-file and masked prompt flows, prompt cancellation, and a wrong password.
- Round-trip Vault 1.1 and labeled Vault 1.2, quoted scalars, and multiline values.
- Verify diagnostics and Fix Vault Header for valid, repairable, and ambiguous headers.
- Verify dirty/read-only/symlink files, concurrent document changes, timeouts, and watcher refresh.
- Inspect Zed logs and process arguments for absence of passwords and plaintext.

After the GitHub Release is published, repeat the smoke test using the downloaded release companion,
not a local binary override, before opening the catalog PR.

## Release procedure

1. Update `CHANGELOG.md` and bump the workspace and `extension.toml` versions together.
2. Run all local and CI checks. Merge the release commit to `main`.
3. Create and push an annotated tag such as `v0.2.0`. The tag must point to a commit reachable from
   `main`.
4. Approve the protected `release` GitHub environment after all four native builds pass.
5. Verify the GitHub Release contains four binaries, adjacent checksums, `SHA256SUMS`, the CycloneDX
   SBOM, and GitHub attestations. Do not replace assets for an existing tag.
6. Complete the post-release clean-install E2E matrix.
7. Fork `zed-industries/extensions`, add this repository as the HTTPS submodule
   `extensions/ansible-vault`, and add:

   ```toml
   [ansible-vault]
   submodule = "extensions/ansible-vault"
   version = "0.2.0"
   ```

8. Run `pnpm sort-extensions` and `pnpm package-extensions ansible-vault`, then open the catalog PR.
   Explain that this extension complements the existing Ansible extension and that its download
   capability is restricted to versioned companion assets in this repository.
9. After merge, install from the public Zed Extensions UI and repeat one file and one value round
   trip.

## Rollback

GitHub release assets are immutable. If a release is broken, do not retag or overwrite it. Fix the
problem, publish the next patch release, update the catalog submodule/version in a new PR, and note
the affected version in the changelog and GitHub Release notes.
