## Summary

Describe the user-visible and implementation changes.

## Verification

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace --locked`
- [ ] `cargo deny check`
- [ ] WASM and companion builds succeed
- [ ] Tests use synthetic secrets only
- [ ] No password, plaintext, private Vault payload, or identifying path appears in code, fixtures, logs, or screenshots
- [ ] `extension.toml`, workspace, companion, tag, and changelog versions agree when this is a release
