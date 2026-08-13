# Changelog

All notable changes are documented here. Versions follow Semantic Versioning while the extension
remains below `1.0.0`.

## [Unreleased]

## [0.2.1] - 2026-08-13

### Fixed

- Accept both modern `LC_BUILD_VERSION` and legacy `LC_VERSION_MIN_MACOSX` metadata when verifying
  the Intel macOS 10.15.7 deployment target. The unpublished `v0.2.0` workflow was stopped before
  creating a GitHub Release or uploading release assets.

## [0.2.0] - 2026-08-13

### Added

- Production release workflow for four native macOS/Linux companion assets.
- Companion `--version` command, CycloneDX SBOM, checksums, and build-provenance attestations.
- Dependency, license, advisory, package, property, and maintained-Ansible CI checks.
- Project security policy, contributor guide, and GitHub issue/PR templates.

### Changed

- Pin companion downloads to the release tag matching the installed extension version.
- Download and verify the companion in staging before atomically activating it.
- Build static Linux companions and target the architecture-appropriate Zed macOS floor (10.15.7
  on Intel and 11.0 on Apple Silicon).
- Replace deprecated `serde_yaml` with `serde-saphyr`.
- Pin the production Rust toolchain to 1.97.1.

### Compatibility

- Settings and the four Vault actions remain compatible with 0.1.5.
- Windows, headless interactive prompts, automatic decrypt-on-open, and password caching remain out
  of scope.

[Unreleased]: https://github.com/gesundes/zed-ansible-vault/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/gesundes/zed-ansible-vault/releases/tag/v0.2.1
[0.2.0]: https://github.com/gesundes/zed-ansible-vault/releases/tag/v0.2.0
