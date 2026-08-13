# Ansible Vault for Zed

A Zed extension and native companion language server for encrypting Ansible Vault files and YAML
`!vault` values. It does not patch Zed and coexists with the existing Ansible/YAML language
servers.

This extension complements the existing **Ansible** extension in the Zed catalog. It adds Vault
operations and diagnostics; it does not replace Ansible syntax highlighting or its language server.

## Installation

After the catalog release, open Zed Extensions, search for **Ansible Vault**, and select **Install**.
The extension downloads the native companion matching its own version and verifies its SHA-256
checksum before making it executable. Companion `0.2.0` is downloaded only from release `v0.2.0`.

For development, open the command palette, run **Extensions: Install Dev Extension**, and select
this repository. A development install can use a locally built companion as described below.

## Actions

Open Zed's contextual code actions menu with `editor: toggle code actions`. With the JetBrains
keymap this is `Alt/Option+Enter`; from the global command palette (double Shift in that keymap),
search for `editor: toggle code actions`. The Vault actions are dynamic LSP actions, so they appear
in the contextual menu rather than directly in the global command palette. To show the toolbar
button, enable `toolbar.code_actions` in Zed settings.

Zed chooses the position of its inline bolt itself. It hides the bolt when the cursor is on a blank
line. If a nonblank cursor line has less than four columns of indentation available for the inline
slot, Zed may move the bolt to a nearby blank or more deeply indented line (up to eight lines away).
The LSP protocol does not let this extension set the bolt coordinates; `Alt/Option+Enter` still
opens the actions for the current cursor position, and the toolbar button does not move between
lines.

For whole-file actions the active document must be a saved `file://` file. Availability is
contextual:

- A regular YAML/Ansible file always offers **Encrypt File**, regardless of cursor position.
- A complete Vault file always offers only **Decrypt File**, regardless of cursor position.
- A scalar mapping value offers **Encrypt YAML Value** from anywhere on its key line or inside the
  value, including multiline scalars.
- A `!vault` mapping value offers **Decrypt !vault Value** from anywhere on its key line or inside
  any ciphertext line. A malformed Vault header still offers decryption and never offers value
  encryption; resolving it stops with a validation error and does not modify the document.

- **Ansible Vault: Encrypt File**
- **Ansible Vault: Decrypt File**
- **Ansible Vault: Encrypt YAML Value**
- **Ansible Vault: Decrypt !vault Value**
- **Ansible Vault: Fix Vault Header** (only when a canonical header can be inferred safely)

There is no separate setup check. Selecting any action performs a new preflight before prompting
or changing data: platform, executable and command support, private temp storage, source access,
target-directory access, password file, or GUI prompt backend.

## Vault diagnostics

The companion validates complete Vault files and inline `!vault` blocks whenever a document is
opened or changed. Invalid markers, unsupported Vault versions or ciphers, missing Vault 1.2 IDs,
empty payloads, and non-hexadecimal payload lines are published as standard LSP errors. Zed
underlines the exact header field or payload line, shows it in the Diagnostics view and scrollbar,
and clears it immediately after the document is corrected or closed. The versioned **Fix Vault
Header** quick fix recognizes confident errors in the marker, separators, version, and cipher and
normalizes the entire line to `$ANSIBLE_VAULT;1.1;AES256` or to a Vault 1.2 header while preserving
its existing ID. It is withheld when a Vault 1.2 ID is missing or the input is too ambiguous. The
fix never invokes Ansible or requests a password.

To keep diagnostic messages visible to the right of their source lines, enable Zed's inline
diagnostics through `editor: toggle inline diagnostics` or settings:

```json
{
  "diagnostics": {
    "inline": {
      "enabled": true,
      "max_severity": "warning"
    }
  }
}
```

## Requirements

- Zed with support for third-party language-server extensions.
- `ansible-vault` from a maintained `ansible-core` release installed on the host. Release `0.2.0`
  is tested with `ansible-core` 2.19, 2.20, and 2.21.
- If no password file is configured:
  - macOS: `/usr/bin/osascript`;
  - Linux: a graphical session and one of `zenity`, `kdialog`, or `yad`.

The extension never bundles Ansible or a dialog tool.

| Platform | Architectures | Support |
| --- | --- | --- |
| macOS 10.15.7 or newer | Intel `x86_64` | Supported |
| macOS 11 or newer | Apple Silicon `aarch64` | Supported |
| Linux supported by Zed | `x86_64`, `aarch64` | Supported with static companion binaries |
| Windows | — | Not supported in 0.2.0 |

Interactive prompts require a graphical desktop session. Headless and remote environments must use
`ansibleVault.passwordFile`.

## Settings

Open Zed's Settings Editor (`Cmd+,` on macOS or `Ctrl+,` on Linux) for global configuration, or edit
`.zed/settings.json` in a project. Search for and open the JSON settings file from that UI, then add
the LSP section below. Zed knows how to start the installed extension, but the `lsp` key is still
required when you want to customize its settings. Project settings override global settings through
Zed's normal LSP settings merge. The Zed extension API does not currently allow this extension to
register a custom graphical settings form.

```json
{
  "lsp": {
    "ansible-vault-lsp": {
      "settings": {
        "ansibleVault": {
          "executable": "ansible-vault",
          "passwordFile": ".vault-password",
          "vaultId": null,
          "promptBackend": "auto"
        }
      }
    }
  }
}
```

`passwordFile` accepts an absolute path, `~/...`, or a path relative to the worktree containing the
current document. A configured but missing, empty, unreadable, or non-regular file is an error; the
server does not silently fall back to a prompt. On POSIX, broadly accessible permissions produce a
warning. The password itself must never be put in settings.

`promptBackend` is `auto`, `osascript`, `zenity`, `kdialog`, or `yad`. An explicitly selected
backend never falls back to another one. `vaultId` supplies the label for Ansible Vault 1.2 and may
not contain `@`.

For local companion development, point Zed directly at the debug or release binary:

```json
{
  "lsp": {
    "ansible-vault-lsp": {
      "binary": {
        "path": "/absolute/path/to/ansible-vault-lsp"
      }
    }
  }
}
```

## Safety model

- Interactive passwords are entered once in a masked native dialog for both encryption and
  decryption.
- Passwords are held in zeroizing memory and passed to Ansible only via a private `0600` temporary
  password file. Passwords and plaintext never appear in process arguments or environment.
- Processes are launched directly without a shell, use a private `ANSIBLE_LOCAL_TEMP`, have a
  timeout, and are killed when timed out.
- Inline changes use a versioned `WorkspaceEdit`, so they participate in Undo and fail safely if
  the document changes.
- Whole-file operations reject dirty, read-only, symlinked, special, and non-UTF-8 files. They run
  on private copies, recheck the document version and disk hash, preserve POSIX permissions, and
  atomically rename the result in the original directory.
- Only one Vault operation may run for a document at a time. Raw Ansible stdout/stderr is never
  exposed in UI errors or logs.

## Development

Install Rust 1.97.1 with `rustfmt`, `clippy`, and the `wasm32-wasip2` target, then run:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build -p ansible-vault-lsp --locked
cargo build -p zed-ansible-vault-extension --release --locked --target wasm32-wasip2
./scripts/check-release-version.sh
```

Before using **Install Dev Extension**, verify the exact toolchain visible to Zed:

```sh
./scripts/check-dev-environment.sh
```

Zed requires `cargo` and `rustc` to be rustup proxies. On macOS, installing both the Homebrew
`rust` and `rustup` formulae can leave `/opt/homebrew/bin/rustc` pointing at the standalone
Homebrew sysroot while `wasm32-wasip2` is installed in the rustup sysroot. The resulting Zed log
contains `can't find crate for core`, and the failed extension will not appear in the installed
list. Fix that conflict with:

```sh
brew unlink rust
brew link --force rustup
rustup target add wasm32-wasip2
```

In Zed, use **Extensions: Install Dev Extension** and select this repository. Configure the local
binary path while developing. Release assets are named
`ansible-vault-lsp-{darwin|linux}-{aarch64|x86_64}` with adjacent `.sha256` files.

## Troubleshooting

- **No Vault actions:** save the file, make sure its language is YAML or Ansible, and run
  `editor: toggle code actions` with the cursor on a nonblank line. Check the Zed language-server
  log for `ansible-vault-lsp` startup errors.
- **`ansible-vault` not found:** use an absolute `ansibleVault.executable` or launch Zed from an
  environment whose `PATH` contains Ansible.
- **No password dialog on Linux:** verify `DISPLAY` or `WAYLAND_DISPLAY` and install `zenity`,
  `kdialog`, or `yad`; otherwise configure a password file.
- **Companion download failure:** confirm GitHub Releases is reachable and the extension can write
  to its own extension directory. Reinstalling retries a clean staged download; checksum failures
  are never activated.
- **File changed but the buffer did not refresh:** reload the file before editing it. The operation
  has already completed on disk, and the warning prevents editing stale plaintext/ciphertext.
- **Persistent diagnostics:** open Zed's Diagnostics view or enable inline diagnostics. The header
  quick fix appears only when the intended canonical header can be inferred safely.

When reporting a problem, include the extension, Zed, OS, and `ansible-vault --version` values plus
a synthetic reproduction. Never include a real password, password file, decrypted value, private
Vault payload, or identifying filesystem path. See [SECURITY.md](SECURITY.md) for private reports.

## Release and E2E

The complete contributor, release, rollback, catalog, and manual E2E procedures are documented in
[CONTRIBUTING.md](CONTRIBUTING.md). Release artifacts include per-file checksums, a combined
`SHA256SUMS`, a CycloneDX SBOM, and GitHub build-provenance attestations.

## License

MIT
