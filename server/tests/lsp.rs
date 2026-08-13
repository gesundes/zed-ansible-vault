#![cfg(unix)]

use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

struct LspProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl LspProcess {
    async fn start(root: &Path, settings: Value) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ansible-vault-lsp"))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("start companion LSP");
        let stdin = child.stdin.take().expect("server stdin");
        let stdout = BufReader::new(child.stdout.take().expect("server stdout"));
        let mut process = Self {
            child,
            stdin,
            stdout,
        };
        let root_uri = format!("file://{}", root.display());
        let result = process
            .request(
                1,
                "initialize",
                json!({
                    "capabilities": {},
                    "rootUri": root_uri,
                    "initializationOptions": settings
                }),
            )
            .await;
        assert_eq!(
            result["capabilities"]["codeActionProvider"]["resolveProvider"],
            true
        );
        process.notify("initialized", json!({})).await;
        process
    }

    async fn send(&mut self, message: Value) {
        let bytes = serde_json::to_vec(&message).expect("JSON-RPC message");
        self.stdin
            .write_all(format!("Content-Length: {}\r\n\r\n", bytes.len()).as_bytes())
            .await
            .expect("write LSP header");
        self.stdin.write_all(&bytes).await.expect("write LSP body");
        self.stdin.flush().await.expect("flush LSP message");
    }

    async fn receive(&mut self) -> Value {
        let mut content_length = None;
        loop {
            let mut line = String::new();
            self.stdout
                .read_line(&mut line)
                .await
                .expect("read LSP header");
            if line == "\r\n" || line == "\n" {
                break;
            }
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                content_length = Some(value.trim().parse::<usize>().expect("content length"));
            }
        }
        let mut body = vec![0_u8; content_length.expect("Content-Length header")];
        self.stdout
            .read_exact(&mut body)
            .await
            .expect("read LSP body");
        serde_json::from_slice(&body).expect("JSON-RPC response")
    }

    async fn notification(&mut self, method: &str) -> Value {
        loop {
            let message = self.receive().await;
            if message["method"] == method {
                return message["params"].clone();
            }
        }
    }

    async fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        }))
        .await;
        loop {
            let response = self.receive().await;
            if response["id"] == id {
                return response["result"].clone();
            }
        }
    }

    async fn notify(&mut self, method: &str, params: Value) {
        self.send(json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        }))
        .await;
    }

    async fn stop(mut self) {
        let _ = self.request(99, "shutdown", Value::Null).await;
        self.notify("exit", Value::Null).await;
        self.stdin.shutdown().await.expect("close server stdin");
        drop(self.stdin);
        tokio::time::timeout(std::time::Duration::from_secs(2), self.child.wait())
            .await
            .expect("server exit timeout")
            .expect("server exit");
    }
}

fn open_params(uri: &str, version: i32, text: &str) -> Value {
    json!({
        "textDocument": {
            "uri": uri,
            "languageId": "yaml",
            "version": version,
            "text": text
        }
    })
}

fn action_params(uri: &str) -> Value {
    action_params_at(uri, 0, 10)
}

fn action_params_at(uri: &str, line: u32, character: u32) -> Value {
    json!({
        "textDocument": { "uri": uri },
        "range": {
            "start": { "line": line, "character": character },
            "end": { "line": line, "character": character }
        },
        "context": { "diagnostics": [] }
    })
}

fn action_titles(actions: &Value) -> Vec<&str> {
    actions
        .as_array()
        .expect("actions")
        .iter()
        .filter_map(|action| action["title"].as_str())
        .collect()
}

#[tokio::test]
async fn advertises_contextual_file_and_scalar_actions() {
    let root = tempfile::tempdir().expect("worktree");
    let path = root.path().join("vars.yml");
    let text = "secret: value\n";
    fs::write(&path, text).expect("YAML file");
    let uri = format!("file://{}", path.display());
    let mut lsp = LspProcess::start(root.path(), json!({})).await;
    lsp.notify("textDocument/didOpen", open_params(&uri, 1, text))
        .await;
    let actions = lsp
        .request(2, "textDocument/codeAction", action_params(&uri))
        .await;
    let titles = action_titles(&actions);
    assert!(titles.contains(&"Ansible Vault: Encrypt File"));
    assert!(titles.contains(&"Ansible Vault: Encrypt YAML Value"));
    lsp.stop().await;
}

#[tokio::test]
async fn advertises_only_decrypt_file_everywhere_in_a_fully_encrypted_file() {
    let root = tempfile::tempdir().expect("worktree");
    let path = root.path().join("vars.yml");
    let text = "$ANSIBLE_VAULT;1.1;AES256\n616263\n646566\n";
    fs::write(&path, text).expect("vault file");
    let uri = format!("file://{}", path.display());
    let mut lsp = LspProcess::start(root.path(), json!({})).await;
    lsp.notify("textDocument/didOpen", open_params(&uri, 1, text))
        .await;

    for (request_id, line) in [(2, 0), (3, 1), (4, 2)] {
        let actions = lsp
            .request(
                request_id,
                "textDocument/codeAction",
                action_params_at(&uri, line, 2),
            )
            .await;
        assert_eq!(action_titles(&actions), vec!["Ansible Vault: Decrypt File"]);
    }
    lsp.stop().await;
}

#[tokio::test]
async fn never_offers_encryption_for_a_file_with_a_malformed_vault_header() {
    let root = tempfile::tempdir().expect("worktree");
    let path = root.path().join("vars.yml");
    let text = "$ANSIBLE_VAULT;9.9;BROKEN\n616263\n";
    fs::write(&path, text).expect("vault-like file");
    let uri = format!("file://{}", path.display());
    let mut lsp = LspProcess::start(root.path(), json!({})).await;
    lsp.notify("textDocument/didOpen", open_params(&uri, 1, text))
        .await;

    for (request_id, line) in [(2, 0), (3, 1)] {
        let actions = lsp
            .request(
                request_id,
                "textDocument/codeAction",
                action_params_at(&uri, line, 2),
            )
            .await;
        assert_eq!(action_titles(&actions), vec!["Ansible Vault: Decrypt File"]);
    }
    lsp.stop().await;
}

#[tokio::test]
async fn publishes_updates_and_clears_inline_vault_diagnostics() {
    let root = tempfile::tempdir().expect("worktree");
    let path = root.path().join("vars.yml");
    let malformed = concat!(
        "secret: !vault |\n",
        "  $sANSIBLE_VAULT;1.1;AES256\n",
        "  616263\n"
    );
    fs::write(&path, malformed).expect("YAML file");
    let uri = format!("file://{}", path.display());
    let mut lsp = LspProcess::start(root.path(), json!({})).await;
    lsp.notify("textDocument/didOpen", open_params(&uri, 1, malformed))
        .await;

    let published = lsp.notification("textDocument/publishDiagnostics").await;
    assert_eq!(published["uri"], uri);
    assert_eq!(published["version"], 1);
    assert_eq!(
        published["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .len(),
        1
    );
    let diagnostic = &published["diagnostics"][0];
    assert_eq!(diagnostic["severity"], 1);
    assert_eq!(diagnostic["source"], "ansible-vault");
    assert_eq!(diagnostic["code"], "ansible-vault.invalid-marker");
    assert_eq!(
        diagnostic["range"]["start"],
        json!({ "line": 1, "character": 2 })
    );
    assert_eq!(
        diagnostic["range"]["end"],
        json!({ "line": 1, "character": 17 })
    );

    let actions = lsp
        .request(2, "textDocument/codeAction", action_params_at(&uri, 1, 8))
        .await;
    let fix = actions
        .as_array()
        .expect("actions")
        .iter()
        .find(|action| action["title"] == "Ansible Vault: Fix Vault Header")
        .expect("header quick fix");
    assert_eq!(fix["kind"], "quickfix");
    assert_eq!(fix["isPreferred"], true);
    assert_eq!(
        fix["edit"]["documentChanges"][0]["textDocument"]["version"],
        1
    );
    assert_eq!(
        fix["edit"]["documentChanges"][0]["edits"][0]["newText"],
        "$ANSIBLE_VAULT;1.1;AES256"
    );

    let corrected = malformed.replace("$sANSIBLE_VAULT", "$ANSIBLE_VAULT");
    lsp.notify(
        "textDocument/didChange",
        json!({
            "textDocument": { "uri": uri, "version": 2 },
            "contentChanges": [{ "text": corrected }]
        }),
    )
    .await;
    let updated = lsp.notification("textDocument/publishDiagnostics").await;
    assert_eq!(updated["version"], 2);
    assert_eq!(updated["diagnostics"], json!([]));

    lsp.notify(
        "textDocument/didClose",
        json!({ "textDocument": { "uri": uri } }),
    )
    .await;
    let cleared = lsp.notification("textDocument/publishDiagnostics").await;
    assert_eq!(cleared["diagnostics"], json!([]));
    lsp.stop().await;
}

#[tokio::test]
async fn treats_a_fixable_full_file_marker_as_vault_not_plaintext() {
    let root = tempfile::tempdir().expect("worktree");
    let path = root.path().join("vars.yml");
    let text = "$sANSIBLE_VAULT;1.1;AES256\n616263\n";
    fs::write(&path, text).expect("Vault-like file");
    let uri = format!("file://{}", path.display());
    let mut lsp = LspProcess::start(root.path(), json!({})).await;
    lsp.notify("textDocument/didOpen", open_params(&uri, 1, text))
        .await;

    let published = lsp.notification("textDocument/publishDiagnostics").await;
    assert_eq!(
        published["diagnostics"][0]["code"],
        "ansible-vault.invalid-marker"
    );
    let actions = lsp
        .request(2, "textDocument/codeAction", action_params_at(&uri, 0, 5))
        .await;
    assert_eq!(
        action_titles(&actions),
        vec![
            "Ansible Vault: Fix Vault Header",
            "Ansible Vault: Decrypt File"
        ]
    );
    assert!(!action_titles(&actions).contains(&"Ansible Vault: Encrypt File"));
    lsp.stop().await;
}

#[tokio::test]
async fn offers_one_smart_fix_for_multiple_header_errors() {
    let root = tempfile::tempdir().expect("worktree");
    let path = root.path().join("vars.yml");
    let text = "$ANSIBLE_VAULT:9.9:ASE-256\n616263\n";
    fs::write(&path, text).expect("Vault-like file");
    let uri = format!("file://{}", path.display());
    let mut lsp = LspProcess::start(root.path(), json!({})).await;
    lsp.notify("textDocument/didOpen", open_params(&uri, 1, text))
        .await;

    let published = lsp.notification("textDocument/publishDiagnostics").await;
    assert!(
        published["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .len()
            >= 2
    );
    let actions = lsp
        .request(2, "textDocument/codeAction", action_params_at(&uri, 0, 8))
        .await;
    let fixes: Vec<_> = actions
        .as_array()
        .expect("actions")
        .iter()
        .filter(|action| action["title"] == "Ansible Vault: Fix Vault Header")
        .collect();
    assert_eq!(fixes.len(), 1);
    assert_eq!(
        fixes[0]["edit"]["documentChanges"][0]["edits"][0]["newText"],
        "$ANSIBLE_VAULT;1.1;AES256"
    );
    assert_eq!(
        fixes[0]["edit"]["documentChanges"][0]["edits"][0]["range"]["start"],
        json!({ "line": 0, "character": 0 })
    );
    assert_eq!(
        fixes[0]["edit"]["documentChanges"][0]["edits"][0]["range"]["end"],
        json!({ "line": 0, "character": 26 })
    );
    lsp.stop().await;
}

#[tokio::test]
async fn advertises_file_action_on_non_value_lines_and_value_action_for_the_whole_pair() {
    let root = tempfile::tempdir().expect("worktree");
    let path = root.path().join("vars.yml");
    let text = "# variables\nsecret: |-\n  first line\n  second line\nnext: value\n";
    fs::write(&path, text).expect("YAML file");
    let uri = format!("file://{}", path.display());
    let mut lsp = LspProcess::start(root.path(), json!({})).await;
    lsp.notify("textDocument/didOpen", open_params(&uri, 1, text))
        .await;

    let comment_actions = lsp
        .request(2, "textDocument/codeAction", action_params_at(&uri, 0, 3))
        .await;
    assert_eq!(
        action_titles(&comment_actions),
        vec!["Ansible Vault: Encrypt File"]
    );

    for (request_id, line, character) in [(3, 1, 1), (4, 1, 8), (5, 2, 4), (6, 3, 8)] {
        let actions = lsp
            .request(
                request_id,
                "textDocument/codeAction",
                action_params_at(&uri, line, character),
            )
            .await;
        assert_eq!(
            action_titles(&actions),
            vec![
                "Ansible Vault: Encrypt File",
                "Ansible Vault: Encrypt YAML Value"
            ]
        );
    }
    lsp.stop().await;
}

#[tokio::test]
async fn advertises_decrypt_value_on_the_key_and_every_vault_payload_line() {
    let root = tempfile::tempdir().expect("worktree");
    let path = root.path().join("vars.yml");
    let text = concat!(
        "secret: !vault |\n",
        "  $ANSIBLE_VAULT;1.1;AES256\n",
        "  616263\n",
        "  646566\n",
        "next: value\n"
    );
    fs::write(&path, text).expect("YAML file");
    let uri = format!("file://{}", path.display());
    let mut lsp = LspProcess::start(root.path(), json!({})).await;
    lsp.notify("textDocument/didOpen", open_params(&uri, 1, text))
        .await;

    for (request_id, line, character) in [(2, 0, 1), (3, 0, 15), (4, 1, 4), (5, 3, 6)] {
        let actions = lsp
            .request(
                request_id,
                "textDocument/codeAction",
                action_params_at(&uri, line, character),
            )
            .await;
        assert_eq!(
            action_titles(&actions),
            vec![
                "Ansible Vault: Encrypt File",
                "Ansible Vault: Decrypt !vault Value"
            ]
        );
    }
    lsp.stop().await;
}

#[tokio::test]
async fn never_offers_encrypt_value_for_a_tagged_vault_with_a_malformed_header() {
    let root = tempfile::tempdir().expect("worktree");
    let path = root.path().join("roles/ssh/defaults/main.yml");
    fs::create_dir_all(path.parent().expect("parent")).expect("fixture directory");
    let text = concat!(
        "---\n",
        "ssh_users:\n",
        "  - name: devops\n",
        "    password: !vault |\n",
        "              $sANSIBLE_VAULT;1.1;AES256\n",
        "              3337646434656465\n",
        "              6462313131616338\n",
        "    uid: 1001\n",
        "  - name: backend\n",
        "    password: \"\"\n"
    );
    fs::write(&path, text).expect("YAML file");
    let uri = format!("file://{}", path.display());
    let mut lsp = LspProcess::start(root.path(), json!({})).await;
    lsp.notify("textDocument/didOpen", open_params(&uri, 1, text))
        .await;

    for (request_id, line, character) in [(2, 3, 5), (3, 3, 22), (4, 4, 18), (5, 5, 25), (6, 6, 20)]
    {
        let actions = lsp
            .request(
                request_id,
                "textDocument/codeAction",
                action_params_at(&uri, line, character),
            )
            .await;
        let expected = if line == 4 {
            vec![
                "Ansible Vault: Fix Vault Header",
                "Ansible Vault: Encrypt File",
                "Ansible Vault: Decrypt !vault Value",
            ]
        } else {
            vec![
                "Ansible Vault: Encrypt File",
                "Ansible Vault: Decrypt !vault Value",
            ]
        };
        assert_eq!(action_titles(&actions), expected);
    }

    let ordinary_value_actions = lsp
        .request(7, "textDocument/codeAction", action_params_at(&uri, 9, 15))
        .await;
    assert_eq!(
        action_titles(&ordinary_value_actions),
        vec![
            "Ansible Vault: Encrypt File",
            "Ansible Vault: Encrypt YAML Value"
        ]
    );

    let malformed_actions = lsp
        .request(8, "textDocument/codeAction", action_params_at(&uri, 5, 25))
        .await;
    let decrypt_action = malformed_actions
        .as_array()
        .expect("actions")
        .iter()
        .find(|action| action["title"] == "Ansible Vault: Decrypt !vault Value")
        .expect("decrypt action")
        .clone();
    let resolved = lsp.request(9, "codeAction/resolve", decrypt_action).await;
    assert!(
        resolved.get("edit").is_none(),
        "a malformed Vault header must never produce an edit"
    );
    lsp.stop().await;
}

#[tokio::test]
async fn resolves_to_a_versioned_edit_and_rejects_a_stale_action() {
    let root = tempfile::tempdir().expect("worktree");
    let executable = fake_ansible_vault(&root);
    let password = root.path().join("password");
    fs::write(&password, "not-a-real-secret\n").expect("password file");
    fs::set_permissions(&password, fs::Permissions::from_mode(0o600))
        .expect("private password permissions");
    let path = root.path().join("vars.yml");
    let text = "secret: value\n";
    fs::write(&path, text).expect("YAML file");
    let uri = format!("file://{}", path.display());
    let mut lsp = LspProcess::start(
        root.path(),
        json!({
            "ansibleVault": {
                "executable": executable,
                "passwordFile": password
            }
        }),
    )
    .await;
    lsp.notify("textDocument/didOpen", open_params(&uri, 1, text))
        .await;
    let actions = lsp
        .request(2, "textDocument/codeAction", action_params(&uri))
        .await;
    let scalar_action = actions
        .as_array()
        .expect("actions")
        .iter()
        .find(|action| action["title"] == "Ansible Vault: Encrypt YAML Value")
        .expect("scalar action")
        .clone();
    let resolved = lsp
        .request(3, "codeAction/resolve", scalar_action.clone())
        .await;
    assert_eq!(
        resolved["edit"]["documentChanges"][0]["textDocument"]["version"],
        1
    );
    assert!(
        resolved["edit"]["documentChanges"][0]["edits"][0]["newText"]
            .as_str()
            .expect("replacement")
            .starts_with("!vault |\n        $ANSIBLE_VAULT;1.1;AES256")
    );

    lsp.notify(
        "textDocument/didChange",
        json!({
            "textDocument": { "uri": uri, "version": 2 },
            "contentChanges": [{ "text": "secret: changed\n" }]
        }),
    )
    .await;
    let stale = lsp.request(4, "codeAction/resolve", scalar_action).await;
    assert!(stale.get("edit").is_none());
    lsp.stop().await;
}

fn fake_ansible_vault(root: &TempDir) -> String {
    let path = root.path().join("ansible-vault");
    let mut file = fs::File::create(&path).expect("fake ansible-vault");
    writeln!(
        file,
        r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "ansible-vault fake"
  exit 0
fi
if [ "$1" = "encrypt_string" ]; then
  for argument in "$@"; do
    if [ "$argument" = "--help" ]; then
      echo "--vault-password-file --vault-id --stdin-name"
      exit 0
    fi
  done
  cat >/dev/null
  printf '%s\n' '__zed_vault_value__: !vault |' '          $ANSIBLE_VAULT;1.1;AES256' '          616263'
  exit 0
fi
exit 2"#
    )
    .expect("fake executable contents");
    file.set_permissions(fs::Permissions::from_mode(0o700))
        .expect("fake executable permissions");
    path.to_string_lossy().into_owned()
}
