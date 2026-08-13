mod config;
mod document;
mod error;
mod preflight;
mod process;
mod prompt;
mod validation;
mod vault;
mod yaml;

use crate::config::Settings;
use crate::document::{byte_range_to_lsp, Document};
use crate::error::{AppError, AppResult};
use crate::preflight::{validate_environment, Operation};
use crate::validation::{
    is_vault_file_candidate, range_touches, validate_vault_document, DIAGNOSTIC_SOURCE,
};
use crate::vault::{
    decrypt_value, encrypt_value, hash_file, is_vault_file, obtain_password_file, prepare_file,
};
use crate::yaml::{
    classify_value, find_scalar, find_vault, format_encrypted_value, format_plaintext_value,
    ValueContext,
};
use dashmap::{DashMap, DashSet};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp::jsonrpc::Result as LspResult;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer};

const SERVER_NAME: &str = "ansible-vault-lsp";

pub struct Backend {
    client: Client,
    documents: Arc<DashMap<Url, Document>>,
    active_operations: Arc<DashSet<Url>>,
    settings: Arc<RwLock<Settings>>,
    settings_error: Arc<RwLock<Option<String>>>,
    workspace_roots: Arc<RwLock<Vec<PathBuf>>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum ActionOperation {
    EncryptFile,
    DecryptFile,
    EncryptValue,
    DecryptValue,
}

impl From<ActionOperation> for Operation {
    fn from(value: ActionOperation) -> Self {
        match value {
            ActionOperation::EncryptFile => Self::EncryptFile,
            ActionOperation::DecryptFile => Self::DecryptFile,
            ActionOperation::EncryptValue => Self::EncryptValue,
            ActionOperation::DecryptValue => Self::DecryptValue,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ActionData {
    operation: ActionOperation,
    uri: Url,
    version: i32,
    range: Range,
}

enum ActionTarget {
    File(PathBuf),
    Scalar(crate::yaml::ScalarTarget),
    Vault(crate::yaml::VaultTarget),
}

struct ActiveOperationGuard {
    operations: Arc<DashSet<Url>>,
    uri: Url,
}

impl Drop for ActiveOperationGuard {
    fn drop(&mut self) {
        self.operations.remove(&self.uri);
    }
}

impl Backend {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            documents: Arc::new(DashMap::new()),
            active_operations: Arc::new(DashSet::new()),
            settings: Arc::new(RwLock::new(Settings::default())),
            settings_error: Arc::new(RwLock::new(None)),
            workspace_roots: Arc::new(RwLock::new(Vec::new())),
        }
    }

    fn unresolved_action(
        title: &str,
        operation: ActionOperation,
        params: &CodeActionParams,
        version: i32,
    ) -> CodeActionOrCommand {
        CodeActionOrCommand::CodeAction(CodeAction {
            title: title.to_string(),
            kind: Some(CodeActionKind::REFACTOR_REWRITE),
            data: serde_json::to_value(ActionData {
                operation,
                uri: params.text_document.uri.clone(),
                version,
                range: params.range,
            })
            .ok(),
            ..CodeAction::default()
        })
    }

    fn validation_quick_fixes(
        document: &Document,
        params: &CodeActionParams,
    ) -> Vec<CodeActionOrCommand> {
        let mut groups: Vec<(TextEdit, Vec<Diagnostic>, bool)> = Vec::new();
        for issue in validate_vault_document(&document.text) {
            let Some(fix) = issue.fix else {
                continue;
            };
            let requested_by_context = params.context.diagnostics.iter().any(|diagnostic| {
                diagnostic.source.as_deref() == Some(DIAGNOSTIC_SOURCE)
                    && diagnostic.code == issue.diagnostic.code
                    && diagnostic.range == issue.diagnostic.range
            });
            let applicable = requested_by_context
                || range_touches(params.range, issue.diagnostic.range)
                || range_touches(params.range, fix.range);
            if let Some((_, diagnostics, group_applicable)) =
                groups.iter_mut().find(|(existing, _, _)| existing == &fix)
            {
                diagnostics.push(issue.diagnostic);
                *group_applicable |= applicable;
            } else {
                groups.push((fix, vec![issue.diagnostic], applicable));
            }
        }

        groups
            .into_iter()
            .filter(|(_, _, applicable)| *applicable)
            .map(|(fix, diagnostics, _)| {
                CodeActionOrCommand::CodeAction(CodeAction {
                    title: "Ansible Vault: Fix Vault Header".to_string(),
                    kind: Some(CodeActionKind::QUICKFIX),
                    diagnostics: Some(diagnostics),
                    is_preferred: Some(true),
                    edit: Some(WorkspaceEdit {
                        changes: None,
                        document_changes: Some(DocumentChanges::Edits(vec![TextDocumentEdit {
                            text_document: OptionalVersionedTextDocumentIdentifier {
                                uri: params.text_document.uri.clone(),
                                version: Some(document.version),
                            },
                            edits: vec![OneOf::Left(fix)],
                        }])),
                        change_annotations: None,
                    }),
                    ..CodeAction::default()
                })
            })
            .collect()
    }

    async fn publish_validation_diagnostics(&self, uri: Url, document: &Document) {
        let diagnostics = validate_vault_document(&document.text)
            .into_iter()
            .map(|issue| issue.diagnostic)
            .collect();
        self.client
            .publish_diagnostics(uri, diagnostics, Some(document.version))
            .await;
    }

    async fn worktree_for(&self, path: &Path) -> PathBuf {
        self.workspace_roots
            .read()
            .await
            .iter()
            .filter(|root| path.starts_with(root))
            .max_by_key(|root| root.components().count())
            .cloned()
            .or_else(|| path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from("."))
    }

    async fn perform_action(&self, action: &mut CodeAction, data: ActionData) -> AppResult<()> {
        if !self.active_operations.insert(data.uri.clone()) {
            return Err(AppError::user(
                "Another Ansible Vault operation is already running for this document",
            ));
        }
        let _guard = ActiveOperationGuard {
            operations: Arc::clone(&self.active_operations),
            uri: data.uri.clone(),
        };
        self.perform_action_inner(action, data).await
    }

    async fn perform_action_inner(
        &self,
        action: &mut CodeAction,
        data: ActionData,
    ) -> AppResult<()> {
        let initial = self
            .documents
            .get(&data.uri)
            .map(|document| document.clone())
            .ok_or_else(|| AppError::user("The document is no longer open"))?;
        if initial.version != data.version {
            return Err(AppError::StaleDocument);
        }
        if let Some(error) = self.settings_error.read().await.clone() {
            return Err(AppError::user(error));
        }
        let settings = self.settings.read().await.clone();
        let operation = Operation::from(data.operation);
        let target = match data.operation {
            ActionOperation::EncryptFile => {
                if is_vault_file(&initial.text) || initial.text.starts_with("$ANSIBLE_VAULT") {
                    return Err(AppError::user(
                        "The file already has an Ansible Vault header",
                    ));
                }
                ActionTarget::File(
                    data.uri.to_file_path().map_err(|_| {
                        AppError::user("This action requires a saved file:// document")
                    })?,
                )
            }
            ActionOperation::DecryptFile => {
                if !is_vault_file(&initial.text) {
                    return Err(AppError::user("The file has no valid Ansible Vault header"));
                }
                ActionTarget::File(
                    data.uri.to_file_path().map_err(|_| {
                        AppError::user("This action requires a saved file:// document")
                    })?,
                )
            }
            ActionOperation::EncryptValue => {
                ActionTarget::Scalar(find_scalar(&initial.text, data.range)?)
            }
            ActionOperation::DecryptValue => {
                let target = find_vault(&initial.text, data.range)?;
                if !is_vault_file(&target.vault_text) {
                    return Err(AppError::user(
                            "The !vault value has an invalid header; expected $ANSIBLE_VAULT;1.1;AES256 or a valid Vault 1.2 header",
                        ));
                }
                ActionTarget::Vault(target)
            }
        };
        let document_path = data.uri.to_file_path().ok();
        let file_path = match &target {
            ActionTarget::File(path) => Some(path.as_path()),
            _ => document_path.as_deref(),
        };
        let root = if let Some(path) = file_path {
            self.worktree_for(path).await
        } else {
            self.workspace_roots
                .read()
                .await
                .first()
                .cloned()
                .unwrap_or_else(|| PathBuf::from("."))
        };

        // Every action intentionally performs a fresh preflight before asking for a password.
        let environment = validate_environment(
            &settings,
            operation,
            &root,
            match &target {
                ActionTarget::File(path) => Some(path.as_path()),
                _ => None,
            },
        )
        .await?;
        for warning in &environment.warnings {
            self.client
                .show_message(MessageType::WARNING, warning)
                .await;
        }
        let password = obtain_password_file(&environment).await?;

        match data.operation {
            ActionOperation::EncryptFile | ActionOperation::DecryptFile => {
                let ActionTarget::File(path) = target else {
                    return Err(AppError::Internal(anyhow::anyhow!("invalid action target")));
                };
                let prepared = prepare_file(
                    &environment,
                    &settings,
                    &password,
                    operation,
                    &path,
                    &initial.text,
                )
                .await?;
                let current = self
                    .documents
                    .get(&data.uri)
                    .map(|document| document.clone())
                    .ok_or(AppError::StaleDocument)?;
                if current.version != initial.version || current.text != initial.text {
                    return Err(AppError::StaleDocument);
                }
                if hash_file(&path)? != prepared.original_hash {
                    return Err(AppError::user(
                        "The file changed on disk while the operation was running; retry the action",
                    ));
                }
                let result_hash = prepared.result_hash;
                prepared.commit(&path)?;
                tokio::time::sleep(std::time::Duration::from_millis(750)).await;
                let watcher_refreshed = self.documents.get(&data.uri).is_some_and(|document| {
                    let hash: [u8; 32] = sha2::Sha256::digest(document.text.as_bytes()).into();
                    hash == result_hash
                });
                if !watcher_refreshed {
                    self.client
                        .show_message(
                            MessageType::WARNING,
                            "The file was updated on disk, but the Zed buffer has not refreshed yet; reload the file before editing",
                        )
                        .await;
                } else {
                    self.client
                        .show_message(MessageType::INFO, "Ansible Vault file operation completed")
                        .await;
                }
            }
            ActionOperation::EncryptValue => {
                let ActionTarget::Scalar(target) = target else {
                    return Err(AppError::Internal(anyhow::anyhow!("invalid action target")));
                };
                let encrypted =
                    encrypt_value(&environment, &settings, &password, &target.plaintext).await?;
                let replacement = format_encrypted_value(&encrypted, &target.continuation_indent)?;
                self.attach_versioned_edit(
                    action,
                    &data.uri,
                    &initial,
                    target.start,
                    target.end,
                    replacement,
                )?;
            }
            ActionOperation::DecryptValue => {
                let ActionTarget::Vault(target) = target else {
                    return Err(AppError::Internal(anyhow::anyhow!("invalid action target")));
                };
                let plaintext =
                    decrypt_value(&environment, &settings, &password, &target.vault_text).await?;
                let replacement = format_plaintext_value(&plaintext, &target.continuation_indent);
                self.attach_versioned_edit(
                    action,
                    &data.uri,
                    &initial,
                    target.start,
                    target.end,
                    replacement,
                )?;
            }
        }
        Ok(())
    }

    fn attach_versioned_edit(
        &self,
        action: &mut CodeAction,
        uri: &Url,
        initial: &Document,
        start: usize,
        end: usize,
        new_text: String,
    ) -> AppResult<()> {
        let current = self
            .documents
            .get(uri)
            .map(|document| document.clone())
            .ok_or(AppError::StaleDocument)?;
        if current.version != initial.version || current.text != initial.text {
            return Err(AppError::StaleDocument);
        }
        action.edit = Some(WorkspaceEdit {
            changes: None,
            document_changes: Some(DocumentChanges::Edits(vec![TextDocumentEdit {
                text_document: OptionalVersionedTextDocumentIdentifier {
                    uri: uri.clone(),
                    version: Some(initial.version),
                },
                edits: vec![OneOf::Left(TextEdit {
                    range: byte_range_to_lsp(&initial.text, start, end),
                    new_text,
                })],
            }])),
            change_annotations: None,
        });
        Ok(())
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, params: InitializeParams) -> LspResult<InitializeResult> {
        match Settings::from_lsp_value(params.initialization_options) {
            Ok(settings) => *self.settings.write().await = settings,
            Err(error) => *self.settings_error.write().await = Some(error.to_string()),
        }
        let mut roots = Vec::new();
        if let Some(folders) = params.workspace_folders {
            roots.extend(
                folders
                    .into_iter()
                    .filter_map(|folder| folder.uri.to_file_path().ok()),
            );
        }
        #[allow(deprecated)]
        if let Some(root_uri) = params.root_uri {
            if let Ok(path) = root_uri.to_file_path() {
                if !roots.contains(&path) {
                    roots.push(path);
                }
            }
        }
        *self.workspace_roots.write().await = roots;
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                code_action_provider: Some(CodeActionProviderCapability::Options(
                    CodeActionOptions {
                        code_action_kinds: Some(vec![
                            CodeActionKind::QUICKFIX,
                            CodeActionKind::REFACTOR_REWRITE,
                        ]),
                        resolve_provider: Some(true),
                        work_done_progress_options: WorkDoneProgressOptions::default(),
                    },
                )),
                workspace: Some(WorkspaceServerCapabilities {
                    workspace_folders: Some(WorkspaceFoldersServerCapabilities {
                        supported: Some(true),
                        change_notifications: Some(OneOf::Left(true)),
                    }),
                    file_operations: None,
                }),
                ..ServerCapabilities::default()
            },
            server_info: Some(ServerInfo {
                name: SERVER_NAME.to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "Ansible Vault LSP initialized")
            .await;
    }

    async fn shutdown(&self) -> LspResult<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let document = Document {
            text: params.text_document.text,
            version: params.text_document.version,
        };
        self.documents.insert(uri.clone(), document.clone());
        self.publish_validation_diagnostics(uri, &document).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        if let Some(change) = params.content_changes.into_iter().last() {
            let uri = params.text_document.uri;
            let document = Document {
                text: change.text,
                version: params.text_document.version,
            };
            self.documents.insert(uri.clone(), document.clone());
            self.publish_validation_diagnostics(uri, &document).await;
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        self.documents.remove(&params.text_document.uri);
        self.client
            .publish_diagnostics(params.text_document.uri, Vec::new(), None)
            .await;
    }

    async fn did_change_configuration(&self, params: DidChangeConfigurationParams) {
        match Settings::from_lsp_value(Some(params.settings)) {
            Ok(settings) => {
                *self.settings.write().await = settings;
                *self.settings_error.write().await = None;
            }
            Err(error) => {
                *self.settings_error.write().await = Some(error.to_string());
                self.client
                    .show_message(MessageType::ERROR, error.to_string())
                    .await;
            }
        }
    }

    async fn did_change_workspace_folders(&self, params: DidChangeWorkspaceFoldersParams) {
        let mut roots = self.workspace_roots.write().await;
        for removed in params.event.removed {
            if let Ok(path) = removed.uri.to_file_path() {
                roots.retain(|root| root != &path);
            }
        }
        for added in params.event.added {
            if let Ok(path) = added.uri.to_file_path() {
                if !roots.contains(&path) {
                    roots.push(path);
                }
            }
        }
    }

    async fn code_action(&self, params: CodeActionParams) -> LspResult<Option<CodeActionResponse>> {
        let Some(document) = self.documents.get(&params.text_document.uri) else {
            return Ok(None);
        };
        let document = document.clone();
        let mut actions = Self::validation_quick_fixes(&document, &params);
        if is_vault_file_candidate(&document.text) {
            if params.text_document.uri.scheme() == "file" {
                actions.push(Self::unresolved_action(
                    "Ansible Vault: Decrypt File",
                    ActionOperation::DecryptFile,
                    &params,
                    document.version,
                ));
            }
            return Ok((!actions.is_empty()).then_some(actions));
        }
        if params.text_document.uri.scheme() == "file" {
            actions.push(Self::unresolved_action(
                "Ansible Vault: Encrypt File",
                ActionOperation::EncryptFile,
                &params,
                document.version,
            ));
        }
        match classify_value(&document.text, params.range) {
            Some(ValueContext::Vault) => actions.push(Self::unresolved_action(
                "Ansible Vault: Decrypt !vault Value",
                ActionOperation::DecryptValue,
                &params,
                document.version,
            )),
            Some(ValueContext::Plaintext) => actions.push(Self::unresolved_action(
                "Ansible Vault: Encrypt YAML Value",
                ActionOperation::EncryptValue,
                &params,
                document.version,
            )),
            None => {}
        }
        Ok((!actions.is_empty()).then_some(actions))
    }

    async fn code_action_resolve(&self, mut action: CodeAction) -> LspResult<CodeAction> {
        let Some(value) = action.data.clone() else {
            return Ok(action);
        };
        let data = match serde_json::from_value::<ActionData>(value) {
            Ok(data) => data,
            Err(_) => return Ok(action),
        };
        match self.perform_action(&mut action, data).await {
            Ok(()) | Err(AppError::Cancelled) => {}
            Err(error) => {
                self.client
                    .show_message(MessageType::ERROR, error.to_string())
                    .await;
            }
        }
        Ok(action)
    }
}
