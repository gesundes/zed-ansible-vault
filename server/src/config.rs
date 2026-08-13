use crate::error::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn default_executable() -> String {
    "ansible-vault".to_string()
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Settings {
    #[serde(default = "default_executable")]
    pub executable: String,
    #[serde(default)]
    pub password_file: Option<String>,
    #[serde(default)]
    pub vault_id: Option<String>,
    #[serde(default)]
    pub prompt_backend: PromptBackendSetting,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            executable: default_executable(),
            password_file: None,
            vault_id: None,
            prompt_backend: PromptBackendSetting::Auto,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PromptBackendSetting {
    #[default]
    Auto,
    Osascript,
    Zenity,
    Kdialog,
    Yad,
}

impl Settings {
    pub fn from_lsp_value(value: Option<Value>) -> AppResult<Self> {
        let Some(mut value) = value else {
            return Ok(Self::default());
        };
        if let Some(nested) = value.get_mut("ansibleVault") {
            value = nested.take();
        }
        let settings: Self = serde_json::from_value(value)
            .map_err(|error| AppError::user(format!("Invalid ansibleVault settings: {error}")))?;
        if settings
            .vault_id
            .as_deref()
            .is_some_and(|id| id.trim().is_empty() || id.contains('@'))
        {
            return Err(AppError::user(
                "ansibleVault.vaultId must be a non-empty label without '@'",
            ));
        }
        Ok(settings)
    }

    pub fn resolve_password_file(&self, worktree_root: &Path) -> AppResult<Option<PathBuf>> {
        let Some(configured) = self.password_file.as_deref() else {
            return Ok(None);
        };
        if configured.trim().is_empty() {
            return Err(AppError::user(
                "ansibleVault.passwordFile must not be empty",
            ));
        }
        let expanded = if configured == "~" {
            dirs::home_dir().ok_or_else(|| AppError::user("Cannot resolve the home directory"))?
        } else if let Some(rest) = configured.strip_prefix("~/") {
            dirs::home_dir()
                .ok_or_else(|| AppError::user("Cannot resolve the home directory"))?
                .join(rest)
        } else {
            PathBuf::from(configured)
        };
        Ok(Some(if expanded.is_absolute() {
            expanded
        } else {
            worktree_root.join(expanded)
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_zed_settings() {
        let settings = Settings::from_lsp_value(Some(serde_json::json!({
            "ansibleVault": {
                "executable": "/opt/bin/ansible-vault",
                "passwordFile": ".vault-pass",
                "vaultId": "dev",
                "promptBackend": "zenity"
            }
        })))
        .expect("valid settings");
        assert_eq!(settings.executable, "/opt/bin/ansible-vault");
        assert_eq!(settings.password_file.as_deref(), Some(".vault-pass"));
        assert_eq!(settings.vault_id.as_deref(), Some("dev"));
        assert_eq!(settings.prompt_backend, PromptBackendSetting::Zenity);
    }

    #[test]
    fn resolves_relative_password_file_from_worktree() {
        let settings = Settings {
            password_file: Some("secrets/vault-pass".into()),
            ..Settings::default()
        };
        assert_eq!(
            settings
                .resolve_password_file(Path::new("/workspace"))
                .expect("path")
                .as_deref(),
            Some(Path::new("/workspace/secrets/vault-pass"))
        );
    }

    #[test]
    fn rejects_secret_values_and_invalid_vault_ids_in_settings_shape() {
        assert!(Settings::from_lsp_value(Some(serde_json::json!({
            "ansibleVault": { "password": "must-not-be-supported" }
        })))
        .is_err());
        assert!(Settings::from_lsp_value(Some(serde_json::json!({
            "ansibleVault": { "vaultId": "dev@password" }
        })))
        .is_err());
    }
}
