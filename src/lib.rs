use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use zed_extension_api as zed;

const SERVER_NAME: &str = "ansible-vault-lsp";
const RELEASE_REPOSITORY: &str = "gesundes/zed-ansible-vault";
const EXTENSION_VERSION: &str = env!("CARGO_PKG_VERSION");

struct AnsibleVaultExtension {
    cached_server_path: Option<String>,
}

impl AnsibleVaultExtension {
    fn release_tag() -> String {
        format!("v{EXTENSION_VERSION}")
    }

    fn release_version_matches(reported: &str) -> bool {
        reported == Self::release_tag() || reported == EXTENSION_VERSION
    }

    fn asset_name_for(os: zed::Os, architecture: zed::Architecture) -> zed::Result<String> {
        let os = match os {
            zed::Os::Mac => "darwin",
            zed::Os::Linux => "linux",
            zed::Os::Windows => {
                return Err(format!(
                    "Ansible Vault extension {EXTENSION_VERSION} supports macOS and Linux only"
                ));
            }
        };
        let architecture = match architecture {
            zed::Architecture::Aarch64 => "aarch64",
            zed::Architecture::X86 => {
                return Err("32-bit platforms are not supported by Ansible Vault extension".into());
            }
            zed::Architecture::X8664 => "x86_64",
        };
        Ok(format!("{SERVER_NAME}-{os}-{architecture}"))
    }

    fn platform_asset_name() -> zed::Result<String> {
        let (os, architecture) = zed::current_platform();
        Self::asset_name_for(os, architecture)
    }

    fn expected_checksum(checksum_path: &Path) -> zed::Result<String> {
        let expected = fs::read_to_string(checksum_path)
            .map_err(|error| format!("failed to read server checksum: {error}"))?
            .split_whitespace()
            .next()
            .ok_or_else(|| "server checksum file is empty".to_string())?
            .to_ascii_lowercase();
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("server checksum is not a valid SHA-256 digest".into());
        }
        Ok(expected)
    }

    fn verify_checksum(binary_path: &Path, checksum_path: &Path) -> zed::Result<()> {
        let expected = Self::expected_checksum(checksum_path)?;
        let bytes = fs::read(binary_path)
            .map_err(|error| format!("failed to read downloaded language server: {error}"))?;
        let actual = format!("{:x}", Sha256::digest(bytes));
        if actual != expected {
            return Err(format!(
                "language server checksum mismatch: expected {expected}, got {actual}"
            ));
        }
        Ok(())
    }

    fn installed_paths(install_dir: &Path) -> (PathBuf, PathBuf) {
        (
            install_dir.join(SERVER_NAME),
            install_dir.join(format!("{SERVER_NAME}.sha256")),
        )
    }

    fn staging_path(install_dir: &Path) -> PathBuf {
        PathBuf::from(format!("{}.staging", install_dir.to_string_lossy()))
    }

    fn reset_staging_directory(staging_dir: &Path) -> zed::Result<()> {
        if staging_dir.exists() {
            fs::remove_dir_all(staging_dir)
                .map_err(|error| format!("failed to remove stale server download: {error}"))?;
        }
        fs::create_dir_all(staging_dir)
            .map_err(|error| format!("failed to create server staging directory: {error}"))
    }

    fn verified_installed_binary(install_dir: &Path) -> Option<PathBuf> {
        let (binary, checksum) = Self::installed_paths(install_dir);
        (binary.is_file()
            && checksum.is_file()
            && Self::verify_checksum(&binary, &checksum).is_ok())
        .then_some(binary)
    }

    fn download_and_install(
        language_server_id: &zed::LanguageServerId,
        binary_url: &str,
        checksum_url: &str,
        install_dir: &Path,
    ) -> zed::Result<PathBuf> {
        let staging_dir = Self::staging_path(install_dir);
        Self::reset_staging_directory(&staging_dir)?;
        let (staged_binary, staged_checksum) = Self::installed_paths(&staging_dir);

        zed::set_language_server_installation_status(
            language_server_id,
            &zed::LanguageServerInstallationStatus::Downloading,
        );
        let result = (|| {
            zed::download_file(
                binary_url,
                staged_binary.to_string_lossy().as_ref(),
                zed::DownloadedFileType::Uncompressed,
            )?;
            zed::download_file(
                checksum_url,
                staged_checksum.to_string_lossy().as_ref(),
                zed::DownloadedFileType::Uncompressed,
            )?;
            Self::verify_checksum(&staged_binary, &staged_checksum)?;
            zed::make_file_executable(staged_binary.to_string_lossy().as_ref())?;

            if install_dir.exists() {
                fs::remove_dir_all(install_dir).map_err(|error| {
                    format!("failed to replace invalid server installation: {error}")
                })?;
            }
            fs::rename(&staging_dir, install_dir)
                .map_err(|error| format!("failed to activate language server: {error}"))?;
            Ok(Self::installed_paths(install_dir).0)
        })();

        if result.is_err() {
            let _ = fs::remove_dir_all(&staging_dir);
        }
        result
    }

    fn install_server(
        &mut self,
        language_server_id: &zed::LanguageServerId,
    ) -> zed::Result<String> {
        if let Some(path) = self.cached_server_path.as_ref() {
            let binary = Path::new(path);
            if binary.parent().and_then(Self::verified_installed_binary) == Some(binary.into()) {
                return Ok(path.clone());
            }
        }
        self.cached_server_path = None;

        let asset_name = Self::platform_asset_name()?;
        let tag = Self::release_tag();
        let release = zed::github_release_by_tag_name(RELEASE_REPOSITORY, &tag)?;
        if !Self::release_version_matches(&release.version) {
            return Err(format!(
                "GitHub returned release {} while {tag} was requested",
                release.version
            ));
        }
        let binary_asset = release
            .assets
            .iter()
            .find(|asset| asset.name == asset_name)
            .ok_or_else(|| format!("release {tag} has no asset {asset_name}"))?;
        let checksum_name = format!("{asset_name}.sha256");
        let checksum_asset = release
            .assets
            .iter()
            .find(|asset| asset.name == checksum_name)
            .ok_or_else(|| format!("release {tag} has no asset {checksum_name}"))?;

        let install_dir = PathBuf::from(format!("{SERVER_NAME}-{EXTENSION_VERSION}"));
        let binary_path = if let Some(binary) = Self::verified_installed_binary(&install_dir) {
            zed::make_file_executable(binary.to_string_lossy().as_ref())?;
            binary
        } else {
            Self::download_and_install(
                language_server_id,
                &binary_asset.download_url,
                &checksum_asset.download_url,
                &install_dir,
            )?
        };

        let absolute_binary_path = std::env::current_dir()
            .map_err(|error| format!("failed to resolve extension directory: {error}"))?
            .join(binary_path)
            .to_string_lossy()
            .into_owned();
        self.cached_server_path = Some(absolute_binary_path.clone());
        Ok(absolute_binary_path)
    }
}

impl zed::Extension for AnsibleVaultExtension {
    fn new() -> Self {
        Self {
            cached_server_path: None,
        }
    }

    fn language_server_command(
        &mut self,
        language_server_id: &zed::LanguageServerId,
        worktree: &zed::Worktree,
    ) -> zed::Result<zed::Command> {
        let lsp_settings = zed::settings::LspSettings::for_worktree(SERVER_NAME, worktree)?;
        if let Some(binary) = lsp_settings.binary {
            if let Some(path) = binary.path {
                return Ok(zed::Command {
                    command: path,
                    args: binary.arguments.unwrap_or_default(),
                    env: binary.env.unwrap_or_default().into_iter().collect(),
                });
            }
        }

        Ok(zed::Command {
            command: self.install_server(language_server_id)?,
            args: Vec::new(),
            env: Vec::new(),
        })
    }

    fn language_server_initialization_options(
        &mut self,
        _language_server_id: &zed::LanguageServerId,
        worktree: &zed::Worktree,
    ) -> zed::Result<Option<serde_json::Value>> {
        Ok(zed::settings::LspSettings::for_worktree(SERVER_NAME, worktree)?.settings)
    }

    fn language_server_workspace_configuration(
        &mut self,
        _language_server_id: &zed::LanguageServerId,
        worktree: &zed::Worktree,
    ) -> zed::Result<Option<serde_json::Value>> {
        Ok(zed::settings::LspSettings::for_worktree(SERVER_NAME, worktree)?.settings)
    }
}

zed::register_extension!(AnsibleVaultExtension);

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn release_is_pinned_to_extension_version() {
        assert_eq!(AnsibleVaultExtension::release_tag(), "v0.2.0");
        assert!(AnsibleVaultExtension::release_version_matches("v0.2.0"));
        assert!(AnsibleVaultExtension::release_version_matches("0.2.0"));
        assert!(!AnsibleVaultExtension::release_version_matches("v0.2.1"));
    }

    #[test]
    fn platform_assets_follow_the_release_contract() {
        assert_eq!(
            AnsibleVaultExtension::asset_name_for(zed::Os::Mac, zed::Architecture::Aarch64)
                .expect("macOS asset"),
            "ansible-vault-lsp-darwin-aarch64"
        );
        assert_eq!(
            AnsibleVaultExtension::asset_name_for(zed::Os::Linux, zed::Architecture::X8664)
                .expect("Linux asset"),
            "ansible-vault-lsp-linux-x86_64"
        );
        assert!(
            AnsibleVaultExtension::asset_name_for(zed::Os::Windows, zed::Architecture::X8664)
                .is_err()
        );
    }

    #[test]
    fn cached_install_requires_matching_checksum() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (binary, checksum) = AnsibleVaultExtension::installed_paths(directory.path());
        fs::write(&binary, b"server").expect("binary");
        let digest = format!("{:x}", Sha256::digest(b"server"));
        let mut checksum_file = fs::File::create(&checksum).expect("checksum");
        writeln!(checksum_file, "{digest}  release-asset").expect("write checksum");

        assert_eq!(
            AnsibleVaultExtension::verified_installed_binary(directory.path()),
            Some(binary.clone())
        );
        fs::write(binary, b"tampered").expect("tamper binary");
        assert!(AnsibleVaultExtension::verified_installed_binary(directory.path()).is_none());
    }

    #[test]
    fn staging_directory_does_not_drop_the_patch_version() {
        assert_eq!(
            AnsibleVaultExtension::staging_path(Path::new("ansible-vault-lsp-0.2.0")),
            Path::new("ansible-vault-lsp-0.2.0.staging")
        );
    }

    #[test]
    fn malformed_checksum_is_rejected() {
        let directory = tempfile::tempdir().expect("temp dir");
        let binary = directory.path().join("server");
        let checksum = directory.path().join("server.sha256");
        fs::write(&binary, b"server").expect("binary");
        fs::write(&checksum, b"not-a-digest\n").expect("checksum");
        assert!(AnsibleVaultExtension::verify_checksum(&binary, &checksum).is_err());
    }

    #[test]
    fn missing_checksum_never_counts_as_an_installed_server() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (binary, _) = AnsibleVaultExtension::installed_paths(directory.path());
        fs::write(binary, b"server").expect("binary");
        assert!(AnsibleVaultExtension::verified_installed_binary(directory.path()).is_none());
    }

    #[test]
    fn interrupted_staging_download_is_removed_before_retry() {
        let directory = tempfile::tempdir().expect("temp dir");
        let install = directory.path().join("ansible-vault-lsp-0.2.0");
        let staging = AnsibleVaultExtension::staging_path(&install);
        fs::create_dir_all(&staging).expect("staging directory");
        fs::write(staging.join(SERVER_NAME), b"partial").expect("partial download");

        AnsibleVaultExtension::reset_staging_directory(&staging).expect("reset staging");
        assert!(staging.is_dir());
        assert!(!staging.join(SERVER_NAME).exists());
    }
}
