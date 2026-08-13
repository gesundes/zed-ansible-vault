use crate::config::Settings;
use crate::error::{AppError, AppResult};
use crate::process::{run_output, COMMAND_TIMEOUT};
use crate::prompt::PromptBackend;
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    EncryptFile,
    DecryptFile,
    EncryptValue,
    DecryptValue,
}

impl Operation {
    fn subcommand(self) -> &'static str {
        match self {
            Self::EncryptFile => "encrypt",
            Self::DecryptFile => "decrypt",
            Self::EncryptValue => "encrypt_string",
            Self::DecryptValue => "view",
        }
    }
}

pub enum PasswordProvider {
    File(PathBuf),
    Prompt(PromptBackend),
}

pub struct Environment {
    pub ansible_vault: PathBuf,
    pub work_dir: TempDir,
    pub password: PasswordProvider,
    pub warnings: Vec<String>,
}

pub async fn validate_environment(
    settings: &Settings,
    operation: Operation,
    worktree_root: &Path,
    target_file: Option<&Path>,
) -> AppResult<Environment> {
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return Err(AppError::user(
            "Ansible Vault extension supports macOS and Linux only",
        ));
    }
    let executable = resolve_executable(&settings.executable)?;
    validate_executable(&executable)?;
    let work_dir = tempfile::Builder::new()
        .prefix("zed-ansible-vault-")
        .tempdir()
        .map_err(AppError::filesystem)?;

    if matches!(operation, Operation::EncryptFile | Operation::DecryptFile) {
        validate_file_access(target_file.ok_or_else(|| {
            AppError::user("A saved file:// document is required for this operation")
        })?)?;
    }

    let env = [("ANSIBLE_LOCAL_TEMP", work_dir.path())];
    let version = run_output(
        &executable,
        &["--version".into()],
        &env,
        None,
        COMMAND_TIMEOUT,
    )
    .await?;
    if !version.success {
        return Err(AppError::user(
            "ansible-vault was found but failed to start; check its Python environment and temporary-directory configuration",
        ));
    }
    let help_args = vec![
        OsString::from(operation.subcommand()),
        OsString::from("--help"),
    ];
    let help = run_output(&executable, &help_args, &env, None, COMMAND_TIMEOUT).await?;
    if !help.success {
        return Err(AppError::user(format!(
            "ansible-vault does not provide a working '{}' command",
            operation.subcommand()
        )));
    }
    let mut help_bytes = help.stdout;
    help_bytes.extend_from_slice(&help.stderr);
    let help_text = String::from_utf8_lossy(&help_bytes);
    for required in required_options(operation, settings.vault_id.is_some()) {
        if !help_text.contains(required) {
            return Err(AppError::user(format!(
                "The installed ansible-vault '{}' command does not support required option {required}",
                operation.subcommand()
            )));
        }
    }

    let mut warnings = Vec::new();
    let password = if let Some(path) = settings.resolve_password_file(worktree_root)? {
        let canonical = validate_password_file(&path, &mut warnings)?;
        PasswordProvider::File(canonical)
    } else {
        PasswordProvider::Prompt(PromptBackend::discover(settings.prompt_backend).await?)
    };
    Ok(Environment {
        ansible_vault: executable,
        work_dir,
        password,
        warnings,
    })
}

fn required_options(operation: Operation, has_vault_id: bool) -> Vec<&'static str> {
    let mut options = if has_vault_id {
        vec!["--vault-id"]
    } else {
        vec!["--vault-password-file"]
    };
    if matches!(operation, Operation::EncryptFile | Operation::DecryptFile) {
        options.push("--output");
    }
    if matches!(operation, Operation::EncryptValue) {
        options.push("--stdin-name");
    }
    options
}

fn validate_file_access(path: &Path) -> AppResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::user(format!(
            "Cannot access target file {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(AppError::user("Symlinked Vault files are not supported"));
    }
    if !metadata.is_file() {
        return Err(AppError::user(
            "Only regular files can be encrypted or decrypted",
        ));
    }
    fs::File::open(path)
        .map_err(|error| AppError::user(format!("The target file is not readable: {error}")))?;
    if metadata.permissions().readonly() {
        return Err(AppError::user("The target file is read-only"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o222 == 0 {
            return Err(AppError::user("The target file is read-only"));
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| AppError::user("The target file has no parent directory"))?;
    tempfile::Builder::new()
        .prefix(".zed-ansible-vault-preflight-")
        .tempfile_in(parent)
        .map_err(|error| {
            AppError::user(format!(
                "The target directory {} is not writable: {error}",
                parent.display()
            ))
        })?;
    Ok(())
}

fn resolve_executable(configured: &str) -> AppResult<PathBuf> {
    if configured.trim().is_empty() {
        return Err(AppError::user("ansibleVault.executable must not be empty"));
    }
    let path = PathBuf::from(configured);
    if path.is_absolute() {
        return Ok(path);
    }
    if path.components().count() > 1 {
        return Err(AppError::user(
            "ansibleVault.executable must be an absolute path or a command name from PATH",
        ));
    }
    which::which(configured).map_err(|_| {
        AppError::user(format!(
            "Cannot find '{configured}' in PATH; install ansible-core or configure ansibleVault.executable"
        ))
    })
}

fn validate_executable(path: &Path) -> AppResult<()> {
    let metadata = fs::metadata(path).map_err(|error| {
        AppError::user(format!(
            "Cannot access ansible-vault at {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(AppError::user(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(AppError::user(format!(
                "{} is not executable",
                path.display()
            )));
        }
    }
    Ok(())
}

fn validate_password_file(path: &Path, warnings: &mut Vec<String>) -> AppResult<PathBuf> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        AppError::user(format!(
            "Cannot access password file {}: {error}",
            path.display()
        ))
    })?;
    let metadata = fs::metadata(&canonical).map_err(AppError::filesystem)?;
    if !metadata.is_file() {
        return Err(AppError::user(format!(
            "Password file {} is not a regular file",
            canonical.display()
        )));
    }
    let mut file = fs::File::open(&canonical).map_err(|error| {
        AppError::user(format!(
            "Password file {} is not readable: {error}",
            canonical.display()
        ))
    })?;
    let mut byte = [0_u8; 1];
    if file.read(&mut byte).map_err(AppError::filesystem)? == 0 {
        return Err(AppError::user(format!(
            "Password file {} is empty",
            canonical.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            warnings.push(format!(
                "Password file {} is readable or writable by group/other users",
                canonical.display()
            ));
        }
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::io::Write;

    #[test]
    fn operation_requires_only_relevant_options() {
        assert_eq!(
            required_options(Operation::EncryptValue, true),
            vec!["--vault-id", "--stdin-name"]
        );
        assert_eq!(
            required_options(Operation::DecryptFile, false),
            vec!["--vault-password-file", "--output"]
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn validates_a_fake_ansible_vault_without_prompting() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temporary directory");
        let executable = directory.path().join("ansible-vault");
        let mut script = fs::File::create(&executable).expect("fake executable");
        writeln!(
            script,
            "#!/bin/sh\ncase \"$1\" in\n  --version) echo ansible-vault-test;;\n  encrypt) echo --output --vault-password-file;;\n  *) exit 2;;\nesac"
        )
        .expect("script");
        script
            .set_permissions(fs::Permissions::from_mode(0o700))
            .expect("executable permissions");
        drop(script);
        let password = directory.path().join("password");
        fs::write(&password, "secret\n").expect("password file");
        fs::set_permissions(&password, fs::Permissions::from_mode(0o600))
            .expect("password permissions");
        let target = directory.path().join("vars.yml");
        fs::write(&target, "secret: value\n").expect("target file");
        let settings = Settings {
            executable: executable.to_string_lossy().into_owned(),
            password_file: Some(password.to_string_lossy().into_owned()),
            ..Settings::default()
        };

        let environment = validate_environment(
            &settings,
            Operation::EncryptFile,
            directory.path(),
            Some(&target),
        )
        .await
        .expect("valid environment");
        assert_eq!(environment.ansible_vault, executable);
    }

    #[test]
    fn rejects_missing_and_empty_password_files() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let missing = directory.path().join("missing");
        assert!(validate_password_file(&missing, &mut Vec::new()).is_err());
        let empty = directory.path().join("empty");
        fs::write(&empty, []).expect("empty password file");
        assert!(validate_password_file(&empty, &mut Vec::new()).is_err());
    }
}
