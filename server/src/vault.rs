use crate::config::Settings;
use crate::error::{AppError, AppResult};
use crate::preflight::{Environment, Operation, PasswordProvider};
use crate::process::{run_output, ProcessOutput, OPERATION_TIMEOUT};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::{self, File, Metadata, Permissions};
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use zeroize::{Zeroize, Zeroizing};

pub const VAULT_HEADER: &str = "$ANSIBLE_VAULT;";

pub struct PasswordFile {
    path: PathBuf,
    _temporary: Option<NamedTempFile>,
}

impl PasswordFile {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub struct PreparedFile {
    output_path: PathBuf,
    pub original_hash: [u8; 32],
    pub result_hash: [u8; 32],
    permissions: Permissions,
    committed: bool,
}

struct OutputGuard {
    path: PathBuf,
    disarmed: bool,
}

impl OutputGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            disarmed: false,
        }
    }

    fn into_path(mut self) -> PathBuf {
        self.disarmed = true;
        self.path.clone()
    }
}

impl Drop for OutputGuard {
    fn drop(&mut self) {
        if !self.disarmed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl PreparedFile {
    pub fn commit(mut self, target: &Path) -> AppResult<()> {
        validate_target_file(target)?;
        if hash_file(target)? != self.original_hash {
            return Err(AppError::user(
                "The file changed on disk while the operation was running; retry the action",
            ));
        }
        let output = File::options()
            .read(true)
            .write(true)
            .open(&self.output_path)
            .map_err(AppError::filesystem)?;
        output
            .set_permissions(self.permissions.clone())
            .map_err(AppError::filesystem)?;
        output.sync_all().map_err(AppError::filesystem)?;
        fs::rename(&self.output_path, target).map_err(AppError::filesystem)?;
        self.committed = true;
        if let Some(parent) = target.parent() {
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(AppError::filesystem)?;
        }
        Ok(())
    }
}

impl Drop for PreparedFile {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.output_path);
        }
    }
}

pub async fn obtain_password_file(environment: &Environment) -> AppResult<PasswordFile> {
    match &environment.password {
        PasswordProvider::File(path) => Ok(PasswordFile {
            path: path.clone(),
            _temporary: None,
        }),
        PasswordProvider::Prompt(backend) => {
            let password = backend
                .ask("Ansible Vault", "Enter the Ansible Vault password")
                .await?;
            let mut file = tempfile::Builder::new()
                .prefix("password-")
                .tempfile_in(environment.work_dir.path())
                .map_err(AppError::filesystem)?;
            set_private_permissions(file.as_file())?;
            let mut bytes = Zeroizing::new(password.as_bytes().to_vec());
            file.write_all(&bytes).map_err(AppError::filesystem)?;
            file.write_all(b"\n").map_err(AppError::filesystem)?;
            file.as_file_mut()
                .sync_all()
                .map_err(AppError::filesystem)?;
            bytes.zeroize();
            Ok(PasswordFile {
                path: file.path().to_path_buf(),
                _temporary: Some(file),
            })
        }
    }
}

pub async fn encrypt_value(
    environment: &Environment,
    settings: &Settings,
    password: &PasswordFile,
    plaintext: &str,
) -> AppResult<String> {
    let mut args = vec![OsString::from("encrypt_string")];
    append_password_args(&mut args, settings, password.path());
    args.extend([
        OsString::from("--stdin-name"),
        OsString::from("__zed_vault_value__"),
    ]);
    let output = run_ansible(environment, &args, Some(plaintext.as_bytes())).await?;
    parse_encrypt_string(&output.stdout)
}

pub async fn decrypt_value(
    environment: &Environment,
    settings: &Settings,
    password: &PasswordFile,
    vault_text: &str,
) -> AppResult<String> {
    let mut encrypted = private_tempfile(environment.work_dir.path(), "value-")?;
    encrypted
        .write_all(vault_text.as_bytes())
        .map_err(AppError::filesystem)?;
    encrypted
        .as_file_mut()
        .sync_all()
        .map_err(AppError::filesystem)?;
    let mut args = vec![OsString::from("view")];
    append_password_args(&mut args, settings, password.path());
    args.push(encrypted.path().as_os_str().to_owned());
    let output = run_ansible(environment, &args, None).await?;
    let mut plaintext = String::from_utf8(output.stdout)
        .map_err(|_| AppError::user("The decrypted Vault value is not valid UTF-8"))?;
    // `ansible-vault view` writes one display newline in addition to the decrypted bytes.
    // Removing exactly that newline preserves a newline that belonged to the secret itself.
    if plaintext.ends_with('\n') {
        plaintext.pop();
        if plaintext.ends_with('\r') {
            plaintext.pop();
        }
    }
    Ok(plaintext)
}

pub async fn prepare_file(
    environment: &Environment,
    settings: &Settings,
    password: &PasswordFile,
    operation: Operation,
    target: &Path,
    document_text: &str,
) -> AppResult<PreparedFile> {
    let metadata = validate_target_file(target)?;
    let disk_bytes = fs::read(target).map_err(AppError::filesystem)?;
    let disk_text = std::str::from_utf8(&disk_bytes)
        .map_err(|_| AppError::user("Non-UTF-8 files are not supported"))?;
    if disk_text != document_text {
        return Err(AppError::user(
            "The editor buffer has unsaved changes; save the file and retry",
        ));
    }
    let original_hash = hash_bytes(&disk_bytes);
    let mut input = private_tempfile(environment.work_dir.path(), "input-")?;
    input.write_all(&disk_bytes).map_err(AppError::filesystem)?;
    input
        .as_file_mut()
        .sync_all()
        .map_err(AppError::filesystem)?;

    let parent = target
        .parent()
        .ok_or_else(|| AppError::user("The target file has no parent directory"))?;
    let reserved_output = private_tempfile(parent, ".zed-ansible-vault-")?;
    let output_path = reserved_output.path().to_path_buf();
    reserved_output.close().map_err(AppError::filesystem)?;
    let output_guard = OutputGuard::new(output_path);
    let mut args = vec![OsString::from(match operation {
        Operation::EncryptFile => "encrypt",
        Operation::DecryptFile => "decrypt",
        _ => return Err(AppError::user("Invalid file operation")),
    })];
    append_password_args(&mut args, settings, password.path());
    args.extend([
        OsString::from("--output"),
        output_guard.path.as_os_str().to_owned(),
        input.path().as_os_str().to_owned(),
    ]);
    run_ansible(environment, &args, None).await?;
    let result = fs::read(&output_guard.path).map_err(AppError::filesystem)?;
    std::str::from_utf8(&result)
        .map_err(|_| AppError::user("The Vault result is not valid UTF-8"))?;
    Ok(PreparedFile {
        output_path: output_guard.into_path(),
        original_hash,
        result_hash: hash_bytes(&result),
        permissions: metadata.permissions(),
        committed: false,
    })
}

pub fn hash_file(path: &Path) -> AppResult<[u8; 32]> {
    fs::read(path)
        .map(|bytes| hash_bytes(&bytes))
        .map_err(AppError::filesystem)
}

pub fn is_vault_file(text: &str) -> bool {
    let Some(header) = text
        .lines()
        .next()
        .map(|header| header.trim_end_matches('\r'))
    else {
        return false;
    };
    let fields: Vec<&str> = header.split(';').collect();
    fields.first() == Some(&"$ANSIBLE_VAULT")
        && matches!(fields.get(1).copied(), Some("1.1" | "1.2"))
        && fields.get(2) == Some(&"AES256")
        && match fields.get(1).copied() {
            Some("1.1") => fields.len() == 3,
            Some("1.2") => fields.len() == 4 && fields.get(3).is_some_and(|id| !id.is_empty()),
            _ => false,
        }
}

fn append_password_args(args: &mut Vec<OsString>, settings: &Settings, password_file: &Path) {
    if let Some(vault_id) = settings.vault_id.as_deref() {
        args.extend([
            OsString::from("--vault-id"),
            OsString::from(format!("{vault_id}@{}", password_file.display())),
        ]);
    } else {
        args.extend([
            OsString::from("--vault-password-file"),
            password_file.as_os_str().to_owned(),
        ]);
    }
}

async fn run_ansible(
    environment: &Environment,
    args: &[OsString],
    stdin: Option<&[u8]>,
) -> AppResult<ProcessOutput> {
    let process_env = [("ANSIBLE_LOCAL_TEMP", environment.work_dir.path())];
    let output = run_output(
        &environment.ansible_vault,
        args,
        &process_env,
        stdin,
        OPERATION_TIMEOUT,
    )
    .await?;
    if output.success {
        return Ok(output);
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if stderr.contains("decrypt")
        || stderr.contains("vault password")
        || stderr.contains("no vault secrets")
        || stderr.contains("vault encrypted data")
        || stderr.contains("vault format")
    {
        Err(AppError::VaultRejected)
    } else if stderr.contains("unknown option") || stderr.contains("unrecognized arguments") {
        Err(AppError::user(
            "The installed ansible-vault does not support this operation",
        ))
    } else {
        Err(AppError::user(
            "ansible-vault failed; verify the input, password source, and filesystem permissions",
        ))
    }
}

fn parse_encrypt_string(stdout: &[u8]) -> AppResult<String> {
    let text = std::str::from_utf8(stdout)
        .map_err(|_| AppError::user("ansible-vault returned invalid text"))?;
    let mut lines = text.lines();
    let marker = lines
        .find(|line| line.contains("!vault |"))
        .ok_or_else(|| AppError::user("ansible-vault returned an invalid encrypted value"))?;
    let indentation = marker.len() - marker.trim_start().len();
    let payload: Vec<String> = lines
        .map(|line| {
            let stripped = line.strip_prefix(&" ".repeat(indentation)).unwrap_or(line);
            stripped.trim_start().to_string()
        })
        .filter(|line| !line.is_empty())
        .collect();
    if !payload
        .first()
        .is_some_and(|line| line.starts_with(VAULT_HEADER))
    {
        return Err(AppError::user(
            "ansible-vault returned an invalid encrypted value",
        ));
    }
    Ok(format!("{}\n", payload.join("\n")))
}

fn private_tempfile(directory: &Path, prefix: &str) -> AppResult<NamedTempFile> {
    let file = tempfile::Builder::new()
        .prefix(prefix)
        .tempfile_in(directory)
        .map_err(AppError::filesystem)?;
    set_private_permissions(file.as_file())?;
    Ok(file)
}

fn set_private_permissions(file: &File) -> AppResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(Permissions::from_mode(0o600))
            .map_err(AppError::filesystem)?;
    }
    Ok(())
}

fn validate_target_file(path: &Path) -> AppResult<Metadata> {
    let link_metadata = fs::symlink_metadata(path).map_err(AppError::filesystem)?;
    if link_metadata.file_type().is_symlink() {
        return Err(AppError::user("Symlinked Vault files are not supported"));
    }
    if !link_metadata.is_file() {
        return Err(AppError::user(
            "Only regular files can be encrypted or decrypted",
        ));
    }
    if link_metadata.permissions().readonly() {
        return Err(AppError::user("The target file is read-only"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if link_metadata.permissions().mode() & 0o222 == 0 {
            return Err(AppError::user("The target file is read-only"));
        }
    }
    Ok(link_metadata)
}

fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn builds_password_arguments_without_secret() {
        let settings = Settings {
            vault_id: Some("dev".into()),
            ..Settings::default()
        };
        let mut args = Vec::new();
        append_password_args(&mut args, &settings, Path::new("/tmp/password"));
        assert_eq!(
            args,
            vec![
                OsString::from("--vault-id"),
                OsString::from("dev@/tmp/password")
            ]
        );
        assert!(!args.iter().any(|arg| arg == "actual-secret"));
    }

    #[test]
    fn parses_encrypt_string_output() {
        let output = b"__zed_vault_value__: !vault |\n          $ANSIBLE_VAULT;1.1;AES256\n          616263\n";
        assert_eq!(
            parse_encrypt_string(output).expect("payload"),
            "$ANSIBLE_VAULT;1.1;AES256\n616263\n"
        );
    }

    #[test]
    fn validates_vault_headers() {
        assert!(is_vault_file("$ANSIBLE_VAULT;1.1;AES256\n616263\n"));
        assert!(is_vault_file("$ANSIBLE_VAULT;1.2;AES256;dev\n616263\n"));
        assert!(!is_vault_file("$ANSIBLE_VAULT;1.2;AES256\n616263\n"));
        assert!(!is_vault_file("$ANSIBLE_VAULT;2.0;AES256\n616263\n"));
    }

    #[cfg(unix)]
    #[test]
    fn secret_temporary_files_are_private_and_removed_on_drop() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = {
            let file = private_tempfile(directory.path(), "secret-").expect("private tempfile");
            let path = file.path().to_path_buf();
            let mode = file
                .as_file()
                .metadata()
                .expect("temporary metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
            path
        };
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_read_only_and_symlinked_targets() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("target.yml");
        fs::write(&target, "secret: value\n").expect("target");
        fs::set_permissions(&target, Permissions::from_mode(0o400)).expect("read-only permissions");
        assert!(validate_target_file(&target).is_err());
        fs::set_permissions(&target, Permissions::from_mode(0o600)).expect("writable permissions");
        let link = directory.path().join("link.yml");
        symlink(&target, &link).expect("symlink");
        assert!(validate_target_file(&link).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn prepared_file_refuses_to_replace_a_concurrently_changed_target() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("target.yml");
        let output = directory.path().join("prepared.yml");
        fs::write(&target, "original\n").expect("target");
        fs::write(&output, "encrypted\n").expect("prepared output");
        let metadata = fs::metadata(&target).expect("target metadata");
        let prepared = PreparedFile {
            output_path: output.clone(),
            original_hash: hash_bytes(b"original\n"),
            result_hash: hash_bytes(b"encrypted\n"),
            permissions: metadata.permissions(),
            committed: false,
        };

        fs::write(&target, "changed\n").expect("concurrent edit");
        assert!(prepared.commit(&target).is_err());
        assert_eq!(
            fs::read_to_string(&target).expect("changed target"),
            "changed\n"
        );
        assert!(!output.exists());
    }

    #[tokio::test]
    #[ignore = "requires ansible-core installed on the host"]
    async fn real_ansible_value_round_trip() {
        use crate::validation::{canonical_header, validate_vault_document};
        use crate::yaml::{find_scalar, find_vault, format_encrypted_value};
        use tower_lsp::lsp_types::{Position, Range};

        let executable = which::which("ansible-vault").expect("ansible-vault in PATH");
        let work_dir = tempfile::tempdir().expect("private work directory");
        let password_path = work_dir.path().join("password");
        fs::write(&password_path, "round-trip-password\n").expect("password file");
        #[cfg(unix)]
        {
            fs::set_permissions(&password_path, Permissions::from_mode(0o600))
                .expect("private password permissions");
        }
        let environment = Environment {
            ansible_vault: executable,
            work_dir,
            password: PasswordProvider::File(password_path.clone()),
            warnings: Vec::new(),
        };
        let password = PasswordFile {
            path: password_path,
            _temporary: None,
        };
        let settings = Settings::default();
        for plaintext in ["single line", "line one\nline two"] {
            let encrypted = encrypt_value(&environment, &settings, &password, plaintext)
                .await
                .expect("encrypt value");
            assert!(validate_vault_document(&format!(
                "secret: !vault |\n  {}",
                encrypted.replace('\n', "\n  ")
            ))
            .is_empty());
            let decrypted = decrypt_value(&environment, &settings, &password, &encrypted)
                .await
                .expect("decrypt value");
            assert_eq!(decrypted, plaintext);
        }

        let encrypted = encrypt_value(&environment, &settings, &password, "repaired header")
            .await
            .expect("encrypt repair fixture");
        let (_, payload) = encrypted.split_once('\n').expect("encrypted payload");
        let repaired = format!(
            "{}\n{payload}",
            canonical_header("$sANSIBLE_VAULT:9.9:ASE-256").expect("canonical 1.1 header")
        );
        assert_eq!(
            decrypt_value(&environment, &settings, &password, &repaired)
                .await
                .expect("decrypt with repaired 1.1 header"),
            "repaired header"
        );

        let mut nested_yaml =
            String::from("ssh_users:\n  - name: devops\n    password: unchanged\n    uid: 1001\n");
        let scalar = find_scalar(
            &nested_yaml,
            Range::new(Position::new(1, 4), Position::new(1, 4)),
        )
        .expect("nested sequence scalar");
        let nested_encrypted = encrypt_value(&environment, &settings, &password, &scalar.plaintext)
            .await
            .expect("encrypt nested sequence scalar");
        let nested_replacement =
            format_encrypted_value(&nested_encrypted, &scalar.continuation_indent)
                .expect("format nested sequence vault");
        nested_yaml.replace_range(scalar.start..scalar.end, &nested_replacement);
        assert!(validate_vault_document(&nested_yaml).is_empty());
        let nested_target = find_vault(
            &nested_yaml,
            Range::new(Position::new(1, 4), Position::new(1, 4)),
        )
        .expect("extract nested sequence vault");
        assert!(!nested_target.vault_text.contains("password:"));
        assert!(!nested_target.vault_text.contains("uid:"));
        assert_eq!(
            decrypt_value(
                &environment,
                &settings,
                &password,
                &nested_target.vault_text,
            )
            .await
            .expect("decrypt nested sequence vault"),
            "devops"
        );

        let labeled_settings = Settings {
            vault_id: Some("dev".into()),
            ..Settings::default()
        };
        let labeled = encrypt_value(&environment, &labeled_settings, &password, "labeled secret")
            .await
            .expect("encrypt labeled value");
        assert!(labeled.starts_with("$ANSIBLE_VAULT;1.2;AES256;dev"));
        assert!(validate_vault_document(&format!(
            "secret: !vault |\n  {}",
            labeled.replace('\n', "\n  ")
        ))
        .is_empty());
        let (_, labeled_payload) = labeled.split_once('\n').expect("labeled payload");
        let repaired_labeled = format!(
            "{}\n{labeled_payload}",
            canonical_header("$sANSIBLE_VAULT;1,2;ASE-256:dev").expect("canonical 1.2 header")
        );
        assert_eq!(
            decrypt_value(
                &environment,
                &labeled_settings,
                &password,
                &repaired_labeled,
            )
            .await
            .expect("decrypt with repaired 1.2 header"),
            "labeled secret"
        );
        assert_eq!(
            decrypt_value(&environment, &labeled_settings, &password, &labeled)
                .await
                .expect("decrypt labeled value"),
            "labeled secret"
        );

        let target = environment.work_dir.path().join("whole-file.yml");
        let original = "secret: value\n";
        fs::write(&target, original).expect("plaintext target");
        #[cfg(unix)]
        fs::set_permissions(&target, Permissions::from_mode(0o640)).expect("target permissions");
        let encrypted = prepare_file(
            &environment,
            &settings,
            &password,
            Operation::EncryptFile,
            &target,
            original,
        )
        .await
        .expect("prepare file encryption");
        encrypted.commit(&target).expect("commit file encryption");
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&target)
                .expect("encrypted metadata")
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        let ciphertext = fs::read_to_string(&target).expect("encrypted target");
        assert!(is_vault_file(&ciphertext));
        assert!(validate_vault_document(&ciphertext).is_empty());
        let decrypted = prepare_file(
            &environment,
            &settings,
            &password,
            Operation::DecryptFile,
            &target,
            &ciphertext,
        )
        .await
        .expect("prepare file decryption");
        decrypted.commit(&target).expect("commit file decryption");
        assert_eq!(
            fs::read_to_string(&target).expect("decrypted target"),
            original
        );
    }
}
