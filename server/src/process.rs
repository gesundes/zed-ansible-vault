use crate::error::{AppError, AppResult};
use std::ffi::OsString;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
pub const OPERATION_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub struct ProcessOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub async fn run_output(
    executable: &Path,
    args: &[OsString],
    env: &[(&str, &Path)],
    stdin: Option<&[u8]>,
    timeout: Duration,
) -> AppResult<ProcessOutput> {
    let mut command = Command::new(executable);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (name, value) in env {
        command.env(name, value);
    }
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }

    let mut child = command.spawn().map_err(|error| {
        AppError::user(format!("Failed to start {}: {error}", executable.display()))
    })?;
    let communicate = async move {
        if let Some(input) = stdin {
            let mut child_stdin = child
                .stdin
                .take()
                .ok_or_else(|| AppError::user("Failed to open subprocess input"))?;
            child_stdin
                .write_all(input)
                .await
                .map_err(AppError::filesystem)?;
            child_stdin.shutdown().await.map_err(AppError::filesystem)?;
        }
        child.wait_with_output().await.map_err(|error| {
            AppError::user(format!(
                "Failed to wait for {}: {error}",
                executable.display()
            ))
        })
    };
    let output = tokio::time::timeout(timeout, communicate)
        .await
        .map_err(|_| AppError::Timeout)??;
    Ok(ProcessOutput {
        success: output.status.success(),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn times_out_a_process() {
        let result = run_output(
            Path::new("/bin/sh"),
            &["-c".into(), "sleep 2".into()],
            &[],
            None,
            Duration::from_millis(20),
        )
        .await;
        assert!(matches!(result, Err(AppError::Timeout)));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sends_input_over_stdin_not_arguments() {
        let output = run_output(
            Path::new("/bin/sh"),
            &["-c".into(), "read value; printf '%s' \"$value\"".into()],
            &[],
            Some(b"secret-value\n"),
            COMMAND_TIMEOUT,
        )
        .await
        .expect("process output");
        assert_eq!(output.stdout, b"secret-value");
    }
}
