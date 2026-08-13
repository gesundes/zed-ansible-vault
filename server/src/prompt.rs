use crate::config::PromptBackendSetting;
use crate::error::{AppError, AppResult};
use crate::process::{run_output, COMMAND_TIMEOUT};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

const PROMPT_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone, Debug)]
pub enum PromptBackend {
    #[cfg(target_os = "macos")]
    Osascript(PathBuf),
    #[cfg(target_os = "linux")]
    Zenity(PathBuf),
    #[cfg(target_os = "linux")]
    Kdialog(PathBuf),
    #[cfg(target_os = "linux")]
    Yad(PathBuf),
}

impl PromptBackend {
    pub async fn discover(setting: PromptBackendSetting) -> AppResult<Self> {
        #[cfg(target_os = "macos")]
        {
            if !matches!(
                setting,
                PromptBackendSetting::Auto | PromptBackendSetting::Osascript
            ) {
                return Err(AppError::user(
                    "The selected prompt backend is not available on macOS",
                ));
            }
            let backend = Self::Osascript(PathBuf::from("/usr/bin/osascript"));
            backend.smoke_test().await?;
            Ok(backend)
        }

        #[cfg(target_os = "linux")]
        {
            let has_display = std::env::var_os("DISPLAY").is_some_and(|value| !value.is_empty())
                || std::env::var_os("WAYLAND_DISPLAY").is_some_and(|value| !value.is_empty());
            if !has_display {
                return Err(AppError::user(
                    "Interactive password input requires DISPLAY or WAYLAND_DISPLAY; configure ansibleVault.passwordFile for headless use",
                ));
            }
            let names: &[(&str, PromptBackendSetting)] = match setting {
                PromptBackendSetting::Auto => &[
                    ("zenity", PromptBackendSetting::Zenity),
                    ("kdialog", PromptBackendSetting::Kdialog),
                    ("yad", PromptBackendSetting::Yad),
                ],
                PromptBackendSetting::Zenity => &[("zenity", PromptBackendSetting::Zenity)],
                PromptBackendSetting::Kdialog => &[("kdialog", PromptBackendSetting::Kdialog)],
                PromptBackendSetting::Yad => &[("yad", PromptBackendSetting::Yad)],
                PromptBackendSetting::Osascript => {
                    return Err(AppError::user("osascript is available on macOS only"));
                }
            };
            for (name, kind) in names {
                if let Ok(path) = which::which(name) {
                    let backend = match kind {
                        PromptBackendSetting::Zenity => Self::Zenity(path),
                        PromptBackendSetting::Kdialog => Self::Kdialog(path),
                        PromptBackendSetting::Yad => Self::Yad(path),
                        _ => continue,
                    };
                    match backend.smoke_test().await {
                        Ok(()) => return Ok(backend),
                        Err(error) if setting != PromptBackendSetting::Auto => return Err(error),
                        Err(_) => continue,
                    }
                }
            }
            Err(AppError::user(
                "No working password dialog tool found; install zenity, kdialog, or yad, or configure ansibleVault.passwordFile",
            ))
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = setting;
            Err(AppError::user(
                "Interactive password input is supported on macOS and Linux only",
            ))
        }
    }

    fn executable(&self) -> &Path {
        match self {
            #[cfg(target_os = "macos")]
            Self::Osascript(path) => path,
            #[cfg(target_os = "linux")]
            Self::Zenity(path) | Self::Kdialog(path) | Self::Yad(path) => path,
        }
    }

    async fn smoke_test(&self) -> AppResult<()> {
        let args: Vec<OsString> = match self {
            #[cfg(target_os = "macos")]
            Self::Osascript(_) => vec!["-e".into(), "return \"ok\"".into()],
            #[cfg(target_os = "linux")]
            Self::Zenity(_) | Self::Yad(_) => vec!["--version".into()],
            #[cfg(target_os = "linux")]
            Self::Kdialog(_) => vec!["--version".into()],
        };
        let output = run_output(self.executable(), &args, &[], None, COMMAND_TIMEOUT).await?;
        if !output.success {
            return Err(AppError::user(format!(
                "Password dialog tool {} is installed but failed its startup check",
                self.executable().display()
            )));
        }
        Ok(())
    }

    pub async fn ask(&self, title: &str, message: &str) -> AppResult<Zeroizing<String>> {
        let args: Vec<OsString> = match self {
            #[cfg(target_os = "macos")]
            Self::Osascript(_) => {
                let escaped_title = apple_script_escape(title);
                let escaped_message = apple_script_escape(message);
                let script = format!(
                    "set response to display dialog \"{escaped_message}\" with title \"{escaped_title}\" default answer \"\" with hidden answer buttons {{\"Cancel\", \"OK\"}} default button \"OK\" cancel button \"Cancel\"\nreturn text returned of response"
                );
                vec!["-e".into(), script.into()]
            }
            #[cfg(target_os = "linux")]
            Self::Zenity(_) => vec![
                "--password".into(),
                format!("--title={title}").into(),
                format!("--text={message}").into(),
            ],
            #[cfg(target_os = "linux")]
            Self::Kdialog(_) => vec![
                "--title".into(),
                title.into(),
                "--password".into(),
                message.into(),
            ],
            #[cfg(target_os = "linux")]
            Self::Yad(_) => vec![
                "--entry".into(),
                "--hide-text".into(),
                format!("--title={title}").into(),
                format!("--text={message}").into(),
            ],
        };
        let output = run_output(self.executable(), &args, &[], None, PROMPT_TIMEOUT).await?;
        if !output.success {
            return Err(AppError::Cancelled);
        }
        let value = String::from_utf8(output.stdout)
            .map_err(|_| AppError::user("Password dialog returned invalid text"))?;
        let value = value.trim_end_matches(['\r', '\n']).to_string();
        if value.is_empty() {
            return Err(AppError::user("Vault password must not be empty"));
        }
        Ok(Zeroizing::new(value))
    }
}

fn apple_script_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_apple_script_strings() {
        assert_eq!(apple_script_escape("a \\\" b"), "a \\\\\\\" b");
    }
}
